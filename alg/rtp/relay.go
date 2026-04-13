package rtp

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// RTP 媒体中继 (Media Relay)
//
// 在 NAT64 场景中，SIP/H.323 的信令可以通过 ALG 做地址重写,
// 但 RTP 媒体流是独立的 UDP 流，使用完全不同的端口。
//
// 本模块在网关上动态分配 UDP 端口对，充当 IPv6 ↔ IPv4 的媒体桥接:
//   - IPv6 侧: 监听一个 UDP6 端口，接收来自 IPv6 终端的 RTP
//   - IPv4 侧: 监听一个 UDP4 端口，接收来自 IPv4 终端的 RTP
//   - 双向转发: IPv6 → IPv4, IPv4 → IPv6
//
// 生命周期:
//   1. SIP ALG 解析 SDP 中的 m= 行, 提取媒体端口
//   2. 调用 RelayManager.AllocateRelay() 分配中继端口对
//   3. ALG 将 SDP 中的 c=/m= 改写为中继的地址/端口
//   4. 通话期间, 中继双向转发 RTP/RTCP 包
//   5. 通话结束 (BYE) 或超时后, 释放中继资源
// ============================================================================

// RelayManager 管理所有活跃的 RTP 中继会话
type RelayManager struct {
	mu       sync.Mutex
	relays   map[uint16]*RelaySession // key = IPv4 中继端口
	bindIPv6 net.IP                   // 网关 IPv6 侧地址 (eth0)
	bindIPv4 net.IP                   // 网关 IPv4 侧地址 (eth1)

	// 端口分配池
	portStart uint16
	portEnd   uint16
	nextPort  uint16

	// 统计
	activeCount  int64
	totalRelayed int64
}

// RelaySession 表示一对 RTP 中继通道
type RelaySession struct {
	ID string // 关联的 SIP Call-ID

	// IPv6 侧
	IPv6Addr    net.IP // 远端 IPv6 终端的地址
	IPv6Port    uint16 // 远端 IPv6 终端的 RTP 端口
	LocalPort6  uint16 // 网关上 IPv6 侧监听的端口
	conn6       *net.UDPConn

	// IPv4 侧
	IPv4Addr    net.IP // 远端 IPv4 终端的地址
	IPv4Port    uint16 // 远端 IPv4 终端的 RTP 端口
	LocalPort4  uint16 // 网关上 IPv4 侧监听的端口 (通常与 LocalPort6 相同)
	conn4       *net.UDPConn

	// 状态
	CreatedAt   time.Time
	LastActive  time.Time
	Packets6to4 uint64 // IPv6→IPv4 转发计数
	Packets4to6 uint64 // IPv4→IPv6 转发计数

	stopCh chan struct{}
	once   sync.Once
}

// NewRelayManager 创建 RTP 中继管理器
func NewRelayManager(bindIPv6, bindIPv4 net.IP, portStart, portEnd uint16) *RelayManager {
	rm := &RelayManager{
		relays:    make(map[uint16]*RelaySession),
		bindIPv6:  bindIPv6,
		bindIPv4:  bindIPv4,
		portStart: portStart,
		portEnd:   portEnd,
		nextPort:  portStart,
	}

	// 启动过期清理
	go rm.cleanupLoop()

	return rm
}

// AllocateRelay 为一次通话分配一对 RTP 中继端口
// 返回分配的本地中继端口 (在双侧使用相同端口号)
func (rm *RelayManager) AllocateRelay(
	callID string,
	ipv6Addr net.IP, ipv6Port uint16,
	ipv4Addr net.IP, ipv4Port uint16,
) (*RelaySession, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 分配端口 (RTP 端口必须是偶数, RTCP = RTP+1)
	localPort, err := rm.allocateEvenPort()
	if err != nil {
		return nil, fmt.Errorf("RTP 端口池耗尽: %w", err)
	}

	// 绑定 IPv6 侧 UDP socket
	addr6 := &net.UDPAddr{IP: rm.bindIPv6, Port: int(localPort)}
	conn6, err := net.ListenUDP("udp6", addr6)
	if err != nil {
		return nil, fmt.Errorf("绑定 IPv6 UDP [%s]:%d 失败: %w", rm.bindIPv6, localPort, err)
	}

	// 绑定 IPv4 侧 UDP socket
	addr4 := &net.UDPAddr{IP: rm.bindIPv4, Port: int(localPort)}
	conn4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		conn6.Close()
		return nil, fmt.Errorf("绑定 IPv4 UDP %s:%d 失败: %w", rm.bindIPv4, localPort, err)
	}

	now := time.Now()
	relay := &RelaySession{
		ID:         callID,
		IPv6Addr:   ipv6Addr,
		IPv6Port:   ipv6Port,
		LocalPort6: localPort,
		conn6:      conn6,
		IPv4Addr:   ipv4Addr,
		IPv4Port:   ipv4Port,
		LocalPort4: localPort,
		conn4:      conn4,
		CreatedAt:  now,
		LastActive: now,
		stopCh:     make(chan struct{}),
	}

	rm.relays[localPort] = relay
	atomic.AddInt64(&rm.activeCount, 1)

	// 启动双向转发 goroutine
	go relay.forwardIPv6ToIPv4()
	go relay.forwardIPv4ToIPv6()

	log.Printf("[RTPRelay] 分配中继: Call=%s, Port=%d, IPv6=[%s]:%d ↔ IPv4=%s:%d",
		callID, localPort, ipv6Addr, ipv6Port, ipv4Addr, ipv4Port)

	return relay, nil
}

// ReleaseRelay 释放一个中继会话
func (rm *RelayManager) ReleaseRelay(localPort uint16) {
	rm.mu.Lock()
	relay, ok := rm.relays[localPort]
	if ok {
		delete(rm.relays, localPort)
	}
	// 同时释放 RTCP 端口 (localPort+1)
	relayRTCP, okRTCP := rm.relays[localPort+1]
	if okRTCP {
		delete(rm.relays, localPort+1)
	}
	rm.mu.Unlock()

	if ok {
		relay.Stop()
		atomic.AddInt64(&rm.activeCount, -1)
		log.Printf("[RTPRelay] 释放中继: Call=%s, Port=%d, 转发统计: 6→4=%d, 4→6=%d",
			relay.ID, localPort, relay.Packets6to4, relay.Packets4to6)
	}
	if okRTCP {
		relayRTCP.Stop()
		atomic.AddInt64(&rm.activeCount, -1)
	}
}

// Stats 返回当前活跃中继数和总转发包数
func (rm *RelayManager) Stats() (active int64, totalRelayed int64) {
	return atomic.LoadInt64(&rm.activeCount), atomic.LoadInt64(&rm.totalRelayed)
}

// GetRelayInfo 获取中继信息 (供 ALG 改写 SDP 使用)
func (rm *RelayManager) GetRelayInfo(localPort uint16) (ipv6Addr net.IP, ipv4Addr net.IP) {
	return rm.bindIPv6, rm.bindIPv4
}

// ============================================================================
// 中继会话的双向转发
// ============================================================================

const (
	rtpBufSize    = 1500            // RTP 包最大大小
	relayTimeout  = 60 * time.Second // 无活动超时
	readDeadline  = 100 * time.Millisecond
)

// forwardIPv6ToIPv4 从 IPv6 侧接收 RTP 并转发到 IPv4 侧
func (rs *RelaySession) forwardIPv6ToIPv4() {
	buf := make([]byte, rtpBufSize)
	dstAddr := &net.UDPAddr{IP: rs.IPv4Addr, Port: int(rs.IPv4Port)}

	for {
		select {
		case <-rs.stopCh:
			return
		default:
		}

		rs.conn6.SetReadDeadline(time.Now().Add(readDeadline))
		n, srcAddr, err := rs.conn6.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// 学习远端 IPv6 地址 (首包可能更新)
		if srcAddr != nil {
			rs.IPv6Addr = srcAddr.IP
			rs.IPv6Port = uint16(srcAddr.Port)
		}

		// 转发到 IPv4 侧
		_, err = rs.conn4.WriteToUDP(buf[:n], dstAddr)
		if err != nil {
			log.Printf("[RTPRelay] 6→4 发送失败: %v", err)
			continue
		}

		rs.Packets6to4++
		rs.LastActive = time.Now()
	}
}

// forwardIPv4ToIPv6 从 IPv4 侧接收 RTP 并转发到 IPv6 侧
func (rs *RelaySession) forwardIPv4ToIPv6() {
	buf := make([]byte, rtpBufSize)

	for {
		select {
		case <-rs.stopCh:
			return
		default:
		}

		rs.conn4.SetReadDeadline(time.Now().Add(readDeadline))
		n, srcAddr, err := rs.conn4.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// 学习远端 IPv4 地址
		if srcAddr != nil {
			rs.IPv4Addr = srcAddr.IP
			rs.IPv4Port = uint16(srcAddr.Port)
		}

		// 转发到 IPv6 侧
		dstAddr6 := &net.UDPAddr{IP: rs.IPv6Addr, Port: int(rs.IPv6Port)}
		_, err = rs.conn6.WriteToUDP(buf[:n], dstAddr6)
		if err != nil {
			log.Printf("[RTPRelay] 4→6 发送失败: %v", err)
			continue
		}

		rs.Packets4to6++
		rs.LastActive = time.Now()
	}
}

// Stop 停止中继会话
func (rs *RelaySession) Stop() {
	rs.once.Do(func() {
		close(rs.stopCh)
		if rs.conn6 != nil {
			rs.conn6.Close()
		}
		if rs.conn4 != nil {
			rs.conn4.Close()
		}
	})
}

// ============================================================================
// 端口分配与清理
// ============================================================================

// allocateEvenPort 分配一个偶数端口 (RTP 规范要求 RTP 端口为偶数)
func (rm *RelayManager) allocateEvenPort() (uint16, error) {
	startPort := rm.nextPort
	// 确保是偶数
	if startPort%2 != 0 {
		startPort++
	}

	for port := startPort; port <= rm.portEnd; port += 2 {
		if _, exists := rm.relays[port]; !exists {
			rm.nextPort = port + 2
			if rm.nextPort > rm.portEnd {
				rm.nextPort = rm.portStart
			}
			return port, nil
		}
	}
	// 回绕搜索
	for port := rm.portStart; port < startPort; port += 2 {
		if port%2 != 0 {
			continue
		}
		if _, exists := rm.relays[port]; !exists {
			rm.nextPort = port + 2
			return port, nil
		}
	}
	return 0, fmt.Errorf("无可用端口")
}

// cleanupLoop 定期清理超时的中继会话
func (rm *RelayManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rm.mu.Lock()
		cutoff := time.Now().Add(-relayTimeout)
		var expired []uint16
		for port, relay := range rm.relays {
			if relay.LastActive.Before(cutoff) {
				expired = append(expired, port)
			}
		}
		rm.mu.Unlock()

		for _, port := range expired {
			rm.ReleaseRelay(port)
			log.Printf("[RTPRelay] 超时释放: Port=%d", port)
		}
	}
}
