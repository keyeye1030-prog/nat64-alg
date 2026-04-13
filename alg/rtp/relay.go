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
//   - IPv6 侧: 监听 UDP6 端口，接收来自 IPv6 终端的 RTP/RTCP
//   - IPv4 侧: 监听 UDP4 端口，接收来自 IPv4 终端的 RTP/RTCP
//   - 双向转发: IPv6 → IPv4, IPv4 → IPv6
//
// 生命周期:
//   1. SIP ALG 解析 SDP 中的 m= 行, 提取媒体端口
//   2. 调用 RelayManager.AllocateRelayPair() 分配 RTP+RTCP 端口对
//   3. ALG 将 SDP 中的 c=/m= 改写为中继的地址/端口
//   4. 通话期间, 中继双向转发 RTP/RTCP 包
//   5. 通话结束后调用 ReleaseByCallID(), 或超时自动释放
// ============================================================================

// RelayManager 管理所有活跃的 RTP 中继会话
type RelayManager struct {
	mu       sync.RWMutex
	relays   map[uint16]*RelaySession // key = 本地中继端口
	byCallID map[string][]*RelaySession // key = SIP Call-ID → 该通话的所有中继
	bindIPv6 net.IP                   // 网关 IPv6 侧地址 (eth0)
	bindIPv4 net.IP                   // 网关 IPv4 侧地址 (eth1)

	// 端口分配池
	portStart uint16
	portEnd   uint16
	nextPort  uint16

	// 统计
	activeCount  int64
	totalRelayed int64 // 累计转发包数

	// 配置
	idleTimeout time.Duration // 无活动超时 (默认 60s)
}

// RelaySession 表示一个 RTP 或 RTCP 中继通道
type RelaySession struct {
	CallID    string  // 关联的 SIP Call-ID
	MediaType string  // "audio", "video" 等
	Proto     string  // "RTP" 或 "RTCP"

	// IPv6 侧
	IPv6Addr    net.IP // 远端 IPv6 终端的地址 (首包学习)
	IPv6Port    uint16 // 远端 IPv6 终端的端口
	LocalPort6  uint16 // 网关上 IPv6 侧监听的端口
	conn6       *net.UDPConn

	// IPv4 侧
	IPv4Addr    net.IP // 远端 IPv4 终端的地址 (首包学习)
	IPv4Port    uint16 // 远端 IPv4 终端的端口
	LocalPort4  uint16 // 网关上 IPv4 侧监听的端口
	conn4       *net.UDPConn

	// 状态
	CreatedAt   time.Time
	LastActive  time.Time
	Packets6to4 uint64 // IPv6→IPv4 转发计数
	Packets4to6 uint64 // IPv4→IPv6 转发计数
	Bytes6to4   uint64 // IPv6→IPv4 转发字节数
	Bytes4to6   uint64 // IPv4→IPv6 转发字节数

	// 首包学习标记 (远端地址未知前不转发)
	learned6 bool
	learned4 bool
	mu       sync.RWMutex

	stopCh chan struct{}
	once   sync.Once

	manager *RelayManager // 反向引用, 用于更新统计
}

// RelayPair 包含 RTP + RTCP 两个中继通道
type RelayPair struct {
	RTP  *RelaySession
	RTCP *RelaySession
}

// NewRelayManager 创建 RTP 中继管理器
func NewRelayManager(bindIPv6, bindIPv4 net.IP, portStart, portEnd uint16) *RelayManager {
	rm := &RelayManager{
		relays:      make(map[uint16]*RelaySession),
		byCallID:    make(map[string][]*RelaySession),
		bindIPv6:    bindIPv6,
		bindIPv4:    bindIPv4,
		portStart:   portStart,
		portEnd:     portEnd,
		nextPort:    portStart,
		idleTimeout: 60 * time.Second,
	}

	// 启动过期清理
	go rm.cleanupLoop()

	return rm
}

// SetIdleTimeout 设置中继无活动超时时间
func (rm *RelayManager) SetIdleTimeout(d time.Duration) {
	rm.idleTimeout = d
}

// AllocateRelayPair 为一个媒体流分配 RTP + RTCP 端口对
// RTP 使用偶数端口, RTCP = RTP+1
func (rm *RelayManager) AllocateRelayPair(
	callID string,
	mediaType string, // "audio", "video"
	ipv6Addr net.IP, ipv6Port uint16,
	ipv4Addr net.IP, ipv4Port uint16,
) (*RelayPair, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 分配偶数端口 (RTP)
	rtpPort, err := rm.allocateEvenPort()
	if err != nil {
		return nil, fmt.Errorf("RTP 端口池耗尽: %w", err)
	}
	rtcpPort := rtpPort + 1

	// 创建 RTP 中继
	rtpRelay, err := rm.createRelay(callID, mediaType, "RTP",
		ipv6Addr, ipv6Port, ipv4Addr, ipv4Port, rtpPort)
	if err != nil {
		return nil, err
	}

	// 创建 RTCP 中继 (端口各 +1)
	rtcpRelay, err := rm.createRelay(callID, mediaType, "RTCP",
		ipv6Addr, ipv6Port+1, ipv4Addr, ipv4Port+1, rtcpPort)
	if err != nil {
		rtpRelay.Stop()
		delete(rm.relays, rtpPort)
		return nil, err
	}

	// 注册到 Call-ID 索引
	rm.byCallID[callID] = append(rm.byCallID[callID], rtpRelay, rtcpRelay)

	log.Printf("[RTPRelay] 分配中继对: Call=%s, Media=%s, RTP=%d, RTCP=%d, "+
		"IPv6=[%s]:%d ↔ IPv4=%s:%d",
		callID, mediaType, rtpPort, rtcpPort,
		ipv6Addr, ipv6Port, ipv4Addr, ipv4Port)

	return &RelayPair{RTP: rtpRelay, RTCP: rtcpRelay}, nil
}

// AllocateRelay 为单个端口分配中继 (兼容旧接口)
func (rm *RelayManager) AllocateRelay(
	callID string,
	ipv6Addr net.IP, ipv6Port uint16,
	ipv4Addr net.IP, ipv4Port uint16,
) (*RelaySession, error) {
	pair, err := rm.AllocateRelayPair(callID, "audio",
		ipv6Addr, ipv6Port, ipv4Addr, ipv4Port)
	if err != nil {
		return nil, err
	}
	return pair.RTP, nil
}

// createRelay 创建并启动单个中继通道
func (rm *RelayManager) createRelay(
	callID, mediaType, proto string,
	ipv6Addr net.IP, ipv6Port uint16,
	ipv4Addr net.IP, ipv4Port uint16,
	localPort uint16,
) (*RelaySession, error) {

	// 绑定 IPv6 侧 UDP socket
	addr6 := &net.UDPAddr{IP: rm.bindIPv6, Port: int(localPort)}
	conn6, err := net.ListenUDP("udp6", addr6)
	if err != nil {
		return nil, fmt.Errorf("绑定 IPv6 UDP [%s]:%d 失败: %w",
			rm.bindIPv6, localPort, err)
	}

	// 绑定 IPv4 侧 UDP socket
	addr4 := &net.UDPAddr{IP: rm.bindIPv4, Port: int(localPort)}
	conn4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		conn6.Close()
		return nil, fmt.Errorf("绑定 IPv4 UDP %s:%d 失败: %w",
			rm.bindIPv4, localPort, err)
	}

	// 设置较大的接收缓冲区 (RTP 对延迟敏感)
	conn6.SetReadBuffer(256 * 1024)
	conn4.SetReadBuffer(256 * 1024)
	conn6.SetWriteBuffer(256 * 1024)
	conn4.SetWriteBuffer(256 * 1024)

	now := time.Now()
	relay := &RelaySession{
		CallID:     callID,
		MediaType:  mediaType,
		Proto:      proto,
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
		manager:    rm,
	}

	// 如果已知远端地址, 标记为已学习
	if ipv6Addr != nil && !ipv6Addr.IsUnspecified() {
		relay.learned6 = true
	}
	if ipv4Addr != nil && !ipv4Addr.IsUnspecified() {
		relay.learned4 = true
	}

	rm.relays[localPort] = relay
	atomic.AddInt64(&rm.activeCount, 1)

	// 启动双向转发 goroutine
	go relay.forwardIPv6ToIPv4()
	go relay.forwardIPv4ToIPv6()

	return relay, nil
}

// ReleaseRelay 释放单个中继
func (rm *RelayManager) ReleaseRelay(localPort uint16) {
	rm.mu.Lock()
	relay, ok := rm.relays[localPort]
	if ok {
		delete(rm.relays, localPort)
	}
	rm.mu.Unlock()

	if ok {
		relay.Stop()
		atomic.AddInt64(&rm.activeCount, -1)
		log.Printf("[RTPRelay] 释放: Call=%s, %s/%s, Port=%d, "+
			"6→4: %d pkts/%d bytes, 4→6: %d pkts/%d bytes",
			relay.CallID, relay.MediaType, relay.Proto, localPort,
			relay.Packets6to4, relay.Bytes6to4,
			relay.Packets4to6, relay.Bytes4to6)
	}
}

// ReleaseByCallID 释放一个通话的所有中继 (由 SIP BYE 触发)
func (rm *RelayManager) ReleaseByCallID(callID string) int {
	rm.mu.Lock()
	relays, ok := rm.byCallID[callID]
	if ok {
		delete(rm.byCallID, callID)
		for _, r := range relays {
			delete(rm.relays, r.LocalPort4)
		}
	}
	rm.mu.Unlock()

	if !ok {
		return 0
	}

	for _, r := range relays {
		r.Stop()
		atomic.AddInt64(&rm.activeCount, -1)
		log.Printf("[RTPRelay] 释放: Call=%s, %s/%s, Port=%d, "+
			"6→4: %d pkts/%d bytes, 4→6: %d pkts/%d bytes",
			r.CallID, r.MediaType, r.Proto, r.LocalPort4,
			r.Packets6to4, r.Bytes6to4,
			r.Packets4to6, r.Bytes4to6)
	}

	log.Printf("[RTPRelay] 通话结束释放: Call=%s, 共 %d 个中继", callID, len(relays))
	return len(relays)
}

// Stats 返回统计信息
func (rm *RelayManager) Stats() (active int64, totalRelayed int64) {
	return atomic.LoadInt64(&rm.activeCount), atomic.LoadInt64(&rm.totalRelayed)
}

// GetRelayInfo 获取中继绑定地址 (供 ALG 改写 SDP 使用)
func (rm *RelayManager) GetRelayInfo(localPort uint16) (ipv6Addr net.IP, ipv4Addr net.IP) {
	return rm.bindIPv6, rm.bindIPv4
}

// ListByCallID 列出一个通话的所有中继
func (rm *RelayManager) ListByCallID(callID string) []*RelaySession {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.byCallID[callID]
}

// ============================================================================
// 中继会话的双向转发
// ============================================================================

const (
	rtpBufSize   = 2048          // 缓冲区大小 (考虑视频大包)
	readTimeout  = 200 * time.Millisecond
)

// forwardIPv6ToIPv4 从 IPv6 侧接收并转发到 IPv4 侧
func (rs *RelaySession) forwardIPv6ToIPv4() {
	buf := make([]byte, rtpBufSize)

	for {
		select {
		case <-rs.stopCh:
			return
		default:
		}

		rs.conn6.SetReadDeadline(time.Now().Add(readTimeout))
		n, srcAddr, err := rs.conn6.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return // socket 已关闭
		}

		if n == 0 {
			continue
		}

		// 首包学习: 记录 IPv6 远端地址
		rs.mu.Lock()
		if srcAddr != nil {
			rs.IPv6Addr = srcAddr.IP
			rs.IPv6Port = uint16(srcAddr.Port)
			rs.learned6 = true
		}
		rs.mu.Unlock()

		// 检查是否已知 IPv4 远端
		rs.mu.RLock()
		hasIPv4 := rs.learned4
		dstAddr := &net.UDPAddr{IP: rs.IPv4Addr, Port: int(rs.IPv4Port)}
		rs.mu.RUnlock()

		if !hasIPv4 {
			continue // 还不知道 IPv4 远端, 丢弃
		}

		// 转发到 IPv4 侧
		_, err = rs.conn4.WriteToUDP(buf[:n], dstAddr)
		if err != nil {
			continue
		}

		atomic.AddUint64(&rs.Packets6to4, 1)
		atomic.AddUint64(&rs.Bytes6to4, uint64(n))
		atomic.AddInt64(&rs.manager.totalRelayed, 1)
		rs.LastActive = time.Now()
	}
}

// forwardIPv4ToIPv6 从 IPv4 侧接收并转发到 IPv6 侧
func (rs *RelaySession) forwardIPv4ToIPv6() {
	buf := make([]byte, rtpBufSize)

	for {
		select {
		case <-rs.stopCh:
			return
		default:
		}

		rs.conn4.SetReadDeadline(time.Now().Add(readTimeout))
		n, srcAddr, err := rs.conn4.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return
		}

		if n == 0 {
			continue
		}

		// 首包学习: 记录 IPv4 远端地址
		rs.mu.Lock()
		if srcAddr != nil {
			rs.IPv4Addr = srcAddr.IP
			rs.IPv4Port = uint16(srcAddr.Port)
			rs.learned4 = true
		}
		rs.mu.Unlock()

		// 检查是否已知 IPv6 远端
		rs.mu.RLock()
		hasIPv6 := rs.learned6
		dstAddr := &net.UDPAddr{IP: rs.IPv6Addr, Port: int(rs.IPv6Port)}
		rs.mu.RUnlock()

		if !hasIPv6 {
			continue
		}

		// 转发到 IPv6 侧
		_, err = rs.conn6.WriteToUDP(buf[:n], dstAddr)
		if err != nil {
			continue
		}

		atomic.AddUint64(&rs.Packets4to6, 1)
		atomic.AddUint64(&rs.Bytes4to6, uint64(n))
		atomic.AddInt64(&rs.manager.totalRelayed, 1)
		rs.LastActive = time.Now()
	}
}

// Stop 停止中继会话, 释放 socket
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

// IsActive 检查中继是否在活跃转发
func (rs *RelaySession) IsActive() bool {
	select {
	case <-rs.stopCh:
		return false
	default:
		return true
	}
}

// ============================================================================
// 端口分配与清理
// ============================================================================

// allocateEvenPort 分配一个偶数端口 (RTP 规范: RTP=偶数, RTCP=RTP+1)
func (rm *RelayManager) allocateEvenPort() (uint16, error) {
	startPort := rm.nextPort
	if startPort%2 != 0 {
		startPort++
	}

	// 从当前位置向后搜索
	for port := startPort; port <= rm.portEnd-1; port += 2 {
		if _, used := rm.relays[port]; !used {
			if _, usedRTCP := rm.relays[port+1]; !usedRTCP {
				rm.nextPort = port + 2
				if rm.nextPort > rm.portEnd {
					rm.nextPort = rm.portStart
				}
				return port, nil
			}
		}
	}
	// 回绕搜索
	for port := rm.portStart; port < startPort; port += 2 {
		if port%2 != 0 {
			continue
		}
		if _, used := rm.relays[port]; !used {
			if _, usedRTCP := rm.relays[port+1]; !usedRTCP {
				rm.nextPort = port + 2
				return port, nil
			}
		}
	}
	return 0, fmt.Errorf("无可用偶数端口对")
}

// cleanupLoop 定期清理超时的中继会话
func (rm *RelayManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rm.mu.Lock()
		cutoff := time.Now().Add(-rm.idleTimeout)
		var expiredPorts []uint16
		var expiredCallIDs []string

		for port, relay := range rm.relays {
			if relay.LastActive.Before(cutoff) {
				expiredPorts = append(expiredPorts, port)
			}
		}

		// 从 byCallID 索引中也清除
		for _, port := range expiredPorts {
			if r, ok := rm.relays[port]; ok {
				delete(rm.relays, port)
				r.Stop()
				atomic.AddInt64(&rm.activeCount, -1)
				expiredCallIDs = append(expiredCallIDs, r.CallID)
				log.Printf("[RTPRelay] 超时释放: Call=%s, %s/%s, Port=%d, "+
					"存活 %s, 6→4: %d pkts, 4→6: %d pkts",
					r.CallID, r.MediaType, r.Proto, port,
					time.Since(r.CreatedAt).Round(time.Second),
					r.Packets6to4, r.Packets4to6)
			}
		}

		// 清理空的 callID 条目
		for _, cid := range expiredCallIDs {
			remaining := []*RelaySession{}
			for _, r := range rm.byCallID[cid] {
				if r.IsActive() {
					remaining = append(remaining, r)
				}
			}
			if len(remaining) == 0 {
				delete(rm.byCallID, cid)
			} else {
				rm.byCallID[cid] = remaining
			}
		}

		rm.mu.Unlock()
	}
}

// isTimeout 判断是否为网络超时错误
func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
