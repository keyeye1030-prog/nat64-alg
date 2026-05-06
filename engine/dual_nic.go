// +build linux

package engine

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/asavie/xdp"

	"nat64-alg/alg/rtp"
	"nat64-alg/nat64"
)

// ============================================================================
// 双臂双网卡引擎 (Mode B: Dual-NIC Engine)
//
// 部署拓扑:
//   eth0 (IPv6 侧) ←→ [NAT64 Engine] ←→ eth1 (IPv4 侧)
//
// 工作流程:
//   1. eth0 XDP 拦截 IPv6 包 → 翻译为 IPv4 → 从 eth1 TX 发出
//   2. eth1 XDP 拦截 IPv4 回包 → 翻译为 IPv6 → 从 eth0 TX 发出
//   3. RTP 中继在应用层通过 UDP socket 独立转发
//
// 优势:
//   - 无 hairpin: 翻译后的包从不同物理接口发送，避免回环
//   - 独立 MTU: IPv6 侧可保持 1500，IPv4 侧可配置不同 MTU
//   - 安全隔离: 两个网络域物理隔离，可分别配置防火墙
//   - 高吞吐: 两块网卡并行收发，理论吞吐翻倍
// ============================================================================

// DualNICEngine 双臂双网卡数据面引擎
type DualNICEngine struct {
	// IPv6 侧 (面向 IPv6-only 网络)
	iface6Name string
	program6   *xdp.Program
	xsk6       *xdp.Socket

	// IPv4 侧 (面向 IPv4 Internet)
	iface4Name string
	program4   *xdp.Program
	xsk4       *xdp.Socket

	// 核心组件
	translator   *nat64.Translator
	relayManager *rtp.RelayManager

	// 配置
	config DualNICConfig
}

// DualNICConfig 双网卡引擎配置
type DualNICConfig struct {
	IPv6Interface  string            // 面向 IPv6 网络的接口名 (如 eth0)
	IPv4Interface  string            // 面向 IPv4 网络的接口名 (如 eth1)
	PoolIPv4s      []net.IP          // NAT64 池地址 (多个 IPv4 出口默认地址)
	GatewayIPv6    net.IP            // 网关自身的 IPv6 地址 (用于 RTP 中继绑定)
	IPv4GatewayMAC net.HardwareAddr  // IPv4 侧下一跳网关 MAC
	IPv6GatewayMAC net.HardwareAddr  // IPv6 侧下一跳网关 MAC
	EnableARPProxy bool              // 是否在用户态响应 ARP 请求
	RTPPortStart   uint16            // RTP 中继端口范围起点
	RTPPortEnd     uint16            // RTP 中继端口范围终点
	SessionTTL     time.Duration
	StaticMappings map[string]net.IP // 一对一静态 IP 映射表 (IPv6 -> IPv4)
}

// NewDualNICEngine 创建双臂双网卡引擎
func NewDualNICEngine(config DualNICConfig) (*DualNICEngine, error) {
	// 验证 IPv6 侧网卡
	eth6, err := net.InterfaceByName(config.IPv6Interface)
	if err != nil {
		return nil, fmt.Errorf("找不到 IPv6 侧网卡 %s: %w", config.IPv6Interface, err)
	}
	log.Printf("[DualNIC] IPv6 侧网卡: %s (Index: %d, MTU: %d)", eth6.Name, eth6.Index, eth6.MTU)

	// 验证 IPv4 侧网卡
	eth4, err := net.InterfaceByName(config.IPv4Interface)
	if err != nil {
		return nil, fmt.Errorf("找不到 IPv4 侧网卡 %s: %w", config.IPv4Interface, err)
	}
	log.Printf("[DualNIC] IPv4 侧网卡: %s (Index: %d, MTU: %d)", eth4.Name, eth4.Index, eth4.MTU)

	// 默认值
	if config.SessionTTL == 0 {
		config.SessionTTL = 5 * time.Minute
	}
	if config.RTPPortStart == 0 {
		config.RTPPortStart = 20000
	}
	if config.RTPPortEnd == 0 {
		config.RTPPortEnd = 30000
	}

	// 初始化 AF_XDP - IPv6 侧
	program6, xsk6, err := setupXDPSocket(eth6, "IPv6")
	if err != nil {
		return nil, err
	}

	// 初始化 AF_XDP - IPv4 侧
	program4, xsk4, err := setupXDPSocket(eth4, "IPv4")
	if err != nil {
		cleanupXDP(program6, xsk6, eth6)
		return nil, err
	}

	// 初始化 NAT64 核心
	sessionTable := nat64.NewSessionTable(config.PoolIPv4s, 10000, 60000, config.SessionTTL)
	if config.StaticMappings != nil {
		sessionTable.SetStaticMappings(config.StaticMappings)
	}
	translator := nat64.NewTranslator(config.PoolIPv4s[0], sessionTable)

	// 配置二层 MAC 地址
	translator.MAC.GatewayMAC4 = config.IPv4GatewayMAC
	translator.MAC.GatewayMAC6 = config.IPv6GatewayMAC
	translator.MAC.LocalMAC6 = eth6.HardwareAddr
	translator.MAC.LocalMAC4 = eth4.HardwareAddr
	log.Printf("[DualNIC] MAC 配置:")
	log.Printf("  eth6 本机 MAC: %s", eth6.HardwareAddr)
	log.Printf("  eth4 本机 MAC: %s", eth4.HardwareAddr)
	log.Printf("  IPv6 网关 MAC: %s", config.IPv6GatewayMAC)
	log.Printf("  IPv4 网关 MAC: %s", config.IPv4GatewayMAC)

	// 初始化 RTP 中继
	relayMgr := rtp.NewRelayManager(
		config.GatewayIPv6,
		config.PoolIPv4s[0],
		config.RTPPortStart,
		config.RTPPortEnd,
	)

	engine := &DualNICEngine{
		iface6Name:   config.IPv6Interface,
		program6:     program6,
		xsk6:         xsk6,
		iface4Name:   config.IPv4Interface,
		program4:     program4,
		xsk4:         xsk4,
		translator:   translator,
		relayManager: relayMgr,
		config:       config,
	}

	// 启动后台清理
	go engine.sessionCleaner(sessionTable)

	log.Printf("[DualNIC] 引擎初始化完成")
	log.Printf("  IPv6 侧: %s (XDP FD=%d)", config.IPv6Interface, xsk6.FD())
	log.Printf("  IPv4 侧: %s (XDP FD=%d)", config.IPv4Interface, xsk4.FD())
	log.Printf("  Pool IPv4: %d addresses", len(config.PoolIPv4s))
	log.Printf("  RTP 端口: %d-%d", config.RTPPortStart, config.RTPPortEnd)

	return engine, nil
}

// setupXDPSocket 为指定网卡创建 XDP 程序和 AF_XDP socket
func setupXDPSocket(iface *net.Interface, label string) (*xdp.Program, *xdp.Socket, error) {
	program, err := xdp.NewProgram(1)
	if err != nil {
		return nil, nil, fmt.Errorf("[%s] 创建 XDP 程序失败: %w", label, err)
	}

	if err := program.Attach(iface.Index); err != nil {
		program.Close()
		return nil, nil, fmt.Errorf("[%s] 附着 XDP 程序到 %s 失败: %w", label, iface.Name, err)
	}

	xsk, err := xdp.NewSocket(iface.Index, 0, nil)
	if err != nil {
		program.Detach(iface.Index)
		program.Close()
		return nil, nil, fmt.Errorf("[%s] 创建 AF_XDP socket 失败: %w", label, err)
	}

	if err := program.Register(0, xsk.FD()); err != nil {
		xsk.Close()
		program.Detach(iface.Index)
		program.Close()
		return nil, nil, fmt.Errorf("[%s] 注册 AF_XDP socket 失败: %w", label, err)
	}

	log.Printf("[DualNIC-%s] AF_XDP socket 就绪 (FD=%d)", label, xsk.FD())
	return program, xsk, nil
}

// cleanupXDP 清理 XDP 资源
func cleanupXDP(program *xdp.Program, xsk *xdp.Socket, iface *net.Interface) {
	if xsk != nil {
		xsk.Close()
	}
	if program != nil {
		program.Detach(iface.Index)
		program.Close()
	}
}

// Start 启动双向数据包处理循环
func (e *DualNICEngine) Start() {
	log.Println("[DualNIC] 启动双向数据帧处理...")

	// 两个独立的 goroutine 分别处理两个方向
	go e.pollIPv6Side()
	go e.pollIPv4Side()

	// 阻塞: 调用方应在独立 goroutine 中调用 Start()
	select {}
}

// pollIPv6Side 轮询 IPv6 侧网卡, 处理 6→4 方向
func (e *DualNICEngine) pollIPv6Side() {
	log.Printf("[DualNIC] IPv6 侧 (%s) 轮询已启动", e.iface6Name)
	fillXSKRing(e.xsk6)

	for {
		_, _, err := e.xsk6.Poll(-1)
		if err != nil {
			log.Printf("[DualNIC-IPv6] Poll 错误: %v", err)
			continue
		}

		numRx := e.xsk6.NumReceived()
		if numRx > 0 {
			rxDescs := e.xsk6.Receive(numRx)
			for i := range rxDescs {
				frame := e.xsk6.GetFrame(rxDescs[i])
				frameLen := int(rxDescs[i].Len)
				if frameLen == 0 || frameLen > len(frame) {
					continue
				}
				frameCopy := make([]byte, frameLen)
				copy(frameCopy, frame[:frameLen])
				e.processIPv6Frame(frameCopy)
			}
			fillXSKRing(e.xsk6)
		}

		numComp := e.xsk6.NumCompleted()
		if numComp > 0 {
			e.xsk6.Complete(numComp)
		}
	}
}

// pollIPv4Side 轮询 IPv4 侧网卡, 处理 4→6 方向
func (e *DualNICEngine) pollIPv4Side() {
	log.Printf("[DualNIC] IPv4 侧 (%s) 轮询已启动", e.iface4Name)
	fillXSKRing(e.xsk4)

	for {
		_, _, err := e.xsk4.Poll(-1)
		if err != nil {
			log.Printf("[DualNIC-IPv4] Poll 错误: %v", err)
			continue
		}

		numRx := e.xsk4.NumReceived()
		if numRx > 0 {
			rxDescs := e.xsk4.Receive(numRx)
			for i := range rxDescs {
				frame := e.xsk4.GetFrame(rxDescs[i])
				frameLen := int(rxDescs[i].Len)
				if frameLen == 0 || frameLen > len(frame) {
					continue
				}
				frameCopy := make([]byte, frameLen)
				copy(frameCopy, frame[:frameLen])
				e.processIPv4Frame(frameCopy)
			}
			fillXSKRing(e.xsk4)
		}

		numComp := e.xsk4.NumCompleted()
		if numComp > 0 {
			e.xsk4.Complete(numComp)
		}
	}
}

// fillXSKRing 将可用描述符填入 XSK 的 Fill Ring
func fillXSKRing(xsk *xdp.Socket) {
	n := xsk.NumFreeFillSlots()
	if n == 0 {
		return
	}
	descs := xsk.GetDescs(n)
	for i := range descs {
		descs[i].Len = 0
	}
	xsk.Fill(descs)
}

// sendToXSK 将帧写入指定 XSK 的 TX 队列
func sendToXSK(xsk *xdp.Socket, frame []byte) {
	if xsk.NumFreeTxSlots() < 1 {
		return
	}
	descs := xsk.GetDescs(1)
	if len(descs) < 1 {
		return
	}
	txFrame := xsk.GetFrame(descs[0])
	n := copy(txFrame, frame)
	descs[0].Len = uint32(n)
	xsk.Transmit(descs)
}

// processIPv6Frame 处理从 IPv6 侧收到的帧
func (e *DualNICEngine) processIPv6Frame(frame []byte) {
	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		return
	}

	switch result.Direction {
	case nat64.Dir6to4:
		// 翻译后的 IPv4 帧从 IPv4 侧网卡发出
		sendToXSK(e.xsk4, result.OutputFrame)
	case nat64.DirPassthrough:
		// 非 NAT64 流量: 放行 (在 XDP 层已放行给内核, 此处不需额外处理)
	}
}

// processIPv4Frame 处理从 IPv4 侧收到的帧
func (e *DualNICEngine) processIPv4Frame(frame []byte) {
	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		return
	}

	switch result.Direction {
	case nat64.Dir4to6:
		// 翻译后的 IPv6 帧从 IPv6 侧网卡发出
		sendToXSK(e.xsk6, result.OutputFrame)
	case nat64.DirPassthrough:
		// 非 NAT64 流量: 放行
	}
}

// Close 释放所有资源
func (e *DualNICEngine) Close() {
	// IPv6 侧
	if e.xsk6 != nil {
		e.xsk6.Close()
	}
	if e.program6 != nil {
		iface6, err := net.InterfaceByName(e.iface6Name)
		if err == nil {
			e.program6.Detach(iface6.Index)
		}
		e.program6.Close()
	}

	// IPv4 侧
	if e.xsk4 != nil {
		e.xsk4.Close()
	}
	if e.program4 != nil {
		iface4, err := net.InterfaceByName(e.iface4Name)
		if err == nil {
			e.program4.Detach(iface4.Index)
		}
		e.program4.Close()
	}

	active, relayed := e.relayManager.Stats()
	log.Printf("[DualNIC] 关闭. 统计: 6→4=%d, 4→6=%d, 丢弃=%d, RTP中继=%d (累计转发=%d包)",
		e.translator.Pkts6to4, e.translator.Pkts4to6,
		e.translator.PktsDropped, active, relayed)
}

// GetTranslator 暴露翻译器供外部使用
func (e *DualNICEngine) GetTranslator() *nat64.Translator {
	return e.translator
}

// GetRelayManager 暴露 RTP 中继管理器
func (e *DualNICEngine) GetRelayManager() *rtp.RelayManager {
	return e.relayManager
}

// sessionCleaner 定期清理过期的 NAT64 会话
func (e *DualNICEngine) sessionCleaner(table *nat64.SessionTable) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cleaned := table.CleanExpired()
		active, _ := e.relayManager.Stats()
		if cleaned > 0 {
			log.Printf("[SessionCleaner] 清除 %d 条过期会话, 剩余: %d, RTP 中继: %d",
				cleaned, table.Stats(), active)
		}
	}
}
