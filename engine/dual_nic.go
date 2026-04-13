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
	IPv6Interface string // 面向 IPv6 网络的接口名 (如 eth0)
	IPv4Interface string // 面向 IPv4 网络的接口名 (如 eth1)
	PoolIPv4      net.IP // NAT64 池地址 (IPv4 出口地址)
	GatewayIPv6   net.IP // 网关自身的 IPv6 地址 (用于 RTP 中继绑定)
	RTPPortStart  uint16 // RTP 中继端口范围起点
	RTPPortEnd    uint16 // RTP 中继端口范围终点
	SessionTTL    time.Duration
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

	// 初始化 NAT64 核心
	sessionTable := nat64.NewSessionTable(config.PoolIPv4, 10000, 60000, config.SessionTTL)
	translator := nat64.NewTranslator(config.PoolIPv4, sessionTable)

	// 初始化 RTP 中继
	relayMgr := rtp.NewRelayManager(
		config.GatewayIPv6,
		config.PoolIPv4,
		config.RTPPortStart,
		config.RTPPortEnd,
	)

	engine := &DualNICEngine{
		iface6Name:   config.IPv6Interface,
		iface4Name:   config.IPv4Interface,
		translator:   translator,
		relayManager: relayMgr,
		config:       config,
	}

	// 启动后台清理
	go engine.sessionCleaner(sessionTable)

	log.Printf("[DualNIC] 引擎初始化完成")
	log.Printf("  IPv6 侧: %s", config.IPv6Interface)
	log.Printf("  IPv4 侧: %s", config.IPv4Interface)
	log.Printf("  Pool IPv4: %s", config.PoolIPv4)
	log.Printf("  RTP 端口: %d-%d", config.RTPPortStart, config.RTPPortEnd)

	return engine, nil
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

	// TODO: 真实实现中从 xsk6 的 RX ring 读取
	// for {
	//     n := e.xsk6.NumReceived()
	//     if n > 0 {
	//         rxDescs := e.xsk6.Receive(n)
	//         for _, desc := range rxDescs {
	//             frame := e.xsk6.GetFrame(desc)
	//             e.processIPv6Frame(frame)
	//         }
	//     }
	//     e.xsk6.Poll(-1)
	// }
}

// pollIPv4Side 轮询 IPv4 侧网卡, 处理 4→6 方向
func (e *DualNICEngine) pollIPv4Side() {
	log.Printf("[DualNIC] IPv4 侧 (%s) 轮询已启动", e.iface4Name)

	// TODO: 真实实现中从 xsk4 的 RX ring 读取
	// for {
	//     n := e.xsk4.NumReceived()
	//     if n > 0 {
	//         rxDescs := e.xsk4.Receive(n)
	//         for _, desc := range rxDescs {
	//             frame := e.xsk4.GetFrame(desc)
	//             e.processIPv4Frame(frame)
	//         }
	//     }
	//     e.xsk4.Poll(-1)
	// }
}

// processIPv6Frame 处理从 IPv6 侧收到的帧
func (e *DualNICEngine) processIPv6Frame(frame []byte) {
	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		log.Printf("[DualNIC-6to4] %v", result.Error)
		return
	}

	switch result.Direction {
	case nat64.Dir6to4:
		// 翻译后的 IPv4 帧从 IPv4 侧网卡发出
		e.sendToIPv4Side(result.OutputFrame)
	case nat64.DirPassthrough:
		// 非 NAT64 流量: 放行回 IPv6 侧内核协议栈
		// XDP_PASS
	}
}

// processIPv4Frame 处理从 IPv4 侧收到的帧
func (e *DualNICEngine) processIPv4Frame(frame []byte) {
	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		log.Printf("[DualNIC-4to6] %v", result.Error)
		return
	}

	switch result.Direction {
	case nat64.Dir4to6:
		// 翻译后的 IPv6 帧从 IPv6 侧网卡发出
		e.sendToIPv6Side(result.OutputFrame)
	case nat64.DirPassthrough:
		// 非 NAT64 流量: 放行回 IPv4 侧内核协议栈
	}
}

// sendToIPv4Side 将帧写入 IPv4 侧网卡的 TX 队列
func (e *DualNICEngine) sendToIPv4Side(frame []byte) {
	// TODO: 真实实现中调用 e.xsk4 的 TX 接口
	// desc := e.xsk4.GetFreeTxDesc()
	// copy(e.xsk4.GetFrame(desc), frame)
	// e.xsk4.Transmit(desc)
	_ = frame
}

// sendToIPv6Side 将帧写入 IPv6 侧网卡的 TX 队列
func (e *DualNICEngine) sendToIPv6Side(frame []byte) {
	// TODO: 真实实现中调用 e.xsk6 的 TX 接口
	_ = frame
}

// Close 释放所有资源
func (e *DualNICEngine) Close() {
	if e.xsk6 != nil {
		e.xsk6.Close()
	}
	if e.xsk4 != nil {
		e.xsk4.Close()
	}
	if e.program6 != nil {
		e.program6.Close()
	}
	if e.program4 != nil {
		e.program4.Close()
	}

	active, relayed := e.relayManager.Stats()
	log.Printf("[DualNIC] 关闭. 活跃会话: %d, RTP 中继: %d (累计转发: %d 包)",
		e.translator.SessionTable.Stats(), active, relayed)
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
		if cleaned > 0 {
			active, _ := e.relayManager.Stats()
			log.Printf("[SessionCleaner] 清除 %d 条过期会话, 剩余: %d, RTP 中继: %d",
				cleaned, table.Stats(), active)
		}
	}
}
