//go:build linux
// +build linux

package engine

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

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
	link6      link.Link
	coll6      *ebpf.Collection
	xsk6       *xdp.Socket

	// IPv4 侧 (面向 IPv4 Internet)
	iface4Name string
	link4      link.Link
	coll4      *ebpf.Collection
	xsk4       *xdp.Socket

	// 原始 AF_PACKET TX 套接字 (替代 AF_XDP TX, 兼容 Generic XDP 模式)
	txFd6    int
	txFd4    int
	ifIndex6 int
	ifIndex4 int

	// 核心组件
	translator   *nat64.Translator
	relayManager *rtp.RelayManager

	// 配置
	config DualNICConfig
}

// DualNICConfig 双网卡引擎配置
type DualNICConfig struct {
	IPv6Interface  string           // 面向 IPv6 网络的接口名 (如 eth0)
	IPv4Interface  string           // 面向 IPv4 网络的接口名 (如 eth1)
	PoolIPv4s      []net.IP         // NAT64 池地址 (多个 IPv4 出口默认地址)
	GatewayIPv6    net.IP           // 网关自身的 IPv6 地址 (用于 RTP 中继绑定)
	IPv6Gateway    net.IP           // IPv6 默认网关地址 (用于从系统邻居表动态查找其 MAC)
	IPv4GatewayMAC net.HardwareAddr // IPv4 侧下一跳网关 MAC
	IPv6GatewayMAC net.HardwareAddr // IPv6 侧下一跳网关 MAC
	EnableARPProxy bool             // 是否在用户态响应 ARP 请求
	RTPPortStart   uint16           // RTP 中继端口范围起点
	RTPPortEnd     uint16           // RTP 中继端口范围终点
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
	link6, coll6, xsk6, err := setupXDPSocket(eth6, "IPv6")
	if err != nil {
		return nil, err
	}

	// 初始化 AF_XDP - IPv4 侧
	link4, coll4, xsk4, err := setupXDPSocket(eth4, "IPv4")
	if err != nil {
		if link6 != nil {
			link6.Close()
		}
		if coll6 != nil {
			coll6.Close()
		}
		if xsk6 != nil {
			xsk6.Close()
		}
		return nil, err
	}

	// 初始化 Dynamic Prefix Map (用于 IPv6 侧 XDP 过滤)
	prefixMap := coll6.Maps["prefix_map"]
	if prefixMap != nil {
		var prefixBytes [4]uint32
		prefixV6 := nat64.WellKnownPrefix.To16()
		if prefixV6 != nil {
			prefixBytes[0] = uint32(prefixV6[0]) | uint32(prefixV6[1])<<8 | uint32(prefixV6[2])<<16 | uint32(prefixV6[3])<<24
			prefixBytes[1] = uint32(prefixV6[4]) | uint32(prefixV6[5])<<8 | uint32(prefixV6[6])<<16 | uint32(prefixV6[7])<<24
			prefixBytes[2] = uint32(prefixV6[8]) | uint32(prefixV6[9])<<8 | uint32(prefixV6[10])<<16 | uint32(prefixV6[11])<<24
			prefixBytes[3] = uint32(prefixV6[12]) | uint32(prefixV6[13])<<8 | uint32(prefixV6[14])<<16 | uint32(prefixV6[15])<<24

			key := uint32(0)
			prefixMap.Update(&key, &prefixBytes, ebpf.UpdateAny)
			log.Printf("[DualNIC] 已同步 IPv6 侧 NAT64 Prefix %s 到 BPF Map", nat64.WellKnownPrefix)
		}
	}

	// 初始化 Local IPv6 Map (用于 NDP 代理应答)
	localIP6Map := coll6.Maps["local_ip6"]
	if localIP6Map != nil && config.GatewayIPv6 != nil {
		gwV6 := config.GatewayIPv6.To16()
		if gwV6 != nil {
			var localBytes [4]uint32
			localBytes[0] = uint32(gwV6[0]) | uint32(gwV6[1])<<8 | uint32(gwV6[2])<<16 | uint32(gwV6[3])<<24
			localBytes[1] = uint32(gwV6[4]) | uint32(gwV6[5])<<8 | uint32(gwV6[6])<<16 | uint32(gwV6[7])<<24
			localBytes[2] = uint32(gwV6[8]) | uint32(gwV6[9])<<8 | uint32(gwV6[10])<<16 | uint32(gwV6[11])<<24
			localBytes[3] = uint32(gwV6[12]) | uint32(gwV6[13])<<8 | uint32(gwV6[14])<<16 | uint32(gwV6[15])<<24
			key := uint32(0)
			localIP6Map.Update(&key, &localBytes, ebpf.UpdateAny)
			log.Printf("[DualNIC] 已同步本机 IPv6 地址 %s 到 NDP 代理 BPF Map", config.GatewayIPv6)
		}
	}

	// 初始化 Pool IPv4 Map (用于 IPv4 侧 XDP 过滤)
	poolMap := coll4.Maps["pool_ips"]
	if poolMap != nil {
		for _, ip := range config.PoolIPv4s {
			v4 := ip.To4()
			if v4 != nil {
				ipInt := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
				val := uint32(1)
				poolMap.Update(&ipInt, &val, ebpf.UpdateAny)
				log.Printf("[DualNIC] 已同步 Pool IP %s 到 IPv4 侧 BPF Map", ip)
			}
		}
		for _, ip := range config.StaticMappings {
			v4 := ip.To4()
			if v4 != nil {
				ipInt := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
				val := uint32(1)
				poolMap.Update(&ipInt, &val, ebpf.UpdateAny)
				log.Printf("[DualNIC] 已同步 静态映射 IP %s 到 IPv4 侧 BPF Map", ip)
			}
		}
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

	// 如果未配置静态 IPv6 网关 MAC，但提供了 IPv6 网关 IP 地址，则从系统邻居表中自动查询并填充！
	if len(translator.MAC.GatewayMAC6) == 0 && config.IPv6Gateway != nil {
		macStr := lookupNeighborMAC(config.IPv6Gateway.String())
		if macStr != "" {
			mac, err := net.ParseMAC(macStr)
			if err == nil {
				translator.MAC.GatewayMAC6 = mac
				log.Printf("[DualNIC] 💡 自动从系统邻居表获取到 IPv6 网关 (%s) MAC: %s", config.IPv6Gateway, mac)
			} else {
				log.Printf("[DualNIC] 解析自动获取到的 IPv6 网关 MAC [%s] 失败: %v", macStr, err)
			}
		} else {
			log.Printf("[DualNIC] ⚠️ 未能从系统邻居表获取到 IPv6 网关 (%s) MAC 地址，将回退为从首包动态学习", config.IPv6Gateway)
		}
	}

	log.Printf("[DualNIC] MAC 配置:")
	log.Printf("  eth6 本机 MAC: %s", eth6.HardwareAddr)
	log.Printf("  eth4 本机 MAC: %s", eth4.HardwareAddr)
	log.Printf("  IPv6 网关 MAC: %s", translator.MAC.GatewayMAC6)
	log.Printf("  IPv4 网关 MAC: %s", translator.MAC.GatewayMAC4)

	// 初始化 RTP 中继
	relayMgr := rtp.NewRelayManager(
		config.GatewayIPv6,
		config.PoolIPv4s[0],
		config.RTPPortStart,
		config.RTPPortEnd,
	)

	// 创建 AF_PACKET 原始发送套接字 (替代 AF_XDP TX, 避免 Generic 模式 EINVAL)
	txFd6, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("创建 IPv6 侧 TX 原始套接字失败: %w", err)
	}
	txFd4, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		syscall.Close(txFd6)
		return nil, fmt.Errorf("创建 IPv4 侧 TX 原始套接字失败: %w", err)
	}
	log.Printf("[DualNIC] 已创建 AF_PACKET 原始 TX 套接字 (fd6=%d, fd4=%d)", txFd6, txFd4)

	engine := &DualNICEngine{
		iface6Name:   config.IPv6Interface,
		link6:        link6,
		coll6:        coll6,
		xsk6:         xsk6,
		iface4Name:   config.IPv4Interface,
		link4:        link4,
		coll4:        coll4,
		xsk4:         xsk4,
		txFd6:        txFd6,
		txFd4:        txFd4,
		ifIndex6:     eth6.Index,
		ifIndex4:     eth4.Index,
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

// setupXDPSocket 加载自定义 eBPF 程序并附着到特定网卡
func setupXDPSocket(iface *net.Interface, label string) (link.Link, *ebpf.Collection, *xdp.Socket, error) {
	// 1. 加载自定义 eBPF 字节码 (nat64.o)
	spec, err := ebpf.LoadCollectionSpec("nat64.o")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("[%s] 加载 nat64.o 失败: %w", label, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("[%s] 创建 eBPF Collection 失败: %w", label, err)
	}

	prog := coll.Programs["xdp_nat64_func"]
	if prog == nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("[%s] 找不到 xdp_nat64_func 程序", label)
	}

	// 2. 附着到网卡 (使用 Generic XDP 模式确保虚拟机网络完全兼容)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("[%s] 附着 XDP 程序失败: %w", label, err)
	}

	// 3. 创建 AF_XDP socket (通过 UMEM 接收 XDP 重定向包)
	xsk, err := xdp.NewSocket(iface.Index, 0, nil)
	if err != nil {
		l.Close()
		coll.Close()
		return nil, nil, nil, fmt.Errorf("[%s] 创建 AF_XDP socket 失败: %w", label, err)
	}

	// 4. 将 Socket FD 注册到 eBPF xsks_map 中
	xsksMap := coll.Maps["xsks_map"]
	if xsksMap == nil {
		xsk.Close()
		l.Close()
		coll.Close()
		return nil, nil, nil, fmt.Errorf("[%s] 找不到 xsks_map", label)
	}
	fd := uint32(xsk.FD())
	key := uint32(0)
	if err := xsksMap.Update(&key, &fd, ebpf.UpdateAny); err != nil {
		xsk.Close()
		l.Close()
		coll.Close()
		return nil, nil, nil, fmt.Errorf("[%s] 更新 xsks_map 失败: %w", label, err)
	}

	log.Printf("[DualNIC-%s] 自定义 XDP 附着成功 (AF_XDP FD=%d)", label, xsk.FD())
	return l, coll, xsk, nil
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

// sendRawFrame 通过 AF_PACKET 原始套接字发送以太网帧
func sendRawFrame(fd int, ifIndex int, frame []byte) {
	addr := syscall.SockaddrLinklayer{
		Ifindex: ifIndex,
	}
	err := syscall.Sendto(fd, frame, 0, &addr)
	if err != nil {
		log.Printf("[TX] 发送失败 (ifIndex=%d, len=%d): %v", ifIndex, len(frame), err)
	}
}

// htons 主机字节序转网络字节序 (16-bit)
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}

// processIPv6Frame 处理从 IPv6 侧收到的帧
func (e *DualNICEngine) processIPv6Frame(frame []byte) {
	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		// log.Printf("[6→4] 翻译错误 (帧长%d): %v", len(frame), result.Error)
		return
	}

	switch result.Direction {
	case nat64.Dir6to4:
		// log.Printf("[6→4] ✅ 翻译成功 → 发送 %d 字节到 IPv4 侧", len(result.OutputFrame))
		// 翻译后的 IPv4 帧从 IPv4 侧网卡发出
		sendRawFrame(e.txFd4, e.ifIndex4, result.OutputFrame)
	case nat64.DirPassthrough:
		// 非 NAT64 流量: 放行 (在 XDP 层已放行给内核, 此处不需额外处理)
	}
}

// processIPv4Frame 处理从 IPv4 侧收到的帧
func (e *DualNICEngine) processIPv4Frame(frame []byte) {
	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		// log.Printf("[4→6] 翻译错误 (帧长%d): %v", len(frame), result.Error)
		return
	}

	switch result.Direction {
	case nat64.Dir4to6:
		// log.Printf("[4→6] ✅ 翻译成功 → 发送 %d 字节到 IPv6 侧", len(result.OutputFrame))
		// 翻译后的 IPv6 帧从 IPv6 侧网卡发出
		sendRawFrame(e.txFd6, e.ifIndex6, result.OutputFrame)
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
	if e.link6 != nil {
		e.link6.Close()
	}
	if e.coll6 != nil {
		e.coll6.Close()
	}

	// IPv4 侧
	if e.xsk4 != nil {
		e.xsk4.Close()
	}
	if e.link4 != nil {
		e.link4.Close()
	}
	if e.coll4 != nil {
		e.coll4.Close()
	}

	// TX 原始套接字
	if e.txFd6 > 0 {
		syscall.Close(e.txFd6)
	}
	if e.txFd4 > 0 {
		syscall.Close(e.txFd4)
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

// lookupNeighborMAC 从宿主机 Linux 内核的邻居缓存表中自动查询指定 IP 的 MAC 地址
func lookupNeighborMAC(ipStr string) string {
	// 执行 ip neighbor show <ip>
	cmd := exec.Command("ip", "neighbor", "show", ipStr)
	output, err := cmd.Output()
	if err == nil {
		fields := strings.Fields(string(output))
		for i, f := range fields {
			if (f == "lladdr" || f == "lladdress") && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}

	// 如果没有查询到，尝试发送一个 ICMPv6 报文/Ping 来触发内核 ARP/NDP 解析，然后再查一次！
	// 在 Linux 上我们可以用 ping -c 1 -W 1 <ip> 触发
	exec.Command("ping", "-c", "1", "-W", "1", ipStr).Run()

	// 再次尝试获取
	cmd2 := exec.Command("ip", "neighbor", "show", ipStr)
	output2, err2 := cmd2.Output()
	if err2 == nil {
		fields2 := strings.Fields(string(output2))
		for i, f := range fields2 {
			if (f == "lladdr" || f == "lladdress") && i+1 < len(fields2) {
				return fields2[i+1]
			}
		}
	}

	return ""
}
