package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"nat64-alg/engine"
	"nat64-alg/nat64"
)

type Config struct {
	Mode           string   `json:"mode"`
	PoolIPv4s      []string `json:"pool_ipv4s"`
	NAT64Prefix    string   `json:"nat64_prefix"`     // 自定义 NAT64 前缀
	Interface      string   `json:"interface"`        // 单臂模式下使用的网卡
	IfaceIPv6      string   `json:"iface_ipv6"`       // 双臂模式 IPv6侧网卡
	IfaceIPv4      string   `json:"iface_ipv4"`       // 双臂模式 IPv4侧网卡
	GwIPv6         string   `json:"gw_ipv6"`          // 网关IPv6地址
	IPv6Gateway    string   `json:"ipv6_gateway"`     // IPv6 默认网关地址
	IPv4GatewayMAC string   `json:"ipv4_gateway_mac"` // IPv4 侧网关 MAC 地址
	IPv6GatewayMAC string   `json:"ipv6_gateway_mac"` // IPv6 侧网关 MAC 地址
	EnableARPProxy bool     `json:"enable_arp_proxy"` // 是否开启 ARP 代理
	RTPPortStart   uint     `json:"rtp_port_start"`   // 中继端口范围起点
	RTPPortEnd     uint     `json:"rtp_port_end"`     // 中继端口范围终点
	StaticMaps     map[string]string `json:"static_mappings"` // 一对一静态 IP 映射 (IPv6 -> IPv4)
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "Path to config.json. If provided, overrides other CLI flags.")

	// Default CLI flags
	mode := flag.String("mode", "single", "部署模式: single (单臂) 或 dual (双臂双网卡)")
	poolIP := flag.String("pool-ipv4", "198.51.100.1", "NAT64 网关的 IPv4 出口地址")
	nat64Prefix := flag.String("nat64-prefix", "", "自定义 NAT64 IPv6 前缀 (例如 240C:C0A9:100F:1::/96)")
	iface := flag.String("interface", "eth0", "[单臂模式] 网卡名称")
	iface6 := flag.String("iface-ipv6", "eth0", "[双臂模式] IPv6 侧网卡名称")
	iface4 := flag.String("iface-ipv4", "eth1", "[双臂模式] IPv4 侧网卡名称")
	gwIPv6 := flag.String("gw-ipv6", "", "[双臂模式] 网关 IPv6 地址 (用于 RTP 中继绑定)")
	ipv6Gateway := flag.String("ipv6-gateway", "", "[双臂模式] IPv6 默认网关地址 (如 1111::1)")
	rtpStart := flag.Uint("rtp-port-start", 20000, "[双臂模式] RTP 中继端口起始")
	rtpEnd := flag.Uint("rtp-port-end", 30000, "[双臂模式] RTP 中继端口结束")

	flag.Parse()

	cfg := Config{
		Mode:         *mode,
		NAT64Prefix:  *nat64Prefix,
		Interface:    *iface,
		IfaceIPv6:    *iface6,
		IfaceIPv4:    *iface4,
		GwIPv6:       *gwIPv6,
		IPv6Gateway:  *ipv6Gateway,
		RTPPortStart: *rtpStart,
		RTPPortEnd:   *rtpEnd,
	}
	if *poolIP != "" {
		cfg.PoolIPv4s = []string{*poolIP}
	}

	// 提前引入 nat64 包来进行前缀设置
	if cfgPath != "" {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			log.Fatalf("无法读取配置文件: %v", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("无法解析配置文件: %v", err)
		}
		log.Printf("Loaded configuration from %s", cfgPath)
	}

	// 设置自定义 NAT64 前缀
	if cfg.NAT64Prefix != "" {
		ip, _, err := net.ParseCIDR(cfg.NAT64Prefix)
		if err != nil {
			ip = net.ParseIP(cfg.NAT64Prefix)
			if ip == nil {
				log.Fatalf("无效的 NAT64 前缀: %s", cfg.NAT64Prefix)
			}
		}
		// 动态导入 nat64 包
		var _ = nat64.WellKnownPrefix
		nat64.SetNAT64Prefix(ip)
		log.Printf("  NAT64 Prefix: %s (Embeds IPv4 in last 32 bits)", ip)
	} else {
		log.Printf("  NAT64 Prefix: %s (Standard Well-Known Prefix)", nat64.WellKnownPrefix)
	}

	var poolIPv4s []net.IP
	for _, ipStr := range cfg.PoolIPv4s {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			log.Fatalf("无效的 IPv4 地址: %s", ipStr)
		}
		poolIPv4s = append(poolIPv4s, ip)
	}
	if len(poolIPv4s) == 0 {
		log.Fatalf("必须配置至少一个 Pool IPv4 地址")
	}

	log.Printf("======================================")
	log.Printf("  NAT64-ALG Engine")
	log.Printf("  Mode     : %s", cfg.Mode)
	log.Printf("  Pool IPv4: %d IPs loaded", len(poolIPv4s))
	log.Printf("======================================")

	switch cfg.Mode {
	case "single":
		startSingleMode(cfg.Interface, poolIPv4s)
	case "dual":
		startDualMode(cfg, poolIPv4s)
	default:
		log.Fatalf("未知的部署模式: %s (支持: single, dual)", cfg.Mode)
	}
}

// startSingleMode 启动单臂模式 (原有模式)
func startSingleMode(ifaceName string, poolIPv4s []net.IP) {
	log.Printf("  Interface: %s", ifaceName)

	xdpEngine, err := engine.NewXDPEngine(ifaceName, poolIPv4s[0]) // single mode may only fully support first IP in XDP currently
	if err != nil {
		log.Fatalf("Failed to init XDP engine: %v", err)
	}
	defer xdpEngine.Close()

	go xdpEngine.Start()

	waitForShutdown()
}

// startDualMode 启动双臂双网卡模式
func startDualMode(cfg Config, poolIPv4s []net.IP) {
	log.Printf("  IPv6 NIC : %s", cfg.IfaceIPv6)
	log.Printf("  IPv4 NIC : %s", cfg.IfaceIPv4)
	log.Printf("  RTP Ports: %d-%d", cfg.RTPPortStart, cfg.RTPPortEnd)

	var gatewayIPv6 net.IP
	if cfg.GwIPv6 != "" {
		gatewayIPv6 = net.ParseIP(cfg.GwIPv6)
		if gatewayIPv6 == nil {
			log.Fatalf("无效的 IPv6 地址: %s", cfg.GwIPv6)
		}
		log.Printf("  GW IPv6  : %s", gatewayIPv6)
	}

	var ipv6Gateway net.IP
	if cfg.IPv6Gateway != "" {
		ipv6Gateway = net.ParseIP(cfg.IPv6Gateway)
		if ipv6Gateway == nil {
			log.Fatalf("无效的 IPv6 默认网关地址: %s", cfg.IPv6Gateway)
		}
		log.Printf("  IPv6 Gateway IP: %s", ipv6Gateway)
	}

	// 解析网关 MAC 地址
	var ipv4GwMAC, ipv6GwMAC net.HardwareAddr
	if cfg.IPv4GatewayMAC != "" {
		var err error
		ipv4GwMAC, err = net.ParseMAC(cfg.IPv4GatewayMAC)
		if err != nil {
			log.Fatalf("无效的 IPv4 网关 MAC: %s (%v)", cfg.IPv4GatewayMAC, err)
		}
		log.Printf("  IPv4 GW MAC: %s", ipv4GwMAC)
	} else {
		log.Println("  ⚠️  未配置 ipv4_gateway_mac, 将使用广播 MAC (ff:ff:ff:ff:ff:ff)")
		ipv4GwMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	}
	if cfg.IPv6GatewayMAC != "" {
		var err error
		ipv6GwMAC, err = net.ParseMAC(cfg.IPv6GatewayMAC)
		if err != nil {
			log.Fatalf("无效的 IPv6 网关 MAC: %s (%v)", cfg.IPv6GatewayMAC, err)
		}
		log.Printf("  IPv6 GW MAC: %s", ipv6GwMAC)
	} else {
		log.Println("  ⚠️  未配置 ipv6_gateway_mac, 将尝试从系统邻居表自动获取或从首包动态学习")
	}

	staticIPs := make(map[string]net.IP)
	for ip6, ip4 := range cfg.StaticMaps {
		parsed6 := net.ParseIP(ip6)
		parsed4 := net.ParseIP(ip4).To4()
		if parsed6 != nil && parsed4 != nil {
			staticIPs[parsed6.To16().String()] = parsed4
		} else {
			log.Printf("警告: 无效的静态映射配置 - [%s] -> [%s]", ip6, ip4)
		}
	}
	if len(staticIPs) > 0 {
		log.Printf("  Static Map : %d rules loaded", len(staticIPs))
	}

	config := engine.DualNICConfig{
		IPv6Interface:  cfg.IfaceIPv6,
		IPv4Interface:  cfg.IfaceIPv4,
		PoolIPv4s:      poolIPv4s,
		GatewayIPv6:    gatewayIPv6,
		IPv6Gateway:    ipv6Gateway,
		IPv4GatewayMAC: ipv4GwMAC,
		IPv6GatewayMAC: ipv6GwMAC,
		EnableARPProxy: cfg.EnableARPProxy,
		RTPPortStart:   uint16(cfg.RTPPortStart),
		RTPPortEnd:     uint16(cfg.RTPPortEnd),
		StaticMappings: staticIPs,
	}

	dualEngine, err := engine.NewDualNICEngine(config)
	if err != nil {
		log.Fatalf("Failed to init Dual-NIC engine: %v", err)
	}
	defer dualEngine.Close()

	go dualEngine.Start()

	waitForShutdown()
}

// waitForShutdown 阻塞等待中断信号
func waitForShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down, releasing resources...")
}
