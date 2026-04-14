package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"nat64-alg/engine"
)

type Config struct {
	Mode         string   `json:"mode"`
	PoolIPv4s    []string `json:"pool_ipv4s"`
	Interface    string   `json:"interface"`      // 单臂模式下使用的网卡
	IfaceIPv6    string `json:"iface_ipv6"`     // 双臂模式 IPv6侧网卡
	IfaceIPv4    string `json:"iface_ipv4"`     // 双臂模式 IPv4侧网卡
	GwIPv6       string `json:"gw_ipv6"`        // 网关IPv6地址
	RTPPortStart uint   `json:"rtp_port_start"` // 中继端口范围起点
	RTPPortEnd   uint   `json:"rtp_port_end"`   // 中继端口范围终点
	StaticMaps   map[string]string `json:"static_mappings"` // 一对一静态 IP 映射 (IPv6 -> IPv4)
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "Path to config.json. If provided, overrides other CLI flags.")

	// Default CLI flags
	mode := flag.String("mode", "single", "部署模式: single (单臂) 或 dual (双臂双网卡)")
	poolIP := flag.String("pool-ipv4", "198.51.100.1", "NAT64 网关的 IPv4 出口地址")
	iface := flag.String("interface", "eth0", "[单臂模式] 网卡名称")
	iface6 := flag.String("iface-ipv6", "eth0", "[双臂模式] IPv6 侧网卡名称")
	iface4 := flag.String("iface-ipv4", "eth1", "[双臂模式] IPv4 侧网卡名称")
	gwIPv6 := flag.String("gw-ipv6", "", "[双臂模式] 网关 IPv6 地址 (用于 RTP 中继绑定)")
	rtpStart := flag.Uint("rtp-port-start", 20000, "[双臂模式] RTP 中继端口起始")
	rtpEnd := flag.Uint("rtp-port-end", 30000, "[双臂模式] RTP 中继端口结束")

	flag.Parse()

	cfg := Config{
		Mode:         *mode,
		Interface:    *iface,
		IfaceIPv6:    *iface6,
		IfaceIPv4:    *iface4,
		GwIPv6:       *gwIPv6,
		RTPPortStart: *rtpStart,
		RTPPortEnd:   *rtpEnd,
	}
	if *poolIP != "" {
		cfg.PoolIPv4s = []string{*poolIP}
	}

	if cfgPath != "" {
		data, err := ioutil.ReadFile(cfgPath)
		if err != nil {
			log.Fatalf("无法读取配置文件: %v", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("无法解析配置文件: %v", err)
		}
		log.Printf("Loaded configuration from %s", cfgPath)
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
		startDualMode(cfg.IfaceIPv6, cfg.IfaceIPv4, poolIPv4s, cfg.GwIPv6, uint16(cfg.RTPPortStart), uint16(cfg.RTPPortEnd), cfg.StaticMaps)
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
func startDualMode(iface6, iface4 string, poolIPv4s []net.IP, gwIPv6Str string, rtpStart, rtpEnd uint16, staticMaps map[string]string) {
	log.Printf("  IPv6 NIC : %s", iface6)
	log.Printf("  IPv4 NIC : %s", iface4)
	log.Printf("  RTP Ports: %d-%d", rtpStart, rtpEnd)

	var gatewayIPv6 net.IP
	if gwIPv6Str != "" {
		gatewayIPv6 = net.ParseIP(gwIPv6Str)
		if gatewayIPv6 == nil {
			log.Fatalf("无效的 IPv6 地址: %s", gwIPv6Str)
		}
		log.Printf("  GW IPv6  : %s", gatewayIPv6)
	}

	staticIPs := make(map[string]net.IP)
	for ip6, ip4 := range staticMaps {
		parsed6 := net.ParseIP(ip6)
		parsed4 := net.ParseIP(ip4).To4()
		if parsed6 != nil && parsed4 != nil {
			// key using the standard 16-byte representation for strict matching
			staticIPs[parsed6.To16().String()] = parsed4
		} else {
			log.Printf("警告: 无效的静态映射配置 - [%s] -> [%s]", ip6, ip4)
		}
	}
	if len(staticIPs) > 0 {
		log.Printf("  Static Map : %d rules loaded", len(staticIPs))
	}

	config := engine.DualNICConfig{
		IPv6Interface:  iface6,
		IPv4Interface:  iface4,
		PoolIPv4s:      poolIPv4s,
		GatewayIPv6:    gatewayIPv6,
		RTPPortStart:   rtpStart,
		RTPPortEnd:     rtpEnd,
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
