package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"nat64-alg/engine"
)

func main() {
	// 通用参数
	mode := flag.String("mode", "single", "部署模式: single (单臂) 或 dual (双臂双网卡)")
	poolIP := flag.String("pool-ipv4", "198.51.100.1", "NAT64 网关的 IPv4 出口地址")

	// 单臂模式参数
	iface := flag.String("interface", "eth0", "[单臂模式] 网卡名称")

	// 双臂模式参数
	iface6 := flag.String("iface-ipv6", "eth0", "[双臂模式] IPv6 侧网卡名称")
	iface4 := flag.String("iface-ipv4", "eth1", "[双臂模式] IPv4 侧网卡名称")
	gwIPv6 := flag.String("gw-ipv6", "", "[双臂模式] 网关 IPv6 地址 (用于 RTP 中继绑定)")
	rtpStart := flag.Uint("rtp-port-start", 20000, "[双臂模式] RTP 中继端口起始")
	rtpEnd := flag.Uint("rtp-port-end", 30000, "[双臂模式] RTP 中继端口结束")

	flag.Parse()

	poolIPv4 := net.ParseIP(*poolIP).To4()
	if poolIPv4 == nil {
		log.Fatalf("无效的 IPv4 地址: %s", *poolIP)
	}

	log.Printf("======================================")
	log.Printf("  NAT64-ALG Engine")
	log.Printf("  Mode     : %s", *mode)
	log.Printf("  Pool IPv4: %s", poolIPv4)
	log.Printf("======================================")

	switch *mode {
	case "single":
		startSingleMode(*iface, poolIPv4)
	case "dual":
		startDualMode(*iface6, *iface4, poolIPv4, *gwIPv6, uint16(*rtpStart), uint16(*rtpEnd))
	default:
		log.Fatalf("未知的部署模式: %s (支持: single, dual)", *mode)
	}
}

// startSingleMode 启动单臂模式 (原有模式)
func startSingleMode(ifaceName string, poolIPv4 net.IP) {
	log.Printf("  Interface: %s", ifaceName)

	xdpEngine, err := engine.NewXDPEngine(ifaceName, poolIPv4)
	if err != nil {
		log.Fatalf("Failed to init XDP engine: %v", err)
	}
	defer xdpEngine.Close()

	go xdpEngine.Start()

	waitForShutdown()
}

// startDualMode 启动双臂双网卡模式
func startDualMode(iface6, iface4 string, poolIPv4 net.IP, gwIPv6Str string, rtpStart, rtpEnd uint16) {
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

	config := engine.DualNICConfig{
		IPv6Interface: iface6,
		IPv4Interface: iface4,
		PoolIPv4:      poolIPv4,
		GatewayIPv6:   gatewayIPv6,
		RTPPortStart:  rtpStart,
		RTPPortEnd:    rtpEnd,
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
