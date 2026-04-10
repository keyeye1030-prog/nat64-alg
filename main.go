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
	iface := flag.String("interface", "eth0", "网络接口名称 (用于附着 XDP 程序)")
	poolIP := flag.String("pool-ipv4", "198.51.100.1", "NAT64 网关的 IPv4 出口地址")
	flag.Parse()

	poolIPv4 := net.ParseIP(*poolIP).To4()
	if poolIPv4 == nil {
		log.Fatalf("无效的 IPv4 地址: %s", *poolIP)
	}

	log.Printf("Starting NAT64-ALG Engine")
	log.Printf("  Interface : %s", *iface)
	log.Printf("  Pool IPv4 : %s", poolIPv4)

	// 初始化底层 AF_XDP 数据面引擎
	xdpEngine, err := engine.NewXDPEngine(*iface, poolIPv4)
	if err != nil {
		log.Fatalf("Failed to init XDP engine: %v", err)
	}
	defer xdpEngine.Close()

	// 启动数据包处理主循环
	go xdpEngine.Start()

	// 阻塞等待系统中断信号实现优雅退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down, releasing XDP resources...")
}
