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
	Mode           string            `json:"mode"`
	PoolIPv4s      []string          `json:"pool_ipv4s"`
	NAT64Prefix    string            `json:"nat64_prefix"`
	Interface      string            `json:"interface"`
	IfaceIPv6      string            `json:"iface_ipv6"`
	IfaceIPv4      string            `json:"iface_ipv4"`
	GwIPv6         string            `json:"gw_ipv6"`
	IPv6Gateway    string            `json:"ipv6_gateway"`
	IPv4GatewayMAC string            `json:"ipv4_gateway_mac"`
	IPv6GatewayMAC string            `json:"ipv6_gateway_mac"`
	EnableARPProxy bool              `json:"enable_arp_proxy"`
	RTPPortStart   uint              `json:"rtp_port_start"`
	RTPPortEnd     uint              `json:"rtp_port_end"`
	StaticMaps     map[string]string `json:"static_mappings"`

	PreflightEnabled            bool `json:"preflight_enabled"`
	PreflightMinSpeedMbps       int  `json:"preflight_min_speed_mbps"`
	PreflightQueues             int  `json:"preflight_queues"`
	PreflightRequireOffloadsOff bool `json:"preflight_require_offloads_off"`
	PreflightRequireCarrier     bool `json:"preflight_require_carrier"`
	PreflightRequireFullDuplex  bool `json:"preflight_require_full_duplex"`
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "Path to config.json. If provided, overrides other CLI flags.")

	mode := flag.String("mode", "single", "Deployment mode: single or dual")
	poolIP := flag.String("pool-ipv4", "198.51.100.1", "NAT64 gateway IPv4 pool address")
	nat64Prefix := flag.String("nat64-prefix", "", "NAT64 IPv6 prefix, for example 64:ff9b::/96")
	iface := flag.String("interface", "eth0", "Interface for single-NIC mode")
	iface6 := flag.String("iface-ipv6", "eth0", "IPv6-side interface for dual-NIC mode")
	iface4 := flag.String("iface-ipv4", "eth1", "IPv4-side interface for dual-NIC mode")
	gwIPv6 := flag.String("gw-ipv6", "", "Gateway IPv6 address used by RTP relay")
	ipv6Gateway := flag.String("ipv6-gateway", "", "Default IPv6 gateway address")
	rtpStart := flag.Uint("rtp-port-start", 20000, "RTP relay port range start")
	rtpEnd := flag.Uint("rtp-port-end", 30000, "RTP relay port range end")
	preflightEnabled := flag.Bool("preflight", true, "Run physical NIC preflight checks before starting")
	preflightMinSpeed := flag.Int("preflight-min-speed-mbps", 100, "Minimum negotiated NIC speed in Mb/s")
	preflightQueues := flag.Int("preflight-queues", 1, "Required current combined queue count")

	flag.Parse()

	cfg := Config{
		Mode:                        *mode,
		NAT64Prefix:                 *nat64Prefix,
		Interface:                   *iface,
		IfaceIPv6:                   *iface6,
		IfaceIPv4:                   *iface4,
		GwIPv6:                      *gwIPv6,
		IPv6Gateway:                 *ipv6Gateway,
		RTPPortStart:                *rtpStart,
		RTPPortEnd:                  *rtpEnd,
		PreflightEnabled:            *preflightEnabled,
		PreflightMinSpeedMbps:       *preflightMinSpeed,
		PreflightQueues:             *preflightQueues,
		PreflightRequireOffloadsOff: true,
		PreflightRequireCarrier:     true,
		PreflightRequireFullDuplex:  true,
	}
	if *poolIP != "" {
		cfg.PoolIPv4s = []string{*poolIP}
	}

	if cfgPath != "" {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			log.Fatalf("cannot read config file: %v", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("cannot parse config file: %v", err)
		}
		log.Printf("Loaded configuration from %s", cfgPath)
	}

	if cfg.NAT64Prefix != "" {
		ip, _, err := net.ParseCIDR(cfg.NAT64Prefix)
		if err != nil {
			ip = net.ParseIP(cfg.NAT64Prefix)
			if ip == nil {
				log.Fatalf("invalid NAT64 prefix: %s", cfg.NAT64Prefix)
			}
		}
		nat64.SetNAT64Prefix(ip)
		log.Printf("  NAT64 Prefix: %s (embeds IPv4 in last 32 bits)", ip)
	} else {
		log.Printf("  NAT64 Prefix: %s (standard well-known prefix)", nat64.WellKnownPrefix)
	}

	var poolIPv4s []net.IP
	for _, ipStr := range cfg.PoolIPv4s {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			log.Fatalf("invalid IPv4 address: %s", ipStr)
		}
		poolIPv4s = append(poolIPv4s, ip)
	}
	if len(poolIPv4s) == 0 {
		log.Fatalf("at least one pool IPv4 address is required")
	}

	log.Printf("======================================")
	log.Printf("  NAT64-ALG Engine")
	log.Printf("  Mode     : %s", cfg.Mode)
	log.Printf("  Pool IPv4: %d IPs loaded", len(poolIPv4s))
	log.Printf("======================================")

	switch cfg.Mode {
	case "single":
		runPreflightOrExit(cfg, []string{cfg.Interface})
		startSingleMode(cfg.Interface, poolIPv4s)
	case "dual":
		runPreflightOrExit(cfg, []string{cfg.IfaceIPv6, cfg.IfaceIPv4})
		startDualMode(cfg, poolIPv4s)
	default:
		log.Fatalf("unknown deployment mode: %s (supported: single, dual)", cfg.Mode)
	}
}

func runPreflightOrExit(cfg Config, interfaces []string) {
	if !cfg.PreflightEnabled {
		log.Printf("[Preflight] disabled")
		return
	}
	if err := engine.RunPreflight(engine.PreflightConfig{
		Interfaces:         interfaces,
		MinSpeedMbps:       cfg.PreflightMinSpeedMbps,
		RequireFullDuplex:  cfg.PreflightRequireFullDuplex,
		RequireCarrier:     cfg.PreflightRequireCarrier,
		ExpectedQueues:     cfg.PreflightQueues,
		RequireOffloadsOff: cfg.PreflightRequireOffloadsOff,
	}); err != nil {
		log.Fatalf("Preflight failed: %v", err)
	}
}

func startSingleMode(ifaceName string, poolIPv4s []net.IP) {
	log.Printf("  Interface: %s", ifaceName)

	xdpEngine, err := engine.NewXDPEngine(ifaceName, poolIPv4s[0])
	if err != nil {
		log.Fatalf("Failed to init XDP engine: %v", err)
	}
	defer xdpEngine.Close()

	go xdpEngine.Start()
	waitForShutdown()
}

func startDualMode(cfg Config, poolIPv4s []net.IP) {
	log.Printf("  IPv6 NIC : %s", cfg.IfaceIPv6)
	log.Printf("  IPv4 NIC : %s", cfg.IfaceIPv4)
	log.Printf("  RTP Ports: %d-%d", cfg.RTPPortStart, cfg.RTPPortEnd)

	var gatewayIPv6 net.IP
	if cfg.GwIPv6 != "" {
		gatewayIPv6 = net.ParseIP(cfg.GwIPv6)
		if gatewayIPv6 == nil {
			log.Fatalf("invalid gateway IPv6 address: %s", cfg.GwIPv6)
		}
		log.Printf("  GW IPv6  : %s", gatewayIPv6)
	}

	var ipv6Gateway net.IP
	if cfg.IPv6Gateway != "" {
		ipv6Gateway = net.ParseIP(cfg.IPv6Gateway)
		if ipv6Gateway == nil {
			log.Fatalf("invalid IPv6 gateway address: %s", cfg.IPv6Gateway)
		}
		log.Printf("  IPv6 Gateway IP: %s", ipv6Gateway)
	}

	var ipv4GwMAC, ipv6GwMAC net.HardwareAddr
	if cfg.IPv4GatewayMAC != "" {
		var err error
		ipv4GwMAC, err = net.ParseMAC(cfg.IPv4GatewayMAC)
		if err != nil {
			log.Fatalf("invalid IPv4 gateway MAC: %s (%v)", cfg.IPv4GatewayMAC, err)
		}
		log.Printf("  IPv4 GW MAC: %s", ipv4GwMAC)
	} else {
		log.Println("  IPv4 gateway MAC is not configured; using broadcast MAC")
		ipv4GwMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	}
	if cfg.IPv6GatewayMAC != "" {
		var err error
		ipv6GwMAC, err = net.ParseMAC(cfg.IPv6GatewayMAC)
		if err != nil {
			log.Fatalf("invalid IPv6 gateway MAC: %s (%v)", cfg.IPv6GatewayMAC, err)
		}
		log.Printf("  IPv6 GW MAC: %s", ipv6GwMAC)
	} else {
		log.Println("  IPv6 gateway MAC is not configured; trying neighbor table or first-packet learning")
	}

	staticIPs := make(map[string]net.IP)
	for ip6, ip4 := range cfg.StaticMaps {
		parsed6 := net.ParseIP(ip6)
		parsed4 := net.ParseIP(ip4).To4()
		if parsed6 != nil && parsed4 != nil {
			staticIPs[parsed6.To16().String()] = parsed4
		} else {
			log.Printf("warning: invalid static mapping: [%s] -> [%s]", ip6, ip4)
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

func waitForShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down, releasing resources...")
}
