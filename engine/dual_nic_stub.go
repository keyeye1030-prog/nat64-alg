// +build !linux

package engine

import (
	"log"
	"net"
	"time"

	"nat64-alg/alg/rtp"
	"nat64-alg/nat64"
)

// 非 Linux 的双臂引擎存根

type DualNICEngine struct {
	translator   *nat64.Translator
	relayManager *rtp.RelayManager
	config       DualNICConfig
}

type DualNICConfig struct {
	IPv6Interface string
	IPv4Interface string
	PoolIPv4      net.IP
	GatewayIPv6   net.IP
	RTPPortStart  uint16
	RTPPortEnd    uint16
	SessionTTL    time.Duration
}

func NewDualNICEngine(config DualNICConfig) (*DualNICEngine, error) {
	log.Println("[WARN] 双臂引擎运行于非 Linux 环境 (Stub 模式)")

	if config.SessionTTL == 0 {
		config.SessionTTL = 5 * time.Minute
	}
	if config.RTPPortStart == 0 {
		config.RTPPortStart = 20000
	}
	if config.RTPPortEnd == 0 {
		config.RTPPortEnd = 30000
	}

	sessionTable := nat64.NewSessionTable(config.PoolIPv4, 10000, 60000, config.SessionTTL)
	translator := nat64.NewTranslator(config.PoolIPv4, sessionTable)

	gwIPv6 := config.GatewayIPv6
	if gwIPv6 == nil {
		gwIPv6 = net.ParseIP("::1")
	}

	relayMgr := rtp.NewRelayManager(
		gwIPv6,
		config.PoolIPv4,
		config.RTPPortStart,
		config.RTPPortEnd,
	)

	return &DualNICEngine{
		translator:   translator,
		relayManager: relayMgr,
		config:       config,
	}, nil
}

func (e *DualNICEngine) Start() {
	log.Println("[DualNIC-Stub] 桩替服务运行中")
}

func (e *DualNICEngine) Close() {
	log.Println("[DualNIC-Stub] 桩替服务关闭")
}

func (e *DualNICEngine) GetTranslator() *nat64.Translator {
	return e.translator
}

func (e *DualNICEngine) GetRelayManager() *rtp.RelayManager {
	return e.relayManager
}
