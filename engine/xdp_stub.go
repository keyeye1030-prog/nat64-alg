//go:build !linux
// +build !linux

package engine

import (
	"log"
	"net"
	"time"

	"nat64-alg/nat64"
)

type XDPEngine struct {
	ifaceName  string
	translator *nat64.Translator
}

func NewXDPEngine(ifaceName string, poolIPv4 net.IP) (*XDPEngine, error) {
	log.Println("[XDPEngine-Stub] non-Linux environment; XDP data plane is disabled")

	poolIPv4s := []net.IP{poolIPv4}
	sessionTable := nat64.NewSessionTable(poolIPv4s, 10000, 60000, 5*time.Minute)
	translator := nat64.NewTranslator(poolIPv4s[0], sessionTable)

	return &XDPEngine{
		ifaceName:  ifaceName,
		translator: translator,
	}, nil
}

func (e *XDPEngine) Start() {
	log.Println("[XDPEngine-Stub] service is running in stub mode")
}

func (e *XDPEngine) Close() {
	log.Printf("[XDPEngine-Stub] stats: 6to4=%d, 4to6=%d, dropped=%d",
		e.translator.Pkts6to4, e.translator.Pkts4to6, e.translator.PktsDropped)
}

func (e *XDPEngine) GetTranslator() *nat64.Translator {
	return e.translator
}
