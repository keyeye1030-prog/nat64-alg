// +build !linux

package engine

import (
	"log"
	"net"
	"time"

	"nat64-alg/nat64"
)

// 非 Linux 的存根(Stub)实现, 方便在 Windows 下做业务逻辑开发和单元测试

type XDPEngine struct {
	ifaceName  string
	translator *nat64.Translator
}

func NewXDPEngine(ifaceName string, poolIPv4 net.IP) (*XDPEngine, error) {
	log.Println("[WARN] 目前运行于 非 Linux 环境，XDP 底层处于存根(Stub)旁路模式。")

	poolIPv4s := []net.IP{poolIPv4}
	sessionTable := nat64.NewSessionTable(poolIPv4s, 10000, 60000, 5*time.Minute)
	translator := nat64.NewTranslator(poolIPv4s[0], sessionTable)

	return &XDPEngine{
		ifaceName:  ifaceName,
		translator: translator,
	}, nil
}

func (e *XDPEngine) Start() {
	log.Println("[XDPEngine-Stub] 桩替服务运行中, 请使用 GOOS=linux 编译到 Linux 服务器执行。")
}

func (e *XDPEngine) Close() {
	log.Println("[XDPEngine-Stub] 桩替服务关闭。")
}

// GetTranslator 暴露翻译器, 方便单元测试
func (e *XDPEngine) GetTranslator() *nat64.Translator {
	return e.translator
}
