// +build linux

package engine

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/asavie/xdp"

	"nat64-alg/nat64"
)

// XDPEngine 封装了 AF_XDP 相关的底层操作
type XDPEngine struct {
	ifaceName  string
	program    *xdp.Program
	xsk        *xdp.Socket
	translator *nat64.Translator
}

// NewXDPEngine 初始化并附着 XDP 程序到目标网卡
func NewXDPEngine(ifaceName string, poolIPv4 net.IP) (*XDPEngine, error) {
	// 获取网卡状态与 Index
	eth, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("找不到网卡 %s: %w", ifaceName, err)
	}

	// TODO: 此处后续填充挂载 XDP eBPF Program 以及开启 UMEM 内存池分配
	log.Printf("[XDPEngine] 准备挂载于网卡: %s (Index: %d)", eth.Name, eth.Index)

	// 初始化 NAT64 会话表和翻译器
	sessionTable := nat64.NewSessionTable(poolIPv4, 10000, 60000, 5*time.Minute)
	translator := nat64.NewTranslator(poolIPv4, sessionTable)

	engine := &XDPEngine{
		ifaceName:  ifaceName,
		translator: translator,
	}

	// 启动会话过期清理 goroutine
	go engine.sessionCleaner(sessionTable)

	return engine, nil
}

// Start 开启包拉取(Poll)轮询循环
func (e *XDPEngine) Start() {
	log.Println("[XDPEngine] 正在进入 AF_XDP 数据帧拉取循环...")

	// 伪代码思路:
	// for {
	//     n := e.xsk.NumReceived()
	//     if n > 0 {
	//         rxDescs := e.xsk.Receive(n)
	//         for _, desc := range rxDescs {
	//             frame := e.xsk.GetFrame(desc)
	//             e.processFrame(frame)
	//         }
	//     }
	//     e.xsk.Poll(-1)
	// }
}

// Close 释放系统与内核资源
func (e *XDPEngine) Close() {
	if e.xsk != nil {
		e.xsk.Close()
	}
	if e.program != nil {
		e.program.Close()
	}
	log.Printf("[XDPEngine] 活跃会话数: %d", e.translator.SessionTable.Stats())
	log.Println("[XDPEngine] AF_XDP socket 和 program 资源已释放完毕。")
}

// sessionCleaner 定期清理过期会话
func (e *XDPEngine) sessionCleaner(table *nat64.SessionTable) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cleaned := table.CleanExpired()
		if cleaned > 0 {
			log.Printf("[SessionCleaner] 清除 %d 条过期会话, 剩余: %d", cleaned, table.Stats())
		}
	}
}
