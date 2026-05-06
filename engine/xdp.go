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
	eth, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("找不到网卡 %s: %w", ifaceName, err)
	}
	log.Printf("[XDPEngine] 准备挂载于网卡: %s (Index: %d, MTU: %d)", eth.Name, eth.Index, eth.MTU)

	// 创建 XDP 程序 (内置 redirect-all 程序)
	// 注: 若需加载自定义 nat64.o, 需使用 cilium/ebpf 替代此处
	program, err := xdp.NewProgram(1) // 单队列
	if err != nil {
		return nil, fmt.Errorf("创建 XDP 程序失败: %w", err)
	}

	// 附着到网卡
	if err := program.Attach(eth.Index); err != nil {
		program.Close()
		return nil, fmt.Errorf("附着 XDP 程序到 %s 失败: %w", ifaceName, err)
	}
	log.Printf("[XDPEngine] XDP 程序已附着到 %s", ifaceName)

	// 创建 AF_XDP socket
	xsk, err := xdp.NewSocket(eth.Index, 0, nil) // 队列 0, 默认选项
	if err != nil {
		program.Detach(eth.Index)
		program.Close()
		return nil, fmt.Errorf("创建 AF_XDP socket 失败: %w", err)
	}

	// 注册 socket 到 XDP 程序的 XSKMAP
	if err := program.Register(0, xsk.FD()); err != nil {
		xsk.Close()
		program.Detach(eth.Index)
		program.Close()
		return nil, fmt.Errorf("注册 AF_XDP socket 失败: %w", err)
	}
	log.Printf("[XDPEngine] AF_XDP socket 已创建并注册 (FD=%d)", xsk.FD())

	// 初始化 NAT64 会话表和翻译器
	poolIPv4s := []net.IP{poolIPv4}
	sessionTable := nat64.NewSessionTable(poolIPv4s, 10000, 60000, 5*time.Minute)
	translator := nat64.NewTranslator(poolIPv4s[0], sessionTable)

	engine := &XDPEngine{
		ifaceName:  ifaceName,
		program:    program,
		xsk:        xsk,
		translator: translator,
	}

	// 启动会话过期清理 goroutine
	go engine.sessionCleaner(sessionTable)

	return engine, nil
}

// Start 开启包拉取(Poll)轮询循环
func (e *XDPEngine) Start() {
	log.Println("[XDPEngine] 正在进入 AF_XDP 数据帧拉取循环...")

	// 初始填充 Fill Ring, 让内核有缓冲区接收新帧
	e.fillRxRing()

	var pollCount uint64
	for {
		// 轮询等待事件 (阻塞直到有 RX 或 TX 完成)
		_, _, err := e.xsk.Poll(-1)
		if err != nil {
			log.Printf("[XDPEngine] Poll 错误: %v", err)
			continue
		}
		pollCount++

		// 处理接收到的帧
		numRx := e.xsk.NumReceived()
		if numRx > 0 {
			rxDescs := e.xsk.Receive(numRx)
			for i := range rxDescs {
				frame := e.xsk.GetFrame(rxDescs[i])
				frameLen := int(rxDescs[i].Len)
				if frameLen == 0 || frameLen > len(frame) {
					continue
				}
				// 复制帧数据 (避免 UMEM 地址被回收后数据被覆盖)
				frameCopy := make([]byte, frameLen)
				copy(frameCopy, frame[:frameLen])

				e.processAndSend(frameCopy)
			}
			// 回收 RX 描述符到 Fill Ring
			e.fillRxRing()
		}

		// 完成 TX
		numComp := e.xsk.NumCompleted()
		if numComp > 0 {
			e.xsk.Complete(numComp)
		}

		// 定期日志
		if pollCount%100000 == 0 {
			log.Printf("[XDPEngine] Poll #%d, 活跃会话: %d, 6→4: %d, 4→6: %d, 丢弃: %d",
				pollCount,
				e.translator.SessionTable.Stats(),
				e.translator.Pkts6to4,
				e.translator.Pkts4to6,
				e.translator.PktsDropped)
		}
	}
}

// processAndSend 处理帧并发送结果 (单臂模式: 同一网卡)
func (e *XDPEngine) processAndSend(frame []byte) {
	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		// 生产环境使用计数器, 不打印每个丢弃
		return
	}

	var outputFrame []byte
	switch result.Direction {
	case nat64.Dir6to4, nat64.Dir4to6:
		outputFrame = result.OutputFrame
	case nat64.DirPassthrough:
		outputFrame = frame // 放行: 原样转发
	default:
		return
	}

	if outputFrame == nil {
		return
	}

	e.sendFrame(outputFrame)
}

// sendFrame 将帧写入 AF_XDP TX 队列
func (e *XDPEngine) sendFrame(frame []byte) {
	if e.xsk.NumFreeTxSlots() < 1 {
		return // TX 队列满, 丢弃
	}

	descs := e.xsk.GetDescs(1)
	if len(descs) < 1 {
		return
	}

	// 获取描述符对应的 UMEM 帧缓冲区并拷贝数据
	txFrame := e.xsk.GetFrame(descs[0])
	n := copy(txFrame, frame)
	descs[0].Len = uint32(n)

	e.xsk.Transmit(descs)
}

// fillRxRing 将可用描述符填入 Fill Ring
func (e *XDPEngine) fillRxRing() {
	n := e.xsk.NumFreeFillSlots()
	if n == 0 {
		return
	}
	descs := e.xsk.GetDescs(n)
	for i := range descs {
		descs[i].Len = 0
	}
	e.xsk.Fill(descs)
}

// Close 释放系统与内核资源
func (e *XDPEngine) Close() {
	if e.xsk != nil {
		e.xsk.Close()
	}
	if e.program != nil {
		iface, err := net.InterfaceByName(e.ifaceName)
		if err == nil {
			e.program.Detach(iface.Index)
		}
		e.program.Close()
	}
	log.Printf("[XDPEngine] 活跃会话数: %d", e.translator.SessionTable.Stats())
	log.Printf("[XDPEngine] 统计: 6→4=%d, 4→6=%d, 丢弃=%d, 放行=%d",
		e.translator.Pkts6to4, e.translator.Pkts4to6,
		e.translator.PktsDropped, e.translator.PktsPassthru)
	log.Println("[XDPEngine] AF_XDP socket 和 program 资源已释放完毕。")
}

// GetTranslator 暴露翻译器供外部使用
func (e *XDPEngine) GetTranslator() *nat64.Translator {
	return e.translator
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
