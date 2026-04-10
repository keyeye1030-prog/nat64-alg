package engine

import (
	"log"

	"nat64-alg/nat64"
)

// processFrame 处理从 AF_XDP 取到的一段原始二进制包帧（Raw Frame）
// 它是整个数据平面的核心热路径 (hot path)
func (e *XDPEngine) processFrame(frame []byte) {
	if e.translator == nil {
		return
	}

	result := e.translator.ProcessFrame(frame)

	if result.Error != nil {
		// 在生产环境下应使用计数器而非 log, 避免日志风暴
		log.Printf("[PacketDrop] %v", result.Error)
		return
	}

	switch result.Direction {
	case nat64.Dir6to4:
		e.sendFrame(result.OutputFrame)
	case nat64.Dir4to6:
		e.sendFrame(result.OutputFrame)
	case nat64.DirPassthrough:
		// 放行: 直接原样转发或不处理
		e.sendFrame(frame)
	}
}

// sendFrame 将帧写入 AF_XDP TX 队列
// TODO: 在真实实现中, 这里会调用 xsk 的发送接口
func (e *XDPEngine) sendFrame(frame []byte) {
	_ = frame // 占位: 真实实现中写入 UMEM TX ring
}
