package nat64

import (
	"sync"
)

// ============================================================================
// TCP 序列号偏差管理 (TCP Sequence Number Management)
//
// 当 ALG 修改了应用层载荷长度时，会导致 TCP 层序列号(Seq)与协商时的对不上。
// 我们需要追踪并动态修正每一个 TCP 会话的偏差。
//
// 机制:
//   1. 记录累积偏差 (Accumulated Delta)
//   2. 发送方向: NewSeq = OldSeq + Delta
//   3. 接收确认方向: NewAck = OldAck - Delta
// ============================================================================

// TCPDelta 存储单个方向的 TCP 偏差状态
type TCPDelta struct {
	mu     sync.RWMutex
	delta  int32  // 累积偏差 (字节)
	lastSeq uint32 // 最后一次看到且未修正的序列号 (用于确定偏差应用的范围)
}

// TCPDeltaTracker 记录一个双向 TCP 会话的偏差
type TCPDeltaTracker struct {
	Dir6to4 TCPDelta // 6->4 方向的 Seq 偏差 (影响 4->6 的 Ack)
	Dir4to6 TCPDelta // 4->6 方向的 Seq 偏差 (影响 6->4 的 Ack)
}

// NewTCPDeltaTracker 创建一个新的偏差追踪器
func NewTCPDeltaTracker() *TCPDeltaTracker {
	return &TCPDeltaTracker{}
}

// AddDelta 记录载荷长度变化
func (d *TCPDelta) AddDelta(diff int, currentSeq uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.delta += int32(diff)
	d.lastSeq = currentSeq
}

// AdjustSeq 修正发送序列号
func (d *TCPDelta) AdjustSeq(oldSeq uint32) uint32 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.delta == 0 {
		return oldSeq
	}
	// TODO: 严格实现需要检查 oldSeq 是否在 lastSeq 之后
	return uint32(int32(oldSeq) + d.delta)
}

// AdjustAck 修正接收确认号 (使用反方向的 Delta)
func (d *TCPDelta) AdjustAck(oldAck uint32) uint32 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.delta == 0 {
		return oldAck
	}
	return uint32(int32(oldAck) - d.delta)
}

// ============================================================================
// 集成到会话表
// ============================================================================

// 为 Session 结构添加可选的 TCPTracker
// 我们在 session.go 中进行实际修改
