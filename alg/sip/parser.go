package sip

import (
	"bytes"
	"regexp"
)

// ============================================================================
// SIP 消息解析工具
// 用于提取 Call-ID, 检测 BYE/CANCEL 等信令事件
// ============================================================================

var (
	// Call-ID 头
	reCallID = regexp.MustCompile(`(?im)^(?:Call-ID|i)\s*:\s*(.+?)\s*$`)

	// SIP 请求行: METHOD sip:xxx SIP/2.0
	reRequestLine = regexp.MustCompile(`^(\w+)\s+sip:`)
)

// SIP 方法常量
const (
	MethodINVITE  = "INVITE"
	MethodBYE     = "BYE"
	MethodCANCEL  = "CANCEL"
	MethodACK     = "ACK"
	MethodOptions = "OPTIONS"
)

// MessageInfo 表示解析出的 SIP 消息关键信息
type MessageInfo struct {
	Method   string // 请求方法 (INVITE, BYE, CANCEL, 等)
	CallID   string // Call-ID 头
	IsRequest bool  // true=请求, false=响应
	HasSDP   bool   // 是否包含 SDP body
}

// ParseMessageInfo 从 SIP 消息中快速提取关键信息
// 不做完整解析, 只提取需要的字段
func ParseMessageInfo(payload []byte) *MessageInfo {
	info := &MessageInfo{}

	// 查找第一行 (请求行或状态行)
	firstLineEnd := bytes.IndexByte(payload, '\n')
	if firstLineEnd < 0 {
		return info
	}
	firstLine := string(payload[:firstLineEnd])

	// 判断是请求还是响应
	if sub := reRequestLine.FindStringSubmatch(firstLine); len(sub) > 1 {
		info.IsRequest = true
		info.Method = sub[1]
	}

	// 提取 Call-ID
	if sub := reCallID.FindSubmatch(payload); len(sub) > 1 {
		info.CallID = string(bytes.TrimSpace(sub[1]))
	}

	// 检查是否有 SDP
	info.HasSDP = bytes.Contains(payload, []byte("\r\n\r\n")) &&
		(bytes.Contains(payload, []byte("application/sdp")) ||
			bytes.Contains(payload, []byte("v=0")))

	return info
}

// IsCallTermination 判断该 SIP 消息是否标志通话结束
func (m *MessageInfo) IsCallTermination() bool {
	return m.IsRequest && (m.Method == MethodBYE || m.Method == MethodCANCEL)
}

// IsCallSetup 判断该 SIP 消息是否是呼叫建立
func (m *MessageInfo) IsCallSetup() bool {
	return m.IsRequest && m.Method == MethodINVITE
}
