package sip

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ============================================================================
// SIP/SDP 应用层网关 (ALG)
//
// SIP 信令是文本格式 (类似 HTTP), 其中包含大量 IP 地址字段需要 NAT64 重写:
//
// SIP Header 中需要修改的字段:
//   - Via: SIP/2.0/UDP [2001:db8::1]:5060
//   - Contact: <sip:user@[2001:db8::1]:5060>
//   - Route / Record-Route 头
//   - From / To 头 (如果含有 IP)
//
// SDP Body (Session Description Protocol) 中需要修改的字段:
//   - c=IN IP6 2001:db8::1          -> c=IN IP4 198.51.100.1
//   - o=... IN IP6 2001:db8::1      -> o=... IN IP4 198.51.100.1
//   - m=audio 20000 RTP/AVP 0       (端口可能需要重映射)
//   - a=rtcp:20001
//
// ============================================================================

// ALGResult 是 SIP ALG 处理结果
type ALGResult struct {
	ModifiedPayload []byte // 修改后的 SIP 信令
	LengthDelta     int    // 载荷长度变化量 (用于 TCP 序列号偏移追踪)
	MediaPorts      []MediaPort // 需要开放的 RTP/RTCP 端口映射
}

// MediaPort 表示一个需要做 NAT 中继的媒体通道
type MediaPort struct {
	OriginalIP   net.IP // SDP 中声明的原始 IP
	OriginalPort uint16 // SDP 中声明的原始端口
	MappedIP     net.IP // NAT 后分配的中继 IP
	MappedPort   uint16 // NAT 后分配的中继端口
	Proto        string // "RTP" 或 "RTCP"
}

// Translator 是 SIP ALG 翻译器
type Translator struct {
	PoolIPv4 net.IP // NAT64 网关的 IPv4 地址
	PoolIPv6 net.IP // NAT64 网关的 IPv6 地址 (如果有)
}

// NewTranslator 创建 SIP ALG 翻译器
func NewTranslator(poolIPv4 net.IP) *Translator {
	return &Translator{
		PoolIPv4: poolIPv4.To4(),
	}
}

// ============================================================================
// SIP Header 正则表达式
// ============================================================================

var (
	// 匹配 Via 头中的 IPv6 地址: Via: SIP/2.0/UDP [2001:db8::1]:5060;branch=...
	reViaIPv6 = regexp.MustCompile(`(?i)(Via:\s*SIP/2\.0/(?:UDP|TCP|TLS)\s+)\[([0-9a-fA-F:]+)\](?::(\d+))?`)

	// 匹配 Contact 头: Contact: <sip:user@[2001:db8::1]:5060>
	reContactIPv6 = regexp.MustCompile(`(?i)(Contact:\s*<?sip:[^@]*@)\[([0-9a-fA-F:]+)\](?::(\d+))?(>?)`)

	// 匹配 Record-Route / Route 头
	reRouteIPv6 = regexp.MustCompile(`(?i)((?:Record-)?Route:\s*<sip:[^@]*@)\[([0-9a-fA-F:]+)\](?::(\d+))?(>?)`)

	// SDP: c= 行 (Connection Data)
	// c=IN IP6 2001:db8::1
	reSDPConnection = regexp.MustCompile(`(?m)^(c=IN\s+)IP6\s+([0-9a-fA-F:]+)\s*$`)

	// SDP: o= 行 (Origin)
	// o=- 12345 12345 IN IP6 2001:db8::1
	reSDPOrigin = regexp.MustCompile(`(?m)^(o=[^\r\n]*IN\s+)IP6\s+([0-9a-fA-F:]+)\s*$`)

	// SDP: m= 行 (Media Description)
	// m=audio 20000 RTP/AVP 0 8
	reSDPMedia = regexp.MustCompile(`(?m)^(m=\w+\s+)(\d+)(\s+.*)$`)

	// SDP: a=rtcp: 行
	// a=rtcp:20001
	reSDPRtcp = regexp.MustCompile(`(?m)^(a=rtcp:)(\d+)(.*)$`)

	// Content-Length 头
	reContentLength = regexp.MustCompile(`(?i)(Content-Length:\s*)(\d+)`)

	// 分隔 SIP Header 和 SDP Body
	sipHeaderBodySep = []byte("\r\n\r\n")
)

// TranslateIPv6ToIPv4 将 SIP 信令中的 IPv6 地址重写为 IPv4 地址
// 用于 6→4 方向: IPv6 客户端发出的 SIP 请求/响应
func (t *Translator) TranslateIPv6ToIPv4(sipPayload []byte, clientIPv6, mappedIPv4 net.IP) (*ALGResult, error) {
	if len(sipPayload) == 0 {
		return nil, fmt.Errorf("空的 SIP 负载")
	}

	originalLen := len(sipPayload)
	result := &ALGResult{}

	// 分离 SIP Header 和 SDP Body
	headerEnd := bytes.Index(sipPayload, sipHeaderBodySep)
	var headerPart, bodyPart []byte

	if headerEnd >= 0 {
		headerPart = sipPayload[:headerEnd]
		bodyPart = sipPayload[headerEnd+len(sipHeaderBodySep):]
	} else {
		headerPart = sipPayload
		bodyPart = nil
	}

	// ---- 重写 SIP Header ----
	modifiedHeader := t.rewriteSIPHeaders(headerPart, clientIPv6, mappedIPv4)

	// ---- 重写 SDP Body ----
	var modifiedBody []byte
	if len(bodyPart) > 0 {
		modifiedBody, result.MediaPorts = t.rewriteSDP(bodyPart, clientIPv6, mappedIPv4)
	}

	// ---- 重组完整 SIP 消息 ----
	if len(modifiedBody) > 0 {
		// 更新 Content-Length
		modifiedHeader = updateContentLength(modifiedHeader, len(modifiedBody))
		result.ModifiedPayload = assembleSIPMessage(modifiedHeader, modifiedBody)
	} else {
		result.ModifiedPayload = modifiedHeader
	}

	result.LengthDelta = len(result.ModifiedPayload) - originalLen
	return result, nil
}

// TranslateIPv4ToIPv6 将 SIP 信令中的 IPv4 地址重写为 IPv6 地址
// 用于 4→6 方向: IPv4 服务器的回包
func (t *Translator) TranslateIPv4ToIPv6(sipPayload []byte, serverIPv4, clientIPv6 net.IP) (*ALGResult, error) {
	if len(sipPayload) == 0 {
		return nil, fmt.Errorf("空的 SIP 负载")
	}

	originalLen := len(sipPayload)
	result := &ALGResult{}

	headerEnd := bytes.Index(sipPayload, sipHeaderBodySep)
	var headerPart, bodyPart []byte

	if headerEnd >= 0 {
		headerPart = sipPayload[:headerEnd]
		bodyPart = sipPayload[headerEnd+len(sipHeaderBodySep):]
	} else {
		headerPart = sipPayload
		bodyPart = nil
	}

	// ---- SIP Header: IPv4 -> IPv6 ----
	modifiedHeader := t.rewriteSIPHeaders4to6(headerPart, serverIPv4, clientIPv6)

	// ---- SDP Body: IPv4 -> IPv6 ----
	var modifiedBody []byte
	if len(bodyPart) > 0 {
		modifiedBody = t.rewriteSDP4to6(bodyPart, serverIPv4, clientIPv6)
	}

	if len(modifiedBody) > 0 {
		modifiedHeader = updateContentLength(modifiedHeader, len(modifiedBody))
		result.ModifiedPayload = assembleSIPMessage(modifiedHeader, modifiedBody)
	} else {
		result.ModifiedPayload = modifiedHeader
	}

	result.LengthDelta = len(result.ModifiedPayload) - originalLen
	return result, nil
}

// ============================================================================
// SIP Header 重写 (IPv6 -> IPv4)
// ============================================================================

func (t *Translator) rewriteSIPHeaders(header []byte, clientIPv6, mappedIPv4 net.IP) []byte {
	s := string(header)
	ipv6Str := clientIPv6.String()
	ipv4Str := mappedIPv4.String()

	// Via: SIP/2.0/UDP [ipv6]:port -> Via: SIP/2.0/UDP ipv4:port
	s = reViaIPv6.ReplaceAllStringFunc(s, func(match string) string {
		sub := reViaIPv6.FindStringSubmatch(match)
		if sub[2] == ipv6Str || isAnyIPv6(sub[2]) {
			port := sub[3]
			if port == "" {
				return sub[1] + ipv4Str
			}
			return sub[1] + ipv4Str + ":" + port
		}
		return match
	})

	// Contact: <sip:user@[ipv6]:port> -> <sip:user@ipv4:port>
	s = reContactIPv6.ReplaceAllStringFunc(s, func(match string) string {
		sub := reContactIPv6.FindStringSubmatch(match)
		if sub[2] == ipv6Str || isAnyIPv6(sub[2]) {
			port := sub[3]
			closing := sub[4]
			if port == "" {
				return sub[1] + ipv4Str + closing
			}
			return sub[1] + ipv4Str + ":" + port + closing
		}
		return match
	})

	// Route / Record-Route
	s = reRouteIPv6.ReplaceAllStringFunc(s, func(match string) string {
		sub := reRouteIPv6.FindStringSubmatch(match)
		if sub[2] == ipv6Str || isAnyIPv6(sub[2]) {
			port := sub[3]
			closing := sub[4]
			if port == "" {
				return sub[1] + ipv4Str + closing
			}
			return sub[1] + ipv4Str + ":" + port + closing
		}
		return match
	})

	return []byte(s)
}

// rewriteSIPHeaders4to6 将 SIP Header 中的 IPv4 地址重写为 IPv6
func (t *Translator) rewriteSIPHeaders4to6(header []byte, serverIPv4, clientIPv6 net.IP) []byte {
	s := string(header)

	// 对 IPv4 地址的简单全局替换 (仅限注册的池地址)
	poolStr := t.PoolIPv4.String()
	ipv6Str := "[" + clientIPv6.String() + "]"
	s = strings.ReplaceAll(s, poolStr, ipv6Str)

	return []byte(s)
}

// ============================================================================
// SDP Body 重写
// ============================================================================

func (t *Translator) rewriteSDP(sdpBody []byte, clientIPv6, mappedIPv4 net.IP) ([]byte, []MediaPort) {
	s := string(sdpBody)
	var mediaPorts []MediaPort
	ipv4Str := mappedIPv4.String()

	// c=IN IP6 xxxx -> c=IN IP4 yyyy
	s = reSDPConnection.ReplaceAllStringFunc(s, func(match string) string {
		sub := reSDPConnection.FindStringSubmatch(match)
		return sub[1] + "IP4 " + ipv4Str
	})

	// o=... IN IP6 xxxx -> o=... IN IP4 yyyy
	s = reSDPOrigin.ReplaceAllStringFunc(s, func(match string) string {
		sub := reSDPOrigin.FindStringSubmatch(match)
		return sub[1] + "IP4 " + ipv4Str
	})

	// m=audio PORT ... — 记录端口, 可选重映射
	s = reSDPMedia.ReplaceAllStringFunc(s, func(match string) string {
		sub := reSDPMedia.FindStringSubmatch(match)
		port, _ := strconv.ParseUint(sub[2], 10, 16)
		mediaPorts = append(mediaPorts, MediaPort{
			OriginalIP:   clientIPv6,
			OriginalPort: uint16(port),
			MappedIP:     mappedIPv4,
			MappedPort:   uint16(port), // 暂时保持原端口; 生产环境需分配
			Proto:        "RTP",
		})
		// RTCP 通常是 RTP 端口 + 1
		mediaPorts = append(mediaPorts, MediaPort{
			OriginalIP:   clientIPv6,
			OriginalPort: uint16(port) + 1,
			MappedIP:     mappedIPv4,
			MappedPort:   uint16(port) + 1,
			Proto:        "RTCP",
		})
		return match // m= 行端口暂不改动
	})

	return []byte(s), mediaPorts
}

// rewriteSDP4to6 将 SDP 中的 IPv4 重写为 IPv6
func (t *Translator) rewriteSDP4to6(sdpBody []byte, serverIPv4, clientIPv6 net.IP) []byte {
	s := string(sdpBody)
	ipv6Str := clientIPv6.String()

	// IPv4 的 c= 和 o= 行匹配
	reC4 := regexp.MustCompile(`(?m)^(c=IN\s+)IP4\s+([\d.]+)\s*$`)
	reO4 := regexp.MustCompile(`(?m)^(o=[^\r\n]*IN\s+)IP4\s+([\d.]+)\s*$`)

	s = reC4.ReplaceAllStringFunc(s, func(match string) string {
		sub := reC4.FindStringSubmatch(match)
		if sub[2] == t.PoolIPv4.String() || sub[2] == serverIPv4.String() {
			return sub[1] + "IP6 " + ipv6Str
		}
		return match
	})

	s = reO4.ReplaceAllStringFunc(s, func(match string) string {
		sub := reO4.FindStringSubmatch(match)
		if sub[2] == t.PoolIPv4.String() || sub[2] == serverIPv4.String() {
			return sub[1] + "IP6 " + ipv6Str
		}
		return match
	})

	return []byte(s)
}

// ============================================================================
// 工具函数
// ============================================================================

// updateContentLength 更新 SIP Header 中的 Content-Length 字段
func updateContentLength(header []byte, bodyLen int) []byte {
	s := string(header)
	s = reContentLength.ReplaceAllString(s, fmt.Sprintf("${1}%d", bodyLen))
	return []byte(s)
}

// assembleSIPMessage 组装 SIP 消息
func assembleSIPMessage(header, body []byte) []byte {
	result := make([]byte, 0, len(header)+4+len(body))
	result = append(result, header...)
	result = append(result, sipHeaderBodySep...)
	result = append(result, body...)
	return result
}

// isAnyIPv6 检查是否是任何 IPv6 地址格式
func isAnyIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}
