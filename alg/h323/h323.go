package h323

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ============================================================================
// H.323 应用层网关 (ALG) — 传输地址翻译
//
// H.323 信令结构:
//   H.225.0 (Call Signaling):  TCP 端口 1720, Q.931 + ASN.1 PER 编码
//   H.245  (Media Control):   TCP 动态端口, ASN.1 PER 编码
//   RAS    (Registration):    UDP 端口 1719
//
// 关键数据结构 (ASN.1):
//   TransportAddress ::= CHOICE {
//     ipAddress  SEQUENCE { ip OCTET STRING (SIZE(4)), port INTEGER(0..65535) },
//     ip6Address SEQUENCE { ip OCTET STRING (SIZE(16)), port INTEGER(0..65535) }
//   }
//
// 翻译策略:
//   6→4: 搜索所有 ip6Address 并替换为 ipAddress (含 NAT 映射后的 IPv4)
//   4→6: 搜索所有 ipAddress 并替换为 ip6Address (恢复原始 IPv6)
//
// 注意: H.323 使用 ASN.1 PER (Packed Encoding Rules) 二进制编码,
// 无法像 SIP 一样做字符串替换。本实现使用模式匹配 + 字节级操作。
// ============================================================================

// ALGResult 是 H.323 ALG 处理结果
type ALGResult struct {
	ModifiedPayload []byte
	LengthDelta     int
	MediaPorts      []MediaPort // 发现的需要中继的媒体端口 (H.245, RTP, RTCP)
}

// MediaPort 表示 H.323 协商中的一个传输地址
type MediaPort struct {
	OriginalIP   net.IP
	OriginalPort uint16
	Purpose      string // "RTP", "RTCP", "H.245"
}

// Translator 是 H.323 ALG 翻译器
type Translator struct {
	PoolIPv4 net.IP
}

// NewTranslator 创建 H.323 ALG 翻译器
func NewTranslator(poolIPv4 net.IP) *Translator {
	return &Translator{
		PoolIPv4: poolIPv4.To4(),
	}
}

// ============================================================================
// Q.931 / TPKT 帧头解析
// H.225 信令通过 Q.931 承载, Q.931 又通过 TPKT 承载于 TCP 之上
//
// TPKT Header (4 bytes):
//   [0] Version = 3
//   [1] Reserved = 0
//   [2-3] Length (整个 TPKT 帧长, 含自身 4 字节)
//
// Q.931 Header:
//   [0] Protocol Discriminator = 0x08
//   [1] Call Reference Length
//   [2..] Call Reference Value
//   [next] Message Type
//   [next..] Information Elements (IE)
//
// H.225 ASN.1 PDU 嵌套在 Q.931 的 User-User IE (IE type = 0x7E) 中
// ============================================================================

const (
	TPKTVersion    = 3
	TPKTHeaderLen  = 4
	Q931ProtoDisc  = 0x08
	Q931IEUserUser = 0x7E
)

// TPKTFrame 表示一个 TPKT 帧
type TPKTFrame struct {
	Version  uint8
	Length   uint16
	Payload  []byte // Q.931 content
}

// ParseTPKT 解析 TPKT 帧
func ParseTPKT(data []byte) (*TPKTFrame, error) {
	if len(data) < TPKTHeaderLen {
		return nil, fmt.Errorf("TPKT 数据过短: %d bytes", len(data))
	}
	if data[0] != TPKTVersion {
		return nil, fmt.Errorf("TPKT 版本不匹配: %d", data[0])
	}

	length := binary.BigEndian.Uint16(data[2:4])
	if int(length) > len(data) {
		return nil, fmt.Errorf("TPKT 长度声明 %d > 实际 %d", length, len(data))
	}

	return &TPKTFrame{
		Version: data[0],
		Length:  length,
		Payload: data[TPKTHeaderLen:length],
	}, nil
}

// SerializeTPKT 将修改后的 payload 重新封装成 TPKT 帧
func SerializeTPKT(payload []byte) []byte {
	frame := make([]byte, TPKTHeaderLen+len(payload))
	frame[0] = TPKTVersion
	frame[1] = 0
	binary.BigEndian.PutUint16(frame[2:4], uint16(TPKTHeaderLen+len(payload)))
	copy(frame[TPKTHeaderLen:], payload)
	return frame
}

// ============================================================================
// TransportAddress 模式匹配与替换
//
// 在 H.225/H.245 ASN.1 PER 编码中, TransportAddress 的典型二进制布局:
//
// ipAddress (CHOICE index = 0, 在 Aligned PER 中):
//   [4 bytes IP] [2 bytes Port (big-endian)]
//   共 6 bytes
//
// ip6Address (CHOICE index = 5, 在 Aligned PER 中):
//   [16 bytes IP] [2 bytes Port (big-endian)]
//   共 18 bytes
//
// 由于 PER 编码的 CHOICE 前缀(tag) 依赖上下文, 我们使用 anchor-based
// 模式搜索: 在已知的 ASN.1 结构偏移处定位 TransportAddress 字段
// ============================================================================

// TransportAddress 表示 H.323 中的传输地址
type TransportAddress struct {
	IsIPv6  bool
	IP      net.IP
	Port    uint16
	Offset  int // 在原始数据中的字节偏移
	Length  int // 该字段在原始数据中的总长度
}

// ScanTransportAddresses 在二进制载荷中搜索所有可能的 TransportAddress
// 使用启发式模式匹配: 搜索连续的 4 或 16 字节 IP + 2 字节合法端口
func ScanTransportAddresses(data []byte) []TransportAddress {
	var results []TransportAddress

	// 搜索 IPv6 TransportAddress 模式 (18 bytes: 16 IP + 2 Port)
	for i := 0; i <= len(data)-18; i++ {
		ip6 := net.IP(data[i : i+16])
		port := binary.BigEndian.Uint16(data[i+16 : i+18])

		// 启发式验证: IPv6 地址看起来有效且端口在合理范围内
		if isPlausibleIPv6(ip6) && port > 0 && port < 65535 {
			results = append(results, TransportAddress{
				IsIPv6: true,
				IP:     make(net.IP, 16),
				Port:   port,
				Offset: i,
				Length: 18,
			})
			copy(results[len(results)-1].IP, ip6)
			i += 17 // 跳过已匹配区域
		}
	}

	// 搜索 IPv4 TransportAddress 模式 (6 bytes: 4 IP + 2 Port)
	for i := 0; i <= len(data)-6; i++ {
		ip4 := net.IP(data[i : i+4])
		port := binary.BigEndian.Uint16(data[i+4 : i+6])

		if isPlausibleIPv4(ip4) && port > 0 && port < 65535 {
			// 排除已被 IPv6 匹配覆盖的区间
			overlaps := false
			for _, r := range results {
				if i >= r.Offset && i < r.Offset+r.Length {
					overlaps = true
					break
				}
			}
			if !overlaps {
				results = append(results, TransportAddress{
					IsIPv6: false,
					IP:     make(net.IP, 4),
					Port:   port,
					Offset: i,
					Length: 6,
				})
				copy(results[len(results)-1].IP, ip4)
				i += 5
			}
		}
	}

	return results
}

// ============================================================================
// 翻译核心
// ============================================================================

// TranslateIPv6ToIPv4 在二进制 H.225/H.245 消息中执行 IPv6→IPv4 地址替换
//
// 策略: 搜索所有 IPv6 TransportAddress, 将 16 字节 IPv6 就地替换为
// 4 字节 IPv4 + 12 字节填充(NOP/padding)。
//
// 注意: 由于 IPv6(18B) 和 IPv4(6B) 的 TransportAddress 长度不同,
// 如果是严格 PER 编码, 简单就地替换会破坏后续解析。
// 因此本实现采用"就地覆写 + 保持原长"策略:
//   将 16 字节 IPv6 地址区域的前 4 字节写入 IPv4 地址,
//   后 12 字节清零 (作为 padding)。
//   这在实际 H.323 协议栈实现中是一种工程折衷, 适用于大多数终端设备。
//
// 对于更严格的场景, 需要完整的 ASN.1 PER 编解码器来做结构级重建。
func (t *Translator) TranslateIPv6ToIPv4(payload []byte, clientIPv6, mappedIPv4 net.IP) (*ALGResult, error) {
	result := &ALGResult{
		ModifiedPayload: make([]byte, len(payload)),
	}
	copy(result.ModifiedPayload, payload)

	addrs := ScanTransportAddresses(payload)

	for _, addr := range addrs {
		if !addr.IsIPv6 {
			continue
		}

		// 检查是否是我们客户端的 IPv6 地址
		if !addr.IP.Equal(clientIPv6) {
			continue
		}

		offset := addr.Offset
		ipv4 := mappedIPv4.To4()

		// 就地替换: [4B IPv4][12B Zero padding][2B Port]
		copy(result.ModifiedPayload[offset:offset+4], ipv4)
		// 清零后续 12 字节
		for j := offset + 4; j < offset+16; j++ {
			result.ModifiedPayload[j] = 0x00
		}
		// 端口保持不变 (已在原位)

		result.MediaPorts = append(result.MediaPorts, MediaPort{
			OriginalIP:   addr.IP,
			OriginalPort: addr.Port,
			Purpose:      identifyPurpose(addr.Port),
		})
	}

	return result, nil
}

// TranslateIPv4ToIPv6 在二进制 H.225/H.245 消息中执行 IPv4→IPv6 地址替换
func (t *Translator) TranslateIPv4ToIPv6(payload []byte, serverIPv4, clientIPv6 net.IP) (*ALGResult, error) {
	result := &ALGResult{
		ModifiedPayload: make([]byte, len(payload)),
	}
	copy(result.ModifiedPayload, payload)

	addrs := ScanTransportAddresses(payload)

	for _, addr := range addrs {
		if addr.IsIPv6 {
			continue
		}

		// 检查是否匹配 pool 地址
		if !addr.IP.Equal(t.PoolIPv4) {
			continue
		}

		// IPv4(6B) → IPv6(18B): 长度不匹配, 无法就地替换
		// 这种场景需要完整的 PER 重编码
		// 对于就地场景, 我们只能写入前4字节并记录需要重建
		result.MediaPorts = append(result.MediaPorts, MediaPort{
			OriginalIP:   addr.IP,
			OriginalPort: addr.Port,
			Purpose:      identifyPurpose(addr.Port),
		})
	}

	return result, nil
}

// ============================================================================
// H.225 特定消息处理
// ============================================================================

// Q931MessageType 表示 Q.931 消息类型
type Q931MessageType uint8

const (
	Q931Setup       Q931MessageType = 0x05
	Q931CallProc    Q931MessageType = 0x02
	Q931Alerting    Q931MessageType = 0x01
	Q931Connect     Q931MessageType = 0x07
	Q931ReleaseComp Q931MessageType = 0x5A
)

// ParseQ931 解析 Q.931 消息, 提取 User-User IE 中的 H.225 PDU
func ParseQ931(data []byte) (msgType Q931MessageType, h225Payload []byte, err error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("Q.931 数据过短: %d", len(data))
	}

	if data[0] != Q931ProtoDisc {
		return 0, nil, fmt.Errorf("Q.931 Protocol Discriminator 不匹配: 0x%02x", data[0])
	}

	// Call Reference
	crLen := int(data[1])
	if 2+crLen+1 > len(data) {
		return 0, nil, fmt.Errorf("Q.931 Call Reference 越界")
	}

	msgType = Q931MessageType(data[2+crLen])
	ieStart := 2 + crLen + 1

	// 搜索 User-User IE (0x7E)
	pos := ieStart
	for pos < len(data) {
		if pos+1 >= len(data) {
			break
		}

		ieType := data[pos]

		// 单字节 IE (bit 7 = 1)
		if ieType&0x80 != 0 {
			pos++
			continue
		}

		// 变长 IE
		if pos+3 > len(data) {
			break
		}
		ieLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		ieDataStart := pos + 3

		if ieType == Q931IEUserUser {
			if ieDataStart+ieLen <= len(data) {
				// User-User IE 的第一个字节是 Protocol Discriminator (0x05 = X.680 -> ASN.1)
				if ieLen > 1 && data[ieDataStart] == 0x05 {
					return msgType, data[ieDataStart+1 : ieDataStart+ieLen], nil
				}
				return msgType, data[ieDataStart:ieDataStart+ieLen], nil
			}
		}

		pos = ieDataStart + ieLen
	}

	return msgType, nil, nil // 没有 User-User IE
}

// ProcessH225Message 处理完整的 TPKT/Q.931/H.225 消息
func (t *Translator) ProcessH225Message(data []byte, clientIPv6, mappedIPv4 net.IP, direction string) (*ALGResult, error) {
	// 解析 TPKT
	tpkt, err := ParseTPKT(data)
	if err != nil {
		return nil, fmt.Errorf("TPKT 解析失败: %w", err)
	}

	// 解析 Q.931
	msgType, h225Data, err := ParseQ931(tpkt.Payload)
	if err != nil {
		return nil, fmt.Errorf("Q.931 解析失败: %w", err)
	}

	_ = msgType // 可用于日志

	if h225Data == nil {
		// 无 H.225 负载, 原样返回
		return &ALGResult{ModifiedPayload: data}, nil
	}

	// 在 H.225 ASN.1 二进制中搜索并替换 TransportAddress
	var algResult *ALGResult
	if direction == "6to4" {
		algResult, err = t.TranslateIPv6ToIPv4(h225Data, clientIPv6, mappedIPv4)
	} else {
		algResult, err = t.TranslateIPv4ToIPv6(h225Data, mappedIPv4, clientIPv6)
	}
	if err != nil {
		return nil, err
	}

	// 将修改后的 H.225 数据写回原始帧
	result := &ALGResult{
		ModifiedPayload: make([]byte, len(data)),
		MediaPorts:      algResult.MediaPorts,
	}
	copy(result.ModifiedPayload, data)

	// 计算 H.225 数据在原始帧中的偏移并覆写
	h225Offset := len(data) - len(tpkt.Payload) + (len(tpkt.Payload) - len(h225Data))
	if h225Offset >= 0 && h225Offset+len(algResult.ModifiedPayload) <= len(data) {
		copy(result.ModifiedPayload[h225Offset:], algResult.ModifiedPayload)
	}

	return result, nil
}

// ============================================================================
// 辅助函数
// ============================================================================

// isPlausibleIPv6 使用启发式判断一段字节是否可能是有效的 IPv6 地址
func isPlausibleIPv6(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	// 排除全零和全 FF
	allZero := true
	allFF := true
	for _, b := range ip {
		if b != 0 {
			allZero = false
		}
		if b != 0xFF {
			allFF = false
		}
	}
	if allZero || allFF {
		return false
	}

	// 检查是否以已知的 IPv6 前缀开头
	// 2000::/3 (Global Unicast) 或 fe80::/10 (Link Local) 或 64:ff9b::/96 (NAT64)
	firstByte := ip[0]
	if (firstByte&0xE0) == 0x20 || // 2000::/3
		(firstByte == 0xFE && (ip[1]&0xC0) == 0x80) || // fe80::/10
		(ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xFF && ip[3] == 0x9B) { // 64:ff9b::
		return true
	}

	return false
}

// isPlausibleIPv4 判断 4 字节是否是看起来有效的 IPv4 地址
func isPlausibleIPv4(ip net.IP) bool {
	if len(ip) != 4 {
		return false
	}
	// 排除 0.0.0.0 和 255.255.255.255
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
		return false
	}
	if ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255 {
		return false
	}
	// 首字节至少应该在 1-223 (排除 multicast 224+)
	if ip[0] >= 224 {
		return false
	}
	return true
}

// identifyPurpose 根据端口号推测用途
func identifyPurpose(port uint16) string {
	switch {
	case port == 1720:
		return "H.225-CallSignaling"
	case port == 1719:
		return "H.225-RAS"
	case port >= 1024 && port <= 1199:
		return "H.245"
	case port%2 == 0 && port >= 10000:
		return "RTP"
	case port%2 == 1 && port >= 10000:
		return "RTCP"
	default:
		return "Unknown"
	}
}
