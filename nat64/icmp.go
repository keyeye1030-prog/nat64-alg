package nat64

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ============================================================================
// ICMP ↔ ICMPv6 协议适配层
// 参照 RFC 6145 Section 4: Translating ICMPv6 Headers
//      RFC 6145 Section 5: Translating ICMPv4 Headers
//
// 核心区别:
//   ICMPv4 校验和: 仅覆盖 ICMP 消息本身 (无伪首部)
//   ICMPv6 校验和: 使用 IPv6 伪首部参与计算
//
// 类型映射 (信息类消息):
//   ICMPv6 Echo Request (128)    <-> ICMPv4 Echo Request (8)
//   ICMPv6 Echo Reply   (129)    <-> ICMPv4 Echo Reply   (0)
//
// 类型映射 (错误类消息):
//   ICMPv6 Destination Unreachable (1)  <-> ICMPv4 Destination Unreachable (3)
//   ICMPv6 Packet Too Big          (2)  <-> ICMPv4 Fragmentation Needed    (3/4)
//   ICMPv6 Time Exceeded           (3)  <-> ICMPv4 Time Exceeded           (11)
//   ICMPv6 Parameter Problem       (4)  <-> ICMPv4 Parameter Problem       (12)
// ============================================================================

// ICMPv6 类型常量
const (
	ICMPv6EchoRequest = 128
	ICMPv6EchoReply   = 129
	ICMPv6DstUnreach  = 1
	ICMPv6PktTooBig   = 2
	ICMPv6TimeExceed  = 3
	ICMPv6ParamProb   = 4
)

// ICMPv4 类型常量
const (
	ICMPv4EchoReply     = 0
	ICMPv4DstUnreach    = 3
	ICMPv4EchoRequest   = 8
	ICMPv4TimeExceed    = 11
	ICMPv4ParamProb     = 12
)

// ICMPv4 Code: Fragmentation Needed (用于 Packet Too Big)
const ICMPv4CodeFragNeeded = 4

// ---------- ICMPv6 -> ICMPv4 ----------

// TranslateICMPv6ToICMPv4 将 ICMPv6 负载转换为 ICMPv4 负载
//
// 输入:
//   icmpv6Payload: ICMPv6 头部+数据 (不含 IPv6 头)
//   srcIPv4, dstIPv4: 已转换的 IPv4 地址 (用于 ICMPv4 错误消息中嵌套包的地址翻译)
//
// 输出: 组装好的 ICMPv4 负载 (头+数据, 校验和已计算)
func TranslateICMPv6ToICMPv4(icmpv6Payload []byte, srcIPv4, dstIPv4 net.IP) ([]byte, error) {
	if len(icmpv6Payload) < 8 {
		return nil, fmt.Errorf("ICMPv6 负载过短: %d bytes", len(icmpv6Payload))
	}

	icmpType := icmpv6Payload[0]
	icmpCode := icmpv6Payload[1]
	// icmpv6Payload[2:4] 原始校验和 (将被重算)
	// icmpv6Payload[4:8] 消息体 (取决于类型)

	var v4Type, v4Code uint8
	var messageBody []byte // 4 bytes (Type 后紧跟的字段)
	var data []byte        // 剩余 data

	switch icmpType {

	// ---- 信息类消息 ----
	case ICMPv6EchoRequest:
		v4Type = ICMPv4EchoRequest
		v4Code = 0
		// Identifier 和 Sequence Number 保持不变
		messageBody = icmpv6Payload[4:8]
		data = icmpv6Payload[8:]

	case ICMPv6EchoReply:
		v4Type = ICMPv4EchoReply
		v4Code = 0
		messageBody = icmpv6Payload[4:8]
		data = icmpv6Payload[8:]

	// ---- 错误类消息 ----
	case ICMPv6DstUnreach:
		v4Type = ICMPv4DstUnreach
		v4Code = translateDstUnreachCode6to4(icmpCode)
		messageBody = make([]byte, 4) // Unused (4 bytes, 置 0)
		data = icmpv6Payload[8:]
		// 错误消息的 data 部分包含触发错误的原始 IPv6 包头, 需要嵌套翻译
		data = translateNestedIPv6ToIPv4(data, srcIPv4, dstIPv4)

	case ICMPv6PktTooBig:
		v4Type = ICMPv4DstUnreach
		v4Code = ICMPv4CodeFragNeeded
		// MTU 需要从 IPv6 MTU 减去 20 (IPv6 和 IPv4 头长度差 = 40-20=20)
		mtu := binary.BigEndian.Uint32(icmpv6Payload[4:8])
		if mtu > 20 {
			mtu -= 20 // 调整 MTU 差
		}
		messageBody = make([]byte, 4)
		// ICMPv4 格式: byte 2-3 = Next-Hop MTU (在 Unused+MTU 字段中)
		binary.BigEndian.PutUint16(messageBody[2:4], uint16(mtu))
		data = icmpv6Payload[8:]
		data = translateNestedIPv6ToIPv4(data, srcIPv4, dstIPv4)

	case ICMPv6TimeExceed:
		v4Type = ICMPv4TimeExceed
		v4Code = icmpCode // 直接映射
		messageBody = make([]byte, 4)
		data = icmpv6Payload[8:]
		data = translateNestedIPv6ToIPv4(data, srcIPv4, dstIPv4)

	case ICMPv6ParamProb:
		v4Type = ICMPv4ParamProb
		v4Code = 0
		// Pointer 值需要从 IPv6 偏移量翻译为 IPv4 偏移量
		ptr6 := binary.BigEndian.Uint32(icmpv6Payload[4:8])
		ptr4 := translateParamProbPointer6to4(ptr6)
		messageBody = make([]byte, 4)
		messageBody[0] = ptr4
		data = icmpv6Payload[8:]
		data = translateNestedIPv6ToIPv4(data, srcIPv4, dstIPv4)

	default:
		return nil, fmt.Errorf("不支持的 ICMPv6 类型: %d", icmpType)
	}

	// ---- 组装 ICMPv4 包 ----
	icmpv4 := make([]byte, 8+len(data))
	icmpv4[0] = v4Type
	icmpv4[1] = v4Code
	icmpv4[2] = 0 // 校验和先清零
	icmpv4[3] = 0
	copy(icmpv4[4:8], messageBody)
	copy(icmpv4[8:], data)

	// 计算 ICMPv4 校验和 (无伪首部)
	csum := ComputeChecksum(icmpv4)
	binary.BigEndian.PutUint16(icmpv4[2:4], csum)

	return icmpv4, nil
}

// ---------- ICMPv4 -> ICMPv6 ----------

// TranslateICMPv4ToICMPv6 将 ICMPv4 负载转换为 ICMPv6 负载
//
// 输入:
//   icmpv4Payload: ICMPv4 头部+数据 (不含 IPv4 头)
//   srcIPv6, dstIPv6: 已转换的 IPv6 地址
//
// 输出: 组装好的 ICMPv6 负载 (头+数据, 校验和需要由调用方结合伪首部计算)
//
// 注意: 返回的包中 checksum 字段为 0, 调用方需用 IPv6 伪首部重算
func TranslateICMPv4ToICMPv6(icmpv4Payload []byte, srcIPv6, dstIPv6 net.IP) ([]byte, error) {
	if len(icmpv4Payload) < 8 {
		return nil, fmt.Errorf("ICMPv4 负载过短: %d bytes", len(icmpv4Payload))
	}

	icmpType := icmpv4Payload[0]
	icmpCode := icmpv4Payload[1]

	var v6Type, v6Code uint8
	var messageBody []byte
	var data []byte

	switch icmpType {

	// ---- 信息类消息 ----
	case ICMPv4EchoRequest:
		v6Type = ICMPv6EchoRequest
		v6Code = 0
		messageBody = icmpv4Payload[4:8]
		data = icmpv4Payload[8:]

	case ICMPv4EchoReply:
		v6Type = ICMPv6EchoReply
		v6Code = 0
		messageBody = icmpv4Payload[4:8]
		data = icmpv4Payload[8:]

	// ---- 错误类消息 ----
	case ICMPv4DstUnreach:
		v6Type = ICMPv6DstUnreach
		if icmpCode == ICMPv4CodeFragNeeded {
			// Fragmentation Needed -> Packet Too Big
			v6Type = ICMPv6PktTooBig
			v6Code = 0
			mtu := binary.BigEndian.Uint16(icmpv4Payload[6:8])
			if mtu == 0 {
				mtu = 576 // 默认最小 MTU
			}
			messageBody = make([]byte, 4)
			// IPv6 MTU = IPv4 MTU + 20 (头部长度差)
			binary.BigEndian.PutUint32(messageBody, uint32(mtu)+20)
		} else {
			v6Code = translateDstUnreachCode4to6(icmpCode)
			messageBody = make([]byte, 4)
		}
		data = icmpv4Payload[8:]
		data = translateNestedIPv4ToIPv6(data, srcIPv6, dstIPv6)

	case ICMPv4TimeExceed:
		v6Type = ICMPv6TimeExceed
		v6Code = icmpCode
		messageBody = make([]byte, 4)
		data = icmpv4Payload[8:]
		data = translateNestedIPv4ToIPv6(data, srcIPv6, dstIPv6)

	case ICMPv4ParamProb:
		v6Type = ICMPv6ParamProb
		v6Code = 0
		ptr4 := icmpv4Payload[4]
		ptr6 := translateParamProbPointer4to6(ptr4)
		messageBody = make([]byte, 4)
		binary.BigEndian.PutUint32(messageBody, ptr6)
		data = icmpv4Payload[8:]
		data = translateNestedIPv4ToIPv6(data, srcIPv6, dstIPv6)

	default:
		return nil, fmt.Errorf("不支持的 ICMPv4 类型: %d", icmpType)
	}

	// ---- 组装 ICMPv6 包 ----
	icmpv6 := make([]byte, 8+len(data))
	icmpv6[0] = v6Type
	icmpv6[1] = v6Code
	icmpv6[2] = 0 // 校验和先清零 (需由调用方结合伪首部计算)
	icmpv6[3] = 0
	copy(icmpv6[4:8], messageBody)
	copy(icmpv6[8:], data)

	// ICMPv6 校验和由调用方通过 IPv6 伪首部计算
	// 在此处仅设置为 0

	return icmpv6, nil
}

// ============================================================================
// ICMPv6 Destination Unreachable Code 映射表 (RFC 6145 Section 4.2)
// ============================================================================

func translateDstUnreachCode6to4(code6 uint8) uint8 {
	switch code6 {
	case 0: // No route to destination
		return 1 // Host unreachable
	case 1: // Communication administratively prohibited
		return 10 // Administratively prohibited
	case 2: // Beyond scope of source address
		return 1 // Host unreachable
	case 3: // Address unreachable
		return 1 // Host unreachable
	case 4: // Port unreachable
		return 3 // Port unreachable
	default:
		return 1 // Host unreachable (保守默认)
	}
}

func translateDstUnreachCode4to6(code4 uint8) uint8 {
	switch code4 {
	case 0: // Net unreachable
		return 0 // No route to destination
	case 1: // Host unreachable
		return 3 // Address unreachable
	case 2: // Protocol unreachable
		return 4 // Port unreachable
	case 3: // Port unreachable
		return 4 // Port unreachable
	case 5: // Source route failed
		return 0 // No route
	case 9, 10: // Administratively prohibited
		return 1 // Communication administratively prohibited
	case 11, 12: // Network/Host unreachable for TOS
		return 0 // No route
	default:
		return 0
	}
}

// ============================================================================
// Parameter Problem Pointer 映射 (IPv6 头字段偏移 <-> IPv4 头字段偏移)
// ============================================================================

// translateParamProbPointer6to4 将 IPv6 字段偏移映射到 IPv4 字段偏移
func translateParamProbPointer6to4(ptr6 uint32) uint8 {
	// IPv6 Header:
	//   0: Version/TrafficClass   -> IPv4 offset 0 (Version/IHL)
	//   1: TrafficClass/FlowLabel -> IPv4 offset 1 (TOS)
	//   4: Payload Length         -> IPv4 offset 2 (Total Length)
	//   6: Next Header            -> IPv4 offset 9 (Protocol)
	//   7: Hop Limit              -> IPv4 offset 8 (TTL)
	//   8: Source Address         -> IPv4 offset 12 (Source Address)
	//  24: Destination Address    -> IPv4 offset 16 (Destination Address)
	switch {
	case ptr6 == 0:
		return 0
	case ptr6 == 1:
		return 1
	case ptr6 >= 4 && ptr6 <= 5:
		return 2 // Total Length
	case ptr6 == 6:
		return 9 // Protocol
	case ptr6 == 7:
		return 8 // TTL
	case ptr6 >= 8 && ptr6 <= 23:
		return 12 // Source Address
	case ptr6 >= 24 && ptr6 <= 39:
		return 16 // Destination Address
	default:
		return 0
	}
}

// translateParamProbPointer4to6 将 IPv4 字段偏移映射到 IPv6 字段偏移
func translateParamProbPointer4to6(ptr4 uint8) uint32 {
	switch {
	case ptr4 == 0:
		return 0 // Version
	case ptr4 == 1:
		return 1 // Traffic Class
	case ptr4 >= 2 && ptr4 <= 3:
		return 4 // Payload Length
	case ptr4 == 8:
		return 7 // Hop Limit
	case ptr4 == 9:
		return 6 // Next Header
	case ptr4 >= 12 && ptr4 <= 15:
		return 8 // Source Address
	case ptr4 >= 16 && ptr4 <= 19:
		return 24 // Destination Address
	default:
		return 0
	}
}

// ============================================================================
// ICMP 错误消息中嵌套包的翻译
// ICMP 错误消息的 Data 部分包含触发错误的原始 IP 包头 + 至少 8 字节传输层头
// 我们需要把这个嵌套的包头也做翻译
// ============================================================================

// translateNestedIPv6ToIPv4 翻译嵌套在 ICMPv6 错误消息中的原始 IPv6 包头
func translateNestedIPv6ToIPv4(data []byte, srcIPv4, dstIPv4 net.IP) []byte {
	if len(data) < IPv6HeaderLen {
		return data // 数据不够, 原样返回
	}

	// 解析原始 IPv6:
	tos := (data[0]&0x0F)<<4 | data[1]>>4
	payloadLen := binary.BigEndian.Uint16(data[4:6])
	nextHeader := data[6]
	hopLimit := data[7]

	ipv4Proto, err := mapNextHeaderToIPv4(nextHeader)
	if err != nil {
		return data // 不认识的协议, 原样返回
	}

	totalLen := IPv4HeaderMinLen + int(payloadLen)
	if totalLen > len(data)-IPv6HeaderLen+IPv4HeaderMinLen {
		totalLen = len(data) - IPv6HeaderLen + IPv4HeaderMinLen
	}

	// 构造简化的 IPv4 头
	result := make([]byte, IPv4HeaderMinLen)
	result[0] = 0x45
	result[1] = tos
	binary.BigEndian.PutUint16(result[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(result[4:6], 0) // ID
	binary.BigEndian.PutUint16(result[6:8], 0x4000)
	result[8] = hopLimit
	result[9] = ipv4Proto

	src4 := srcIPv4.To4()
	dst4 := dstIPv4.To4()
	copy(result[12:16], src4)
	copy(result[16:20], dst4)

	// 计算校验和
	binary.BigEndian.PutUint16(result[10:12], IPv4HeaderChecksum(result))

	// 追加原始 IPv6 payload 中尽可能多的数据 (至少 8 字节供调试)
	remaining := data[IPv6HeaderLen:]
	if len(remaining) > 0 {
		result = append(result, remaining...)
	}

	return result
}

// translateNestedIPv4ToIPv6 翻译嵌套在 ICMPv4 错误消息中的原始 IPv4 包头
func translateNestedIPv4ToIPv6(data []byte, srcIPv6, dstIPv6 net.IP) []byte {
	if len(data) < IPv4HeaderMinLen {
		return data
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < IPv4HeaderMinLen || ihl > len(data) {
		return data
	}

	tos := data[1]
	totalLen := binary.BigEndian.Uint16(data[2:4])
	protocol := data[9]
	ttl := data[8]

	nextHeader, err := mapProtocolToIPv6(protocol)
	if err != nil {
		return data
	}

	payloadLen := int(totalLen) - ihl
	if payloadLen < 0 {
		payloadLen = 0
	}

	// 构造简化的 IPv6 头
	result := make([]byte, IPv6HeaderLen)
	result[0] = 0x60 | (tos >> 4)
	result[1] = tos << 4
	binary.BigEndian.PutUint16(result[4:6], uint16(payloadLen))
	result[6] = nextHeader
	result[7] = ttl

	src6 := srcIPv6.To16()
	dst6 := dstIPv6.To16()
	copy(result[8:24], src6)
	copy(result[24:40], dst6)

	// 追加原始 IPv4 payload
	remaining := data[ihl:]
	if len(remaining) > 0 {
		result = append(result, remaining...)
	}

	return result
}
