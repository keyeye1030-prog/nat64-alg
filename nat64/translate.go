package nat64

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ============================================================================
// NAT64 IP 头部转换核心逻辑
// 参照 RFC 6145: IP/ICMP Translation Algorithm
// ============================================================================

// ---------- 常量定义 ----------

const (
	IPv4HeaderMinLen = 20
	IPv6HeaderLen    = 40

	// IPv4 Protocol / IPv6 Next Header 编号
	ProtoNumICMPv4  = 1
	ProtoNumTCPNum  = 6
	ProtoNumUDPNum  = 17
	ProtoNumICMPv6  = 58

	// IPv4 默认 TTL / IPv6 Hop Limit
	DefaultTTL = 64
)

// TranslateResult 是转换后输出包的容器
type TranslateResult struct {
	EthHeader   []byte // 以太帧头 (14 bytes), 可选
	IPHeader    []byte // 转换后的 IP 头
	Payload     []byte // 传输层及以上 (TCP/UDP/ICMP Header + Data)
	TotalLen    int
}

// ---------- IPv6 → IPv4 转换 ----------

// TranslateIPv6ToIPv4 将一个 IPv6 数据包转换为 IPv4 数据包
//
// 输入: rawIPv6 表示不含以太帧头的纯 IPv6 数据包
// 输出: 转换后的 IPv4 包 (IP Header + Payload) 或错误
//
// 注意: 本函数仅做包头转换与校验和重算, 不涉及 NAT 端口映射.
// 端口映射由 session table 在外部处理后传参进来.
func TranslateIPv6ToIPv4(rawIPv6 []byte, srcIPv4, dstIPv4 net.IP) ([]byte, error) {
	if len(rawIPv6) < IPv6HeaderLen {
		return nil, fmt.Errorf("IPv6 包过短: %d bytes", len(rawIPv6))
	}

	// ---- 解析 IPv6 首部基础字段 ----
	// Byte 0: Version (4 bit) + Traffic Class (高 4 bit)
	// Byte 1: Traffic Class (低 4 bit) + Flow Label (高 4 bit)
	// Byte 4-5: Payload Length
	// Byte 6: Next Header
	// Byte 7: Hop Limit
	// Byte 8-23: Source Address
	// Byte 24-39: Destination Address

	version := rawIPv6[0] >> 4
	if version != 6 {
		return nil, fmt.Errorf("非 IPv6 包, version=%d", version)
	}

	trafficClass := (rawIPv6[0]&0x0F)<<4 | rawIPv6[1]>>4
	payloadLen := binary.BigEndian.Uint16(rawIPv6[4:6])
	nextHeader := rawIPv6[6]
	hopLimit := rawIPv6[7]

	// 跳过扩展头 (简化处理: 本版本仅处理无扩展头的直连 Next Header)
	ipv6Payload := rawIPv6[IPv6HeaderLen:]
	if int(payloadLen) > len(ipv6Payload) {
		return nil, fmt.Errorf("Payload 长度声明 %d > 实际可用 %d", payloadLen, len(ipv6Payload))
	}
	ipv6Payload = ipv6Payload[:payloadLen]

	// ---- 映射 Next Header ----
	ipv4Proto, err := mapNextHeaderToIPv4(nextHeader)
	if err != nil {
		return nil, err
	}

	// ---- 构建 IPv4 首部 (20 bytes, 无 Options) ----
	totalLen := IPv4HeaderMinLen + len(ipv6Payload)
	ipv4Pkt := make([]byte, totalLen)
	ipv4Hdr := ipv4Pkt[:IPv4HeaderMinLen]

	ipv4Hdr[0] = 0x45                               // Version=4, IHL=5 (20 bytes)
	ipv4Hdr[1] = trafficClass                        // TOS = Traffic Class
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], uint16(totalLen)) // Total Length
	binary.BigEndian.PutUint16(ipv4Hdr[4:6], 0)     // Identification = 0
	binary.BigEndian.PutUint16(ipv4Hdr[6:8], 0x4000) // Flags: DF=1, Fragment Offset=0
	ipv4Hdr[8] = hopLimit                            // TTL = Hop Limit (直接映射)
	ipv4Hdr[9] = ipv4Proto                           // Protocol

	// 校验和字段先清零 (待后续填写)
	ipv4Hdr[10] = 0
	ipv4Hdr[11] = 0

	// 源/目的 IPv4 地址
	src4 := srcIPv4.To4()
	dst4 := dstIPv4.To4()
	copy(ipv4Hdr[12:16], src4)
	copy(ipv4Hdr[16:20], dst4)

	// 计算 IPv4 首部校验和
	binary.BigEndian.PutUint16(ipv4Hdr[10:12], IPv4HeaderChecksum(ipv4Hdr))

	// ---- 拷贝上层负载 ----
	copy(ipv4Pkt[IPv4HeaderMinLen:], ipv6Payload)

	// ---- 必须根据协议类型重算传输层校验和 ----
	// 因为伪首部从 IPv6 变成了 IPv4, 原来的校验和一定无效
	if err := recalcTransportChecksum4(ipv4Pkt, ipv4Proto); err != nil {
		return nil, err
	}

	return ipv4Pkt, nil
}

// ---------- IPv4 → IPv6 转换 ----------

// TranslateIPv4ToIPv6 将一个 IPv4 数据包转换为 IPv6 数据包
//
// 输入: rawIPv4 表示不含以太帧头的纯 IPv4 数据包
// srcIPv6, dstIPv6: 转换后的 IPv6 源和目的地址
func TranslateIPv4ToIPv6(rawIPv4 []byte, srcIPv6, dstIPv6 net.IP) ([]byte, error) {
	if len(rawIPv4) < IPv4HeaderMinLen {
		return nil, fmt.Errorf("IPv4 包过短: %d bytes", len(rawIPv4))
	}

	version := rawIPv4[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("非 IPv4 包, version=%d", version)
	}

	ihl := int(rawIPv4[0]&0x0F) * 4 // IPv4 头实际长度 (含 options)
	if ihl < IPv4HeaderMinLen || ihl > len(rawIPv4) {
		return nil, fmt.Errorf("IHL 异常: %d", ihl)
	}

	tos := rawIPv4[1]
	totalLen := binary.BigEndian.Uint16(rawIPv4[2:4])
	protocol := rawIPv4[9]
	ttl := rawIPv4[8]

	ipv4Payload := rawIPv4[ihl:]
	if int(totalLen) < ihl {
		return nil, fmt.Errorf("Total length %d < IHL %d", totalLen, ihl)
	}
	payloadLen := int(totalLen) - ihl
	if payloadLen > len(ipv4Payload) {
		payloadLen = len(ipv4Payload)
	}
	ipv4Payload = ipv4Payload[:payloadLen]

	// ---- 映射 Protocol 到 IPv6 Next Header ----
	nextHeader, err := mapProtocolToIPv6(protocol)
	if err != nil {
		return nil, err
	}

	// ---- 构建 IPv6 首部 (40 bytes, 无扩展头) ----
	ipv6Pkt := make([]byte, IPv6HeaderLen+len(ipv4Payload))
	ipv6Hdr := ipv6Pkt[:IPv6HeaderLen]

	// Version=6, Traffic Class=TOS, Flow Label=0
	ipv6Hdr[0] = 0x60 | (tos >> 4)
	ipv6Hdr[1] = (tos << 4)
	ipv6Hdr[2] = 0 // Flow Label
	ipv6Hdr[3] = 0

	binary.BigEndian.PutUint16(ipv6Hdr[4:6], uint16(len(ipv4Payload))) // Payload Length
	ipv6Hdr[6] = nextHeader
	ipv6Hdr[7] = ttl // Hop Limit = TTL

	// 源/目的 IPv6 地址
	src6 := srcIPv6.To16()
	dst6 := dstIPv6.To16()
	copy(ipv6Hdr[8:24], src6)
	copy(ipv6Hdr[24:40], dst6)

	// ---- 拷贝上层负载 ----
	copy(ipv6Pkt[IPv6HeaderLen:], ipv4Payload)

	// ---- 重算传输层校验和 (伪首部变了) ----
	if err := recalcTransportChecksum6(ipv6Pkt, nextHeader); err != nil {
		return nil, err
	}

	return ipv6Pkt, nil
}

// ---------- 内部辅助函数 ----------

// mapNextHeaderToIPv4 将 IPv6 Next Header 映射为 IPv4 Protocol
func mapNextHeaderToIPv4(nh uint8) (uint8, error) {
	switch nh {
	case ProtoNumTCPNum:
		return ProtoNumTCPNum, nil
	case ProtoNumUDPNum:
		return ProtoNumUDPNum, nil
	case ProtoNumICMPv6:
		return ProtoNumICMPv4, nil // ICMPv6 -> ICMPv4
	default:
		return 0, fmt.Errorf("不支持的 IPv6 Next Header: %d", nh)
	}
}

// mapProtocolToIPv6 将 IPv4 Protocol 映射为 IPv6 Next Header
func mapProtocolToIPv6(proto uint8) (uint8, error) {
	switch proto {
	case ProtoNumTCPNum:
		return ProtoNumTCPNum, nil
	case ProtoNumUDPNum:
		return ProtoNumUDPNum, nil
	case ProtoNumICMPv4:
		return ProtoNumICMPv6, nil // ICMPv4 -> ICMPv6
	default:
		return 0, fmt.Errorf("不支持的 IPv4 Protocol: %d", proto)
	}
}

// recalcTransportChecksum4 重新计算 IPv4 包中传输层校验和
func recalcTransportChecksum4(ipv4Pkt []byte, proto uint8) error {
	hdr := ipv4Pkt[:IPv4HeaderMinLen]
	payload := ipv4Pkt[IPv4HeaderMinLen:]
	srcIP := hdr[12:16]
	dstIP := hdr[16:20]

	switch proto {
	case ProtoNumTCPNum:
		if len(payload) < 20 {
			return fmt.Errorf("TCP 段过短")
		}
		// 清零原校验和
		payload[16] = 0
		payload[17] = 0
		psum := PseudoHeaderChecksumIPv4(srcIP, dstIP, ProtoNumTCPNum, uint16(len(payload)))
		csum := FinishChecksum(psum, payload)
		binary.BigEndian.PutUint16(payload[16:18], csum)

	case ProtoNumUDPNum:
		if len(payload) < 8 {
			return fmt.Errorf("UDP 段过短")
		}
		payload[6] = 0
		payload[7] = 0
		psum := PseudoHeaderChecksumIPv4(srcIP, dstIP, ProtoNumUDPNum, uint16(len(payload)))
		csum := FinishChecksum(psum, payload)
		if csum == 0 {
			csum = 0xFFFF // UDP 的 0 值校验和需表示为 0xFFFF
		}
		binary.BigEndian.PutUint16(payload[6:8], csum)

	case ProtoNumICMPv4:
		// ICMPv4 校验和不使用伪首部, 完全自包含
		if len(payload) < 8 {
			return fmt.Errorf("ICMP 段过短")
		}
		payload[2] = 0
		payload[3] = 0
		csum := ComputeChecksum(payload)
		binary.BigEndian.PutUint16(payload[2:4], csum)
	}

	return nil
}

// recalcTransportChecksum6 重新计算 IPv6 包中传输层校验和
func recalcTransportChecksum6(ipv6Pkt []byte, nextHeader uint8) error {
	hdr := ipv6Pkt[:IPv6HeaderLen]
	payload := ipv6Pkt[IPv6HeaderLen:]
	srcIP := hdr[8:24]
	dstIP := hdr[24:40]

	switch nextHeader {
	case ProtoNumTCPNum:
		if len(payload) < 20 {
			return fmt.Errorf("TCP 段过短")
		}
		payload[16] = 0
		payload[17] = 0
		psum := PseudoHeaderChecksumIPv6(srcIP, dstIP, ProtoNumTCPNum, uint32(len(payload)))
		csum := FinishChecksum(psum, payload)
		binary.BigEndian.PutUint16(payload[16:18], csum)

	case ProtoNumUDPNum:
		if len(payload) < 8 {
			return fmt.Errorf("UDP 段过短")
		}
		payload[6] = 0
		payload[7] = 0
		psum := PseudoHeaderChecksumIPv6(srcIP, dstIP, ProtoNumUDPNum, uint32(len(payload)))
		csum := FinishChecksum(psum, payload)
		if csum == 0 {
			csum = 0xFFFF
		}
		binary.BigEndian.PutUint16(payload[6:8], csum)

	case ProtoNumICMPv6:
		// ICMPv6 校验和使用 IPv6 伪首部
		if len(payload) < 8 {
			return fmt.Errorf("ICMPv6 段过短")
		}
		payload[2] = 0
		payload[3] = 0
		psum := PseudoHeaderChecksumIPv6(srcIP, dstIP, ProtoNumICMPv6, uint32(len(payload)))
		csum := FinishChecksum(psum, payload)
		binary.BigEndian.PutUint16(payload[2:4], csum)
	}

	return nil
}
