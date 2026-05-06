package nat64

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ============================================================================
// IPv4 分片与 IPv6 Fragment Header 翻译
//
// RFC 6145 Section 5.1: IPv4→IPv6 分片翻译规则:
//   - DF=1, MF=0, Offset=0 → 不添加 Fragment Header
//   - DF=0 (允许分片) 或实际分片 → 添加 Fragment Extension Header
//
// RFC 6145 Section 4.1: IPv6→IPv4 分片翻译规则:
//   - 无 Fragment Header → DF=1
//   - 有 Fragment Header → DF=0, 映射 Fragment Offset/MF/ID
//
// ============================================================================

// IPv4 分片相关常量
const (
	IPv4FlagDF         uint16 = 0x4000 // Don't Fragment
	IPv4FlagMF         uint16 = 0x2000 // More Fragments
	IPv4FragOffsetMask uint16 = 0x1FFF // Fragment Offset (以 8 字节为单位)
)

// IPv4FragmentInfo 保存 IPv4 包的分片信息
type IPv4FragmentInfo struct {
	DontFragment   bool   // DF 标志
	MoreFragments  bool   // MF 标志
	FragmentOffset uint16 // 分片偏移 (以 8 字节为单位)
	Identification uint16 // IP 标识符
	IsFragment     bool   // 是否是分片包 (MF=1 或 offset>0)
}

// ParseIPv4FragmentInfo 从 IPv4 包中提取分片信息
func ParseIPv4FragmentInfo(rawIPv4 []byte) (*IPv4FragmentInfo, error) {
	if len(rawIPv4) < IPv4HeaderMinLen {
		return nil, fmt.Errorf("IPv4 包过短: %d bytes", len(rawIPv4))
	}

	flags := binary.BigEndian.Uint16(rawIPv4[6:8])
	info := &IPv4FragmentInfo{
		DontFragment:   (flags & IPv4FlagDF) != 0,
		MoreFragments:  (flags & IPv4FlagMF) != 0,
		FragmentOffset: flags & IPv4FragOffsetMask,
		Identification: binary.BigEndian.Uint16(rawIPv4[4:6]),
	}
	info.IsFragment = info.MoreFragments || info.FragmentOffset > 0

	return info, nil
}

// TranslateIPv6ToIPv4WithFragments 将 IPv6 包(可能含 Fragment Header)翻译为 IPv4 包
// 处理 Fragment Extension Header → IPv4 分片标志 的映射
func TranslateIPv6ToIPv4WithFragments(rawIPv6 []byte, srcIPv4, dstIPv4 net.IP) ([]byte, error) {
	if len(rawIPv6) < IPv6HeaderLen {
		return nil, fmt.Errorf("IPv6 包过短: %d bytes", len(rawIPv6))
	}

	// 解析扩展头链
	parsed, err := ParseIPv6ExtensionHeaders(rawIPv6)
	if err != nil {
		return nil, fmt.Errorf("解析 IPv6 扩展头失败: %w", err)
	}

	// 如果是后续分片 (offset>0), 无法访问传输层头
	// 但仍然需要翻译 IP 头和分片信息
	if parsed.IsSubsequentFragment() {
		return translateIPv6FragmentToIPv4(rawIPv6, parsed, srcIPv4, dstIPv4)
	}

	// 对于未分片的包或第一个分片: 先剥离 Fragment Header, 再做标准翻译
	if parsed.HasFragment && parsed.IsUnfragmented() {
		// 有 Fragment Header 但未实际分片 (atomic fragment)
		// 剥离 Fragment Header, 作为普通包翻译, 但保留 DF=0
		stripped, err := StripFragmentHeader(rawIPv6, parsed)
		if err != nil {
			return nil, err
		}
		ipv4Pkt, err := TranslateIPv6ToIPv4(stripped, srcIPv4, dstIPv4)
		if err != nil {
			return nil, err
		}
		// 清除 DF 位 (原始 IPv6 有 Fragment Header 暗示允许分片)
		flags := binary.BigEndian.Uint16(ipv4Pkt[6:8])
		flags &= ^IPv4FlagDF
		binary.BigEndian.PutUint16(ipv4Pkt[6:8], flags)
		// 设置 Identification
		binary.BigEndian.PutUint16(ipv4Pkt[4:6], uint16(parsed.FragmentID))
		// 重算 IPv4 首部校验和
		ipv4Pkt[10] = 0
		ipv4Pkt[11] = 0
		binary.BigEndian.PutUint16(ipv4Pkt[10:12], IPv4HeaderChecksum(ipv4Pkt[:IPv4HeaderMinLen]))
		return ipv4Pkt, nil
	}

	if parsed.IsFirstFragment() {
		return translateIPv6FragmentToIPv4(rawIPv6, parsed, srcIPv4, dstIPv4)
	}

	// 无 Fragment Header: 标准翻译 (DF=1 已在 TranslateIPv6ToIPv4 中设置)
	return TranslateIPv6ToIPv4(rawIPv6, srcIPv4, dstIPv4)
}

// translateIPv6FragmentToIPv4 翻译包含 Fragment Header 的 IPv6 分片为 IPv4 分片
func translateIPv6FragmentToIPv4(rawIPv6 []byte, parsed *IPv6ParsedHeaders, srcIPv4, dstIPv4 net.IP) ([]byte, error) {
	// 剥离 Fragment Header
	stripped, err := StripFragmentHeader(rawIPv6, parsed)
	if err != nil {
		return nil, err
	}

	// 构建 IPv4 头
	tos := (rawIPv6[0]&0x0F)<<4 | rawIPv6[1]>>4
	hopLimit := rawIPv6[7]

	// 获取传输层协议 (Fragment Header 中的 Next Header)
	ipv4Proto, err := mapNextHeaderToIPv4(parsed.TransportProto)
	if err != nil {
		return nil, err
	}

	// 计算 IPv4 载荷 (去掉 IPv6 基本头和所有扩展头, 不含 Fragment Header)
	payloadStart := parsed.TransportOffset
	if parsed.HasFragment {
		// 由于已剥离 Fragment Header, 需要调整偏移
		payloadStart -= FragmentHdrLen
	}
	// 使用 stripped 包, 从基本头后开始就是载荷
	ipv4Payload := stripped[IPv6HeaderLen:]

	totalLen := IPv4HeaderMinLen + len(ipv4Payload)
	ipv4Pkt := make([]byte, totalLen)
	ipv4Hdr := ipv4Pkt[:IPv4HeaderMinLen]

	ipv4Hdr[0] = 0x45
	ipv4Hdr[1] = tos
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], uint16(totalLen))

	// Identification: 使用 Fragment Header 的 ID 低 16 位
	binary.BigEndian.PutUint16(ipv4Hdr[4:6], uint16(parsed.FragmentID))

	// Flags + Fragment Offset
	var flags uint16
	// DF=0 (因为有 Fragment Header)
	if parsed.MoreFragments {
		flags |= IPv4FlagMF
	}
	flags |= parsed.FragmentOffset & IPv4FragOffsetMask
	binary.BigEndian.PutUint16(ipv4Hdr[6:8], flags)

	ipv4Hdr[8] = hopLimit
	ipv4Hdr[9] = ipv4Proto

	src4 := srcIPv4.To4()
	dst4 := dstIPv4.To4()
	copy(ipv4Hdr[12:16], src4)
	copy(ipv4Hdr[16:20], dst4)

	// 首部校验和
	ipv4Hdr[10] = 0
	ipv4Hdr[11] = 0
	binary.BigEndian.PutUint16(ipv4Hdr[10:12], IPv4HeaderChecksum(ipv4Hdr))

	copy(ipv4Pkt[IPv4HeaderMinLen:], ipv4Payload)

	// 只有第一个分片需要重算传输层校验和
	if parsed.FragmentOffset == 0 {
		recalcTransportChecksum4(ipv4Pkt, ipv4Proto)
	}

	return ipv4Pkt, nil
}

// TranslateIPv4ToIPv6WithFragments 将 IPv4 包(可能分片)翻译为 IPv6 包
// 处理 IPv4 分片标志 → Fragment Extension Header 的映射
func TranslateIPv4ToIPv6WithFragments(rawIPv4 []byte, srcIPv6, dstIPv6 net.IP) ([]byte, error) {
	if len(rawIPv4) < IPv4HeaderMinLen {
		return nil, fmt.Errorf("IPv4 包过短: %d bytes", len(rawIPv4))
	}

	fragInfo, err := ParseIPv4FragmentInfo(rawIPv4)
	if err != nil {
		return nil, err
	}

	// 非分片包且 DF=1: 标准翻译 (无需 Fragment Header)
	if !fragInfo.IsFragment && fragInfo.DontFragment {
		return TranslateIPv4ToIPv6(rawIPv4, srcIPv6, dstIPv6)
	}

	// 需要添加 Fragment Extension Header 的情况:
	// 1. 实际分片包 (MF=1 或 offset>0)
	// 2. DF=0 的未分片包 (需要保留"可分片"语义 → atomic fragment)
	return translateIPv4ToIPv6WithFragHdr(rawIPv4, fragInfo, srcIPv6, dstIPv6)
}

// translateIPv4ToIPv6WithFragHdr 构建含 Fragment Header 的 IPv6 包
func translateIPv4ToIPv6WithFragHdr(rawIPv4 []byte, fragInfo *IPv4FragmentInfo, srcIPv6, dstIPv6 net.IP) ([]byte, error) {
	ihl := int(rawIPv4[0]&0x0F) * 4
	if ihl < IPv4HeaderMinLen || ihl > len(rawIPv4) {
		return nil, fmt.Errorf("IHL 异常: %d", ihl)
	}

	tos := rawIPv4[1]
	protocol := rawIPv4[9]
	ttl := rawIPv4[8]

	nextHeader, err := mapProtocolToIPv6(protocol)
	if err != nil {
		return nil, err
	}

	ipv4Payload := rawIPv4[ihl:]
	totalLen := int(binary.BigEndian.Uint16(rawIPv4[2:4]))
	payloadLen := totalLen - ihl
	if payloadLen > len(ipv4Payload) {
		payloadLen = len(ipv4Payload)
	}
	ipv4Payload = ipv4Payload[:payloadLen]

	// IPv6 包 = 基本头 (40) + Fragment Header (8) + 载荷
	ipv6PktLen := IPv6HeaderLen + FragmentHdrLen + len(ipv4Payload)
	ipv6Pkt := make([]byte, ipv6PktLen)
	ipv6Hdr := ipv6Pkt[:IPv6HeaderLen]

	// Version=6, Traffic Class=TOS, Flow Label=0
	ipv6Hdr[0] = 0x60 | (tos >> 4)
	ipv6Hdr[1] = tos << 4
	ipv6Hdr[2] = 0
	ipv6Hdr[3] = 0

	// Payload Length = Fragment Header + 载荷
	binary.BigEndian.PutUint16(ipv6Hdr[4:6], uint16(FragmentHdrLen+len(ipv4Payload)))

	// Next Header = Fragment (44)
	ipv6Hdr[6] = ExtHdrFragment
	ipv6Hdr[7] = ttl

	src6 := srcIPv6.To16()
	dst6 := dstIPv6.To16()
	copy(ipv6Hdr[8:24], src6)
	copy(ipv6Hdr[24:40], dst6)

	// Fragment Header (8 bytes)
	fragHdr := ipv6Pkt[IPv6HeaderLen : IPv6HeaderLen+FragmentHdrLen]
	fragHdr[0] = nextHeader // 实际传输层协议
	fragHdr[1] = 0          // Reserved

	// Fragment Offset (13 bits) + Res (2 bits) + MF (1 bit)
	fragField := fragInfo.FragmentOffset << 3
	if fragInfo.MoreFragments {
		fragField |= 0x01
	}
	binary.BigEndian.PutUint16(fragHdr[2:4], fragField)

	// Identification (扩展 16-bit IPv4 ID 到 32-bit)
	binary.BigEndian.PutUint32(fragHdr[4:8], uint32(fragInfo.Identification))

	// 拷贝载荷
	copy(ipv6Pkt[IPv6HeaderLen+FragmentHdrLen:], ipv4Payload)

	// 只有第一个分片需要重算传输层校验和 (后续分片无传输层头)
	if fragInfo.FragmentOffset == 0 {
		// ICMPv6 需要伪首部, 其他协议也需要
		// 但校验和计算需要基于完整载荷, 对分片包这里只处理第一个分片
		recalcTransportChecksum6WithOffset(ipv6Pkt, nextHeader, IPv6HeaderLen+FragmentHdrLen)
	}

	return ipv6Pkt, nil
}

// recalcTransportChecksum6WithOffset 重新计算 IPv6 包中传输层校验和
// offset 是传输层头在 ipv6Pkt 中的起始偏移
func recalcTransportChecksum6WithOffset(ipv6Pkt []byte, nextHeader uint8, transportOffset int) error {
	if transportOffset >= len(ipv6Pkt) {
		return nil
	}

	srcIP := ipv6Pkt[8:24]
	dstIP := ipv6Pkt[24:40]
	payload := ipv6Pkt[transportOffset:]

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
