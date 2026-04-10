package nat64

import "encoding/binary"

// ============================================================================
// 校验和计算工具集 (IP / TCP / UDP / ICMP)
// ============================================================================

// ComputeChecksum 计算 RFC 1071 Internet Checksum
// 接收待校验的字节流, 返回 16-bit 校验和
func ComputeChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	// 奇数长度, 追加最后一个字节 (左对齐)
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	// 折叠进位
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}

// IPv4HeaderChecksum 计算 IPv4 首部校验和
// hdr 必须是完整的 IPv4 首部 (通常 20 字节), 其中 checksum 字段须先置 0
func IPv4HeaderChecksum(hdr []byte) uint16 {
	return ComputeChecksum(hdr)
}

// PseudoHeaderChecksumIPv4 构建 IPv4 伪首部并返回其上的部分校验和
// 用于 TCP/UDP/ICMP 校验和计算
func PseudoHeaderChecksumIPv4(srcIP, dstIP []byte, proto uint8, length uint16) uint32 {
	var sum uint32
	sum += uint32(srcIP[0])<<8 + uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 + uint32(srcIP[3])
	sum += uint32(dstIP[0])<<8 + uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 + uint32(dstIP[3])
	sum += uint32(proto)
	sum += uint32(length)
	return sum
}

// PseudoHeaderChecksumIPv6 构建 IPv6 伪首部并返回其上的部分校验和
// 用于 TCP/UDP/ICMPv6 校验和计算
func PseudoHeaderChecksumIPv6(srcIP, dstIP []byte, nextHeader uint8, length uint32) uint32 {
	var sum uint32
	// 源地址 (16 bytes = 8 words)
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 + uint32(srcIP[i+1])
	}
	// 目的地址 (16 bytes = 8 words)
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 + uint32(dstIP[i+1])
	}
	// Upper-layer packet length (32-bit)
	sum += length >> 16
	sum += length & 0xFFFF
	// Next Header (8-bit, 右对齐在 32-bit 字中)
	sum += uint32(nextHeader)
	return sum
}

// FinishChecksum 将部分校验和折叠到最终的 16-bit 校验和
func FinishChecksum(partialSum uint32, data []byte) uint16 {
	sum := partialSum
	length := len(data)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// UpdateChecksumField 增量更新校验和 (RFC 1624)
// 当只修改了部分字段(如 IP/Port)时，可以直接增量而非全量重新计算——高性能场景必需
func UpdateChecksumField(oldChecksum uint16, oldValue, newValue uint16) uint16 {
	// ~HC' = ~HC + ~m + m'
	sum := uint32(^oldChecksum) + uint32(^oldValue) + uint32(newValue)
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
