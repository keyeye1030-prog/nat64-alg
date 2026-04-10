package nat64

import "net"

// ============================================================================
// NAT64 Well-Known Prefix 与地址转换工具
// 参照 RFC 6052: IPv6 Addressing of IPv4/IPv6 Translators
// ============================================================================

var (
	// WellKnownPrefix 是 NAT64 标准前缀 64:ff9b::/96
	// IPv4 地址嵌入在最后 32 bit: 64:ff9b::C0A8:0101 == 192.168.1.1
	WellKnownPrefix = net.IP{0x00, 0x64, 0xff, 0x9b,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	WellKnownPrefixLen = 96
)

// IPv4ToIPv6 将 IPv4 地址用 NAT64 well-known prefix 嵌入为合成的 IPv6 地址
// 例如: 192.168.1.1 -> 64:ff9b::c0a8:0101
func IPv4ToIPv6(ipv4 net.IP) net.IP {
	v4 := ipv4.To4()
	if v4 == nil {
		return nil
	}

	v6 := make(net.IP, 16)
	copy(v6, WellKnownPrefix)

	// 将 IPv4 的 4 字节写入 IPv6 地址的尾部 (bit 96-127)
	v6[12] = v4[0]
	v6[13] = v4[1]
	v6[14] = v4[2]
	v6[15] = v4[3]

	return v6
}

// IPv6ExtractIPv4 从合成的 NAT64 IPv6 地址中提取嵌入的 IPv4 地址
// 如果不是 64:ff9b::/96 前缀则返回 nil
func IPv6ExtractIPv4(ipv6 net.IP) net.IP {
	v6 := ipv6.To16()
	if v6 == nil {
		return nil
	}

	// 前 12 字节必须匹配 Well-Known Prefix
	for i := 0; i < 12; i++ {
		if v6[i] != WellKnownPrefix[i] {
			return nil
		}
	}

	return net.IPv4(v6[12], v6[13], v6[14], v6[15]).To4()
}

// IsNAT64Address 判断给定的 IPv6 地址是否使用了 NAT64 前缀
func IsNAT64Address(ipv6 net.IP) bool {
	return IPv6ExtractIPv4(ipv6) != nil
}
