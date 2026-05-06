package nat64

import (
	"encoding/binary"
	"fmt"
)

// ============================================================================
// IPv6 Extension Header Chain 遍历
//
// IPv6 包可能在基本头之后包含一个或多个扩展头:
//   IPv6 Header (Next Header = X)
//     → Extension Header X (Next Header = Y)
//       → Extension Header Y (Next Header = Z)
//         → Transport Header Z (TCP/UDP/ICMPv6)
//
// 本模块提供工具来遍历扩展头链, 定位真实的传输层头和载荷.
//
// 参考: RFC 8200 Section 4
// ============================================================================

// IPv6 Extension Header 类型常量
const (
	ExtHdrHopByHop    uint8 = 0   // Hop-by-Hop Options
	ExtHdrRouting     uint8 = 43  // Routing
	ExtHdrFragment    uint8 = 44  // Fragment
	ExtHdrAH          uint8 = 51  // Authentication Header
	ExtHdrDestOptions uint8 = 60  // Destination Options
	ExtHdrNoNextHdr   uint8 = 59  // No Next Header

	// Fragment Extension Header 固定长度 8 bytes
	FragmentHdrLen = 8
)

// IPv6ParsedHeaders 保存解析后的 IPv6 头信息
type IPv6ParsedHeaders struct {
	// 传输层协议 (跳过所有扩展头后的 Next Header)
	TransportProto uint8

	// 传输层载荷在原始包中的起始偏移 (从 IPv6 包头字节 0 开始算)
	TransportOffset int

	// Fragment Header 信息 (如果存在)
	HasFragment    bool
	FragmentOffset uint16 // 分片偏移 (以 8 字节为单位)
	MoreFragments  bool   // MF 标志
	FragmentID     uint32 // 分片标识

	// Fragment Header 在原始包中的偏移 (用于移除/修改)
	FragHdrOffset int
}

// ParseIPv6ExtensionHeaders 遍历 IPv6 扩展头链
//
// 输入: rawIPv6 是完整的 IPv6 包 (从版本号开始)
// 输出: 解析后的头信息, 或错误
func ParseIPv6ExtensionHeaders(rawIPv6 []byte) (*IPv6ParsedHeaders, error) {
	if len(rawIPv6) < IPv6HeaderLen {
		return nil, fmt.Errorf("IPv6 包过短: %d bytes", len(rawIPv6))
	}

	result := &IPv6ParsedHeaders{}
	nextHeader := rawIPv6[6]
	offset := IPv6HeaderLen // 当前解析位置 (跳过基本头)

	// 最多遍历 16 层扩展头 (防止畸形包死循环)
	for i := 0; i < 16; i++ {
		switch nextHeader {
		case ExtHdrHopByHop, ExtHdrRouting, ExtHdrDestOptions:
			// 通用 TLV 格式扩展头
			if offset+2 > len(rawIPv6) {
				return nil, fmt.Errorf("扩展头 %d 越界 (offset=%d)", nextHeader, offset)
			}
			nextHeader = rawIPv6[offset]
			// Hdr Ext Len 以 8 字节为单位, 不含首 8 字节
			hdrLen := int(rawIPv6[offset+1])*8 + 8
			offset += hdrLen

		case ExtHdrFragment:
			// Fragment Header 固定 8 字节
			if offset+FragmentHdrLen > len(rawIPv6) {
				return nil, fmt.Errorf("Fragment Header 越界 (offset=%d)", offset)
			}
			result.HasFragment = true
			result.FragHdrOffset = offset
			nextHeader = rawIPv6[offset]
			// Byte 2-3: Fragment Offset (13 bits) + Res (2 bits) + MF (1 bit)
			fragField := binary.BigEndian.Uint16(rawIPv6[offset+2 : offset+4])
			result.FragmentOffset = fragField >> 3
			result.MoreFragments = (fragField & 0x01) != 0
			result.FragmentID = binary.BigEndian.Uint32(rawIPv6[offset+4 : offset+8])
			offset += FragmentHdrLen

		case ExtHdrAH:
			// Authentication Header
			if offset+2 > len(rawIPv6) {
				return nil, fmt.Errorf("AH Header 越界 (offset=%d)", offset)
			}
			nextHeader = rawIPv6[offset]
			// AH length 以 4 字节为单位, 减 2
			hdrLen := (int(rawIPv6[offset+1]) + 2) * 4
			offset += hdrLen

		case ExtHdrNoNextHdr:
			// 无后续载荷
			result.TransportProto = ExtHdrNoNextHdr
			result.TransportOffset = offset
			return result, nil

		default:
			// 到达传输层 (TCP/UDP/ICMPv6 或其他未知上层协议)
			result.TransportProto = nextHeader
			result.TransportOffset = offset
			return result, nil
		}

		if offset > len(rawIPv6) {
			return nil, fmt.Errorf("扩展头链越界: offset=%d, pktLen=%d", offset, len(rawIPv6))
		}
	}

	return nil, fmt.Errorf("扩展头链过长 (超过 16 层)")
}

// IsFirstFragment 判断是否是第一个分片 (offset=0, MF=1)
func (p *IPv6ParsedHeaders) IsFirstFragment() bool {
	return p.HasFragment && p.FragmentOffset == 0 && p.MoreFragments
}

// IsSubsequentFragment 判断是否是后续分片 (offset>0)
func (p *IPv6ParsedHeaders) IsSubsequentFragment() bool {
	return p.HasFragment && p.FragmentOffset > 0
}

// IsUnfragmented 判断包是否未分片 (无 Fragment Header, 或 offset=0 且 MF=0)
func (p *IPv6ParsedHeaders) IsUnfragmented() bool {
	if !p.HasFragment {
		return true
	}
	return p.FragmentOffset == 0 && !p.MoreFragments
}

// StripFragmentHeader 从 IPv6 包中移除 Fragment Extension Header
// 返回新的包 (不修改原始数据)
func StripFragmentHeader(rawIPv6 []byte, parsed *IPv6ParsedHeaders) ([]byte, error) {
	if !parsed.HasFragment {
		return rawIPv6, nil
	}

	fragOff := parsed.FragHdrOffset
	if fragOff < IPv6HeaderLen || fragOff+FragmentHdrLen > len(rawIPv6) {
		return nil, fmt.Errorf("Fragment Header 偏移无效: %d", fragOff)
	}

	// 新包 = 原包去掉 8 字节 Fragment Header
	newPkt := make([]byte, 0, len(rawIPv6)-FragmentHdrLen)
	newPkt = append(newPkt, rawIPv6[:fragOff]...)
	newPkt = append(newPkt, rawIPv6[fragOff+FragmentHdrLen:]...)

	// 修正前一个头的 Next Header 字段
	// Fragment Header 的 Next Header 值要写入前一个头的 Next Header 字段
	fragNextHdr := rawIPv6[fragOff] // Fragment Header 的 Next Header

	// 找到指向 Fragment Header 的前一个 Next Header 字段位置
	// 需要回溯扩展头链
	prevNHOff, err := findPrevNextHeaderOffset(rawIPv6, fragOff)
	if err != nil {
		return nil, err
	}
	newPkt[prevNHOff] = fragNextHdr

	// 更新 Payload Length
	newPayloadLen := uint16(len(newPkt) - IPv6HeaderLen)
	binary.BigEndian.PutUint16(newPkt[4:6], newPayloadLen)

	return newPkt, nil
}

// findPrevNextHeaderOffset 找到指向 offset 处扩展头的前一个 Next Header 字段位置
func findPrevNextHeaderOffset(rawIPv6 []byte, targetOffset int) (int, error) {
	if targetOffset == IPv6HeaderLen {
		// Fragment Header 紧跟基本头, Next Header 在基本头的 byte 6
		return 6, nil
	}

	// 遍历扩展头链找到前一个
	nextHeader := rawIPv6[6]
	offset := IPv6HeaderLen
	prevNHOffset := 6

	for i := 0; i < 16; i++ {
		if offset == targetOffset {
			return prevNHOffset, nil
		}

		switch nextHeader {
		case ExtHdrHopByHop, ExtHdrRouting, ExtHdrDestOptions:
			prevNHOffset = offset
			nextHeader = rawIPv6[offset]
			hdrLen := int(rawIPv6[offset+1])*8 + 8
			offset += hdrLen
		case ExtHdrFragment:
			prevNHOffset = offset
			nextHeader = rawIPv6[offset]
			offset += FragmentHdrLen
		case ExtHdrAH:
			prevNHOffset = offset
			nextHeader = rawIPv6[offset]
			hdrLen := (int(rawIPv6[offset+1]) + 2) * 4
			offset += hdrLen
		default:
			return 0, fmt.Errorf("无法定位 Fragment Header 的前驱")
		}
	}

	return 0, fmt.Errorf("扩展头链遍历未找到目标偏移 %d", targetOffset)
}
