package nat64

import (
	"encoding/binary"
	"log"
	"net"

	"nat64-alg/alg/h323"
	"nat64-alg/alg/sip"
)

// ============================================================================
// ALG (Application Layer Gateway) 集成层
// 将 SIP 和 H.323 ALG 挂接到 NAT64 翻译管道中
// ============================================================================

// ALGHandler 管理所有应用层网关
type ALGHandler struct {
	sipTranslator  *sip.Translator
	h323Translator *h323.Translator
}

// NewALGHandler 创建 ALG 处理器
func NewALGHandler(poolIPv4 net.IP) *ALGHandler {
	return &ALGHandler{
		sipTranslator:  sip.NewTranslator(poolIPv4),
		h323Translator: h323.NewTranslator(poolIPv4),
	}
}

// ALG 端口常量
const (
	PortSIP     = 5060
	PortSIPTLS  = 5061
	PortH225    = 1720
	PortH225RAS = 1719
)

// NeedsALG 检查给定端口是否需要 ALG 处理
func NeedsALG(srcPort, dstPort uint16) bool {
	return isSIPPort(srcPort, dstPort) || isH323Port(srcPort, dstPort)
}

func isSIPPort(src, dst uint16) bool {
	return src == PortSIP || dst == PortSIP || src == PortSIPTLS || dst == PortSIPTLS
}

func isH323Port(src, dst uint16) bool {
	return src == PortH225 || dst == PortH225 || src == PortH225RAS || dst == PortH225RAS
}

// ProcessALG6to4 在 6→4 方向处理 ALG 协议
// 输入: ipv4Pkt 是已经完成 IP 头转换但尚未发送的 IPv4 包
// 返回: 修改后的 IPv4 包 (载荷可能已被 ALG 修改, 长度可能变化)
func (a *ALGHandler) ProcessALG6to4(ipv4Pkt []byte, sess *Session) ([]byte, int) {
	if len(ipv4Pkt) < IPv4HeaderMinLen+4 {
		return ipv4Pkt, 0
	}

	proto := ipv4Pkt[9]
	transportHdr := ipv4Pkt[IPv4HeaderMinLen:]
	srcPort := binary.BigEndian.Uint16(transportHdr[0:2])
	dstPort := binary.BigEndian.Uint16(transportHdr[2:4])

	// 提取应用层载荷
	var payloadOffset int
	if proto == ProtoNumTCPNum {
		if len(transportHdr) < 20 {
			return ipv4Pkt, 0
		}
		dataOffset := int(transportHdr[12]>>4) * 4
		payloadOffset = IPv4HeaderMinLen + dataOffset
	} else if proto == ProtoNumUDPNum {
		payloadOffset = IPv4HeaderMinLen + 8
	} else {
		return ipv4Pkt, 0
	}

	if payloadOffset >= len(ipv4Pkt) {
		return ipv4Pkt, 0
	}
	appPayload := ipv4Pkt[payloadOffset:]

	clientIPv6 := net.IP(sess.Key6.SrcIP[:]).To16()
	mappedIPv4 := net.IP(sess.Key4.SrcIP[:]).To4()

	var modifiedPayload []byte
	var lengthDelta int

	if isSIPPort(srcPort, dstPort) {
		// SIP ALG
		result, err := a.sipTranslator.TranslateIPv6ToIPv4(appPayload, clientIPv6, mappedIPv4)
		if err != nil {
			log.Printf("[ALG-SIP] 6→4 处理失败: %v", err)
			return ipv4Pkt, 0
		}
		modifiedPayload = result.ModifiedPayload
		lengthDelta = result.LengthDelta

		if len(result.MediaPorts) > 0 {
			log.Printf("[ALG-SIP] 发现 %d 个媒体端口需要 RTP 中继", len(result.MediaPorts))
		}

	} else if isH323Port(srcPort, dstPort) {
		// H.323 ALG
		result, err := a.h323Translator.TranslateIPv6ToIPv4(appPayload, clientIPv6, mappedIPv4)
		if err != nil {
			log.Printf("[ALG-H323] 6→4 处理失败: %v", err)
			return ipv4Pkt, 0
		}
		modifiedPayload = result.ModifiedPayload
		lengthDelta = result.LengthDelta

		if len(result.DynamicPorts) > 0 {
			log.Printf("[ALG-H323] 发现 %d 个动态端口", len(result.DynamicPorts))
		}
	}

	if modifiedPayload == nil || lengthDelta == 0 {
		return ipv4Pkt, 0
	}

	// 重新组装 IPv4 包 (载荷长度可能变化)
	newPkt := make([]byte, payloadOffset+len(modifiedPayload))
	copy(newPkt, ipv4Pkt[:payloadOffset])
	copy(newPkt[payloadOffset:], modifiedPayload)

	// 更新 IPv4 Total Length
	binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))

	// 如果是 UDP, 更新 UDP Length
	if proto == ProtoNumUDPNum {
		udpLen := uint16(8 + len(modifiedPayload))
		binary.BigEndian.PutUint16(newPkt[IPv4HeaderMinLen+4:IPv4HeaderMinLen+6], udpLen)
	}

	// 重算 IPv4 首部校验和
	newPkt[10] = 0
	newPkt[11] = 0
	binary.BigEndian.PutUint16(newPkt[10:12], IPv4HeaderChecksum(newPkt[:IPv4HeaderMinLen]))

	// 重算传输层校验和
	recalcTransportChecksum4(newPkt, proto)

	return newPkt, lengthDelta
}

// ProcessALG4to6 在 4→6 方向处理 ALG 协议
func (a *ALGHandler) ProcessALG4to6(ipv6Pkt []byte, sess *Session) ([]byte, int) {
	if len(ipv6Pkt) < IPv6HeaderLen+4 {
		return ipv6Pkt, 0
	}

	nextHeader := ipv6Pkt[6]
	transportHdr := ipv6Pkt[IPv6HeaderLen:]
	srcPort := binary.BigEndian.Uint16(transportHdr[0:2])
	dstPort := binary.BigEndian.Uint16(transportHdr[2:4])

	var payloadOffset int
	if nextHeader == ProtoNumTCPNum {
		if len(transportHdr) < 20 {
			return ipv6Pkt, 0
		}
		dataOffset := int(transportHdr[12]>>4) * 4
		payloadOffset = IPv6HeaderLen + dataOffset
	} else if nextHeader == ProtoNumUDPNum {
		payloadOffset = IPv6HeaderLen + 8
	} else {
		return ipv6Pkt, 0
	}

	if payloadOffset >= len(ipv6Pkt) {
		return ipv6Pkt, 0
	}
	appPayload := ipv6Pkt[payloadOffset:]

	serverIPv4 := net.IP(sess.Key4.DstIP[:]).To4()
	clientIPv6 := net.IP(sess.Key6.SrcIP[:]).To16()

	var modifiedPayload []byte
	var lengthDelta int

	if isSIPPort(srcPort, dstPort) {
		result, err := a.sipTranslator.TranslateIPv4ToIPv6(appPayload, serverIPv4, clientIPv6)
		if err != nil {
			log.Printf("[ALG-SIP] 4→6 处理失败: %v", err)
			return ipv6Pkt, 0
		}
		modifiedPayload = result.ModifiedPayload
		lengthDelta = result.LengthDelta
	} else if isH323Port(srcPort, dstPort) {
		result, err := a.h323Translator.TranslateIPv4ToIPv6(appPayload, serverIPv4, clientIPv6)
		if err != nil {
			log.Printf("[ALG-H323] 4→6 处理失败: %v", err)
			return ipv6Pkt, 0
		}
		modifiedPayload = result.ModifiedPayload
		lengthDelta = result.LengthDelta
	}

	if modifiedPayload == nil || lengthDelta == 0 {
		return ipv6Pkt, 0
	}

	newPkt := make([]byte, payloadOffset+len(modifiedPayload))
	copy(newPkt, ipv6Pkt[:payloadOffset])
	copy(newPkt[payloadOffset:], modifiedPayload)

	// 更新 IPv6 Payload Length
	binary.BigEndian.PutUint16(newPkt[4:6], uint16(len(newPkt)-IPv6HeaderLen))

	// 如果是 UDP, 更新 UDP Length
	if nextHeader == ProtoNumUDPNum {
		udpLen := uint16(8 + len(modifiedPayload))
		binary.BigEndian.PutUint16(newPkt[IPv6HeaderLen+4:IPv6HeaderLen+6], udpLen)
	}

	// 重算传输层校验和
	recalcTransportChecksum6(newPkt, nextHeader)

	return newPkt, lengthDelta
}
