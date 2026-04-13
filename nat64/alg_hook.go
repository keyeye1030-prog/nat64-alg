package nat64

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"

	"nat64-alg/alg/h323"
	"nat64-alg/alg/rtp"
	"nat64-alg/alg/sip"
)

// ============================================================================
// ALG (Application Layer Gateway) 集成层
// 将 SIP、H.323 ALG 和 RTP 中继挂接到 NAT64 翻译管道中
// ============================================================================

// ALGHandler 管理所有应用层网关
type ALGHandler struct {
	sipTranslator  *sip.Translator
	h323Translator *h323.Translator
	relayManager   *rtp.RelayManager // RTP 媒体中继 (可选, 双臂模式下启用)
}

// NewALGHandler 创建 ALG 处理器 (无 RTP 中继, 单臂模式)
func NewALGHandler(poolIPv4 net.IP) *ALGHandler {
	return &ALGHandler{
		sipTranslator:  sip.NewTranslator(poolIPv4),
		h323Translator: h323.NewTranslator(poolIPv4),
	}
}

// SetRelayManager 注入 RTP 中继管理器 (双臂模式启用)
func (a *ALGHandler) SetRelayManager(rm *rtp.RelayManager) {
	a.relayManager = rm
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

		// 如果有 RTP 中继管理器, 为每个媒体端口分配中继
		if a.relayManager != nil && len(result.MediaPorts) > 0 {
			modifiedPayload, lengthDelta = a.allocateRelaysAndRewriteSDP(
				result, sess, clientIPv6, mappedIPv4)
		} else {
			modifiedPayload = result.ModifiedPayload
			lengthDelta = result.LengthDelta
			if len(result.MediaPorts) > 0 {
				log.Printf("[ALG-SIP] 发现 %d 个媒体端口 (RTP 中继未启用)", len(result.MediaPorts))
			}
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

// ============================================================================
// RTP 中继集成: 分配中继端口并就地修改已翻译的 SDP
// ============================================================================

// allocateRelaysAndRewriteSDP 在 SDP 已经做完 IPv6→IPv4 地址重写后,
// 进一步为每个媒体流分配 RTP 中继端口, 并将 m= 行的端口替换为中继端口
func (a *ALGHandler) allocateRelaysAndRewriteSDP(
	sipResult *sip.ALGResult,
	sess *Session,
	clientIPv6, mappedIPv4 net.IP,
) ([]byte, int) {

	originalLen := len(sipResult.ModifiedPayload)
	modifiedStr := string(sipResult.ModifiedPayload)

	for _, mp := range sipResult.MediaPorts {
		if mp.Proto != "RTP" {
			continue // RTCP 端口跟随 RTP 端口 +1
		}

		// 从会话中提取远端 IPv4 地址
		remoteIPv4 := net.IP(sess.Key4.DstIP[:]).To4()

		// 分配中继
		callID := fmt.Sprintf("sess-%d-%d", sess.Key6.SrcPort, sess.Key6.DstPort)
		relay, err := a.relayManager.AllocateRelay(
			callID,
			clientIPv6, mp.OriginalPort,    // IPv6 终端
			remoteIPv4, mp.OriginalPort,    // IPv4 终端 (初始端口, 会被首包学习更新)
		)
		if err != nil {
			log.Printf("[ALG-RTP] 分配中继失败: %v", err)
			continue
		}

		// 获取中继绑定地址
		_, relayIPv4 := a.relayManager.GetRelayInfo(relay.LocalPort4)

		// 在已翻译的 SDP 中, 将 m=audio ORIGINAL_PORT 替换为 m=audio RELAY_PORT
		oldPort := strconv.Itoa(int(mp.OriginalPort))
		newPort := strconv.Itoa(int(relay.LocalPort4))

		// 精确替换 m= 行中的端口 (避免替换其他数字)
		oldMedia := "m=audio " + oldPort
		newMedia := "m=audio " + newPort
		modifiedStr = replaceFirst(modifiedStr, oldMedia, newMedia)

		// 同时替换 a=rtcp: 行
		oldRtcp := "a=rtcp:" + strconv.Itoa(int(mp.OriginalPort)+1)
		newRtcp := "a=rtcp:" + strconv.Itoa(int(relay.LocalPort4)+1)
		modifiedStr = replaceFirst(modifiedStr, oldRtcp, newRtcp)

		log.Printf("[ALG-RTP] 已分配中继: %s:%d ↔ %s:%d (中继端口: %d)",
			clientIPv6, mp.OriginalPort, relayIPv4, mp.OriginalPort, relay.LocalPort4)
	}

	result := []byte(modifiedStr)
	return result, len(result) - originalLen + sipResult.LengthDelta
}

// replaceFirst 替换字符串中第一个匹配项
func replaceFirst(s, old, new string) string {
	idx := len(s) // 如果找不到就不替换
	for i := 0; i <= len(s)-len(old); i++ {
		if s[i:i+len(old)] == old {
			idx = i
			break
		}
	}
	if idx < len(s) {
		return s[:idx] + new + s[idx+len(old):]
	}
	return s
}
