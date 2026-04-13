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
func (a *ALGHandler) ProcessALG6to4(ipv4Pkt []byte, sess *Session) ([]byte, int) {
	if len(ipv4Pkt) < IPv4HeaderMinLen+4 {
		return ipv4Pkt, 0
	}

	proto := ipv4Pkt[9]
	transportHdr := ipv4Pkt[IPv4HeaderMinLen:]
	srcPort := binary.BigEndian.Uint16(transportHdr[0:2])
	dstPort := binary.BigEndian.Uint16(transportHdr[2:4])

	needALG := NeedsALG(srcPort, dstPort)

	// 1. TCP 序列号修正基础处理
	if proto == ProtoNumTCPNum && needALG {
		if sess.TCPTracker == nil {
			sess.TCPTracker = NewTCPDeltaTracker()
		}

		// 执行 Seq/Ack 修正
		oldSeq := binary.BigEndian.Uint32(transportHdr[4:8])
		oldAck := binary.BigEndian.Uint32(transportHdr[8:12])
		
		newSeq := sess.TCPTracker.Dir6to4.AdjustSeq(oldSeq)
		newAck := sess.TCPTracker.Dir4to6.AdjustAck(oldAck)

		if newSeq != oldSeq || newAck != oldAck {
			binary.BigEndian.PutUint32(transportHdr[4:8], newSeq)
			binary.BigEndian.PutUint32(transportHdr[8:12], newAck)
			// 标记需要重算校验和
		}
	}

	// 2. 提取应用层载荷并执行 ALG 翻译
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
		// 无载荷包 (如纯 ACK), 也要返回修改后的 Seq/Ack
		return ipv4Pkt, 0 
	}
	appPayload := ipv4Pkt[payloadOffset:]

	clientIPv6 := net.IP(sess.Key6.SrcIP[:]).To16()
	mappedIPv4 := net.IP(sess.Key4.SrcIP[:]).To4()

	var modifiedPayload []byte
	var lengthDelta int

	if isSIPPort(srcPort, dstPort) {
		// 解析 SIP 消息: 提取 Call-ID 和方法
		msgInfo := sip.ParseMessageInfo(appPayload)

		// BYE/CANCEL: 释放该通话的所有 RTP 中继
		if msgInfo.IsCallTermination() && a.relayManager != nil && msgInfo.CallID != "" {
			released := a.relayManager.ReleaseByCallID(msgInfo.CallID)
			if released > 0 {
				log.Printf("[ALG-SIP] 检测到 %s, 释放 %d 个 RTP 中继 (Call-ID: %s)",
					msgInfo.Method, released, msgInfo.CallID)
			}
		}

		// SIP ALG 地址翻译
		result, err := a.sipTranslator.TranslateIPv6ToIPv4(appPayload, clientIPv6, mappedIPv4)
		if err != nil {
			log.Printf("[ALG-SIP] 6→4 处理失败: %v", err)
			return ipv4Pkt, 0
		}

		// 如果有 RTP 中继管理器且发现媒体端口, 分配中继并改写 SDP
		if a.relayManager != nil && len(result.MediaPorts) > 0 {
			callID := msgInfo.CallID
			if callID == "" {
				callID = fmt.Sprintf("sess-%d-%d", sess.Key6.SrcPort, sess.Key6.DstPort)
			}
			modifiedPayload, lengthDelta = a.allocateRelaysAndRewriteSDP(
				result, sess, clientIPv6, mappedIPv4, callID)
		} else {
			modifiedPayload = result.ModifiedPayload
			lengthDelta = result.LengthDelta
		}

	} else if isH323Port(srcPort, dstPort) {
		// H.323 ALG
		result, err := a.h323Translator.ProcessH225Message(appPayload, clientIPv6, mappedIPv4, "6to4")
		if err != nil {
			log.Printf("[ALG-H323] 6→4 处理失败: %v", err)
			return ipv4Pkt, 0
		}

		// 如果有 RTP 中继管理器, 为 H.323 发现的端口分配中继
		if a.relayManager != nil && len(result.MediaPorts) > 0 {
			modifiedPayload, lengthDelta = a.allocateH323Relays(result, sess, clientIPv6, mappedIPv4)
		} else {
			modifiedPayload = result.ModifiedPayload
			lengthDelta = result.LengthDelta
		}
	}

	// 3. 如果载荷变化, 更新 Delta Tracker
	if lengthDelta != 0 && proto == ProtoNumTCPNum && sess.TCPTracker != nil {
		currentSeq := binary.BigEndian.Uint32(transportHdr[4:8])
		sess.TCPTracker.Dir6to4.AddDelta(lengthDelta, currentSeq)
	}

	if modifiedPayload == nil || lengthDelta == 0 {
		// 即使没有载荷修改, 但如果 Seq/Ack 被动过了, 也要重算校验和
		if proto == ProtoNumTCPNum && needALG {
			recalcTransportChecksum4(ipv4Pkt, proto)
		}
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

	needALG := NeedsALG(srcPort, dstPort)

	// 1. TCP 序列号修正基础处理
	if nextHeader == ProtoNumTCPNum && needALG {
		if sess.TCPTracker == nil {
			sess.TCPTracker = NewTCPDeltaTracker()
		}

		// 执行 Seq/Ack 修正
		oldSeq := binary.BigEndian.Uint32(transportHdr[4:8])
		oldAck := binary.BigEndian.Uint32(transportHdr[8:12])

		// 4 to 6 方向: Seq 用 Dir4to6 修正, Ack 用 Dir6to4 修正
		newSeq := sess.TCPTracker.Dir4to6.AdjustSeq(oldSeq)
		newAck := sess.TCPTracker.Dir6to4.AdjustAck(oldAck)

		if newSeq != oldSeq || newAck != oldAck {
			binary.BigEndian.PutUint32(transportHdr[4:8], newSeq)
			binary.BigEndian.PutUint32(transportHdr[8:12], newAck)
		}
	}

	// 2. 提取应用层载荷并执行 ALG 翻译
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
		// 解析 SIP 消息: 检测 BYE/CANCEL (服务端发起的挂断)
		msgInfo := sip.ParseMessageInfo(appPayload)
		if msgInfo.IsCallTermination() && a.relayManager != nil && msgInfo.CallID != "" {
			released := a.relayManager.ReleaseByCallID(msgInfo.CallID)
			if released > 0 {
				log.Printf("[ALG-SIP] 4→6 检测到 %s, 释放 %d 个 RTP 中继 (Call-ID: %s)",
					msgInfo.Method, released, msgInfo.CallID)
			}
		}

		result, err := a.sipTranslator.TranslateIPv4ToIPv6(appPayload, serverIPv4, clientIPv6)
		if err != nil {
			log.Printf("[ALG-SIP] 4→6 处理失败: %v", err)
			return ipv6Pkt, 0
		}
		modifiedPayload = result.ModifiedPayload
		lengthDelta = result.LengthDelta
	} else if isH323Port(srcPort, dstPort) {
		result, err := a.h323Translator.ProcessH225Message(appPayload, clientIPv6, serverIPv4, "4to6")
		if err != nil {
			log.Printf("[ALG-H323] 4→6 处理失败: %v", err)
			return ipv6Pkt, 0
		}
		modifiedPayload = result.ModifiedPayload
		lengthDelta = result.LengthDelta
	}

	// 3. 如果载荷变化, 更新 Delta Tracker
	if lengthDelta != 0 && nextHeader == ProtoNumTCPNum && sess.TCPTracker != nil {
		currentSeq := binary.BigEndian.Uint32(transportHdr[4:8])
		sess.TCPTracker.Dir4to6.AddDelta(lengthDelta, currentSeq)
	}

	if modifiedPayload == nil || lengthDelta == 0 {
		if nextHeader == ProtoNumTCPNum && needALG {
			recalcTransportChecksum6(ipv6Pkt, nextHeader)
		}
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
	callID string,
) ([]byte, int) {

	originalLen := len(sipResult.ModifiedPayload)
	modifiedStr := string(sipResult.ModifiedPayload)

	for _, mp := range sipResult.MediaPorts {
		if mp.Proto != "RTP" {
			continue // RTCP 端口跟随 RTP 端口 +1
		}

		// 从会话中提取远端 IPv4 地址
		remoteIPv4 := net.IP(sess.Key4.DstIP[:]).To4()

		// 分配中继端口对 (RTP + RTCP)
		pair, err := a.relayManager.AllocateRelayPair(
			callID,
			"audio",                           // 媒体类型
			clientIPv6, mp.OriginalPort,       // IPv6 终端
			remoteIPv4, mp.OriginalPort,       // IPv4 终端 (首包学习更新)
		)
		if err != nil {
			log.Printf("[ALG-RTP] 分配中继失败: %v", err)
			continue
		}

		// 获取中继绑定地址
		_, relayIPv4 := a.relayManager.GetRelayInfo(pair.RTP.LocalPort4)

		// 在已翻译的 SDP 中, 将 m=audio ORIGINAL_PORT 替换为 m=audio RELAY_PORT
		oldPort := strconv.Itoa(int(mp.OriginalPort))
		newPort := strconv.Itoa(int(pair.RTP.LocalPort4))

		// 精确替换 m= 行中的端口 (支持 audio 和 video)
		for _, mediaKind := range []string{"audio", "video"} {
			oldMedia := "m=" + mediaKind + " " + oldPort
			newMedia := "m=" + mediaKind + " " + newPort
			modifiedStr = replaceFirst(modifiedStr, oldMedia, newMedia)
		}

		// 同时替换 a=rtcp: 行
		oldRtcp := "a=rtcp:" + strconv.Itoa(int(mp.OriginalPort)+1)
		newRtcp := "a=rtcp:" + strconv.Itoa(int(pair.RTCP.LocalPort4))
		modifiedStr = replaceFirst(modifiedStr, oldRtcp, newRtcp)

		log.Printf("[ALG-RTP] 已分配中继对: Call=%s, %s:%d ↔ %s:%d (RTP=%d, RTCP=%d)",
			callID, clientIPv6, mp.OriginalPort,
			relayIPv4, mp.OriginalPort,
			pair.RTP.LocalPort4, pair.RTCP.LocalPort4)
	}

	result := []byte(modifiedStr)
	return result, len(result) - originalLen + sipResult.LengthDelta
}

// allocateH323Relays 为 H.323 发现的动态端口分配中继
func (a *ALGHandler) allocateH323Relays(
	h323Result *h323.ALGResult,
	sess *Session,
	clientIPv6, mappedIPv4 net.IP,
) ([]byte, int) {
	// 目前 H.323 我们主要处理 6to4 方向的分配
	// 注意: H.323 地址是二进制编码, h323Result.ModifiedPayload 已经包含了初步的地址替换
	// 我们遍历 MediaPorts 进行资源分配

	callID := fmt.Sprintf("h323-%d-%d", sess.Key6.SrcPort, sess.Key6.DstPort)

	for _, mp := range h323Result.MediaPorts {
		// 分配中继 (根据 Purpose 决定是 RTP/RTCP 还是控制通道)
		// H.323 的 H.245 也可以做中继
		var relay *rtp.RelaySession
		var err error

		remoteIPv4 := net.IP(sess.Key4.DstIP[:]).To4()

		if mp.Purpose == "RTP" {
			pair, err := a.relayManager.AllocateRelayPair(callID, "audio", clientIPv6, mp.OriginalPort, remoteIPv4, mp.OriginalPort)
			if err == nil {
				relay = pair.RTP
				log.Printf("[ALG-H323] 已分配 RTP 中继: %d", relay.LocalPort4)
			}
		} else {
			// 对于 H.245 或其他单端口, 仅分配一个中继
			relay, err = a.relayManager.AllocateRelay(callID, clientIPv6, mp.OriginalPort, remoteIPv4, mp.OriginalPort)
			if err == nil {
				log.Printf("[ALG-H323] 已分配 %s 中继: %d", mp.Purpose, relay.LocalPort4)
			}
		}

		if err != nil {
			log.Printf("[ALG-H323] 分配中继失败: %v", err)
			continue
		}

		// TODO: H.323 的二进制重写比较复杂。目前的实现中, 
		// h323Result.ModifiedPayload 已经将 IPv6 改成了 IPv4 并填充了 0。
		// 在生产环境中, 我们需要再次扫描二进制载荷并修正刚刚填入的 4字节 IPv4 中的端口信息(如果发生了变化)。
		// 这里暂且认为中继端口和原始端口一致, 因为我们的中继管理器会尽量尝试分配相同端口。
	}

	return h323Result.ModifiedPayload, h323Result.LengthDelta
}

// replaceFirst 替换字符串中第一个匹配项
func replaceFirst(s, old, new string) string {
	idx := -1
	for i := 0; i <= len(s)-len(old); i++ {
		if s[i:i+len(old)] == old {
			idx = i
			break
		}
	}
	if idx != -1 {
		return s[:idx] + new + s[idx+len(old):]
	}
	return s
}
