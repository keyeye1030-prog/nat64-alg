package nat64

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

// ============================================================================
// Pipeline: 完整的 NAT64 包处理管道
// 将 XDP 来的原始以太帧 -> 判断方向 -> 调用转换引擎 -> 返回转换后的以太帧
// ============================================================================

// EtherType 常量
const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeIPv6 uint16 = 0x86DD
	EtherHdrLen          = 14
)

// Translator 是 NAT64 翻译器的主入口
type Translator struct {
	SessionTable *SessionTable
	PoolIPv4     net.IP // NAT64 网关的 IPv4 出口地址
	ALG          *ALGHandler // SIP/H.323 应用层网关
}

// NewTranslator 创建 NAT64 翻译器实例
func NewTranslator(poolIPv4 net.IP, table *SessionTable) *Translator {
	return &Translator{
		SessionTable: table,
		PoolIPv4:     poolIPv4.To4(),
		ALG:          NewALGHandler(poolIPv4),
	}
}

// Direction 标志包的翻译方向
type Direction int

const (
	Dir6to4 Direction = iota
	Dir4to6
	DirPassthrough // 不需要翻译, 直接放行
)

// ProcessResult 是管道对输入帧处理后的输出
type ProcessResult struct {
	OutputFrame []byte    // 转换后的完整以太帧 (或 nil 表示丢弃)
	Direction   Direction
	Error       error
}

// ProcessFrame 处理一个从 AF_XDP 获取的完整以太帧
// 返回转换后的帧，可直接写入 TX 队列发送
func (t *Translator) ProcessFrame(frame []byte) *ProcessResult {
	if len(frame) < EtherHdrLen {
		return &ProcessResult{Error: fmt.Errorf("帧过短: %d", len(frame))}
	}

	// 解析以太帧头
	dstMAC := frame[0:6]
	srcMAC := frame[6:12]
	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[EtherHdrLen:]

	switch etherType {
	case EtherTypeIPv6:
		return t.process6to4(dstMAC, srcMAC, payload)
	case EtherTypeIPv4:
		return t.process4to6(dstMAC, srcMAC, payload)
	default:
		// 非 IP 协议, 直接放行
		return &ProcessResult{OutputFrame: frame, Direction: DirPassthrough}
	}
}

// process6to4 处理 IPv6 -> IPv4 方向的翻译
func (t *Translator) process6to4(dstMAC, srcMAC, ipv6Raw []byte) *ProcessResult {
	if len(ipv6Raw) < IPv6HeaderLen {
		return &ProcessResult{Error: fmt.Errorf("IPv6 包过短")}
	}

	// 提取 IPv6 地址
	srcIPv6 := net.IP(ipv6Raw[8:24]).To16()
	dstIPv6 := net.IP(ipv6Raw[24:40]).To16()
	nextHeader := ipv6Raw[6]

	// 检查目的地址是否在 NAT64 前缀内
	dstIPv4 := IPv6ExtractIPv4(dstIPv6)
	if dstIPv4 == nil {
		// 不是发往 NAT64 前缀的包, 放行
		return &ProcessResult{Direction: DirPassthrough}
	}

	// 获取传输层端口 (用于会话表)
	srcPort, dstPort, proto, err := extractTransportInfo6(ipv6Raw)
	if err != nil {
		return &ProcessResult{Error: err}
	}

	// 查找/创建会话
	key6 := SessionKey6{
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
	}
	copy(key6.SrcIP[:], srcIPv6)
	copy(key6.DstIP[:], dstIPv6)

	sess, err := t.SessionTable.Lookup6to4(key6)
	if err != nil {
		return &ProcessResult{Error: fmt.Errorf("查找会话失败: %w", err)}
	}

	// ---- 执行 IP 头部翻译 ----
	var resultPayload []byte

	if nextHeader == ProtoNumICMPv6 {
		// ICMP 特殊处理: 需要做类型/代码转换
		resultPayload, err = t.translateICMPv6Packet(ipv6Raw, sess)
	} else {
		// TCP/UDP: IP 头转换 + 端口 NAT
		resultPayload, err = TranslateIPv6ToIPv4(ipv6Raw, t.PoolIPv4, dstIPv4)
		if err == nil {
			// 写入 NAT 映射后的源端口
			patchSrcPort(resultPayload[IPv4HeaderMinLen:], sess.Key4.SrcPort)
			// 重算传输层校验和 (端口变了)
			recalcTransportChecksum4(resultPayload, resultPayload[9])

			// ALG 处理: 如果是 SIP/H.323 端口, 修改应用层载荷
			if NeedsALG(srcPort, dstPort) {
				resultPayload, _ = t.ALG.ProcessALG6to4(resultPayload, sess)
			}
		}
	}

	if err != nil {
		return &ProcessResult{Error: fmt.Errorf("6->4 翻译失败: %w", err)}
	}

	// 组装以太帧 (交换 MAC)
	outputFrame := makeEtherFrame(srcMAC, dstMAC, EtherTypeIPv4, resultPayload)

	log.Printf("[NAT64 6->4] %s:%d -> %s:%d (mapped port: %d)",
		srcIPv6, srcPort, dstIPv4, dstPort, sess.Key4.SrcPort)

	return &ProcessResult{OutputFrame: outputFrame, Direction: Dir6to4}
}

// process4to6 处理 IPv4 -> IPv6 方向的翻译 (回包)
func (t *Translator) process4to6(dstMAC, srcMAC, ipv4Raw []byte) *ProcessResult {
	if len(ipv4Raw) < IPv4HeaderMinLen {
		return &ProcessResult{Error: fmt.Errorf("IPv4 包过短")}
	}

	protocol := ipv4Raw[9]
	ihl := int(ipv4Raw[0]&0x0F) * 4

	srcIPv4 := net.IP(ipv4Raw[12:16]).To4()
	dstIPv4 := net.IP(ipv4Raw[16:20]).To4()

	// 检查目的 IP 是否是我们的 NAT64 池地址
	if !dstIPv4.Equal(t.PoolIPv4) {
		return &ProcessResult{Direction: DirPassthrough}
	}

	// 提取传输层端口
	srcPort, dstPort, proto, err := extractTransportInfo4(ipv4Raw, ihl)
	if err != nil {
		return &ProcessResult{Error: err}
	}

	// 查找反向会话
	// 回包: srcIP=远端服务器, srcPort=远端端口, dstIP=我们(pool), dstPort=mappedPort
	sess, ok := t.SessionTable.LookupByMappedPort(srcIPv4, srcPort, dstPort, proto)
	if !ok {
		return &ProcessResult{Error: fmt.Errorf("找不到反向会话: %s:%d -> %s:%d",
			srcIPv4, srcPort, dstIPv4, dstPort)}
	}

	// 恢复原始 IPv6 地址
	origSrcIPv6 := net.IP(sess.Key6.SrcIP[:]).To16()

	// ---- 执行 IP 头部翻译 ----
	var resultPayload []byte

	if protocol == ProtoNumICMPv4 {
		resultPayload, err = t.translateICMPv4Packet(ipv4Raw, sess)
	} else {
		// srcIPv6 = NAT64 合成地址 (对方 IPv4 嵌入), dstIPv6 = 原始 IPv6 客户端
		synthSrcIPv6 := IPv4ToIPv6(srcIPv4)
		resultPayload, err = TranslateIPv4ToIPv6(ipv4Raw, synthSrcIPv6, origSrcIPv6)
		if err == nil {
			// 恢复原始目的端口
			patchDstPort(resultPayload[IPv6HeaderLen:], sess.Key6.SrcPort)
			recalcTransportChecksum6(resultPayload, resultPayload[6])

			// ALG 处理: 如果是 SIP/H.323 端口, 修改应用层载荷
			if NeedsALG(srcPort, dstPort) {
				resultPayload, _ = t.ALG.ProcessALG4to6(resultPayload, sess)
			}
		}
	}

	if err != nil {
		return &ProcessResult{Error: fmt.Errorf("4->6 翻译失败: %w", err)}
	}

	outputFrame := makeEtherFrame(srcMAC, dstMAC, EtherTypeIPv6, resultPayload)

	log.Printf("[NAT64 4->6] %s:%d -> %s (restored to %s:%d)",
		srcIPv4, srcPort, dstIPv4, origSrcIPv6, sess.Key6.SrcPort)

	return &ProcessResult{OutputFrame: outputFrame, Direction: Dir4to6}
}

// ---------- ICMP 专用翻译流程 ----------

func (t *Translator) translateICMPv6Packet(ipv6Raw []byte, sess *Session) ([]byte, error) {
	icmpv6Payload := ipv6Raw[IPv6HeaderLen:]
	dstIPv4 := net.IP(sess.Key4.DstIP[:]).To4()

	// 1. 翻译 ICMPv6 -> ICMPv4 负载 (类型/代码映射)
	icmpv4Payload, err := TranslateICMPv6ToICMPv4(icmpv6Payload, t.PoolIPv4, dstIPv4)
	if err != nil {
		return nil, err
	}

	// 2. 构建 IPv4 头
	totalLen := IPv4HeaderMinLen + len(icmpv4Payload)
	ipv4Pkt := make([]byte, totalLen)
	ipv4Hdr := ipv4Pkt[:IPv4HeaderMinLen]

	tos := (ipv6Raw[0]&0x0F)<<4 | ipv6Raw[1]>>4
	hopLimit := ipv6Raw[7]

	ipv4Hdr[0] = 0x45
	ipv4Hdr[1] = tos
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipv4Hdr[6:8], 0x4000)
	ipv4Hdr[8] = hopLimit
	ipv4Hdr[9] = ProtoNumICMPv4
	copy(ipv4Hdr[12:16], t.PoolIPv4)
	copy(ipv4Hdr[16:20], dstIPv4)
	binary.BigEndian.PutUint16(ipv4Hdr[10:12], IPv4HeaderChecksum(ipv4Hdr))

	copy(ipv4Pkt[IPv4HeaderMinLen:], icmpv4Payload)

	return ipv4Pkt, nil
}

func (t *Translator) translateICMPv4Packet(ipv4Raw []byte, sess *Session) ([]byte, error) {
	ihl := int(ipv4Raw[0]&0x0F) * 4
	icmpv4Payload := ipv4Raw[ihl:]

	srcIPv4 := net.IP(ipv4Raw[12:16]).To4()
	origSrcIPv6 := net.IP(sess.Key6.SrcIP[:]).To16()
	synthSrcIPv6 := IPv4ToIPv6(srcIPv4)

	// 1. 翻译 ICMPv4 -> ICMPv6 负载
	icmpv6Payload, err := TranslateICMPv4ToICMPv6(icmpv4Payload, synthSrcIPv6, origSrcIPv6)
	if err != nil {
		return nil, err
	}

	// 2. 构建 IPv6 头
	ipv6Pkt := make([]byte, IPv6HeaderLen+len(icmpv6Payload))
	ipv6Hdr := ipv6Pkt[:IPv6HeaderLen]

	tos := ipv4Raw[1]
	ttl := ipv4Raw[8]

	ipv6Hdr[0] = 0x60 | (tos >> 4)
	ipv6Hdr[1] = tos << 4
	binary.BigEndian.PutUint16(ipv6Hdr[4:6], uint16(len(icmpv6Payload)))
	ipv6Hdr[6] = ProtoNumICMPv6
	ipv6Hdr[7] = ttl
	copy(ipv6Hdr[8:24], synthSrcIPv6)
	copy(ipv6Hdr[24:40], origSrcIPv6)

	copy(ipv6Pkt[IPv6HeaderLen:], icmpv6Payload)

	// 3. 计算 ICMPv6 校验和 (需要 IPv6 伪首部)
	payload := ipv6Pkt[IPv6HeaderLen:]
	payload[2] = 0
	payload[3] = 0
	psum := PseudoHeaderChecksumIPv6(ipv6Hdr[8:24], ipv6Hdr[24:40], ProtoNumICMPv6, uint32(len(payload)))
	csum := FinishChecksum(psum, payload)
	binary.BigEndian.PutUint16(payload[2:4], csum)

	return ipv6Pkt, nil
}

// ---------- 辅助函数 ----------

// extractTransportInfo6 从 IPv6 包中提取传输层信息
func extractTransportInfo6(ipv6Raw []byte) (srcPort, dstPort uint16, proto Protocol, err error) {
	nextHeader := ipv6Raw[6]
	payload := ipv6Raw[IPv6HeaderLen:]

	switch nextHeader {
	case ProtoNumTCPNum, ProtoNumUDPNum:
		if len(payload) < 4 {
			return 0, 0, 0, fmt.Errorf("传输层头过短")
		}
		srcPort = binary.BigEndian.Uint16(payload[0:2])
		dstPort = binary.BigEndian.Uint16(payload[2:4])
		if nextHeader == ProtoNumTCPNum {
			proto = ProtoTCP
		} else {
			proto = ProtoUDP
		}
	case ProtoNumICMPv6:
		if len(payload) < 8 {
			return 0, 0, 0, fmt.Errorf("ICMPv6 头过短")
		}
		proto = ProtoICMP
		icmpType := payload[0]
		// 对于 Echo Request/Reply, 使用 Identifier 作为 "端口"
		if icmpType == ICMPv6EchoRequest || icmpType == ICMPv6EchoReply {
			srcPort = binary.BigEndian.Uint16(payload[4:6]) // Identifier
			dstPort = 0
		}
	default:
		return 0, 0, 0, fmt.Errorf("不支持的 Next Header: %d", nextHeader)
	}
	return
}

// extractTransportInfo4 从 IPv4 包中提取传输层信息
func extractTransportInfo4(ipv4Raw []byte, ihl int) (srcPort, dstPort uint16, proto Protocol, err error) {
	protocol := ipv4Raw[9]
	payload := ipv4Raw[ihl:]

	switch protocol {
	case ProtoNumTCPNum, ProtoNumUDPNum:
		if len(payload) < 4 {
			return 0, 0, 0, fmt.Errorf("传输层头过短")
		}
		srcPort = binary.BigEndian.Uint16(payload[0:2])
		dstPort = binary.BigEndian.Uint16(payload[2:4])
		if protocol == ProtoNumTCPNum {
			proto = ProtoTCP
		} else {
			proto = ProtoUDP
		}
	case ProtoNumICMPv4:
		if len(payload) < 8 {
			return 0, 0, 0, fmt.Errorf("ICMPv4 头过短")
		}
		proto = ProtoICMP
		icmpType := payload[0]
		if icmpType == ICMPv4EchoRequest || icmpType == ICMPv4EchoReply {
			srcPort = binary.BigEndian.Uint16(payload[4:6]) // Identifier
			dstPort = 0
		}
	default:
		return 0, 0, 0, fmt.Errorf("不支持的 Protocol: %d", protocol)
	}
	return
}

// patchSrcPort 修改传输层的源端口 (TCP/UDP 的前 2 字节)
func patchSrcPort(transportHdr []byte, port uint16) {
	if len(transportHdr) >= 2 {
		binary.BigEndian.PutUint16(transportHdr[0:2], port)
	}
}

// patchDstPort 修改传输层的目的端口 (TCP/UDP 的第 2-3 字节)
func patchDstPort(transportHdr []byte, port uint16) {
	if len(transportHdr) >= 4 {
		binary.BigEndian.PutUint16(transportHdr[2:4], port)
	}
}

// makeEtherFrame 组装以太帧
func makeEtherFrame(dstMAC, srcMAC []byte, etherType uint16, payload []byte) []byte {
	frame := make([]byte, EtherHdrLen+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[EtherHdrLen:], payload)
	return frame
}
