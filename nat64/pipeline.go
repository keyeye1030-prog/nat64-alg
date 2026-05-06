package nat64

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync/atomic"
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
	MAC          *MACConfig  // 二层 MAC 地址配置
	DebugLog     bool   // 是否输出每包调试日志

	// 统计计数器 (原子操作)
	Pkts6to4     uint64
	Pkts4to6     uint64
	PktsDropped  uint64
	PktsPassthru uint64
}

// NewTranslator 创建 NAT64 翻译器实例
func NewTranslator(poolIPv4 net.IP, table *SessionTable) *Translator {
	return &Translator{
		SessionTable: table,
		PoolIPv4:     poolIPv4.To4(),
		ALG:          NewALGHandler(poolIPv4),
		MAC:          NewMACConfig(),
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
		// 从 IPv6 帧中学习源 MAC (将 srcIPv6 → srcMAC 记入邻居表)
		if t.MAC != nil && t.MAC.Neighbors != nil && len(payload) >= IPv6HeaderLen {
			srcIPv6 := net.IP(payload[8:24]).To16()
			t.MAC.Neighbors.Learn(srcIPv6, srcMAC)
		}
		return t.process6to4(dstMAC, srcMAC, payload)
	case EtherTypeIPv4:
		// 从 IPv4 帧中学习源 MAC (将 srcIPv4 → srcMAC 记入邻居表)
		if t.MAC != nil && t.MAC.Neighbors != nil && len(payload) >= IPv4HeaderMinLen {
			srcIPv4 := net.IP(payload[12:16]).To4()
			t.MAC.Neighbors.Learn(srcIPv4, srcMAC)
		}
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

	// 检查目的地址是否在 NAT64 前缀内
	dstIPv4 := IPv6ExtractIPv4(dstIPv6)
	if dstIPv4 == nil {
		atomic.AddUint64(&t.PktsPassthru, 1)
		return &ProcessResult{Direction: DirPassthrough}
	}

	// 解析扩展头链, 获取真实传输层协议
	parsed, err := ParseIPv6ExtensionHeaders(ipv6Raw)
	if err != nil {
		atomic.AddUint64(&t.PktsDropped, 1)
		return &ProcessResult{Error: fmt.Errorf("解析扩展头失败: %w", err)}
	}

	// 后续分片无传输层头, 只做 IP 层翻译, 不查会话表
	if parsed.IsSubsequentFragment() {
		resultPayload, err := TranslateIPv6ToIPv4WithFragments(ipv6Raw, t.PoolIPv4, dstIPv4)
		if err != nil {
			atomic.AddUint64(&t.PktsDropped, 1)
			return &ProcessResult{Error: fmt.Errorf("6->4 分片翻译失败: %w", err)}
		}
		outputFrame := t.buildOutputFrame6to4(dstIPv4, resultPayload)
		atomic.AddUint64(&t.Pkts6to4, 1)
		return &ProcessResult{OutputFrame: outputFrame, Direction: Dir6to4}
	}

	// 获取传输层端口 (使用扩展头解析结果)
	srcPort, dstPort, proto, err := extractTransportInfo6WithParsed(ipv6Raw, parsed)
	if err != nil {
		atomic.AddUint64(&t.PktsDropped, 1)
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
		atomic.AddUint64(&t.PktsDropped, 1)
		return &ProcessResult{Error: fmt.Errorf("查找会话失败: %w", err)}
	}

	// ---- 执行 IP 头部翻译 ----
	var resultPayload []byte
	transportProto := parsed.TransportProto

	if transportProto == ProtoNumICMPv6 {
		resultPayload, err = t.translateICMPv6Packet(ipv6Raw, sess)
	} else {
		// TCP/UDP: 使用分片感知的翻译
		resultPayload, err = TranslateIPv6ToIPv4WithFragments(ipv6Raw, t.PoolIPv4, dstIPv4)
		if err == nil {
			patchSrcPort(resultPayload[IPv4HeaderMinLen:], sess.Key4.SrcPort)
			recalcTransportChecksum4(resultPayload, resultPayload[9])

			if NeedsALG(srcPort, dstPort) {
				resultPayload, _ = t.ALG.ProcessALG6to4(resultPayload, sess)
			}
		}
	}

	if err != nil {
		atomic.AddUint64(&t.PktsDropped, 1)
		return &ProcessResult{Error: fmt.Errorf("6->4 翻译失败: %w", err)}
	}

	outputFrame := t.buildOutputFrame6to4(dstIPv4, resultPayload)
	atomic.AddUint64(&t.Pkts6to4, 1)

	if t.DebugLog {
		log.Printf("[NAT64 6->4] %s:%d -> %s:%d (mapped port: %d)",
			srcIPv6, srcPort, dstIPv4, dstPort, sess.Key4.SrcPort)
	}

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

	// 检查目的 IP 是否是我们的 NAT64 池地址或静态映射地址
	if !t.SessionTable.IsPoolIP(dstIPv4) {
		atomic.AddUint64(&t.PktsPassthru, 1)
		return &ProcessResult{Direction: DirPassthrough}
	}

	// 检查是否是后续分片 (offset>0, 无传输层头)
	fragInfo, _ := ParseIPv4FragmentInfo(ipv4Raw)
	if fragInfo != nil && fragInfo.IsFragment && fragInfo.FragmentOffset > 0 {
		// 后续分片: 只做 IP 层翻译, 无法查会话表
		// TODO: 实现分片跟踪表, 关联后续分片到第一个分片的会话
		atomic.AddUint64(&t.PktsDropped, 1)
		return &ProcessResult{Error: fmt.Errorf("4->6 后续分片暂不支持 (需分片跟踪表)")}
	}

	// 提取传输层端口
	srcPort, dstPort, proto, err := extractTransportInfo4(ipv4Raw, ihl)
	if err != nil {
		atomic.AddUint64(&t.PktsDropped, 1)
		return &ProcessResult{Error: err}
	}

	// 查找反向会话
	sess, ok := t.SessionTable.LookupByMappedPort(dstIPv4, srcIPv4, srcPort, dstPort, proto)
	if !ok {
		atomic.AddUint64(&t.PktsDropped, 1)
		return &ProcessResult{Error: fmt.Errorf("找不到反向会话: %s:%d -> %s:%d",
			srcIPv4, srcPort, dstIPv4, dstPort)}
	}

	origSrcIPv6 := net.IP(sess.Key6.SrcIP[:]).To16()

	// ---- 执行 IP 头部翻译 ----
	var resultPayload []byte

	if protocol == ProtoNumICMPv4 {
		resultPayload, err = t.translateICMPv4Packet(ipv4Raw, sess)
	} else {
		synthSrcIPv6 := IPv4ToIPv6(srcIPv4)
		// 使用分片感知的翻译
		resultPayload, err = TranslateIPv4ToIPv6WithFragments(ipv4Raw, synthSrcIPv6, origSrcIPv6)
		if err == nil {
			// 恢复原始目的端口 (需要找到传输层头的正确偏移)
			transportOff := IPv6HeaderLen
			if fragInfo != nil && fragInfo.IsFragment {
				transportOff += FragmentHdrLen // 跳过 Fragment Header
			}
			patchDstPort(resultPayload[transportOff:], sess.Key6.SrcPort)
			// 重算校验和
			nextHdr := resultPayload[6]
			if nextHdr == ExtHdrFragment {
				nextHdr = resultPayload[IPv6HeaderLen] // Fragment Header 的 Next Header
				recalcTransportChecksum6WithOffset(resultPayload, nextHdr, transportOff)
			} else {
				recalcTransportChecksum6(resultPayload, nextHdr)
			}

			if NeedsALG(srcPort, dstPort) {
				resultPayload, _ = t.ALG.ProcessALG4to6(resultPayload, sess)
			}
		}
	}

	if err != nil {
		atomic.AddUint64(&t.PktsDropped, 1)
		return &ProcessResult{Error: fmt.Errorf("4->6 翻译失败: %w", err)}
	}

	outputFrame := t.buildOutputFrame4to6(origSrcIPv6, resultPayload)
	atomic.AddUint64(&t.Pkts4to6, 1)

	if t.DebugLog {
		log.Printf("[NAT64 4->6] %s:%d -> %s (restored to %s:%d)",
			srcIPv4, srcPort, dstIPv4, origSrcIPv6, sess.Key6.SrcPort)
	}

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

// extractTransportInfo6 从 IPv6 包中提取传输层信息 (不处理扩展头, 兼容旧调用)
func extractTransportInfo6(ipv6Raw []byte) (srcPort, dstPort uint16, proto Protocol, err error) {
	parsed, parseErr := ParseIPv6ExtensionHeaders(ipv6Raw)
	if parseErr != nil {
		// 降级: 使用基本头的 Next Header
		nextHeader := ipv6Raw[6]
		payload := ipv6Raw[IPv6HeaderLen:]
		return extractFromPayload6(nextHeader, payload)
	}
	return extractTransportInfo6WithParsed(ipv6Raw, parsed)
}

// extractTransportInfo6WithParsed 使用已解析的扩展头信息提取传输层信息
func extractTransportInfo6WithParsed(ipv6Raw []byte, parsed *IPv6ParsedHeaders) (srcPort, dstPort uint16, proto Protocol, err error) {
	if parsed.TransportOffset >= len(ipv6Raw) {
		return 0, 0, 0, fmt.Errorf("传输层偏移越界: %d >= %d", parsed.TransportOffset, len(ipv6Raw))
	}
	payload := ipv6Raw[parsed.TransportOffset:]
	return extractFromPayload6(parsed.TransportProto, payload)
}

// extractFromPayload6 从传输层载荷中提取端口信息
func extractFromPayload6(nextHeader uint8, payload []byte) (srcPort, dstPort uint16, proto Protocol, err error) {
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
		if icmpType == ICMPv6EchoRequest || icmpType == ICMPv6EchoReply {
			srcPort = binary.BigEndian.Uint16(payload[4:6])
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

// buildOutputFrame6to4 构建 6→4 方向的输出以太帧
// 使用 MACConfig 解析正确的目的 MAC (IPv4 侧网关) 和源 MAC (本机 eth1)
func (t *Translator) buildOutputFrame6to4(dstIPv4 net.IP, ipv4Payload []byte) []byte {
	if t.MAC == nil {
		// 无 MAC 配置, 使用零 MAC (仅用于测试)
		return makeEtherFrame(make([]byte, 6), make([]byte, 6), EtherTypeIPv4, ipv4Payload)
	}

	dstMAC := t.MAC.ResolveMAC4(dstIPv4)
	srcMAC := t.MAC.LocalMAC4

	if dstMAC == nil {
		dstMAC = make(net.HardwareAddr, 6) // 无法解析时用零 MAC
	}
	if srcMAC == nil {
		srcMAC = make(net.HardwareAddr, 6)
	}

	return makeEtherFrame(dstMAC, srcMAC, EtherTypeIPv4, ipv4Payload)
}

// buildOutputFrame4to6 构建 4→6 方向的输出以太帧
// 使用 MACConfig 解析正确的目的 MAC (IPv6 终端或网关) 和源 MAC (本机 eth2)
func (t *Translator) buildOutputFrame4to6(dstIPv6 net.IP, ipv6Payload []byte) []byte {
	if t.MAC == nil {
		return makeEtherFrame(make([]byte, 6), make([]byte, 6), EtherTypeIPv6, ipv6Payload)
	}

	dstMAC := t.MAC.ResolveMAC6(dstIPv6)
	srcMAC := t.MAC.LocalMAC6

	if dstMAC == nil {
		dstMAC = make(net.HardwareAddr, 6)
	}
	if srcMAC == nil {
		srcMAC = make(net.HardwareAddr, 6)
	}

	return makeEtherFrame(dstMAC, srcMAC, EtherTypeIPv6, ipv6Payload)
}
