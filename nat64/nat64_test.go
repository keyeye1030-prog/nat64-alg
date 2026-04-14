package nat64

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// ============================================================================
// NAT64 核心逻辑单元测试
// ============================================================================

// ---------- 地址转换测试 ----------

func TestIPv4ToIPv6(t *testing.T) {
	ipv4 := net.ParseIP("192.168.1.1").To4()
	ipv6 := IPv4ToIPv6(ipv4)

	expected := net.ParseIP("64:ff9b::c0a8:0101")
	if !ipv6.Equal(expected) {
		t.Errorf("IPv4ToIPv6(%s) = %s, want %s", ipv4, ipv6, expected)
	}
}

func TestIPv6ExtractIPv4(t *testing.T) {
	ipv6 := net.ParseIP("64:ff9b::c0a8:0101")
	ipv4 := IPv6ExtractIPv4(ipv6)

	expected := net.ParseIP("192.168.1.1").To4()
	if !ipv4.Equal(expected) {
		t.Errorf("IPv6ExtractIPv4(%s) = %s, want %s", ipv6, ipv4, expected)
	}
}

func TestIPv6ExtractIPv4_NonNAT64(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1")
	ipv4 := IPv6ExtractIPv4(ipv6)
	if ipv4 != nil {
		t.Errorf("非 NAT64 地址应返回 nil, got %s", ipv4)
	}
}

func TestIsNAT64Address(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"64:ff9b::1.2.3.4", true},
		{"64:ff9b::c0a8:0101", true},
		{"2001:db8::1", false},
		{"::1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := IsNAT64Address(ip)
		if got != tt.want {
			t.Errorf("IsNAT64Address(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// ---------- 校验和测试 ----------

func TestComputeChecksum(t *testing.T) {
	// 经典测试: RFC 1071 example
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	csum := ComputeChecksum(data)
	if csum != 0x220D {
		t.Errorf("ComputeChecksum = 0x%04X, want 0x220D", csum)
	}
}

func TestUpdateChecksumField(t *testing.T) {
	// 初始数据
	data := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x00, 0x01,
		0xC0, 0xA8, 0x00, 0x02}
	// 计算初始校验和
	origCsum := ComputeChecksum(data)
	data[10] = byte(origCsum >> 8)
	data[11] = byte(origCsum)

	// 修改 TTL 从 0x40 变为 0x39 (递减 1)
	oldVal := uint16(data[8]) << 8
	data[8] = 0x39
	newVal := uint16(data[8]) << 8

	newCsum := UpdateChecksumField(origCsum, uint16(oldVal), uint16(newVal))

	// 验证: 清零并全量重算应该跟增量一致
	data[10] = 0
	data[11] = 0
	fullCsum := ComputeChecksum(data)

	if newCsum != fullCsum {
		t.Errorf("增量校验和 0x%04X != 全量校验和 0x%04X", newCsum, fullCsum)
	}
}

// ---------- IPv6 -> IPv4 翻译测试 ----------

func TestTranslateIPv6ToIPv4_UDP(t *testing.T) {
	// 构造一个最小的 IPv6 + UDP 包
	srcIPv6 := net.ParseIP("2001:db8::1").To16()
	dstIPv6 := net.ParseIP("64:ff9b::c0a8:0101").To16()

	udpPayload := []byte("Hello NAT64!")
	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], 12345) // Src Port
	binary.BigEndian.PutUint16(udpHdr[2:4], 53)    // Dst Port
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(udpPayload)))
	// checksum=0 暂时先不算, TranslateIPv6ToIPv4 会重算
	udpSegment := append(udpHdr, udpPayload...)

	// 构造 IPv6 头
	ipv6Pkt := make([]byte, IPv6HeaderLen+len(udpSegment))
	ipv6Pkt[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Pkt[4:6], uint16(len(udpSegment)))
	ipv6Pkt[6] = ProtoNumUDPNum // Next Header = UDP
	ipv6Pkt[7] = 64             // Hop Limit
	copy(ipv6Pkt[8:24], srcIPv6)
	copy(ipv6Pkt[24:40], dstIPv6)
	copy(ipv6Pkt[IPv6HeaderLen:], udpSegment)

	// 执行翻译
	srcIPv4 := net.ParseIP("198.51.100.1").To4()
	dstIPv4 := net.ParseIP("192.168.1.1").To4()
	ipv4Pkt, err := TranslateIPv6ToIPv4(ipv6Pkt, srcIPv4, dstIPv4)

	if err != nil {
		t.Fatalf("TranslateIPv6ToIPv4 error: %v", err)
	}

	// 验证 IPv4 头
	if ipv4Pkt[0] != 0x45 {
		t.Errorf("Version/IHL = 0x%02X, want 0x45", ipv4Pkt[0])
	}
	if ipv4Pkt[9] != ProtoNumUDPNum {
		t.Errorf("Protocol = %d, want %d (UDP)", ipv4Pkt[9], ProtoNumUDPNum)
	}
	if ipv4Pkt[8] != 64 {
		t.Errorf("TTL = %d, want 64", ipv4Pkt[8])
	}

	gotSrc := net.IP(ipv4Pkt[12:16])
	gotDst := net.IP(ipv4Pkt[16:20])
	if !gotSrc.Equal(srcIPv4) {
		t.Errorf("SrcIP = %s, want %s", gotSrc, srcIPv4)
	}
	if !gotDst.Equal(dstIPv4) {
		t.Errorf("DstIP = %s, want %s", gotDst, dstIPv4)
	}

	// 验证 IPv4 首部校验和
	savedCsum := binary.BigEndian.Uint16(ipv4Pkt[10:12])
	ipv4Pkt[10] = 0
	ipv4Pkt[11] = 0
	calcCsum := IPv4HeaderChecksum(ipv4Pkt[:IPv4HeaderMinLen])
	if savedCsum != calcCsum {
		t.Errorf("IPv4 首部校验和不一致: stored=0x%04X, calc=0x%04X", savedCsum, calcCsum)
	}

	t.Logf("✅ IPv6->IPv4 翻译成功, 输出长度=%d", len(ipv4Pkt))
}

// ---------- IPv4 -> IPv6 翻译测试 ----------

func TestTranslateIPv4ToIPv6_TCP(t *testing.T) {
	// 构造最小 IPv4 + TCP(SYN) 包
	srcIPv4 := net.ParseIP("192.168.1.1").To4()
	dstIPv4 := net.ParseIP("198.51.100.1").To4()

	// 最小 TCP 头 (20 bytes)
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], 80)    // Src Port
	binary.BigEndian.PutUint16(tcpHdr[2:4], 54321) // Dst Port
	binary.BigEndian.PutUint32(tcpHdr[4:8], 1000)  // Seq
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)    // Ack
	tcpHdr[12] = 0x50                               // Data Offset=5 (20 bytes)
	tcpHdr[13] = 0x02                               // SYN flag

	// 构造 IPv4 头
	totalLen := IPv4HeaderMinLen + len(tcpHdr)
	ipv4Pkt := make([]byte, totalLen)
	ipv4Pkt[0] = 0x45
	ipv4Pkt[1] = 0 // TOS
	binary.BigEndian.PutUint16(ipv4Pkt[2:4], uint16(totalLen))
	ipv4Pkt[8] = 128 // TTL
	ipv4Pkt[9] = ProtoNumTCPNum
	copy(ipv4Pkt[12:16], srcIPv4)
	copy(ipv4Pkt[16:20], dstIPv4)
	binary.BigEndian.PutUint16(ipv4Pkt[10:12], IPv4HeaderChecksum(ipv4Pkt[:IPv4HeaderMinLen]))
	copy(ipv4Pkt[IPv4HeaderMinLen:], tcpHdr)

	// 执行翻译
	srcIPv6 := IPv4ToIPv6(srcIPv4)
	dstIPv6 := net.ParseIP("2001:db8::1").To16()
	ipv6Pkt, err := TranslateIPv4ToIPv6(ipv4Pkt, srcIPv6, dstIPv6)

	if err != nil {
		t.Fatalf("TranslateIPv4ToIPv6 error: %v", err)
	}

	// 验证 IPv6 头
	version := ipv6Pkt[0] >> 4
	if version != 6 {
		t.Errorf("Version = %d, want 6", version)
	}
	nextHeader := ipv6Pkt[6]
	if nextHeader != ProtoNumTCPNum {
		t.Errorf("Next Header = %d, want %d (TCP)", nextHeader, ProtoNumTCPNum)
	}
	hopLimit := ipv6Pkt[7]
	if hopLimit != 128 {
		t.Errorf("Hop Limit = %d, want 128", hopLimit)
	}

	gotSrc := net.IP(ipv6Pkt[8:24])
	gotDst := net.IP(ipv6Pkt[24:40])
	if !gotSrc.Equal(srcIPv6) {
		t.Errorf("SrcIPv6 = %s, want %s", gotSrc, srcIPv6)
	}
	if !gotDst.Equal(dstIPv6) {
		t.Errorf("DstIPv6 = %s, want %s", gotDst, dstIPv6)
	}

	t.Logf("✅ IPv4->IPv6 翻译成功, 输出长度=%d", len(ipv6Pkt))
}

// ---------- ICMP 翻译测试 ----------

func TestICMPv6EchoToICMPv4(t *testing.T) {
	// 构造 ICMPv6 Echo Request
	icmpv6 := make([]byte, 12)
	icmpv6[0] = ICMPv6EchoRequest // Type=128
	icmpv6[1] = 0                 // Code=0
	// checksum bytes [2:4] not important, will be recalculated
	binary.BigEndian.PutUint16(icmpv6[4:6], 0x1234) // Identifier
	binary.BigEndian.PutUint16(icmpv6[6:8], 1)      // Sequence
	copy(icmpv6[8:], []byte("TEST"))

	srcIPv4 := net.ParseIP("198.51.100.1").To4()
	dstIPv4 := net.ParseIP("192.168.1.1").To4()

	icmpv4, err := TranslateICMPv6ToICMPv4(icmpv6, srcIPv4, dstIPv4)
	if err != nil {
		t.Fatalf("TranslateICMPv6ToICMPv4 error: %v", err)
	}

	// 验证类型映射
	if icmpv4[0] != ICMPv4EchoRequest {
		t.Errorf("ICMPv4 Type = %d, want %d (Echo Request)", icmpv4[0], ICMPv4EchoRequest)
	}

	// 验证 Identifier 保持不变
	id := binary.BigEndian.Uint16(icmpv4[4:6])
	if id != 0x1234 {
		t.Errorf("Identifier = 0x%04X, want 0x1234", id)
	}

	// 验证校验和有效 (对完整 ICMPv4 包重算应为 0)
	csum := ComputeChecksum(icmpv4)
	if csum != 0 {
		t.Errorf("ICMPv4 校验和验证失败: re-compute=0x%04X (should be 0)", csum)
	}

	t.Logf("✅ ICMPv6 Echo Request -> ICMPv4 Echo Request 成功")
}

func TestICMPv4EchoToICMPv6(t *testing.T) {
	// 构造 ICMPv4 Echo Reply
	icmpv4 := make([]byte, 12)
	icmpv4[0] = ICMPv4EchoReply
	icmpv4[1] = 0
	binary.BigEndian.PutUint16(icmpv4[4:6], 0x5678) // Identifier
	binary.BigEndian.PutUint16(icmpv4[6:8], 42)     // Sequence
	copy(icmpv4[8:], []byte("PONG"))

	srcIPv6 := net.ParseIP("64:ff9b::c0a8:0101").To16()
	dstIPv6 := net.ParseIP("2001:db8::1").To16()

	icmpv6, err := TranslateICMPv4ToICMPv6(icmpv4, srcIPv6, dstIPv6)
	if err != nil {
		t.Fatalf("TranslateICMPv4ToICMPv6 error: %v", err)
	}

	// 验证类型映射
	if icmpv6[0] != ICMPv6EchoReply {
		t.Errorf("ICMPv6 Type = %d, want %d (Echo Reply)", icmpv6[0], ICMPv6EchoReply)
	}

	// 验证 Identifier
	id := binary.BigEndian.Uint16(icmpv6[4:6])
	if id != 0x5678 {
		t.Errorf("Identifier = 0x%04X, want 0x5678", id)
	}

	t.Logf("✅ ICMPv4 Echo Reply -> ICMPv6 Echo Reply 成功")
}

func TestICMPv6PacketTooBig_ToICMPv4(t *testing.T) {
	// 构造 ICMPv6 Packet Too Big (Type=2), MTU=1400
	icmpv6 := make([]byte, 48) // 8 header + 40 nested IPv6 header
	icmpv6[0] = ICMPv6PktTooBig
	icmpv6[1] = 0
	binary.BigEndian.PutUint32(icmpv6[4:8], 1400) // MTU

	// 嵌套的原始 IPv6 包头 (触发错误的包)
	nested := icmpv6[8:]
	nested[0] = 0x60
	nested[6] = ProtoNumUDPNum
	nested[7] = 64

	srcIPv4 := net.ParseIP("198.51.100.1").To4()
	dstIPv4 := net.ParseIP("10.0.0.1").To4()

	icmpv4, err := TranslateICMPv6ToICMPv4(icmpv6, srcIPv4, dstIPv4)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// 应转为 ICMPv4 Destination Unreachable (Type=3), Code=4 (Frag Needed)
	if icmpv4[0] != ICMPv4DstUnreach {
		t.Errorf("Type = %d, want %d", icmpv4[0], ICMPv4DstUnreach)
	}
	if icmpv4[1] != ICMPv4CodeFragNeeded {
		t.Errorf("Code = %d, want %d", icmpv4[1], ICMPv4CodeFragNeeded)
	}

	// MTU 应减去 20 -> 1380
	mtu := binary.BigEndian.Uint16(icmpv4[6:8])
	if mtu != 1380 {
		t.Errorf("Next-Hop MTU = %d, want 1380", mtu)
	}

	t.Logf("✅ ICMPv6 Packet Too Big (MTU=1400) -> ICMPv4 Frag Needed (MTU=1380) 成功")
}

// ---------- Session Table 测试 ----------

func TestSessionTable_LookupAndReverse(t *testing.T) {
	poolIPv4 := net.ParseIP("198.51.100.1").To4()
	st := NewSessionTable([]net.IP{poolIPv4}, 10000, 60000, 30000000000) // 30s TTL

	srcIPv6 := net.ParseIP("2001:db8::1").To16()
	dstIPv6 := net.ParseIP("64:ff9b::c0a8:0101").To16()

	key6 := SessionKey6{
		SrcPort: 54321,
		DstPort: 80,
		Proto:   ProtoTCP,
	}
	copy(key6.SrcIP[:], srcIPv6)
	copy(key6.DstIP[:], dstIPv6)

	// 创建会话
	sess, err := st.Lookup6to4(key6)
	if err != nil {
		t.Fatalf("Lookup6to4 error: %v", err)
	}

	if sess.Key4.SrcPort < 10000 || sess.Key4.SrcPort > 60000 {
		t.Errorf("映射端口 %d 不在范围 [10000, 60000]", sess.Key4.SrcPort)
	}

	// 查找同一会话应返回同一条目
	sess2, err := st.Lookup6to4(key6)
	if err != nil {
		t.Fatalf("second lookup error: %v", err)
	}
	if sess2.Key4.SrcPort != sess.Key4.SrcPort {
		t.Errorf("同一会话返回不同端口: %d vs %d", sess.Key4.SrcPort, sess2.Key4.SrcPort)
	}

	// 反向查找: 模拟收到 192.168.1.1:80 -> 198.51.100.1:mappedPort 的回包
	// 使用 LookupByMappedPort: remoteIP=192.168.1.1, remotePort=80, mappedPort=sess.Key4.SrcPort
	remoteIPv4 := net.ParseIP("192.168.1.1").To4()
	foundSess, ok := st.LookupByMappedPort(poolIPv4, remoteIPv4, 80, sess.Key4.SrcPort, ProtoNumTCPNum)
	if !ok {
		t.Fatalf("LookupByMappedPort 找不到反向会话")
	}
	if foundSess.Key6.SrcPort != 54321 {
		t.Errorf("反向会话 SrcPort = %d, want 54321", foundSess.Key6.SrcPort)
	}

	// 统计
	if st.Stats() != 1 {
		t.Errorf("Stats = %d, want 1", st.Stats())
	}

	t.Logf("✅ 会话表双向查找成功, 映射端口=%d", sess.Key4.SrcPort)
}

// ---------- Pipeline 完整端到端测试 ----------

func TestSessionTable_InboundStaticMapping(t *testing.T) {
	poolIPv4 := net.ParseIP("198.51.100.1").To4()
	st := NewSessionTable([]net.IP{poolIPv4}, 10000, 60000, 30*time.Second)

	// 配置一组静态保留 IP 映射: 2001:db8::10 -> 198.51.100.10
	staticMaps := map[string]net.IP{
		"2001:db8::10": net.ParseIP("198.51.100.10"),
	}
	st.SetStaticMappings(staticMaps)

	// 模拟公网一台陌生终端的 TCP 入站请求:
	// source 203.0.113.5:12345 向我们配置的保留 IP 198.51.100.10:5060 发起建单
	remoteIP := net.ParseIP("203.0.113.5").To4()
	mappedIP := net.ParseIP("198.51.100.10").To4()
	var remotePort uint16 = 12345
	var mappedPort uint16 = 5060

	// 执行基于 Inbound 端口特征的反向查找与自动打洞
	sess, ok := st.LookupByMappedPort(mappedIP, remoteIP, remotePort, mappedPort, ProtoNumTCPNum)
	if !ok || sess == nil {
		t.Fatalf("Inbound Static NAT 创建失败, LookupByMappedPort 返回 false")
	}

	// 验证打洞所生成的逆向 IPv6 会话参数
	expectedIPv6Target := net.ParseIP("2001:db8::10").To16()
	expectedIPv6Remote := IPv4ToIPv6(remoteIP).To16()

	if !bytes.Equal(sess.Key6.SrcIP[:], expectedIPv6Target) {
		t.Errorf("逆向构建的内网设备 IPv6 错误, want %s, got %s", expectedIPv6Target, net.IP(sess.Key6.SrcIP[:]))
	}

	if !bytes.Equal(sess.Key6.DstIP[:], expectedIPv6Remote) {
		t.Errorf("逆向合成的 NAT64 远端 IPv6 错误, want %s, got %s", expectedIPv6Remote, net.IP(sess.Key6.DstIP[:]))
	}

	if sess.Key6.SrcPort != mappedPort {
		t.Errorf("逆向分配保留端口失败, want %d, got %d", mappedPort, sess.Key6.SrcPort)
	}

	// 反证: 拿我们生成的虚拟内网 Key6，去正常按正向查找（类似内网回包了），应能立刻命中
	forwardSess, err := st.Lookup6to4(sess.Key6)
	if err != nil {
		t.Fatalf("验证正向索引失败: %v", err)
	}
	if forwardSess != sess {
		t.Errorf("由于索引断裂, 正反向找到的不是同一会话实例")
	}

	t.Logf("✅ Full-Cone Inbound 静态映射测试通过: %s:%d -> %s:%d 成功透传为 %s:%d -> %s:%d",
		remoteIP, remotePort, mappedIP, mappedPort,
		expectedIPv6Remote, remotePort, expectedIPv6Target, mappedPort)
}

// ---------- Pipeline 端到端完整包收发测试 ----------

func TestPipeline_IPv6UDPtoIPv4(t *testing.T) {
	poolIPv4 := net.ParseIP("198.51.100.1").To4()
	st := NewSessionTable([]net.IP{poolIPv4}, 10000, 60000, 30000000000)
	translator := NewTranslator(poolIPv4, st)

	// 构造 IPv6+UDP 以太帧
	srcIPv6 := net.ParseIP("2001:db8::99").To16()
	dstIPv6 := net.ParseIP("64:ff9b::0a00:0001").To16() // 10.0.0.1

	udpData := []byte("DNS query")
	udpSeg := make([]byte, 8+len(udpData))
	binary.BigEndian.PutUint16(udpSeg[0:2], 33333) // SrcPort
	binary.BigEndian.PutUint16(udpSeg[2:4], 53)    // DstPort
	binary.BigEndian.PutUint16(udpSeg[4:6], uint16(8+len(udpData)))

	ipv6Pkt := make([]byte, IPv6HeaderLen+len(udpSeg))
	ipv6Pkt[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Pkt[4:6], uint16(len(udpSeg)))
	ipv6Pkt[6] = ProtoNumUDPNum
	ipv6Pkt[7] = 64
	copy(ipv6Pkt[8:24], srcIPv6)
	copy(ipv6Pkt[24:40], dstIPv6)
	copy(ipv6Pkt[IPv6HeaderLen:], udpSeg)

	// 包装成以太帧
	frame := make([]byte, EtherHdrLen+len(ipv6Pkt))
	frame[0] = 0xFF // Dst MAC (broadcast for test)
	frame[6] = 0xAA // Src MAC
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv6)
	copy(frame[EtherHdrLen:], ipv6Pkt)

	result := translator.ProcessFrame(frame)
	if result.Error != nil {
		t.Fatalf("ProcessFrame error: %v", result.Error)
	}
	if result.Direction != Dir6to4 {
		t.Errorf("Direction = %d, want Dir6to4", result.Direction)
	}
	if result.OutputFrame == nil {
		t.Fatalf("OutputFrame is nil")
	}

	// 验证输出是 IPv4 以太帧
	outEtherType := binary.BigEndian.Uint16(result.OutputFrame[12:14])
	if outEtherType != EtherTypeIPv4 {
		t.Errorf("输出 EtherType = 0x%04X, want 0x0800 (IPv4)", outEtherType)
	}

	// 验证 IPv4 目的地址是 10.0.0.1
	outIPv4 := result.OutputFrame[EtherHdrLen:]
	gotDst := net.IP(outIPv4[16:20])
	wantDst := net.ParseIP("10.0.0.1").To4()
	if !gotDst.Equal(wantDst) {
		t.Errorf("目的 IPv4 = %s, want %s", gotDst, wantDst)
	}

	t.Logf("✅ Pipeline 端到端: IPv6 UDP -> IPv4 UDP 翻译成功, 输出帧长=%d", len(result.OutputFrame))
}
