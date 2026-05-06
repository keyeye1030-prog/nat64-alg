package nat64

import (
	"encoding/binary"
	"net"
	"testing"
)

// ============================================================================
// IPv6 Extension Header & Fragment 单元测试
// ============================================================================

// ---------- Extension Header 解析测试 ----------

func TestParseExtHeaders_NoExtension(t *testing.T) {
	// 普通 IPv6+TCP 包 (无扩展头)
	pkt := make([]byte, IPv6HeaderLen+20)
	pkt[0] = 0x60
	pkt[6] = ProtoNumTCPNum
	pkt[7] = 64
	binary.BigEndian.PutUint16(pkt[4:6], 20)

	parsed, err := ParseIPv6ExtensionHeaders(pkt)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if parsed.TransportProto != ProtoNumTCPNum {
		t.Errorf("TransportProto = %d, want %d", parsed.TransportProto, ProtoNumTCPNum)
	}
	if parsed.TransportOffset != IPv6HeaderLen {
		t.Errorf("TransportOffset = %d, want %d", parsed.TransportOffset, IPv6HeaderLen)
	}
	if parsed.HasFragment {
		t.Error("不应有 Fragment Header")
	}
	t.Log("✅ 无扩展头解析成功")
}

func TestParseExtHeaders_WithFragment(t *testing.T) {
	// IPv6 + Fragment Header + UDP
	fragHdrLen := 8
	pkt := make([]byte, IPv6HeaderLen+fragHdrLen+8)
	pkt[0] = 0x60
	pkt[6] = ExtHdrFragment // Next Header = Fragment
	pkt[7] = 64
	binary.BigEndian.PutUint16(pkt[4:6], uint16(fragHdrLen+8))

	// Fragment Header
	frag := pkt[IPv6HeaderLen:]
	frag[0] = ProtoNumUDPNum // Next Header = UDP
	frag[1] = 0              // Reserved
	// Fragment Offset=100 (800 bytes), MF=1
	fragField := uint16(100<<3) | 0x01
	binary.BigEndian.PutUint16(frag[2:4], fragField)
	binary.BigEndian.PutUint32(frag[4:8], 0x12345678) // ID

	parsed, err := ParseIPv6ExtensionHeaders(pkt)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !parsed.HasFragment {
		t.Error("应该有 Fragment Header")
	}
	if parsed.FragmentOffset != 100 {
		t.Errorf("FragmentOffset = %d, want 100", parsed.FragmentOffset)
	}
	if !parsed.MoreFragments {
		t.Error("MF 应该为 true")
	}
	if parsed.FragmentID != 0x12345678 {
		t.Errorf("FragmentID = 0x%08X, want 0x12345678", parsed.FragmentID)
	}
	if parsed.TransportProto != ProtoNumUDPNum {
		t.Errorf("TransportProto = %d, want %d", parsed.TransportProto, ProtoNumUDPNum)
	}
	if parsed.TransportOffset != IPv6HeaderLen+fragHdrLen {
		t.Errorf("TransportOffset = %d, want %d", parsed.TransportOffset, IPv6HeaderLen+fragHdrLen)
	}
	if !parsed.IsSubsequentFragment() {
		t.Error("应该是后续分片")
	}
	t.Logf("✅ Fragment Header 解析成功: offset=%d, MF=%v, ID=0x%X",
		parsed.FragmentOffset, parsed.MoreFragments, parsed.FragmentID)
}

func TestParseExtHeaders_HopByHopThenFragment(t *testing.T) {
	// IPv6 + Hop-by-Hop (8 bytes) + Fragment (8 bytes) + TCP
	hopLen := 8
	fragLen := 8
	pkt := make([]byte, IPv6HeaderLen+hopLen+fragLen+20)
	pkt[0] = 0x60
	pkt[6] = ExtHdrHopByHop // Next Header = Hop-by-Hop
	pkt[7] = 64
	binary.BigEndian.PutUint16(pkt[4:6], uint16(hopLen+fragLen+20))

	// Hop-by-Hop Header
	hop := pkt[IPv6HeaderLen:]
	hop[0] = ExtHdrFragment // Next = Fragment
	hop[1] = 0              // Len = 0 → 8 bytes total

	// Fragment Header
	frag := pkt[IPv6HeaderLen+hopLen:]
	frag[0] = ProtoNumTCPNum // Next = TCP
	frag[1] = 0
	// First fragment: offset=0, MF=1
	binary.BigEndian.PutUint16(frag[2:4], 0x01) // offset=0, MF=1
	binary.BigEndian.PutUint32(frag[4:8], 42)

	parsed, err := ParseIPv6ExtensionHeaders(pkt)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !parsed.HasFragment {
		t.Error("应该有 Fragment Header")
	}
	if parsed.TransportProto != ProtoNumTCPNum {
		t.Errorf("TransportProto = %d, want TCP", parsed.TransportProto)
	}
	expectedOffset := IPv6HeaderLen + hopLen + fragLen
	if parsed.TransportOffset != expectedOffset {
		t.Errorf("TransportOffset = %d, want %d", parsed.TransportOffset, expectedOffset)
	}
	if !parsed.IsFirstFragment() {
		t.Error("应该是第一个分片")
	}
	t.Log("✅ Hop-by-Hop + Fragment 链解析成功")
}

// ---------- Fragment Header 剥离测试 ----------

func TestStripFragmentHeader(t *testing.T) {
	// IPv6 + Fragment Header + 载荷
	payload := []byte("Hello Fragment!")
	pkt := make([]byte, IPv6HeaderLen+FragmentHdrLen+len(payload))
	pkt[0] = 0x60
	pkt[6] = ExtHdrFragment
	binary.BigEndian.PutUint16(pkt[4:6], uint16(FragmentHdrLen+len(payload)))

	frag := pkt[IPv6HeaderLen:]
	frag[0] = ProtoNumUDPNum
	copy(pkt[IPv6HeaderLen+FragmentHdrLen:], payload)

	parsed, _ := ParseIPv6ExtensionHeaders(pkt)
	stripped, err := StripFragmentHeader(pkt, parsed)
	if err != nil {
		t.Fatalf("剥离失败: %v", err)
	}

	expectedLen := IPv6HeaderLen + len(payload)
	if len(stripped) != expectedLen {
		t.Errorf("剥离后长度 = %d, want %d", len(stripped), expectedLen)
	}
	if stripped[6] != ProtoNumUDPNum {
		t.Errorf("Next Header = %d, want %d (UDP)", stripped[6], ProtoNumUDPNum)
	}
	newPayloadLen := binary.BigEndian.Uint16(stripped[4:6])
	if int(newPayloadLen) != len(payload) {
		t.Errorf("Payload Length = %d, want %d", newPayloadLen, len(payload))
	}
	t.Log("✅ Fragment Header 剥离成功")
}

// ---------- IPv4 分片信息解析测试 ----------

func TestParseIPv4FragmentInfo_DF(t *testing.T) {
	pkt := make([]byte, IPv4HeaderMinLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[6:8], IPv4FlagDF) // DF=1

	info, err := ParseIPv4FragmentInfo(pkt)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !info.DontFragment {
		t.Error("DF 应该为 true")
	}
	if info.IsFragment {
		t.Error("不应该是分片包")
	}
	t.Log("✅ DF 标志解析成功")
}

func TestParseIPv4FragmentInfo_MF(t *testing.T) {
	pkt := make([]byte, IPv4HeaderMinLen+8)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(IPv4HeaderMinLen+8))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(pkt[6:8], IPv4FlagMF|50) // MF=1, offset=50

	info, err := ParseIPv4FragmentInfo(pkt)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !info.MoreFragments {
		t.Error("MF 应该为 true")
	}
	if info.FragmentOffset != 50 {
		t.Errorf("FragmentOffset = %d, want 50", info.FragmentOffset)
	}
	if info.Identification != 0x1234 {
		t.Errorf("ID = 0x%04X, want 0x1234", info.Identification)
	}
	if !info.IsFragment {
		t.Error("应该是分片包")
	}
	t.Log("✅ MF + Fragment Offset 解析成功")
}

// ---------- 分片感知翻译测试 ----------

func TestTranslateIPv4ToIPv6WithFragments_DF(t *testing.T) {
	// DF=1 的普通包: 不应添加 Fragment Header
	pkt := buildMinimalIPv4UDP(t, true)

	srcIPv6 := net.ParseIP("64:ff9b::c0a8:0101").To16()
	dstIPv6 := net.ParseIP("2001:db8::1").To16()

	result, err := TranslateIPv4ToIPv6WithFragments(pkt, srcIPv6, dstIPv6)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if result[6] == ExtHdrFragment {
		t.Error("DF=1 的包不应添加 Fragment Header")
	}
	t.Log("✅ DF=1 包翻译成功 (无 Fragment Header)")
}

func TestTranslateIPv4ToIPv6WithFragments_NoDFNoFrag(t *testing.T) {
	// DF=0 但未实际分片: 应添加 atomic Fragment Header
	pkt := buildMinimalIPv4UDP(t, false) // DF=0

	srcIPv6 := net.ParseIP("64:ff9b::c0a8:0101").To16()
	dstIPv6 := net.ParseIP("2001:db8::1").To16()

	result, err := TranslateIPv4ToIPv6WithFragments(pkt, srcIPv6, dstIPv6)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if result[6] != ExtHdrFragment {
		t.Errorf("DF=0 的包应添加 Fragment Header, 但 Next Header = %d", result[6])
	}
	// Fragment Header 中 offset=0, MF=0 (atomic fragment)
	fragField := binary.BigEndian.Uint16(result[IPv6HeaderLen+2 : IPv6HeaderLen+4])
	if fragField != 0 {
		t.Errorf("Atomic fragment 的 fragField 应为 0, got 0x%04X", fragField)
	}
	t.Log("✅ DF=0 未分片包翻译成功 (添加 atomic Fragment Header)")
}

// ---------- 辅助函数 ----------

func buildMinimalIPv4UDP(t *testing.T, df bool) []byte {
	t.Helper()
	udpPayload := []byte("test")
	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], 12345)
	binary.BigEndian.PutUint16(udpHdr[2:4], 53)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(udpPayload)))
	udpSeg := append(udpHdr, udpPayload...)

	totalLen := IPv4HeaderMinLen + len(udpSeg)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x5678) // ID
	if df {
		binary.BigEndian.PutUint16(pkt[6:8], IPv4FlagDF)
	}
	pkt[8] = 64
	pkt[9] = ProtoNumUDPNum
	copy(pkt[12:16], net.ParseIP("192.168.1.1").To4())
	copy(pkt[16:20], net.ParseIP("198.51.100.1").To4())
	pkt[10] = 0
	pkt[11] = 0
	binary.BigEndian.PutUint16(pkt[10:12], IPv4HeaderChecksum(pkt[:IPv4HeaderMinLen]))
	copy(pkt[IPv4HeaderMinLen:], udpSeg)
	return pkt
}
