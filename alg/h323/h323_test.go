package h323

import (
	"encoding/binary"
	"net"
	"testing"
)

// ============================================================================
// H.323 ALG 单元测试
// ============================================================================

func TestParseTPKT(t *testing.T) {
	// 构造合法 TPKT
	data := make([]byte, 20)
	data[0] = TPKTVersion // Version=3
	data[1] = 0           // Reserved
	binary.BigEndian.PutUint16(data[2:4], 20) // Length=20
	// 填充一些 Q.931 模拟数据
	data[4] = Q931ProtoDisc // Protocol Discriminator

	tpkt, err := ParseTPKT(data)
	if err != nil {
		t.Fatalf("ParseTPKT error: %v", err)
	}

	if tpkt.Version != 3 {
		t.Errorf("Version = %d, want 3", tpkt.Version)
	}
	if tpkt.Length != 20 {
		t.Errorf("Length = %d, want 20", tpkt.Length)
	}
	if len(tpkt.Payload) != 16 {
		t.Errorf("Payload len = %d, want 16", len(tpkt.Payload))
	}

	t.Logf("✅ TPKT 解析成功")
}

func TestParseTPKT_Invalid(t *testing.T) {
	// 版本号错误
	data := []byte{0x04, 0x00, 0x00, 0x10}
	_, err := ParseTPKT(data)
	if err == nil {
		t.Errorf("应该返回版本号错误")
	}

	// 太短
	_, err = ParseTPKT([]byte{0x03})
	if err == nil {
		t.Errorf("应该返回数据过短")
	}
}

func TestSerializeTPKT(t *testing.T) {
	payload := []byte{0x08, 0x02, 0x00, 0x01, 0x05}
	frame := SerializeTPKT(payload)

	if frame[0] != TPKTVersion {
		t.Errorf("Version = %d", frame[0])
	}
	expectedLen := uint16(TPKTHeaderLen + len(payload))
	gotLen := binary.BigEndian.Uint16(frame[2:4])
	if gotLen != expectedLen {
		t.Errorf("Length = %d, want %d", gotLen, expectedLen)
	}

	t.Logf("✅ TPKT 序列化成功, 总长=%d", len(frame))
}

func TestScanTransportAddresses_IPv6(t *testing.T) {
	// 构造模拟的 H.225 数据, 嵌入一个 IPv6 TransportAddress
	ipv6 := net.ParseIP("2001:db8::1").To16()
	port := uint16(1720)

	data := make([]byte, 30)
	// 前几个字节是随机 ASN.1 结构填充
	data[0] = 0x28
	data[1] = 0x06
	data[2] = 0x00
	// 在 offset 3 处嵌入 IPv6 TransportAddress
	copy(data[3:19], ipv6)
	binary.BigEndian.PutUint16(data[19:21], port)

	addrs := ScanTransportAddresses(data)

	found := false
	for _, addr := range addrs {
		if addr.IsIPv6 && addr.IP.Equal(ipv6) && addr.Port == port {
			found = true
			t.Logf("  发现 IPv6 TransportAddress @ offset %d: %s:%d", addr.Offset, addr.IP, addr.Port)
		}
	}

	if !found {
		t.Errorf("未能在模拟数据中发现 IPv6 TransportAddress")
	}

	t.Logf("✅ IPv6 TransportAddress 扫描成功, 发现 %d 个候选", len(addrs))
}

func TestScanTransportAddresses_IPv4(t *testing.T) {
	ipv4 := net.ParseIP("198.51.100.1").To4()
	port := uint16(1720)

	// 填充: 使用 0xFF 开头 (>= 224 会被 isPlausibleIPv4 拒绝)
	data := make([]byte, 14)
	data[0] = 0xFF
	data[1] = 0xFF
	data[2] = 0xFF
	data[3] = 0xFF
	copy(data[4:8], ipv4)
	binary.BigEndian.PutUint16(data[8:10], port)

	addrs := ScanTransportAddresses(data)

	found := false
	for _, addr := range addrs {
		if !addr.IsIPv6 && addr.IP.Equal(ipv4) && addr.Port == port {
			found = true
		}
	}

	if !found {
		t.Errorf("未能发现 IPv4 TransportAddress, 共扫描到 %d 个候选", len(addrs))
		for _, a := range addrs {
			t.Logf("  候选: offset=%d ipv6=%v ip=%s port=%d", a.Offset, a.IsIPv6, a.IP, a.Port)
		}
	}

	t.Logf("✅ IPv4 TransportAddress 扫描成功")
}

func TestTranslateIPv6ToIPv4_H225(t *testing.T) {
	translator := NewTranslator(net.ParseIP("198.51.100.1"))

	clientIPv6 := net.ParseIP("2001:db8::1").To16()
	mappedIPv4 := net.ParseIP("198.51.100.1").To4()

	// 模拟 H.225 二进制, 在 offset 10 处嵌入客户端 IPv6 地址
	payload := make([]byte, 40)
	payload[0] = 0x05 // ASN.1 header
	payload[1] = 0x20
	copy(payload[10:26], clientIPv6)
	binary.BigEndian.PutUint16(payload[26:28], 1720) // port

	result, err := translator.TranslateIPv6ToIPv4(payload, clientIPv6, mappedIPv4)
	if err != nil {
		t.Fatalf("TranslateIPv6ToIPv4 error: %v", err)
	}

	// 验证 IPv4 地址被写入原来 IPv6 地址开头的 4 字节
	gotIP := net.IP(result.ModifiedPayload[10:14])
	if !gotIP.Equal(mappedIPv4) {
		t.Errorf("写入的 IPv4 = %s, want %s", gotIP, mappedIPv4)
	}

	// 验证后续 12 字节被清零
	for i := 14; i < 26; i++ {
		if result.ModifiedPayload[i] != 0 {
			t.Errorf("offset %d 应为 0x00, got 0x%02X", i, result.ModifiedPayload[i])
		}
	}

	// 验证端口保持不变
	port := binary.BigEndian.Uint16(result.ModifiedPayload[26:28])
	if port != 1720 {
		t.Errorf("端口 = %d, want 1720", port)
	}

	// 验证 DynamicPorts 记录
	if len(result.DynamicPorts) != 1 {
		t.Errorf("DynamicPorts 数量 = %d, want 1", len(result.DynamicPorts))
	} else {
		dp := result.DynamicPorts[0]
		if dp.Purpose != "H.225-CallSignaling" {
			t.Errorf("Purpose = %s, want H.225-CallSignaling", dp.Purpose)
		}
	}

	t.Logf("✅ H.225 IPv6→IPv4 TransportAddress 翻译成功")
}

func TestParseQ931(t *testing.T) {
	// 构造最小 Q.931 消息:
	// [0] Protocol Discriminator = 0x08
	// [1] Call Reference Length = 2
	// [2-3] Call Reference Value
	// [4] Message Type = Setup (0x05)
	// [5] User-User IE: type=0x7E, length=0x0005, data=0x05+4bytes
	q931 := []byte{
		0x08,       // Protocol Discriminator
		0x02,       // CR Length
		0x00, 0x01, // Call Reference
		0x05,       // Message Type = Setup
		// User-User IE
		0x7E,       // IE type
		0x00, 0x06, // IE length (6 bytes)
		0x05,                         // UU Protocol Discriminator (ASN.1)
		0x20, 0x00, 0x06, 0x00, 0x08, // 模拟 H.225 ASN.1 数据
	}

	msgType, h225Data, err := ParseQ931(q931)
	if err != nil {
		t.Fatalf("ParseQ931 error: %v", err)
	}

	if msgType != Q931Setup {
		t.Errorf("Message Type = 0x%02x, want 0x%02x (Setup)", msgType, Q931Setup)
	}

	if h225Data == nil {
		t.Fatalf("H.225 data 为 nil")
	}

	if len(h225Data) != 5 {
		t.Errorf("H.225 data len = %d, want 5", len(h225Data))
	}

	t.Logf("✅ Q.931 解析成功, Message Type=Setup, H.225 数据长度=%d", len(h225Data))
}

func TestProcessH225Message(t *testing.T) {
	translator := NewTranslator(net.ParseIP("198.51.100.1"))
	clientIPv6 := net.ParseIP("2001:db8::1").To16()
	mappedIPv4 := net.ParseIP("198.51.100.1").To4()

	// 构造完整的 TPKT + Q.931 + H.225 消息, 其中 H.225 包含客户端的 IPv6 地址
	h225Data := make([]byte, 30)
	copy(h225Data[5:21], clientIPv6) // IPv6 TransportAddress @ offset 5
	binary.BigEndian.PutUint16(h225Data[21:23], 1720)

	q931 := []byte{
		0x08,       // Proto Disc
		0x02,       // CR len
		0x00, 0x01, // CR value
		0x05, // Setup
		0x7E, // User-User IE
	}
	ieLen := 1 + len(h225Data) // 1 for UU proto disc
	q931 = append(q931, byte(ieLen>>8), byte(ieLen))
	q931 = append(q931, 0x05) // UU proto disc
	q931 = append(q931, h225Data...)

	tpktFrame := SerializeTPKT(q931)

	result, err := translator.ProcessH225Message(tpktFrame, clientIPv6, mappedIPv4, "6to4")
	if err != nil {
		t.Fatalf("ProcessH225Message error: %v", err)
	}

	if result.ModifiedPayload == nil {
		t.Fatalf("输出为 nil")
	}

	if len(result.DynamicPorts) > 0 {
		t.Logf("  发现 %d 个动态端口需要 NAT", len(result.DynamicPorts))
		for _, dp := range result.DynamicPorts {
			t.Logf("    %s: %s:%d -> %s:%d", dp.Purpose, dp.OriginalIP, dp.OriginalPort, dp.MappedIP, dp.MappedPort)
		}
	}

	t.Logf("✅ H.225 完整消息处理成功 (TPKT+Q.931+H.225)")
}
