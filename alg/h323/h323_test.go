package h323

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestParseTPKT(t *testing.T) {
	data := []byte{0x03, 0x00, 0x00, 0x07, 0x01, 0x02, 0x03}
	tpkt, err := ParseTPKT(data)
	if err != nil {
		t.Fatalf("ParseTPKT failed: %v", err)
	}
	if tpkt.Version != 3 || tpkt.Length != 7 || !bytes.Equal(tpkt.Payload, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("TPKT field mismatch: %+v", tpkt)
	}
	t.Log("✅ TPKT 解析成功")
}

func TestParseTPKT_Invalid(t *testing.T) {
	// 版本错误
	data := []byte{0x04, 0x00, 0x00, 0x07}
	if _, err := ParseTPKT(data); err == nil {
		t.Error("应该报错: 版本不支持")
	}

	// 长度不足
	data = []byte{0x03, 0x00, 0x00}
	if _, err := ParseTPKT(data); err == nil {
		t.Error("应该报错: 数据过短")
	}
}

func TestSerializeTPKT(t *testing.T) {
	payload := []byte{0x05, 0x06, 0x07, 0x08, 0x09}
	frame := SerializeTPKT(payload)
	if len(frame) != len(payload)+4 {
		t.Errorf("长度错误: %d", len(frame))
	}
	if frame[0] != 3 || binary.BigEndian.Uint16(frame[2:4]) != 9 {
		t.Errorf("Header 错误: %v", frame[:4])
	}
	t.Logf("✅ TPKT 序列化成功, 总长=%d", len(frame))
}

func TestScanTransportAddress(t *testing.T) {
	data := make([]byte, 100)
	// 埋入一个 IPv6 地址 [2001:db8::1]:1720
	// 2001:db8::1 = 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
	ipv6 := net.ParseIP("2001:db8::1")
	copy(data[20:36], ipv6)
	binary.BigEndian.PutUint16(data[36:38], 1720)

	// 埋入一个 IPv4 地址 192.168.1.1:1720
	ipv4 := net.ParseIP("192.168.1.1").To4()
	copy(data[60:64], ipv4)
	binary.BigEndian.PutUint16(data[64:66], 1720)

	addrs := ScanTransportAddresses(data)
	if len(addrs) != 2 {
		t.Fatalf("应该找到 2 个地址, 实际: %d", len(addrs))
	}

	if !addrs[0].IsIPv6 || addrs[0].Port != 1720 || !addrs[0].IP.Equal(ipv6) {
		t.Errorf("IPv6 匹配错误: %+v", addrs[0])
	}

	if addrs[1].IsIPv6 || addrs[1].Port != 1720 || !addrs[1].IP.Equal(ipv4) {
		t.Errorf("IPv4 匹配错误: %+v", addrs[1])
	}
	t.Log("✅ TransportAddress 启发式扫描成功")
}

func TestTranslateIPv6ToIPv4(t *testing.T) {
	tr := NewTranslator(net.ParseIP("10.0.0.1"))
	data := make([]byte, 50)
	
	clientIPv6 := net.ParseIP("2001:db8::100")
	mappedIPv4 := net.ParseIP("10.0.0.100").To4()

	// 埋入客户端 IPv6 地址
	copy(data[10:26], clientIPv6)
	binary.BigEndian.PutUint16(data[26:28], 50000)

	result, err := tr.TranslateIPv6ToIPv4(data, clientIPv6, mappedIPv4)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}

	// 检查是否替换成 IPv4 地址并清零
	if !net.IP(result.ModifiedPayload[10:14]).Equal(mappedIPv4) {
		t.Errorf("IPv4 替换失败: %v", result.ModifiedPayload[10:14])
	}
	for i := 14; i < 26; i++ {
		if result.ModifiedPayload[i] != 0 {
			t.Errorf("未正确清零 padding: index %d", i)
		}
	}

	if len(result.MediaPorts) != 1 {
		t.Errorf("未记录媒体端口")
	} else {
		if result.MediaPorts[0].OriginalPort != 50000 || result.MediaPorts[0].Purpose != "RTP" {
			t.Errorf("媒体端口信息错误: %+v", result.MediaPorts[0])
		}
	}
	t.Log("✅ IPv6->IPv4 TransportAddress 翻译成功")
}

func TestQ931Parse(t *testing.T) {
	// 构造一个简单的 Q.931 Setup 消息 (IE 用伪造数据)
	// Header: [08] [01] [01] [05]
	// IE: [7E] [00 06] [05] [AA BB CC DD EE]
	data := []byte{
		0x08, 0x01, 0x01, 0x05,
		0x7E, 0x00, 0x06, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
	}

	msgType, h225Buf, err := ParseQ931(data)
	if err != nil {
		t.Fatalf("Q.931 解析失败: %v", err)
	}

	if msgType != Q931Setup || !bytes.Equal(h225Buf, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}) {
		t.Errorf("Q.931 解析不匹配: type=%v, payload=%v", msgType, h225Buf)
	}
	t.Logf("✅ Q.931/H.225 解析成功, Message Type=%v, H.225 数据长度=%d", msgType, len(h225Buf))
}

func TestProcessH225Message(t *testing.T) {
	tr := NewTranslator(net.ParseIP("10.0.0.1"))
	clientIPv6 := net.ParseIP("2001:db8::100")
	mappedIPv4 := net.ParseIP("10.0.0.100").To4()

	// 构造完整 TPKT + Q.931 + H.225 (含 IPv6 地址)
	h225Data := make([]byte, 30)
	copy(h225Data[5:21], clientIPv6)
	binary.BigEndian.PutUint16(h225Data[21:23], 60000)

	q931 := []byte{0x08, 0x01, 0x01, 0x05, 0x7E, 0x00, uint8(uint16(len(h225Data)+1) >> 8), uint8(len(h225Data) + 1), 0x05}
	q931 = append(q931, h225Data...)
	tpkt := SerializeTPKT(q931)

	result, err := tr.ProcessH225Message(tpkt, clientIPv6, mappedIPv4, "6to4")
	if err != nil {
		t.Fatalf("ProcessH225Message failed: %v", err)
	}

	if len(result.MediaPorts) != 1 {
		t.Errorf("应该找到 1 个端口, 实际: %d", len(result.MediaPorts))
	}
	if result.MediaPorts[0].OriginalPort != 60000 {
		t.Errorf("端口错误: %d", result.MediaPorts[0].OriginalPort)
	}
	
	// 验证最终 payload 中已经完成替换
	// TPKT(4) + Q931_Fixed(4) + IE_Header(4) + X.680_Tag(1) + H225Offset(5) = 18
	replacedIP := result.ModifiedPayload[18:22]
	if !net.IP(replacedIP).Equal(mappedIPv4) {
		t.Errorf("最终 IP 替换失败: %v", replacedIP)
	}
	t.Log("✅ H.225 完整链路处理成功")
}
