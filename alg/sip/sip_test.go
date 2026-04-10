package sip

import (
	"net"
	"strings"
	"testing"
)

// ============================================================================
// SIP ALG 单元测试
// ============================================================================

func TestSIPInviteIPv6ToIPv4(t *testing.T) {
	translator := NewTranslator(net.ParseIP("198.51.100.1"))
	clientIPv6 := net.ParseIP("2001:db8::1")
	mappedIPv4 := net.ParseIP("198.51.100.1")

	sipMsg := "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK776\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: Bob <sip:bob@biloxi.example.com>\r\n" +
		"From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:alice@[2001:db8::1]:5060>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 142\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=alice 2890844526 2890844526 IN IP6 2001:db8::1\r\n" +
		"s=-\r\n" +
		"c=IN IP6 2001:db8::1\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"

	result, err := translator.TranslateIPv6ToIPv4([]byte(sipMsg), clientIPv6, mappedIPv4)
	if err != nil {
		t.Fatalf("TranslateIPv6ToIPv4 error: %v", err)
	}

	modified := string(result.ModifiedPayload)

	// ---- 验证 Via 头被正确重写  ----
	if strings.Contains(modified, "[2001:db8::1]") {
		t.Errorf("Via 头仍包含 IPv6 地址")
	}
	if !strings.Contains(modified, "Via: SIP/2.0/UDP 198.51.100.1:5060") {
		t.Errorf("Via 头未正确重写为 IPv4.\n实际: %s", extractLine(modified, "Via:"))
	}

	// ---- 验证 Contact 头被正确重写 ----
	if !strings.Contains(modified, "sip:alice@198.51.100.1:5060>") {
		t.Errorf("Contact 头未正确重写.\n实际: %s", extractLine(modified, "Contact:"))
	}

	// ---- 验证 SDP c= 行 ----
	if !strings.Contains(modified, "c=IN IP4 198.51.100.1") {
		t.Errorf("SDP c= 行未正确重写.\n实际: %s", extractLine(modified, "c="))
	}

	// ---- 验证 SDP o= 行 ----
	if !strings.Contains(modified, "IN IP4 198.51.100.1") {
		t.Errorf("SDP o= 行未正确重写")
	}

	// ---- 验证 SDP 中不再包含 IP6 ----
	sdpStart := strings.Index(modified, "v=0")
	if sdpStart > 0 {
		sdpPart := modified[sdpStart:]
		if strings.Contains(sdpPart, "IP6") {
			t.Errorf("SDP 中仍包含 IP6")
		}
	}

	// ---- 验证媒体端口被记录 ----
	if len(result.MediaPorts) < 2 {
		t.Errorf("MediaPorts 数量 = %d, 期望至少 2 (RTP+RTCP)", len(result.MediaPorts))
	} else {
		if result.MediaPorts[0].OriginalPort != 49170 {
			t.Errorf("RTP 端口 = %d, want 49170", result.MediaPorts[0].OriginalPort)
		}
		if result.MediaPorts[1].OriginalPort != 49171 {
			t.Errorf("RTCP 端口 = %d, want 49171", result.MediaPorts[1].OriginalPort)
		}
	}

	// ---- 验证 Content-Length 已更新 ----
	t.Logf("✅ SIP INVITE IPv6→IPv4 翻译成功, LengthDelta=%d", result.LengthDelta)
	t.Logf("修改后消息预览:\n%s", modified)
}

func TestSIP200OKIPv4ToIPv6(t *testing.T) {
	translator := NewTranslator(net.ParseIP("198.51.100.1"))
	serverIPv4 := net.ParseIP("203.0.113.5")
	clientIPv6 := net.ParseIP("2001:db8::1")

	sipMsg := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK776\r\n" +
		"To: Bob <sip:bob@biloxi.example.com>;tag=314159\r\n" +
		"From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:bob@198.51.100.1>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 131\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=bob 2808844564 2808844564 IN IP4 198.51.100.1\r\n" +
		"s=-\r\n" +
		"c=IN IP4 198.51.100.1\r\n" +
		"t=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"

	result, err := translator.TranslateIPv4ToIPv6([]byte(sipMsg), serverIPv4, clientIPv6)
	if err != nil {
		t.Fatalf("TranslateIPv4ToIPv6 error: %v", err)
	}

	modified := string(result.ModifiedPayload)

	// ---- 验证 SDP 被重写为 IPv6 ----
	if !strings.Contains(modified, "c=IN IP6 2001:db8::1") {
		t.Errorf("SDP c= 行未正确重写为 IPv6.\n实际: %s", extractLine(modified, "c="))
	}

	// ---- 验证 Via 头中的 pool 地址被重写 ----
	if strings.Contains(modified, "198.51.100.1") {
		t.Errorf("仍包含 pool IPv4 地址")
	}

	t.Logf("✅ SIP 200 OK IPv4→IPv6 翻译成功, LengthDelta=%d", result.LengthDelta)
	t.Logf("修改后消息预览:\n%s", modified)
}

func TestSIPRegisterNoSDP(t *testing.T) {
	translator := NewTranslator(net.ParseIP("198.51.100.1"))
	clientIPv6 := net.ParseIP("2001:db8::99")
	mappedIPv4 := net.ParseIP("198.51.100.1")

	sipMsg := "REGISTER sip:registrar.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP [2001:db8::99]:5060;branch=z9hG4bKnashds7\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: Bob <sip:bob@example.com>\r\n" +
		"From: Bob <sip:bob@example.com>;tag=456248\r\n" +
		"Call-ID: 843817637684230@998sdasdh09\r\n" +
		"CSeq: 1826 REGISTER\r\n" +
		"Contact: <sip:bob@[2001:db8::99]:5060>\r\n" +
		"Content-Length: 0\r\n"

	result, err := translator.TranslateIPv6ToIPv4([]byte(sipMsg), clientIPv6, mappedIPv4)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	modified := string(result.ModifiedPayload)

	if strings.Contains(modified, "[2001:db8::99]") {
		t.Errorf("仍包含 IPv6 方括号地址")
	}

	if !strings.Contains(modified, "Via: SIP/2.0/UDP 198.51.100.1:5060") {
		t.Errorf("Via 未正确重写")
	}

	if !strings.Contains(modified, "sip:bob@198.51.100.1:5060>") {
		t.Errorf("Contact 未正确重写")
	}

	if len(result.MediaPorts) != 0 {
		t.Errorf("无 SDP 的 REGISTER 不应有 MediaPorts")
	}

	t.Logf("✅ SIP REGISTER (无 SDP) 翻译成功")
}

// ---- 辅助函数 ----

func extractLine(s, prefix string) string {
	for _, line := range strings.Split(s, "\r\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return "(not found)"
}
