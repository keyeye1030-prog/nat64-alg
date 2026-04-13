package sip

import (
	"testing"
)

func TestParseMessageInfo_INVITE(t *testing.T) {
	payload := []byte("INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP [2001:db8::100]:5060;branch=z9hG4bK776\r\n" +
		"From: <sip:alice@example.com>;tag=1928301774\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Call-ID: a84b4c76e66710@pc33.example.com\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:alice@[2001:db8::100]:5060>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 142\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=alice 2890844526 2890844526 IN IP6 2001:db8::100\r\n" +
		"s=-\r\n" +
		"c=IN IP6 2001:db8::100\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0 8\r\n")

	info := ParseMessageInfo(payload)

	if !info.IsRequest {
		t.Errorf("应该是请求")
	}
	if info.Method != "INVITE" {
		t.Errorf("Method = %q, want INVITE", info.Method)
	}
	if info.CallID != "a84b4c76e66710@pc33.example.com" {
		t.Errorf("CallID = %q", info.CallID)
	}
	if !info.HasSDP {
		t.Errorf("应该检测到 SDP")
	}
	if !info.IsCallSetup() {
		t.Errorf("应该是呼叫建立")
	}
	if info.IsCallTermination() {
		t.Errorf("不应该是呼叫终止")
	}

	t.Logf("✅ INVITE 解析: Call-ID=%s, HasSDP=%v", info.CallID, info.HasSDP)
}

func TestParseMessageInfo_BYE(t *testing.T) {
	payload := []byte("BYE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK777\r\n" +
		"Call-ID: a84b4c76e66710@pc33.example.com\r\n" +
		"CSeq: 2 BYE\r\n" +
		"\r\n")

	info := ParseMessageInfo(payload)

	if info.Method != "BYE" {
		t.Errorf("Method = %q, want BYE", info.Method)
	}
	if info.CallID != "a84b4c76e66710@pc33.example.com" {
		t.Errorf("CallID = %q", info.CallID)
	}
	if !info.IsCallTermination() {
		t.Errorf("BYE 应该是呼叫终止")
	}
	if info.HasSDP {
		t.Errorf("BYE 不应有 SDP")
	}

	t.Logf("✅ BYE 解析: Call-ID=%s, IsTermination=%v", info.CallID, info.IsCallTermination())
}

func TestParseMessageInfo_CANCEL(t *testing.T) {
	payload := []byte("CANCEL sip:bob@example.com SIP/2.0\r\n" +
		"Call-ID: cancel-test-123@host\r\n" +
		"CSeq: 1 CANCEL\r\n" +
		"\r\n")

	info := ParseMessageInfo(payload)

	if info.Method != "CANCEL" {
		t.Errorf("Method = %q, want CANCEL", info.Method)
	}
	if !info.IsCallTermination() {
		t.Errorf("CANCEL 应该是呼叫终止")
	}
	if info.CallID != "cancel-test-123@host" {
		t.Errorf("CallID = %q", info.CallID)
	}

	t.Logf("✅ CANCEL 解析正确")
}

func TestParseMessageInfo_Response(t *testing.T) {
	payload := []byte("SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK776\r\n" +
		"Call-ID: resp-test-456@host\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 100\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=bob 53655765 2353687637 IN IP4 203.0.113.50\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.50\r\n" +
		"t=0 0\r\n" +
		"m=audio 30000 RTP/AVP 0\r\n")

	info := ParseMessageInfo(payload)

	if info.IsRequest {
		t.Errorf("应该是响应, 不是请求")
	}
	if info.CallID != "resp-test-456@host" {
		t.Errorf("CallID = %q", info.CallID)
	}
	if !info.HasSDP {
		t.Errorf("应该检测到 SDP")
	}

	t.Logf("✅ 200 OK 响应解析: Call-ID=%s, HasSDP=%v", info.CallID, info.HasSDP)
}

func TestParseMessageInfo_CompactCallID(t *testing.T) {
	// RFC 3261 允许 "i" 作为 Call-ID 的紧凑形式
	payload := []byte("BYE sip:bob@example.com SIP/2.0\r\n" +
		"i: compact-callid-789@host\r\n" +
		"CSeq: 3 BYE\r\n" +
		"\r\n")

	info := ParseMessageInfo(payload)

	if info.CallID != "compact-callid-789@host" {
		t.Errorf("紧凑 Call-ID 解析失败: %q", info.CallID)
	}

	t.Logf("✅ 紧凑格式 Call-ID 解析正确: %s", info.CallID)
}
