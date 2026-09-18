package nat64

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSIPALGSessionDirectionMapping(t *testing.T) {
	clientIPv6 := net.ParseIP("2001:db8::100").To16()
	serverIPv4 := net.ParseIP("203.0.113.20").To4()
	synthServerIPv6 := IPv4ToIPv6(serverIPv4)
	mappedClientIPv4 := net.ParseIP("198.51.100.1").To4()

	sess := &Session{
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Key6: SessionKey6{
			SrcPort: 5060,
			DstPort: 5060,
			Proto:   ProtoUDP,
		},
		Key4: SessionKey4{
			SrcPort: 5060,
			DstPort: 5060,
			Proto:   ProtoUDP,
		},
	}
	copy(sess.Key6.SrcIP[:], clientIPv6)
	copy(sess.Key6.DstIP[:], synthServerIPv6)
	copy(sess.Key4.SrcIP[:], mappedClientIPv4)
	copy(sess.Key4.DstIP[:], serverIPv4)

	handler := NewALGHandler(mappedClientIPv4)

	invite := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP [2001:db8::100]:5060;branch=z9hG4bK776\r\n" +
		"Contact: <sip:alice@[2001:db8::100]:5060>\r\n" +
		"Call-ID: call-001@example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 78\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=alice 1 1 IN IP6 2001:db8::100\r\n" +
		"c=IN IP6 2001:db8::100\r\n" +
		"m=audio 40000 RTP/AVP 0\r\n"

	ipv4Pkt := buildTestIPv4UDP(t, mappedClientIPv4, serverIPv4, 5060, 5060, []byte(invite))
	translated4, _ := handler.ProcessALG6to4(ipv4Pkt, sess)
	got4 := string(translated4[IPv4HeaderMinLen+8:])
	if !strings.Contains(got4, "Contact: <sip:alice@198.51.100.1:5060>") {
		t.Fatalf("6to4 Contact used wrong endpoint:\n%s", got4)
	}
	if !strings.Contains(got4, "c=IN IP4 198.51.100.1") {
		t.Fatalf("6to4 SDP c= used wrong endpoint:\n%s", got4)
	}
	if strings.Contains(got4, "203.0.113.20") {
		t.Fatalf("6to4 unexpectedly rewrote client media to server IPv4:\n%s", got4)
	}

	ok := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK776\r\n" +
		"Contact: <sip:bob@203.0.113.20:5060>\r\n" +
		"Call-ID: call-001@example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 73\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=bob 1 1 IN IP4 203.0.113.20\r\n" +
		"c=IN IP4 203.0.113.20\r\n" +
		"m=audio 50000 RTP/AVP 0\r\n"

	ipv6Pkt := buildTestIPv6UDP(t, IPv4ToIPv6(serverIPv4), clientIPv6, 5060, 5060, []byte(ok))
	translated6, _ := handler.ProcessALG4to6(ipv6Pkt, sess)
	got6 := string(translated6[IPv6HeaderLen+8:])
	if !strings.Contains(got6, "Contact: <sip:bob@["+synthServerIPv6.String()+"]:5060>") {
		t.Fatalf("4to6 Contact used wrong endpoint:\n%s", got6)
	}
	if !strings.Contains(got6, "c=IN IP6 "+synthServerIPv6.String()) {
		t.Fatalf("4to6 SDP c= used wrong endpoint:\n%s", got6)
	}
	if strings.Contains(got6, clientIPv6.String()+"]:5060") {
		t.Fatalf("4to6 unexpectedly rewrote server contact to client IPv6:\n%s", got6)
	}
}

func buildTestIPv4UDP(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	udpLen := 8 + len(payload)
	pkt := make([]byte, IPv4HeaderMinLen+udpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = ProtoNumUDPNum
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[10:12], IPv4HeaderChecksum(pkt[:IPv4HeaderMinLen]))
	udp := pkt[IPv4HeaderMinLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	recalcTransportChecksum4(pkt, ProtoNumUDPNum)
	return pkt
}

func buildTestIPv6UDP(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	udpLen := 8 + len(payload)
	pkt := make([]byte, IPv6HeaderLen+udpLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = ProtoNumUDPNum
	pkt[7] = 64
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())
	udp := pkt[IPv6HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	recalcTransportChecksum6(pkt, ProtoNumUDPNum)

	if bytes.Equal(pkt[8:24], make([]byte, 16)) || bytes.Equal(pkt[24:40], make([]byte, 16)) {
		t.Fatalf("test helper built packet with empty IPv6 address")
	}
	return pkt
}
