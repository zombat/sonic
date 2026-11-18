package extract

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildDynamicRTPDTMFPcap(t *testing.T, outPath string) (srtpSecret, mikeySecret string) {
	t.Helper()
	srtpSecret = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
	mikeySecret = "AQAFgM0XflABAAAAAAAAAAAAAAsAyOOh4RqXbQ"

	sdpOffer := strings.Join([]string{
		"v=0",
		"o=alice 100 100 IN IP4 192.0.2.10",
		"s=call",
		"c=IN IP4 192.0.2.10",
		"t=0 0",
		"m=audio 42000 RTP/AVP 0 105",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:105 telephone-event/8000",
		"a=fmtp:105 0-15",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + srtpSecret + "|2^20|1:4",
		"a=key-mgmt:mikey " + mikeySecret,
		"",
	}, "\r\n")

	invite := strings.Join([]string{
		"INVITE sip:bob@example.com SIP/2.0",
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-dyn1",
		"From: <sip:alice@example.com>;tag=t1",
		"To: <sip:bob@example.com>",
		"Call-ID: dyn-dtmf-1@192.0.2.10",
		"CSeq: 1 INVITE",
		"Max-Forwards: 70",
		"Content-Type: application/sdp",
		"Content-Length: " + itoa(len(sdpOffer)),
		"",
		sdpOffer,
	}, "\r\n")

	okResp := strings.Join([]string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-dyn1",
		"From: <sip:alice@example.com>;tag=t1",
		"To: <sip:bob@example.com>;tag=t2",
		"Call-ID: dyn-dtmf-1@192.0.2.10",
		"CSeq: 1 INVITE",
		"Content-Type: application/sdp",
		"Content-Length: " + itoa(len(sdpOffer)),
		"",
		sdpOffer,
	}, "\r\n")

	buildRTP := func(pt byte, seq uint16, ts, ssrc uint32, body []byte) []byte {
		pkt := make([]byte, 12+len(body))
		pkt[0] = 0x80
		pkt[1] = pt
		binary.BigEndian.PutUint16(pkt[2:4], seq)
		binary.BigEndian.PutUint32(pkt[4:8], ts)
		binary.BigEndian.PutUint32(pkt[8:12], ssrc)
		copy(pkt[12:], body)
		return pkt
	}
	wrapUDP := func(sport, dport uint16, payload []byte) []byte {
		u := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(u[0:2], sport)
		binary.BigEndian.PutUint16(u[2:4], dport)
		binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
		copy(u[8:], payload)
		return u
	}

	// RFC 4733 events: digit '5' (start + end=0x80) and digit '*' (event=10, end=0x80).
	ev5Start := []byte{5, 10, 0x01, 0x40}
	ev5End := []byte{5, 0x80 | 10, 0x06, 0x40}
	evStarEnd := []byte{10, 0x80 | 10, 0x06, 0x40}

	type frameSpec struct {
		sec, usec uint32
		src, dst  string
		sp, dp    uint16
		payload   []byte
	}
	frames := []frameSpec{
		{1700000000, 0, "192.0.2.10", "192.0.2.20", 5060, 5060, []byte(invite)},
		{1700000000, 100000, "192.0.2.20", "192.0.2.10", 5060, 5060, []byte(okResp)},
		// First RTP arrives 800 ms after 200 OK on dynamic SDP port 42000 (outside 10000..20000).
		{1700000000, 900000, "192.0.2.10", "192.0.2.20", 42000, 42000, buildRTP(0, 1, 160, 0x11223344, make([]byte, 160))},
		{1700000001, 0, "192.0.2.10", "192.0.2.20", 42000, 42000, buildRTP(105, 2, 320, 0x11223344, ev5Start)},
		{1700000001, 60000, "192.0.2.10", "192.0.2.20", 42000, 42000, buildRTP(105, 3, 320, 0x11223344, ev5End)},
		{1700000001, 250000, "192.0.2.10", "192.0.2.20", 42000, 42000, buildRTP(105, 4, 1600, 0x11223344, evStarEnd)},
	}

	var buf bytes.Buffer
	var gh [24]byte
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	binary.LittleEndian.PutUint32(gh[20:24], 1)
	buf.Write(gh[:])

	for _, fr := range frames {
		ipPkt := transportIPPacket(fr.src, fr.dst, 17, wrapUDP(fr.sp, fr.dp, fr.payload))
		var eth [14]byte
		binary.BigEndian.PutUint16(eth[12:14], 0x0800)
		tlen := uint32(14 + len(ipPkt))
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], fr.sec)
		binary.LittleEndian.PutUint32(rh[4:8], fr.usec)
		binary.LittleEndian.PutUint32(rh[8:12], tlen)
		binary.LittleEndian.PutUint32(rh[12:16], tlen)
		buf.Write(rh[:])
		buf.Write(eth[:])
		buf.Write(ipPkt)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return srtpSecret, mikeySecret
}

func TestStreamingSIPDynamicRTPPortDecodeAndMasking(t *testing.T) {
	ctx := context.Background()
	pcap := filepath.Join(t.TempDir(), "dyn_rtp.pcap")
	srtpSec, mikeySec := buildDynamicRTPDTMFPcap(t, pcap)

	sum, jsonOut, err := ExtractSIPData(ctx, pcap)
	if err != nil {
		t.Fatalf("ExtractSIPData: %v", err)
	}
	if sum == nil || sum.SIPCount != 2 || sum.RTPStreamCount != 1 {
		t.Fatalf("expected 2 SIP and 1 dynamic-port RTP stream, got %+v", sum)
	}
	if sum.RTPStreams[0].PacketCount != 4 || sum.RTPStreams[0].FirstEpoch == nil || sum.RTPStreams[0].LastEpoch == nil {
		t.Fatalf("unexpected RTP stream summary: %+v", sum.RTPStreams[0])
	}
	if len(sum.RTPEvents) < 2 {
		t.Fatalf("expected >= 2 rtpevent packets, got %+v", sum.RTPEvents)
	}
	if strings.Contains(jsonOut, srtpSec) || strings.Contains(jsonOut, mikeySec) {
		t.Fatal("SDP inline SRTP or MIKEY secret leaked into extracted SIP summary JSON")
	}
}
