package sip

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/extract"
)

func TestMediaClippingAndDTMFUnitCases(t *testing.T) {
	t.Parallel()

	invEp := 100.0
	okEp := 100.2
	earlyRTPEp := 100.1
	critRTPEp := 202.7

	// Cover early media, critical clipping, delayed offer, and missing media.
	pkts := []extract.SIPPacket{
		{CallID: "c-early", Method: "INVITE", Epoch: &invEp, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SDPMedia: "audio 10000 RTP/AVP 0 101", SDPMediaPort: "10000"},
		{CallID: "c-early", StatusCode: "200", CSeqMethod: "INVITE", Epoch: &okEp, SrcIP: "10.0.0.2", DstIP: "10.0.0.1"},
		{CallID: "c-crit", Method: "INVITE", Epoch: f64Ptr(200.0), SrcIP: "10.0.0.3", DstIP: "10.0.0.4"}, // delayed offer
		{CallID: "c-crit", StatusCode: "200", CSeqMethod: "INVITE", Epoch: f64Ptr(200.1), SrcIP: "10.0.0.4", DstIP: "10.0.0.3", SDPMediaPort: "24000", SDPMediaAttrs: []string{"rtpmap:105 telephone-event/8000"}},
		{CallID: "c-nomedia", Method: "INVITE", Epoch: f64Ptr(300.0), SrcIP: "10.0.0.5", DstIP: "10.0.0.6", SDPMediaPort: "30000"},
		{CallID: "c-nomedia", StatusCode: "200", CSeqMethod: "INVITE", Epoch: f64Ptr(300.1), SrcIP: "10.0.0.6", DstIP: "10.0.0.5"},
	}
	streams := []extract.RTPStreamSummary{
		{SSRC: "0x1", SrcIP: "10.0.0.1", SrcPort: "10000", DstIP: "10.0.0.2", DstPort: "10000", FirstEpoch: &earlyRTPEp},
		{SSRC: "0x2", SrcIP: "10.0.0.3", SrcPort: "24000", DstIP: "10.0.0.4", DstPort: "24000", FirstEpoch: &critRTPEp},
	}

	clip := AnalyzeMediaClipping(pkts, streams)
	if clip.AnalyzedCalls != 3 || clip.EarlyMediaCalls != 1 || clip.CriticalCount != 1 || clip.NoMediaCount != 1 || clip.EarlyOfferCalls != 2 || clip.DelayedOfferCalls != 1 {
		t.Fatalf("unexpected AnalyzeMediaClipping counts: %+v", clip)
	}
	if math.Abs(clip.MaxDelayMS-2600.0) > 1.0 || !strings.Contains(clip.Verdict, "critical clipping") {
		t.Fatalf("unexpected clipping delay/verdict: %+v", clip)
	}
	if emptyClip := AnalyzeMediaClipping(nil, nil); emptyClip.AnalyzedCalls != 0 {
		t.Fatalf("expected 0 calls for empty clipping input, got %+v", emptyClip)
	}

	// Cover DTMF dynamic PT 105 + PT mismatch + incomplete event + event label mapping.
	dtmf := AnalyzeDTMFEvents(pkts, []extract.RTPEventPacket{
		{PacketNum: 10, Epoch: 201.0, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SSRC: "0x2", PayloadType: "105", EventID: 0, EndOfEvent: false, Duration: 400},
		{PacketNum: 11, Epoch: 201.05, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SSRC: "0x2", PayloadType: "105", EventID: 0, EndOfEvent: true, Duration: 1200},
		{PacketNum: 12, Epoch: 201.4, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SSRC: "0x2", PayloadType: "105", EventID: 10, EndOfEvent: true, Duration: 800},
		{PacketNum: 13, Epoch: 201.8, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SSRC: "0x2", PayloadType: "105", EventID: 11, EndOfEvent: true, Duration: 800},
		{PacketNum: 14, Epoch: 202.2, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SSRC: "0x2", PayloadType: "105", EventID: 12, EndOfEvent: true, Duration: 800},
		{PacketNum: 15, Epoch: 202.6, SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SSRC: "0x2", PayloadType: "110", EventID: 99, EndOfEvent: false, Duration: 400},
	})
	if dtmf.CompletedEvents != 4 || dtmf.IncompleteEvents != 1 || dtmf.PTMismatchCount != 1 {
		t.Fatalf("unexpected DTMF summary: %+v", dtmf)
	}
	if !strings.HasPrefix(dtmf.Digits, "0*#A") || len(dtmf.Warnings) != 2 {
		t.Fatalf("unexpected DTMF digits or warnings: digits=%q warnings=%v", dtmf.Digits, dtmf.Warnings)
	}
	if dtmf.NegotiatedPTs[0] != 101 || dtmf.NegotiatedPTs[1] != 105 {
		t.Fatalf("expected negotiated PTs [101 105], got %v", dtmf.NegotiatedPTs)
	}
}

func TestQuickQualityCheckRealDynamicPortClippingAndDTMF(t *testing.T) {
	ctx := context.Background()
	pcapPath := filepath.Join(t.TempDir(), "real_clip_dtmf.pcap")
	writeSIPDynamicRTPDTMFPcap(t, pcapPath)

	rep := QuickQualityCheck(ctx, pcapPath)
	if rep.Status != "success" || rep.MediaClipping == nil || rep.DTMFEvents == nil {
		t.Fatalf("expected MediaClipping and DTMFEvents on real capture, got %+v", rep)
	}
	if rep.MediaClipping.WarningCount != 1 || math.Abs(rep.MediaClipping.MaxDelayMS-800.0) > 10.0 {
		t.Fatalf("expected ~800ms warning clipping delay, got %+v", rep.MediaClipping)
	}
	if rep.DTMFEvents.Digits != "7#" || rep.DTMFEvents.CompletedEvents != 2 || len(rep.DTMFEvents.NegotiatedPTs) != 1 || rep.DTMFEvents.NegotiatedPTs[0] != 106 {
		t.Fatalf("expected digits 7# on PT 106, got %+v", rep.DTMFEvents)
	}

	netSIP := EvaluateNetorchSIP(ctx, pcapPath, true, true)
	if !netSIP.Present || netSIP.MediaClipping == nil || netSIP.DTMFEvents == nil || netSIP.DTMFEvents.Digits != "7#" {
		t.Fatalf("expected EvaluateNetorchSIP clipping+DTMF, got %+v", netSIP)
	}
	if clip, dtmf := optionalVoIPExtras(nil); clip != nil || dtmf != nil {
		t.Fatal("expected nil extras for nil summary")
	}
}

func writeSIPDynamicRTPDTMFPcap(t *testing.T, outPath string) {
	t.Helper()
	sdp := strings.Join([]string{
		"v=0", "o=alice 100 100 IN IP4 192.0.2.10", "s=call", "c=IN IP4 192.0.2.10", "t=0 0",
		"m=audio 42100 RTP/AVP 0 106",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:106 telephone-event/8000",
		"",
	}, "\r\n")
	lenStr := "Content-Length: " + itoa(len(sdp))
	inv := strings.Join([]string{
		"INVITE sip:bob@example.com SIP/2.0",
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1",
		"From: <sip:alice@example.com>;tag=a1",
		"To: <sip:bob@example.com>",
		"Call-ID: clip-dtmf@192.0.2.10",
		"CSeq: 1 INVITE", "Max-Forwards: 70", "Content-Type: application/sdp", lenStr, "", sdp,
	}, "\r\n")
	ok := strings.Join([]string{
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1",
		"From: <sip:alice@example.com>;tag=a1",
		"To: <sip:bob@example.com>;tag=b1",
		"Call-ID: clip-dtmf@192.0.2.10",
		"CSeq: 1 INVITE", "Content-Type: application/sdp", lenStr, "", sdp,
	}, "\r\n")
	buildRTP := func(pt byte, seq uint16, ts, ssrc uint32, body []byte) []byte {
		p := make([]byte, 12+len(body))
		p[0], p[1] = 0x80, pt
		binary.BigEndian.PutUint16(p[2:4], seq)
		binary.BigEndian.PutUint32(p[4:8], ts)
		binary.BigEndian.PutUint32(p[8:12], ssrc)
		copy(p[12:], body)
		return p
	}
	type pktSpec struct {
		sec, usec uint32
		src, dst  string
		sp, dp    uint16
		payload   []byte
	}
	specs := []pktSpec{
		{1700000100, 0, "192.0.2.10", "192.0.2.20", 5060, 5060, []byte(inv)},
		{1700000100, 100000, "192.0.2.20", "192.0.2.10", 5060, 5060, []byte(ok)},
		{1700000100, 900000, "192.0.2.10", "192.0.2.20", 42100, 42100, buildRTP(0, 1, 160, 0xaabbccdd, make([]byte, 160))},
		{1700000101, 50000, "192.0.2.10", "192.0.2.20", 42100, 42100, buildRTP(106, 2, 320, 0xaabbccdd, []byte{7, 0x8a, 0x06, 0x40})},
		{1700000101, 250000, "192.0.2.10", "192.0.2.20", 42100, 42100, buildRTP(106, 3, 1920, 0xaabbccdd, []byte{11, 0x8a, 0x06, 0x40})},
	}

	var buf bytes.Buffer
	var gh [24]byte
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	binary.LittleEndian.PutUint32(gh[20:24], 1)
	buf.Write(gh[:])
	for _, s := range specs {
		ipPkt := buildUDPv4(s.src, s.dst, s.sp, s.dp, s.payload)
		var eth [14]byte
		binary.BigEndian.PutUint16(eth[12:14], 0x0800)
		tlen := uint32(14 + len(ipPkt))
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], s.sec)
		binary.LittleEndian.PutUint32(rh[4:8], s.usec)
		binary.LittleEndian.PutUint32(rh[8:12], tlen)
		binary.LittleEndian.PutUint32(rh[12:16], tlen)
		buf.Write(rh[:])
		buf.Write(eth[:])
		buf.Write(ipPkt)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
