package sip

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/parity"
)

func intPtr(v int) *int         { return &v }
func f64Ptr(v float64) *float64 { return &v }

func buildSyntheticAuthPCAP(t *testing.T, outPath string) []string {
	t.Helper()
	digestResp := "6629fae49393a05397450978507c4ef1"
	nonce := "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	basicPass := "not-a-real-password"
	basicCred := base64.StdEncoding.EncodeToString([]byte("bob:" + basicPass))
	srtpKey := "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
	mikeyPayload := "AQAFgM0XflABAAAAAAAAAAAAAAsAyOOh4RqXbQ"
	sdpKKey := "not-a-real-sdp-key"
	secrets := []string{digestResp, basicCred, basicPass, srtpKey, mikeyPayload, sdpKKey}

	common := func(method string, cseq int, cid string) string {
		return strings.Join([]string{
			"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-" + string(rune('0'+cseq)),
			"From: <sip:alice@example.com>;tag=1928301774",
			"To: <sip:alice@example.com>",
			"Call-ID: " + cid,
			"CSeq: " + string(rune('0'+cseq)) + " " + method,
			"Max-Forwards: 70",
			"Content-Length: 0",
		}, "\r\n")
	}
	sdp := strings.Join([]string{
		"v=0", "o=alice 2890844526 2890844526 IN IP4 192.0.2.10",
		"s=call", "c=IN IP4 192.0.2.10", "t=0 0", "k=clear:" + sdpKKey,
		"m=audio 49170 RTP/SAVP 0",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + srtpKey + "|2^20|1:4",
		"a=key-mgmt:mikey " + mikeyPayload, "",
	}, "\r\n")
	invHead := []string{
		"INVITE sip:dave@example.com SIP/2.0",
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1",
		"From: <sip:alice@example.com>;tag=1928301774",
		"To: <sip:alice@example.com>",
		"Call-ID: inv-2@192.0.2.10",
		"CSeq: 1 INVITE", "Max-Forwards: 70", "Content-Type: application/sdp",
		"Content-Length: " + itoa(len(sdp)),
	}
	invWithSDP := strings.Join(invHead, "\r\n") + "\r\n\r\n" + sdp

	msgs := []struct{ src, dst, body string }{
		{"192.0.2.10", "192.0.2.20", "REGISTER sip:example.com SIP/2.0\r\n" + common("REGISTER", 1, "reg-1@192.0.2.10") + "\r\n\r\n"},
		{"192.0.2.20", "192.0.2.10", "SIP/2.0 401 Unauthorized\r\n" + common("REGISTER", 1, "reg-1@192.0.2.10") + "\r\n" + `WWW-Authenticate: Digest realm="example.com", nonce="` + nonce + `", algorithm=MD5, qop="auth"` + "\r\n\r\n"},
		{"192.0.2.10", "192.0.2.20", "REGISTER sip:example.com SIP/2.0\r\n" + common("REGISTER", 2, "reg-1@192.0.2.10") + "\r\n" + `Authorization: Digest username="alice", realm="example.com", nonce="` + nonce + `", uri="sip:example.com", response="` + digestResp + `", algorithm=MD5, qop=auth, nc=00000001, cnonce="0a4f113b"` + "\r\n\r\n"},
		{"192.0.2.20", "192.0.2.10", "SIP/2.0 200 OK\r\n" + common("REGISTER", 2, "reg-1@192.0.2.10") + "\r\nExpires: 3600\r\n\r\n"},
		{"192.0.2.10", "192.0.2.20", "INVITE sip:carol@example.com SIP/2.0\r\n" + common("INVITE", 1, "inv-1@192.0.2.10") + "\r\nProxy-Authorization: Basic " + basicCred + "\r\n\r\n"},
		{"192.0.2.10", "192.0.2.20", invWithSDP},
	}

	var buf bytes.Buffer
	var gh [24]byte
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	binary.LittleEndian.PutUint32(gh[20:24], 1)
	buf.Write(gh[:])

	for i, m := range msgs {
		ipPkt := buildUDPv4(m.src, m.dst, 5060, 5060, []byte(m.body))
		var eth [14]byte
		eth[5], eth[11] = 0x02, 0x01
		binary.BigEndian.PutUint16(eth[12:14], 0x0800)
		totalLen := uint32(14 + len(ipPkt))
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(rh[8:12], totalLen)
		binary.LittleEndian.PutUint32(rh[12:16], totalLen)
		buf.Write(rh[:])
		buf.Write(eth[:])
		buf.Write(ipPkt)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return secrets
}

func buildUDPv4(src, dst string, sport, dport uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 20+udpLen)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	s4 := netip.MustParseAddr(src).As4()
	d4 := netip.MustParseAddr(dst).As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], payload)
	return pkt
}

func itoa(n int) string {
	var digits [20]byte
	if n == 0 {
		return "0"
	}
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}

func TestSIPGoldenParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	sipMinPath := filepath.Join("tests", "fixtures", "sip_minimal.pcap")
	_, rawMin, err := extract.ExtractSIPData(ctx, sipMinPath)
	if err != nil || rawMin == "" {
		t.Fatalf("ExtractSIPData(sip_minimal) failed: %v", err)
	}

	t.Run("sip_minimal_quick_quality", func(t *testing.T) {
		got := QuickQualityCheck(ctx, sipMinPath)
		parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "sip", "sip_minimal_quick_quality.json"))
	})
	t.Run("sip_auth_quick_quality", func(t *testing.T) {
		authPcap := filepath.Join(t.TempDir(), "sip_auth_synthetic.pcap")
		secrets := buildSyntheticAuthPCAP(t, authPcap)
		got := QuickQualityCheck(ctx, authPcap)
		raw, _ := json.Marshal(got)
		for _, sec := range secrets {
			if strings.Contains(string(raw), sec) {
				t.Fatalf("secret %q leaked in QuickQualityCheck JSON", sec)
			}
		}
		got.File = "tests/fixtures/sip_auth_synthetic.pcap"
		parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "sip", "sip_auth_quick_quality.json"))
	})
	t.Run("sip_minimal_tracking", func(t *testing.T) {
		got := ExtractAndAnalyzeCallTracking(rawMin)
		parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "sip", "sip_minimal_tracking.json"))
	})
	t.Run("sip_minimal_overlap", func(t *testing.T) {
		got := DetectOverlapDialing(rawMin)
		parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "sip", "sip_minimal_overlap.json"))
	})
}

// TestAuthDiagnosticsPortsTestAuthDiagnosticsPY mirrors all 5 cases in test_auth_diagnostics.py.
func TestAuthDiagnosticsPortsTestAuthDiagnosticsPY(t *testing.T) {
	t.Run("401_challenges_weak_md5_missing_qop", func(t *testing.T) {
		in := ScoringInput{
			SIPPackets: []extract.SIPPacket{{Method: "REGISTER"}, {StatusCode: "401"}},
			Auth: &extract.AuthInfo{
				AuthChallenges: []extract.AuthChallenge{
					{StatusCode: "401", Algorithm: "MD5", QoP: ""},
					{StatusCode: "401", Algorithm: "", QoP: ""},
				},
			},
		}
		res := ScoreCallQuality(in)
		if res.ProtocolDetails["auth_challenges_401"] != 2 || res.ProtocolDetails["auth_challenges_407"] != 0 ||
			res.ProtocolDetails["auth_penalty"] != 25 || res.ProtocolDetails["authentication"] != 75 {
			t.Fatalf("unexpected protocol details: %+v", res.ProtocolDetails)
		}
		joined := strings.Join(res.DegradationFactors, " | ")
		for _, want := range []string{"Weak digest algorithm detected", "Missing qop in majority of auth challenges", "Auth challenges present without Authorization responses"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("missing degradation factor %q in %s", want, joined)
			}
		}
	})

	t.Run("407_cascading_proxy_challenges", func(t *testing.T) {
		in := ScoringInput{
			SIPPackets: []extract.SIPPacket{{Method: "INVITE"}, {StatusCode: "407"}},
			Auth: &extract.AuthInfo{
				AuthChallenges: []extract.AuthChallenge{
					{StatusCode: "407", Algorithm: "SHA-256", QoP: "auth"},
					{StatusCode: "407", Algorithm: "SHA-256", QoP: "auth"},
					{StatusCode: "407", Algorithm: "SHA-256", QoP: "auth"},
					{StatusCode: "407", Algorithm: "SHA-256", QoP: "auth"},
				},
				AuthResponses: []extract.AuthResponse{{Method: "INVITE", IsProxy: true}},
			},
		}
		res := ScoreCallQuality(in)
		if res.ProtocolDetails["auth_challenges_407"] != 4 || res.ProtocolDetails["auth_penalty"] != 25 || res.ProtocolDetails["authentication"] != 75 {
			t.Fatalf("unexpected 407 details: %+v", res.ProtocolDetails)
		}
		joined := strings.Join(res.DegradationFactors, " | ")
		if !strings.Contains(joined, "Excessive auth challenges detected: 4") || !strings.Contains(joined, "Cascading proxy auth challenges (407): 4") {
			t.Fatalf("missing cascading 407 factors: %s", joined)
		}
	})

	t.Run("register_failures_apply_penalty", func(t *testing.T) {
		in := ScoringInput{
			SIPPackets: []extract.SIPPacket{{Method: "REGISTER"}, {StatusCode: "401"}, {StatusCode: "403"}},
			Auth: &extract.AuthInfo{
				AuthChallenges:   []extract.AuthChallenge{{StatusCode: "401", Algorithm: "SHA-256", QoP: "auth"}},
				AuthResponses:    []extract.AuthResponse{{Method: "REGISTER"}},
				RegisterAttempts: []extract.RegisterAttempt{{CallID: "reg-1", Success: false}},
			},
		}
		res := ScoreCallQuality(in)
		if res.ProtocolDetails["register_failures"] != 1 || res.ProtocolDetails["auth_penalty"] != 20 || res.ProtocolDetails["authentication"] != 80 {
			t.Fatalf("unexpected register failure details: %+v", res.ProtocolDetails)
		}
		if !slices.Contains(res.DegradationFactors, "❌ Failed REGISTER attempts: 1") {
			t.Fatalf("missing failed REGISTER degradation: %v", res.DegradationFactors)
		}
	})

	t.Run("healthy_auth_flow_receives_no_penalty", func(t *testing.T) {
		in := ScoringInput{
			SIPPackets: []extract.SIPPacket{{Method: "REGISTER"}, {StatusCode: "401"}, {StatusCode: "200"}},
			Auth: &extract.AuthInfo{
				AuthChallenges:   []extract.AuthChallenge{{StatusCode: "401", Algorithm: "SHA-256", QoP: "auth"}},
				AuthResponses:    []extract.AuthResponse{{Method: "REGISTER"}},
				RegisterAttempts: []extract.RegisterAttempt{{CallID: "reg-ok", Success: true, Authenticated: true}},
			},
		}
		res := ScoreCallQuality(in)
		if res.ProtocolDetails["auth_penalty"] != 0 || res.ProtocolDetails["authentication"] != 100 {
			t.Fatalf("expected 0 penalty for healthy auth, got %+v", res.ProtocolDetails)
		}
		if !slices.Contains(res.QualityFactors, "✅ Authentication flow appears healthy") {
			t.Fatalf("missing healthy auth factor: %v", res.QualityFactors)
		}
	})

	t.Run("fallback_sip_packet_auth_inference", func(t *testing.T) {
		res := ScoreCallQuality(ScoringInput{
			SIPPackets: []extract.SIPPacket{
				{StatusCode: "401"},
				{Method: "INVITE", Authorization: "Digest response=\"[MASKED]\""},
			},
		})
		if res.ProtocolDetails["auth_challenges_401"] != 1 || res.ProtocolDetails["auth_responses"] != 1 || res.ProtocolDetails["auth_penalty"] != 0 {
			t.Fatalf("unexpected packet fallback auth details: %+v", res.ProtocolDetails)
		}
	})
}

func TestQualityScoringAndMOSTiers(t *testing.T) {
	// Quality scoring with network QoS issues, TCP health, codecs, and incomplete/error calls.
	codeBye, codeErr := "200", "486"
	hiScore := 92.0
	midScore := 75.0
	lowScore := 40.0
	for _, hs := range []*float64{&hiScore, &midScore, &lowScore} {
		q := ScoreCallQuality(ScoringInput{
			SIPPackets: []extract.SIPPacket{
				{StatusCode: "200"}, {StatusCode: "200"}, {StatusCode: "486"},
			},
			RTPStreams: []extract.RTPStreamSummary{{SSRC: "0x1", PayloadType: "9"}},
			SDPSessions: []SDPSessionSpec{{Media: []SDPMediaSpec{{
				MediaType: "audio", PayloadTypes: []string{"0", "9", "18", "99"},
			}}}},
			CallSessions: []CallSessionSummary{
				{CompleteSession: true, DisconnectCode: &codeBye},
				{CompleteSession: false, DisconnectCode: &codeErr},
			},
			Network: &NetworkQualityInput{
				HasRealIssues: true, RealIssuesDetected: []string{"QoS DSCP mismatch"}, TCPHealthScore: hs,
			},
		})
		if q.CodecDetails["negotiation"] != 80 || q.Grade == "" {
			t.Fatalf("unexpected multi-codec negotiation score: %+v", q)
		}
	}

	// ScoreCallQualityFromJSON fallback path with rtp_streams codecs and single G.729 stream.
	jsonQ := ScoreCallQualityFromJSON(`{"sip_messages":[{"status_code":"200"},{"status_code":"407"}],"rtp_streams":[{"payload_type":"18"}]}`,
		nil, &NetworkQualityInput{HasRealIssues: true}, nil)
	if jsonQ.NetworkDetails["qos_markings"] != 100 || jsonQ.CodecScore <= 70 {
		t.Fatalf("unexpected JSON quality score: %+v", jsonQ)
	}
	_ = determineQualityGrade(95)
	_ = determineQualityGrade(85)
	_ = determineQualityGrade(75)
	_ = determineQualityGrade(65)
	_ = determineQualityGrade(45)
	_ = determineQualityGrade(10)

	// RTP MOS: packet flow (loss, out-of-order, jitter) and metadata variants.
	mosRes := AnalyzeRTPStreams([]RTPStreamInput{
		{
			SSRC: "0xaaaa", PayloadType: "18",
			Packets: []RTPPacketSample{
				{Sequence: intPtr(1), Timestamp: f64Ptr(0.000)},
				{Sequence: intPtr(4), Timestamp: f64Ptr(0.080)},
				{Sequence: intPtr(2), Timestamp: f64Ptr(0.025)},
				{Sequence: intPtr(3), Timestamp: f64Ptr(0.070)},
			},
		},
		{SSRC: "0xbbbb", PayloadType: "98", PacketCount: 200, HasPacketCount: true, LossRate: 0.5, Jitter: 35, HasJitter: true, Latency: 160, HasLatency: true},
		{SSRC: "0xcccc", PayloadType: "97", PacketCount: 100, HasPacketCount: true, LossRate: 6.0, Jitter: 110, HasJitter: true, Latency: 250, HasLatency: true},
		{PayloadType: "9", LossRate: 2.5, Jitter: 55, HasJitter: true, Latency: 120, HasLatency: true},
	})
	if len(mosRes.Streams) != 4 || mosRes.WorstMOS > mosRes.BestMOS {
		t.Fatalf("unexpected MOS aggregate: %+v", mosRes)
	}
	jsonMOS := AnalyzeRTPStreamsFromJSON(`{"rtp_streams":[{"ssrc":"0x1","payload_type":"0","packet_count":50,"jitter":10,"latency":40}]}`)
	if jsonMOS.OverallCategory != MOSGood || jsonMOS.Streams[0].Codec != "G.711" {
		t.Fatalf("unexpected G.711 JSON MOS: %+v", jsonMOS)
	}
	for _, pt := range []string{"0", "3", "4", "8", "9", "18", "97", "98", "99"} {
		_ = mapMOSPayloadToCodec(pt)
	}
	for _, m := range []float64{4.6, 3.8, 2.8, 1.8, 1.0} {
		_ = determineMOSCategory(m)
	}
}

func TestTrackingOverlapEndpointsAndQuickPaths(t *testing.T) {
	ctx := context.Background()

	// Call tracking: scapy text, _source raw JSON, error responses, recipient hangup, invite_only, bye_only.
	scapyRaw := strings.Join([]string{
		"INVITE sip:bob@10.0.0.2 SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.1:5060",
		"From: <sip:alice@10.0.0.1>",
		"To: <sip:bob@10.0.0.2>",
		"Contact: <sip:alice@10.0.0.9>",
		"Call-ID: scapy-1",
		"User-Agent: TestUA/1.0",
		"---PACKET---",
		"SIP/2.0 200 OK",
		"Call-ID: scapy-1",
		"From: <sip:bob@10.0.0.2>",
		"To: <sip:alice@10.0.0.1>",
		"---PACKET---",
		"BYE sip:alice@10.0.0.9 SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.2:5062",
		"Call-ID: scapy-1",
	}, "\n")
	converted := ConvertSIPDataForTracking(scapyRaw)
	if !strings.Contains(converted, `"call_id": "scapy-1"`) || ConvertSIPDataForTracking(`{"sip_packets":[]}`) != `{"sip_packets":[]}` {
		t.Fatalf("ConvertSIPDataForTracking mismatch: %s", converted)
	}
	repScapy := ExtractAndAnalyzeCallTracking(converted)
	if repScapy.Analysis.CompleteCalls != 1 || repScapy.Analysis.RecipientHangups != 1 {
		t.Fatalf("expected recipient hangup complete call, got %+v", repScapy.Analysis)
	}

	rawLayerJSON := `[
		{"_source":{"layers":{"frame":{"frame.number":["1"],"frame.time":["1.0"]},"ip":{"ip.src":["10.1.0.1"],"ip.dst":["10.1.0.2"]},"udp":{"udp.srcport":["5060"],"udp.dstport":["5060"]},"sip":{"sip.Call-ID":["c-err"],"sip.Method":["INVITE"],"sip.User-Agent":["UA"]}}}},
		{"_source":{"layers":{"frame":{"frame.number":["2"],"frame.time":["1.1"]},"ip":{"ip.src":["10.1.0.2"],"ip.dst":["10.1.0.1"]},"udp":{"udp.srcport":["5060"],"udp.dstport":["5060"]},"sip":{"sip.Call-ID":["c-err"],"sip.Status-Code":["486"]}}}},
		{"_source":{"layers":{"frame":{"frame.number":["3"],"frame.time":["1.2"]},"ip":{"ip.src":["10.1.0.3"],"ip.dst":["10.1.0.4"]},"udp":{"udp.srcport":["5060"],"udp.dstport":["5060"]},"sip":{"sip.Call-ID":["c-byeonly"],"sip.Method":["BYE"]}}}},
		{"_source":{"layers":{"frame":{"frame.number":["4"],"frame.time":["1.3"]},"ip":{"ip.src":["10.1.0.5"],"ip.dst":["10.1.0.6"]},"udp":{"udp.srcport":["5060"],"udp.dstport":["5060"]},"sip":{"sip.Call-ID":["c-invonly"],"sip.Method":["INVITE"]}}}}
	]`
	repRaw := ExtractAndAnalyzeCallTracking(rawLayerJSON)
	if repRaw.Analysis.ErrorTerminations != 1 || repRaw.Analysis.ByeOnlyCalls != 1 || repRaw.Analysis.InviteOnlyCalls != 2 {
		t.Fatalf("unexpected raw call tracking report: %+v", repRaw.Analysis)
	}

	// Overlap dialing: DTMF, function, special, NOTIFY, progressive INVITEs, re-INVITE, INFO.
	overlapJSON := `{"sip_packets":[
		{"packet_num":1,"call_id":"ov-1","method":"INVITE","request_uri":"sip:123overlap@pbx","time":"0.1","packet_data":"INVITE sip:123@pbx SIP/2.0\r\nSignal=F1\r\nHOLD"},
		{"packet_num":2,"call_id":"ov-1","method":"INVITE","request_uri":"sip:123overlap4@pbx","time":"0.2"},
		{"packet_num":3,"call_id":"ov-1","method":"INFO","request_uri":"sip:123overlap45@pbx","time":"0.3","packet_data":"Signal=5"},
		{"packet_num":4,"call_id":"ov-1","method":"NOTIFY","request_uri":"sip:123overlap456@pbx","time":"0.4","packet_data":"NOTIFY digitkey=6"}
	]}`
	dk := ExtractDigitKeysFromSIPData(overlapJSON)
	if !dk.OverlapDialingDetected || dk.CallSetupMethod != "overlap" || dk.TotalEvents < 4 {
		t.Fatalf("unexpected digit extraction: %+v", dk)
	}
	ov := DetectOverlapDialing(overlapJSON)
	if !ov.OverlapDetected || ov.OverlapCallsCount != 1 {
		t.Fatalf("expected overlap detected: %+v", ov)
	}
	if ovBytes, err := json.Marshal(ov); err != nil || !strings.Contains(string(ovBytes), `"first_invite_packet":1`) {
		t.Fatalf("expected populated OverlapTimingAnalysis JSON, got %s err=%v", ovBytes, err)
	}
	if emptyOv := DetectOverlapDialing(`{"sip_packets":[]}`); emptyOv.OverlapDetected || emptyOv.Reason != "No SIP packets found" {
		t.Fatalf("unexpected empty overlap result: %+v", emptyOv)
	}
	if badOv := DetectOverlapDialing("not-json"); badOv.Reason == "" {
		t.Fatalf("expected error reason for invalid JSON")
	}

	// Codecs, SDP media lines, and endpoints.
	sdpInfo := AnalyzeSDPMediaLine("m=audio 49198 RTP/AVP 0 8 96 101 50")
	if !sdpInfo.DTMFSupport || len(sdpInfo.AudioCodecs) != 2 || len(sdpInfo.DynamicPayloads) != 1 {
		t.Fatalf("unexpected SDP media analysis: %+v", sdpInfo)
	}
	if !strings.Contains(EnrichSIPDataWithCodecContext("{}"), "CODEC ANALYSIS CONTEXT") {
		t.Fatal("missing codec context enrichment banner")
	}
	if GetCodecAnalysisContext("g711a", "96").PayloadTypeNote == "" || !strings.Contains(GetCodecAnalysisContext("custom", "99").CodecName, "Unknown Codec") {
		t.Fatal("codec context alias or unknown fallback failed")
	}
	if ExtractCodecDirectly(`[{"rtp.p_type":"0"}]`) != "G.711 μ-law (PCMU)" || ExtractCodecDirectly(`pcma text`) != "G.711 A-law (PCMA)" || ExtractCodecDirectly("plain") != "Unknown" {
		t.Fatal("ExtractCodecDirectly mismatch")
	}
	eps := AnalyzeEndpoints([]extract.SIPPacket{
		{SrcIP: "10.0.0.1", Method: "INVITE", FromAddr: "sip:a@10.0.0.1", UserAgent: "Caller", SDPMedia: "audio 4000 RTP/AVP 0 101"},
		{SrcIP: "10.0.0.2", StatusCode: "200"},
		{SrcIP: "10.0.0.3", StatusCode: "401"},
		{SrcIP: "10.0.0.4", Method: "REGISTER"},
	}, &extract.AuthInfo{AuthChallenges: []extract.AuthChallenge{{ToIP: "10.0.0.4", Realm: "example.com"}}})
	if eps["10.0.0.1"].Role != "caller" || eps["10.0.0.2"].Role != "callee" || eps["10.0.0.3"].Role != "sip_server" || eps["10.0.0.4"].AuthRealms[0] != "example.com" {
		t.Fatalf("unexpected endpoint roles: %+v", eps)
	}

	// QuickQualityCheck & EvaluateNetorchSIP error and edge paths.
	repoRoot, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	t.Chdir(repoRoot)
	if q := QuickQualityCheck(ctx, "/nonexistent/missing.pcap"); q.Status != "error" || !strings.Contains(q.Error, "File not found") {
		t.Fatalf("unexpected missing-file quick check: %+v", q)
	}
	icmpPath := filepath.Join("tests", "fixtures", "icmp_loss.pcap")
	if q := QuickQualityCheck(ctx, icmpPath); q.Status != "success" || q.QualityAnalysis == nil {
		t.Fatalf("unexpected empty-SIP pcap quick check: %+v", q)
	}
	if s := EvaluateNetorchSIP(ctx, icmpPath, false, true); s.Present || s.Note != "no SIP in this capture" {
		t.Fatalf("unexpected EvaluateNetorchSIP without SIP: %+v", s)
	}
	if s := EvaluateNetorchSIP(ctx, icmpPath, true, false); !s.Present || s.Note != "SIP present; set include_sip to run the SIP quality path" {
		t.Fatalf("unexpected EvaluateNetorchSIP disabled: %+v", s)
	}
	if s := EvaluateNetorchSIP(ctx, "/nonexistent/missing.pcap", true, true); !s.Present || s.Error == "" {
		t.Fatalf("expected error from EvaluateNetorchSIP on missing file: %+v", s)
	}
	if q := QuickQualityCheck(ctx, ""); q.Status != "error" || q.Error != "File not found: " {
		t.Fatalf("expected empty-path error, got %+v", q)
	}
	if m := AnalyzeRTPStreamsFromSummary([]extract.RTPStreamSummary{{SSRC: "0xdead", PayloadType: "0", PacketCount: 40}}); len(m.Streams) != 1 || m.Streams[0].PacketsSent != 40 {
		t.Fatalf("unexpected AnalyzeRTPStreamsFromSummary result: %+v", m)
	}
}
