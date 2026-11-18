package extract

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/zombat/sonic/internal/parity"
)

// useEasternTime runs the test in America/New_York, the zone the SIP golden's
// local timestamps were written in, so the golden does not depend on the
// machine's own zone (CI runs in UTC).
func useEasternTime(t *testing.T) {
	t.Helper()
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load America/New_York: %v", err)
	}
	prev := time.Local
	time.Local = loc
	// tshark renders frame.time in its own zone from TZ, and the child inherits it.
	prevTZ, hadTZ := os.LookupEnv("TZ")
	if err := os.Setenv("TZ", "America/New_York"); err != nil {
		t.Fatalf("set TZ: %v", err)
	}
	t.Cleanup(func() {
		time.Local = prev
		if hadTZ {
			_ = os.Setenv("TZ", prevTZ)
		} else {
			_ = os.Unsetenv("TZ")
		}
	})
}

func buildSyntheticSIPAuthPCAP(t *testing.T, outPath string) (secrets []string) {
	t.Helper()
	digestResp := "6629fae49393a05397450978507c4ef1"
	nonce := "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	basicPass := "not-a-real-password"
	basicCred := base64.StdEncoding.EncodeToString([]byte("bob:" + basicPass))
	srtpKey := "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
	mikeyPayload := "AQAFgM0XflABAAAAAAAAAAAAAAsAyOOh4RqXbQ"
	sdpKKey := "not-a-real-sdp-key"
	secrets = []string{digestResp, basicCred, basicPass, srtpKey, mikeyPayload, sdpKKey}

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
		"v=0",
		"o=alice 2890844526 2890844526 IN IP4 192.0.2.10",
		"s=call",
		"c=IN IP4 192.0.2.10",
		"t=0 0",
		"k=clear:" + sdpKKey,
		"m=audio 49170 RTP/SAVP 0",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + srtpKey + "|2^20|1:4",
		"a=key-mgmt:mikey " + mikeyPayload,
		"",
	}, "\r\n")
	inviteSDP := "INVITE sip:dave@example.com SIP/2.0\r\n" +
		strings.TrimSuffix(common("INVITE", 1, "inv-2@192.0.2.10"), "Content-Length: 0") +
		"Content-Type: application/sdp\r\nContent-Length: " +
		strings.TrimSpace(string(rune('0'+len(sdp)/100))) // placeholder fixed below
	_ = inviteSDP
	invHead := []string{
		"INVITE sip:dave@example.com SIP/2.0",
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1",
		"From: <sip:alice@example.com>;tag=1928301774",
		"To: <sip:alice@example.com>",
		"Call-ID: inv-2@192.0.2.10",
		"CSeq: 1 INVITE",
		"Max-Forwards: 70",
		"Content-Type: application/sdp",
	}
	invWithSDP := strings.Join(append(invHead, "Content-Length: "+itoa(len(sdp))), "\r\n") + "\r\n\r\n" + sdp

	msgs := []struct {
		src, dst, body string
	}{
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
		ipPkt := transportIPPacket(m.src, m.dst, 17, wrapUDP5060([]byte(m.body)))
		var eth [14]byte
		eth[5] = 0x02
		eth[11] = 0x01
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

func wrapUDP5060(payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(out[0:2], 5060)
	binary.BigEndian.PutUint16(out[2:4], 5060)
	binary.BigEndian.PutUint16(out[4:6], uint16(8+len(payload)))
	copy(out[8:], payload)
	return out
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

func TestSIPMaskingExtractionAndGoldenParity(t *testing.T) {
	useEasternTime(t)
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	// Unit tests matching test_sip_credentials.py masking assertions.
	digestResp := "6629fae49393a05397450978507c4ef1"
	nonce := "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	hdr := `Digest username="alice", realm="example.com", nonce="` + nonce + `", uri="sip:example.com", response="` + digestResp + `", algorithm=MD5, qop=auth, nc=00000001, cnonce="0a4f113b"`
	masked := MaskSIPCredentials(hdr)
	if strings.Contains(masked, digestResp) || !strings.Contains(masked, `response="[MASKED]"`) || !strings.Contains(masked, `username="alice"`) {
		t.Fatalf("unexpected Digest masking: %q", masked)
	}
	if MaskSIPCredentials("Basic Ym9iOnNlY3JldA==") != "Basic [MASKED]" ||
		MaskSIPCredentials("Bearer abc.def.ghi") != "Bearer [MASKED]" ||
		MaskSIPCredentials("NTLM TlRMTVNTUAAB") != "NTLM [MASKED]" {
		t.Fatal("Basic/Bearer/NTLM scheme masking mismatch")
	}
	unquoted := MaskSIPCredentials(`Digest username="a",response=` + digestResp + `,auts="AKAresync"`)
	if strings.Contains(unquoted, digestResp) || strings.Contains(unquoted, "AKAresync") {
		t.Fatalf("unquoted response/auts leaked: %q", unquoted)
	}

	rawInvite := "INVITE sip:d@e SIP/2.0\r\nAuthorization: Basic c2VjcmV0\r\nk=clear:sdpk\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7|2^20\r\na=key-mgmt:mikey AQAFgM0XflABAAAA\r\n"
	maskedText := MaskSIPText(rawInvite)
	for _, secret := range []string{"c2VjcmV0", "sdpk", "WVNfX19zZW1jdGwg", "AQAFgM0XflABAAAA"} {
		if strings.Contains(maskedText, secret) {
			t.Fatalf("MaskSIPText leaked secret %q in %q", secret, maskedText)
		}
	}

	// Live tshark + golden parity on sip_minimal.pcap.
	ctx := context.Background()
	sipMinPath := filepath.Join("testdata", "fixtures", "sip_minimal.pcap")
	sumMin, rawMin, err := ExtractSIPData(ctx, sipMinPath)
	if err != nil || sumMin == nil || rawMin == "" {
		t.Fatalf("ExtractSIPData(sip_minimal) failed: sum=%v err=%v", sumMin, err)
	}
	parity.CompareGolden(t, sumMin, filepath.Join("testdata", "golden", "sip", "sip_minimal_extract.json"))
	authMin := ExtractAuthAndRegistrationInfo(ctx, sipMinPath)
	parity.CompareGolden(t, authMin, filepath.Join("testdata", "golden", "sip", "sip_minimal_auth.json"))

	// Synthetic SIP auth capture matching test_sip_credentials.py + golden parity + zero secret leak.
	authPcap := filepath.Join(t.TempDir(), "sip_auth.pcap")
	secrets := buildSyntheticSIPAuthPCAP(t, authPcap)
	sumAuth, rawAuth, err := ExtractSIPData(ctx, authPcap)
	if err != nil || sumAuth == nil {
		t.Fatalf("ExtractSIPData(auth) failed: %v", err)
	}
	for _, sec := range secrets {
		if strings.Contains(rawAuth, sec) {
			t.Fatalf("secret %q leaked in SIP extraction JSON", sec)
		}
	}
	parity.CompareGolden(t, sumAuth, filepath.Join("testdata", "golden", "sip", "sip_auth_extract.json"))
	authInfo := ExtractAuthAndRegistrationInfo(ctx, authPcap)
	authBytes, _ := json.Marshal(authInfo)
	for _, sec := range secrets {
		if strings.Contains(string(authBytes), sec) {
			t.Fatalf("secret %q leaked in AuthInfo JSON", sec)
		}
	}
	parity.CompareGolden(t, authInfo, filepath.Join("testdata", "golden", "sip", "sip_auth_info.json"))

	// Fallback raw PCAP scan masks Authorization & SDP keys directly without tshark.
	rawFallback, err := readSIPRawPCAP(authPcap)
	if err != nil || !strings.Contains(rawFallback, "Authorization: Digest") || !strings.Contains(rawFallback, "AES_CM_128_HMAC_SHA1_80 inline:[MASKED]") {
		t.Fatalf("raw PCAP SIP fallback mismatch: err=%v len=%d", err, len(rawFallback))
	}
	for _, sec := range secrets {
		if strings.Contains(rawFallback, sec) {
			t.Fatalf("secret %q leaked in raw PCAP SIP fallback", sec)
		}
	}

	// Posture & upgrade recommendation coverage.
	emptyPosture := CalculateAuthSecurityPosture(emptyAuthInfo())
	if emptyPosture.Grade != "N/A" {
		t.Fatalf("unexpected empty posture: %+v", emptyPosture)
	}
	riskyAuth := AuthInfo{
		AuthChallenges: []AuthChallenge{
			{StatusCode: "401", Algorithm: "MD5", Stale: true},
			{StatusCode: "407", Algorithm: "MD5"},
			{StatusCode: "407", Algorithm: ""},
			{StatusCode: "407", Algorithm: "SHA-256", QoP: "auth-int"},
			{StatusCode: "401", Algorithm: "SHA-512", QoP: "auth"},
			{StatusCode: "401", Algorithm: "MD5"},
		},
		RegisterAttempts: []RegisterAttempt{{CallID: "c1", Success: false}},
	}
	posture := CalculateAuthSecurityPosture(riskyAuth)
	recs := GenerateAuthUpgradeRecommendations(riskyAuth)
	if posture.Score >= 60 || len(recs) < 4 {
		t.Fatalf("expected degraded posture and multiple recommendations, got score=%d recs=%d", posture.Score, len(recs))
	}

	// Cover RTP aggregation in buildSIPSummary via synthetic tshark layer map.
	rtpSum := buildSIPSummary(2, func(yield func(map[string][]string)) {
		yield(map[string][]string{"frame.number": {"1"}, "ip.src": {"10.0.0.1"}, "ip.dst": {"10.0.0.2"}, "udp.srcport": {"10000"}, "udp.dstport": {"10002"}, "rtp.ssrc": {"0x1234"}, "rtp.p_type": {"0"}})
		yield(map[string][]string{"frame.number": {"2"}, "ip.src": {"10.0.0.1"}, "ip.dst": {"10.0.0.2"}, "udp.srcport": {"10000"}, "udp.dstport": {"10002"}, "rtp.ssrc": {"0x1234"}, "rtp.p_type": {"0"}})
	})
	if rtpSum.RTPStreamCount != 1 || rtpSum.RTPStreams[0].PacketCount != 2 {
		t.Fatalf("unexpected RTP stream aggregation: %+v", rtpSum)
	}
}

func TestSIPAuthAnomaliesPostureAndEdgeCases(t *testing.T) {
	ctx := context.Background()

	// MaskSIPCredentials edge cases: empty string, escaped quote, plain Digest without secret params.
	if MaskSIPCredentials("") != "" || MaskSIPText("") != "" {
		t.Fatal("empty masking must return empty string")
	}
	escaped := MaskSIPCredentials(`Digest username="a", response="abc\"def", realm="x"`)
	if strings.Contains(escaped, "abc") || !strings.Contains(escaped, `realm="x"`) {
		t.Fatalf("escaped quote digest masking failed: %q", escaped)
	}
	if _, _, err := ExtractSIPData(ctx, "/nonexistent/missing.pcap"); err == nil {
		t.Fatal("expected error for missing file")
	}
	badFile := filepath.Join(t.TempDir(), "notpcap.bin")
	if err := os.WriteFile(badFile, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := readSIPRawPCAP(badFile); err != nil || out != "" {
		t.Fatalf("expected empty non-pcap raw output, got out=%q err=%v", out, err)
	}
	badMagic := filepath.Join(t.TempDir(), "badmagic.bin")
	if err := os.WriteFile(badMagic, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := readSIPRawPCAP(badMagic); err != nil || out != "" {
		t.Fatalf("expected empty bad-magic raw output, got out=%q err=%v", out, err)
	}
	if _, err := readSIPRawPCAP("/nonexistent/missing.pcap"); err == nil {
		t.Fatal("expected error reading missing raw file")
	}

	// Empty packet extraction returns empty JSON packets cleanly.
	if info := ExtractAuthAndRegistrationInfo(ctx, "/nonexistent/missing.pcap"); len(info.AuthChallenges) != 0 {
		t.Fatalf("expected empty AuthInfo on error, got %+v", info)
	}
	// Invalid JSON passed to ExtractAuthFromPackets fallback via Parse* helpers.
	if s, r, d, n, op, al, q, st := ParseAuthenticationHeader("invalidheader"); s != "" || r != "" || d != "" || n != "" || op != "" || al != "MD5" || q != "" || st {
		t.Fatalf("unexpected ParseAuthenticationHeader on malformed input: %s", s)
	}
	if s, u, r, n, ur, rs, op, al, q, nc, cn := ParseAuthorizationHeader("invalid"); s != "" || u != "" || r != "" || n != "" || ur != "" || rs != "" || op != "" || al != "MD5" || q != "" || nc != "" || cn != "" {
		t.Fatalf("unexpected ParseAuthorizationHeader on malformed input: %s", s)
	}
	if _, r, _, _, _, _, _, _ := ParseAuthenticationHeader(""); r != "" {
		t.Fatal("expected empty parse result for empty auth header")
	}
	if _, u, _, _, _, _, _, _, _, _, _ := ParseAuthorizationHeader(""); u != "" {
		t.Fatal("expected empty parse result for empty authorization header")
	}

	// Exercise 407 proxy challenge, domain/opaque/stale, and posture/anomaly branches.
	pkts := []SIPPacket{
		{PacketNum: 1, Time: "1.0", Method: "REGISTER", CallID: "reg-a", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Expires: "3600"},
		{PacketNum: 2, Time: "1.1", StatusCode: "401", CallID: "reg-a", SrcIP: "10.0.0.2", DstIP: "10.0.0.1"},
		{PacketNum: 3, Time: "1.2", StatusCode: "407", CallID: "reg-a", SrcIP: "10.0.0.2", DstIP: "10.0.0.1",
			ProxyAuthenticate: `Digest realm="proxy.com", domain="sip:proxy.com", nonce="n1", opaque="op1", algorithm=SHA-256, qop="auth-int", stale=true`},
		{PacketNum: 4, Time: "1.3", StatusCode: "407", CallID: "reg-a", SrcIP: "10.0.0.2", DstIP: "10.0.0.1",
			ProxyAuthenticate: `Digest realm="proxy.com", nonce="n2", algorithm=SHA-256, qop="auth"`},
		{PacketNum: 5, Time: "1.4", StatusCode: "407", CallID: "reg-a", SrcIP: "10.0.0.2", DstIP: "10.0.0.1",
			ProxyAuthenticate: `Digest realm="proxy.com", nonce="n3", algorithm=MD5`},
		{PacketNum: 6, Time: "1.5", StatusCode: "401", CallID: "reg-b", SrcIP: "10.0.0.3", DstIP: "10.0.0.1",
			WWWAuthenticate: `Digest realm="srv.com", nonce="n4"`},
		{PacketNum: 7, Time: "1.6", Method: "REGISTER", CallID: "reg-a", SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			ProxyAuthorization: `Digest username="u", realm="proxy.com", nonce="n1", uri="sip:p", response="[MASKED]", algorithm=SHA-256, qop=auth-int, nc=00000001, cnonce="1234"`},
		{PacketNum: 8, Time: "1.7", StatusCode: "403", CallID: "reg-a", SrcIP: "10.0.0.2", DstIP: "10.0.0.1"},
	}
	derived := ExtractAuthFromPackets(pkts)
	if len(derived.AuthChallenges) != 4 || len(derived.AuthAnomalies) < 5 {
		t.Fatalf("unexpected derived challenges=%d anomalies=%v", len(derived.AuthChallenges), derived.AuthAnomalies)
	}
	if derived.AuthResponses[0].CNonce != "1234..." || !derived.AuthResponses[0].IsProxy {
		t.Fatalf("unexpected AuthResponse fields: %+v", derived.AuthResponses[0])
	}

	// Strong posture yields A+.
	strongAuth := AuthInfo{
		AuthChallenges: []AuthChallenge{
			{StatusCode: "401", Algorithm: "SHA-256", QoP: "auth-int"},
		},
		AuthResponses:    []AuthResponse{{PacketNum: 2, Algorithm: "SHA-256"}},
		RegisterAttempts: []RegisterAttempt{{CallID: "c1", Success: true, Authenticated: true}},
	}
	strongPosture := CalculateAuthSecurityPosture(strongAuth)
	if strongPosture.Grade != "A+" || strongPosture.Score != 100 {
		t.Fatalf("expected A+ (100), got %+v", strongPosture)
	}
	// qop=auth variant without auth-int and fewer responses than challenges.
	partialAuth := AuthInfo{
		AuthChallenges: []AuthChallenge{
			{StatusCode: "401", Algorithm: "SHA-512", QoP: "auth"},
			{StatusCode: "401", Algorithm: "SHA-512", QoP: "auth"},
		},
		AuthResponses: []AuthResponse{{PacketNum: 3}},
	}
	if p := CalculateAuthSecurityPosture(partialAuth); p.Score != 95 {
		t.Fatalf("expected score 95, got %+v", p)
	}
}
