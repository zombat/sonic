package tlsinspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestSuitesClassificationAndNormalization(t *testing.T) {
	t.Parallel()

	cases := []struct {
		code    uint16
		want    EncState
		hasNote bool
	}{
		{0x1301, StateEncrypted, false},
		{0xC02F, StateEncrypted, false},
		{0x00FF, StateUnverified, true},
		{0x5600, StateUnverified, true},
		{0xC0B4, StateCleartext, true},
		{0x0000, StateCleartext, true},
		{0x003B, StateCleartext, true},
		{0x0003, StateCleartext, true},
		{0x00A6, StateCleartext, true},
		{0x0005, StateWeak, true},
		{0xBEEF, StateUnverified, true},
	}
	for _, tc := range cases {
		got, note := SuiteEncryption(tc.code)
		if got != tc.want {
			t.Fatalf("SuiteEncryption(0x%04x) = %v, want %v", tc.code, got, tc.want)
		}
		if (note != "") != tc.hasNote {
			t.Fatalf("SuiteEncryption(0x%04x) note=%q, want hasNote=%v", tc.code, note, tc.hasNote)
		}
	}

	if !IsGrease(0x0A0A) || !IsGrease(0x9A9A) || IsGrease(0x1301) {
		t.Fatal("IsGrease mismatch")
	}
	if !SuiteHasForwardSecrecy("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") ||
		!SuiteHasForwardSecrecy("TLS_AES_128_GCM_SHA256") ||
		SuiteHasForwardSecrecy("TLS_RSA_WITH_AES_128_CBC_SHA") {
		t.Fatal("SuiteHasForwardSecrecy mismatch")
	}
	if !VersionIsWeak("SSL3.0") || !VersionIsWeak("TLS1.0") || !VersionIsWeak("TLS1.1") ||
		VersionIsWeak("TLS1.2") || VersionIsWeak("TLS1.3") {
		t.Fatal("VersionIsWeak mismatch")
	}
	if v, ok := NormalizeVersion("TLSv1.3"); !ok || v != "TLS1.3" {
		t.Fatalf("NormalizeVersion(TLSv1.3) = (%q, %v)", v, ok)
	}
	if v, ok := NormalizeVersion("1.2"); !ok || v != "TLS1.2" {
		t.Fatalf("NormalizeVersion(1.2) = (%q, %v)", v, ok)
	}
	if v, ok := NormalizeVersion("SSLv3"); !ok || v != "SSL3.0" {
		t.Fatalf("NormalizeVersion(SSLv3) = (%q, %v)", v, ok)
	}
	if _, ok := NormalizeVersion("bogus"); ok {
		t.Fatal("expected bogus version false")
	}
	if NormalizeSuite("0x1302") != "TLS_AES_256_GCM_SHA384" {
		t.Fatalf("NormalizeSuite(0x1302) = %q", NormalizeSuite("0x1302"))
	}
	if NormalizeSuite("tls_aes_128_gcm_sha256") != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("NormalizeSuite(lowercase) mismatch")
	}
	if StateNotStarted.String() != "not_started" || EncState(99).String() != "unverified" {
		t.Fatal("EncState.String mismatch")
	}
}

func TestParseClientAndServerHello(t *testing.T) {
	t.Parallel()

	// Build a minimal ClientHello with SNI, supported_versions (TLS1.3 + GREASE), ALPN, groups, key_share, ECH.
	buildExt := func(typ uint16, body []byte) []byte {
		out := make([]byte, 4+len(body))
		binary.BigEndian.PutUint16(out[0:2], typ)
		binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
		copy(out[4:], body)
		return out
	}

	sniHost := []byte("api.example.com")
	sniExtBody := make([]byte, 5+len(sniHost))
	binary.BigEndian.PutUint16(sniExtBody[0:2], uint16(3+len(sniHost)))
	sniExtBody[2] = 0
	binary.BigEndian.PutUint16(sniExtBody[3:5], uint16(len(sniHost)))
	copy(sniExtBody[5:], sniHost)

	var exts []byte
	exts = append(exts, buildExt(0, sniExtBody)...)
	exts = append(exts, buildExt(43, []byte{4, 0x0a, 0x0a, 0x03, 0x04})...)
	exts = append(exts, buildExt(16, []byte{0, 3, 2, 'h', '2'})...)
	exts = append(exts, buildExt(10, []byte{0, 4, 0x0a, 0x0a, 0x00, 0x1d})...)
	exts = append(exts, buildExt(51, []byte{0, 6, 0x00, 0x1d, 0, 2, 1, 2})...)
	exts = append(exts, buildExt(0xFE0D, []byte{1})...)

	var ch []byte
	ch = append(ch, 0x03, 0x03)                   // legacy TLS 1.2
	ch = append(ch, make([]byte, 32)...)          // random
	ch = append(ch, 0)                            // session id len
	ch = append(ch, 0, 4, 0x1a, 0x1a, 0x13, 0x01) // GREASE + TLS_AES_128_GCM_SHA256
	ch = append(ch, 1, 0)                         // compression methods
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(exts)))
	ch = append(ch, extLen...)
	ch = append(ch, exts...)

	parsedCH := ParseClientHello(ch)
	if parsedCH == nil || parsedCH.SNI == nil || *parsedCH.SNI != "api.example.com" {
		t.Fatalf("ParseClientHello SNI mismatch: %+v", parsedCH)
	}
	if !parsedCH.ECHOffered || len(parsedCH.Versions) != 1 || parsedCH.Versions[0] != "TLS1.3" {
		t.Fatalf("ParseClientHello versions/ECH mismatch: %+v", parsedCH)
	}
	if len(parsedCH.CipherSuites) != 1 || parsedCH.CipherSuites[0] != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("ParseClientHello suites mismatch: %+v", parsedCH)
	}
	if len(parsedCH.ALPN) != 1 || parsedCH.ALPN[0] != "h2" {
		t.Fatalf("ParseClientHello ALPN mismatch: %+v", parsedCH)
	}
	if len(parsedCH.Groups) != 1 || parsedCH.Groups[0] != "x25519" {
		t.Fatalf("ParseClientHello groups mismatch: %+v", parsedCH)
	}

	// Build a ServerHello choosing TLS 1.3 + x25519 + HRR random.
	var shExts []byte
	shExts = append(shExts, buildExt(43, []byte{0x03, 0x04})...)
	shExts = append(shExts, buildExt(16, []byte{0, 3, 2, 'h', '2'})...)
	shExts = append(shExts, buildExt(51, []byte{0x00, 0x1d, 0, 0})...)

	var sh []byte
	sh = append(sh, 0x03, 0x03)
	sh = append(sh, HRRRandom...)
	sh = append(sh, 0)
	sh = append(sh, 0x13, 0x02, 0) // TLS_AES_256_GCM_SHA384 + comp 0
	shExtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(shExtLen, uint16(len(shExts)))
	sh = append(sh, shExtLen...)
	sh = append(sh, shExts...)

	suite, ok := ServerHelloSuite(sh)
	if !ok || suite != 0x1302 {
		t.Fatalf("ServerHelloSuite = (0x%04x, %v), want (0x1302, true)", suite, ok)
	}
	parsedSH := ParseServerHello(sh)
	if parsedSH == nil || parsedSH.Version != "TLS1.3" || parsedSH.CipherSuite != "TLS_AES_256_GCM_SHA384" || !parsedSH.HelloRetryRequest {
		t.Fatalf("ParseServerHello mismatch: %+v", parsedSH)
	}
	if parsedSH.ALPN == nil || *parsedSH.ALPN != "h2" || parsedSH.KeyShareGroup == nil || *parsedSH.KeyShareGroup != "x25519" {
		t.Fatalf("ParseServerHello extensions mismatch: %+v", parsedSH)
	}

	if ParseClientHello([]byte{1, 2, 3}) != nil || ParseServerHello([]byte{1, 2, 3}) != nil {
		t.Fatal("short hello bodies should return nil")
	}
	if _, ok := ServerHelloSuite([]byte{1, 2}); ok {
		t.Fatal("short ServerHelloSuite should fail")
	}
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add([]byte{0x03, 0x03})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseClientHello(data)
	})
}

func FuzzParseServerHello(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add([]byte{0x03, 0x03})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseServerHello(data)
		_, _ = ServerHelloSuite(data)
	})
}

func FuzzParseCertificate(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 5, 0, 0, 2, 0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseCertificate(data, 1767225600.0)
	})
}

func TestGoldenTLSInspectParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	cases := []struct {
		name     string
		pcap     string
		golden   string
		baseline *Baseline
	}{
		{name: "dp_tls", pcap: "dp_tls", golden: "dp_tls", baseline: nil},
		{name: "dp_tls_baseline_tls13", pcap: "dp_tls", golden: "dp_tls_baseline_tls13", baseline: &Baseline{Versions: []string{"TLS1.3"}}},
		{name: "enc_tls10", pcap: "enc_tls10", golden: "enc_tls10", baseline: nil},
		{name: "enc_tls12_null", pcap: "enc_tls12_null", golden: "enc_tls12_null", baseline: nil},
		{name: "enc_tls13_integrity_only", pcap: "enc_tls13_integrity_only", golden: "enc_tls13_integrity_only", baseline: nil},
		{name: "grpc_tls12_alert", pcap: "grpc_tls12_alert", golden: "grpc_tls12_alert", baseline: nil},
		{name: "grpc_tls13_hrr", pcap: "grpc_tls13_hrr", golden: "grpc_tls13_hrr", baseline: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", tc.pcap+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewDetector(tc.baseline)
			var startPtr, endPtr *float64
			for i := range out.Records {
				rec := &out.Records[i]
				if rec.T != 0 {
					tv := rec.T
					if startPtr == nil || tv < *startPtr {
						v := tv
						startPtr = &v
					}
					if endPtr == nil || tv > *endPtr {
						v := tv
						endPtr = &v
					}
				}
				det.Feed(rec)
			}
			got := det.Report(model.Context{Start: startPtr, End: endPtr, MaxItems: 25})
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "tls", tc.golden+".json"))
		})
	}
}

func TestTLSInspectEdgeCasesBaselinesAndReassembly(t *testing.T) {
	t.Parallel()

	empty := NewDetector(nil).Report(model.Context{MaxItems: 25})
	if empty.Status != model.StatusNotPresent || empty.Verdict != "No TLS handshake in this capture." {
		t.Fatalf("unexpected empty report: %+v", empty)
	}

	intp := func(v int) *int { return &v }
	boolp := func(b bool) *bool { return &b }
	sport, dport := 45000, 443

	// Non-TLS TCP payload gets ignored.
	det := NewDetector(&Baseline{
		MinVersion:            "TLS1.3",
		CipherSuites:          []string{"0x1301"},
		RequireSNI:            boolp(true),
		ALPN:                  []string{"h2"},
		RequireForwardSecrecy: boolp(true),
		ForbidWeakOffers:      boolp(true),
	})
	det.Feed(&model.Record{
		N: 1, T: 1.0,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sport, Dport: &dport, Flags: 24, Len: 4},
		DP:  &model.DataPlane{HL: 20, TL: 44, PL: "47455420", TCP: &model.DPTCP{Seq: 1}},
	})

	// Split ClientHello across two out-of-order TCP segments + ClientHello with no ServerHello + unknown alert.
	chBody := []byte{
		0x03, 0x03,
	}
	chBody = append(chBody, make([]byte, 32)...)
	chBody = append(chBody, 0)                            // session id
	chBody = append(chBody, 0, 4, 0x00, 0x2f, 0x00, 0x05) // AES128-CBC-SHA + RC4-SHA (no FS, weak)
	chBody = append(chBody, 1, 0)                         // compression
	chBody = append(chBody, 0, 0)                         // empty extensions (no SNI)
	chMsg := make([]byte, 4+len(chBody))
	chMsg[0] = 1
	chMsg[1] = byte(len(chBody) >> 16)
	chMsg[2] = byte(len(chBody) >> 8)
	chMsg[3] = byte(len(chBody))
	copy(chMsg[4:], chBody)
	rec1 := make([]byte, 5+len(chMsg))
	rec1[0], rec1[1], rec1[2] = 22, 3, 1
	binary.BigEndian.PutUint16(rec1[3:5], uint16(len(chMsg)))
	copy(rec1[5:], chMsg)

	// Feed second half first (out-of-order), then first half.
	split := len(rec1) / 2
	det.Feed(&model.Record{
		N: 2, T: 1.1,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sport, Dport: &dport, Flags: 24, Len: len(rec1) - split},
		DP:  &model.DataPlane{HL: 20, TL: 40 + len(rec1) - split, PL: hex.EncodeToString(rec1[split:]), TCP: &model.DPTCP{Seq: 100 + uint32(split)}},
	})
	det.Feed(&model.Record{
		N: 3, T: 1.05,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sport, Dport: &dport, Flags: 24, Len: split},
		DP:  &model.DataPlane{HL: 20, TL: 40 + split, PL: hex.EncodeToString(rec1[:split]), TCP: &model.DPTCP{Seq: 100}},
	})
	// Note: reassembled out-of-order with first segment arriving second (rel < 0 check ignored; re-seed from base at seq 100).
	det2 := NewDetector(&Baseline{
		MinVersion:            "TLS1.3",
		CipherSuites:          []string{"0x1301"},
		RequireSNI:            boolp(true),
		ALPN:                  []string{"h2"},
		RequireForwardSecrecy: boolp(true),
		ForbidWeakOffers:      boolp(true),
	})
	sport2 := 45001
	// Unanswered ClientHello triggers TLS_NO_SERVER_HELLO + no-SNI + weak offer warning.
	det2.Feed(&model.Record{
		N: 4, T: 2.0,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sport2, Dport: &dport, Flags: 24, Len: len(rec1)},
		DP:  &model.DataPlane{HL: 20, TL: 40 + len(rec1), PL: hex.EncodeToString(rec1), TCP: &model.DPTCP{Seq: 100}},
	})

	// Second session with ServerHello choosing TLS1.2 + static RSA AES128 + no ALPN + ServerHelloDone + CCS + encrypted alert.
	sport3 := 45002
	det2.Feed(&model.Record{
		N: 5, T: 3.0,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sport3, Dport: &dport, Flags: 24, Len: len(rec1)},
		DP:  &model.DataPlane{HL: 20, TL: 40 + len(rec1), PL: hex.EncodeToString(rec1), TCP: &model.DPTCP{Seq: 100}},
	})
	shBody := make([]byte, 38)
	shBody[0], shBody[1] = 0x03, 0x03
	shBody[35], shBody[36] = 0x00, 0x2f // TLS_RSA_WITH_AES_128_CBC_SHA
	shMsg := make([]byte, 4+len(shBody))
	shMsg[0] = 2
	shMsg[3] = byte(len(shBody))
	copy(shMsg[4:], shBody)
	ccsAndEncryptedAlert := []byte{
		22, 3, 3, 0, byte(len(shMsg)),
	}
	ccsAndEncryptedAlert = append(ccsAndEncryptedAlert, shMsg...)
	ccsAndEncryptedAlert = append(ccsAndEncryptedAlert, 20, 3, 3, 0, 1, 1)    // CCS -> sets encrypted=true
	ccsAndEncryptedAlert = append(ccsAndEncryptedAlert, 21, 3, 3, 0, 2, 1, 0) // encrypted alert
	det2.Feed(&model.Record{
		N: 6, T: 3.1,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.2", Dst: "10.0.0.1", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &dport, Dport: &sport3, Flags: 24, Len: len(ccsAndEncryptedAlert)},
		DP:  &model.DataPlane{HL: 20, TL: 40 + len(ccsAndEncryptedAlert), PL: hex.EncodeToString(ccsAndEncryptedAlert), TCP: &model.DPTCP{Seq: 500}},
	})
	// Cleartext warning alert (unknown code 250) on another port.
	sport4 := 45003
	alertRec := []byte{21, 3, 3, 0, 2, 1, 250}
	det2.Feed(&model.Record{
		N: 7, T: 4.0,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sport4, Dport: &dport, Flags: 24, Len: len(alertRec)},
		DP:  &model.DataPlane{HL: 20, TL: 40 + len(alertRec), PL: hex.EncodeToString(alertRec), TCP: &model.DPTCP{Seq: 1}},
	})

	start := 1.0
	rep := det2.Report(model.Context{Start: &start, MaxItems: 25})
	if rep.Summary.Handshakes != 3 || rep.Summary.BaselineFailures != 1 {
		t.Fatalf("unexpected summary: %+v", rep.Summary)
	}
	if _, err := jsonMarshalRoundTrip(rep); err != nil {
		t.Fatal(err)
	}
}

func TestParseCertificateAndSANEdges(t *testing.T) {
	t.Parallel()

	if c := ParseCertificate([]byte{0, 0}, 100); !c.Visible || c.ChainLength == nil || *c.ChainLength != 0 {
		t.Fatalf("short cert msg mismatch: %+v", c)
	}
	if c := ParseCertificate([]byte{0, 0, 5, 0, 0, 2, 0x30, 0x00}, 100); c.Parsed == nil || *c.Parsed {
		t.Fatalf("bad DER cert should report parsed=false: %+v", c)
	}

	// Self-signed cert without CommonName (exercises pkix.Name.String fallback) + >20 DNS names + IP SAN.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var dns []string
	for i := 0; i < 25; i++ {
		dns = append(dns, "h.example.com")
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"S.O.N.I.C. Test"}},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     dns,
		IPAddresses:  []net.IP{net.ParseIP("192.0.2.10")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 6+len(der))
	total := 3 + len(der)
	body[0], body[1], body[2] = byte(total>>16), byte(total>>8), byte(total)
	body[3], body[4], body[5] = byte(len(der)>>16), byte(len(der)>>8), byte(len(der))
	copy(body[6:], der)

	parsed := ParseCertificate(body, float64(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Unix()))
	if parsed.Parsed == nil || !*parsed.Parsed || parsed.SelfSigned == nil || !*parsed.SelfSigned {
		t.Fatalf("valid cert mismatch: %+v", parsed)
	}
	if parsed.Subject == nil || *parsed.Subject == "" || parsed.ValidAtCaptureTime == nil || !*parsed.ValidAtCaptureTime {
		t.Fatalf("subject/validity mismatch: %+v", parsed)
	}
	if parsed.DNSNames == nil || len(*parsed.DNSNames) != 20 || parsed.IPAddresses == nil || len(*parsed.IPAddresses) != 1 {
		t.Fatalf("SAN count mismatch: %+v", parsed)
	}
	// Missing IP SAN hint triggers for another server IP.
	hints := SessionHints("192.0.2.99", nil, "TLS1.2", parsed)
	if len(hints) != 1 || hints[0].Code != "TLS_CERT_NO_IP_SAN" {
		t.Fatalf("expected TLS_CERT_NO_IP_SAN, got %+v", hints)
	}
	if ah := AlertHint("close_notify", "client"); ah != nil {
		t.Fatalf("expected nil alert hint for close_notify, got %v", *ah)
	}
}

func jsonMarshalRoundTrip(rep Report) ([]byte, error) {
	return json.Marshal(rep)
}
