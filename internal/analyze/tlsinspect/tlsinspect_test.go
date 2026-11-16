package tlsinspect

import (
	"encoding/binary"
	"testing"
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
