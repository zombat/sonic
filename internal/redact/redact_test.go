// Package redact tests dotenv parsing, secret-shape masking, and SDP masking.
package redact

import (
	"strings"
	"testing"
)

// TestParseDotenv verifies literal parsing, quote handling, and sanitized errors.
func TestParseDotenv(t *testing.T) {
	text := "# comment\n\nexport ANTHROPIC_API_KEY='a b $HOME #x'\n" +
		"OPENAI_API_KEY=plain-value # trailing\nAZURE_OPENAI_KEY=\"q\"  # c\nIGNORED=1\n"
	got, err := ParseDotenv(text, nil, "/tmp/test.env")
	if err != nil {
		t.Fatalf("ParseDotenv failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d keys, want 3: %#v", len(got), got)
	}
	if got["ANTHROPIC_API_KEY"] != "a b $HOME #x" {
		t.Fatalf("ANTHROPIC_API_KEY = %q", got["ANTHROPIC_API_KEY"])
	}
	if got["OPENAI_API_KEY"] != "plain-value" {
		t.Fatalf("OPENAI_API_KEY = %q", got["OPENAI_API_KEY"])
	}
	if got["AZURE_OPENAI_KEY"] != "q" {
		t.Fatalf("AZURE_OPENAI_KEY = %q", got["AZURE_OPENAI_KEY"])
	}

	other, err := ParseDotenv("SECRET=x\nAWS_KEY=y\n", nil, "")
	if err != nil || len(other) != 0 {
		t.Fatalf("expected empty map for unrelated keys, got %#v, err=%v", other, err)
	}

	dummy := "sk-" + "ant-dummy-value"
	for _, bad := range []string{
		"ANTHROPIC_API_KEY=\"" + dummy + "\n",
		"not a line " + dummy + "\n",
		"ANTHROPIC_API_KEY=\"abc\" extra\n",
	} {
		_, err := ParseDotenv(bad, nil, "/x/.env")
		if err == nil {
			t.Fatalf("expected error for %q", bad)
		}
		if !strings.Contains(err.Error(), "line 1") {
			t.Fatalf("error %q missing line number", err.Error())
		}
		if strings.Contains(err.Error(), dummy) {
			t.Fatalf("error %q leaked secret value", err.Error())
		}
	}
}

// TestSecretShapesAndOrdinaryText verifies parity with test_credentials.py.
func TestSecretShapesAndOrdinaryText(t *testing.T) {
	shaped := []struct {
		name   string
		text   string
		secret string
	}{
		{"openai proj key", "error: invalid key sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWx0123 rejected", "AbCdEfGhIjKlMnOpQrStUvWx0123"},
		{"plain sk key", "OPENAI said sk-" + "0123456789abcdefABCDEF0123456789.", "0123456789abcdefABCDEF0123456789"},
		{"stripe key", "key sk_" + "live_" + "0123456789abcdefABCD", "0123456789abcdefABCD"},
		{"aws access key", "aws_access_key_id AKIA" + "IOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"},
		{"aws temp key", "creds ASIA" + "ZZZZ1234ZZZZ5678", "ZZZZ1234ZZZZ5678"},
		{"github classic", "push with ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"},
		{"github pat", "pat github_" + "pat_" + "11ABCDEFG0123456789_abcdefghijklmnop", "11ABCDEFG0123456789_abcdefghijklmnop"},
		{"slack token", "hook xox" + "b-" + "123456789012-abcdefABCDEF", "123456789012-abcdefABCDEF"},
		{"jwt", "token eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiJ0ZXN0In0." + "c2lnbmF0dXJlX2R1bW15", "zdWIiOiJ0ZXN0In0"},
		{"pem key", "file:\n-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEdummyBODY\n-----END " + "RSA PRIVATE KEY-----\nend", "MIIEdummyBODY"},
		{"pem cutoff", "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA", "b3BlbnNzaC1rZXktdjEAAAA"},
		{"auth basic", "Authorization: Basic " + "YWxpY2U6" + "aHVudGVyMg==", "YWxpY2U6aHVudGVyMg=="},
		{"auth bearer", "proxy-authorization: Bearer abc.def-ghi", "abc.def-ghi"},
		{"auth json", `{"authorization": "Bearer short1"}`, "short1"},
		{"standalone basic", "header Basic " + "Ym9iOn" + "NlY3JldA==", "Ym9iOnNlY3JldA=="},
		{"standalone bearer", "sent Bearer " + "tok" + "en0123456789abcdef", "token0123456789abcdef"},
		{"password assign", "login password=hunter2 failed", "hunter2"},
		{"secret assign", "radius secret='s3cr3t value'", "s3cr3t value"},
		{"key assign", "GET /api?key=dummyvalue42&x=1", "dummyvalue42"},
		{"dotted key", "tacplus.key=dummykey99", "dummykey99"},
		{"token assign", `client_token="abc123xyz"`, "abc123xyz"},
		{"password colon", "Password: correct-horse", "correct-horse"},
		{"password json", `{"password": "battery-staple"}`, "battery-staple"},
		{"sdp inline", "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + "WVNfX19zZW1j" + "dGwgKCkgewkyMjA7|2^20", "WVNfX19zZW1jdGwgKCkgewkyMjA7"},
		{"sdp mikey", "a=key-mgmt:mikey AQAFgM0XflABAAAAAAAAAsAyOOh", "AQAFgM0XflABAAAAAAAAAsAyOOh"},
		{"sdp k line", "s=x\nk=clear:sdpdummykey\nm=audio 4000 RTP/AVP 0", "sdpdummykey"},
	}

	for _, tc := range shaped {
		t.Run(tc.name, func(t *testing.T) {
			out := RedactText(tc.text)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret %q survived in %q", tc.secret, out)
			}
			if !strings.Contains(out, Redacted) {
				t.Fatalf("output %q missing %s", out, Redacted)
			}
		})
	}

	ordinary := []string{
		"OID 1.3.6.1.6.3.15.1.1.2.0 usmStatsUnknownUserNames, sysName.0 = 1.3.6.1.2.1.1.5.0",
		"MAC 00:1a:2b:3c:4d:5e and 00-1A-2B-3C-4D-5E, EUI-64 fe80::21a:2bff:fe3c:4d5e",
		"Authorization Basic on 10.0.0.1:52000 -> 10.0.0.2:80 in 3 request(s)",
		"Basic authentication sends the password in cleartext; use Bearer tokens over TLS instead",
		"key: 3 SAs, keys=4, monkeys ok, tacplus key present (masked), password: [REDACTED], secret=[REDACTED]",
		"frame 42: risk-free disk-0123456789abcdefghij task_id=7 password=None",
		"shown inline: yes, inline:true, k=prompt, a=crypto:1 AES_CM_128_HMAC_SHA1_80 (key masked)",
	}
	for _, text := range ordinary {
		if got := RedactText(text); got != text {
			t.Fatalf("ordinary text modified:\ngot:  %q\nwant: %q", got, text)
		}
	}

	if got := RedactText("auth failed for dummy-openai-value-0123456789", "short", "dummy-openai-value-0123456789"); got != "auth failed for [REDACTED]" {
		t.Fatalf("RedactText knownSecrets got %q", got)
	}
	if got := MaskSDPKeys("k=base64:abcdef123456", ""); got != "k=base64:[REDACTED]" {
		t.Fatalf("MaskSDPKeys default mask got %q", got)
	}
}

// FuzzParseDotenv ensures ParseDotenv never panics on arbitrary input.
func FuzzParseDotenv(f *testing.F) {
	f.Add("ANTHROPIC_API_KEY='val'\n# comment\nexport OPENAI_API_KEY=abc # c")
	f.Add("bad line")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = ParseDotenv(input, nil, "fuzz.env")
	})
}

// FuzzMaskSecretShapes ensures MaskSecretShapes never panics on arbitrary text.
func FuzzMaskSecretShapes(f *testing.F) {
	f.Add("Authorization: Basic YWxpY2U6aHVudGVyMg== password=secret -----BEGIN PRIVATE KEY-----")
	f.Add("Basic AAAAAAAA=A")
	f.Fuzz(func(t *testing.T, input string) {
		_ = MaskSecretShapes(input)
	})
}
