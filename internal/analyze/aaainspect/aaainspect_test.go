package aaainspect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/parity"
)

func TestGoldenAAAParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	keysPath := filepath.Join(t.TempDir(), "keys.txt")
	const (
		tacacsKey    = "tacacs-shared-key-not-real"
		radiusSecret = "radius-shared-secret-not-real"
	)
	if err := os.WriteFile(keysPath, []byte("tacacs_key: "+tacacsKey+"\nradius_secret: "+radiusSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		pcap     string
		keysFile string
		golden   string
	}{
		{name: "radius_no_key", pcap: "aaa_radius.pcap", golden: "aaa_radius_no_key.json"},
		{name: "radius_with_key", pcap: "aaa_radius.pcap", keysFile: keysPath, golden: "aaa_radius_with_key.json"},
		{name: "tacacs_no_key", pcap: "aaa_tacacs.pcap", golden: "aaa_tacacs_no_key.json"},
		{name: "tacacs_with_key", pcap: "aaa_tacacs.pcap", keysFile: keysPath, golden: "aaa_tacacs_with_key.json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeCapture(context.Background(), filepath.Join("testdata", "fixtures", tc.pcap), Options{
				KeysFile: tc.keysFile,
			})
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "aaa", tc.golden))

			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			for _, sec := range []string{tacacsKey, radiusSecret, "user-password-not-real", "enable-password-not-real", keysPath} {
				if strings.Contains(text, sec) {
					t.Fatalf("secret %q leaked into report JSON", sec)
				}
			}
		})
	}
}

func TestReadKeysFileWrongSecretAndErrorPaths(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	tmp := t.TempDir()
	k1 := filepath.Join(tmp, "named.txt")
	if err := os.WriteFile(k1, []byte("# comment\ntacacs_key: abc\nradius_secret = \"def\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tk, rs, err := ReadKeysFile(k1)
	if err != nil || tk == nil || *tk != "abc" || rs == nil || *rs != "def" {
		t.Fatalf("ReadKeysFile(named) = (%v, %v, %v)", tk, rs, err)
	}

	k2 := filepath.Join(tmp, "bare.txt")
	if err := os.WriteFile(k2, []byte("onekey123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tk, rs, err = ReadKeysFile(k2)
	if err != nil || tk == nil || *tk != "onekey123" || rs == nil || *rs != "onekey123" {
		t.Fatalf("ReadKeysFile(bare) = (%v, %v, %v)", tk, rs, err)
	}

	kEmpty := filepath.Join(tmp, "empty.txt")
	if err := os.WriteFile(kEmpty, []byte("# comment only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadKeysFile(kEmpty); err == nil {
		t.Fatal("expected error for empty key file")
	}

	// Wrong secret on aaa_radius.pcap must flag RADIUS_BAD_AUTHENTICATOR and RADIUS_BAD_MESSAGE_AUTHENTICATOR.
	wrongPath := filepath.Join(tmp, "wrong.txt")
	if err := os.WriteFile(wrongPath, []byte("radius_secret: this-is-the-wrong-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repWrong := AnalyzeCapture(context.Background(), filepath.Join("testdata", "fixtures", "aaa_radius.pcap"), Options{
		KeysFile: wrongPath,
	})
	foundBadAuth := false
	for _, iss := range repWrong.Issues {
		if iss.Code == "RADIUS_BAD_AUTHENTICATOR" {
			foundBadAuth = true
		}
	}
	if !foundBadAuth {
		t.Fatalf("expected RADIUS_BAD_AUTHENTICATOR with wrong secret, got issues=%+v", repWrong.Issues)
	}

	// Error paths & MessageAuthenticator short inputs.
	ctx := context.Background()
	if rep := AnalyzeCapture(ctx, filepath.Join(tmp, "missing.pcap"), Options{}); rep.Status != "error" {
		t.Fatalf("missing capture should return error")
	}
	if rep := AnalyzeCapture(ctx, tmp, Options{}); rep.Status != "error" {
		t.Fatalf("directory capture should return error")
	}
	radPath := filepath.Join("testdata", "fixtures", "aaa_radius.pcap")
	zero := 0
	if rep := AnalyzeCapture(ctx, radPath, Options{MaxPackets: &zero}); rep.Status != "error" {
		t.Fatalf("max_packets=0 should return error")
	}
	if rep := AnalyzeCapture(ctx, radPath, Options{KeysFile: filepath.Join(tmp, "missing-keys")}); rep.Status != "error" {
		t.Fatalf("missing keys_file should return error")
	}
	repBadKeys := AnalyzeCapture(ctx, radPath, Options{KeysFile: kEmpty})
	rawErr, _ := json.Marshal(repBadKeys)
	if repBadKeys.Status != "error" || !strings.Contains(string(rawErr), `"status":"error"`) {
		t.Fatalf("bad keys JSON mismatch: %s", rawErr)
	}
	if got := MessageAuthenticator([]byte{1, 2}, nil, nil); got != "unchecked" {
		t.Fatalf("short payload MessageAuthenticator = %q, want unchecked", got)
	}
	if emptyV := aaaVerdict(nil, nil, false, false, nil); emptyV != "No TACACS+ or RADIUS found in this capture." {
		t.Fatalf("empty verdict = %q", emptyV)
	}
}
