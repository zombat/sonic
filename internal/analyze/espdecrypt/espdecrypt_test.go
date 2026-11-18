package espdecrypt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
)

func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

func writeTempSA(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sa.conf")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func saFileFixtureText() (string, []string) {
	aesKey := "000102030405060708090a0b0c0d0e0f"
	sha1Key := "000102030405060708090a0b0c0d0e0f10111213"
	sha256Key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	gcmKey := "000102030405060708090a0b0c0d0e0fdeadbeef"
	text := strings.Join([]string{
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00001001\nencryption: aes-cbc\nencryption_key: 0x" + aesKey + "\nintegrity: hmac-sha1-96\nintegrity_key: 0x" + sha1Key,
		"src: 198.51.100.2\ndst: 198.51.100.1\nspi: 0x00001002\nencryption: aes-gcm\nencryption_key: 0x" + gcmKey,
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00002001\nencryption: aes-cbc\nencryption_key: 0x" + aesKey + "\nintegrity: hmac-sha256-128\nintegrity_key: 0x" + sha256Key,
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00003001\nencryption: aes-cbc\nencryption_key: 0x" + aesKey + "\nintegrity: hmac-sha256-128\nintegrity_key: 0x" + sha256Key,
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00004001\nencryption: aes-gcm\nencryption_key: 0x" + gcmKey,
	}, "\n\n") + "\n"
	return text, []string{aesKey, sha1Key, sha256Key, gcmKey}
}

func xfrmFixtureText() string {
	return "src 198.51.100.1 dst 198.51.100.2\n" +
		"\tproto esp spi 0x00001001 reqid 1 mode tunnel\n" +
		"\tenc cbc(aes) 0x000102030405060708090a0b0c0d0e0f\n" +
		"\tauth-trunc hmac(sha1) 0x000102030405060708090a0b0c0d0e0f10111213 96\n" +
		"src 198.51.100.2 dst 198.51.100.1\n" +
		"\tproto esp spi 0x00001002 reqid 2 mode tunnel\n" +
		"\taead rfc4106(gcm(aes)) 0x000102030405060708090a0b0c0d0e0fdeadbeef 128\n"
}

func TestGoldenEspDecryptParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	pcapPath := filepath.Join("testdata", "fixtures", "esp_tunnel.pcap")
	saText, secrets := saFileFixtureText()
	saFile := writeTempSA(t, saText)
	xfrmFile := writeTempSA(t, xfrmFixtureText())

	cases := []struct {
		name   string
		saPath string
		golden string
	}{
		{"sa_file", saFile, filepath.Join("testdata", "golden", "esp_decrypt", "esp_tunnel_sa_file.json")},
		{"xfrm", xfrmFile, filepath.Join("testdata", "golden", "esp_decrypt", "esp_tunnel_xfrm.json")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := AnalyzeCapture(ctx, pcapPath, Options{SAFile: tc.saPath})
			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			for _, sec := range secrets {
				if strings.Contains(strings.ToLower(string(raw)), sec) {
					t.Fatalf("secret key leaked in JSON output: %s", sec)
				}
			}
			parity.CompareOrUpdateJSON(t, raw, tc.golden)
		})
	}
}

func TestEspDecryptBranchesAndHelpers(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	pcapPath := filepath.Join("testdata", "fixtures", "esp_tunnel.pcap")
	saText, _ := saFileFixtureText()
	saFile := writeTempSA(t, saText)

	assertErr := func(r Report, substr string) {
		t.Helper()
		if r.Status != "error" || !strings.Contains(r.Error, substr) {
			t.Fatalf("expected error containing %q, got status=%q err=%q", substr, r.Status, r.Error)
		}
		raw, err := json.Marshal(r)
		if err != nil || !strings.Contains(string(raw), `"status":"error"`) || strings.Contains(string(raw), `"schema"`) {
			t.Fatalf("unexpected error JSON marshal: %s err=%v", raw, err)
		}
	}

	assertErr(AnalyzeCapture(ctx, "", Options{}), "File not found")
	assertErr(AnalyzeCapture(ctx, filepath.Join("testdata", "fixtures", "missing.pcap"), Options{}), "File not found")
	assertErr(AnalyzeCapture(ctx, t.TempDir(), Options{}), "File not readable")
	assertErr(AnalyzeCapture(ctx, pcapPath, Options{}), "ESP decryption needs an SA file")
	assertErr(AnalyzeCapture(ctx, pcapPath, Options{SAFile: t.TempDir()}), "sa_file is not a readable file")
	assertErr(AnalyzeCapture(ctx, pcapPath, Options{SAFile: saFile, MaxPackets: intPtr(0)}), "max_packets must be a positive number")
	badSA := writeTempSA(t, "not an sa\n")
	assertErr(AnalyzeCapture(ctx, pcapPath, Options{SAFile: badSA}), "cannot read the SA file")

	// Empty-match display filter exercises ESP_SA_NO_PACKETS + nil inner analysis + display_filter string.
	empty := AnalyzeCapture(ctx, pcapPath, Options{SAFile: saFile, DisplayFilter: "esp.spi==0xffffffff"})
	if empty.Status != "success" || empty.InnerAnalysis != nil || empty.Capture.DisplayFilter == nil {
		t.Fatalf("expected clean empty ESP result: %+v", empty)
	}

	// Wrong key on matching SPI exercises ESP_SA_NOT_DECRYPTED + saReason(ICVBad).
	wrongSA := writeTempSA(t, "src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00001001\nencryption: aes-cbc\nencryption_key: 0xffffffffffffffffffffffffffffffff\nintegrity: hmac-sha1-96\nintegrity_key: 0xffffffffffffffffffffffffffffffffffffffff\n")
	wrongRep := AnalyzeCapture(ctx, pcapPath, Options{SAFile: wrongSA})
	if wrongRep.Status != "success" || len(wrongRep.Issues) != 1 || wrongRep.Issues[0].Code != "ESP_SA_NOT_DECRYPTED" {
		t.Fatalf("expected ESP_SA_NOT_DECRYPTED, got %+v", wrongRep.Issues)
	}

	// Unit tests for saReason, writeInnerPCAP, buildInnerSummary, and buildVerdict.
	if r := saReason(SARow{Packets: 2, Decrypted: 1, ICVBad: 1, Encryption: strPtr("aes-gcm")}); r == nil || !strings.Contains(*r, "4-byte salt") {
		t.Fatalf("unexpected AEAD saReason: %v", r)
	}
	if r := saReason(SARow{Packets: 2, Decrypted: 1, ICVGood: 2, Encryption: strPtr("aes-cbc")}); r == nil || !strings.Contains(*r, "encryption key or algorithm is wrong") {
		t.Fatalf("unexpected ICV-good saReason: %v", r)
	}
	if r := saReason(SARow{Packets: 2, Decrypted: 1}); r == nil || !strings.Contains(*r, "RFC 4303") {
		t.Fatalf("unexpected fallback saReason: %v", r)
	}
	if buildVerdict(nil, 0, 0, 0, nil) != "No Security Association given." {
		t.Fatal("unexpected empty verdict")
	}
	if v := buildVerdict([]SARow{{Decrypted: 1}}, 1, 1, 0, nil); !strings.Contains(v, "no inner packet could be reconstructed") {
		t.Fatalf("unexpected dummy verdict: %q", v)
	}
	if sum := buildInnerSummary(netorch.NetworkReport{NetworkBody: netorch.NetworkBody{Status: "error", Error: "boom"}}); sum.Status != "error" || sum.Error != "boom" {
		t.Fatalf("unexpected inner error summary: %+v", sum)
	}
	// IPv6 + empty/invalid packets in writeInnerPCAP + splitTimestamp edge cases.
	v6 := make([]byte, 40)
	v6[0] = 0x60
	v4 := make([]byte, 20)
	v4[0] = 0x45
	outPcap := filepath.Join(t.TempDir(), "test.pcap")
	written, err := writeInnerPCAP([]extract.DecryptedInnerPacket{
		{Time: 2.9999999, Bytes: v6},
		{Time: 1.5, Bytes: v4},
		{Time: -1, Bytes: []byte{1, 2}},
	}, outPcap)
	if err != nil || written != 2 {
		t.Fatalf("writeInnerPCAP expected 2 valid packets, got %d err=%v", written, err)
	}
	if raw, err := json.Marshal(InnerSummary{Status: "success", OverallStatus: model.StatusOK}); err != nil || !strings.Contains(string(raw), `"issues":[]`) {
		t.Fatalf("InnerSummary MarshalJSON missing empty issues array: %s err=%v", raw, err)
	}
}
