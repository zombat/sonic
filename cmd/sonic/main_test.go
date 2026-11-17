package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/parity"
)

func TestCLIDumpAndAuditGoldenParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()

	// 1. dump --file reproduces golden record JSON.
	var dumpOut, dumpErr bytes.Buffer
	code := run(ctx, []string{"dump", "--file", filepath.Join("tests", "fixtures", "audit_one_leak.pcap")}, &dumpOut, &dumpErr)
	if code != 0 {
		t.Fatalf("dump exited %d: %s", code, dumpErr.String())
	}
	wantDump, err := os.ReadFile(filepath.Join("testdata", "golden", "records", "audit_one_leak.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := parity.CompareJSON(dumpOut.Bytes(), wantDump); err != nil {
		t.Fatalf("dump golden parity mismatch: %v", err)
	}

	// 2. --network-only --detectors cleartext_audit --allow crypto --json reproduces golden audit JSON.
	var auditOut, auditErr bytes.Buffer
	code = run(ctx, []string{
		"--network-only",
		"--file", filepath.Join("tests", "fixtures", "audit_one_leak.pcap"),
		"--detectors", "cleartext_audit",
		"--allow", "crypto",
		"--json",
	}, &auditOut, &auditErr)
	if code != 0 {
		t.Fatalf("audit --json exited %d: %s", code, auditErr.String())
	}
	wantAudit, err := os.ReadFile(filepath.Join("testdata", "golden", "cleartext_audit", "audit_one_leak_allow_crypto.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := parity.CompareJSON(auditOut.Bytes(), wantAudit); err != nil {
		t.Fatalf("audit golden parity mismatch: %v", err)
	}

	// 3. Human-readable verdict mode without --json.
	var textOut, textErr bytes.Buffer
	code = run(ctx, []string{"--file", filepath.Join("tests", "fixtures", "ipsec_ikev2_esp.pcap"), "--max-packets", "10"}, &textOut, &textErr)
	if code != 0 || !strings.Contains(textOut.String(), "PASS:") {
		t.Fatalf("text mode = (code=%d, out=%q, err=%q)", code, textOut.String(), textErr.String())
	}
}

func TestCLIErrorPaths(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"dump_no_file", []string{"dump"}, 1},
		{"dump_bad_flag", []string{"dump", "--nope"}, 2},
		{"dump_missing_pcap", []string{"dump", "--file", "/no/such/file.pcap"}, 1},
		{"audit_no_file", []string{}, 1},
		{"audit_bad_flag", []string{"--nope"}, 2},
		{"allow_without_detector", []string{"--file", "x.pcap", "--detectors", "routing", "--allow", "crypto"}, 1},
		{"unsupported_detector", []string{"--file", "x.pcap", "--detectors", "routing"}, 1},
		{"bad_allow_json", []string{"--file", "x.pcap", "--allow", "bogus_tok", "--json"}, 1},
		{"missing_pcap_text", []string{"--file", "/no/such/file.pcap"}, 1},
		{"grpc_missing", []string{"--grpc", "--file", "/no/such/file.pcap"}, 1},
		{"restconf_missing_json", []string{"--restconf", "--file", "/no/such/file.pcap", "--json"}, 1},
		{"snmp_missing", []string{"--snmp", "--file", "/no/such/file.pcap"}, 1},
		{"aaa_missing", []string{"--aaa", "--file", "/no/such/file.pcap"}, 1},
		{"esp_missing", []string{"--esp-decrypt", "--file", "/no/such/file.pcap"}, 1},
		{"quality_missing", []string{"--quality-only", "--file", "/no/such/file.pcap"}, 1},
		{"network_bad_allow", []string{"--network-only", "--file", "x.pcap", "--detectors", "ipsec", "--allow", "crypto"}, 1},
		{"network_missing", []string{"--network-only", "--file", "/no/such/file.pcap", "--json"}, 1},
	}
	for _, tc := range cases {
		var out, errBuf bytes.Buffer
		got := run(ctx, tc.args, &out, &errBuf)
		if got != tc.wantCode {
			t.Fatalf("%s: exit code = %d, want %d (out=%q err=%q)", tc.name, got, tc.wantCode, out.String(), errBuf.String())
		}
	}
}

func TestCLIProtocolModesAndSaveFile(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	tmp := t.TempDir()
	saText := "src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00001001\nencryption: aes-cbc\nencryption_key: 0x000102030405060708090a0b0c0d0e0f\nintegrity: hmac-sha1-96\nintegrity_key: 0x000102030405060708090a0b0c0d0e0f10111213\n"
	saPath := filepath.Join(tmp, "sa.conf")
	if err := os.WriteFile(saPath, []byte(saText), 0o600); err != nil {
		t.Fatal(err)
	}

	runs := []struct {
		name string
		args []string
		want string
	}{
		{"network_text_save", []string{"--network-only", "--file", filepath.Join("tests", "fixtures", "ipsec_ikev2_esp.pcap"), "--save_file", filepath.Join(tmp, "net.md")}, "S.O.N.I.C. network analysis"},
		{"network_json", []string{"--network-only", "--file", filepath.Join("tests", "fixtures", "ipsec_ikev2_esp.pcap"), "--detectors", "ipsec", "--json"}, `"encryption_verdict"`},
		{"grpc_text_save", []string{"--grpc", "--file", filepath.Join("tests", "fixtures", "grpc_h2_trouble.pcap"), "--proto-path", tmp, "--save_file", filepath.Join(tmp, "grpc.md")}, "S.O.N.I.C. gRPC troubleshooting"},
		{"restconf_text_save", []string{"--restconf", "--file", filepath.Join("tests", "fixtures", "restconf_cleartext.pcap"), "--save_file", filepath.Join(tmp, "http.json")}, "S.O.N.I.C. RESTCONF and REST troubleshooting"},
		{"snmp_text_save", []string{"--snmp", "--file", filepath.Join("tests", "fixtures", "snmp_v1v2c.pcap"), "--save_file", filepath.Join(tmp, "snmp.md")}, "S.O.N.I.C. SNMP troubleshooting"},
		{"aaa_text_save", []string{"--aaa", "--file", filepath.Join("tests", "fixtures", "aaa_radius.pcap"), "--save_file", filepath.Join(tmp, "aaa.md")}, "S.O.N.I.C. TACACS+ and RADIUS troubleshooting"},
		{"esp_text_save", []string{"--esp-decrypt", "--esp-sa", saPath, "--file", filepath.Join("tests", "fixtures", "esp_tunnel.pcap"), "--save_file", filepath.Join(tmp, "esp.md")}, "S.O.N.I.C. IPsec ESP decryption"},
		{"quality_json", []string{"--quality-only", "--file", filepath.Join("tests", "fixtures", "sip_minimal.pcap"), "--json"}, `"mos_analysis"`},
		{"quality_text", []string{"--quality-only", "--file", filepath.Join("tests", "fixtures", "sip_minimal.pcap")}, "Quality Grade:"},
	}
	for _, tc := range runs {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			if code := run(ctx, tc.args, &out, &errBuf); code != 0 {
				t.Fatalf("%s exited %d: out=%q err=%q", tc.name, code, out.String(), errBuf.String())
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("%s output missing %q: %s", tc.name, tc.want, out.String())
			}
		})
	}
}
