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
	}
	for _, tc := range cases {
		var out, errBuf bytes.Buffer
		got := run(ctx, tc.args, &out, &errBuf)
		if got != tc.wantCode {
			t.Fatalf("%s: exit code = %d, want %d (out=%q err=%q)", tc.name, got, tc.wantCode, out.String(), errBuf.String())
		}
	}
}
