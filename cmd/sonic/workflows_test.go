package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestV4CLIWorkflowsGateDiffTUIHTMLFastPathAndRedactAudit(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	sipCap := filepath.Join("testdata", "fixtures", "sip_minimal.pcap")
	bgpGood := filepath.Join("testdata", "fixtures", "bgp_session.pcap")
	bgpBad := filepath.Join("testdata", "fixtures", "bgp_failover.pcap")
	tlsOK := filepath.Join("testdata", "fixtures", "grpc_tls13_hrr.pcap")
	leakCap := filepath.Join("testdata", "fixtures", "audit_one_leak.pcap")
	tcpCap := filepath.Join("testdata", "fixtures", "dp_tcp_health.pcap")

	// 1. gate subcommand: PASS (0), FAIL (3), SARIF, JUnit, JSON, HTML, invalid format/policy (2), missing (1).
	var out, errBuf bytes.Buffer
	if code := run(ctx, []string{"gate", "--file", tlsOK, "--policy", "no-weak-crypto,no-critical-issues", "--redact-audit"}, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "[PASS]") || !strings.Contains(errBuf.String(), "Redaction audit:") {
		t.Fatalf("gate pass unexpected: code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	sarifSave := filepath.Join(t.TempDir(), "gate.sarif")
	gateHTML := filepath.Join(t.TempDir(), "gate.html")
	if code := run(ctx, []string{"gate", "--file", leakCap, "--policy", "zero-cleartext", "--format", "sarif", "--save_file", sarifSave, "--html", gateHTML}, &out, &errBuf); code != 3 || !strings.Contains(out.String(), `"version": "2.1.0"`) {
		t.Fatalf("gate SARIF fail unexpected: code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}
	if _, err := os.Stat(sarifSave); err != nil {
		t.Fatalf("gate SARIF save missing: %v", err)
	}
	if _, err := os.Stat(gateHTML); err != nil {
		t.Fatalf("gate HTML missing: %v", err)
	}

	out.Reset()
	if code := run(ctx, []string{"gate", "--file", leakCap, "--policy", "zero-cleartext", "--format", "junit"}, &out, &errBuf); code != 3 || !strings.Contains(out.String(), "<testsuites") {
		t.Fatalf("gate JUnit unexpected: code=%d out=%q", code, out.String())
	}
	out.Reset()
	if code := run(ctx, []string{"gate", "--file", leakCap, "--json", "--redact-audit"}, &out, &errBuf); code != 3 || !strings.Contains(out.String(), `"redact_audit"`) {
		t.Fatalf("gate JSON --redact-audit unexpected: code=%d out=%q", code, out.String())
	}
	for _, badArgs := range []struct {
		args []string
		want int
	}{
		{[]string{"gate", "--help"}, 0},
		{[]string{"gate"}, 2},
		{[]string{"gate", "--nope"}, 2},
		{[]string{"gate", "--file", tlsOK, "--format", "yaml"}, 2},
		{[]string{"gate", "--file", tlsOK, "--policy", "bad_rule"}, 2},
		{[]string{"gate", "--file", "/nonexistent.pcap", "--json"}, 1},
	} {
		out.Reset()
		errBuf.Reset()
		if got := run(ctx, badArgs.args, &out, &errBuf); got != badArgs.want {
			t.Fatalf("gate %v = %d, want %d (stderr: %s)", badArgs.args, got, badArgs.want, errBuf.String())
		}
	}

	// 2. diff subcommand + --diff flag + .html auto-save.
	out.Reset()
	errBuf.Reset()
	diffHTML := filepath.Join(t.TempDir(), "diff.html")
	if code := run(ctx, []string{"diff", "--baseline", bgpGood, "--target", bgpBad, "--save_file", diffHTML}, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "Diff:") {
		t.Fatalf("diff subcommand failed: code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}
	if b, err := os.ReadFile(diffHTML); err != nil || !strings.Contains(string(b), "<!DOCTYPE html>") {
		t.Fatalf("diff HTML missing: err=%v", err)
	}
	out.Reset()
	if code := run(ctx, []string{"--diff", bgpGood + "," + bgpBad, "--json", "--redact-audit"}, &out, &errBuf); code != 0 || !strings.Contains(out.String(), `"redact_audit"`) {
		t.Fatalf("--diff flag failed: code=%d err=%q", code, errBuf.String())
	}
	for _, dBad := range []struct {
		args []string
		want int
	}{
		{[]string{"diff", "--help"}, 0},
		{[]string{"diff"}, 2},
		{[]string{"diff", "--nope"}, 2},
		{[]string{"--diff", "onlyone.pcap"}, 2},
		{[]string{"diff", "--baseline", "/missing.pcap", "--target", bgpBad}, 1},
	} {
		out.Reset()
		errBuf.Reset()
		if got := run(ctx, dBad.args, &out, &errBuf); got != dBad.want {
			t.Fatalf("diff %v = %d, want %d", dBad.args, got, dBad.want)
		}
	}

	// 3. --correlate-media, --fast-path, --since/--until, --html, and tui subcommand.
	out.Reset()
	errBuf.Reset()
	muHTML := filepath.Join(t.TempDir(), "mu.html")
	if code := run(ctx, []string{"--correlate-media", "--file", sipCap, "--json", "--html", muHTML}, &out, &errBuf); code != 0 || !strings.Contains(out.String(), `"cross_layer_links"`) {
		t.Fatalf("--correlate-media failed: code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}
	if _, err := os.Stat(muHTML); err != nil {
		t.Fatalf("media-underlay HTML missing: %v", err)
	}
	if code := run(ctx, []string{"--correlate-media", "--file", "/no/such.pcap"}, &out, &errBuf); code != 1 {
		t.Fatalf("expected error code 1 for missing --correlate-media capture, got %d", code)
	}

	out.Reset()
	errBuf.Reset()
	if code := run(ctx, []string{"--network-only", "--file", tcpCap, "--detectors", "tcp,path_mtu,qos", "--fast-path", "always", "--since", "0", "--until", "100000", "--json"}, &out, &errBuf); code != 0 {
		t.Fatalf("fast-path network run failed: code=%d err=%q", code, errBuf.String())
	}
	var netOut struct {
		Capture struct {
			Backend string `json:"backend"`
		} `json:"capture"`
	}
	if err := json.Unmarshal(out.Bytes(), &netOut); err != nil || netOut.Capture.Backend != "go-fast" {
		t.Fatalf("expected go-fast backend in CLI JSON, got err=%v json=%s", err, out.String())
	}
	if code := run(ctx, []string{"--network-only", "--file", tcpCap, "--since", "bad"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected exit 2 on invalid --since, got %d", code)
	}
	if code := run(ctx, []string{"--network-only", "--file", tcpCap, "--until", "bad"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected exit 2 on invalid --until, got %d", code)
	}

	// tui subcommand with OneByteReader navigating tabs and quitting.
	out.Reset()
	errBuf.Reset()
	code := runWithIO(ctx, []string{"tui", "--file", tcpCap, "--detectors", "tcp,conversations", "--fast-path", "always"},
		iotest.OneByteReader(strings.NewReader("2q")), &out, &errBuf, defaultLLMRuntimeDeps())
	if code != 0 || !strings.Contains(out.String(), "S.O.N.I.C. TUI") {
		t.Fatalf("tui subcommand failed: code=%d err=%q", code, errBuf.String())
	}
}
