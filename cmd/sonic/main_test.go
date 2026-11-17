package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/analyze/grpc"
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
	code = run(ctx, []string{"--network-only", "--detectors", "cleartext_audit", "--file", filepath.Join("tests", "fixtures", "ipsec_ikev2_esp.pcap"), "--max-packets", "10"}, &textOut, &textErr)
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
		{"audit_no_file", []string{}, 2},
		{"audit_bad_flag", []string{"--nope"}, 2},
		{"bad_model_flag", []string{"--file", "x.pcap", "--model", "bogus"}, 2},
		{"bad_provider_flag", []string{"--file", "x.pcap", "--provider", "bogus"}, 2},
		{"model_all_with_override", []string{"--file", "x.pcap", "--model", "all", "--model-name", "qwen2.5:0.5b"}, 2},
		{"bad_batch_mode", []string{"--batch-dir", "d", "--batch-mode", "bogus"}, 2},
		{"bad_batch_workers", []string{"--batch-dir", "d", "--batch-workers", "0"}, 2},
		{"bad_env_file", []string{"--env-file", "/definitely/missing/.env", "--file", "x.pcap"}, 2},
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

func TestCLICreateSkillAndRefusal(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "sonic")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"--create-skill", target}, &out, &errOut); code != 0 {
		t.Fatalf("--create-skill exited %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Skill 'sonic'") {
		t.Fatalf("unexpected stdout: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(target, "SKILL.md")); err != nil {
		t.Fatalf("missing SKILL.md: %v", err)
	}

	foreign := filepath.Join(tmp, "other")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "SKILL.md"), []byte("foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{"--create-skill", foreign}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not written by sonic --create-skill") {
		t.Fatalf("expected refusal exit 1, got code=%d err=%s", code, errOut.String())
	}
}

func TestPhase7LLMFetchProtosStreamPartialAndBatch(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)
	ctx := context.Background()

	// 1. --fetch-grpc-protos text and --json success + failure paths.
	okDeps := llmRuntimeDeps{
		fetchProtos: func(_ context.Context, dest string) grpc.FetchResult {
			return grpc.FetchResult{Status: "success", Dir: dest, Files: []string{"gnmi.proto", "gnoi.proto"}}
		},
	}
	var out, errOut bytes.Buffer
	if code := runCommandWithDeps(ctx, []string{"--fetch-grpc-protos", "/tmp/protos"}, &out, &errOut, okDeps); code != 0 || !strings.Contains(out.String(), "Fetched 2 proto files into /tmp/protos") {
		t.Fatalf("fetch-grpc-protos text failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runCommandWithDeps(ctx, []string{"--fetch-grpc-protos=/tmp/protos", "--json"}, &out, &errOut, okDeps); code != 0 || !strings.Contains(out.String(), `"status": "success"`) {
		t.Fatalf("fetch-grpc-protos json failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	failDeps := llmRuntimeDeps{
		fetchProtos: func(_ context.Context, dest string) grpc.FetchResult {
			return grpc.FetchResult{Status: "error", Dir: dest, Error: "network disabled"}
		},
	}
	out.Reset()
	errOut.Reset()
	if code := runCommandWithDeps(ctx, []string{"--fetch-grpc-protos"}, &out, &errOut, failDeps); code != 1 || !strings.Contains(errOut.String(), "network disabled") {
		t.Fatalf("fetch-grpc-protos failure mismatch (%d): out=%q err=%q", code, out.String(), errOut.String())
	}

	// 2. Local httptest OpenAI SSE server exercises full direct-HTTP path across standard, --stream, --partial, and --batch-dir.
	secret := "sk-proj-testopenaisecret1234567890abcdef"
	failMode := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failMode {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"error":{"message":"upstream down"}}`)
			return
		}
		report := `{"totalCalls":1,"calls":[{"callId":"c-1","callerIp":"10.0.0.1","calleeIp":"10.0.0.2","userAgents":["UA"],"audioQuality":{"codecUsed":"PCMU","payloadTypes":["0"],"rtpPort":"4000","potentialIssues":[]},"callFlow":{"callSetupMethod":"INVITE","callTermination":"BYE","responseCodes":["200"],"callDurationIndicators":"2s"},"diagnosticSummary":"Clean call ` + secret + `"}],"overallAssessment":"Normal SIP call","recommendations":["Keep monitoring"]}`
		w.Header().Set("Content-Type", "text/event-stream")
		payload, _ := json.Marshal(struct {
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}{
			Model: "gpt-4o",
			Choices: []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			}{{
				Delta: struct {
					Content string `json:"content"`
				}{Content: report},
				FinishReason: "stop",
			}},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			}{PromptTokens: 20, CompletionTokens: 45},
		})
		_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", payload)
	}))
	defer srv.Close()

	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("OPENAI_API_KEY="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENAI_BASE_URL", srv.URL)

	tmpOut := t.TempDir()
	sipFix := filepath.Join("tests", "fixtures", "sip_minimal.pcap")

	// 2a. Standard --provider openai --model detailed --quality --mos saving markdown + redacted secret.
	mdPath := filepath.Join(tmpOut, "diag.md")
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--file", sipFix, "--env-file", envFile, "--provider", "openai", "--model", "detailed", "--quality", "--mos", "--save_file", mdPath}, &out, &errOut); code != 0 {
		t.Fatalf("standard openai run failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	savedMD, err := os.ReadFile(mdPath)
	if err != nil || strings.Contains(string(savedMD), secret) || !strings.Contains(string(savedMD), "# S.O.N.I.C. SIP Diagnostic Report") {
		t.Fatalf("unexpected or leaky saved markdown: err=%v body=%s", err, savedMD)
	}

	// 2b. --stream text mode + --verbose and --stream --json.
	out.Reset()
	errOut.Reset()
	streamMD := filepath.Join(tmpOut, "stream.md")
	if code := run(ctx, []string{"--file", sipFix, "--env-file", envFile, "--provider", "openai", "--stream", "--verbose", "--save_file", streamMD}, &out, &errOut); code != 0 {
		t.Fatalf("--stream run failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), secret) || !strings.Contains(errOut.String(), "Streaming analysis from LLM") {
		t.Fatalf("unexpected --stream output/stderr: out=%q err=%q", out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--file", sipFix, "--env-file", envFile, "--provider", "openai", "--stream", "--json"}, &out, &errOut); code != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("--stream --json invalid (%d): out=%q err=%q", code, out.String(), errOut.String())
	}

	// 2c. --partial text mode + --verbose + --save_file and --partial --json.
	out.Reset()
	errOut.Reset()
	partialMD := filepath.Join(tmpOut, "partial.md")
	if code := run(ctx, []string{"--file", sipFix, "--env-file", envFile, "--provider", "openai", "--partial", "--verbose", "--save_file", partialMD}, &out, &errOut); code != 0 {
		t.Fatalf("--partial run failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "[partial]") {
		t.Fatalf("missing [partial] notification in --partial stdout: %q", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--file", sipFix, "--env-file", envFile, "--provider", "openai", "--partial", "--json"}, &out, &errOut); code != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("--partial --json invalid (%d): out=%q err=%q", code, out.String(), errOut.String())
	}

	// 2d. --batch-dir sequential/parallel, empty, missing, and total-failure error path.
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--batch-dir", filepath.Join(tmpOut, "missing")}, &out, &errOut); code != 1 {
		t.Fatalf("expected exit 1 for missing --batch-dir, got %d", code)
	}
	emptyDir := t.TempDir()
	if code := run(ctx, []string{"--batch-dir", emptyDir, "--json"}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "no pcap files found") {
		t.Fatalf("expected JSON error for empty --batch-dir, got %d out=%q", code, out.String())
	}
	batchDir := t.TempDir()
	sipBytes, err := os.ReadFile(sipFix)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"c1.pcap", "c2.pcapng"} {
		if err := os.WriteFile(filepath.Join(batchDir, fn), sipBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	batchMD := filepath.Join(tmpOut, "batch.md")
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--batch-dir", batchDir, "--env-file", envFile, "--provider", "openai", "--model", "detailed", "--batch-mode", "parallel", "--batch-workers", "2", "--verbose", "--save_file", batchMD}, &out, &errOut); code != 0 {
		t.Fatalf("--batch-dir parallel failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "2/2 succeeded") {
		t.Fatalf("unexpected batch stdout: %s", out.String())
	}

	failMode = true
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--batch-dir", batchDir, "--env-file", envFile, "--provider", "openai", "--save_file", filepath.Join(tmpOut, "failbatch.md")}, &out, &errOut); code != 1 {
		t.Fatalf("expected exit 1 on failed batch, got %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--file", sipFix, "--env-file", envFile, "--provider", "openai", "--partial"}, &out, &errOut); code != 1 {
		t.Fatalf("expected exit 1 on failed --partial, got %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"--file", sipFix, "--env-file", envFile, "--provider", "openai", "--stream"}, &out, &errOut); code != 1 {
		t.Fatalf("expected exit 1 on failed --stream, got %d", code)
	}
}
