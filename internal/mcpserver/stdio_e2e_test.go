package mcpserver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/zombat/sonic/internal/guide"
)

type stdioClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  <-chan []byte
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	done   chan error
	wg     sync.WaitGroup
}

func startStdioServer(t *testing.T, binPath string, extraEnv map[string]string, args ...string) *stdioClient {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	env := filteredCleanEnv(extraEnv)
	cmd.Env = env
	inPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binPath, err)
	}

	lineCh := make(chan []byte, 64)
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	c := &stdioClient{cmd: cmd, stdin: inPipe, lines: lineCh, stdout: outBuf, stderr: errBuf, done: make(chan error, 1)}

	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		defer close(lineCh)
		r := bufio.NewReader(outPipe)
		for {
			line, rerr := r.ReadBytes('\n')
			if len(line) > 0 {
				outBuf.Write(line)
				cp := append([]byte(nil), line...)
				lineCh <- cp
			}
			if rerr != nil {
				return
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		_, _ = io.Copy(errBuf, errPipe)
	}()
	return c
}

func filteredCleanEnv(extra map[string]string) []string {
	skip := []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_KEY", "SONIC_ENV_FILE", "SONIC_LLM_PROVIDER"}
	var env []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if slices.Contains(skip, key) {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

func (c *stdioClient) request(t *testing.T, id int, method string, params any) map[string]json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.stdin.Write(append(payload, '\n')); err != nil {
		t.Fatal(err)
	}
	for raw := range c.lines {
		var msg map[string]json.RawMessage
		if jerr := json.Unmarshal(raw, &msg); jerr != nil {
			t.Fatalf("non-JSON line on stdout: %q", raw)
		}
		var gotID int
		if msg["id"] != nil && json.Unmarshal(msg["id"], &gotID) == nil && gotID == id {
			return msg
		}
	}
	t.Fatalf("EOF waiting for id %d (%s); stderr=%s", id, method, c.stderr.String())
	return nil
}

func (c *stdioClient) notify(t *testing.T, method string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	if _, err := c.stdin.Write(append(payload, '\n')); err != nil {
		t.Fatal(err)
	}
}

func (c *stdioClient) closeAndAssertPureStdout(t *testing.T) {
	t.Helper()
	_ = c.stdin.Close()
	c.wg.Wait()
	if err := c.cmd.Wait(); err != nil {
		t.Fatalf("server wait: %v\nstderr=%s", err, c.stderr.String())
	}
	raw := c.stdout.Bytes()
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("stdout must end with newline: %q", raw)
	}
	for _, line := range bytes.Split(raw[:len(raw)-1], []byte("\n")) {
		var msg map[string]any
		if err := json.Unmarshal(line, &msg); err != nil {
			t.Fatalf("non-JSON line on stdout: %q (%v)", line, err)
		}
		if msg["jsonrpc"] != "2.0" {
			t.Fatalf("missing jsonrpc 2.0 on stdout: %q", line)
		}
	}
}

func buildTestBinary(t *testing.T, pkg, name, ldflags string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	args := []string{"build"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", out, pkg)
	cmd := exec.Command("go", args...)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s failed: %v\n%s", pkg, err, combined)
	}
	return out
}

func TestMcpStdioHandshakeGuidanceAndPurity(t *testing.T) {
	chdirRepoRoot(t)
	mcpBin := buildTestBinary(t, "./cmd/sonic-mcp", "sonic-mcp", "-X main.version=v4.0.0-test -X main.commit=deadbeef")
	stubBin := buildTestBinary(t, "./tests/stub_llm_mcp_server.go", "sonic-mcp-stub", "")

	// 1. Live server process: initialize, instructions, prompts, resources, tools/list, and SIP stderr isolation.
	srv := startStdioServer(t, mcpBin, map[string]string{"SONIC_LLM_PROVIDER": "ollama"})
	initResp := srv.request(t, 1, "initialize", map[string]any{
		"protocolVersion": LatestProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "go-e2e-test", "version": "1"},
	})
	var initBody initializeResult
	if err := json.Unmarshal(initResp["result"], &initBody); err != nil {
		t.Fatal(err)
	}
	if initBody.ServerInfo.Version != "v4.0.0-test (deadbeef)" {
		t.Fatalf("expected ldflags server version, got %q", initBody.ServerInfo.Version)
	}
	if len(initBody.Instructions) == 0 || len(initBody.Instructions) >= 2048 || !strings.Contains(initBody.Instructions, "sonic://guide/") {
		t.Fatalf("unexpected instructions: %q", initBody.Instructions)
	}
	srv.notify(t, "notifications/initialized")

	toolsResp := srv.request(t, 2, "tools/list", map[string]any{})
	var listed struct {
		Tools []toolDef `json:"tools"`
	}
	if err := json.Unmarshal(toolsResp["result"], &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 21 {
		t.Fatalf("expected 21 tools, got %d", len(listed.Tools))
	}

	promptResp := srv.request(t, 3, "prompts/get", map[string]any{
		"name":      "check_vpn_encryption",
		"arguments": map[string]string{"file_path": "/c/wan.pcap", "peers": "192.0.2.1, 198.51.100.2"},
	})
	if !strings.Contains(string(promptResp["result"]), "192.0.2.1") || !strings.Contains(string(promptResp["result"]), "198.51.100.2") {
		t.Fatalf("unexpected prompt response: %s", promptResp["result"])
	}

	resResp := srv.request(t, 4, "resources/read", map[string]any{"uri": "sonic://guide/mcp-tools"})
	if !strings.Contains(string(resResp["result"]), "analyze_vpn_pcap") {
		t.Fatalf("unexpected resource response: %s", resResp["result"])
	}

	for id, tc := range []struct {
		tool string
		args map[string]any
		sub  string
	}{
		{
			"quick_quality_check",
			map[string]any{"file_path": "testdata/fixtures/sip_minimal.pcap"},
			`"status":"success"`,
		},
		{
			"analyze_network_pcap",
			map[string]any{"file_path": "testdata/fixtures/sip_minimal.pcap"},
			`"status":"success"`,
		},
		{
			"analyze_vpn_pcap",
			map[string]any{"file_path": "testdata/fixtures/ipsec_natt.pcap"},
			`"encryption_verdict":"encrypted"`,
		},
		{
			"audit_cleartext_pcap",
			map[string]any{"file_path": "testdata/fixtures/audit_one_leak.pcap", "allow": []string{"crypto"}},
			`"result":"fail"`,
		},
		{
			"analyze_convergence_pcap",
			map[string]any{"file_path": "testdata/fixtures/convergence_dpd.pcap", "event_time": 30},
			`"mechanism":"dpd"`,
		},
	} {
		callResp := srv.request(t, 10+id, "tools/call", map[string]any{"name": tc.tool, "arguments": tc.args})
		if !strings.Contains(string(callResp["result"]), tc.sub) {
			t.Fatalf("%s missing %q: %s", tc.tool, tc.sub, callResp["result"])
		}
	}
	srv.closeAndAssertPureStdout(t)
	if !strings.Contains(srv.stderr.String(), "Extracting SIP data") {
		t.Fatalf("expected SIP extraction logs on stderr, got: %s", srv.stderr.String())
	}

	// 2. Stubbed streaming MCP server child process: verify partial streaming over clean stdout.
	stubSrv := startStdioServer(t, stubBin, nil)
	stubSrv.request(t, 1, "initialize", map[string]any{"protocolVersion": LatestProtocolVersion})
	stubSrv.notify(t, "notifications/initialized")
	streamResp := stubSrv.request(t, 2, "tools/call", map[string]any{
		"name":      "analyze_pcap_partial_streaming",
		"arguments": map[string]any{"file_path": "testdata/fixtures/sip_minimal.pcap", "provider": "anthropic"},
	})
	var callRes toolResult
	if err := json.Unmarshal(streamResp["result"], &callRes); err != nil {
		t.Fatal(err)
	}
	if callRes.IsError || !strings.Contains(string(callRes.StructuredContent), `"stub":true`) || !strings.Contains(string(callRes.StructuredContent), `"provider":"anthropic"`) {
		t.Fatalf("unexpected partial streaming stub payload: %s", callRes.StructuredContent)
	}
	stubSrv.closeAndAssertPureStdout(t)
}

func TestAllToolsGuidanceAndProviderSchemas(t *testing.T) {
	specs, err := DefaultToolSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != len(guide.AllToolGuide) {
		t.Fatalf("tool count mismatch: specs=%d guide=%d", len(specs), len(guide.AllToolGuide))
	}
	llmTools := make(map[string]bool)
	for _, g := range guide.AllToolGuide {
		llmTools[g.Name] = g.LLM
	}

	for _, s := range specs {
		if len(s.Description) <= 200 || !strings.Contains(s.Description, "Returns") || !strings.Contains(s.Description, "For example") || !strings.Contains(s.Description, "LLM") {
			t.Fatalf("tool %s description fails self-teaching checks", s.Name)
		}
		if strings.ContainsRune(s.Description, '\u2014') || s.Title == "" {
			t.Fatalf("tool %s missing title or contains em-dash", s.Name)
		}
		if !s.Annotations.ReadOnlyHint || s.Annotations.DestructiveHint {
			t.Fatalf("tool %s annotations not read-only/non-destructive: %+v", s.Name, s.Annotations)
		}
		isLLM := llmTools[s.Name]
		if s.Annotations.IdempotentHint == isLLM || s.Annotations.OpenWorldHint != isLLM {
			t.Fatalf("tool %s idempotent/openWorld mismatch (llm=%v): %+v", s.Name, isLLM, s.Annotations)
		}

		var schema struct {
			Properties map[string]struct {
				Description string `json:"description"`
				Default     any    `json:"default"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(s.InputSchema, &schema); err != nil {
			t.Fatalf("tool %s invalid inputSchema: %v", s.Name, err)
		}
		for propName, prop := range schema.Properties {
			if strings.TrimSpace(prop.Description) == "" {
				t.Fatalf("tool %s.%s missing schema description", s.Name, propName)
			}
			if propName == "provider" && prop.Default != nil {
				t.Fatalf("tool %s provider schema must default to nil so SONIC_LLM_PROVIDER works", s.Name)
			}
		}
	}
}
