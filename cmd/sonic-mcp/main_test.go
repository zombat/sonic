package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/mcpserver"
)

func TestRunMCPStdioLoop(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
	}, "\n") + "\n")
	var out, errOut bytes.Buffer
	code := runWithArgs(context.Background(), nil, in, &out, &errOut, false, defaultDeps())
	if code != 0 {
		t.Fatalf("run exited %d: %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 JSON-RPC response lines, got %d (%q)", len(lines), out.String())
	}
	for i, line := range lines {
		var msg map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
		if string(msg["jsonrpc"]) != `"2.0"` {
			t.Fatalf("line %d missing jsonrpc 2.0: %s", i, line)
		}
	}
}

func TestRunMCPReserveStdoutAndCreateSkill(t *testing.T) {
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	var out, errOut bytes.Buffer
	code := runWithArgs(context.Background(), nil, in, &out, &errOut, true, defaultDeps())
	if code != 0 {
		t.Fatalf("run with reserveFD=true failed (%d): %s", code, errOut.String())
	}

	target := filepath.Join(t.TempDir(), "sonic")
	out.Reset()
	errOut.Reset()
	if code := runWithArgs(context.Background(), []string{"--create-skill", target}, strings.NewReader(""), &out, &errOut, false, defaultDeps()); code != 0 || !strings.Contains(out.String(), "Skill 'sonic'") {
		t.Fatalf("--create-skill failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(filepath.Join(target, "SKILL.md")); err != nil {
		t.Fatalf("missing generated SKILL.md: %v", err)
	}

	out.Reset()
	errOut.Reset()
	if code := runWithArgs(context.Background(), []string{"--version"}, strings.NewReader(""), &out, &errOut, false, defaultDeps()); code != 0 || !strings.Contains(out.String(), "sonic-mcp") {
		t.Fatalf("--version failed (%d): out=%q err=%q", code, out.String(), errOut.String())
	}
	if got := resolveServerVersion("v4.0.0", "abc1234"); got != "v4.0.0 (abc1234)" {
		t.Fatalf("unexpected resolved version with commit: %q", got)
	}
	if got := resolveServerVersion("v4.0.0", "none"); got != "v4.0.0" {
		t.Fatalf("unexpected resolved version without commit: %q", got)
	}
}

func TestRunMCPErrorPaths(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runWithArgs(context.Background(), []string{"--unknown-flag"}, strings.NewReader(""), &out, &errOut, false, defaultDeps()); code != 2 {
		t.Fatalf("expected exit 2 on bad flag, got %d", code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	errOut.Reset()
	if code := runWithArgs(ctx, nil, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, &errOut, false, defaultDeps()); code != 1 {
		t.Fatalf("expected exit code 1 on cancelled ctx, got %d", code)
	}
	if !strings.Contains(errOut.String(), "serve mcp stdio:") {
		t.Fatalf("unexpected stderr: %q", errOut.String())
	}

	errOut.Reset()
	badInit := runtimeDeps{
		loadCreds: llm.NewCredentialStore,
		newServer: func(ai.Deps) (*mcpserver.Server, error) {
			return nil, errors.New("sk-ant-api03-1234567890abcdefghijklmnop")
		},
		reserveStdout: defaultDeps().reserveStdout,
	}
	if code := runWithArgs(context.Background(), nil, strings.NewReader(""), &out, &errOut, false, badInit); code != 1 || strings.Contains(errOut.String(), "sk-ant-") {
		t.Fatalf("expected redacted init failure, got code=%d stderr=%q", code, errOut.String())
	}

	errOut.Reset()
	badReserve := runtimeDeps{
		loadCreds:     llm.NewCredentialStore,
		newServer:     defaultDeps().newServer,
		reserveStdout: func() (*os.File, func(), error) { return nil, nil, errors.New("dup failed") },
	}
	if code := runWithArgs(context.Background(), nil, strings.NewReader(""), &out, &errOut, true, badReserve); code != 1 || !strings.Contains(errOut.String(), "reserve protocol stdout:") {
		t.Fatalf("expected reserve failure, got code=%d stderr=%q", code, errOut.String())
	}

	// Missing --env-file exits 2 without leaking values.
	errOut.Reset()
	if code := runWithArgs(context.Background(), []string{"--env-file", "/nonexistent/env.txt"}, strings.NewReader(""), &out, &errOut, false, defaultDeps()); code != 2 {
		t.Fatalf("expected exit 2 on missing --env-file, got code=%d stderr=%q", code, errOut.String())
	}

	// Unexpected non-EnvFile loader failure exits 1.
	errOut.Reset()
	badCredLoader := runtimeDeps{
		loadCreds: func(string) (*llm.CredentialStore, error) {
			return nil, errors.New("io boom sk-ant-api03-1234567890abcdefghijklmnop")
		},
		newServer:     defaultDeps().newServer,
		reserveStdout: defaultDeps().reserveStdout,
	}
	if code := runWithArgs(context.Background(), nil, strings.NewReader(""), &out, &errOut, false, badCredLoader); code != 1 || strings.Contains(errOut.String(), "sk-ant-") {
		t.Fatalf("expected exit 1 redacted load failure, got code=%d stderr=%q", code, errOut.String())
	}

	// Valid --env-file wires configured status without leaking secret into list_llm_providers.
	secret := "sk-ant-api03-testsecretvalue9876543210abcd"
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("ANTHROPIC_API_KEY="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	out.Reset()
	errOut.Reset()
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_llm_providers","arguments":{}}}` + "\n"
	if code := runWithArgs(context.Background(), []string{"--env-file", envPath}, strings.NewReader(req), &out, &errOut, false, defaultDeps()); code != 0 {
		t.Fatalf("list_llm_providers with --env-file failed (%d): %s", code, errOut.String())
	}
	if strings.Contains(out.String(), secret) || !strings.Contains(out.String(), `"anthropic_key_set":true`) {
		t.Fatalf("unexpected or leaky list_llm_providers output: %s", out.String())
	}
}
