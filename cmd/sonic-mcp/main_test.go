package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

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
	code := run(context.Background(), in, &out, &errOut, false, defaultDeps())
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

func TestRunMCPReserveStdoutForProtocol(t *testing.T) {
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	var out, errOut bytes.Buffer
	code := run(context.Background(), in, &out, &errOut, true, defaultDeps())
	if code != 0 {
		t.Fatalf("run with reserveFD=true failed (%d): %s", code, errOut.String())
	}
}

func TestRunMCPErrorPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	if code := run(ctx, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, &errOut, false, defaultDeps()); code != 1 {
		t.Fatalf("expected exit code 1 on cancelled ctx, got %d", code)
	}
	if !strings.Contains(errOut.String(), "serve mcp stdio:") {
		t.Fatalf("unexpected stderr: %q", errOut.String())
	}

	errOut.Reset()
	badInit := runtimeDeps{
		newServer:     func() (*mcpserver.Server, error) { return nil, errors.New("sk-ant-api03-1234567890abcdefghijklmnop") },
		reserveStdout: defaultDeps().reserveStdout,
	}
	if code := run(context.Background(), strings.NewReader(""), &out, &errOut, false, badInit); code != 1 || strings.Contains(errOut.String(), "sk-ant-") {
		t.Fatalf("expected redacted init failure, got code=%d stderr=%q", code, errOut.String())
	}

	errOut.Reset()
	badReserve := runtimeDeps{
		newServer:     defaultDeps().newServer,
		reserveStdout: func() (*os.File, func(), error) { return nil, nil, errors.New("dup failed") },
	}
	if code := run(context.Background(), strings.NewReader(""), &out, &errOut, true, badReserve); code != 1 || !strings.Contains(errOut.String(), "reserve protocol stdout:") {
		t.Fatalf("expected reserve failure, got code=%d stderr=%q", code, errOut.String())
	}
}
