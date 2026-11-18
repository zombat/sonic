package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderCapabilitiesAndWireNames(t *testing.T) {
	cases := []struct {
		name      string
		streaming bool
		param     string
		wantWire  string
	}{
		{"ollama", false, ParamMaxTokens, "num_predict"},
		{"ollama", false, ParamSchema, "format"},
		{"ollama", false, ParamTopP, "top_p"},
		{"anthropic", true, ParamStop, "stop_sequences"},
		{"anthropic", true, ParamSchema, "tool"},
		{"anthropic", true, ParamTopP, "top_p"},
		{"openai", true, ParamSchema, "response_format"},
		{"azure", true, ParamSchema, "response_format"},
		{"azure", true, ParamStop, "stop"},
	}
	for _, tc := range cases {
		p, ok := Lookup(tc.name)
		if !ok {
			t.Fatalf("missing provider %s", tc.name)
		}
		if p.SupportsStreaming() != tc.streaming {
			t.Fatalf("%s SupportsStreaming() = %v, want %v", tc.name, p.SupportsStreaming(), tc.streaming)
		}
		if got := p.WireName(tc.param); got != tc.wantWire {
			t.Fatalf("%s.WireName(%s) = %q, want %q", tc.name, tc.param, got, tc.wantWire)
		}
	}
}

func TestConfigEnvAndTildeAndRetryExhaustion(t *testing.T) {
	t.Setenv("SONIC_LLM_TEMPERATURE", "0.25")
	t.Setenv("SONIC_LLM_MAX_TOKENS", "1024")
	cfg := NewConfig("openai", "", "explicit-key", nil)
	if cfg.Temperature != 0.25 || cfg.MaxTokens != 1024 || cfg.APIKey != "explicit-key" {
		t.Fatalf("unexpected NewConfig: %+v", cfg)
	}
	if got := expandTildeResult(t, "~/missing.env"); !strings.HasSuffix(got, "missing.env") {
		t.Fatalf("unexpected tilde expansion: %q", got)
	}
	if _, err := expandTilde("~"); err != nil {
		t.Fatalf("expandTilde(~): %v", err)
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, `{"error":"temporary overload"}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	t.Setenv("OPENAI_BASE_URL", srv.URL)
	t.Setenv("OPENAI_API_KEY", "sk-proj-retrytest01234567890123")
	store, _ := NewCredentialStore("")
	c := NewClient(store)
	c.Base.HTTPClient = srv.Client()
	c.Opts = CallOptions{
		Retries: 2,
		Backoff: time.Millisecond,
		Sleep:   func(context.Context, time.Duration) error { return nil },
	}
	_, _, err := c.Complete(context.Background(), "openai", "fast", "", []Message{{Role: "user", Content: "hi"}}, nil, nil)
	if err == nil || calls.Load() != 3 || !strings.Contains(err.Error(), "after 2 retries") {
		t.Fatalf("expected exhaustion after 2 retries (3 calls), got calls=%d err=%v", calls.Load(), err)
	}

	// Sleep cancelled on retry fails cleanly.
	calls.Store(0)
	c.Opts.Sleep = func(context.Context, time.Duration) error { return context.DeadlineExceeded }
	if _, _, err := c.Complete(context.Background(), "openai", "fast", "", []Message{{Role: "user", Content: "hi"}}, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded from sleep, got %v", err)
	}
}

func expandTildeResult(t *testing.T, p string) string {
	t.Helper()
	got, err := expandTilde(p)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestAllProviderEdgePathsAndErrors(t *testing.T) {
	// Ollama text + schema + all params, plus truncated stream & error JSON line.
	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "truncate") {
			fmt.Fprintln(w, `{"model":"m","message":{"content":"partial"},"done":false}`)
			return
		}
		if strings.Contains(string(body), "chunkerr") {
			fmt.Fprintln(w, `{"error":"model vanished"}`)
			return
		}
		if strings.Contains(string(body), "badjson") {
			fmt.Fprintln(w, `{bad`)
			return
		}
		fmt.Fprintln(w, `{"model":"m","message":{"content":"{\"ok\":true}"},"done":true,"done_reason":"stop"}`)
	}))
	defer ollamaSrv.Close()
	t.Setenv("OLLAMA_HOST", ollamaSrv.URL)
	pOllama, _ := Lookup("ollama")
	epOllama, err := pOllama.Endpoint(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	topP := 0.9
	maxTok := 128
	resp, err := pOllama.Chat(context.Background(), epOllama, Request{
		Model:    "qwen2.5:0.5b",
		Messages: []Message{{Role: "user", Content: "good"}},
		Params:   Params{TopP: &topP, MaxTokens: &maxTok, Stop: []string{"END"}},
		Schema:   json.RawMessage(`{"type":"object"}`),
	}, map[string]bool{}, nil)
	if err != nil || resp.Text != `{"ok":true}` {
		t.Fatalf("ollama full options failed: resp=%+v err=%v", resp, err)
	}
	for _, probe := range []string{"truncate", "chunkerr", "badjson"} {
		if _, err := pOllama.Chat(context.Background(), epOllama, Request{Model: "m", Messages: []Message{{Role: "user", Content: probe}}}, map[string]bool{}, nil); err == nil {
			t.Fatalf("expected error for ollama probe %s", probe)
		}
	}

	// Anthropic text_delta + multiple system prompts + truncation + invalid JSON event.
	antSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		if strings.Contains(string(body), "badjson") {
			fmt.Fprint(w, "data: {not-json\n\n")
			return
		}
		if strings.Contains(string(body), "trunc") {
			fmt.Fprint(w, "data: {\"type\":\"message_start\",\"message\":{\"model\":\"c\"}}\n\n")
			return
		}
		fmt.Fprint(w, "data: {\"type\":\"message_start\",\"message\":{\"model\":\"c\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"message_stop\"}\n\n")
	}))
	defer antSrv.Close()
	t.Setenv("ANTHROPIC_BASE_URL", antSrv.URL)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-testkey0123456789")
	pAnt, _ := Lookup("anthropic")
	epAnt, _ := pAnt.Endpoint(Config{}, nil)
	antResp, err := pAnt.Chat(context.Background(), epAnt, Request{
		Model:    "claude-sonnet-5-5",
		Messages: []Message{{Role: "system", Content: "s1"}, {Role: "system", Content: "s2"}, {Role: "user", Content: "ok"}},
		Params:   Params{TopP: &topP, MaxTokens: &maxTok, Stop: []string{"STOP"}},
	}, map[string]bool{}, nil)
	if err != nil || antResp.Text != "hello" {
		t.Fatalf("anthropic text_delta failed: resp=%+v err=%v", antResp, err)
	}
	for _, probe := range []string{"badjson", "trunc"} {
		if _, err := pAnt.Chat(context.Background(), epAnt, Request{Model: "c", Messages: []Message{{Role: "user", Content: probe}}}, map[string]bool{}, nil); err == nil {
			t.Fatalf("expected error for anthropic probe %s", probe)
		}
	}

	// OpenAI stream chunk error, truncation, invalid JSON, and schema option.
	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		if strings.Contains(string(body), "chunkerr") {
			fmt.Fprint(w, "data: {\"error\":{\"message\":\"boom\"}}\n\n")
			return
		}
		if strings.Contains(string(body), "trunc") {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n")
			return
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer oaiSrv.Close()
	t.Setenv("OPENAI_BASE_URL", oaiSrv.URL)
	pOAI, _ := Lookup("openai")
	epOAI, _ := pOAI.Endpoint(Config{APIKey: "k"}, nil)
	if _, err := pOAI.Chat(context.Background(), epOAI, Request{
		Model: "gpt-4o", Messages: []Message{{Role: "user", Content: "ok"}},
		Params: Params{TopP: &topP, MaxTokens: &maxTok, Stop: []string{"END"}},
		Schema: json.RawMessage(`{"type":"object"}`),
	}, map[string]bool{}, nil); err != nil {
		t.Fatalf("openai full params failed: %v", err)
	}
	for _, probe := range []string{"chunkerr", "trunc"} {
		if _, err := pOAI.Chat(context.Background(), epOAI, Request{Model: "gpt-4o", Messages: []Message{{Role: "user", Content: probe}}}, map[string]bool{}, nil); err == nil {
			t.Fatalf("expected error for openai probe %s", probe)
		}
	}

	// Misc transport & URL error paths.
	if _, err := validateBaseURL("ftp://example.com", false, false); err == nil {
		t.Fatal("expected invalid scheme error")
	}
	if _, err := validateBaseURL("https://", false, false); err == nil {
		t.Fatal("expected empty host error")
	}
	if got := excerpt("a\x00bcde", 4); got != "a bc" {
		t.Fatalf("unexpected excerpt: %q", got)
	}
	if got, _ := endpointURL(Endpoint{Base: epOAI.Base}, "/v1/x?a=1"); !strings.Contains(got, "?a=1") {
		t.Fatalf("unexpected endpointURL: %q", got)
	}
	if _, _, err := NewClient(nil).Complete(context.Background(), "bogus", "fast", "", nil, nil, nil); err == nil {
		t.Fatal("expected unknown provider error")
	}
}
