package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func floatPtr(v float64) *float64 { return &v }
func intPtr(v int) *int           { return &v }

func TestProviderRegistryAndModelResolution(t *testing.T) {
	names := Names()
	want := []string{"anthropic", "azure", "ollama", "openai"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
	if err := Register(nil); err == nil {
		t.Fatal("expected error registering nil provider")
	}
	if err := Register(ollamaProvider{}); err == nil {
		t.Fatal("expected error registering duplicate ollama provider")
	}
	if _, ok := Lookup("unknown"); ok {
		t.Fatal("expected Lookup(unknown) = false")
	}

	if got := GetModelName("anthropic", "deep", ""); got != "claude-opus-5-5" {
		t.Fatalf("anthropic deep = %q", got)
	}
	if got := GetModelName("ollama", "deep", ""); got != "mistral:7b" {
		t.Fatalf("ollama deep fallback = %q", got)
	}
	if got := GetModelName("openai", "bogus", ""); got != "gpt-4o-mini" {
		t.Fatalf("openai bogus profile = %q", got)
	}
	if got := GetModelName("ollama", "fast", "llama3:8b"); got != "llama3:8b" {
		t.Fatalf("model override = %q", got)
	}
}

func TestCredentialStoreAndResolution(t *testing.T) {
	t.Setenv("SONIC_LLM_PROVIDER", "")
	t.Setenv("SONIC_ENV_FILE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("AZURE_OPENAI_KEY", "")

	if ResolveProvider("") != DefaultProvider {
		t.Fatalf("default provider = %q", ResolveProvider(""))
	}
	t.Setenv("SONIC_LLM_PROVIDER", "anthropic")
	if ResolveProvider("") != "anthropic" || ResolveProvider("openai") != "openai" {
		t.Fatalf("ResolveProvider mismatch")
	}

	envPath := filepath.Join(t.TempDir(), "keys.env")
	secretAnt := "sk-ant-api03-file-secret-1234567890"
	secretOAI := "sk-proj-env-override-1234567890abcd"
	if err := os.WriteFile(envPath, []byte("ANTHROPIC_API_KEY='"+secretAnt+"'\nOPENAI_API_KEY=\"ignored\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENAI_API_KEY", secretOAI)

	store, err := NewCredentialStore(envPath)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		t.Fatal("CredentialStore leaked dotenv secret into os.Environ")
	}
	if store.APIKeyFor("ANTHROPIC_API_KEY") != secretAnt || store.APIKeyFor("OPENAI_API_KEY") != secretOAI {
		t.Fatal("CredentialStore lookup precedence mismatch")
	}
	listing := ListProviders(store)
	raw, _ := json.Marshal(listing)
	if strings.Contains(string(raw), secretAnt) || strings.Contains(string(raw), secretOAI) {
		t.Fatalf("ListProviders leaked secret: %s", raw)
	}
	if !listing.CurrentConfig.AnthropicKeySet || !listing.CurrentConfig.OpenAIKeySet || listing.CurrentConfig.Provider != "anthropic" {
		t.Fatalf("unexpected ListProviders config: %+v", listing.CurrentConfig)
	}
	redacted := store.Redact("tok=" + secretAnt + " oai=" + secretOAI)
	if strings.Contains(redacted, secretAnt) || strings.Contains(redacted, secretOAI) {
		t.Fatalf("Redact failed: %s", redacted)
	}

	badPath := filepath.Join(t.TempDir(), "bad.env")
	_ = os.WriteFile(badPath, []byte("not_a_valid_line\n"), 0o600)
	if _, err := NewCredentialStore(badPath); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("expected EnvFileError, got %v", err)
	}
	if _, err := NewCredentialStore("/no/such/sonic.env"); err == nil {
		t.Fatal("expected missing env file error")
	}
	binPath := filepath.Join(t.TempDir(), "bin.env")
	_ = os.WriteFile(binPath, []byte{0xff, 0xfe, 0x00}, 0o600)
	if _, err := NewCredentialStore(binPath); err == nil {
		t.Fatal("expected invalid UTF-8 env file error")
	}
}

func TestOllamaDirectHTTPAndStreaming(t *testing.T) {
	var seenBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		seenBody = string(b)
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintln(w, `{"model":"qwen2.5:0.5b","message":{"content":"hello "},"done":false}`)
		fmt.Fprintln(w, `{"model":"qwen2.5:0.5b","message":{"content":"world sk-ant-api03-leaksecretvalue999"},"done":true,"done_reason":"stop","prompt_eval_count":10,"eval_count":5}`)
	}))
	defer srv.Close()

	t.Setenv("OLLAMA_HOST", srv.URL)
	t.Setenv("SONIC_LLM_PROVIDER", "")
	store, _ := NewCredentialStore("")
	client := NewClient(store)

	var streamed []string
	resp, usage, err := client.Complete(
		context.Background(), "ollama", "fast", "",
		[]Message{{Role: "user", Content: "check secret sk-ant-api03-outboundsecret123"}},
		nil,
		func(tok string) { streamed = append(streamed, tok) },
	)
	if err != nil {
		t.Fatalf("ollama Complete error: %v", err)
	}
	if strings.Contains(seenBody, "outboundsecret123") {
		t.Fatalf("outbound prompt was not redacted: %s", seenBody)
	}
	if strings.Contains(resp.Text, "leaksecretvalue999") || strings.Contains(strings.Join(streamed, ""), "leaksecretvalue999") {
		t.Fatalf("inbound response/stream was not redacted: text=%q streamed=%v", resp.Text, streamed)
	}
	if !usage.Reported || usage.InputTokens != 10 || usage.OutputTokens != 5 {
		t.Fatalf("unexpected usage: %+v", usage)
	}
}

func TestAnthropicDirectHTTPNoTemperatureAndStructured(t *testing.T) {
	key := "sk-ant-api03-testkey0123456789abcdef"
	var sawPayload map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != key || r.Header.Get("anthropic-version") != anthropicVersion {
			http.Error(w, `{"error":{"message":"bad auth"}}`, http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &sawPayload)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5-5\",\"usage\":{\"input_tokens\":12}}}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"ok\\\":true}\"}}\n\n")
		fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":4}}\n\n")
		fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	t.Setenv("ANTHROPIC_API_KEY", key)
	store, _ := NewCredentialStore("")
	client := NewClient(store)

	var streamed strings.Builder
	resp, usage, err := client.Complete(
		context.Background(), "anthropic", "detailed", "",
		[]Message{{Role: "system", Content: "sys"}, {Role: "user", Content: "hi"}},
		json.RawMessage(`{"type":"object"}`),
		func(tok string) { streamed.WriteString(tok) },
	)
	if err != nil {
		t.Fatalf("anthropic Complete failed: %v", err)
	}
	if _, hasTemp := sawPayload["temperature"]; hasTemp {
		t.Fatal("anthropic must not send temperature")
	}
	if resp.Text != `{"ok":true}` || streamed.String() != `{"ok":true}` || !slicesContain(usage.Ignored, ParamTemperature) {
		t.Fatalf("unexpected response/usage: resp=%+v usage=%+v", resp, usage)
	}
}

func TestOpenAIParamDropRetryRedirectAndAzure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch {
		case strings.HasPrefix(r.URL.Path, "/redirect"):
			http.Redirect(w, r, "https://evil.example/", http.StatusFound)
			return
		case n == 1:
			w.Header().Set("Retry-After", "0")
			http.Error(w, `{"error":{"message":"rate limit"}}`, http.StatusTooManyRequests)
			return
		case n == 2:
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "stream_options") {
				http.Error(w, `{"error":{"message":"unsupported parameter: stream_options"}}`, http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"done\"}}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":2}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	t.Setenv("OPENAI_BASE_URL", srv.URL)
	t.Setenv("OPENAI_API_KEY", "")
	store, _ := NewCredentialStore("")
	client := NewClient(store)
	client.Opts = CallOptions{
		Retries: 2,
		Backoff: time.Millisecond,
		Sleep:   func(context.Context, time.Duration) error { return nil },
	}

	resp, usage, err := client.Complete(context.Background(), "openai", "detailed", "", []Message{{Role: "user", Content: "test"}}, nil, nil)
	if err != nil {
		t.Fatalf("openai retry/drop failed: %v", err)
	}
	if resp.Text != "done" || usage.Retries != 1 || !slicesContain(usage.Dropped, ParamStreamOptions) {
		t.Fatalf("unexpected openai result: resp=%+v usage=%+v", resp, usage)
	}

	// Azure missing endpoint rejected cleanly; configured Azure hits deployment URL with api-key header.
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")
	t.Setenv("AZURE_OPENAI_KEY", "az-secret-1234567890")
	if _, _, err := client.Complete(context.Background(), "azure", "fast", "", []Message{{Role: "user", Content: "x"}}, nil, nil); err == nil {
		t.Fatal("expected azure missing endpoint error")
	}
	var gotHeader, gotPath string
	azSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("api-key")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"az\"},\"finish_reason\":\"stop\"}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer azSrv.Close()
	t.Setenv("AZURE_OPENAI_ENDPOINT", azSrv.URL)
	azResp, _, err := client.Complete(context.Background(), "azure", "fast", "", []Message{{Role: "user", Content: "x"}}, nil, nil)
	if err != nil || azResp.Text != "az" || gotHeader != "az-secret-1234567890" || !strings.Contains(gotPath, "/openai/deployments/gpt-4o-mini/chat/completions") {
		t.Fatalf("unexpected azure result: resp=%+v err=%v header=%q path=%q", azResp, err, gotHeader, gotPath)
	}

	// Non-loopback plaintext HTTP with key refused; redirect refused without forwarding credentials.
	if _, err := validateBaseURL("http://api.example.com/v1", true, false); err == nil {
		t.Fatal("expected non-HTTPS API key rejection")
	}
	if _, err := validateBaseURL("http://user:pass@localhost:11434", false, true); err == nil {
		t.Fatal("expected userinfo rejection")
	}
	p, _ := Lookup("openai")
	u, _ := validateBaseURL(srv.URL+"/redirect", false, true)
	ep := Endpoint{Base: u, Client: newHTTPClient(nil)}
	if _, err := postRawJSON(context.Background(), ep, "", nil, []byte(`{}`)); err == nil {
		t.Fatal("expected redirect refusal error")
	}
	var apiErr *APIError
	apiErrStreamed := &APIError{Status: 500, Streamed: true}
	if apiErrStreamed.Retryable() {
		t.Fatal("streamed error must never be retryable")
	}
	apiErr429 := &APIError{Status: 429}
	if !apiErr429.Retryable() || !(&APIError{Network: true}).Retryable() {
		t.Fatal("429 and network errors should be retryable")
	}
	_ = apiErr
	_ = p
}

func TestStreamErrorCasesAndTruncations(t *testing.T) {
	// Streamed error inside SSE must NOT retry even with Retries > 0.
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy sk-ant-api03-errsecret\"}}\n\n")
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-testkey0123456789")
	store, _ := NewCredentialStore("")
	c := NewClient(store)
	c.Opts = CallOptions{Retries: 3, Backoff: time.Millisecond, Sleep: func(context.Context, time.Duration) error { return nil }}
	_, _, err := c.Complete(context.Background(), "anthropic", "fast", "", []Message{{Role: "user", Content: "x"}}, nil, nil)
	if err == nil || attempts.Load() != 1 || strings.Contains(err.Error(), "errsecret") {
		t.Fatalf("expected 1 attempt with redacted streamed error, got attempts=%d err=%v", attempts.Load(), err)
	}

	// Anthropic missing key fails before dialing.
	t.Setenv("ANTHROPIC_API_KEY", "")
	emptyStore, _ := NewCredentialStore("")
	if _, _, err := NewClient(emptyStore).Complete(context.Background(), "anthropic", "fast", "", []Message{{Role: "user", Content: "x"}}, nil, nil); err == nil {
		t.Fatal("expected missing API key error")
	}

	// Drops cleared when retries fail.
	p, _ := Lookup("openai")
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"unsupported parameter: temperature and always broken"}`, http.StatusBadRequest)
	}))
	defer badSrv.Close()
	u, _ := validateBaseURL(badSrv.URL, false, true)
	drops := Drops{}
	_, _, err = Call(context.Background(), p, Endpoint{Base: u, Client: newHTTPClient(nil)}, Request{
		Model: "gpt-4o", Messages: []Message{{Role: "user", Content: "x"}}, Params: Params{Temperature: floatPtr(0.5), TopP: floatPtr(0.9), MaxTokens: intPtr(10), Stop: []string{"END"}},
	}, drops, CallOptions{}, emptyStore, nil)
	if err == nil || drops[ParamTemperature] {
		t.Fatalf("expected failure and reverted drop, err=%v drops=%v", err, drops)
	}

	// Verify APIError.Error variants and Sleep cancellation.
	if !strings.Contains((&APIError{Network: true, Message: "down"}).Error(), "could not be reached") {
		t.Fatal("unexpected Network error formatting")
	}
	if !strings.Contains((&APIError{Status: 502, Streamed: true, Message: "cut"}).Error(), "stopped partway") {
		t.Fatal("unexpected Streamed error formatting")
	}
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctxCancel, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func slicesContain(items []string, want string) bool {
	for _, s := range items {
		if s == want {
			return true
		}
	}
	return false
}
