// Package llm provides direct-HTTP, streaming, credential-redacting LLM
// clients behind the Provider and Completer interfaces without external SDKs.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

const (
	// DefaultProvider is used when no explicit provider or SONIC_LLM_PROVIDER is set.
	DefaultProvider = "ollama"
	// ProviderVariable selects the default provider from process environment.
	ProviderVariable = "SONIC_LLM_PROVIDER"
	// ProfileFast selects the small low-latency model for a provider.
	ProfileFast = "fast"
	// ProfileDetailed selects the primary reasoning model for a provider.
	ProfileDetailed = "detailed"
	// ProfileDeep selects the highest-capability model (or Detailed fallback).
	ProfileDeep = "deep"

	// ParamTemperature controls sampling temperature when supported by the provider.
	ParamTemperature = "temperature"
	// ParamTopP controls nucleus sampling when supported.
	ParamTopP = "top_p"
	// ParamMaxTokens bounds generated output tokens.
	ParamMaxTokens = "max_tokens"
	// ParamStop defines stop sequences.
	ParamStop = "stop"
	// ParamSchema requests JSON schema output conformance.
	ParamSchema = "schema"
	// ParamStreamOptions requests token usage in OpenAI-compatible streams.
	ParamStreamOptions = "stream_options"
)

// Profiles lists supported model tier names in ascending capability order.
var Profiles = []string{ProfileFast, ProfileDetailed, ProfileDeep}

// Config configures provider selection, model override, and default sampling limits.
type Config struct {
	Provider    string
	ModelName   string
	APIKey      string `json:"-"`
	Temperature float64
	MaxTokens   int
	// HTTPClient optionally overrides the HTTP transport client (used in unit tests).
	HTTPClient *http.Client
	// AllowPlaintextCredentials permits non-loopback http:// endpoints in local test harnesses.
	AllowPlaintextCredentials bool
}

// Endpoint describes a validated provider origin, HTTP client, and credential.
type Endpoint struct {
	Base       *url.URL
	Client     *http.Client
	Key        string `json:"-"`
	APIVersion string
}

// Message is one chat turn sent to a Provider.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Params holds optional generation settings; nil fields are omitted on the wire.
type Params struct {
	Temperature *float64
	TopP        *float64
	MaxTokens   *int
	Stop        []string
}

// Request represents one streaming or single-turn chat completion request.
type Request struct {
	Model    string
	Messages []Message
	Params   Params
	Schema   json.RawMessage
}

// Set returns the parameter names configured on req in canonical order.
func (r Request) Set() []string {
	var out []string
	p := r.Params
	for _, item := range []struct {
		name string
		set  bool
	}{
		{ParamTemperature, p.Temperature != nil},
		{ParamTopP, p.TopP != nil},
		{ParamMaxTokens, p.MaxTokens != nil},
		{ParamStop, len(p.Stop) > 0},
		{ParamSchema, len(r.Schema) > 0},
	} {
		if item.set {
			out = append(out, item.name)
		}
	}
	return out
}

// Response captures the completed assistant text and provider metadata.
type Response struct {
	Text         string
	InputTokens  int
	OutputTokens int
	Reported     bool
	Model        string
	StopReason   string
}

// Usage records provider metrics, retries, and omitted parameters for one Call.
type Usage struct {
	Provider     string        `json:"provider"`
	Model        string        `json:"model"`
	InputTokens  int           `json:"input_tokens"`
	OutputTokens int           `json:"output_tokens"`
	Reported     bool          `json:"usage_reported"`
	Duration     time.Duration `json:"duration"`
	Retries      int           `json:"retries"`
	Ignored      []string      `json:"ignored,omitempty"`
	Dropped      []string      `json:"dropped,omitempty"`
}

// CallOptions controls retry limits and backoff timing in Call.
type CallOptions struct {
	Retries int
	Backoff time.Duration
	Sleep   func(context.Context, time.Duration) error
}

// Drops remembers parameters rejected by an HTTP 400 response so retries drop them.
type Drops map[string]bool

// Provider abstracts a direct-HTTP language model vendor API.
type Provider interface {
	Name() string
	NeedsKey() bool
	SupportsStreaming() bool
	Accepts(param string) bool
	WireName(param string) string
	Endpoint(cfg Config, creds *CredentialStore) (Endpoint, error)
	Chat(ctx context.Context, ep Endpoint, req Request, omit map[string]bool, onToken func(string)) (Response, error)
}

// Completer executes one redacted chat completion with optional token streaming.
type Completer interface {
	Complete(ctx context.Context, provider, profile, modelName string, messages []Message, schema json.RawMessage, onToken func(string)) (Response, Usage, error)
}

// APIError captures an HTTP, network, or mid-stream error from a provider.
type APIError struct {
	Status     int
	Message    string
	RetryAfter time.Duration
	Streamed   bool
	Network    bool
}

// Error implements the error interface for APIError.
func (e *APIError) Error() string {
	switch {
	case e.Network:
		return "the provider could not be reached: " + e.Message
	case e.Streamed:
		return fmt.Sprintf("the answer stopped partway (status %d): %s", e.Status, e.Message)
	default:
		return fmt.Sprintf("status %d: %s", e.Status, e.Message)
	}
}

// Retryable reports whether retrying the call may succeed without double-billing.
func (e *APIError) Retryable() bool {
	if e.Streamed {
		return false
	}
	if e.Network {
		return true
	}
	switch e.Status {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		529:
		return true
	}
	return false
}

var (
	regMu     sync.RWMutex
	providers = make(map[string]Provider)
)

// Register adds a Provider implementation to the global registry.
func Register(p Provider) error {
	regMu.Lock()
	defer regMu.Unlock()
	if p == nil || p.Name() == "" {
		return fmt.Errorf("llm: provider name must be non-empty")
	}
	if _, dup := providers[p.Name()]; dup {
		return fmt.Errorf("llm: provider %q already registered", p.Name())
	}
	providers[p.Name()] = p
	return nil
}

func mustRegister(p Provider) {
	if err := Register(p); err != nil {
		panic(err)
	}
}

// Lookup retrieves a registered Provider by name.
func Lookup(name string) (Provider, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	p, ok := providers[name]
	return p, ok
}

// Names returns all registered provider names in sorted order.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(providers))
	for name := range providers {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
