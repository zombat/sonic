// Package llm implements redacting Request/Response wrappers, retry/drop logic,
// and Client execution through the Provider interface.
package llm

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"
)

// Client calls registered Providers through Call with shared credentials and retry policy.
type Client struct {
	mu    sync.Mutex
	Creds *CredentialStore
	Drops Drops
	Opts  CallOptions
	Base  Config
}

// NewClient creates a redacting LLM Completer backed by creds.
func NewClient(creds *CredentialStore) *Client {
	return &Client{
		Creds: creds,
		Drops: make(Drops),
		Opts:  CallOptions{Retries: 2, Backoff: time.Second},
	}
}

// Complete implements Completer by resolving the provider endpoint, enforcing redaction,
// and invoking Call with direct HTTP streaming.
func (c *Client) Complete(
	ctx context.Context,
	providerName, profile, modelName string,
	messages []Message,
	schema json.RawMessage,
	onToken func(string),
) (Response, Usage, error) {
	resolved := ResolveProvider(providerName)
	p, ok := Lookup(resolved)
	if !ok {
		return Response{}, Usage{}, fmt.Errorf("unknown LLM provider: %s", resolved)
	}
	cfg := NewConfig(resolved, modelName, c.Base.APIKey, c.Creds)
	cfg.HTTPClient = c.Base.HTTPClient
	cfg.AllowPlaintextCredentials = c.Base.AllowPlaintextCredentials
	ep, err := p.Endpoint(cfg, c.Creds)
	if err != nil {
		return Response{}, Usage{}, fmt.Errorf("configure provider %s: %s", resolved, c.Creds.Redact(err.Error()))
	}
	req := Request{
		Model:    GetModelName(resolved, profile, modelName),
		Messages: messages,
		Params: Params{
			Temperature: &cfg.Temperature,
			MaxTokens:   &cfg.MaxTokens,
		},
		Schema: schema,
	}
	c.mu.Lock()
	localDrops := maps.Clone(c.Drops)
	c.mu.Unlock()
	if localDrops == nil {
		localDrops = make(Drops)
	}
	resp, usage, cerr := Call(ctx, p, ep, req, localDrops, c.Opts, c.Creds, onToken)
	if cerr == nil && len(usage.Dropped) > 0 {
		c.mu.Lock()
		if c.Drops == nil {
			c.Drops = make(Drops)
		}
		for _, param := range usage.Dropped {
			c.Drops[param] = true
		}
		c.mu.Unlock()
	}
	return resp, usage, cerr
}

// Call executes req through p with outbound/inbound redaction, 400 parameter dropping,
// and bounded backoff retries matching ~/auto-roboto/pkg/aiprovider/call.go.
func Call(
	ctx context.Context,
	p Provider,
	ep Endpoint,
	req Request,
	drops Drops,
	opts CallOptions,
	creds *CredentialStore,
	onToken func(string),
) (Response, Usage, error) {
	if drops == nil {
		drops = make(Drops)
	}
	redactedReq := redactRequest(req, creds)
	var learned []string
	resp, usage, err := callWithDrops(ctx, p, ep, redactedReq, drops, opts, creds, onToken, &learned)
	if err != nil {
		for _, param := range learned {
			delete(drops, param)
			usage.Dropped = slices.DeleteFunc(usage.Dropped, func(d string) bool { return d == param })
		}
		return Response{}, usage, redactError(err, creds)
	}
	resp.Text = creds.Redact(resp.Text)
	resp.Model = creds.Redact(excerpt(resp.Model, 128))
	resp.StopReason = creds.Redact(excerpt(resp.StopReason, 64))
	return resp, usage, nil
}

func redactError(err error, creds *CredentialStore) error {
	if err == nil {
		return nil
	}
	orig := err.Error()
	cleaned := creds.Redact(orig)
	if cleaned == orig {
		return err
	}
	return errors.New(cleaned)
}

func redactRequest(req Request, creds *CredentialStore) Request {
	cleaned := make([]Message, len(req.Messages))
	for i, m := range req.Messages {
		cleaned[i] = Message{
			Role:    m.Role,
			Content: creds.Redact(m.Content),
		}
	}
	req.Messages = cleaned
	return req
}

func callWithDrops(
	ctx context.Context,
	p Provider,
	ep Endpoint,
	req Request,
	drops Drops,
	opts CallOptions,
	creds *CredentialStore,
	onToken func(string),
	learned *[]string,
) (Response, Usage, error) {
	usage := Usage{Provider: p.Name(), Model: req.Model}
	if p.NeedsKey() && ep.Key == "" {
		return Response{}, usage, fmt.Errorf("a %s provider needs an API key, and none is configured", p.Name())
	}
	omit := make(map[string]bool)
	for _, param := range req.Set() {
		switch {
		case !p.Accepts(param):
			omit[param] = true
			usage.Ignored = append(usage.Ignored, param)
		case drops[param]:
			omit[param] = true
			usage.Dropped = append(usage.Dropped, param)
		}
	}
	if drops[ParamStreamOptions] {
		omit[ParamStreamOptions] = true
	}

	sleep := opts.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	backoff := opts.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}

	start := time.Now()
	defer func() { usage.Duration = time.Since(start) }()

	for {
		var redactingTokenCB func(string)
		if onToken != nil {
			redactingTokenCB = func(tok string) { onToken(creds.Redact(tok)) }
		}
		resp, err := p.Chat(ctx, ep, req, omit, redactingTokenCB)
		if err == nil {
			usage.InputTokens = resp.InputTokens
			usage.OutputTokens = resp.OutputTokens
			usage.Reported = resp.Reported
			if resp.Model != "" {
				usage.Model = creds.Redact(excerpt(resp.Model, 128))
			}
			usage.Duration = time.Since(start)
			return resp, usage, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return Response{}, usage, err
		}
		if param := rejectedParam(p, req, omit, apiErr); param != "" {
			omit[param] = true
			drops[param] = true
			usage.Dropped = append(usage.Dropped, param)
			*learned = append(*learned, param)
			continue
		}
		if !apiErr.Retryable() || usage.Retries >= opts.Retries {
			if usage.Retries > 0 {
				return Response{}, usage, fmt.Errorf("after %d retries: %w", usage.Retries, err)
			}
			return Response{}, usage, err
		}
		wait := backoff << usage.Retries
		wait += jitter(wait / 2)
		if apiErr.RetryAfter > wait {
			wait = apiErr.RetryAfter
		}
		usage.Retries++
		if serr := sleep(ctx, wait); serr != nil {
			return Response{}, usage, serr
		}
	}
}

func rejectedParam(p Provider, req Request, omit map[string]bool, e *APIError) string {
	if e.Status != 400 {
		return ""
	}
	msg := strings.ToLower(e.Message)
	candidates := append(req.Set(), ParamStreamOptions)
	for _, param := range candidates {
		if omit[param] {
			continue
		}
		wire := strings.ToLower(p.WireName(param))
		if wire != "" && mentionsToken(msg, wire) {
			return param
		}
	}
	return ""
}

func mentionsToken(msg, name string) bool {
	isWord := func(b byte) bool {
		return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	for from := 0; ; {
		at := strings.Index(msg[from:], name)
		if at < 0 {
			return false
		}
		start, end := from+at, from+at+len(name)
		if (start == 0 || !isWord(msg[start-1])) && (end == len(msg) || !isWord(msg[end])) {
			return true
		}
		from = start + 1
	}
}

func jitter(most time.Duration) time.Duration {
	if most <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(most)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
