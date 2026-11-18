// Package llm handles bounded HTTP JSON posts, origin validation, SSE, and
// NDJSON stream decoding matching ~/auto-roboto/pkg/aiprovider transport rigor.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	maxLineBytes = 4 << 20
	maxErrorBody = 64 << 10
	maxAnswer    = 16 << 20
	maxExcerpt   = 512
)

// validateBaseURL ensures provider origins carry http/https without embedded credentials
// and forbids sending API keys over cleartext non-loopback http:// URLs.
func validateBaseURL(raw string, hasKey, allowPlaintext bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid provider base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("provider URL must use http or https scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("provider URL %q has an empty host", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("provider URL must not embed credentials in authority")
	}
	if u.Scheme == "http" && hasKey && !allowPlaintext && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("refusing to send API key over non-HTTPS non-loopback URL %q", u.Host)
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newHTTPClient builds a hardened HTTP client with TLS >= 1.2 and redirect blocking.
func newHTTPClient(override *http.Client) *http.Client {
	if override != nil {
		cloned := *override
		if cloned.CheckRedirect == nil {
			cloned.CheckRedirect = refuseRedirects
		}
		return &cloned
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.TLSHandshakeTimeout = 15 * time.Second
	tr.ResponseHeaderTimeout = 60 * time.Second
	return &http.Client{
		Transport:     tr,
		CheckRedirect: refuseRedirects,
	}
}

func refuseRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func endpointURL(ep Endpoint, ref string) (string, error) {
	if ep.Base == nil {
		return "", errors.New("llm: endpoint missing base URL")
	}
	rel, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("parse provider endpoint path %q: %w", ref, err)
	}
	baseCopy := *ep.Base
	basePath := strings.TrimRight(baseCopy.Path, "/")
	relPath := rel.EscapedPath()
	if relPath != "" && !strings.HasPrefix(relPath, "/") {
		relPath = "/" + relPath
	}
	baseCopy.Path = basePath + relPath
	baseCopy.RawPath = ""
	if rel.RawQuery != "" {
		if baseCopy.RawQuery != "" {
			baseCopy.RawQuery += "&" + rel.RawQuery
		} else {
			baseCopy.RawQuery = rel.RawQuery
		}
	}
	return baseCopy.String(), nil
}

func postRawJSON(ctx context.Context, ep Endpoint, ref string, headers map[string]string, payload []byte) (*http.Response, error) {
	u, err := endpointURL(ep, ref)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build provider request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream, application/x-ndjson, application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := ep.Client
	if client == nil {
		return nil, errors.New("llm: endpoint missing HTTP client")
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &APIError{Network: true, Message: excerpt(err.Error(), maxExcerpt)}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	return nil, &APIError{
		Status:     resp.StatusCode,
		Message:    parseErrorMessage(body),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
}

func parseErrorMessage(body []byte) string {
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil && len(envelope.Error) > 0 {
		var strMsg string
		if json.Unmarshal(envelope.Error, &strMsg) == nil && strMsg != "" {
			return excerpt(strMsg, maxExcerpt)
		}
		var nested struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(envelope.Error, &nested) == nil && nested.Message != "" {
			return excerpt(nested.Message, maxExcerpt)
		}
	}
	return excerpt(strings.TrimSpace(string(body)), maxExcerpt)
}

func parseRetryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 || n > 3600 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// excerpt bounds untrusted provider strings to limit runes and strips control bytes.
func excerpt(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	var sb strings.Builder
	count := 0
	for _, r := range s {
		if count >= limit {
			break
		}
		if unicode.IsControl(r) && r != ' ' && r != '\t' && r != '\n' {
			sb.WriteRune(' ')
		} else {
			sb.WriteRune(r)
		}
		count++
	}
	return sb.String()
}

// sseEvents decodes a server-sent events response stream into per-event callbacks.
func sseEvents(body io.Reader, fn func(event string, data []byte) error) error {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	event := ""
	var data []byte

	flush := func() error {
		if data == nil {
			return nil
		}
		err := fn(event, data)
		event, data = "", nil
		return err
	}

	for sc.Scan() {
		line := bytes.TrimSuffix(sc.Bytes(), []byte("\r"))
		switch {
		case len(line) == 0:
			if err := flush(); err != nil {
				return err
			}
		case bytes.HasPrefix(line, []byte(":")):
		case bytes.HasPrefix(line, []byte("event:")):
			event = strings.TrimSpace(string(line[len("event:"):]))
		case bytes.HasPrefix(line, []byte("data:")):
			d := bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" "))
			if len(data)+len(d)+1 > maxAnswer {
				return &APIError{Streamed: true, Message: fmt.Sprintf("an event exceeded %d bytes", maxAnswer)}
			}
			if data != nil {
				data = append(data, '\n')
			}
			data = append(data, d...)
		}
	}
	if err := sc.Err(); err != nil {
		return &APIError{Streamed: true, Message: excerpt(err.Error(), maxExcerpt)}
	}
	return flush()
}

// ndjson decodes a newline-delimited JSON response stream line by line.
func ndjson(body io.Reader, fn func(line []byte) error) error {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return &APIError{Streamed: true, Message: excerpt(err.Error(), maxExcerpt)}
	}
	return nil
}

type boundedAnswer struct {
	b strings.Builder
}

func (a *boundedAnswer) add(chunk string, onToken func(string)) error {
	if chunk == "" {
		return nil
	}
	if a.b.Len()+len(chunk) > maxAnswer {
		return &APIError{Streamed: true, Message: fmt.Sprintf("the answer exceeded %d bytes", maxAnswer)}
	}
	a.b.WriteString(chunk)
	if onToken != nil {
		onToken(chunk)
	}
	return nil
}
