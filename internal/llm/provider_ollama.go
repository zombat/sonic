// Package llm implements the Ollama direct-HTTP NDJSON chat provider.
package llm

import (
	"context"
	"encoding/json"
	"os"
)

const defaultOllamaURL = "http://127.0.0.1:11434"

func init() {
	mustRegister(ollamaProvider{})
}

type ollamaProvider struct{}

func (ollamaProvider) Name() string            { return "ollama" }
func (ollamaProvider) NeedsKey() bool          { return false }
func (ollamaProvider) SupportsStreaming() bool { return false }
func (ollamaProvider) Accepts(string) bool     { return true }
func (ollamaProvider) WireName(p string) string {
	if p == ParamMaxTokens {
		return "num_predict"
	}
	if p == ParamSchema {
		return "format"
	}
	return p
}

func (ollamaProvider) Endpoint(cfg Config, _ *CredentialStore) (Endpoint, error) {
	raw := os.Getenv("OLLAMA_HOST")
	if raw == "" {
		raw = os.Getenv("OLLAMA_BASE_URL")
	}
	if raw == "" {
		raw = defaultOllamaURL
	}
	u, err := validateBaseURL(raw, false, true)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Base: u, Client: newHTTPClient(cfg.HTTPClient)}, nil
}

type ollamaOptions struct {
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	NumPredict  *int     `json:"num_predict,omitempty"`
	Stop        []string `json:"stop,omitempty"`
}

type ollamaChatReq struct {
	Model    string          `json:"model"`
	Messages []Message       `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  *ollamaOptions  `json:"options,omitempty"`
	Format   json.RawMessage `json:"format,omitempty"`
}

func (ollamaProvider) Chat(ctx context.Context, ep Endpoint, req Request, omit map[string]bool, onToken func(string)) (Response, error) {
	p := req.Params
	var opts ollamaOptions
	hasOpts := false
	if p.Temperature != nil && !omit[ParamTemperature] {
		opts.Temperature = p.Temperature
		hasOpts = true
	}
	if p.TopP != nil && !omit[ParamTopP] {
		opts.TopP = p.TopP
		hasOpts = true
	}
	if p.MaxTokens != nil && !omit[ParamMaxTokens] {
		opts.NumPredict = p.MaxTokens
		hasOpts = true
	}
	if len(p.Stop) > 0 && !omit[ParamStop] {
		opts.Stop = p.Stop
		hasOpts = true
	}
	wire := ollamaChatReq{
		Model:    req.Model,
		Messages: req.Messages,
		Stream:   true,
	}
	if hasOpts {
		wire.Options = &opts
	}
	if len(req.Schema) > 0 && !omit[ParamSchema] {
		wire.Format = req.Schema
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return Response{}, err
	}
	resp, err := postRawJSON(ctx, ep, "/api/chat", nil, body)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var out Response
	var text boundedAnswer
	finished := false
	err = ndjson(resp.Body, func(line []byte) error {
		var chunk struct {
			Model   string `json:"model"`
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done            bool   `json:"done"`
			DoneReason      string `json:"done_reason"`
			PromptEvalCount int    `json:"prompt_eval_count"`
			EvalCount       int    `json:"eval_count"`
			Error           string `json:"error"`
		}
		if jerr := json.Unmarshal(line, &chunk); jerr != nil {
			return &APIError{Streamed: true, Message: "stream line is not valid JSON: " + jerr.Error()}
		}
		if chunk.Error != "" {
			return &APIError{Status: 500, Streamed: true, Message: excerpt(chunk.Error, maxExcerpt)}
		}
		if chunk.Model != "" {
			out.Model = chunk.Model
		}
		if chunk.Done {
			finished = true
			out.InputTokens = chunk.PromptEvalCount
			out.OutputTokens = chunk.EvalCount
			out.StopReason = chunk.DoneReason
			out.Reported = true
		}
		return text.add(chunk.Message.Content, onToken)
	})
	if err != nil {
		return Response{}, err
	}
	if !finished {
		return Response{}, &APIError{Streamed: true, Message: "the stream ended before completion"}
	}
	out.Text = text.b.String()
	return out, nil
}
