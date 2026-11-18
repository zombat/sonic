// Package llm implements the OpenAI and Azure OpenAI direct-HTTP providers
// sharing typed SSE chat-completions stream parsing.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

const (
	defaultOpenAIURL       = "https://api.openai.com/v1"
	defaultAzureAPIVersion = "2024-02-15-preview"
)

func init() {
	mustRegister(openaiProvider{})
	mustRegister(azureProvider{})
}

type openaiStreamOpts struct {
	IncludeUsage bool `json:"include_usage"`
}

type openaiJSONSchema struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict"`
}

type openaiRespFormat struct {
	Type       string            `json:"type"`
	JSONSchema *openaiJSONSchema `json:"json_schema,omitempty"`
}

type openaiChatReq struct {
	Model          string            `json:"model"`
	Messages       []Message         `json:"messages"`
	Stream         bool              `json:"stream"`
	StreamOptions  *openaiStreamOpts `json:"stream_options,omitempty"`
	Temperature    *float64          `json:"temperature,omitempty"`
	TopP           *float64          `json:"top_p,omitempty"`
	MaxTokens      *int              `json:"max_tokens,omitempty"`
	Stop           []string          `json:"stop,omitempty"`
	ResponseFormat *openaiRespFormat `json:"response_format,omitempty"`
}

func chatOpenAICompat(
	ctx context.Context,
	ep Endpoint,
	path string,
	headers map[string]string,
	req Request,
	omit map[string]bool,
	onToken func(string),
) (Response, error) {
	wire := openaiChatReq{
		Model:    req.Model,
		Messages: req.Messages,
		Stream:   true,
	}
	if !omit[ParamStreamOptions] {
		wire.StreamOptions = &openaiStreamOpts{IncludeUsage: true}
	}
	p := req.Params
	if p.Temperature != nil && !omit[ParamTemperature] {
		wire.Temperature = p.Temperature
	}
	if p.TopP != nil && !omit[ParamTopP] {
		wire.TopP = p.TopP
	}
	if p.MaxTokens != nil && !omit[ParamMaxTokens] {
		wire.MaxTokens = p.MaxTokens
	}
	if len(p.Stop) > 0 && !omit[ParamStop] {
		wire.Stop = p.Stop
	}
	if len(req.Schema) > 0 && !omit[ParamSchema] {
		wire.ResponseFormat = &openaiRespFormat{
			Type:       "json_schema",
			JSONSchema: &openaiJSONSchema{Name: "answer", Schema: req.Schema, Strict: true},
		}
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return Response{}, err
	}
	resp, err := postRawJSON(ctx, ep, path, headers, payload)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var out Response
	var text boundedAnswer
	finished := false
	err = sseEvents(resp.Body, func(_ string, data []byte) error {
		if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			finished = true
			return nil
		}
		var chunk struct {
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if jerr := json.Unmarshal(data, &chunk); jerr != nil {
			return &APIError{Streamed: true, Message: "stream chunk is not valid JSON: " + jerr.Error()}
		}
		if chunk.Error != nil {
			return &APIError{Status: 500, Streamed: true, Message: excerpt(chunk.Error.Message, maxExcerpt)}
		}
		if chunk.Model != "" {
			out.Model = chunk.Model
		}
		if chunk.Usage != nil {
			out.InputTokens = chunk.Usage.PromptTokens
			out.OutputTokens = chunk.Usage.CompletionTokens
			out.Reported = true
		}
		for _, c := range chunk.Choices {
			if c.FinishReason != "" {
				out.StopReason = c.FinishReason
			}
			if aerr := text.add(c.Delta.Content, onToken); aerr != nil {
				return aerr
			}
		}
		return nil
	})
	if err != nil {
		return Response{}, err
	}
	if !finished {
		return Response{}, &APIError{Streamed: true, Message: "the stream ended before [DONE]"}
	}
	out.Text = text.b.String()
	return out, nil
}

type openaiProvider struct{}

func (openaiProvider) Name() string            { return "openai" }
func (openaiProvider) NeedsKey() bool          { return os.Getenv("OPENAI_BASE_URL") == "" }
func (openaiProvider) SupportsStreaming() bool { return true }
func (openaiProvider) Accepts(string) bool     { return true }
func (openaiProvider) WireName(p string) string {
	if p == ParamSchema {
		return "response_format"
	}
	return p
}

func (openaiProvider) Endpoint(cfg Config, creds *CredentialStore) (Endpoint, error) {
	key := cfg.APIKey
	if key == "" {
		key = creds.APIKeyFor("OPENAI_API_KEY")
	}
	raw := os.Getenv("OPENAI_BASE_URL")
	if raw == "" {
		raw = defaultOpenAIURL
	}
	u, err := validateBaseURL(raw, key != "", cfg.AllowPlaintextCredentials)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Base: u, Client: newHTTPClient(cfg.HTTPClient), Key: key}, nil
}

func (openaiProvider) Chat(ctx context.Context, ep Endpoint, req Request, omit map[string]bool, onToken func(string)) (Response, error) {
	var headers map[string]string
	if ep.Key != "" {
		headers = map[string]string{"Authorization": "Bearer " + ep.Key}
	}
	return chatOpenAICompat(ctx, ep, "/chat/completions", headers, req, omit, onToken)
}

type azureProvider struct{}

func (azureProvider) Name() string            { return "azure" }
func (azureProvider) NeedsKey() bool          { return true }
func (azureProvider) SupportsStreaming() bool { return true }
func (azureProvider) Accepts(string) bool     { return true }
func (azureProvider) WireName(p string) string {
	if p == ParamSchema {
		return "response_format"
	}
	return p
}

func (azureProvider) Endpoint(cfg Config, creds *CredentialStore) (Endpoint, error) {
	key := cfg.APIKey
	if key == "" {
		key = creds.APIKeyFor("AZURE_OPENAI_KEY")
	}
	raw := os.Getenv("AZURE_OPENAI_ENDPOINT")
	if raw == "" {
		return Endpoint{}, fmt.Errorf("azure provider requires AZURE_OPENAI_ENDPOINT")
	}
	apiVer := os.Getenv("AZURE_OPENAI_API_VERSION")
	if apiVer == "" {
		apiVer = defaultAzureAPIVersion
	}
	u, err := validateBaseURL(raw, key != "", cfg.AllowPlaintextCredentials)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Base: u, Client: newHTTPClient(cfg.HTTPClient), Key: key, APIVersion: apiVer}, nil
}

func (azureProvider) Chat(ctx context.Context, ep Endpoint, req Request, omit map[string]bool, onToken func(string)) (Response, error) {
	apiVer := ep.APIVersion
	if apiVer == "" {
		apiVer = defaultAzureAPIVersion
	}
	path := fmt.Sprintf("/openai/deployments/%s/chat/completions?api-version=%s",
		url.PathEscape(req.Model), url.QueryEscape(apiVer))
	headers := map[string]string{"api-key": ep.Key}
	return chatOpenAICompat(ctx, ep, path, headers, req, omit, onToken)
}
