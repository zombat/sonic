// Package llm implements the Anthropic Messages direct-HTTP SSE provider.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
)

const (
	defaultAnthropicURL = "https://api.anthropic.com"
	anthropicVersion    = "2023-06-01"
	anthropicMaxTokens  = 4000
	anthropicToolName   = "answer"
)

func init() {
	mustRegister(anthropicProvider{})
}

type anthropicProvider struct{}

func (anthropicProvider) Name() string            { return "anthropic" }
func (anthropicProvider) NeedsKey() bool          { return true }
func (anthropicProvider) SupportsStreaming() bool { return true }

// Accepts omits temperature because current Claude models reject non-default sampling.
func (anthropicProvider) Accepts(p string) bool { return p != ParamTemperature }

func (anthropicProvider) WireName(p string) string {
	switch p {
	case ParamStop:
		return "stop_sequences"
	case ParamSchema:
		return "tool"
	default:
		return p
	}
}

func (anthropicProvider) Endpoint(cfg Config, creds *CredentialStore) (Endpoint, error) {
	key := cfg.APIKey
	if key == "" {
		key = creds.APIKeyFor("ANTHROPIC_API_KEY")
	}
	raw := os.Getenv("ANTHROPIC_BASE_URL")
	if raw == "" {
		raw = defaultAnthropicURL
	}
	u, err := validateBaseURL(raw, key != "", cfg.AllowPlaintextCredentials)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Base: u, Client: newHTTPClient(cfg.HTTPClient), Key: key}, nil
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthropicToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type anthropicMsgReq struct {
	Model         string               `json:"model"`
	MaxTokens     int                  `json:"max_tokens"`
	Stream        bool                 `json:"stream"`
	System        string               `json:"system,omitempty"`
	Messages      []Message            `json:"messages"`
	TopP          *float64             `json:"top_p,omitempty"`
	StopSequences []string             `json:"stop_sequences,omitempty"`
	Tools         []anthropicTool      `json:"tools,omitempty"`
	ToolChoice    *anthropicToolChoice `json:"tool_choice,omitempty"`
}

func (anthropicProvider) Chat(ctx context.Context, ep Endpoint, req Request, omit map[string]bool, onToken func(string)) (Response, error) {
	var sysParts []string
	var msgs []Message
	for _, m := range req.Messages {
		if m.Role == "system" {
			sysParts = append(sysParts, m.Content)
			continue
		}
		msgs = append(msgs, m)
	}
	maxTok := anthropicMaxTokens
	if req.Params.MaxTokens != nil && !omit[ParamMaxTokens] {
		maxTok = *req.Params.MaxTokens
	}
	wire := anthropicMsgReq{
		Model:     req.Model,
		MaxTokens: maxTok,
		Stream:    true,
		Messages:  msgs,
	}
	if len(sysParts) > 0 {
		wire.System = joinBlankLines(sysParts)
	}
	if req.Params.TopP != nil && !omit[ParamTopP] {
		wire.TopP = req.Params.TopP
	}
	if len(req.Params.Stop) > 0 && !omit[ParamStop] {
		wire.StopSequences = req.Params.Stop
	}
	structured := len(req.Schema) > 0 && !omit[ParamSchema]
	if structured {
		wire.Tools = []anthropicTool{{Name: anthropicToolName, Description: "Return the structured diagnostic report.", InputSchema: req.Schema}}
		wire.ToolChoice = &anthropicToolChoice{Type: "tool", Name: anthropicToolName}
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return Response{}, err
	}
	headers := map[string]string{
		"x-api-key":         ep.Key,
		"anthropic-version": anthropicVersion,
	}
	resp, err := postRawJSON(ctx, ep, "/v1/messages", headers, payload)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var out Response
	var text, toolText boundedAnswer
	sawInput, stopped := false, false
	err = sseEvents(resp.Body, func(_ string, data []byte) error {
		var ev struct {
			Type    string `json:"type"`
			Message struct {
				Model string `json:"model"`
				Usage *struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Usage *struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if jerr := json.Unmarshal(data, &ev); jerr != nil {
			return &APIError{Streamed: true, Message: "stream event is not valid JSON: " + jerr.Error()}
		}
		switch ev.Type {
		case "message_start":
			out.Model = ev.Message.Model
			if ev.Message.Usage != nil {
				out.InputTokens = ev.Message.Usage.InputTokens
				sawInput = true
			}
		case "content_block_delta":
			if ev.Delta.Type == "text_delta" {
				return text.add(ev.Delta.Text, onToken)
			}
			if ev.Delta.Type == "input_json_delta" {
				return toolText.add(ev.Delta.PartialJSON, onToken)
			}
		case "message_delta":
			if ev.Usage != nil {
				out.OutputTokens = ev.Usage.OutputTokens
				out.Reported = sawInput
			}
			if ev.Delta.StopReason != "" {
				out.StopReason = ev.Delta.StopReason
			}
		case "message_stop":
			stopped = true
		case "error":
			status := 500
			if ev.Error.Type == "overloaded_error" {
				status = 529
			}
			return &APIError{Status: status, Streamed: true, Message: excerpt(ev.Error.Message, maxExcerpt)}
		}
		return nil
	})
	if err != nil {
		return Response{}, err
	}
	if !stopped {
		return Response{}, &APIError{Streamed: true, Message: "the stream ended before message_stop"}
	}
	if structured {
		if toolText.b.Len() == 0 {
			return Response{}, errors.New("anthropic returned empty structured tool payload")
		}
		out.Text = toolText.b.String()
		return out, nil
	}
	out.Text = text.b.String()
	return out, nil
}

func joinBlankLines(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "\n\n"
		}
		out += p
	}
	return out
}
