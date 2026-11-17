// Package mcpserver implements prompts/list, prompts/get, resources/list, and
// resources/read backed by internal/guide.
package mcpserver

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/guide"
)

type promptGetParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type promptContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type promptMessage struct {
	Role    string        `json:"role"`
	Content promptContent `json:"content"`
}

type promptGetResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []promptMessage `json:"messages"`
}

type resourceReadParams struct {
	URI string `json:"uri"`
}

type resourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

func (s *Server) listPrompts() (json.RawMessage, *rpcError) {
	raw, err := json.Marshal(struct {
		Prompts []guide.PromptInfo `json:"prompts"`
	}{Prompts: guide.Prompts()})
	if err != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}

func (s *Server) getPrompt(params json.RawMessage) (json.RawMessage, *rpcError) {
	var p promptGetParams
	if len(params) == 0 || json.Unmarshal(params, &p) != nil || p.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "Invalid params"}
	}
	text, err := guide.WorkflowText(p.Name, p.Arguments)
	if err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: err.Error()}
	}
	desc := ""
	for _, wf := range guide.Workflows {
		if wf.Name == p.Name {
			desc = wf.Description
			break
		}
	}
	raw, merr := json.Marshal(promptGetResult{
		Description: desc,
		Messages: []promptMessage{
			{Role: "user", Content: promptContent{Type: "text", Text: text}},
		},
	})
	if merr != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}

func (s *Server) listResources() (json.RawMessage, *rpcError) {
	raw, err := json.Marshal(struct {
		Resources []guide.ResourceInfo `json:"resources"`
	}{Resources: guide.Resources()})
	if err != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}

func (s *Server) readResource(params json.RawMessage) (json.RawMessage, *rpcError) {
	var p resourceReadParams
	if len(params) == 0 || json.Unmarshal(params, &p) != nil || p.URI == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "Invalid params"}
	}
	text, err := guide.ReadResource(p.URI, s.ToolSpecs(), "sonic", guide.DefaultCLIFlags())
	if err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: err.Error()}
	}
	raw, merr := json.Marshal(struct {
		Contents []resourceContent `json:"contents"`
	}{
		Contents: []resourceContent{
			{URI: p.URI, MimeType: "text/markdown", Text: text},
		},
	})
	if merr != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}
