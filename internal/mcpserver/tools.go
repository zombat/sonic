// Package mcpserver registers the embedded tool definitions, lists them, and
// runs tools/call with masked, JSON-validated results.
package mcpserver

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/guide"
	"github.com/zombat/sonic/internal/redact"
)

// toolsJSON holds the tool definitions dumped from mcp_server.py by tools/gen_mcp_tools.py.
//
//go:embed tools.json
var toolsJSON []byte

// ServerName matches the Python server's MCP name.
const ServerName = "S.O.N.I.C. VoIP and Network Analyzer"

// Version identifies this Go server build in serverInfo when built without ldflags.
const Version = "4.0.0"

// Handler runs one tool: it decodes args and returns the report as JSON.
type Handler func(ctx context.Context, args json.RawMessage) ([]byte, error)

// toolDef is one tool definition exactly as an MCP client sees it.
type toolDef struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// registeredTool pairs a definition with the handler that serves it.
type registeredTool struct {
	def     toolDef
	handler Handler
}

// toolContent is one text item of a tools/call result.
type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult is the result of tools/call.
type toolResult struct {
	Content           []toolContent   `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError"`
}

// callParams holds the tools/call request parameters.
type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// New builds a Server from the embedded tool definitions and handlers.
// It fails when a definition has no handler or a handler has no definition.
func New(handlers map[string]Handler) (*Server, error) {
	var defs []toolDef
	if err := json.Unmarshal(toolsJSON, &defs); err != nil {
		return nil, fmt.Errorf("parse embedded tool definitions: %w", err)
	}
	return newServer(defs, handlers)
}

// newServer pairs defs with handlers in definition order.
func newServer(defs []toolDef, handlers map[string]Handler) (*Server, error) {
	s := &Server{name: ServerName, version: Version, byName: make(map[string]int, len(defs))}
	for _, d := range defs {
		h, ok := handlers[d.Name]
		if !ok {
			return nil, fmt.Errorf("no handler for tool %s", d.Name)
		}
		s.byName[d.Name] = len(s.tools)
		s.tools = append(s.tools, registeredTool{def: d, handler: h})
	}
	for name := range handlers {
		if _, ok := s.byName[name]; !ok {
			return nil, fmt.Errorf("handler without a tool definition: %s", name)
		}
	}
	s.instructions = guide.Instructions(s.ToolSpecs())
	return s, nil
}

// ServerName and SetVersion helpers follow.

// SetVersion overrides the serverInfo version string reported during initialize.
func (s *Server) SetVersion(v string) {
	if strings.TrimSpace(v) != "" {
		s.version = v
	}
}

// ToolSpecs returns guide descriptors for every registered tool in definition order.
func (s *Server) ToolSpecs() []guide.ToolSpec {
	out := make([]guide.ToolSpec, len(s.tools))
	for i, t := range s.tools {
		var notes guide.ToolAnnotations
		if len(t.def.Annotations) > 0 {
			_ = json.Unmarshal(t.def.Annotations, &notes)
		} else if _, fallback, ok := guide.ToolOptions(t.def.Name); ok {
			notes = fallback
		}
		out[i] = guide.ToolSpec{
			Name:        t.def.Name,
			Title:       t.def.Title,
			Description: t.def.Description,
			InputSchema: t.def.InputSchema,
			Annotations: notes,
		}
	}
	return out
}

// DefaultToolSpecs decodes tool metadata directly from embedded tools.json for CLI skill generation.
func DefaultToolSpecs() ([]guide.ToolSpec, error) {
	var defs []toolDef
	if err := json.Unmarshal(toolsJSON, &defs); err != nil {
		return nil, fmt.Errorf("parse embedded tool definitions: %w", err)
	}
	out := make([]guide.ToolSpec, len(defs))
	for i, d := range defs {
		var notes guide.ToolAnnotations
		if len(d.Annotations) > 0 {
			_ = json.Unmarshal(d.Annotations, &notes)
		} else if _, fallback, ok := guide.ToolOptions(d.Name); ok {
			notes = fallback
		}
		out[i] = guide.ToolSpec{
			Name:        d.Name,
			Title:       d.Title,
			Description: d.Description,
			InputSchema: d.InputSchema,
			Annotations: notes,
		}
	}
	return out, nil
}

// listTools returns every tool definition.
func (s *Server) listTools() (json.RawMessage, *rpcError) {
	defs := make([]toolDef, len(s.tools))
	for i, t := range s.tools {
		defs[i] = t.def
	}
	raw, err := json.Marshal(struct {
		Tools []toolDef `json:"tools"`
	}{Tools: defs})
	if err != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}

// callTool runs the named tool; tool failures are results with isError set.
func (s *Server) callTool(ctx context.Context, params json.RawMessage) (json.RawMessage, *rpcError) {
	var p callParams
	if len(params) == 0 || json.Unmarshal(params, &p) != nil || p.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "Invalid params"}
	}
	idx, ok := s.byName[p.Name]
	if !ok {
		return errorResult(fmt.Sprintf("Unknown tool: '%s'", p.Name))
	}
	args := p.Arguments
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	report, err := s.tools[idx].handler(ctx, args)
	if err != nil {
		return errorResult(redact.RedactText(err.Error()))
	}
	text := redact.RedactText(string(report))
	if !json.Valid([]byte(text)) || !strings.HasPrefix(strings.TrimSpace(text), "{") {
		return errorResult("tool result was not a JSON object after redaction")
	}
	raw, merr := json.Marshal(toolResult{
		Content:           []toolContent{{Type: "text", Text: text}},
		StructuredContent: json.RawMessage(text),
	})
	if merr != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}

// errorResult builds a tools/call result that reports a tool-level failure.
func errorResult(msg string) (json.RawMessage, *rpcError) {
	raw, err := json.Marshal(toolResult{Content: []toolContent{{Type: "text", Text: msg}}, IsError: true})
	if err != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}
