// Package mcpserver implements a dependency-free Model Context Protocol server
// over newline-delimited JSON-RPC 2.0 on stdio, serving the S.O.N.I.C.
// deterministic analysis tools with the same contract as mcp_server.py.
package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sync"
)

// LatestProtocolVersion is the MCP revision this server speaks by default.
const LatestProtocolVersion = "2025-06-18"

// supportedVersions lists MCP revisions the server accepts from a client.
var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// maxLineBytes bounds one inbound JSON-RPC message so a bad client cannot exhaust memory.
const maxLineBytes = 16 << 20

// JSON-RPC 2.0 error codes used by the server.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// rpcRequest is one inbound JSON-RPC request or notification.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcError is the error member of a JSON-RPC response.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// rpcResponse is one outbound JSON-RPC response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// serverInfo names the server in the initialize result.
type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// initializeResult is the result of the initialize request.
type initializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities"`
	ServerInfo      serverInfo      `json:"serverInfo"`
	Instructions    string          `json:"instructions,omitempty"`
}

// initializeParams holds the client fields the server reads from initialize.
type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

// Server dispatches MCP requests to the registered tools.
type Server struct {
	name         string
	version      string
	instructions string
	tools        []registeredTool
	byName       map[string]int
	writeMu      sync.Mutex
}

// Serve reads one JSON-RPC message per line from in and writes responses to out
// until in reaches EOF or ctx is cancelled. Requests are handled in order.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if resp, ok := s.handleLine(ctx, line); ok {
			if err := s.write(out, resp); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read mcp input: %w", err)
	}
	return nil
}

// handleLine decodes one message and returns the response to send, if any.
func (s *Server) handleLine(ctx context.Context, line []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return errorResponse(json.RawMessage("null"), codeParseError, "Parse error", ""), true
	}
	isNotification := len(req.ID) == 0
	if req.JSONRPC != "2.0" || req.Method == "" {
		if isNotification {
			return rpcResponse{}, false
		}
		return errorResponse(req.ID, codeInvalidRequest, "Invalid Request", ""), true
	}
	result, rerr := s.dispatch(ctx, req)
	if isNotification {
		return rpcResponse{}, false
	}
	if rerr != nil {
		return errorResponse(req.ID, rerr.Code, rerr.Message, rerr.Data), true
	}
	return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, true
}

// dispatch routes a request to its method handler.
func (s *Server) dispatch(ctx context.Context, req rpcRequest) (json.RawMessage, *rpcError) {
	switch req.Method {
	case "initialize":
		return s.initialize(req.Params)
	case "ping":
		return json.RawMessage("{}"), nil
	case "tools/list":
		return s.listTools()
	case "tools/call":
		return s.callTool(ctx, req.Params)
	case "prompts/list":
		return s.listPrompts()
	case "prompts/get":
		return s.getPrompt(req.Params)
	case "resources/list":
		return s.listResources()
	case "resources/read":
		return s.readResource(req.Params)
	default:
		if len(req.Method) > len("notifications/") && req.Method[:len("notifications/")] == "notifications/" {
			return json.RawMessage("{}"), nil
		}
		return nil, &rpcError{Code: codeMethodNotFound, Message: "Method not found", Data: req.Method}
	}
}

// initialize negotiates the protocol version and describes the server.
func (s *Server) initialize(params json.RawMessage) (json.RawMessage, *rpcError) {
	var p initializeParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{Code: codeInvalidParams, Message: "Invalid params"}
		}
	}
	version := LatestProtocolVersion
	if slices.Contains(supportedVersions, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	return marshalResult(initializeResult{
		ProtocolVersion: version,
		Capabilities:    json.RawMessage(`{"tools":{"listChanged":false},"prompts":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false}}`),
		ServerInfo:      serverInfo{Name: s.name, Version: s.version},
		Instructions:    s.instructions,
	})
}

// write serializes resp as one line on out; writes never interleave.
func (s *Server) write(out io.Writer, resp rpcResponse) error {
	raw, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal mcp response: %w", err)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := out.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("write mcp response: %w", err)
	}
	return nil
}

// errorResponse builds a JSON-RPC error response.
func errorResponse(id json.RawMessage, code int, msg, data string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg, Data: data}}
}

// marshalResult encodes v as a JSON-RPC result.
func marshalResult(v json.Marshaler) (json.RawMessage, *rpcError) {
	raw, err := v.MarshalJSON()
	if err != nil {
		return nil, &rpcError{Code: codeInternalError, Message: "Internal error"}
	}
	return raw, nil
}

// MarshalJSON encodes the initialize result with its declared field order.
func (r initializeResult) MarshalJSON() ([]byte, error) {
	type plain initializeResult
	return json.Marshal(plain(r))
}
