// Package mcpserver implements the LLM-backed SIP diagnosis, partial streaming,
// batch directory analysis, and provider discovery MCP tool handlers.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/llm"
)

type llmTools struct {
	deps ai.Deps
}

func newLLMTools(deps ai.Deps) (llmTools, error) {
	if deps.Creds == nil {
		creds, err := llm.NewCredentialStore("")
		if err != nil {
			return llmTools{}, err
		}
		deps.Creds = creds
	}
	if deps.Completer == nil {
		deps.Completer = llm.NewClient(deps.Creds)
	}
	if deps.Factory == nil {
		deps.Factory = ai.NewArtifactFactory()
	}
	return llmTools{deps: deps}, nil
}

type analyzePcapArgs struct {
	FilePath      string  `json:"file_path"`
	Provider      *string `json:"provider"`
	Model         string  `json:"model"`
	EnableQuality *bool   `json:"enable_quality"`
	EnableMOS     *bool   `json:"enable_mos"`
}

func (l llmTools) handleAnalyzePcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a analyzePcapArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if errBytes := captureReadable(a.FilePath); errBytes != nil {
		return errBytes, nil
	}
	modelMode := a.Model
	if modelMode == "" {
		modelMode = "combined"
	}
	enableQuality := true
	if a.EnableQuality != nil {
		enableQuality = *a.EnableQuality
	}
	enableMOS := true
	if a.EnableMOS != nil {
		enableMOS = *a.EnableMOS
	}
	res := ai.RunAnalysisMode(ctx, l.deps, a.FilePath, modelMode, enableQuality, enableMOS, derefString(a.Provider), "")
	return json.Marshal(res)
}

func (l llmTools) handleListLLMProviders(_ context.Context, raw json.RawMessage) ([]byte, error) {
	if !isNullJSON(raw) {
		var unused struct{}
		if err := json.Unmarshal(raw, &unused); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	return json.Marshal(llm.ListProviders(l.deps.Creds))
}

type analyzeBatchArgs struct {
	Directory string  `json:"directory"`
	Provider  *string `json:"provider"`
	Model     string  `json:"model"`
	Mode      string  `json:"mode"`
}

func (l llmTools) handleAnalyzeBatchPcaps(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a analyzeBatchArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	files, cerr := ai.CollectBatchPcaps(a.Directory)
	if cerr != nil {
		return errJSON(cerr.Error()), nil
	}
	modelTier := a.Model
	if modelTier == "" {
		modelTier = llm.ProfileFast
	}
	mode := ai.ModeSequential
	workers := 1
	switch a.Mode {
	case "", string(ai.ModeSequential):
	case string(ai.ModeParallel):
		mode = ai.ModeParallel
		workers = 3
	default:
		return errJSON(fmt.Sprintf("Invalid batch mode: %s (expected sequential or parallel)", a.Mode)), nil
	}
	provider := derefString(a.Provider)
	modelOverride := ""
	if modelTier != llm.ProfileFast {
		modelOverride = llm.GetModelName(llm.ResolveProvider(provider), modelTier, "")
	}
	res := ai.AnalyzeBatch(ctx, l.deps, files, provider, modelTier, mode, workers, modelOverride, nil, nil)
	return json.Marshal(res)
}

type analyzePartialArgs struct {
	FilePath string  `json:"file_path"`
	Provider *string `json:"provider"`
}

func (l llmTools) handleAnalyzePcapPartialStreaming(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a analyzePartialArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if errBytes := captureReadable(a.FilePath); errBytes != nil {
		return errBytes, nil
	}
	res := ai.RunPartialAnalysisStreaming(ctx, l.deps, a.FilePath, derefString(a.Provider), "", nil, nil, nil)
	return json.Marshal(res)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
