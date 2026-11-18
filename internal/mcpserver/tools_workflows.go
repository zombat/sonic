// Package mcpserver implements deterministic cross-layer VoIP underlay correlation,
// baseline capture diffing, and CI policy gate MCP tool handlers.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zombat/sonic/internal/analyze/diff"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/gate"
)

type mediaUnderlayArgs struct {
	FilePath      string   `json:"file_path"`
	Peers         []string `json:"peers"`
	DisplayFilter string   `json:"display_filter"`
	MaxPackets    *int     `json:"max_packets"`
	Since         *float64 `json:"since"`
	Until         *float64 `json:"until"`
}

func handleDiagnoseMediaUnderlay(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a mediaUnderlayArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if errBytes := captureReadable(a.FilePath); errBytes != nil {
		return errBytes, nil
	}
	rep := netorch.AnalyzeMediaUnderlay(ctx, a.FilePath, netorch.UnderlayCorrelationOptions{
		Peers:         a.Peers,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		Since:         a.Since,
		Until:         a.Until,
	})
	return json.Marshal(rep)
}

type diffArgs struct {
	BaselinePath  string   `json:"baseline_path"`
	TargetPath    string   `json:"target_path"`
	Detectors     []string `json:"detectors"`
	Peers         []string `json:"peers"`
	DisplayFilter string   `json:"display_filter"`
	MaxPackets    *int     `json:"max_packets"`
}

func handleDiffPcaps(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a diffArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if errBytes := captureReadable(a.BaselinePath); errBytes != nil {
		return errBytes, nil
	}
	if errBytes := captureReadable(a.TargetPath); errBytes != nil {
		return errBytes, nil
	}
	rep := diff.CompareCaptures(ctx, a.BaselinePath, a.TargetPath, diff.Options{
		Peers:         a.Peers,
		Detectors:     a.Detectors,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
	})
	return json.Marshal(rep)
}

type gateArgs struct {
	FilePath      string   `json:"file_path"`
	Policies      []string `json:"policies"`
	Allow         []string `json:"allow"`
	Peers         []string `json:"peers"`
	DisplayFilter string   `json:"display_filter"`
	MaxPackets    *int     `json:"max_packets"`
}

func handleEvaluateCaptureGate(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a gateArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if errBytes := captureReadable(a.FilePath); errBytes != nil {
		return errBytes, nil
	}
	rep := gate.Evaluate(ctx, a.FilePath, gate.Options{
		Policies:      a.Policies,
		Allow:         a.Allow,
		Peers:         a.Peers,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
	})
	return json.Marshal(rep)
}
