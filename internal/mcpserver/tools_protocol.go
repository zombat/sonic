// Package mcpserver implements the gRPC, RESTCONF, SNMP, AAA, ESP, and SIP
// deterministic MCP tool handlers and constructs the default server registry.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/analyze/aaainspect"
	"github.com/zombat/sonic/internal/analyze/espdecrypt"
	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/analyze/httpinspect"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/analyze/snmpinspect"
)

// NewDefault constructs the MCP Server wired to every tool in tools.json using default credentials.
func NewDefault() (*Server, error) {
	return NewWithDeps(ai.Deps{})
}

// NewWithDeps constructs the MCP Server wired to all deterministic and LLM tools using deps.
func NewWithDeps(deps ai.Deps) (*Server, error) {
	llmHandlers, err := newLLMTools(deps)
	if err != nil {
		return nil, err
	}
	return New(map[string]Handler{
		"analyze_pcap":                   llmHandlers.handleAnalyzePcap,
		"analyze_pcap_partial_streaming": llmHandlers.handleAnalyzePcapPartialStreaming,
		"analyze_batch_pcaps":            llmHandlers.handleAnalyzeBatchPcaps,
		"list_llm_providers":             llmHandlers.handleListLLMProviders,
		"quick_quality_check":            handleQuickQualityCheck,
		"analyze_network_pcap":           handleAnalyzeNetworkPcap,
		"analyze_vpn_pcap":               handleAnalyzeVPNPcap,
		"analyze_routing_pcap":           handleAnalyzeRoutingPcap,
		"audit_cleartext_pcap":           handleAuditCleartextPcap,
		"analyze_convergence_pcap":       handleAnalyzeConvergencePcap,
		"analyze_data_plane_pcap":        handleAnalyzeDataPlanePcap,
		"correlate_pcaps":                handleCorrelatePcaps,
		"merge_pcap_timelines":           handleMergePcapTimelines,
		"analyze_grpc_pcap":              handleAnalyzeGRPCPcap,
		"analyze_restconf_pcap":          handleAnalyzeRestconfPcap,
		"analyze_snmp_pcap":              handleAnalyzeSNMPPcap,
		"analyze_aaa_pcap":               handleAnalyzeAAAPcap,
		"analyze_esp_pcap":               handleAnalyzeESPPcap,
	})
}

type fileOnlyArgs struct {
	FilePath string `json:"file_path"`
}

func handleQuickQualityCheck(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a fileOnlyArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	return json.Marshal(sip.QuickQualityCheck(ctx, a.FilePath))
}

type grpcArgs struct {
	FilePath      string   `json:"file_path"`
	KeylogFile    string   `json:"keylog_file"`
	ProtoPaths    []string `json:"proto_paths"`
	Ports         []int    `json:"ports"`
	DisplayFilter string   `json:"display_filter"`
	MaxPackets    *int     `json:"max_packets"`
	MaxItems      *int     `json:"max_items"`
}

func handleAnalyzeGRPCPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a grpcArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := grpc.AnalyzeCapture(ctx, a.FilePath, grpc.Options{
		KeylogFile:    a.KeylogFile,
		ProtoPaths:    a.ProtoPaths,
		Ports:         a.Ports,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
	})
	return json.Marshal(rep)
}

type restconfArgs struct {
	FilePath      string `json:"file_path"`
	KeylogFile    string `json:"keylog_file"`
	Ports         []int  `json:"ports"`
	DisplayFilter string `json:"display_filter"`
	MaxPackets    *int   `json:"max_packets"`
	MaxItems      *int   `json:"max_items"`
}

func handleAnalyzeRestconfPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a restconfArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := httpinspect.AnalyzeCapture(ctx, a.FilePath, httpinspect.Options{
		KeylogFile:    a.KeylogFile,
		Ports:         a.Ports,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
	})
	return json.Marshal(rep)
}

type snmpArgs struct {
	FilePath      string `json:"file_path"`
	UsersFile     string `json:"users_file"`
	DisplayFilter string `json:"display_filter"`
	MaxPackets    *int   `json:"max_packets"`
	MaxItems      *int   `json:"max_items"`
}

func handleAnalyzeSNMPPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a snmpArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := snmpinspect.AnalyzeCapture(ctx, a.FilePath, snmpinspect.Options{
		UsersFile:     a.UsersFile,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
	})
	return json.Marshal(rep)
}

type aaaArgs struct {
	FilePath      string `json:"file_path"`
	KeysFile      string `json:"keys_file"`
	DisplayFilter string `json:"display_filter"`
	MaxPackets    *int   `json:"max_packets"`
	MaxItems      *int   `json:"max_items"`
}

func handleAnalyzeAAAPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a aaaArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := aaainspect.AnalyzeCapture(ctx, a.FilePath, aaainspect.Options{
		KeysFile:      a.KeysFile,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
	})
	return json.Marshal(rep)
}

type espArgs struct {
	FilePath      string   `json:"file_path"`
	SAFile        string   `json:"sa_file"`
	Detectors     []string `json:"detectors"`
	DisplayFilter string   `json:"display_filter"`
	MaxPackets    *int     `json:"max_packets"`
	MaxItems      *int     `json:"max_items"`
}

func handleAnalyzeESPPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a espArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := espdecrypt.AnalyzeCapture(ctx, a.FilePath, espdecrypt.Options{
		SAFile:        a.SAFile,
		Detectors:     a.Detectors,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
	})
	return json.Marshal(rep)
}
