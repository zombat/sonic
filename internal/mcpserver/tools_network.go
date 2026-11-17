// Package mcpserver implements the network, VPN, routing, audit, convergence,
// data-plane, correlation, and multi-capture timeline MCP handlers.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zombat/sonic/internal/analyze/convergence"
	"github.com/zombat/sonic/internal/analyze/correlate"
	"github.com/zombat/sonic/internal/analyze/espoverhead"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/timeline"
	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/model"
)

type networkArgs struct {
	FilePath      string                     `json:"file_path"`
	Detectors     []string                   `json:"detectors"`
	Peers         []string                   `json:"peers"`
	DisplayFilter string                     `json:"display_filter"`
	MaxPackets    *int                       `json:"max_packets"`
	IncludeSIP    *bool                      `json:"include_sip"`
	MaxItems      *int                       `json:"max_items"`
	Options       map[string]json.RawMessage `json:"options"`
}

func handleAnalyzeNetworkPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a networkArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if errBytes := captureReadable(a.FilePath); errBytes != nil {
		return errBytes, nil
	}
	detOpts, errPayload, err := parseNetworkOptions(a.Options)
	if err != nil {
		return nil, err
	}
	if errPayload != nil {
		return errPayload, nil
	}
	incSIP := true
	if a.IncludeSIP != nil {
		incSIP = *a.IncludeSIP
	}
	rep := netorch.AnalyzeNetworkCapture(ctx, a.FilePath, netorch.Options{
		Detectors:     a.Detectors,
		Peers:         a.Peers,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		IncludeSIP:    &incSIP,
		MaxItems:      clampMaxItems(a.MaxItems),
		DetectorOpts:  detOpts,
	})
	return json.Marshal(rep)
}

type vpnArgs struct {
	FilePath      string   `json:"file_path"`
	Peers         []string `json:"peers"`
	DisplayFilter string   `json:"display_filter"`
	MaxPackets    *int     `json:"max_packets"`
	MaxItems      *int     `json:"max_items"`
	Hubs          []string `json:"hubs"`
}

func handleAnalyzeVPNPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a vpnArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := netorch.AnalyzeVPNCapture(ctx, a.FilePath, netorch.Options{
		Peers:         a.Peers,
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
		DetectorOpts:  netorch.DetectorOptions{DMVPNHubs: a.Hubs},
	})
	return json.Marshal(rep)
}

type routingArgs struct {
	FilePath      string `json:"file_path"`
	DisplayFilter string `json:"display_filter"`
	MaxPackets    *int   `json:"max_packets"`
	MaxItems      *int   `json:"max_items"`
	ExpectedMSS   *int   `json:"expected_mss"`
}

func handleAnalyzeRoutingPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a routingArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := netorch.AnalyzeRoutingCapture(ctx, a.FilePath, netorch.Options{
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
		DetectorOpts:  netorch.DetectorOptions{RoutingMSS: a.ExpectedMSS},
	})
	return json.Marshal(rep)
}

type auditArgs struct {
	FilePath      string          `json:"file_path"`
	Allow         json.RawMessage `json:"allow"`
	DisplayFilter string          `json:"display_filter"`
	MaxPackets    *int            `json:"max_packets"`
	MaxItems      *int            `json:"max_items"`
}

func handleAuditCleartextPcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a auditArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	var auditOpt *netorch.AuditOption
	if !isNullJSON(a.Allow) {
		var allow []string
		if err := json.Unmarshal(a.Allow, &allow); err != nil {
			return nil, fmt.Errorf("invalid allow argument: %w", err)
		}
		auditOpt = &netorch.AuditOption{Allow: allow, HasAllow: true}
	}
	rep := netorch.AuditCleartextCapture(ctx, a.FilePath, netorch.Options{
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
		DetectorOpts:  netorch.DetectorOptions{CleartextAudit: auditOpt},
	})
	return json.Marshal(rep)
}

type convergenceArgs struct {
	FilePath      string     `json:"file_path"`
	EventTime     flexString `json:"event_time"`
	FailedPeer    string     `json:"failed_peer"`
	HoldTime      *float64   `json:"hold_time"`
	SilenceS      *float64   `json:"silence_s"`
	DisplayFilter string     `json:"display_filter"`
	MaxPackets    *int       `json:"max_packets"`
	MaxItems      *int       `json:"max_items"`
}

func handleAnalyzeConvergencePcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a convergenceArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rep := netorch.AnalyzeConvergenceCapture(ctx, a.FilePath, netorch.Options{
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
		DetectorOpts: netorch.DetectorOptions{
			Convergence: &convergence.Options{
				EventTime:  string(a.EventTime),
				FailedPeer: a.FailedPeer,
				HoldTime:   a.HoldTime,
				SilenceS:   a.SilenceS,
			},
		},
	})
	return json.Marshal(rep)
}

type dataPlaneArgs struct {
	FilePath       string               `json:"file_path"`
	TLSBaseline    *tlsinspect.Baseline `json:"tls_baseline"`
	TransportMTU   *int                 `json:"transport_mtu"`
	TunnelMTU      *int                 `json:"tunnel_mtu"`
	GREHeaderBytes *int                 `json:"gre_header_bytes"`
	DisplayFilter  string               `json:"display_filter"`
	MaxPackets     *int                 `json:"max_packets"`
	MaxItems       *int                 `json:"max_items"`
}

// orderedDataPlane keeps Python's top-level field order (status, overall_status, path_mtu_verdict, ...).
type orderedDataPlane struct {
	Status             string       `json:"status"`
	OverallStatus      model.Status `json:"overall_status"`
	PathMTUVerdict     string       `json:"path_mtu_verdict"`
	ESPOverheadVerdict string       `json:"esp_overhead_verdict"`
	TCPVerdict         string       `json:"tcp_verdict"`
	TLSVerdict         string       `json:"tls_verdict"`
	QoSVerdict         string       `json:"qos_verdict"`
	netorch.NetworkBody
}

func handleAnalyzeDataPlanePcap(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a dataPlaneArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	tMTU := 1500
	if a.TransportMTU != nil {
		tMTU = *a.TransportMTU
	}
	rep := netorch.AnalyzeDataPlaneCapture(ctx, a.FilePath, netorch.Options{
		DisplayFilter: a.DisplayFilter,
		MaxPackets:    a.MaxPackets,
		MaxItems:      clampMaxItems(a.MaxItems),
		DetectorOpts: netorch.DetectorOptions{
			EspOverhead: &espoverhead.Options{
				TransportMTU:   tMTU,
				TunnelMTU:      a.TunnelMTU,
				GREHeaderBytes: a.GREHeaderBytes,
			},
			TLSBaseline: a.TLSBaseline,
		},
	})
	if rep.Status != "success" {
		return json.Marshal(rep)
	}
	return json.Marshal(orderedDataPlane{
		Status:             rep.Status,
		OverallStatus:      rep.OverallStatus,
		PathMTUVerdict:     rep.PathMTUVerdict,
		ESPOverheadVerdict: rep.ESPOverheadVerdict,
		TCPVerdict:         rep.TCPVerdict,
		TLSVerdict:         rep.TLSVerdict,
		QoSVerdict:         rep.QoSVerdict,
		NetworkBody:        rep.NetworkBody,
	})
}

type correlateArgs struct {
	Captures       []correlate.CaptureInput `json:"captures"`
	WindowS        *float64                 `json:"window_s"`
	MaxPacketsHeld *int                     `json:"max_packets_held"`
	ClockOffsetsS  map[string]float64       `json:"clock_offsets_s"`
	MaxPackets     *int                     `json:"max_packets"`
	MaxItems       *int                     `json:"max_items"`
}

func handleCorrelatePcaps(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a correlateArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	maxHeld := 0
	if a.MaxPacketsHeld != nil {
		if *a.MaxPacketsHeld < 100 {
			return errJSON("max_packets_held must be at least 100"), nil
		}
		maxHeld = *a.MaxPacketsHeld
	}
	rep := correlate.CorrelateCaptures(ctx, a.Captures, correlate.Options{
		WindowS:        a.WindowS,
		MaxPacketsHeld: maxHeld,
		ClockOffsetsS:  a.ClockOffsetsS,
		MaxPackets:     a.MaxPackets,
		MaxItems:       clampMaxItems(a.MaxItems),
	})
	return json.Marshal(rep)
}

type timelineArgs struct {
	Captures      []timeline.CaptureInput    `json:"captures"`
	Measurements  []timeline.MeasurementSpec `json:"measurements"`
	Detectors     []string                   `json:"detectors"`
	FailoverMaxS  *float64                   `json:"failover_max_s"`
	ClockOffsetsS map[string]float64         `json:"clock_offsets_s"`
	MaxEvents     *int                       `json:"max_events"`
	OutputPath    string                     `json:"output_path"`
	Overwrite     bool                       `json:"overwrite"`
}

func handleMergePcapTimelines(ctx context.Context, raw json.RawMessage) ([]byte, error) {
	var a timelineArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	maxEvents := 500
	if a.MaxEvents != nil {
		maxEvents = *a.MaxEvents
		if maxEvents < 1 {
			return errJSON("max_events must be at least 1"), nil
		}
	}
	rep := timeline.MergeTimelines(ctx, a.Captures, timeline.Options{
		Measurements:  a.Measurements,
		Detectors:     a.Detectors,
		FailoverMaxS:  a.FailoverMaxS,
		ClockOffsetsS: a.ClockOffsetsS,
		MaxEvents:     maxEvents,
		OutputPath:    a.OutputPath,
		Overwrite:     a.Overwrite,
	})
	return json.Marshal(rep)
}
