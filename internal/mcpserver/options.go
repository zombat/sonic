// Package mcpserver decodes tool arguments, validates per-detector options,
// and formats uniform tool-level JSON responses.
package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/convergence"
	"github.com/zombat/sonic/internal/analyze/espoverhead"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/tlsinspect"
)

// optionKeysByDetector mirrors Python analyzers/network_orchestrator.py OPTION_KEYS.
var optionKeysByDetector = map[string][]string{
	"cleartext_audit": {"allow"},
	"convergence":     {"event_time", "failed_peer", "hold_time", "silence_s"},
	"dmvpn_phase3":    {"hubs"},
	"esp_overhead":    {"gre_header_bytes", "transport_mtu", "tunnel_mtu"},
	"routing":         {"expected_mss"},
	"tls":             {"baseline"},
}

type espOverheadOptionArgs struct {
	TransportMTU   int  `json:"transport_mtu"`
	TunnelMTU      *int `json:"tunnel_mtu"`
	GREHeaderBytes *int `json:"gre_header_bytes"`
}

type convergenceOptionArgs struct {
	EventTime  flexString `json:"event_time"`
	FailedPeer string     `json:"failed_peer"`
	HoldTime   *float64   `json:"hold_time"`
	SilenceS   *float64   `json:"silence_s"`
}

// flexString decodes JSON strings or finite JSON numbers as their string text
// (matching Python's convergence event_time parameter).
type flexString string

// UnmarshalJSON implements json.Unmarshaler for JSON strings, numbers, and null.
func (f *flexString) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*f = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	num, err := strconv.ParseFloat(string(trimmed), 64)
	if err == nil && !math.IsNaN(num) && !math.IsInf(num, 0) {
		*f = flexString(string(trimmed))
		return nil
	}
	return fmt.Errorf("expected string or number, got %s", string(trimmed))
}

// isNullJSON reports whether raw is empty or JSON null.
func isNullJSON(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// clampMaxItems reproduces Python's max(1, int(max_items or 25)) defaulting rule.
func clampMaxItems(v *int) int {
	if v == nil || *v == 0 {
		return 25
	}
	if *v < 1 {
		return 1
	}
	return *v
}

// errJSON builds a {"status": "error", "error": msg} JSON response payload.
func errJSON(msg string) []byte {
	raw, _ := json.Marshal(struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}{Status: "error", Error: msg})
	return raw
}

// captureReadable checks that path points to a readable non-directory file, matching Python.
func captureReadable(path string) []byte {
	if path == "" {
		return errJSON("File not found: " + path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return errJSON("File not found: " + path)
	}
	if info.IsDir() {
		return errJSON("File not readable: " + path)
	}
	f, err := os.Open(path)
	if err != nil {
		return errJSON("File not readable: " + path)
	}
	_ = f.Close()
	return nil
}

// optionsErrorPayload emits a Python-compatible error object with extra metadata keys.
func optionsErrorPayload(msg string, withDetectors, validOpts []string) []byte {
	raw, _ := json.Marshal(struct {
		Status               string   `json:"status"`
		Error                string   `json:"error"`
		DetectorsWithOptions []string `json:"detectors_with_options,omitempty"`
		ValidOptions         []string `json:"valid_options,omitempty"`
	}{
		Status:               "error",
		Error:                msg,
		DetectorsWithOptions: withDetectors,
		ValidOptions:         validOpts,
	})
	return raw
}

// sortedDetectorsWithOptions returns sorted keys of optionKeysByDetector.
func sortedDetectorsWithOptions() []string {
	keys := make([]string, 0, len(optionKeysByDetector))
	for k := range optionKeysByDetector {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// parseNetworkOptions validates per-detector option maps against optionKeysByDetector
// and converts them into netorch.DetectorOptions.
func parseNetworkOptions(raw map[string]json.RawMessage) (netorch.DetectorOptions, []byte, error) {
	var out netorch.DetectorOptions
	if len(raw) == 0 {
		return out, nil, nil
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		allowed, ok := optionKeysByDetector[name]
		if !ok {
			return out, optionsErrorPayload(
				fmt.Sprintf("No options for detector '%s'", name),
				sortedDetectorsWithOptions(),
				nil,
			), nil
		}
		var settings map[string]json.RawMessage
		if isNullJSON(raw[name]) || json.Unmarshal(raw[name], &settings) != nil || settings == nil {
			return out, optionsErrorPayload(
				fmt.Sprintf("Unknown option(s) for %s: []", name),
				nil,
				allowed,
			), nil
		}
		var badKeys []string
		clean := make(map[string]json.RawMessage, len(settings))
		for k, v := range settings {
			if !slices.Contains(allowed, k) {
				badKeys = append(badKeys, k)
				continue
			}
			if !isNullJSON(v) {
				clean[k] = v
			}
		}
		if len(badKeys) > 0 {
			slices.Sort(badKeys)
			return out, optionsErrorPayload(
				fmt.Sprintf("Unknown option(s) for %s: ['%s']", name, strings.Join(badKeys, "', '")),
				nil,
				allowed,
			), nil
		}
		if err := applyDetectorOptions(&out, name, clean); err != nil {
			return out, nil, err
		}
	}
	return out, nil, nil
}

// applyDetectorOptions decodes cleaned key/value pairs for one validated detector into out.
func applyDetectorOptions(out *netorch.DetectorOptions, name string, clean map[string]json.RawMessage) error {
	if len(clean) == 0 {
		return nil
	}
	rawClean, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	switch name {
	case "esp_overhead":
		var eo espOverheadOptionArgs
		if err := json.Unmarshal(rawClean, &eo); err != nil {
			return fmt.Errorf("invalid esp_overhead options: %w", err)
		}
		out.EspOverhead = &espoverhead.Options{
			TransportMTU:   eo.TransportMTU,
			TunnelMTU:      eo.TunnelMTU,
			GREHeaderBytes: eo.GREHeaderBytes,
		}
	case "tls":
		if bRaw, ok := clean["baseline"]; ok {
			var b tlsinspect.Baseline
			if err := json.Unmarshal(bRaw, &b); err != nil {
				return fmt.Errorf("invalid tls.baseline option: %w", err)
			}
			out.TLSBaseline = &b
		}
	case "dmvpn_phase3":
		if hRaw, ok := clean["hubs"]; ok {
			var hubs []string
			if err := json.Unmarshal(hRaw, &hubs); err != nil {
				return fmt.Errorf("invalid dmvpn_phase3.hubs option: %w", err)
			}
			out.DMVPNHubs = hubs
		}
	case "routing":
		if mRaw, ok := clean["expected_mss"]; ok {
			var mss int
			if err := json.Unmarshal(mRaw, &mss); err != nil {
				return fmt.Errorf("invalid routing.expected_mss option: %w", err)
			}
			out.RoutingMSS = &mss
		}
	case "cleartext_audit":
		if aRaw, ok := clean["allow"]; ok {
			var allow []string
			if err := json.Unmarshal(aRaw, &allow); err != nil {
				return fmt.Errorf("invalid cleartext_audit.allow option: %w", err)
			}
			out.CleartextAudit = &netorch.AuditOption{Allow: allow, HasAllow: true}
		}
	case "convergence":
		var ca convergenceOptionArgs
		if err := json.Unmarshal(rawClean, &ca); err != nil {
			return fmt.Errorf("invalid convergence options: %w", err)
		}
		out.Convergence = &convergence.Options{
			EventTime:  string(ca.EventTime),
			FailedPeer: ca.FailedPeer,
			HoldTime:   ca.HoldTime,
			SilenceS:   ca.SilenceS,
		}
	}
	return nil
}
