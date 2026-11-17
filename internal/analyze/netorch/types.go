// Package netorch defines detector lists, options, and combined report structs for orchestration.
package netorch

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/analyze/convergence"
	"github.com/zombat/sonic/internal/analyze/espoverhead"
	"github.com/zombat/sonic/internal/analyze/ipsec"
	"github.com/zombat/sonic/internal/analyze/reach"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/model"
)

// ReportSchema identifies the JSON output contract for network_orchestrator reports.
const ReportSchema = "sonic.network_report/1"

var (
	// DetectorNames lists the 11 detectors enabled by default on every network capture.
	DetectorNames = []string{
		"ipsec", "gre_nhrp", "dmvpn_phase3", "routing", "reachability",
		"path_mtu", "esp_overhead", "tcp", "tls", "qos", "conversations",
	}
	// AllDetectors lists all 13 detectors including opt-in cleartext_audit and convergence.
	AllDetectors = []string{
		"ipsec", "gre_nhrp", "dmvpn_phase3", "routing", "reachability",
		"path_mtu", "esp_overhead", "tcp", "tls", "qos", "conversations",
		"cleartext_audit", "convergence",
	}
	// VPNDetectors selects the three tunnel control-plane and data-plane detectors.
	VPNDetectors = []string{"ipsec", "gre_nhrp", "dmvpn_phase3"}
	// RoutingDetectors selects dynamic routing and ICMP/ARP reachability detectors.
	RoutingDetectors = []string{"routing", "reachability"}
	// DataPlaneDetectors selects MTU, ESP overhead, TCP, TLS, and QoS detectors.
	DataPlaneDetectors = []string{"path_mtu", "esp_overhead", "tcp", "tls", "qos"}
)

// AuditOption configures optional cleartext_audit allowlists when invoked through netorch.
type AuditOption struct {
	Allow    []string
	HasAllow bool
}

// DetectorOptions configures per-detector settings passed to AnalyzeNetworkCapture.
type DetectorOptions struct {
	EspOverhead    *espoverhead.Options
	TLSBaseline    *tlsinspect.Baseline
	DMVPNHubs      []string
	RoutingMSS     *int
	CleartextAudit *AuditOption
	Convergence    *convergence.Options
}

// Options controls capture filtering, detector selection, and output bounds.
type Options struct {
	Detectors     []string
	Peers         []string
	DisplayFilter string
	MaxPackets    *int
	IncludeSIP    *bool
	MaxItems      int
	DetectorOpts  DetectorOptions
}

// SIPSummary reports whether SIP frames were seen and embeds Phase 5 call quality and MOS analysis.
type SIPSummary struct {
	Present         bool                   `json:"present"`
	QualityAnalysis *sip.QualityMetrics    `json:"quality_analysis,omitempty"`
	QualityError    string                 `json:"quality_error,omitempty"`
	MOSAnalysis     *sip.MOSAnalysisResult `json:"mos_analysis,omitempty"`
	MOSError        string                 `json:"mos_error,omitempty"`
	Error           string                 `json:"error,omitempty"`
	Note            string                 `json:"note,omitempty"`
}

// NetworkBody holds shared fields across NetworkReport and wrapper reports without custom MarshalJSON promotion.
type NetworkBody struct {
	Status              string            `json:"status"`
	Error               string            `json:"error,omitempty"`
	ValidDetectors      []string          `json:"valid_detectors,omitempty"`
	Schema              string            `json:"schema"`
	File                string            `json:"file"`
	Capture             model.CaptureInfo `json:"capture"`
	ProtocolsPresent    []string          `json:"protocols_present"`
	DetectorsRequested  []string          `json:"detectors_requested"`
	DetectorsRun        []string          `json:"detectors_run"`
	DetectorsNotPresent []string          `json:"detectors_not_present"`
	OverallStatus       model.Status      `json:"overall_status"`
	Verdicts            map[string]string `json:"verdicts"`
	Issues              []model.Issue     `json:"issues"`
	IssuesOmitted       int               `json:"issues_omitted"`
	Timeline            []model.Event     `json:"timeline"`
	TimelineOmitted     int               `json:"timeline_omitted"`
	SIP                 SIPSummary        `json:"sip"`

	IPsec          json.RawMessage `json:"ipsec,omitempty"`
	GreNHRP        json.RawMessage `json:"gre_nhrp,omitempty"`
	DMVPNPhase3    json.RawMessage `json:"dmvpn_phase3,omitempty"`
	Routing        json.RawMessage `json:"routing,omitempty"`
	Reachability   json.RawMessage `json:"reachability,omitempty"`
	PathMTU        json.RawMessage `json:"path_mtu,omitempty"`
	ESPOverhead    json.RawMessage `json:"esp_overhead,omitempty"`
	TCP            json.RawMessage `json:"tcp,omitempty"`
	TLS            json.RawMessage `json:"tls,omitempty"`
	QoS            json.RawMessage `json:"qos,omitempty"`
	Conversations  json.RawMessage `json:"conversations,omitempty"`
	CleartextAudit json.RawMessage `json:"cleartext_audit,omitempty"`
	Convergence    json.RawMessage `json:"convergence,omitempty"`
}

// NetworkReport is the combined JSON report returned by AnalyzeNetworkCapture.
type NetworkReport struct {
	NetworkBody
}

func marshalErrBody(b NetworkBody) ([]byte, error) {
	type errPayload struct {
		Status         string   `json:"status"`
		Error          string   `json:"error"`
		ValidDetectors []string `json:"valid_detectors,omitempty"`
	}
	return json.Marshal(errPayload{
		Status:         b.Status,
		Error:          b.Error,
		ValidDetectors: b.ValidDetectors,
	})
}

// MarshalJSON emits {"status":"error",...} on failure or the full NetworkReport on success.
func (r NetworkReport) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		return marshalErrBody(r.NetworkBody)
	}
	type fullNetwork NetworkReport
	return json.Marshal(fullNetwork(r))
}

// IKEDiagnosis summarizes one IKE SA negotiation outcome lifted to VPNReport.
type IKEDiagnosis struct {
	Initiator    *string         `json:"initiator"`
	Responder    *string         `json:"responder"`
	InitiatorSPI string          `json:"initiator_spi"`
	Outcome      string          `json:"outcome"`
	Diagnosis    ipsec.Diagnosis `json:"diagnosis"`
}

// VPNReport wraps NetworkBody with top-level IPsec, DMVPN overlay, and IKE summaries.
type VPNReport struct {
	EncryptionVerdict  string         `json:"encryption_verdict"`
	Verdict            string         `json:"verdict"`
	NegotiationVerdict string         `json:"negotiation_verdict"`
	OverlayVerdict     string         `json:"overlay_verdict"`
	Phase3Verdict      string         `json:"phase3_verdict"`
	IKEDiagnoses       []IKEDiagnosis `json:"ike_diagnoses"`
	NetworkBody
}

// MarshalJSON emits error JSON on failure or the full VPNReport on success.
func (r VPNReport) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		return marshalErrBody(r.NetworkBody)
	}
	type fullVPN VPNReport
	return json.Marshal(fullVPN(r))
}

// PingOutage pairs an ICMP echo outage window with its source and destination addresses.
type PingOutage struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	reach.OutageWindow
}

// RoutingReport wraps NetworkBody with top-level routing, reachability, and failover summaries.
type RoutingReport struct {
	Verdict             string        `json:"verdict"`
	ReachabilityVerdict string        `json:"reachability_verdict"`
	FailoverTimeline    []model.Event `json:"failover_timeline"`
	PingOutages         []PingOutage  `json:"ping_outages"`
	NetworkBody
}

// MarshalJSON emits error JSON on failure or the full RoutingReport on success.
func (r RoutingReport) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		return marshalErrBody(r.NetworkBody)
	}
	type fullRouting RoutingReport
	return json.Marshal(fullRouting(r))
}

// ConvergenceReport exposes lifted failover timeline and measurement fields for convergence_dpd parity.
type ConvergenceReport struct {
	Status           string                      `json:"status"`
	Error            string                      `json:"error,omitempty"`
	Verdict          string                      `json:"verdict"`
	Driver           convergence.DriverInfo      `json:"driver"`
	FailedPeer       *string                     `json:"failed_peer"`
	FailedPeerSource *string                     `json:"failed_peer_source"`
	EventTime        *string                     `json:"event_time"`
	EventT           *float64                    `json:"event_t"`
	Measurements     convergence.Measurements    `json:"measurements"`
	Timeline         []convergence.TimelineEntry `json:"timeline"`
	TimelineOmitted  int                         `json:"timeline_omitted"`
	TrafficShift     *convergence.TrafficShift   `json:"traffic_shift"`
	Issues           []model.Issue               `json:"issues"`
	CannotShow       []string                    `json:"cannot_show"`
	File             string                      `json:"file"`
	Capture          model.CaptureInfo           `json:"capture"`
	ProtocolsPresent []string                    `json:"protocols_present"`
}

// MarshalJSON encodes {"status":"error","error":...} when convergence fails or full output on success.
func (r ConvergenceReport) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		type errPayload struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		return json.Marshal(errPayload{Status: r.Status, Error: r.Error})
	}
	type fullConv ConvergenceReport
	return json.Marshal(fullConv(r))
}

// DataPlaneReport wraps NetworkBody with top-level per-detector data-plane verdicts.
type DataPlaneReport struct {
	PathMTUVerdict     string `json:"path_mtu_verdict"`
	ESPOverheadVerdict string `json:"esp_overhead_verdict"`
	TCPVerdict         string `json:"tcp_verdict"`
	TLSVerdict         string `json:"tls_verdict"`
	QoSVerdict         string `json:"qos_verdict"`
	NetworkBody
}

// MarshalJSON emits error JSON on failure or the full DataPlaneReport on success.
func (r DataPlaneReport) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		return marshalErrBody(r.NetworkBody)
	}
	type fullDP DataPlaneReport
	return json.Marshal(fullDP(r))
}
