// Package diff compares a baseline "known good" capture against a target
// capture and reports deterministic protocol, cipher, MTU, QoS, and VoIP deltas.
package diff

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/model"
)

// Options configures capture comparison across two PCAP/PCAPNG inputs.
type Options struct {
	Peers         []string
	Detectors     []string
	DisplayFilter string
	MaxPackets    *int
}

// IssueDelta identifies an issue added in or resolved by the target capture.
type IssueDelta struct {
	Detector string         `json:"detector"`
	Code     string         `json:"code"`
	Severity model.Severity `json:"severity"`
	Message  string         `json:"message"`
}

// TLSDelta captures differences in negotiated TLS versions, ciphers, ALPNs, and handshakes.
type TLSDelta struct {
	BaselineVersions []string `json:"baseline_versions"`
	TargetVersions   []string `json:"target_versions"`
	BaselineCiphers  []string `json:"baseline_ciphers"`
	TargetCiphers    []string `json:"target_ciphers"`
	BaselineALPNs    []string `json:"baseline_alpns"`
	TargetALPNs      []string `json:"target_alpns"`
	HandshakesDelta  int      `json:"handshakes_delta"`
	Changed          bool     `json:"changed"`
}

// TCPMTUDelta captures differences in offered TCP MSS values and path-MTU issues.
type TCPMTUDelta struct {
	BaselineMSS []int `json:"baseline_mss"`
	TargetMSS   []int `json:"target_mss"`
	Changed     bool  `json:"changed"`
}

// QoSDelta captures differences in observed DSCP markings across captures.
type QoSDelta struct {
	BaselineDSCPs []string `json:"baseline_dscps"`
	TargetDSCPs   []string `json:"target_dscps"`
	Changed       bool     `json:"changed"`
}

// SIPDiff summarizes changes in SIP quality score, MOS, clipping delay, and DTMF digits.
type SIPDiff struct {
	Present              bool    `json:"present"`
	BaselineScore        float64 `json:"baseline_score"`
	TargetScore          float64 `json:"target_score"`
	ScoreDelta           float64 `json:"score_delta"`
	BaselineMOS          float64 `json:"baseline_mos"`
	TargetMOS            float64 `json:"target_mos"`
	MOSDelta             float64 `json:"mos_delta"`
	BaselineClippingMS   float64 `json:"baseline_clipping_ms"`
	TargetClippingMS     float64 `json:"target_clipping_ms"`
	ClippingDelayDeltaMS float64 `json:"clipping_delay_delta_ms"`
	BaselineDTMF         string  `json:"baseline_dtmf,omitempty"`
	TargetDTMF           string  `json:"target_dtmf,omitempty"`
	Changed              bool    `json:"changed"`
}

// DiffReport contains structured behavioral deltas between baseline and target captures.
type DiffReport struct {
	Status             string       `json:"status"`
	Error              string       `json:"error,omitempty"`
	BaselineFile       string       `json:"baseline_file"`
	TargetFile         string       `json:"target_file"`
	OverallStatusDelta string       `json:"overall_status_delta"`
	BaselinePackets    int          `json:"baseline_packets"`
	TargetPackets      int          `json:"target_packets"`
	ProtocolsAdded     []string     `json:"protocols_added"`
	ProtocolsRemoved   []string     `json:"protocols_removed"`
	IssuesAdded        []IssueDelta `json:"issues_added"`
	IssuesResolved     []IssueDelta `json:"issues_resolved"`
	TLSDeltas          TLSDelta     `json:"tls_deltas"`
	TCPAndMTUDeltas    TCPMTUDelta  `json:"tcp_and_mtu_deltas"`
	QoSDSCPDeltas      QoSDelta     `json:"qos_dscp_deltas"`
	SIPDeltas          *SIPDiff     `json:"sip_deltas,omitempty"`
	Highlights         []string     `json:"highlights"`
	Verdict            string       `json:"verdict"`
}

// CompareCaptures runs deterministic detectors concurrently on baseline and target
// captures and returns the structured behavioral delta report.
func CompareCaptures(ctx context.Context, baselinePath, targetPath string, opts Options) DiffReport {
	netOpts := netorch.Options{
		Detectors:     opts.Detectors,
		Peers:         opts.Peers,
		DisplayFilter: opts.DisplayFilter,
		MaxPackets:    opts.MaxPackets,
	}

	var baseRep, tgtRep netorch.NetworkReport
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		baseRep = netorch.AnalyzeNetworkCapture(ctx, baselinePath, netOpts)
	}()
	go func() {
		defer wg.Done()
		tgtRep = netorch.AnalyzeNetworkCapture(ctx, targetPath, netOpts)
	}()
	wg.Wait()

	if baseRep.Status != "success" {
		return errDiffReport(baselinePath, targetPath, "baseline error: "+baseRep.Error)
	}
	if tgtRep.Status != "success" {
		return errDiffReport(baselinePath, targetPath, "target error: "+tgtRep.Error)
	}

	protoAdded, protoRemoved := diffStringSets(baseRep.ProtocolsPresent, tgtRep.ProtocolsPresent)
	issAdded, issResolved := diffIssues(baseRep.Issues, tgtRep.Issues)
	tlsDelta := diffTLS(baseRep.TLS, tgtRep.TLS)
	tcpDelta := diffTCPMSS(baseRep.TCP, tgtRep.TCP)
	qosDelta := diffQoS(baseRep.QoS, tgtRep.QoS)
	sipDelta := diffSIP(baseRep.SIP, tgtRep.SIP)

	statusDelta := fmt.Sprintf("%s -> %s", baseRep.OverallStatus, tgtRep.OverallStatus)
	highlights := buildHighlights(statusDelta, baseRep.OverallStatus != tgtRep.OverallStatus,
		protoAdded, protoRemoved, issAdded, issResolved, tlsDelta, tcpDelta, qosDelta, sipDelta)

	return DiffReport{
		Status:             "success",
		BaselineFile:       baselinePath,
		TargetFile:         targetPath,
		OverallStatusDelta: statusDelta,
		BaselinePackets:    baseRep.Capture.Packets,
		TargetPackets:      tgtRep.Capture.Packets,
		ProtocolsAdded:     protoAdded,
		ProtocolsRemoved:   protoRemoved,
		IssuesAdded:        issAdded,
		IssuesResolved:     issResolved,
		TLSDeltas:          tlsDelta,
		TCPAndMTUDeltas:    tcpDelta,
		QoSDSCPDeltas:      qosDelta,
		SIPDeltas:          sipDelta,
		Highlights:         highlights,
		Verdict:            buildDiffVerdict(statusDelta, issAdded, issResolved, highlights),
	}
}

// FormatDiffSummary renders a concise multi-line report for terminal output.
func FormatDiffSummary(rep DiffReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Diff: %s vs %s | Status: %s\n", rep.BaselineFile, rep.TargetFile, rep.OverallStatusDelta)
	fmt.Fprintf(&sb, "Verdict: %s\n", rep.Verdict)
	for _, h := range rep.Highlights {
		fmt.Fprintf(&sb, "- %s\n", h)
	}
	return sb.String()
}
