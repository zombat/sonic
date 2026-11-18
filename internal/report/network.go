// Package report formats deterministic console summaries, Markdown reports, and redacted
// JSON outputs for network_orchestrator captures matching utils/network_reporting.py.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/analyze/netorch"
)

type sectionHeader struct {
	Status  string `json:"status"`
	Verdict string `json:"verdict"`
}

func netSectionRaw(rep netorch.NetworkReport, key string) json.RawMessage {
	switch key {
	case "cleartext_audit":
		return rep.CleartextAudit
	case "ipsec":
		return rep.IPsec
	case "gre_nhrp":
		return rep.GreNHRP
	case "dmvpn_phase3":
		return rep.DMVPNPhase3
	case "routing":
		return rep.Routing
	case "reachability":
		return rep.Reachability
	case "path_mtu":
		return rep.PathMTU
	case "esp_overhead":
		return rep.ESPOverhead
	case "tcp":
		return rep.TCP
	case "tls":
		return rep.TLS
	case "qos":
		return rep.QoS
	case "convergence":
		return rep.Convergence
	case "conversations":
		return rep.Conversations
	default:
		return nil
	}
}

// FormatNetworkSummary renders the human-readable console summary of a NetworkReport.
func FormatNetworkSummary(rep netorch.NetworkReport) string {
	if rep.Status != "success" {
		return fmt.Sprintf("Network analysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("S.O.N.I.C. network analysis (deterministic, no LLM)\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	fmt.Fprintf(&sb, "File: %s\n", rep.File)
	fmt.Fprintf(&sb, "Backend: %s | packets: %d | duration: %s s\n", rep.Capture.Backend, rep.Capture.Packets, DerefFloat(rep.Capture.DurationS, "0"))
	protos := strings.Join(rep.ProtocolsPresent, ", ")
	if protos == "" {
		protos = "none"
	}
	fmt.Fprintf(&sb, "Protocols present: %s\n", protos)
	fmt.Fprintf(&sb, "Overall: %s\n\n", StatusMark(rep.OverallStatus.String()))

	for _, st := range SectionTitles {
		raw := netSectionRaw(rep, st.Key)
		if len(raw) == 0 {
			continue
		}
		var hdr sectionHeader
		if json.Unmarshal(raw, &hdr) != nil {
			continue
		}
		fmt.Fprintf(&sb, "[%s] %s: %s\n", StatusMark(hdr.Status), st.Title, hdr.Verdict)
	}
	if len(rep.Issues) > 0 {
		sb.WriteString("\nIssues:\n")
		limit := min(30, len(rep.Issues))
		for _, iss := range rep.Issues[:limit] {
			fmt.Fprintf(&sb, "  - %s %s: %s\n", strings.ToUpper(iss.Severity.String()), iss.Code, iss.Message)
		}
		if len(rep.Issues) > 30 {
			fmt.Fprintf(&sb, "  ... and %d more\n", len(rep.Issues)-30)
		}
	}
	if len(rep.Timeline) > 0 {
		sb.WriteString("\nTimeline (seconds from first frame):\n")
		limit := min(40, len(rep.Timeline))
		for _, ev := range rep.Timeline[:limit] {
			fmt.Fprintf(&sb, "  %10v %-6s %-22s %s\n", ev.T, ev.Protocol, ev.Event, ev.Detail)
		}
		if len(rep.Timeline) > 40 {
			fmt.Fprintf(&sb, "  ... and %d more\n", len(rep.Timeline)-40)
		}
	}
	if rep.SIP.Present {
		grade := ""
		if rep.SIP.QualityAnalysis != nil {
			grade = string(rep.SIP.QualityAnalysis.Grade)
		}
		fmt.Fprintf(&sb, "\nSIP present: quality grade %s (see the sip section of the report)\n", grade)
	}
	return sb.String()
}

// BuildNetworkMarkdown renders a NetworkReport as structured Markdown.
func BuildNetworkMarkdown(rep netorch.NetworkReport) string {
	if rep.Status != "success" {
		return fmt.Sprintf("# S.O.N.I.C. network analysis\n\nAnalysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString("# S.O.N.I.C. network analysis\n\n")
	fmt.Fprintf(&sb, "- File: `%s`\n", rep.File)
	fmt.Fprintf(&sb, "- Backend: %s, %d packets, %d bytes, %s s\n", rep.Capture.Backend, rep.Capture.Packets, rep.Capture.Bytes, DerefFloat(rep.Capture.DurationS, "0"))
	fmt.Fprintf(&sb, "- Capture window: %s to %s\n", DerefStr(rep.Capture.Start, "none"), DerefStr(rep.Capture.End, "none"))
	if rep.Capture.DisplayFilter != nil && *rep.Capture.DisplayFilter != "" {
		fmt.Fprintf(&sb, "- Display filter: `%s`\n", *rep.Capture.DisplayFilter)
	}
	protos := strings.Join(rep.ProtocolsPresent, ", ")
	if protos == "" {
		protos = "none"
	}
	fmt.Fprintf(&sb, "- Protocols present: %s\n", protos)
	fmt.Fprintf(&sb, "- Overall status: **%s**\n\n", rep.OverallStatus)

	sb.WriteString("## Verdicts\n\n")
	for _, st := range SectionTitles {
		raw := netSectionRaw(rep, st.Key)
		if len(raw) == 0 {
			continue
		}
		var hdr sectionHeader
		if json.Unmarshal(raw, &hdr) == nil {
			fmt.Fprintf(&sb, "- **%s** (%s): %s\n", st.Title, hdr.Status, hdr.Verdict)
		}
	}
	sb.WriteString("\n## Issues\n\n")
	issRows := make([][]string, 0, len(rep.Issues))
	for _, iss := range rep.Issues {
		issRows = append(issRows, []string{iss.Severity.String(), iss.Detector, iss.Code, iss.Message, FormatInts(iss.Frames)})
	}
	sb.WriteString(MarkdownTable([]string{"severity", "detector", "code", "message", "frames"}, issRows))

	appendNetworkIPsecMarkdown(&sb, rep.IPsec)
	appendNetworkGREMarkdown(&sb, rep.GreNHRP)
	appendNetworkRoutingMarkdown(&sb, rep.Routing)
	appendNetworkReachTimelineConvMarkdown(&sb, rep)
	sb.WriteString("_Generated by S.O.N.I.C. network detectors. Frame numbers match Wireshark's._\n")
	return sb.String()
}

// SaveNetworkReport writes a redacted JSON or Markdown report for NetworkReport.
func SaveNetworkReport(rep netorch.NetworkReport, path string) error {
	raw, err := json.Marshal(rep)
	return SaveRawReport(raw, err, BuildNetworkMarkdown(rep), path)
}
