// Package report formats deterministic console summaries, Markdown reports, and redacted
// JSON outputs for SNMP inspections matching utils/snmp_reporting.py.
package report

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/snmpinspect"
)

func formatOutcomes(outcomes map[string]int, replaceUnderscore bool) string {
	keys := make([]string, 0, len(outcomes))
	for k := range outcomes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		lbl := k
		if replaceUnderscore {
			lbl = strings.ReplaceAll(k, "_", " ")
		}
		parts = append(parts, fmt.Sprintf("%d %s", outcomes[k], lbl))
	}
	return strings.Join(parts, ", ")
}

// FormatSNMPSummary renders the human-readable console summary of an SNMP Report.
func FormatSNMPSummary(rep snmpinspect.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("SNMP analysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("S.O.N.I.C. SNMP troubleshooting (Wireshark dissector through tshark, no LLM)\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	fmt.Fprintf(&sb, "File: %s\n", rep.File)
	uState := "no"
	if rep.Capture.UsersFileGiven {
		uState = fmt.Sprintf("yes (%d user(s))", rep.Capture.UsersCount)
	}
	fmt.Fprintf(&sb, "tshark: %s | users file: %s\n", DerefStr(rep.Capture.Tshark, "none"), uState)
	fmt.Fprintf(&sb, "Overall: %s\n", StatusMark(rep.OverallStatus.String()))
	fmt.Fprintf(&sb, "Verdict: %s\n", rep.Verdict)
	vB, _ := json.Marshal(rep.Summary.Versions)
	sB, _ := json.Marshal(rep.Summary.V3SecurityLevels)
	fmt.Fprintf(&sb, "Versions: %s | v3 security levels: %s\n", string(vB), string(sB))

	if len(rep.V3Users) > 0 {
		sb.WriteString("\n🔓 SNMPv3 users (outcome per authenticated message):\n")
		for _, u := range rep.V3Users {
			fmt.Fprintf(&sb, "  %-20s %s\n", DerefStr(u.User, "?"), formatOutcomes(u.Outcomes, true))
		}
	}
	if len(rep.Messages) > 0 {
		sb.WriteString("\nMessages:\n")
		limit := min(40, len(rep.Messages))
		for _, m := range rep.Messages[:limit] {
			extra := ""
			if m.Version == "v3" {
				extra = " user=" + DerefStr(m.User, "-")
				if m.Role != "" {
					extra += fmt.Sprintf(" [%s]", m.Role)
				}
				if m.Outcome != "" {
					extra += " " + m.Outcome
				}
				if m.Report != "" {
					extra += " report " + m.Report
				}
			}
			fmt.Fprintf(&sb, "  %-4s %-13s %-17s %s -> %s%s\n",
				m.Version, m.SecurityLevel, DerefStr(m.PDU, ""), m.Src, m.Dst, extra)
		}
	}
	if len(rep.Credentials) > 0 {
		sb.WriteString("\n🔑 Cleartext community credentials (values masked):\n")
		for _, c := range rep.Credentials {
			fmt.Fprintf(&sb, "  [%s] %s on %s\n", c.Protocol, c.Kind, c.Flow)
		}
	}
	if len(rep.Issues) > 0 {
		fmt.Fprintf(&sb, "\nIssues (%d):\n", len(rep.Issues))
		limit := min(30, len(rep.Issues))
		for _, iss := range rep.Issues[:limit] {
			fmt.Fprintf(&sb, "  [%s] %s: %s\n", iss.Severity, iss.Code, iss.Message)
		}
	}
	return sb.String()
}

// BuildSNMPMarkdown renders an SNMP Report as structured Markdown.
func BuildSNMPMarkdown(rep snmpinspect.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("# S.O.N.I.C. SNMP report\n\nAnalysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString("# S.O.N.I.C. SNMP troubleshooting\n\n")
	fmt.Fprintf(&sb, "**File:** `%s`  \n**tshark:** %s  \n**Overall:** %s  \n**Verdict:** %s\n\n",
		rep.File, DerefStr(rep.Capture.Tshark, "none"), StatusMark(rep.OverallStatus.String()), rep.Verdict)
	vB, _ := json.Marshal(rep.Summary.Versions)
	sB, _ := json.Marshal(rep.Summary.V3SecurityLevels)
	fmt.Fprintf(&sb, "Versions: %s. v3 security levels: %s. authPriv decrypted: %d/%d.\n\n",
		string(vB), string(sB), rep.Summary.AuthPrivDecrypted, rep.Summary.AuthPrivDecrypted+rep.Summary.AuthPrivNotDecrypted)

	sb.WriteString("## Messages\n\n")
	msgRows := make([][]string, 0, len(rep.Messages))
	for _, m := range rep.Messages {
		outcome := m.Outcome
		if outcome == "" {
			outcome = m.Role
		}
		msgRows = append(msgRows, []string{
			DerefInt(m.Frame, ""), m.Version, m.SecurityLevel, DerefStr(m.PDU, ""),
			m.Src, m.Dst, DerefStr(m.User, ""), outcome, m.Report, DerefStr(m.Reason, ""), m.Credential,
		})
	}
	sb.WriteString(MarkdownTable([]string{"frame", "version", "security_level", "pdu", "src", "dst", "user", "outcome", "report", "reason", "credential"}, msgRows) + "\n")

	if len(rep.V3Users) > 0 {
		sb.WriteString("## SNMPv3 users\n\n")
		uRows := make([][]string, 0, len(rep.V3Users))
		for _, u := range rep.V3Users {
			uRows = append(uRows, []string{DerefStr(u.User, ""), strconv.Itoa(u.Messages), formatOutcomes(u.Outcomes, false)})
		}
		sb.WriteString(MarkdownTable([]string{"user", "messages", "outcomes"}, uRows) + "\n")
	}
	if len(rep.Credentials) > 0 {
		sb.WriteString("## Cleartext community credentials (values masked)\n\n")
		cRows := make([][]string, 0, len(rep.Credentials))
		for _, c := range rep.Credentials {
			cRows = append(cRows, []string{c.Protocol, c.Flow, c.Kind, c.Value})
		}
		sb.WriteString(MarkdownTable([]string{"protocol", "flow", "kind", "value"}, cRows) + "\n")
	}
	AppendMarkdownIssues(&sb, rep.Issues)
	AppendMarkdownLimits(&sb, rep.Limits)
	sb.WriteString("_Generated by S.O.N.I.C. SNMP troubleshooting. Frame numbers match Wireshark's._\n")
	return sb.String()
}

// SaveSNMPReport writes a redacted JSON or Markdown report for snmpinspect.Report.
func SaveSNMPReport(rep snmpinspect.Report, path string) error {
	raw, err := json.Marshal(rep)
	return SaveRawReport(raw, err, BuildSNMPMarkdown(rep), path)
}
