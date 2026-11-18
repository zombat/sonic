// Package report formats deterministic console summaries, Markdown reports, and redacted
// JSON outputs for TACACS+/RADIUS AAA inspections matching utils/aaa_reporting.py.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/analyze/aaainspect"
)

func boolValidStr(p *bool) string {
	if p == nil {
		return "-"
	}
	if *p {
		return "valid"
	}
	return "invalid"
}

// FormatAAASummary renders the human-readable console summary of an AAA Report.
func FormatAAASummary(rep aaainspect.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("AAA analysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("S.O.N.I.C. TACACS+ and RADIUS troubleshooting (Wireshark dissectors through tshark, no LLM)\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	fmt.Fprintf(&sb, "File: %s\n", rep.File)
	var keys []string
	if rep.Capture.TacacsKeyGiven {
		keys = append(keys, "tacacs key")
	}
	if rep.Capture.RadiusSecretGiven {
		keys = append(keys, "radius secret")
	}
	keyStr := strings.Join(keys, ", ")
	if keyStr == "" {
		keyStr = "none"
	}
	fmt.Fprintf(&sb, "tshark: %s | keys given: %s\n", DerefStr(rep.Capture.Tshark, "none"), keyStr)
	fmt.Fprintf(&sb, "Overall: %s\n", StatusMark(rep.OverallStatus.String()))
	fmt.Fprintf(&sb, "Verdict: %s\n", rep.Verdict)

	if len(rep.Radius) > 0 {
		sb.WriteString("\nRADIUS:\n")
		for _, e := range rep.Radius {
			acct := ""
			if e.AcctStatus != nil && *e.AcctStatus != "" {
				acct = " acct " + *e.AcctStatus
			}
			badAuth := ""
			if e.AuthenticatorValid != nil && !*e.AuthenticatorValid {
				badAuth = "  BAD AUTHENTICATOR"
			}
			fmt.Fprintf(&sb, "  %-10s id %-4s %-14s %s -> %-18s [%s]%s%s  Message-Authenticator %s/%s\n",
				e.Kind, DerefInt(e.ID, "?"), DerefStr(e.Username, "?"),
				DerefStr(e.RequestCode, ""), DerefStr(e.ResponseCode, "-"), e.Result,
				acct, badAuth, DerefStr(e.MessageAuthenticator.Request, "-"), DerefStr(e.MessageAuthenticator.Response, "-"))
		}
	}
	if len(rep.Tacacs) > 0 {
		sb.WriteString("\nTACACS+:\n")
		for _, s := range rep.Tacacs {
			flags := ""
			if s.Cleartext {
				flags = " CLEARTEXT"
			}
			var res []string
			for _, x := range []*string{s.Authentication, s.Authorization, s.Accounting} {
				if x != nil && *x != "" {
					res = append(res, *x)
				}
			}
			resStr := strings.Join(res, "/")
			if resStr == "" {
				resStr = "-"
			}
			fmt.Fprintf(&sb, "  session 0x%08x %-12s %-28s %s%s\n",
				s.SessionID, DerefStr(s.User, "?"), strings.Join(s.Types, ","), resStr, flags)
		}
	}
	if len(rep.Credentials) > 0 {
		sb.WriteString("\n🔑 Credentials recovered (values masked):\n")
		for _, c := range rep.Credentials {
			fmt.Fprintf(&sb, "  [%s] %s for %s on %s\n", c.Protocol, c.Kind, DerefStr(c.Username, "?"), c.Flow)
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

// BuildAAAMarkdown renders an AAA Report as structured Markdown.
func BuildAAAMarkdown(rep aaainspect.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("# S.O.N.I.C. AAA report\n\nAnalysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString("# S.O.N.I.C. TACACS+ and RADIUS troubleshooting\n\n")
	fmt.Fprintf(&sb, "**File:** `%s`  \n**tshark:** %s  \n**Overall:** %s  \n**Verdict:** %s\n\n",
		rep.File, DerefStr(rep.Capture.Tshark, "none"), StatusMark(rep.OverallStatus.String()), rep.Verdict)

	if len(rep.Radius) > 0 {
		sb.WriteString("## RADIUS\n\n")
		rows := make([][]string, 0, len(rep.Radius))
		for _, e := range rep.Radius {
			rows = append(rows, []string{
				e.Kind, DerefInt(e.ID, ""), DerefStr(e.Username, ""), DerefStr(e.RequestCode, ""),
				DerefStr(e.ResponseCode, ""), e.Result, DerefStr(e.AcctStatus, ""), DerefStr(e.NAS, ""),
				boolValidStr(e.AuthenticatorValid),
				DerefStr(e.MessageAuthenticator.Request, "-") + "/" + DerefStr(e.MessageAuthenticator.Response, "-"),
				DerefStr(e.Credential, ""),
			})
		}
		sb.WriteString(MarkdownTable([]string{"kind", "id", "user", "request", "response", "result", "acct", "nas", "authenticator", "msg_auth", "credential"}, rows) + "\n")
	}
	if len(rep.Tacacs) > 0 {
		sb.WriteString("## TACACS+\n\n")
		rows := make([][]string, 0, len(rep.Tacacs))
		for _, s := range rep.Tacacs {
			cl := ""
			if s.Cleartext {
				cl = "yes"
			}
			rows = append(rows, []string{
				fmt.Sprintf("0x%08x", s.SessionID), DerefStr(s.User, ""), strings.Join(s.Types, ", "),
				DerefStr(s.Action, ""), DerefStr(s.Service, ""), DerefStr(s.Authentication, ""),
				DerefStr(s.Authorization, ""), DerefStr(s.Accounting, ""), cl, DerefStr(s.Credential, ""),
			})
		}
		sb.WriteString(MarkdownTable([]string{"session", "user", "types", "action", "service", "authentication", "authorization", "accounting", "cleartext", "credential"}, rows) + "\n")
	}
	if len(rep.Credentials) > 0 {
		sb.WriteString("## Credentials recovered (values masked)\n\n")
		rows := make([][]string, 0, len(rep.Credentials))
		for _, c := range rep.Credentials {
			rows = append(rows, []string{c.Protocol, c.Flow, DerefStr(c.Username, ""), c.Kind, c.Value})
		}
		sb.WriteString(MarkdownTable([]string{"protocol", "flow", "user", "kind", "value"}, rows) + "\n")
	}
	AppendMarkdownIssues(&sb, rep.Issues)
	AppendMarkdownLimits(&sb, rep.Limits)
	sb.WriteString("_Generated by S.O.N.I.C. AAA troubleshooting. Frame numbers match Wireshark's._\n")
	return sb.String()
}

// SaveAAAReport writes a redacted JSON or Markdown report for aaainspect.Report.
func SaveAAAReport(rep aaainspect.Report, path string) error {
	raw, err := json.Marshal(rep)
	return SaveRawReport(raw, err, BuildAAAMarkdown(rep), path)
}
