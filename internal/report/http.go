// Package report formats deterministic console summaries, Markdown reports, and redacted
// JSON outputs for RESTCONF/REST HTTP inspections matching utils/http_reporting.py.
package report

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/httpinspect"
)

// FormatHTTPSummary renders the human-readable console summary of an HTTP/RESTCONF Report.
func FormatHTTPSummary(rep httpinspect.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("RESTCONF/REST analysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("S.O.N.I.C. RESTCONF and REST troubleshooting (Wireshark dissectors through tshark, no LLM)\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	fmt.Fprintf(&sb, "File: %s\n", rep.File)
	decAs := strings.Join(rep.Capture.DecodeAs, ", ")
	if decAs == "" {
		decAs = "none"
	}
	fmt.Fprintf(&sb, "tshark: %s | HTTP messages: %d | decode-as: %s\n", DerefStr(rep.Capture.TShark, "none"), rep.Capture.HTTPMessages, decAs)
	fmt.Fprintf(&sb, "Overall: %s\n", StatusMark(rep.OverallStatus.String()))
	fmt.Fprintf(&sb, "Verdict: %s\n", rep.Verdict)

	if cov := rep.TLSDecryption; cov != nil && cov.Total > 0 {
		fmt.Fprintf(&sb, "🔓 TLS decryption: %s\n", cov.Verdict)
		for _, r := range cov.Sessions {
			if !r.Decrypted && cov.SecretsSource != nil {
				fmt.Fprintf(&sb, "  not decrypted: %s: %s\n", r.Flow, DerefStr(r.Reason, ""))
			}
		}
	}
	for _, c := range rep.Connections {
		vers := strings.Join(c.HTTPVersions, ", ")
		if vers == "" {
			vers = "?"
		}
		rc := ""
		if c.Restconf != nil && *c.Restconf {
			rc = ", RESTCONF"
		}
		fmt.Fprintf(&sb, "\n[%s] %s %s (HTTP/%s%s)\n", c.Transport, c.Flow, c.Service, vers, rc)
	}
	if len(rep.Requests) > 0 {
		sb.WriteString("\nRequests:\n")
		limit := min(40, len(rep.Requests))
		for _, r := range rep.Requests[:limit] {
			ms := "-"
			if r.TimingMS != nil {
				ms = fmt.Sprintf("%v ms", *r.TimingMS)
			}
			path := CleanCell(DerefStr(r.Path, ""))
			if len(path) > 52 {
				path = path[:52]
			}
			fmt.Fprintf(&sb, "  %-7s %-52s -> %-4s %-9s %s\n",
				DerefStr(r.Method, "?"), path, DerefInt(r.Status, ""), ms, CleanCell(DerefStr(r.ResponseContentType, "")))
			for _, re := range r.RestconfErrors {
				fmt.Fprintf(&sb, "        ! %s %s %s\n", re["error-tag"], re["error-path"], re["error-message"])
			}
		}
	}
	if len(rep.Credentials) > 0 {
		sb.WriteString("\n🔑 Credentials present (values masked):\n")
		for _, c := range rep.Credentials {
			where := "over TLS"
			if c.Cleartext {
				where = "CLEARTEXT"
			}
			scheme := ""
			if c.Scheme != nil && *c.Scheme != "" {
				scheme = " " + *c.Scheme
			}
			fmt.Fprintf(&sb, "  [%s] %s%s on %s in %d request(s)\n", where, c.Header, scheme, c.Flow, c.Requests)
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

// BuildHTTPMarkdown renders an HTTP/RESTCONF Report as structured Markdown.
func BuildHTTPMarkdown(rep httpinspect.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("# S.O.N.I.C. RESTCONF/REST report\n\nAnalysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString("# S.O.N.I.C. RESTCONF and REST troubleshooting\n\n")
	fmt.Fprintf(&sb, "**File:** `%s`  \n**tshark:** %s  \n**Overall:** %s  \n**Verdict:** %s\n\n",
		rep.File, DerefStr(rep.Capture.TShark, "none"), StatusMark(rep.OverallStatus.String()), rep.Verdict)

	if rep.Capture.TLSSecrets.Source != nil {
		fmt.Fprintf(&sb, "TLS secrets: %s (key log: %d, pcapng: %d).\n\n",
			*rep.Capture.TLSSecrets.Source, rep.Capture.TLSSecrets.SessionsInKeyLog, rep.Capture.TLSSecrets.SessionsInPCAPNG)
	}
	if cov := rep.TLSDecryption; cov != nil && cov.Total > 0 {
		sb.WriteString("## TLS decryption\n\n" + cov.Verdict + "\n\n")
		rows := make([][]string, 0, len(cov.Sessions))
		for _, s := range cov.Sessions {
			sec := strings.Join(s.SecretIn, ", ")
			if sec == "" {
				sec = "-"
			}
			rows = append(rows, []string{s.Flow, s.Service, YesNo(s.Decrypted), sec, DerefStr(s.Reason, "-")})
		}
		sb.WriteString(MarkdownTable([]string{"flow", "service", "decrypted", "secret_in", "reason"}, rows) + "\n")
	}

	sb.WriteString("## Connections\n\n")
	connRows := make([][]string, 0, len(rep.Connections))
	for _, c := range rep.Connections {
		connRows = append(connRows, []string{c.Flow, c.Service, c.Transport, strings.Join(c.HTTPVersions, ", "), DerefBool(c.Restconf, "no"), strconv.Itoa(c.Requests)})
	}
	sb.WriteString(MarkdownTable([]string{"flow", "service", "transport", "http", "restconf", "requests"}, connRows) + "\n")

	if len(rep.Requests) > 0 {
		sb.WriteString("## Requests\n\n")
		reqRows := make([][]string, 0, len(rep.Requests))
		for _, r := range rep.Requests {
			var tags []string
			for _, re := range r.RestconfErrors {
				tags = append(tags, re["error-tag"])
			}
			rcStr := ""
			if r.Restconf {
				rcStr = "yes"
			}
			reqRows = append(reqRows, []string{
				DerefStr(r.Method, ""), DerefStr(r.Path, ""), DerefInt(r.Status, ""),
				DerefFloat(r.TimingMS, ""), DerefStr(r.ResponseContentType, ""), rcStr,
				strings.Join(tags, "; "), DerefStr(r.Location, ""),
			})
		}
		sb.WriteString(MarkdownTable([]string{"method", "path", "status", "ms", "content_type", "restconf", "errors", "location"}, reqRows) + "\n")
	}
	if len(rep.Credentials) > 0 {
		sb.WriteString("## Credentials present (values masked)\n\n")
		credRows := make([][]string, 0, len(rep.Credentials))
		for _, c := range rep.Credentials {
			cl := "no (TLS)"
			if c.Cleartext {
				cl = "yes"
			}
			credRows = append(credRows, []string{c.Flow, c.Header, DerefStr(c.Scheme, ""), cl, strconv.Itoa(c.Requests)})
		}
		sb.WriteString(MarkdownTable([]string{"flow", "header", "scheme", "cleartext", "requests"}, credRows) + "\n")
	}
	AppendMarkdownIssues(&sb, rep.Issues)
	AppendMarkdownLimits(&sb, rep.Limits)
	sb.WriteString("_Generated by S.O.N.I.C. RESTCONF/REST troubleshooting. Frame numbers match Wireshark's._\n")
	return sb.String()
}

// SaveHTTPReport writes a redacted JSON or Markdown report for httpinspect.Report.
func SaveHTTPReport(rep httpinspect.Report, path string) error {
	raw, err := json.Marshal(rep)
	return SaveRawReport(raw, err, BuildHTTPMarkdown(rep), path)
}
