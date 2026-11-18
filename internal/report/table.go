// Package report implements console summaries, Markdown/JSON report formatters,
// secret-redacting file output, SIP auth visualizations, and MCP stdio reservation.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/redact"
)

// SectionTitle pairs a netorch detector key with its display heading.
type SectionTitle struct {
	Key   string
	Title string
}

// SectionTitles defines the deterministic section display order matching network_reporting.py.
var SectionTitles = []SectionTitle{
	{Key: "cleartext_audit", Title: "Zero-cleartext audit"},
	{Key: "ipsec", Title: "IPsec / VPN"},
	{Key: "gre_nhrp", Title: "GRE / NHRP (DMVPN)"},
	{Key: "dmvpn_phase3", Title: "DMVPN Phase 3 sequence"},
	{Key: "routing", Title: "Routing protocols"},
	{Key: "reachability", Title: "Reachability (ICMP / ARP)"},
	{Key: "path_mtu", Title: "Path MTU and fragmentation"},
	{Key: "esp_overhead", Title: "ESP overhead (estimate)"},
	{Key: "tcp", Title: "TCP health"},
	{Key: "tls", Title: "TLS"},
	{Key: "qos", Title: "QoS"},
	{Key: "convergence", Title: "Convergence"},
	{Key: "conversations", Title: "Conversations"},
}

// StatusMark translates internal status codes to display labels.
func StatusMark(status string) string {
	switch status {
	case "ok":
		return "OK"
	case "warning":
		return "WARNING"
	case "problem":
		return "PROBLEM"
	case "not_present":
		return "not present"
	default:
		return status
	}
}

// CleanCell escapes pipe and newline characters inside Markdown table cells.
func CleanCell(v string) string {
	v = strings.ReplaceAll(v, "|", "/")
	return strings.ReplaceAll(v, "\n", " ")
}

// MarkdownTable renders a GitHub-flavored Markdown table or "_none_\n" when empty.
func MarkdownTable(columns []string, rows [][]string) string {
	if len(rows) == 0 {
		return "_none_\n"
	}
	var sb strings.Builder
	sb.WriteString("| ")
	sb.WriteString(strings.Join(columns, " | "))
	sb.WriteString(" |\n|")
	for range columns {
		sb.WriteString("---|")
	}
	sb.WriteByte('\n')
	for _, row := range rows {
		sb.WriteString("| ")
		for i := range columns {
			if i > 0 {
				sb.WriteString(" | ")
			}
			if i < len(row) {
				sb.WriteString(CleanCell(row[i]))
			}
		}
		sb.WriteString(" |\n")
	}
	return sb.String()
}

// FormatInts joins integer slices with ", " for concise report tables.
func FormatInts(nums []int) string {
	if len(nums) == 0 {
		return ""
	}
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

// DerefStr returns *p when non-nil, otherwise fallback.
func DerefStr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}

// DerefInt returns the decimal string of *p when non-nil, otherwise fallback.
func DerefInt(p *int, fallback string) string {
	if p == nil {
		return fallback
	}
	return strconv.Itoa(*p)
}

// DerefFloat returns a formatted string of *p when non-nil, otherwise fallback.
func DerefFloat(p *float64, fallback string) string {
	if p == nil {
		return fallback
	}
	return fmt.Sprintf("%v", *p)
}

// DerefBool returns "yes" / "no" / fallback for an optional boolean pointer.
func DerefBool(p *bool, fallback string) string {
	if p == nil {
		return fallback
	}
	if *p {
		return "yes"
	}
	return "no"
}

// YesNo renders a boolean as "yes" or "no".
func YesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// AppendMarkdownIssues writes the common Issues section across Markdown protocol reports.
func AppendMarkdownIssues(sb *strings.Builder, issues []model.Issue) {
	if len(issues) == 0 {
		return
	}
	sb.WriteString("## Issues\n\n")
	for _, iss := range issues {
		frames := ""
		if len(iss.Frames) > 0 {
			frames = fmt.Sprintf(" (frames [%s])", FormatInts(iss.Frames))
		}
		fmt.Fprintf(sb, "- **[%s] %s**: %s%s\n", iss.Severity, iss.Code, iss.Message, frames)
	}
	sb.WriteByte('\n')
}

// AppendMarkdownLimits writes the Limits bullet section across Markdown protocol reports.
func AppendMarkdownLimits(sb *strings.Builder, limits []string) {
	sb.WriteString("## Limits\n\n")
	for _, line := range limits {
		fmt.Fprintf(sb, "- %s\n", line)
	}
	sb.WriteByte('\n')
}

// WriteRedacted masks secrets in content using redact.RedactText and writes path safely.
func WriteRedacted(path, content string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create report dir %s: %w", dir, err)
		}
	}
	masked := redact.RedactText(content)
	if err := os.WriteFile(path, []byte(masked), 0o644); err != nil {
		return fmt.Errorf("write report %s: %w", path, err)
	}
	return nil
}

// SaveRawReport writes pretty-indented redacted JSON (for .json paths) or redacted Markdown.
func SaveRawReport(rawJSON []byte, jsonErr error, markdown, path string) error {
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if jsonErr != nil {
			return fmt.Errorf("marshal report json: %w", jsonErr)
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, rawJSON, "", "  "); err != nil {
			return fmt.Errorf("indent report json: %w", err)
		}
		buf.WriteByte('\n')
		return WriteRedacted(path, buf.String())
	}
	return WriteRedacted(path, markdown)
}
