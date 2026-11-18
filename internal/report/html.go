// Package report extracts typed ReportDigest structures from S.O.N.I.C. JSON
// outputs for self-contained offline HTML reports and the terminal TUI viewer.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/redact"
)

// DigestIssue holds one normalized issue row for HTML and TUI rendering.
type DigestIssue struct {
	Severity string `json:"severity"`
	Detector string `json:"detector"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Frames   []int  `json:"frames"`
}

// DigestTimelineEvent holds one chronological timeline event row.
type DigestTimelineEvent struct {
	T        anyString `json:"t"`
	Protocol string    `json:"protocol"`
	Detector string    `json:"detector"`
	Event    string    `json:"event"`
	Detail   string    `json:"detail"`
	Frame    *int      `json:"frame"`
}

// anyString decodes JSON string or number values into a trimmed display string without using interface{}.
type anyString string

// UnmarshalJSON decodes scalar JSON numbers, booleans, or strings into a display string.
func (a *anyString) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*a = ""
		return nil
	}
	var s string
	if json.Unmarshal(data, &s) == nil {
		*a = anyString(s)
		return nil
	}
	*a = anyString(trimmed)
	return nil
}

// DigestVerdictRow holds one detector or rule verdict row.
type DigestVerdictRow struct {
	Name   string
	Status string
	Text   string
}

// ReportDigest provides a uniform, secret-redacted view across CLI and MCP report payloads.
type ReportDigest struct {
	Title         string
	Status        string
	OverallStatus string
	File          string
	Verdict       string
	Protocols     []string
	Verdicts      []DigestVerdictRow
	Issues        []DigestIssue
	Timeline      []DigestTimelineEvent
	Highlights    []string
	Audit         *redact.AuditCounts
	PrettyJSON    string
}

type rawReportEnvelope struct {
	Status           string                `json:"status"`
	OverallStatus    string                `json:"overall_status"`
	File             string                `json:"file"`
	BaselineFile     string                `json:"baseline_file"`
	TargetFile       string                `json:"target_file"`
	Error            string                `json:"error"`
	Verdict          string                `json:"verdict"`
	ProtocolsPresent []string              `json:"protocols_present"`
	Verdicts         map[string]string     `json:"verdicts"`
	Issues           []DigestIssue         `json:"issues"`
	Timeline         []DigestTimelineEvent `json:"timeline"`
	Highlights       []string              `json:"highlights"`
	CrossLayerLinks  []struct {
		UnderlayArea string `json:"underlay_area"`
		Severity     string `json:"severity"`
		Summary      string `json:"summary"`
	} `json:"cross_layer_links"`
	Results []struct {
		Name    string `json:"name"`
		Passed  bool   `json:"passed"`
		Summary string `json:"summary"`
	} `json:"results"`
	RedactAudit *redact.AuditCounts `json:"redact_audit"`
}

// ParseReportDigest parses any redacted S.O.N.I.C. report JSON into a normalized ReportDigest.
func ParseReportDigest(title string, rawJSON []byte, audit *redact.AuditCounts) (ReportDigest, error) {
	redactedText, inlineAudit := redact.RedactTextWithAudit(string(rawJSON))
	if audit != nil {
		merged := *audit
		merged.Add(inlineAudit)
		audit = &merged
	}
	var env rawReportEnvelope
	if err := json.Unmarshal([]byte(redactedText), &env); err != nil {
		return ReportDigest{}, fmt.Errorf("parse report json: %w", err)
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, []byte(redactedText), "", "  ") != nil {
		pretty.WriteString(redactedText)
	}
	if title == "" {
		title = "S.O.N.I.C. Inspection Report"
	}
	fileLabel := env.File
	if fileLabel == "" && env.BaselineFile != "" {
		fileLabel = fmt.Sprintf("%s vs %s", env.BaselineFile, env.TargetFile)
	}
	verdict := env.Verdict
	if verdict == "" && env.Error != "" {
		verdict = env.Error
	}

	verdictRows := make([]DigestVerdictRow, 0, len(env.Verdicts)+len(env.Results))
	for k, v := range env.Verdicts {
		verdictRows = append(verdictRows, DigestVerdictRow{Name: k, Status: "info", Text: v})
	}
	for _, r := range env.Results {
		st := "ok"
		if !r.Passed {
			st = "error"
		}
		verdictRows = append(verdictRows, DigestVerdictRow{Name: r.Name, Status: st, Text: r.Summary})
	}
	highlights := append([]string{}, env.Highlights...)
	for _, link := range env.CrossLayerLinks {
		highlights = append(highlights, fmt.Sprintf("[%s/%s] %s", link.Severity, link.UnderlayArea, link.Summary))
	}

	finalAudit := env.RedactAudit
	if finalAudit == nil {
		finalAudit = audit
	}

	return ReportDigest{
		Title:         title,
		Status:        env.Status,
		OverallStatus: env.OverallStatus,
		File:          fileLabel,
		Verdict:       verdict,
		Protocols:     env.ProtocolsPresent,
		Verdicts:      verdictRows,
		Issues:        env.Issues,
		Timeline:      env.Timeline,
		Highlights:    highlights,
		Audit:         finalAudit,
		PrettyJSON:    pretty.String(),
	}, nil
}
