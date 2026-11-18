// Package report formats deterministic console summaries, Markdown reports, and redacted
// JSON outputs for gRPC/gNMI/gNOI inspections matching utils/grpc_reporting.py.
package report

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/model"
)

// FormatGRPCSummary renders the human-readable console summary of a gRPC Report.
func FormatGRPCSummary(rep grpc.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("gRPC analysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("S.O.N.I.C. gRPC troubleshooting (Wireshark dissectors through tshark, no LLM)\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	fmt.Fprintf(&sb, "File: %s\n", rep.File)
	decAs := strings.Join(rep.Capture.DecodeAs, ", ")
	if decAs == "" {
		decAs = "none"
	}
	fmt.Fprintf(&sb, "tshark: %s | HTTP/2 packets: %d | decode-as: %s\n", DerefStr(rep.Capture.TShark, "none"), rep.Capture.HTTP2Packets, decAs)
	fmt.Fprintf(&sb, "Overall: %s\n", StatusMark(rep.OverallStatus.String()))
	fmt.Fprintf(&sb, "Verdict: %s\n", rep.Verdict)

	if cov := rep.TLSDecryption; cov != nil && cov.Total > 0 {
		fmt.Fprintf(&sb, "🔓 TLS decryption: %s\n", cov.Verdict)
		for _, row := range cov.Sessions {
			if !row.Decrypted && cov.SecretsSource != nil {
				fmt.Fprintf(&sb, "  not decrypted: %s: %s\n", row.Flow, DerefStr(row.Reason, ""))
			}
		}
	}
	for _, conn := range rep.Connections {
		svcs := ""
		if len(conn.Services) > 0 {
			svcs = " services: " + strings.Join(conn.Services, ", ")
		}
		fmt.Fprintf(&sb, "\n[%s] %s %s (%s)%s\n", conn.Transport, conn.Flow, DerefStr(conn.Service, ""), conn.Protocol, svcs)
		if tls := conn.TLS; tls != nil {
			certDesc := ""
			if c := tls.Certificate; c != nil && c.Parsed != nil && *c.Parsed {
				var ipSANs []string
				if c.IPAddresses != nil {
					ipSANs = *c.IPAddresses
				}
				certDesc = fmt.Sprintf(" certificate %s (IP SANs %v)", DerefStr(c.Subject, ""), ipSANs)
			}
			fmt.Fprintf(&sb, "  TLS %s SNI %s ALPN offered %v%s\n", DerefStr(tls.Version, "none"), DerefStr(tls.SNI, "none"), tls.ALPNOffered, certDesc)
		}
	}
	if len(rep.RPCs) > 0 {
		sb.WriteString("\nRPCs:\n")
		limit := min(40, len(rep.RPCs))
		for _, r := range rep.RPCs[:limit] {
			st := DerefStr(r.GrpcStatusName, r.Outcome)
			fmt.Fprintf(&sb, "  stream %4d %-48s %-18s %s\n", r.StreamID, DerefStr(r.Method, "?"), st, r.Diagnosis)
		}
		if len(rep.RPCs) > 40 {
			fmt.Fprintf(&sb, "  ... and %d more\n", len(rep.RPCs)-40)
		}
	}
	if len(rep.Credentials) > 0 {
		sb.WriteString("\nCredentials in metadata (values masked):\n")
		for _, c := range rep.Credentials {
			where := c.Transport
			if c.Cleartext {
				where = "CLEARTEXT"
			}
			fmt.Fprintf(&sb, "  %-16s %s %s in %d request(s), frames %v\n", c.Key, c.Flow, where, c.Requests, c.Frames)
		}
	}
	var errWarn []model.Issue
	for _, iss := range rep.Issues {
		if iss.Severity == model.SeverityError || iss.Severity == model.SeverityWarning {
			errWarn = append(errWarn, iss)
		}
	}
	if len(errWarn) > 0 {
		sb.WriteString("\nIssues:\n")
		limit := min(30, len(errWarn))
		for _, iss := range errWarn[:limit] {
			fmt.Fprintf(&sb, "  - %s %s: %s\n", strings.ToUpper(iss.Severity.String()), iss.Code, iss.Message)
		}
		if len(errWarn) > 30 {
			fmt.Fprintf(&sb, "  ... and %d more\n", len(errWarn)-30)
		}
	}
	return sb.String()
}

// BuildGRPCMarkdown renders a gRPC Report as structured Markdown.
func BuildGRPCMarkdown(rep grpc.Report) string {
	if rep.Status != "success" {
		return fmt.Sprintf("# S.O.N.I.C. gRPC troubleshooting\n\nAnalysis failed: %s\n", rep.Error)
	}
	var sb strings.Builder
	sb.WriteString("# S.O.N.I.C. gRPC troubleshooting\n\n")
	fmt.Fprintf(&sb, "- File: `%s`\n", rep.File)
	fmt.Fprintf(&sb, "- tshark: %s; HTTP/2 packets: %d\n", DerefStr(rep.Capture.TShark, "none"), rep.Capture.HTTP2Packets)
	decAs := "none"
	if len(rep.Capture.DecodeAs) > 0 {
		parts := make([]string, len(rep.Capture.DecodeAs))
		for i, d := range rep.Capture.DecodeAs {
			parts[i] = "`" + d + "`"
		}
		decAs = strings.Join(parts, ", ")
	}
	fmt.Fprintf(&sb, "- Decode-as: %s\n", decAs)
	protos := strings.Join(rep.Capture.ProtoPaths, ", ")
	if protos == "" {
		protos = "none"
	}
	fmt.Fprintf(&sb, "- Key log given: %s; TLS secrets: %s; .proto paths: %s\n", YesNo(rep.Capture.KeylogFileGiven), DerefStr(rep.Capture.TLSSecrets.Source, "none"), protos)
	fmt.Fprintf(&sb, "- Overall status: **%s**\n\n", rep.OverallStatus)
	fmt.Fprintf(&sb, "**Verdict:** %s\n\n", rep.Verdict)

	if cov := rep.TLSDecryption; cov != nil && cov.Total > 0 {
		sb.WriteString("## TLS decryption\n\n")
		sb.WriteString(cov.Verdict + "\n\n")
		rows := make([][]string, 0, len(cov.Sessions))
		for _, r := range cov.Sessions {
			secIn := strings.Join(r.SecretIn, ", ")
			if secIn == "" {
				secIn = "none"
			}
			rows = append(rows, []string{r.Flow, r.Service, DerefStr(r.Version, ""), strconv.FormatBool(r.Decrypted), secIn, DerefStr(r.Reason, "")})
		}
		sb.WriteString(MarkdownTable([]string{"flow", "service", "version", "decrypted", "secret in", "why not"}, rows))
		sb.WriteByte('\n')
	}

	sb.WriteString("## Connections\n\n")
	connRows := make([][]string, 0, len(rep.Connections))
	for _, c := range rep.Connections {
		stB, _ := json.Marshal(c.RPCStatus)
		connRows = append(connRows, []string{c.Flow, DerefStr(c.Service, ""), c.Transport, c.Protocol, strings.Join(c.Services, ", "), strconv.Itoa(c.RPCs), string(stB)})
	}
	sb.WriteString(MarkdownTable([]string{"flow", "service", "transport", "protocol", "services", "rpcs", "status"}, connRows))

	for _, c := range rep.Connections {
		if c.TLS == nil {
			continue
		}
		t := c.TLS
		fmt.Fprintf(&sb, "### TLS %s\n\n", c.Flow)
		fmt.Fprintf(&sb, "- Version %s, suite %s, SNI %s, ALPN offered %v, decrypted: %v\n",
			DerefStr(t.Version, "none"), DerefStr(t.CipherSuite, "none"), DerefStr(t.SNI, "none"), t.ALPNOffered, t.Decrypted)
		if cert := t.Certificate; cert != nil && cert.Parsed != nil && *cert.Parsed {
			fmt.Fprintf(&sb, "- Certificate: subject %s, issuer %s, valid %s to %s\n",
				DerefStr(cert.Subject, ""), DerefStr(cert.Issuer, ""), DerefStr(cert.NotBefore, ""), DerefStr(cert.NotAfter, ""))
		} else if cert != nil {
			fmt.Fprintf(&sb, "- Certificate: %s\n", defaultWhenEmpty(cert.Reason, "not visible"))
		}
		for _, al := range t.Alerts {
			fmt.Fprintf(&sb, "- Alert %s %s from %s: %s\n", al.Level, al.Description, al.From, DerefStr(al.Hint, ""))
		}
		for _, h := range t.Hints {
			fmt.Fprintf(&sb, "- %s\n", h.Text)
		}
		sb.WriteByte('\n')
	}

	sb.WriteString("## RPCs\n\n")
	rpcRows := make([][]string, 0, len(rep.RPCs))
	for _, r := range rep.RPCs {
		rpcRows = append(rpcRows, []string{
			strconv.Itoa(r.StreamID), DerefStr(r.Method, ""), DerefStr(r.GrpcStatusName, r.Outcome),
			DerefStr(r.GrpcMessage, ""), strconv.Itoa(r.Request.Messages), strconv.Itoa(r.Response.Messages),
			DerefFloat(r.Timing.ToFirstResponseMS, ""), DerefFloat(r.Timing.ToEndMS, ""), r.Diagnosis,
		})
	}
	sb.WriteString(MarkdownTable([]string{"stream", "method", "status", "message", "req msgs", "resp msgs", "first response ms", "end ms", "diagnosis"}, rpcRows))

	sb.WriteString("## Credentials in metadata\n\nReported by key only; no value is read into this report.\n\n")
	credRows := make([][]string, 0, len(rep.Credentials))
	for _, c := range rep.Credentials {
		credRows = append(credRows, []string{c.Key, c.Flow, strconv.FormatBool(c.Cleartext), strconv.Itoa(c.Requests), FormatInts(c.Frames)})
	}
	sb.WriteString(MarkdownTable([]string{"key", "flow", "cleartext", "requests", "frames"}, credRows))

	sb.WriteString("## Issues\n\n")
	issRows := make([][]string, 0, len(rep.Issues))
	for _, iss := range rep.Issues {
		issRows = append(issRows, []string{iss.Severity.String(), iss.Code, iss.Message, FormatInts(iss.Frames)})
	}
	sb.WriteString(MarkdownTable([]string{"severity", "code", "message", "frames"}, issRows))

	AppendMarkdownLimits(&sb, rep.Limits)
	sb.WriteString("_Generated by S.O.N.I.C. gRPC troubleshooting. Frame numbers match Wireshark's._\n")
	return sb.String()
}

// SaveGRPCReport writes a redacted JSON or Markdown report for grpc.Report.
func SaveGRPCReport(rep grpc.Report, path string) error {
	raw, err := json.Marshal(rep)
	return SaveRawReport(raw, err, BuildGRPCMarkdown(rep), path)
}

func defaultWhenEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
