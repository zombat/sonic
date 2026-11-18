// Package httpinspect computes capture bounds, verdicts, TLS alerts, and secret scrubbing.
package httpinspect

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func captureTimeBounds(messages []extract.HTTPMessage, disc map[int]*extract.TCPConnection) (*float64, *float64) {
	var startPtr, endPtr *float64
	for _, m := range messages {
		if m.T == 0 {
			continue
		}
		if startPtr == nil || m.T < *startPtr {
			v := m.T
			startPtr = &v
		}
		if endPtr == nil || m.T > *endPtr {
			v := m.T
			endPtr = &v
		}
	}
	for _, conn := range disc {
		if startPtr == nil || conn.FirstT < *startPtr {
			v := conn.FirstT
			startPtr = &v
		}
		if endPtr == nil || conn.LastT > *endPtr {
			v := conn.LastT
			endPtr = &v
		}
	}
	return startPtr, endPtr
}

func appendFallbackTLSConns(
	wanted map[int]bool,
	disc map[int]*extract.TCPConnection,
	secretsGiven bool,
	connRows *[]ConnectionRow,
	issues *[]model.Issue,
) {
	seenFlows := make(map[string]bool, len(*connRows))
	for _, row := range *connRows {
		seenFlows[row.Flow] = true
	}
	for _, idx := range slices.Sorted(maps.Keys(wanted)) {
		conn := disc[idx]
		if conn == nil || !conn.IsTLS() {
			continue
		}
		flow := connectionFlow(conn)
		if seenFlows[flow] {
			continue
		}
		var svcName *string
		if name := extract.HTTPPorts[conn.ServicePort()]; name != "" {
			svcName = &name
		}
		alpn := []string{}
		if len(conn.ALPN) > 0 {
			alpn = slices.Clone(conn.ALPN)
		}
		decFalse := false
		*connRows = append(*connRows, ConnectionRow{
			Flow:         flow,
			Service:      fmt.Sprintf("tcp/%d", conn.ServicePort()),
			ServiceName:  svcName,
			Transport:    transportLabel(conn, false, secretsGiven),
			HTTPVersions: []string{},
			Requests:     0,
			Restconf:     nil,
			SNI:          conn.SNI,
			ALPNOffered:  alpn,
			Decrypted:    &decFalse,
		})
		if !secretsGiven {
			frames := []int{}
			if conn.TLSClientHello != nil {
				frames = []int{*conn.TLSClientHello}
			}
			*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "HTTP_TLS_NOT_DECRYPTED",
				fmt.Sprintf("%s (tcp/%d): TLS with no key log, so the requests are encrypted; have the client write a key log (SSLKEYLOGFILE) and pass it to read them", flow, conn.ServicePort()),
				frames))
		}
	}
	slices.SortStableFunc(*connRows, func(a, b ConnectionRow) int {
		return cmp.Compare(a.Flow, b.Flow)
	})
}

func appendTLSDecryptIssues(
	coverage *TLSDecryptionSummary,
	secrets secretsInfo,
	secretsGiven bool,
	issues *[]model.Issue,
) {
	if coverage != nil && secretsGiven {
		for _, row := range coverage.Sessions {
			if row.Decrypted {
				continue
			}
			frames := []int{}
			if row.ClientHelloFrame != nil {
				frames = []int{*row.ClientHelloFrame}
			}
			reason := ""
			if row.Reason != nil {
				reason = *row.Reason
			}
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "TLS_SESSION_NOT_DECRYPTED",
				fmt.Sprintf("%s (%s): not decrypted: %s", row.Flow, row.Service, reason), frames))
		}
	}
	if secrets.PCAPNGBlocks > 0 {
		*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "TLS_SECRETS_IN_CAPTURE",
			fmt.Sprintf("the capture carries TLS secrets in %d Decryption Secrets Block(s) (%d session(s)): anyone with this file can read the sessions they cover", secrets.PCAPNGBlocks, secrets.SessionsInPCAPNG),
			[]int{}))
	}
}

func httpVerdict(connRows []ConnectionRow, requests []RequestRow, credentials []CredentialRow, secretsGiven bool) string {
	if len(connRows) == 0 {
		return "No HTTP, RESTCONF or REST found: nothing on an HTTP(S) port, no HTTP/2 and no HTTP/1 request."
	}
	restconf := 0
	for _, r := range requests {
		if r.Restconf {
			restconf++
		}
	}
	var tlsRows []ConnectionRow
	for _, c := range connRows {
		if strings.HasPrefix(c.Transport, "tls") {
			tlsRows = append(tlsRows, c)
		}
	}
	parts := []string{fmt.Sprintf("%d HTTP connection(s)", len(connRows))}
	if len(tlsRows) > 0 {
		decrypted := 0
		for _, c := range tlsRows {
			if c.Decrypted != nil && *c.Decrypted {
				decrypted++
			}
		}
		tail := ""
		if !secretsGiven {
			tail = " (no key log: give one to read the requests)"
		}
		parts = append(parts, fmt.Sprintf("%d over TLS, %d decrypted%s", len(tlsRows), decrypted, tail))
	}
	if len(requests) > 0 {
		errs := 0
		for _, r := range requests {
			if r.Status != nil && *r.Status >= 400 {
				errs++
			}
		}
		s := fmt.Sprintf("%d request(s)", len(requests))
		if restconf > 0 {
			s += fmt.Sprintf(", %d RESTCONF", restconf)
		}
		if errs > 0 {
			s += fmt.Sprintf(", %d with a 4xx/5xx status", errs)
		}
		parts = append(parts, s)
	} else {
		tail := ""
		if !secretsGiven {
			tail = " (TLS without a key log shows only the handshake)"
		}
		parts = append(parts, "no request decoded"+tail)
	}
	clearHeaders := make(map[string]bool)
	for _, c := range credentials {
		if c.Cleartext {
			clearHeaders[c.Header] = true
		}
	}
	if len(clearHeaders) > 0 {
		hdrs := slices.Sorted(maps.Keys(clearHeaders))
		parts = append(parts, "credentials in cleartext: "+strings.Join(hdrs, ", ")+" (values masked)")
	}
	return strings.Join(parts, ". ") + "."
}

func scrubText(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "[REDACTED]")
		}
	}
	return s
}

func scrubPtr(p *string, secrets []string) {
	if p != nil {
		*p = scrubText(*p, secrets)
	}
}

func scrubReport(rep *Report, secrets []string) {
	rep.Verdict = scrubText(rep.Verdict, secrets)
	for i := range rep.Capture.Warnings {
		rep.Capture.Warnings[i] = scrubText(rep.Capture.Warnings[i], secrets)
	}
	for i := range rep.Connections {
		scrubPtr(rep.Connections[i].SNI, secrets)
	}
	for i := range rep.Requests {
		scrubPtr(rep.Requests[i].Path, secrets)
		scrubPtr(rep.Requests[i].Host, secrets)
		scrubPtr(rep.Requests[i].Phrase, secrets)
		scrubPtr(rep.Requests[i].Location, secrets)
		for j := range rep.Requests[i].RestconfErrors {
			for k, v := range rep.Requests[i].RestconfErrors[j] {
				rep.Requests[i].RestconfErrors[j][k] = scrubText(v, secrets)
			}
		}
	}
	for i := range rep.Issues {
		rep.Issues[i].Message = scrubText(rep.Issues[i].Message, secrets)
	}
}
