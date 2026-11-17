// Package httpinspect emits HTTP, RESTCONF, and credential issues and summarizes status counts.
package httpinspect

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

// carriesHTTP reports whether TCP connection c carries HTTP/1.1, HTTP/2, RESTCONF, or gRPC traffic.
func carriesHTTP(conn *extract.TCPConnection, extraPorts map[int]bool) bool {
	port := conn.ServicePort()
	if extract.HTTPPorts[port] != "" || extraPorts[port] {
		return true
	}
	_, isGrpc := extract.GrpcPorts[port]
	if conn.IsTLS() && (isGrpc || slices.Contains(conn.ALPN, "h2") || slices.Contains(conn.ALPN, "http/1.1")) {
		return true
	}
	return conn.PrefaceFrame != nil || isGrpc
}

// transportLabel returns the human-readable wire transport state for conn.
func transportLabel(conn *extract.TCPConnection, decrypted, secretsGiven bool) string {
	if !conn.IsTLS() {
		return "cleartext"
	}
	if decrypted {
		return "tls (decrypted)"
	}
	if secretsGiven {
		return "tls (not decrypted)"
	}
	return "tls (no key log)"
}

func httpOutcome(resp *extract.HTTPMessage) string {
	if resp == nil {
		return "no_response"
	}
	code := 0
	if resp.Status != nil {
		code = *resp.Status
	}
	switch {
	case code >= 500:
		return "server_error"
	case code >= 400:
		return "client_error"
	case code >= 200:
		return "ok"
	default:
		return "other"
	}
}

func appendRequestIssues(rec RequestRow, label string, issues *[]model.Issue) {
	var frames []int
	if rec.Frames.Response != nil && *rec.Frames.Response != 0 {
		frames = append(frames, *rec.Frames.Response)
	}
	if rec.Frames.Request != nil && *rec.Frames.Request != 0 {
		frames = append(frames, *rec.Frames.Request)
	}
	if frames == nil {
		frames = []int{}
	}

	code := 0
	if rec.Status != nil {
		code = *rec.Status
	}
	method := "?"
	if rec.Method != nil && *rec.Method != "" {
		method = *rec.Method
	}
	path := "?"
	if rec.Path != nil && *rec.Path != "" {
		path = *rec.Path
	}
	desc := method + " " + path
	phrase := ""
	if rec.Phrase != nil {
		phrase = *rec.Phrase
	}

	switch {
	case len(rec.RestconfErrors) > 0:
		for _, rcErr := range rec.RestconfErrors {
			tag := rcErr["error-tag"]
			if tag == "" {
				tag = "error"
			}
			var parts []string
			for _, k := range errorFields {
				if k != "error-tag" {
					if v, ok := rcErr[k]; ok {
						parts = append(parts, k+"="+v)
					}
				}
			}
			msg := fmt.Sprintf("%s: %s -> %d %s", label, desc, code, tag)
			if len(parts) > 0 {
				msg += " (" + strings.Join(parts, ", ") + ")"
			}
			sev := model.SeverityWarning
			if code >= 500 || code == 0 {
				sev = model.SeverityError
			}
			iss := model.MakeIssue(sev, "RESTCONF_ERROR", msg, frames)
			c := code
			iss.Status = &c
			iss.ErrorTag = tag
			*issues = append(*issues, iss)
		}
	case code >= 500:
		hint := HTTPStatusHints[code]
		if hint == "" {
			hint = "a server error"
		}
		iss := model.MakeIssue(model.SeverityError, "HTTP_SERVER_ERROR",
			fmt.Sprintf("%s: %s -> %d %s: %s", label, desc, code, phrase, hint), frames)
		c := code
		iss.Status = &c
		*issues = append(*issues, iss)
	case code >= 400:
		hint := HTTPStatusHints[code]
		if hint == "" {
			hint = "a client error"
		}
		iss := model.MakeIssue(model.SeverityWarning, "HTTP_CLIENT_ERROR",
			fmt.Sprintf("%s: %s -> %d %s: %s", label, desc, code, phrase, hint), frames)
		c := code
		iss.Status = &c
		*issues = append(*issues, iss)
	case rec.Outcome == "no_response" && rec.Method != nil && *rec.Method != "":
		*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "HTTP_NO_RESPONSE",
			fmt.Sprintf("%s: %s got no response before the capture ended", label, desc), frames))
	}

	cleartext := rec.Transport == "cleartext"
	for _, cred := range rec.Credentials {
		name := cred.Header
		if cred.Scheme != nil && *cred.Scheme != "" {
			name += " (" + *cred.Scheme + ")"
		}
		if cleartext {
			iss := model.MakeIssue(model.SeverityError, "CLEARTEXT_CREDENTIAL",
				fmt.Sprintf("%s: %s sent in cleartext on %s (value masked): anyone on the path can read it; use TLS", label, name, desc),
				frames)
			iss.Header = cred.Header
			*issues = append(*issues, iss)
		} else {
			iss := model.MakeIssue(model.SeverityInfo, "CREDENTIAL_IN_REQUEST",
				fmt.Sprintf("%s: %s on %s, protected by TLS on the wire (seen because the secrets decrypted it; value masked)", label, name, desc),
				frames)
			iss.Header = cred.Header
			*issues = append(*issues, iss)
		}
	}
}

func credentialsSummary(requests []RequestRow) []CredentialRow {
	type key struct {
		flow   string
		header string
	}
	summary := make(map[key]*CredentialRow)
	for _, rec := range requests {
		for _, cred := range rec.Credentials {
			k := key{flow: rec.Flow, header: cred.Header}
			entry, ok := summary[k]
			if !ok {
				entry = &CredentialRow{
					Flow:      rec.Flow,
					Service:   rec.Service,
					Header:    cred.Header,
					Kind:      cred.Kind,
					Scheme:    cred.Scheme,
					Cleartext: rec.Transport == "cleartext",
					Frames:    []int{},
					Value:     "masked",
				}
				summary[k] = entry
			}
			entry.Requests++
			if rec.Frames.Request != nil && *rec.Frames.Request != 0 {
				entry.Frames = append(entry.Frames, *rec.Frames.Request)
			}
		}
	}
	rows := make([]CredentialRow, 0, len(summary))
	for _, row := range summary {
		rows = append(rows, *row)
	}
	slices.SortStableFunc(rows, func(a, b CredentialRow) int {
		if c := cmp.Compare(a.Flow, b.Flow); c != 0 {
			return c
		}
		return cmp.Compare(a.Header, b.Header)
	})
	return rows
}

func statusCounts(requests []RequestRow) map[string]int {
	counts := make(map[string]int)
	for _, rec := range requests {
		k := rec.Outcome
		if rec.Status != nil && *rec.Status != 0 {
			k = strconv.Itoa(*rec.Status)
		}
		counts[k]++
	}
	return counts
}
