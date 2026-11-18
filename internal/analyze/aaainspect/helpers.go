// Package aaainspect scalar parsing, endpoint formatting, and secret redaction helpers.
package aaainspect

import (
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

// firstVal returns the first occurrence of tshark field name in row, or "".
func firstVal(row map[string]string, name string) string {
	raw := row[name]
	if raw == "" {
		return ""
	}
	if idx := strings.Index(raw, extract.AAAFieldSep); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

// parseInt parses decimal or 0x-prefixed hex values into int.
func parseInt(val string) (int, bool) {
	if val == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(val, 0, 64)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// parseInt64 parses decimal or 0x-prefixed hex values into int64 (used for TACACS+ session IDs).
func parseInt64(val string) (int64, bool) {
	if val == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(val, 0, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// endpoint formats ip[:port] from row.
func endpoint(row map[string]string, which, portField string) string {
	ip := firstVal(row, "ip."+which)
	if ip == "" {
		ip = firstVal(row, "ipv6."+which)
	}
	if port := firstVal(row, portField); port != "" {
		return ip + ":" + port
	}
	return ip
}

// scrubStr replaces all secrets in s with "[REDACTED]".
func scrubStr(s string, secrets []string) string {
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "[REDACTED]")
		}
	}
	return s
}

// scrubPtr replaces secrets inside an optional string pointer without modifying nil pointers.
func scrubPtr(p **string, secrets []string) {
	if *p == nil {
		return
	}
	v := scrubStr(**p, secrets)
	*p = &v
}

// scrubReport redacts every known key, secret, or recovered credential across report fields.
func scrubReport(r *Report, secrets []string) {
	r.Verdict = scrubStr(r.Verdict, secrets)
	r.File = scrubStr(r.File, secrets)
	for i := range r.Radius {
		rv := &r.Radius[i]
		scrubPtr(&rv.Username, secrets)
		scrubPtr(&rv.NAS, secrets)
		scrubPtr(&rv.CallingStation, secrets)
	}
	for i := range r.Tacacs {
		tv := &r.Tacacs[i]
		scrubPtr(&tv.User, secrets)
	}
	for i := range r.Credentials {
		c := &r.Credentials[i]
		scrubPtr(&c.Username, secrets)
	}
	for i := range r.Issues {
		iss := &r.Issues[i]
		iss.Message = scrubStr(iss.Message, secrets)
		scrubPtr(&iss.User, secrets)
		scrubPtr(&iss.Username, secrets)
	}
}
