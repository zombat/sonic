// Package snmpinspect field parsing, IP endpoint formatting, and secret scrubbing helpers.
package snmpinspect

import (
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

// splitField splits a multi-valued tshark SNMP field on SnmpFieldSep, omitting empties.
func splitField(row map[string]string, name string) []string {
	raw := row[name]
	if raw == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(raw, extract.SnmpFieldSep) {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// firstVal returns the first occurrence of field name in row, or "".
func firstVal(row map[string]string, name string) string {
	vals := splitField(row, name)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// parseInt parses decimal or 0x-prefixed hex tshark field values.
func parseInt(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 0, 64)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// flagSet interprets a boolean tshark field value ("1", "True", "true").
func flagSet(row map[string]string, name string) bool {
	v := firstVal(row, name)
	return v == "1" || v == "True" || v == "true"
}

// endpoint formats ip[:udp_port] for source or destination columns of row.
func endpoint(row map[string]string, which string) string {
	ip := firstVal(row, "ip."+which)
	if ip == "" {
		ip = firstVal(row, "ipv6."+which)
	}
	portField := "udp.dstport"
	if which == "src" {
		portField = "udp.srcport"
	}
	if port := firstVal(row, portField); port != "" {
		return ip + ":" + port
	}
	return ip
}

// hostOnly strips the trailing :port suffix from an endpoint string.
func hostOnly(ep string) string {
	if idx := strings.LastIndexByte(ep, ':'); idx >= 0 {
		return ep[:idx]
	}
	return ep
}

// pyRepr quotes s with single quotes when possible to match Python repr().
func pyRepr(s string) string {
	if !strings.ContainsRune(s, '\'') {
		return "'" + s + "'"
	}
	return strconv.Quote(s)
}

// scrubStr replaces every known secret value in s with "[REDACTED]".
func scrubStr(s string, secrets []string) string {
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "[REDACTED]")
		}
	}
	return s
}

// scrubReport scrubs communities and passphrases from every textual field of r.
func scrubReport(r *Report, secrets []string) {
	r.Verdict = scrubStr(r.Verdict, secrets)
	r.File = scrubStr(r.File, secrets)
	for i := range r.Capture.Warnings {
		r.Capture.Warnings[i] = scrubStr(r.Capture.Warnings[i], secrets)
	}
	for i := range r.Messages {
		m := &r.Messages[i]
		m.Src = scrubStr(m.Src, secrets)
		m.Dst = scrubStr(m.Dst, secrets)
		if m.User != nil {
			u := scrubStr(*m.User, secrets)
			m.User = &u
		}
		if m.Reason != nil {
			rs := scrubStr(*m.Reason, secrets)
			m.Reason = &rs
		}
	}
	for i := range r.Issues {
		r.Issues[i].Message = scrubStr(r.Issues[i].Message, secrets)
		if r.Issues[i].User != nil {
			u := scrubStr(*r.Issues[i].User, secrets)
			r.Issues[i].User = &u
		}
	}
}
