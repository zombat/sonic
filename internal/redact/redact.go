// Package redact masks known secret values and common credential shapes
// (API keys, JWTs, PEM blocks, Authorization headers, assignments, SDP keys).
package redact

import (
	"regexp"
	"strings"
)

const (
	// Redacted is the replacement marker for masked secrets.
	Redacted = "[REDACTED]"
	// MinSecretLength prevents short values from mangling ordinary text.
	MinSecretLength = 8
)

var (
	pemBeginRe    = regexp.MustCompile(`-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----`)
	jwtRe         = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	authHeaderRe  = regexp.MustCompile(`(?i)(\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?\s*)(basic|bearer)(\s+)([A-Za-z0-9+/._~\-]+=*)`)
	tokenShapesRe = regexp.MustCompile(
		`\bsk-ant-[A-Za-z0-9_\-]+` +
			`|\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}` +
			`|\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}` +
			`|\bAIza[0-9A-Za-z_\-]{35}` +
			`|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b` +
			`|\bgh[pousr]_[A-Za-z0-9]{36,255}\b` +
			`|\bgithub_pat_[A-Za-z0-9_]{22,255}\b` +
			`|\bxox[bpas]-[A-Za-z0-9-]{10,}`,
	)
	bearerRe        = regexp.MustCompile(`\b(Bearer\s+)([A-Za-z0-9._~+/\-]{16,}=*)`)
	basicCandidateR = regexp.MustCompile(`\b(Basic\s+)([A-Za-z0-9+/=]+)`)
	basicStrictR    = regexp.MustCompile(`^[A-Za-z0-9+/]{8,}={0,2}$`)
	assignmentRe    = regexp.MustCompile(
		`(?i)([A-Za-z0-9_.\-]*(?:password|passwd|passphrase|pwd|secret|token|api[_\-]?key|apikey|key|psk)\s*=\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;&"'<>()\[\]{}]+)`,
	)
	colonAssignmentRe = regexp.MustCompile(
		`(?i)(["']?[A-Za-z0-9_.\-]*(?:password|passwd|passphrase|secret)["']?\s*:[ \t]*)("[^"\n]*"|'[^'\n]*'|[^\s,;&"'<>()\[\]{}]+)`,
	)
	sdpInlineRe  = regexp.MustCompile(`(\binline:)([A-Za-z0-9+/]{16,}={0,2})`)
	sdpKeyMgmtRe = regexp.MustCompile(`(?im)(\ba=key-mgmt:[ \t]*[A-Za-z0-9._\-]+[ \t]+)([^\r\n"]+)`)
	sdpKLineRe   = regexp.MustCompile(`(?im)(^k=(?:clear|base64):)([^\r\n"]+)`)
)

var notAValue = map[string]struct{}{
	"": {}, "none": {}, "null": {}, "true": {}, "false": {},
	"redacted": {}, "[redacted]": {}, "masked": {}, "[masked]": {},
}

// MaskSDPKeys replaces SRTP inline keys, key-mgmt payloads, and k= media keys
// in SDP text with mask (default Redacted when mask is empty).
func MaskSDPKeys(text, mask string) string {
	masked, _ := maskSDPKeysCount(text, mask)
	return masked
}

// MaskSecretShapes masks all recognized credential patterns in text.
func MaskSecretShapes(text string) string {
	out, _ := RedactTextWithAudit(text)
	return out
}

// RedactText masks every known secret (length >= MinSecretLength, longest
// first) and every SECRET_SHAPES match in text with Redacted.
func RedactText(text string, knownSecrets ...string) string {
	out, _ := RedactTextWithAudit(text, knownSecrets...)
	return out
}

// maskPEMBlocks masks private key PEM bodies while preserving the BEGIN/END header label.
func maskPEMBlocks(text string) (string, int) {
	var out strings.Builder
	pos, count := 0, 0
	for pos < len(text) {
		loc := pemBeginRe.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			out.WriteString(text[pos:])
			break
		}
		count++
		beginEnd := pos + loc[1]
		label := text[pos+loc[2] : pos+loc[3]]
		out.WriteString(text[pos:beginEnd])
		out.WriteString(Redacted)
		endMarker := "-----END " + label + "-----"
		out.WriteString(endMarker)
		if endIdx := strings.Index(text[beginEnd:], endMarker); endIdx >= 0 {
			pos = beginEnd + endIdx + len(endMarker)
		} else {
			pos = len(text)
		}
	}
	return out.String(), count
}

// replaceAssignments masks key=value and key:value secret assignments while honoring
// a negative lookbehind against [A-Za-z0-9_.\-] before the key name.
func replaceAssignments(text string, re *regexp.Regexp) (string, int) {
	var out strings.Builder
	pos, count := 0, 0
	for pos < len(text) {
		loc := re.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			out.WriteString(text[pos:])
			break
		}
		matchStart := pos + loc[0]
		matchEnd := pos + loc[1]
		if matchStart > 0 && isIdentByte(text[matchStart-1]) {
			out.WriteString(text[pos : matchStart+1])
			pos = matchStart + 1
			continue
		}
		prefix := text[pos+loc[2] : pos+loc[3]]
		value := text[pos+loc[4] : pos+loc[5]]
		out.WriteString(text[pos:matchStart])
		masked, changed := maskAssignedValue(prefix, value)
		if changed {
			count++
		}
		out.WriteString(masked)
		pos = matchEnd
	}
	return out.String(), count
}

// maskAssignedValue preserves quotes and skips placeholder values such as None or [REDACTED].
func maskAssignedValue(prefix, value string) (string, bool) {
	bare := strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	if _, skip := notAValue[bare]; skip {
		return prefix + value, false
	}
	quote := ""
	if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
		quote = value[:1]
	}
	return prefix + quote + Redacted + quote, true
}

// isIdentByte reports whether b belongs to [A-Za-z0-9_.\-].
func isIdentByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '_' || b == '.' || b == '-'
}
