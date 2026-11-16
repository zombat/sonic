// Package redact masks known secret values and common credential shapes
// (API keys, JWTs, PEM blocks, Authorization headers, assignments, SDP keys).
package redact

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"sort"
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
	if text == "" {
		return text
	}
	if mask == "" {
		mask = Redacted
	}
	text = sdpInlineRe.ReplaceAllString(text, "${1}"+mask)
	text = sdpKeyMgmtRe.ReplaceAllString(text, "${1}"+mask)
	return sdpKLineRe.ReplaceAllString(text, "${1}"+mask)
}

// MaskSecretShapes masks all recognized credential patterns in text.
func MaskSecretShapes(text string) string {
	if text == "" {
		return text
	}
	text = maskPEMBlocks(text)
	text = jwtRe.ReplaceAllString(text, Redacted)
	text = authHeaderRe.ReplaceAllString(text, "${1}${2}${3}"+Redacted)
	text = tokenShapesRe.ReplaceAllString(text, Redacted)
	text = replaceBearer(text)
	text = replaceBasic(text)
	text = replaceAssignments(text, assignmentRe)
	text = replaceAssignments(text, colonAssignmentRe)
	return MaskSDPKeys(text, Redacted)
}

// RedactText masks every known secret (length >= MinSecretLength, longest
// first) and every SECRET_SHAPES match in text with Redacted.
func RedactText(text string, knownSecrets ...string) string {
	if text == "" {
		return text
	}
	if len(knownSecrets) > 0 {
		filtered := make([]string, 0, len(knownSecrets))
		seen := make(map[string]struct{}, len(knownSecrets))
		for _, s := range knownSecrets {
			if len(s) < MinSecretLength {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			filtered = append(filtered, s)
		}
		sort.Slice(filtered, func(i, j int) bool {
			if len(filtered[i]) != len(filtered[j]) {
				return len(filtered[i]) > len(filtered[j])
			}
			return filtered[i] < filtered[j]
		})
		for _, secret := range filtered {
			if strings.Contains(text, secret) {
				text = strings.ReplaceAll(text, secret, Redacted)
			}
		}
	}
	return MaskSecretShapes(text)
}

// maskPEMBlocks masks private key PEM bodies while preserving the BEGIN/END header label.
func maskPEMBlocks(text string) string {
	var out strings.Builder
	pos := 0
	for pos < len(text) {
		loc := pemBeginRe.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			out.WriteString(text[pos:])
			break
		}
		beginStart := pos + loc[0]
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
		_ = beginStart
	}
	return out.String()
}

// replaceBearer masks standalone "Bearer <token>" values when <token> contains a digit.
func replaceBearer(text string) string {
	return bearerRe.ReplaceAllStringFunc(text, func(full string) string {
		m := bearerRe.FindStringSubmatch(full)
		if len(m) != 3 {
			return full
		}
		if strings.IndexFunc(m[2], func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
			return m[1] + Redacted
		}
		return full
	})
}

// replaceBasic masks standalone "Basic <b64>" when <b64> strictly decodes to user:password.
func replaceBasic(text string) string {
	return basicCandidateR.ReplaceAllStringFunc(text, func(full string) string {
		m := basicCandidateR.FindStringSubmatch(full)
		if len(m) != 3 || !basicStrictR.MatchString(m[2]) {
			return full
		}
		padded := m[2]
		if rem := len(padded) % 4; rem != 0 {
			padded += strings.Repeat("=", 4-rem)
		}
		decoded, err := base64.StdEncoding.DecodeString(padded)
		if err != nil || !bytes.Contains(decoded, []byte(":")) {
			return full
		}
		return m[1] + Redacted
	})
}

// replaceAssignments masks key=value and key:value secret assignments while honoring
// a negative lookbehind against [A-Za-z0-9_.\-] before the key name.
func replaceAssignments(text string, re *regexp.Regexp) string {
	var out strings.Builder
	pos := 0
	for pos < len(text) {
		loc := re.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			out.WriteString(text[pos:])
			break
		}
		matchStart := pos + loc[0]
		matchEnd := pos + loc[1]
		if matchStart > 0 && isIdentByte(text[matchStart-1]) {
			// Advance past one byte so quoted keys after an identifier char can still match.
			out.WriteString(text[pos : matchStart+1])
			pos = matchStart + 1
			continue
		}
		prefix := text[pos+loc[2] : pos+loc[3]]
		value := text[pos+loc[4] : pos+loc[5]]
		out.WriteString(text[pos:matchStart])
		out.WriteString(maskAssignedValue(prefix, value))
		pos = matchEnd
	}
	return out.String()
}

// maskAssignedValue preserves quotes and skips placeholder values such as None or [REDACTED].
func maskAssignedValue(prefix, value string) string {
	bare := strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	if _, skip := notAValue[bare]; skip {
		return prefix + value
	}
	quote := ""
	if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
		quote = value[:1]
	}
	return prefix + quote + Redacted + quote
}

// isIdentByte reports whether b belongs to [A-Za-z0-9_.\-].
func isIdentByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '_' || b == '.' || b == '-'
}
