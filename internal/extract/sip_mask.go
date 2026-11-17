// Package extract masks SIP Authorization/Proxy-Authorization credentials and SDP media
// keys at extraction time before summaries reach analyzers, reports, or LLMs.
package extract

import (
	"regexp"
	"strings"

	"github.com/zombat/sonic/internal/redact"
)

// SIPCredentialMask replaces sensitive SIP authentication and SDP media key values.
const SIPCredentialMask = "[MASKED]"

var (
	sipSchemeRe      = regexp.MustCompile(`(?s)^(\s*)([A-Za-z][A-Za-z0-9._\-]*)(\s+|$)(.*)$`)
	sipAuthLineRe    = regexp.MustCompile(`(?im)^((?:proxy-)?authorization[ \t]*:)([^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)`)
	sipDigestParamRe = regexp.MustCompile(`(?i)\b(?:response|auts)\s*=\s*`)
)

// MaskSIPCredentials masks secret credentials in a single Authorization or Proxy-Authorization value.
func MaskSIPCredentials(value string) string {
	if value == "" {
		return value
	}
	m := sipSchemeRe.FindStringSubmatch(value)
	if m == nil {
		return SIPCredentialMask
	}
	lead, scheme, space, rest := m[1], m[2], m[3], m[4]
	if strings.EqualFold(scheme, "digest") {
		return lead + scheme + space + replaceDigestSecrets(rest, true)
	}
	if rest == "" {
		return value
	}
	if space == "" {
		space = " "
	}
	return lead + scheme + space + SIPCredentialMask
}

// MaskSIPText masks Authorization headers, SDP media keys, and Digest response/auts parameters in text.
func MaskSIPText(text string) string {
	if text == "" {
		return text
	}
	text = sipAuthLineRe.ReplaceAllStringFunc(text, func(line string) string {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			return line
		}
		return line[:idx+1] + MaskSIPCredentials(line[idx+1:])
	})
	text = redact.MaskSDPKeys(text, SIPCredentialMask)
	return replaceDigestSecrets(text, false)
}

// replaceDigestSecrets rewrites response= and auts= parameter values without using regex lookahead.
func replaceDigestSecrets(text string, preserveQuotes bool) string {
	var b strings.Builder
	pos := 0
	for pos < len(text) {
		loc := sipDigestParamRe.FindStringIndex(text[pos:])
		if loc == nil {
			b.WriteString(text[pos:])
			break
		}
		matchStart := pos + loc[0]
		valStart := pos + loc[1]
		b.WriteString(text[pos:valStart])

		valEnd := scanDigestValueEnd(text, valStart)
		rawVal := text[valStart:valEnd]
		if !preserveQuotes && strings.Contains(rawVal, SIPCredentialMask) {
			b.WriteString(rawVal)
		} else if preserveQuotes && strings.ContainsRune(rawVal, '"') {
			b.WriteByte('"')
			b.WriteString(SIPCredentialMask)
			b.WriteByte('"')
		} else {
			b.WriteString(SIPCredentialMask)
		}
		pos = valEnd
		if pos <= matchStart {
			pos = matchStart + 1
		}
	}
	return b.String()
}

// scanDigestValueEnd returns the byte offset just past one quoted or token Digest parameter value.
func scanDigestValueEnd(text string, start int) int {
	if start >= len(text) {
		return start
	}
	if strings.HasPrefix(text[start:], `\"`) || text[start] == '"' {
		i := start
		if strings.HasPrefix(text[i:], `\"`) {
			i += 2
		} else {
			i++
		}
		for i < len(text) {
			if strings.HasPrefix(text[i:], `\"`) {
				return i + 2
			}
			if text[i] == '"' {
				return i + 1
			}
			if text[i] == '\\' && i+1 < len(text) {
				i += 2
				continue
			}
			i++
		}
		return len(text)
	}
	i := start
	for i < len(text) && text[i] != ',' && text[i] != ' ' && text[i] != '\t' && text[i] != '\r' && text[i] != '\n' {
		i++
	}
	return i
}
