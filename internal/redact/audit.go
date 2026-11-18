// Package redact tracks deterministic redaction counts across secret categories
// without retaining or exposing any matched credential substrings.
package redact

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// AuditCounts summarizes how many secrets of each category were redacted.
type AuditCounts struct {
	KnownSecrets   int `json:"known_secrets"`
	PEMBlocks      int `json:"pem_blocks"`
	JWTs           int `json:"jwts"`
	AuthHeaders    int `json:"auth_headers"`
	ProviderTokens int `json:"provider_tokens"`
	BearerTokens   int `json:"bearer_tokens"`
	BasicAuth      int `json:"basic_auth"`
	Assignments    int `json:"assignments"`
	SDPKeys        int `json:"sdp_keys"`
	Total          int `json:"total"`
}

// Add merges other counts into c.
func (c *AuditCounts) Add(other AuditCounts) {
	c.KnownSecrets += other.KnownSecrets
	c.PEMBlocks += other.PEMBlocks
	c.JWTs += other.JWTs
	c.AuthHeaders += other.AuthHeaders
	c.ProviderTokens += other.ProviderTokens
	c.BearerTokens += other.BearerTokens
	c.BasicAuth += other.BasicAuth
	c.Assignments += other.Assignments
	c.SDPKeys += other.SDPKeys
	c.Total += other.Total
}

// AuditTracker safely accumulates AuditCounts across concurrent workers or responses.
type AuditTracker struct {
	mu     sync.Mutex
	counts AuditCounts
}

// Redact applies RedactTextWithAudit to text and records the redaction counts.
func (t *AuditTracker) Redact(text string, knownSecrets ...string) string {
	redacted, counts := RedactTextWithAudit(text, knownSecrets...)
	t.Add(counts)
	return redacted
}

// Add accumulates existing counts into the tracker.
func (t *AuditTracker) Add(c AuditCounts) {
	if t == nil || c.Total == 0 {
		return
	}
	t.mu.Lock()
	t.counts.Add(c)
	t.mu.Unlock()
}

// Snapshot returns a copy of accumulated counts.
func (t *AuditTracker) Snapshot() AuditCounts {
	if t == nil {
		return AuditCounts{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counts
}

// RedactTextWithAudit masks known secrets and secret shapes while returning exact per-category counts.
func RedactTextWithAudit(text string, knownSecrets ...string) (string, AuditCounts) {
	var counts AuditCounts
	if text == "" {
		return text, counts
	}
	for _, sec := range dedupeSortSecrets(knownSecrets) {
		if n := strings.Count(text, sec); n > 0 {
			counts.KnownSecrets += n
			text = strings.ReplaceAll(text, sec, Redacted)
		}
	}

	var n int
	text, n = maskPEMBlocks(text)
	counts.PEMBlocks = n
	text, counts.JWTs = replaceSimpleCount(text, jwtRe, Redacted)
	text, counts.AuthHeaders = replaceSimpleCount(text, authHeaderRe, "${1}${2}${3}"+Redacted)
	text, counts.ProviderTokens = replaceSimpleCount(text, tokenShapesRe, Redacted)
	text, counts.BearerTokens = replaceBearerCount(text)
	text, counts.BasicAuth = replaceBasicCount(text)

	var a1, a2 int
	text, a1 = replaceAssignments(text, assignmentRe)
	text, a2 = replaceAssignments(text, colonAssignmentRe)
	counts.Assignments = a1 + a2
	text, counts.SDPKeys = maskSDPKeysCount(text, Redacted)

	counts.Total = counts.KnownSecrets + counts.PEMBlocks + counts.JWTs +
		counts.AuthHeaders + counts.ProviderTokens + counts.BearerTokens +
		counts.BasicAuth + counts.Assignments + counts.SDPKeys
	return text, counts
}

func dedupeSortSecrets(knownSecrets []string) []string {
	if len(knownSecrets) == 0 {
		return nil
	}
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
	return filtered
}

func replaceSimpleCount(text string, re *regexp.Regexp, repl string) (string, int) {
	n := len(re.FindAllStringIndex(text, -1))
	if n == 0 {
		return text, 0
	}
	return re.ReplaceAllString(text, repl), n
}

func maskSDPKeysCount(text, mask string) (string, int) {
	if text == "" {
		return text, 0
	}
	if mask == "" {
		mask = Redacted
	}
	c1, c2, c3 := 0, 0, 0
	text, c1 = replaceSimpleCount(text, sdpInlineRe, "${1}"+mask)
	text, c2 = replaceSimpleCount(text, sdpKeyMgmtRe, "${1}"+mask)
	text, c3 = replaceSimpleCount(text, sdpKLineRe, "${1}"+mask)
	return text, c1 + c2 + c3
}

func replaceBearerCount(text string) (string, int) {
	n := 0
	out := bearerRe.ReplaceAllStringFunc(text, func(full string) string {
		m := bearerRe.FindStringSubmatch(full)
		if len(m) != 3 {
			return full
		}
		if strings.IndexFunc(m[2], func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
			n++
			return m[1] + Redacted
		}
		return full
	})
	return out, n
}

func replaceBasicCount(text string) (string, int) {
	n := 0
	out := basicCandidateR.ReplaceAllStringFunc(text, func(full string) string {
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
		n++
		return m[1] + Redacted
	})
	return out, n
}
