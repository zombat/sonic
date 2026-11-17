// Package grpc implements credential/identity scrubbing and endpoint formatting helpers.
package grpc

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func endpointStr(end *extract.Endpoint) string {
	if end == nil {
		return "None"
	}
	if strings.Contains(end.IP, ":") {
		return fmt.Sprintf("[%s]:%d", end.IP, end.Port)
	}
	return fmt.Sprintf("%s:%d", end.IP, end.Port)
}

func endpointPtr(end *extract.Endpoint) *string {
	if end == nil {
		return nil
	}
	s := endpointStr(end)
	return &s
}

func serviceFamily(method *string) *string {
	if method == nil || *method == "" {
		return nil
	}
	service := strings.SplitN(strings.TrimLeft(*method, "/"), "/", 2)[0]
	for _, fp := range ServiceFamilies {
		if strings.HasPrefix(service, fp.prefix) {
			f := fp.family
			return &f
		}
	}
	g := "gRPC"
	return &g
}

var timeoutRe = regexp.MustCompile(`^(\d{1,8})([HMSmun])$`)

func parseTimeout(val *string) *float64 {
	if val == nil || *val == "" {
		return nil
	}
	m := timeoutRe.FindStringSubmatch(strings.TrimSpace(*val))
	if len(m) != 3 {
		return nil
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return nil
	}
	var scale float64
	switch m[2] {
	case "H":
		scale = 3600.0
	case "M":
		scale = 60.0
	case "S":
		scale = 1.0
	case "m":
		scale = 1e-3
	case "u":
		scale = 1e-6
	case "n":
		scale = 1e-9
	}
	res := model.Round(float64(n)*scale, 6)
	return &res
}

type scrubRule struct {
	value      string
	standalone bool
}

func buildScrubRules(secrets, identities map[string]bool) []scrubRule {
	var rules []scrubRule
	for v := range secrets {
		if len(v) >= extract.MinScrubLength {
			rules = append(rules, scrubRule{value: v})
		}
	}
	for v := range identities {
		if secrets[v] || len(v) < extract.MinScrubLength {
			continue
		}
		rules = append(rules, scrubRule{value: v, standalone: true})
	}
	slices.SortStableFunc(rules, func(a, b scrubRule) int {
		return cmp.Compare(len(b.value), len(a.value))
	})
	return rules
}

func isWordOrHyphenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-'
}

func applyScrubRules(s string, rules []scrubRule) string {
	for _, r := range rules {
		if !strings.Contains(s, r.value) {
			continue
		}
		if !r.standalone {
			s = strings.ReplaceAll(s, r.value, "[REDACTED]")
			continue
		}
		var out strings.Builder
		pos := 0
		for pos < len(s) {
			idx := strings.Index(s[pos:], r.value)
			if idx < 0 {
				out.WriteString(s[pos:])
				break
			}
			absIdx := pos + idx
			endIdx := absIdx + len(r.value)
			prevOK := absIdx == 0
			if !prevOK {
				prevRune, _ := utf8.DecodeLastRuneInString(s[:absIdx])
				prevOK = !isWordOrHyphenRune(prevRune)
			}
			nextOK := endIdx == len(s)
			if !nextOK {
				nextRune, _ := utf8.DecodeRuneInString(s[endIdx:])
				nextOK = !isWordOrHyphenRune(nextRune)
			}
			if prevOK && nextOK {
				out.WriteString(s[pos:absIdx])
				out.WriteString("[REDACTED]")
			} else {
				out.WriteString(s[pos:endIdx])
			}
			pos = endIdx
		}
		s = out.String()
	}
	return s
}

func scrubPtr(p *string, rules []scrubRule) {
	if p != nil {
		*p = applyScrubRules(*p, rules)
	}
}

func scrubReport(rep *Report, rules []scrubRule) {
	if len(rules) == 0 {
		return
	}
	rep.Verdict = applyScrubRules(rep.Verdict, rules)
	for i := range rep.Capture.Warnings {
		rep.Capture.Warnings[i] = applyScrubRules(rep.Capture.Warnings[i], rules)
	}
	for i := range rep.RPCs {
		scrubPtr(rep.RPCs[i].GrpcMessage, rules)
		scrubPtr(rep.RPCs[i].Authority, rules)
		scrubPtr(rep.RPCs[i].UserAgent, rules)
		rep.RPCs[i].Diagnosis = applyScrubRules(rep.RPCs[i].Diagnosis, rules)
	}
	for i := range rep.Issues {
		rep.Issues[i].Message = applyScrubRules(rep.Issues[i].Message, rules)
	}
	for i := range rep.Timeline {
		rep.Timeline[i].Detail = applyScrubRules(rep.Timeline[i].Detail, rules)
	}
}

func nonNilInts(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}
