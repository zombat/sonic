// Package ai implements enhanced codec/RTP adaptation, natural-language fallback
// recovery, balanced JSON scanning, and DSPy/provider error extraction.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/sip"
)

type enhancedCodecAdapter struct{}

func (enhancedCodecAdapter) Name() string { return "enhanced_codec" }
func (enhancedCodecAdapter) Matches(keys map[string]json.RawMessage) bool {
	if _, ok := keys["enhanced_codec_analysis"]; ok {
		return true
	}
	if _, ok := keys["codec_analysis"]; ok {
		return true
	}
	for _, k := range []string{"g_711_mu_law", "g_711_a_law", "g_729_low_bitrate_codec", "opus", "ilbc"} {
		if _, ok := keys[k]; ok {
			return true
		}
	}
	return false
}

func (enhancedCodecAdapter) Build(ctx context.Context, buildCtx BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error) {
	var detectedCodecs []string
	var usedPTs []string

	if buildCtx.SIPData != "" {
		var parsed struct {
			RTPStreams []struct {
				PayloadType string `json:"payload_type"`
			} `json:"rtp_streams"`
		}
		if json.Unmarshal([]byte(buildCtx.SIPData), &parsed) == nil {
			for _, s := range parsed.RTPStreams {
				if s.PayloadType != "" && !slices.Contains(usedPTs, s.PayloadType) {
					usedPTs = append(usedPTs, s.PayloadType)
				}
			}
		}
	}
	if len(usedPTs) == 0 {
		usedPTs = []string{"0"}
	}

	codecKeyByPT := map[string]string{
		"0":  "g_711_mu_law",
		"8":  "g_711_a_law",
		"18": "g_729_low_bitrate_codec",
	}
	var enhanced map[string]CodecAnalysisContext
	for _, holderKey := range []string{"enhanced_codec_analysis", "codec_analysis"} {
		if raw, ok := keys[holderKey]; ok && json.Unmarshal(raw, &enhanced) == nil {
			break
		}
	}
	for _, pt := range usedPTs {
		if c, ok := enhanced[codecKeyByPT[pt]]; ok && c.CodecName != "" {
			detectedCodecs = append(detectedCodecs, c.CodecName)
		}
	}
	if len(detectedCodecs) == 0 {
		if direct := ExtractCodecDirectly(buildCtx.SIPData); direct != "Unknown" {
			detectedCodecs = append(detectedCodecs, direct)
		} else {
			detectedCodecs = append(detectedCodecs, "Multiple codecs analyzed")
		}
	}

	var realIssues []string
	if buildCtx.FilePath != "" {
		quick := sip.QuickQualityCheck(ctx, buildCtx.FilePath)
		if quick.Status == "success" && quick.QualityAnalysis != nil {
			realIssues = append(realIssues, quick.QualityAnalysis.DegradationFactors...)
		}
	}

	call := baseCall("enhanced-codec-analysis", "Enhanced-Codec", "Analysis",
		"SIP INVITE (inferred from codec analysis)",
		fmt.Sprintf("Enhanced analysis of %d codec types", len(detectedCodecs)),
		fmt.Sprintf("Enhanced codec analysis evaluated %s", strings.Join(detectedCodecs, ", ")),
		realIssues[:min(len(realIssues), 5)])
	call.AudioQuality.CodecUsed = detectedCodecs[0]
	call.AudioQuality.PayloadTypes = usedPTs

	recs := []string{
		"Review QoS markings and network configuration",
		"Monitor RTP streams for continued packet loss or jitter",
	}
	if len(realIssues) > 0 {
		recs = append([]string{"Address detected network quality issues immediately"}, recs...)
	}
	return DiagnosticReport{
		TotalCallsAnalyzed: 1,
		Calls:              []CallDiagnostic{call},
		OverallAssessment:  fmt.Sprintf("Enhanced codec analysis completed for: %s", strings.Join(detectedCodecs, ", ")),
		Recommendations:    recs,
	}, nil
}

// ExtractBalancedJSON scans s for the first balanced JSON object substring.
func ExtractBalancedJSON(s string) (json.RawMessage, bool) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return nil, false
	}
	inString := false
	escaped := false
	depth := 0
	for i := start; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				candidate := s[start : i+1]
				if json.Valid([]byte(candidate)) {
					return json.RawMessage(candidate), true
				}
				return nil, false
			}
		}
	}
	return nil, false
}

// RecoverLMResponseError extracts embedded JSON from DSPy-style adapter error text.
func RecoverLMResponseError(errStr string) (string, bool) {
	const startMarker = "LM Response: "
	const endMarker = "\n\nExpected to find"
	start := strings.Index(errStr, startMarker)
	end := strings.Index(errStr, endMarker)
	if start < 0 || end <= start+len(startMarker) {
		return "", false
	}
	inner := strings.TrimSpace(errStr[start+len(startMarker) : end])
	if _, ok := ExtractBalancedJSON(inner); !ok {
		return "", false
	}
	return inner, true
}

var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func buildNaturalLanguageReport(text, modelName string) DiagnosticReport {
	lower := strings.ToLower(text)
	ips := uniqueSorted(ipv4Re.FindAllString(text, -1))
	var methods, codes, issues []string
	for _, m := range []string{"INVITE", "BYE", "ACK"} {
		if strings.Contains(lower, strings.ToLower(m)) {
			methods = append(methods, m)
		}
	}
	if strings.Contains(lower, "ringing") {
		codes = append(codes, "180 Ringing")
	}
	if strings.Contains(lower, "200 ok") {
		codes = append(codes, "200 OK")
	}
	if strings.Contains(lower, "multiple bye") || strings.Contains(lower, "repeats") {
		issues = append(issues, "Multiple BYE messages detected - possible call termination issues")
	}
	if strings.Contains(lower, "timeout") {
		issues = append(issues, "Timeout issues detected")
	}
	if strings.Contains(lower, "error") || strings.Contains(lower, "fail") {
		issues = append(issues, "Error conditions detected in call flow")
	}
	if len(ips) >= 2 {
		setup := "Unknown"
		if len(methods) > 0 {
			setup = methods[0]
		}
		term := "Unknown"
		if slices.Contains(methods, "BYE") {
			term = "BYE"
		}
		call := baseCall(fmt.Sprintf("nlp-extracted-%s-%s", ips[0], ips[1]), ips[0], ips[1],
			setup, "Natural language analysis of SIP flow",
			fmt.Sprintf("NLP analysis extracted call between %s and %s with %s methods", ips[0], ips[1], strings.Join(methods, ", ")), issues)
		call.CallFlow.CallTermination = term
		call.CallFlow.ResponseCodes = codes
		return DiagnosticReport{
			TotalCallsAnalyzed: 1,
			Calls:              []CallDiagnostic{call},
			OverallAssessment:  "Analysis extracted from natural language response instead of JSON format",
			Recommendations:    []string{"Model provided detailed analysis in text format", "Consider JSON-focused prompting for structured output"},
		}
	}
	if modelName == "" {
		modelName = "unknown"
	}
	return DiagnosticReport{
		TotalCallsAnalyzed: 0,
		Calls:              []CallDiagnostic{},
		OverallAssessment:  fmt.Sprintf("Analysis failed due to parsing error - model: %s", modelName),
		Recommendations:    []string{"Review the capture file format", "Try with a different model"},
	}
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]bool, len(items))
	var out []string
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}
