// Package ai registers primary SIP JSON response adapters inside ArtifactFactory.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

func defaultAdapters() []ResponseAdapter {
	return []ResponseAdapter{
		enhancedCodecAdapter{},
		directDiagnosticAdapter{},
		singleCallAdapter{},
		messagesArrayAdapter{},
		elasticsearchAdapter{},
		statisticsAdapter{},
		structuredIssuesAdapter{},
		codecAnalysisAdapter{},
		mediaSessionsAdapter{},
	}
}

func baseCall(id, caller, callee, setup, duration, summary string, issues []string) CallDiagnostic {
	if len(issues) == 0 {
		issues = []string{}
	}
	return CallDiagnostic{
		CallID:     id,
		CallerIP:   caller,
		CalleeIP:   callee,
		UserAgents: []string{},
		AudioQuality: AudioQuality{
			CodecUsed:       "Unknown",
			PayloadTypes:    []string{},
			RTPPort:         "Unknown",
			PotentialIssues: issues,
		},
		CallFlow: CallFlow{
			CallSetupMethod:        setup,
			CallTermination:        "Unknown",
			ResponseCodes:          []string{},
			CallDurationIndicators: duration,
		},
		DiagnosticSummary: summary,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

type directDiagnosticAdapter struct{}

func (directDiagnosticAdapter) Name() string { return "direct_diagnostic" }
func (directDiagnosticAdapter) Matches(keys map[string]json.RawMessage) bool {
	_, hasCalls := keys["calls"]
	_, hasTotal := keys["totalCalls"]
	_, hasTotalSnake := keys["total_calls_analyzed"]
	_, hasAssess := keys["overallAssessment"]
	_, hasAssessSnake := keys["overall_assessment"]
	return hasCalls && (hasTotal || hasTotalSnake || hasAssess || hasAssessSnake)
}

func (directDiagnosticAdapter) Build(_ context.Context, buildCtx BuildContext, _ map[string]json.RawMessage) (DiagnosticReport, error) {
	rawObj, ok := ExtractBalancedJSON(buildCtx.RawText)
	if !ok {
		return DiagnosticReport{}, fmt.Errorf("missing JSON object")
	}
	var flex flexReport
	if err := json.Unmarshal(rawObj, &flex); err != nil {
		return DiagnosticReport{}, err
	}
	total := len(flex.Calls)
	if flex.TotalCallsAnalyzed != nil {
		total = *flex.TotalCallsAnalyzed
	} else if flex.TotalCalls != nil {
		total = *flex.TotalCalls
	}
	calls := make([]CallDiagnostic, 0, len(flex.Calls))
	for _, c := range flex.Calls {
		calls = append(calls, normalizeFlexCall(c))
	}
	return DiagnosticReport{
		TotalCallsAnalyzed: total,
		Calls:              calls,
		OverallAssessment:  firstNonEmpty(flex.OverallAssessment, flex.OverallAssessCamel, "Analysis complete"),
		Recommendations:    flex.Recommendations,
		AnalysisMethod:     flex.AnalysisMethod,
		ModelsUsed:         flex.ModelsUsed,
	}, nil
}

func normalizeFlexCall(c flexCall) CallDiagnostic {
	ua := c.UACamel
	if len(ua) == 0 {
		ua = c.UASnake
	}
	if ua == nil {
		ua = []string{}
	}
	var aq AudioQuality
	srcAQ := c.AudioCamel
	if srcAQ == nil {
		srcAQ = c.AudioSnake
	}
	if srcAQ != nil {
		pt := srcAQ.PayloadTypes
		if len(pt) == 0 {
			pt = srcAQ.PayloadsSnake
		}
		issues := srcAQ.PotentialIssues
		if len(issues) == 0 {
			issues = srcAQ.IssuesSnake
		}
		aq = AudioQuality{
			CodecUsed:       firstNonEmpty(srcAQ.CodecUsed, srcAQ.CodecSnake, "Unknown"),
			PayloadTypes:    pt,
			RTPPort:         firstNonEmpty(srcAQ.RTPPort, srcAQ.RTPPortSnake, "Unknown"),
			PotentialIssues: issues,
		}
	}
	var cf CallFlow
	srcCF := c.FlowCamel
	if srcCF == nil {
		srcCF = c.FlowSnake
	}
	if srcCF != nil {
		codes := srcCF.CodesCamel
		if len(codes) == 0 {
			codes = srcCF.CodesSnake
		}
		term := firstNonEmpty(derefStr(srcCF.TermCamel), derefStr(srcCF.TermSnake), "Unknown")
		cf = CallFlow{
			CallSetupMethod:        firstNonEmpty(srcCF.MethodCamel, srcCF.MethodSnake, "Unknown"),
			CallTermination:        term,
			ResponseCodes:          codes,
			CallDurationIndicators: firstNonEmpty(srcCF.DurCamel, srcCF.DurSnake, "Unknown"),
			InitiatorIP:            firstPtr(srcCF.InitCamel, srcCF.InitSnake),
			TerminatorIP:           firstPtr(srcCF.TermIPCamel, srcCF.TermIPSnake),
			DisconnectCode:         firstPtr(srcCF.DiscCamel, srcCF.DiscSnake),
			HangupPattern:          firstPtr(srcCF.HangCamel, srcCF.HangSnake),
		}
	}
	return CallDiagnostic{
		CallID:            firstNonEmpty(c.CallIDCamel, c.CallIDSnake, "unknown-call-id"),
		CallerIP:          firstNonEmpty(c.CallerCamel, c.CallerSnake, "unknown"),
		CalleeIP:          firstNonEmpty(c.CalleeCamel, c.CalleeSnake, "unknown"),
		UserAgents:        ua,
		AudioQuality:      aq,
		NetworkBaseline:   c.NetBase,
		CallFlow:          cf,
		DiagnosticSummary: firstNonEmpty(c.SummaryCamel, c.SummarySnake, "No summary available"),
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func firstPtr(a, b *string) *string {
	if a != nil {
		return a
	}
	return b
}

type singleCallAdapter struct{}

func (singleCallAdapter) Name() string { return "single_call" }
func (singleCallAdapter) Matches(keys map[string]json.RawMessage) bool {
	_, hasAQ := keys["audioQuality"]
	_, hasCF := keys["callFlow"]
	_, hasCalls := keys["calls"]
	return hasAQ && hasCF && !hasCalls
}

func (singleCallAdapter) Build(_ context.Context, buildCtx BuildContext, _ map[string]json.RawMessage) (DiagnosticReport, error) {
	rawObj, _ := ExtractBalancedJSON(buildCtx.RawText)
	var c flexCall
	if err := json.Unmarshal(rawObj, &c); err != nil {
		return DiagnosticReport{}, err
	}
	call := normalizeFlexCall(c)
	return DiagnosticReport{
		TotalCallsAnalyzed: 1,
		Calls:              []CallDiagnostic{call},
		OverallAssessment:  "Partial analysis completed based on available data",
		Recommendations:    []string{"Verify pcap file completeness", "Check for additional call data"},
	}, nil
}

type messagesArrayAdapter struct{}

func (messagesArrayAdapter) Name() string { return "messages_array" }
func (messagesArrayAdapter) Matches(keys map[string]json.RawMessage) bool {
	raw, ok := keys["messages"]
	return ok && strings.HasPrefix(strings.TrimSpace(string(raw)), "[")
}

func (messagesArrayAdapter) Build(_ context.Context, _ BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error) {
	var msgs []struct {
		SrcIP       string          `json:"source_ip"`
		DstIP       string          `json:"destination_ip"`
		MessageType string          `json:"message_type"`
		StatusCode  json.RawMessage `json:"status_code"`
	}
	if err := json.Unmarshal(keys["messages"], &msgs); err != nil {
		return DiagnosticReport{}, err
	}
	order := []string{}
	byKey := make(map[string]*CallDiagnostic)
	for _, m := range msgs {
		src := firstNonEmpty(m.SrcIP, "Unknown")
		dst := firstNonEmpty(m.DstIP, "Unknown")
		key := src + "-" + dst
		if _, ok := byKey[key]; !ok {
			order = append(order, key)
			c := baseCall("extracted-"+key, src, dst, "INVITE", "Extracted from message trace", "SIP exchange "+key, nil)
			byKey[key] = &c
		}
		code := strings.Trim(strings.TrimSpace(string(m.StatusCode)), `"`)
		if strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5") {
			byKey[key].AudioQuality.PotentialIssues = append(byKey[key].AudioQuality.PotentialIssues, "Error response: "+code)
		}
		if code != "" && !slices.Contains(byKey[key].CallFlow.ResponseCodes, code) {
			byKey[key].CallFlow.ResponseCodes = append(byKey[key].CallFlow.ResponseCodes, code)
		}
	}
	calls := make([]CallDiagnostic, 0, len(order))
	for _, k := range order {
		calls = append(calls, *byKey[k])
	}
	return DiagnosticReport{
		TotalCallsAnalyzed: len(calls),
		Calls:              calls,
		OverallAssessment:  fmt.Sprintf("Extracted %d call flows from message array", len(calls)),
		Recommendations:    []string{"Review 4xx/5xx SIP error responses in extracted flows"},
	}, nil
}
