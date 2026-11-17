// Package ai orchestrates SIP LLM diagnostics across fast, detailed, deep,
// combined, and all-models modes through llm.Completer and ArtifactFactory.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/redact"
)

// ModelsToTest lists the default model comparison roster for --model all.
var ModelsToTest = []string{"qwen2.5:0.5b", "qwen2.5vl:7b"}

// Deps holds runtime dependencies shared across all AI analysis entrypoints.
type Deps struct {
	Completer llm.Completer
	Creds     *llm.CredentialStore
	Factory   *ArtifactFactory
}

func (d Deps) normalized() (Deps, error) {
	if d.Creds == nil {
		creds, err := llm.NewCredentialStore("")
		if err != nil {
			return Deps{}, err
		}
		d.Creds = creds
	}
	if d.Completer == nil {
		d.Completer = llm.NewClient(d.Creds)
	}
	if d.Factory == nil {
		d.Factory = NewArtifactFactory()
	}
	return d, nil
}

// DiagnosticMessages builds the redacted system/user prompt pair matching SipDiagnosticSignature.
func DiagnosticMessages(enrichedSIPData string) []llm.Message {
	system := `Analyzes SIP capture data to diagnose call quality issues like choppy audio and unexpected disconnects.

You must respond with ONLY a valid JSON object matching this shape:
{
  "totalCalls": 1,
  "calls": [{
    "callId": "REAL_CALL_ID_FROM_DATA",
    "callerIp": "REAL_CALLER_IP",
    "calleeIp": "REAL_CALLEE_IP",
    "userAgents": ["REAL_USER_AGENT_STRINGS"],
    "audioQuality": {
      "codecUsed": "REAL_CODEC_NAME",
      "payloadTypes": ["REAL_PAYLOAD_NUMBERS"],
      "rtpPort": "REAL_PORT_NUMBER",
      "potentialIssues": ["IDENTIFIED_ISSUES_OR_EMPTY_ARRAY"]
    },
    "callFlow": {
      "callSetupMethod": "REAL_METHOD_LIKE_INVITE",
      "callTermination": "REAL_TERMINATION_OR_Unknown",
      "responseCodes": ["REAL_STATUS_CODES"],
      "callDurationIndicators": "YOUR_ANALYSIS"
    },
    "diagnosticSummary": "YOUR_ANALYSIS_OF_THIS_CALL"
  }],
  "overallAssessment": "YOUR_OVERALL_ANALYSIS",
  "recommendations": ["YOUR_SPECIFIC_RECOMMENDATIONS"]
}

CRITICAL: Do NOT include placeholder text like "<actual_value>" or "REAL_VALUE".
Respond with ONLY valid JSON, no explanations.`
	return []llm.Message{
		{Role: "system", Content: system},
		{Role: "user", Content: enrichedSIPData},
	}
}

// SIPDiagnosticTest runs one LLM pass and builds a validated, redacted DiagnosticArtifact.
func SIPDiagnosticTest(
	ctx context.Context,
	deps Deps,
	provider, profile, modelName, fileContent, filePath string,
) AnalysisResult {
	if fileContent == "" {
		return AnalysisResult{Status: "skipped", Error: "No SIP data extracted from the provided pcap file."}
	}
	d, err := deps.normalized()
	if err != nil {
		return AnalysisResult{Status: "error", Error: err.Error()}
	}
	resolvedProvider := llm.ResolveProvider(provider)
	targetModel := llm.GetModelName(resolvedProvider, profile, modelName)
	enriched := d.Creds.Redact(EnrichSIPDataWithCodecContext(fileContent))

	resp, _, err := d.Completer.Complete(ctx, resolvedProvider, profile, modelName, DiagnosticMessages(enriched), nil, nil)
	if err != nil {
		errText := d.Creds.Redact(err.Error())
		if recovered, ok := RecoverLMResponseError(errText); ok {
			art, aerr := d.Factory.BuildDiagnostic(ctx, BuildContext{
				RawText:      recovered,
				ModelName:    targetModel,
				SIPData:      fileContent,
				FilePath:     filePath,
				KnownSecrets: d.Creds.KnownSecrets(),
			})
			if aerr == nil {
				return AnalysisResult{Status: "success", Output: &ReportOutput{DiagnosticReport: art.Report}}
			}
		}
		return AnalysisResult{Status: "error", Error: errText}
	}

	art, aerr := d.Factory.BuildDiagnostic(ctx, BuildContext{
		RawText:      resp.Text,
		ModelName:    firstNonEmpty(resp.Model, targetModel),
		SIPData:      fileContent,
		FilePath:     filePath,
		KnownSecrets: d.Creds.KnownSecrets(),
	})
	if aerr != nil {
		return AnalysisResult{Status: "error", Error: d.Creds.Redact(aerr.Error())}
	}
	return AnalysisResult{
		Status:      "success",
		Output:      &ReportOutput{DiagnosticReport: art.Report},
		RawResponse: d.Creds.Redact(resp.Text),
	}
}

// CombineDiagnosticResults merges fast structured and detailed insight reports.
func CombineDiagnosticResults(fastRes, detailedRes AnalysisResult) AnalysisResult {
	if fastRes.Status != "success" && detailedRes.Status != "success" {
		return AnalysisResult{Status: "error", Error: "Both models failed to provide analysis"}
	}
	var combined DiagnosticReport
	if fastRes.Status == "success" && fastRes.Output != nil {
		combined = cloneReport(fastRes.Output.DiagnosticReport)
	} else if detailedRes.Output != nil {
		combined = cloneReport(detailedRes.Output.DiagnosticReport)
	}

	if detailedRes.Status == "success" && detailedRes.Output != nil {
		det := detailedRes.Output.DiagnosticReport
		for i := range combined.Calls {
			if i >= len(det.Calls) {
				break
			}
			mergeCallDiagnostic(&combined.Calls[i], det.Calls[i])
		}
		if strings.Contains(det.OverallAssessment, "Analysis extracted from natural language") {
			combined.OverallAssessment += " | Detailed Analysis: Rich natural language insights provided additional context."
		}
		for _, rec := range det.Recommendations {
			if !slices.Contains(combined.Recommendations, rec) && !strings.Contains(rec, "JSON-focused prompting") {
				combined.Recommendations = append(combined.Recommendations, "[Detailed Analysis] "+rec)
			}
		}
	}
	combined.AnalysisMethod = "Combined: Fast structured analysis + Detailed natural language insights"
	combined.ModelsUsed = []string{"qwen2.5:0.5b (structured)", "qwen2.5vl:7b (detailed)"}
	return AnalysisResult{
		Status: "success",
		Output: &ReportOutput{DiagnosticReport: combined},
	}
}

func mergeCallDiagnostic(base *CallDiagnostic, det CallDiagnostic) {
	if base.AudioQuality.CodecUsed == "Unknown" && det.AudioQuality.CodecUsed != "" && det.AudioQuality.CodecUsed != "Unknown" {
		base.AudioQuality.CodecUsed = det.AudioQuality.CodecUsed
	}
	if len(base.AudioQuality.PayloadTypes) == 0 && len(det.AudioQuality.PayloadTypes) > 0 {
		base.AudioQuality.PayloadTypes = slices.Clone(det.AudioQuality.PayloadTypes)
	}
	if base.AudioQuality.RTPPort == "Unknown" && det.AudioQuality.RTPPort != "" && det.AudioQuality.RTPPort != "Unknown" {
		base.AudioQuality.RTPPort = det.AudioQuality.RTPPort
	}
	base.AudioQuality.PotentialIssues = uniqueSorted(append(slices.Clone(base.AudioQuality.PotentialIssues), det.AudioQuality.PotentialIssues...))
	if det.DiagnosticSummary != "" && det.DiagnosticSummary != "No summary available" {
		base.DiagnosticSummary = fmt.Sprintf("%s | Enhanced: %s", base.DiagnosticSummary, det.DiagnosticSummary)
	}
}

func cloneReport(r DiagnosticReport) DiagnosticReport {
	out := r
	out.Recommendations = slices.Clone(r.Recommendations)
	out.ModelsUsed = slices.Clone(r.ModelsUsed)
	out.Calls = make([]CallDiagnostic, len(r.Calls))
	for i, c := range r.Calls {
		c.UserAgents = slices.Clone(c.UserAgents)
		c.AudioQuality.PayloadTypes = slices.Clone(c.AudioQuality.PayloadTypes)
		c.AudioQuality.PotentialIssues = slices.Clone(c.AudioQuality.PotentialIssues)
		c.CallFlow.ResponseCodes = slices.Clone(c.CallFlow.ResponseCodes)
		out.Calls[i] = c
	}
	return out
}

// RunCombinedAnalysis executes fast and detailed passes (or a single model override) and merges them.
func RunCombinedAnalysis(ctx context.Context, deps Deps, fileContent, filePath, provider, modelName string) AnalysisResult {
	if modelName != "" {
		return SIPDiagnosticTest(ctx, deps, provider, llm.ProfileDetailed, modelName, fileContent, filePath)
	}
	fastRes := SIPDiagnosticTest(ctx, deps, provider, llm.ProfileFast, "", fileContent, filePath)
	detailedRes := SIPDiagnosticTest(ctx, deps, provider, llm.ProfileDetailed, "", fileContent, filePath)
	combined := CombineDiagnosticResults(fastRes, detailedRes)
	if combined.Status == "success" && combined.Output != nil {
		for i := range combined.Output.DiagnosticReport.Calls {
			if combined.Output.DiagnosticReport.Calls[i].AudioQuality.CodecUsed == "Unknown" {
				if fallback := ExtractCodecDirectly(fileContent); fallback != "Unknown" {
					combined.Output.DiagnosticReport.Calls[i].AudioQuality.CodecUsed = fallback
				}
			}
		}
	}
	return combined
}

// RunAnalysisMode orchestrates fast/detailed/deep/combined/all SIP LLM analysis with optional quality and MOS.
func RunAnalysisMode(
	ctx context.Context,
	deps Deps,
	filePath, modelMode string,
	enableQuality, enableMOS bool,
	provider, modelName string,
) AnalysisResult {
	if modelName != "" && modelMode == "all" {
		return AnalysisResult{Status: "error", Error: "--model-name cannot be used with --model all, which tests its own models"}
	}
	switch modelMode {
	case "fast", "detailed", "deep", "combined", "all":
	default:
		return AnalysisResult{Status: "error", Error: fmt.Sprintf("Unknown model mode: %s", modelMode)}
	}
	sipText, summary, err := extractSIPText(ctx, filePath)
	if err != nil {
		return AnalysisResult{Status: "error", Error: "No SIP data found"}
	}
	auth := extract.ExtractAuthAndRegistrationInfo(ctx, filePath)

	var result AnalysisResult
	switch modelMode {
	case "combined":
		result = RunCombinedAnalysis(ctx, deps, sipText, filePath, provider, modelName)
	case "fast", "detailed", "deep":
		result = SIPDiagnosticTest(ctx, deps, provider, modelMode, modelName, sipText, filePath)
	case "all":
		result = runAllModels(ctx, deps, sipText, filePath, provider)
	}
	if result.Status != "success" {
		return result
	}
	result.SIPData = redact.RedactText(sipText)
	if rawAuth, merr := json.Marshal(auth); merr == nil {
		result.AuthData = json.RawMessage(redact.RedactText(string(rawAuth)))
	}
	if enableQuality || enableMOS {
		result.QualityAnalysis = buildQualityBundle(summary, sipText, &auth, enableQuality, enableMOS)
	}
	return result
}

func runAllModels(ctx context.Context, deps Deps, sipText, filePath, provider string) AnalysisResult {
	prov := llm.ResolveProvider(provider)
	for _, model := range ModelsToTest {
		res := SIPDiagnosticTest(ctx, deps, prov, llm.ProfileFast, model, sipText, filePath)
		if res.Status == "success" {
			return res
		}
	}
	return AnalysisResult{Status: "error", Error: "All models failed to provide analysis"}
}
