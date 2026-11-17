// Package ai implements streaming combined diagnosis and partial deterministic-first
// streaming orchestration.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/redact"
)

// RunCombinedAnalysisStreaming streams token output and validates the JSON report via ArtifactFactory.
func RunCombinedAnalysisStreaming(
	ctx context.Context,
	deps Deps,
	fileContent, filePath, provider, modelName string,
	onToken func(string),
	onProgress func(string),
) (AnalysisResult, json.RawMessage) {
	d, err := deps.normalized()
	if err != nil {
		return AnalysisResult{Status: "error", Error: err.Error()}, nil
	}
	resolved := llm.ResolveProvider(provider)
	if onProgress != nil {
		onProgress("Initializing streaming analysis...")
	}
	p, ok := llm.Lookup(resolved)
	if !ok || !p.SupportsStreaming() {
		if onProgress != nil {
			onProgress(fmt.Sprintf("Streaming not supported for %s, using standard analysis", resolved))
		}
		res := RunCombinedAnalysis(ctx, d, fileContent, filePath, resolved, modelName)
		var rawReport json.RawMessage
		if res.Output != nil {
			rawReport, _ = json.Marshal(res.Output.DiagnosticReport)
		}
		return res, rawReport
	}

	prompt := fmt.Sprintf("Analyze this VoIP SIP capture data for call quality issues:\n\n%s\n\nRespond with ONLY a valid JSON object (no markdown, no explanation).", fileContent)
	prompt = d.Creds.Redact(prompt)
	if onProgress != nil {
		onProgress("Streaming analysis from LLM...")
	}

	resp, usage, cerr := d.Completer.Complete(ctx, resolved, llm.ProfileFast, modelName, []llm.Message{{Role: "user", Content: prompt}}, nil, onToken)
	if cerr != nil {
		return AnalysisResult{Status: "error", Error: d.Creds.Redact(cerr.Error())}, nil
	}
	if onProgress != nil {
		onProgress("Parsing analysis result...")
	}

	rawObj, hasJSON := ExtractBalancedJSON(resp.Text)
	if !hasJSON {
		return AnalysisResult{Status: "error", Error: "Invalid JSON in streaming response"}, nil
	}
	art, berr := d.Factory.BuildDiagnostic(ctx, BuildContext{
		RawText:      string(rawObj),
		ModelName:    firstNonEmpty(resp.Model, llm.GetModelName(resolved, llm.ProfileFast, modelName)),
		SIPData:      fileContent,
		FilePath:     filePath,
		KnownSecrets: d.Creds.KnownSecrets(),
	})
	if berr != nil {
		return AnalysisResult{Status: "error", Error: d.Creds.Redact(berr.Error())}, nil
	}
	tokCount := usage.OutputTokens
	if tokCount == 0 {
		tokCount = len(strings.Fields(resp.Text))
	}
	return AnalysisResult{
		Status: "success",
		Output: &ReportOutput{DiagnosticReport: art.Report},
		StreamingMetadata: &StreamingMeta{
			TotalTokens: tokCount,
			Provider:    resolved,
		},
	}, art.RawJSON
}

// RunStreamingMode extracts SIP capture data and executes RunCombinedAnalysisStreaming.
func RunStreamingMode(
	ctx context.Context,
	deps Deps,
	filePath, provider, modelName string,
	onToken func(string),
	onProgress func(string),
) AnalysisResult {
	sipText, _, err := extractSIPText(ctx, filePath)
	if err != nil {
		return AnalysisResult{Status: "error", Error: "No SIP data found"}
	}
	res, _ := RunCombinedAnalysisStreaming(ctx, deps, sipText, filePath, provider, modelName, onToken, onProgress)
	if res.Status == "success" {
		res.SIPData = redact.RedactText(sipText)
	}
	return res
}

// RunPartialAnalysisStreaming computes deterministic quality + MOS scores concurrently,
// reports the partial snapshot immediately, and then streams LLM diagnosis.
func RunPartialAnalysisStreaming(
	ctx context.Context,
	deps Deps,
	filePath, provider, modelName string,
	onToken func(string),
	onProgress func(string),
	onPartial func(PartialSnapshot),
) PartialStreamingResult {
	resolved := llm.ResolveProvider(provider)
	start := time.Now()
	if onProgress != nil {
		onProgress("Extracting SIP data...")
	}
	sipText, summary, err := extractSIPText(ctx, filePath)
	if err != nil {
		return PartialStreamingResult{Status: "error", Error: "No SIP data found"}
	}
	if onProgress != nil {
		onProgress("Running quality and MOS analysis (parallel)...")
	}

	var qRaw, mRaw json.RawMessage
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		auth := extract.ExtractAuthAndRegistrationInfo(ctx, filePath)
		var pkts []extract.SIPPacket
		var rtp []extract.RTPStreamSummary
		if summary != nil {
			pkts = summary.SIPPackets
			rtp = summary.RTPStreams
		}
		q := sip.ScoreCallQuality(sip.ScoringInput{SIPPackets: pkts, RTPStreams: rtp, Auth: &auth})
		b, _ := json.Marshal(q)
		qRaw = json.RawMessage(redact.RedactText(string(b)))
	}()
	go func() {
		defer wg.Done()
		var rtp []extract.RTPStreamSummary
		if summary != nil {
			rtp = summary.RTPStreams
		}
		m := sip.AnalyzeRTPStreamsFromSummary(rtp)
		b, _ := json.Marshal(m)
		mRaw = json.RawMessage(redact.RedactText(string(b)))
	}()
	wg.Wait()

	partialDur := time.Since(start)
	if onPartial != nil {
		onPartial(PartialSnapshot{
			Status:              "partial",
			QualityAnalysis:     qRaw,
			MOSAnalysis:         mRaw,
			PartialResultTimeMS: partialDur.Milliseconds(),
		})
	}
	if onProgress != nil {
		onProgress("Starting LLM streaming...")
	}
	llmStart := time.Now()
	llmRes, rawDiag := RunCombinedAnalysisStreaming(ctx, deps, sipText, filePath, resolved, modelName, onToken, nil)
	llmDur := time.Since(llmStart)

	if llmRes.Status != "success" && len(rawDiag) == 0 {
		return PartialStreamingResult{
			Status:          "error",
			Error:           llmRes.Error,
			QualityAnalysis: qRaw,
			MOSAnalysis:     mRaw,
		}
	}
	if len(rawDiag) == 0 && llmRes.Output != nil {
		rawDiag, _ = json.Marshal(llmRes.Output.DiagnosticReport)
	}
	if len(rawDiag) == 0 {
		rawDiag = json.RawMessage("{}")
	}
	tokens := 0
	if llmRes.StreamingMetadata != nil {
		tokens = llmRes.StreamingMetadata.TotalTokens
	}
	return PartialStreamingResult{
		Status:          "success",
		QualityAnalysis: qRaw,
		MOSAnalysis:     mRaw,
		LLMAnalysis:     rawDiag,
		Timing: &PartialTiming{
			PartialResultMS: partialDur.Milliseconds(),
			LLMStreamingMS:  llmDur.Milliseconds(),
			TotalMS:         time.Since(start).Milliseconds(),
		},
		StreamingMetadata: &PartialStreamMeta{
			Provider: resolved,
			Tokens:   tokens,
		},
	}
}
