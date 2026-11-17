// Package main wires Phase 7 SIP LLM analysis, streaming, batch directory
// processing, and gRPC proto fetching CLI submodes.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
)

func finishLLMReport(raw []byte, merr error, md, summary string, o cliOptions, creds *llm.CredentialStore, stdout, stderr io.Writer) int {
	if merr == nil {
		raw = []byte(creds.Redact(string(raw)))
	}
	var saveErr error
	if o.saveFile != "" {
		saveErr = report.SaveRawReport(raw, merr, md, o.saveFile)
	}
	return finishReport(raw, merr, saveErr, o.saveFile != "", summary, o.asJSON, stdout, stderr)
}

func runFetchProtos(ctx context.Context, dest string, asJSON bool, deps llmRuntimeDeps, stdout, stderr io.Writer) int {
	fetchFn := deps.fetchProtos
	if fetchFn == nil {
		fetchFn = defaultLLMRuntimeDeps().fetchProtos
	}
	res := fetchFn(ctx, dest)
	raw, merr := json.MarshalIndent(res, "", "  ")
	if merr == nil {
		raw = []byte(redact.RedactText(string(raw)))
	}
	if res.Status != "success" {
		return writeFailure(redact.RedactText(res.Error), raw, merr, asJSON, stdout, stderr)
	}
	if asJSON {
		return writeJSONBytes(stdout, stderr, raw, merr)
	}
	fmt.Fprintf(stdout, "Fetched %d proto files into %s\n", len(res.Files), res.Dir)
	return 0
}

func runSIPAnalysisLLM(
	ctx context.Context,
	o cliOptions,
	lo llmCLIOptions,
	creds *llm.CredentialStore,
	deps llmRuntimeDeps,
	stdout, stderr io.Writer,
) int {
	res := ai.RunAnalysisMode(ctx, buildAIDeps(creds, deps), o.file, lo.model, lo.quality, lo.mos, lo.provider, lo.modelName)
	raw, merr := json.MarshalIndent(res, "", "  ")
	if res.Status != "success" {
		return writeFailure(creds.Redact(res.Error), raw, merr, o.asJSON, stdout, stderr)
	}
	return finishLLMReport(raw, merr, buildDiagnosticMarkdown(res.Output, creds), formatSIPDiagnosticSummary(res), o, creds, stdout, stderr)
}

func runStreamLLM(
	ctx context.Context,
	o cliOptions,
	lo llmCLIOptions,
	creds *llm.CredentialStore,
	deps llmRuntimeDeps,
	stdout, stderr io.Writer,
) int {
	var onProg func(string)
	if lo.verbose {
		onProg = func(msg string) { fmt.Fprintln(stderr, creds.Redact(msg)) }
	}
	var onTok func(string)
	if !o.asJSON {
		onTok = func(tok string) { _, _ = io.WriteString(stdout, creds.Redact(tok)) }
	}
	aiDeps := buildAIDeps(creds, deps)
	if lo.partial {
		var onPartial func(ai.PartialSnapshot)
		if !o.asJSON {
			onPartial = func(snap ai.PartialSnapshot) {
				fmt.Fprintf(stdout, "[partial] deterministic quality and MOS ready in %dms\n", snap.PartialResultTimeMS)
			}
		}
		res := ai.RunPartialAnalysisStreaming(ctx, aiDeps, o.file, lo.provider, lo.modelName, onTok, onProg, onPartial)
		if !o.asJSON {
			fmt.Fprintln(stdout)
		}
		raw, merr := json.MarshalIndent(res, "", "  ")
		if res.Status != "success" {
			return writeFailure(creds.Redact(res.Error), raw, merr, o.asJSON, stdout, stderr)
		}
		summary := fmt.Sprintf("Partial streaming complete (provider=%s, tokens=%d)", partialProvider(res), partialTokens(res))
		return finishLLMReport(raw, merr, buildPartialMarkdown(ctx, aiDeps, res, creds), summary, o, creds, stdout, stderr)
	}

	res := ai.RunStreamingMode(ctx, aiDeps, o.file, lo.provider, lo.modelName, onTok, onProg)
	if !o.asJSON {
		fmt.Fprintln(stdout)
	}
	raw, merr := json.MarshalIndent(res, "", "  ")
	if res.Status != "success" {
		return writeFailure(creds.Redact(res.Error), raw, merr, o.asJSON, stdout, stderr)
	}
	return finishLLMReport(raw, merr, buildDiagnosticMarkdown(res.Output, creds), formatSIPDiagnosticSummary(res), o, creds, stdout, stderr)
}

func runBatchLLM(
	ctx context.Context,
	o cliOptions,
	lo llmCLIOptions,
	creds *llm.CredentialStore,
	deps llmRuntimeDeps,
	stdout, stderr io.Writer,
) int {
	files, cerr := ai.CollectBatchPcaps(lo.batchDir)
	if cerr != nil {
		msg := creds.Redact(cerr.Error())
		errRaw, merr := json.MarshalIndent(struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}{Status: "error", Error: msg}, "", "  ")
		return writeFailure(msg, errRaw, merr, o.asJSON, stdout, stderr)
	}
	mode := ai.ModeSequential
	if lo.batchMode == string(ai.ModeParallel) {
		mode = ai.ModeParallel
	}
	var onProg func(ai.BatchProgress)
	if lo.verbose {
		onProg = func(p ai.BatchProgress) {
			fmt.Fprintf(stderr, "[%d/%d] %s: %s\n", p.Index+1, p.TotalFiles, p.FilePath, p.Status)
		}
	}
	modelOverride := lo.modelName
	if modelOverride == "" && lo.model != "fast" && lo.model != "combined" && lo.model != "all" {
		modelOverride = llm.GetModelName(llm.ResolveProvider(lo.provider), lo.model, "")
	}
	res := ai.AnalyzeBatch(ctx, buildAIDeps(creds, deps), files, lo.provider, lo.model, mode, lo.batchWorkers, modelOverride, onProg, nil)
	raw, merr := json.MarshalIndent(res, "", "  ")
	if merr == nil {
		raw = []byte(creds.Redact(string(raw)))
	}
	md := buildBatchMarkdown(res, creds)
	if res.Aggregate.Successful == 0 && res.Aggregate.Failed > 0 {
		if o.saveFile != "" {
			_ = report.SaveRawReport(raw, merr, md, o.saveFile)
		}
		return writeFailure(fmt.Sprintf("all %d batch files failed analysis", res.Aggregate.Failed), raw, merr, o.asJSON, stdout, stderr)
	}
	summary := fmt.Sprintf("Batch analysis complete: %d/%d succeeded, total_tokens=%d, duration=%.2fs",
		res.Aggregate.Successful, res.BatchMetadata.TotalFiles, res.Aggregate.TotalTokens, res.Aggregate.TotalDuration)
	return finishLLMReport(raw, merr, md, summary, o, creds, stdout, stderr)
}

func buildDiagnosticMarkdown(out *ai.ReportOutput, creds *llm.CredentialStore) string {
	if out == nil {
		return ""
	}
	art := ai.DiagnosticArtifact{Report: out.DiagnosticReport}
	_ = art.Validate()
	art.Redact(creds.KnownSecrets())
	return creds.Redact(art.Markdown())
}

func buildPartialMarkdown(ctx context.Context, deps ai.Deps, res ai.PartialStreamingResult, creds *llm.CredentialStore) string {
	if len(res.LLMAnalysis) > 0 {
		factory := deps.Factory
		if factory == nil {
			factory = ai.NewArtifactFactory()
		}
		if art, err := factory.BuildDiagnostic(ctx, ai.BuildContext{
			RawText:      string(res.LLMAnalysis),
			KnownSecrets: creds.KnownSecrets(),
		}); err == nil {
			return creds.Redact(art.Markdown())
		}
	}
	return "# S.O.N.I.C. Partial Streaming Report\n"
}

func buildBatchMarkdown(res ai.BatchResult, creds *llm.CredentialStore) string {
	var sb strings.Builder
	sb.WriteString("# S.O.N.I.C. Batch SIP Diagnostic Report\n\n")
	fmt.Fprintf(&sb, "- Mode: %s\n- Total Files: %d\n- Succeeded: %d\n- Failed: %d\n- Total Tokens: %d\n\n",
		res.BatchMetadata.Mode, res.BatchMetadata.TotalFiles, res.Aggregate.Successful, res.Aggregate.Failed, res.Aggregate.TotalTokens)
	for _, f := range res.Files {
		fmt.Fprintf(&sb, "## %s (%s)\n\n", f.File, f.Status)
		if f.Error != "" {
			fmt.Fprintf(&sb, "- Error: %s\n\n", creds.Redact(f.Error))
		} else if f.Output != nil {
			fmt.Fprintf(&sb, "- Assessment: %s\n\n", creds.Redact(f.Output.DiagnosticReport.OverallAssessment))
		}
	}
	return creds.Redact(sb.String())
}

func formatSIPDiagnosticSummary(res ai.AnalysisResult) string {
	if res.Output == nil {
		return "SIP analysis complete"
	}
	rep := res.Output.DiagnosticReport
	return fmt.Sprintf("SIP analysis complete: %d call(s); %s", rep.TotalCallsAnalyzed, rep.OverallAssessment)
}

func partialProvider(res ai.PartialStreamingResult) string {
	if res.StreamingMetadata == nil {
		return ""
	}
	return res.StreamingMetadata.Provider
}

func partialTokens(res ai.PartialStreamingResult) int {
	if res.StreamingMetadata == nil {
		return 0
	}
	return res.StreamingMetadata.Tokens
}
