package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zombat/sonic/internal/llm"
)

type stubCompleter struct {
	mu      sync.Mutex
	calls   []string
	handler func(provider, profile, modelName string, msgs []llm.Message, onToken func(string)) (llm.Response, llm.Usage, error)
}

func (s *stubCompleter) Complete(_ context.Context, provider, profile, modelName string, messages []llm.Message, _ json.RawMessage, onToken func(string)) (llm.Response, llm.Usage, error) {
	s.mu.Lock()
	s.calls = append(s.calls, fmt.Sprintf("%s/%s/%s", provider, profile, modelName))
	s.mu.Unlock()
	return s.handler(provider, profile, modelName, messages, onToken)
}

func chdirRepoRoot(t *testing.T) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
}

func TestArtifactFactoryBuildersAndValidation(t *testing.T) {
	factory := NewArtifactFactory()
	ctx := context.Background()

	if _, err := factory.Build(ctx, BuildContext{}); err == nil {
		t.Fatal("expected error for empty kind")
	}
	if _, err := factory.Build(ctx, BuildContext{Kind: "bogus"}); err == nil {
		t.Fatal("expected error for unregistered kind")
	}

	// Custom failing builder + bad negative calls trigger validation failure.
	badFactory := NewArtifactFactoryWithBuilders(map[ArtifactKind]ArtifactBuilder{
		KindDiagnosticReport: func(context.Context, BuildContext) (Artifact, error) {
			return &DiagnosticArtifact{Report: DiagnosticReport{TotalCallsAnalyzed: -1}}, nil
		},
	}, nil)
	if _, err := badFactory.BuildDiagnostic(ctx, BuildContext{}); err == nil {
		t.Fatal("expected negative totalCalls validation failure")
	}

	// Verify all response adapters normalize into validated, redacted DiagnosticArtifacts.
	secret := "sk-ant-api03-artifactsecret123456"
	cases := []struct {
		name      string
		raw       string
		wantCalls int
		wantSub   string
	}{
		{"direct_camel", `{"totalCalls":1,"calls":[{"callId":"c1","callerIp":"10.0.0.1","calleeIp":"10.0.0.2","audioQuality":{"codecUsed":"PCMU"},"callFlow":{"callSetupMethod":"INVITE"}}],"overallAssessment":"ok ` + secret + `"}`, 1, "[REDACTED]"},
		{"single_call", `{"callId":"s1","audioQuality":{"codecUsed":"PCMA"},"callFlow":{"callSetupMethod":"INVITE"},"diagnosticSummary":"drop"}`, 1, "Partial analysis"},
		{"messages_array", `{"messages":[{"source_ip":"1.1.1.1","destination_ip":"2.2.2.2","message_type":"INVITE","status_code":486}]}`, 1, "Error response: 486"},
		{"elasticsearch", `{"query":{"terms":{"prefix":"c"}},"aggregations":{"call_id_counts":{"value":{"count":2}}}}`, 2, "Elasticsearch"},
		{"statistics", `{"total_numbers_of_calls":3,"average_number_of_requests_per_day":1}`, 3, "Statistical"},
		{"structured_issues", `{"audioCodecIssue1":"jitter","callSetupMethod":"INVITE"}`, 1, "structured"},
		{"codec_analysis", `{"codec_types":["PCMU","G729"],"common_issues":["loss"],"diagnostic_focus":["check qos"]}`, 1, "PCMU"},
		{"media_sessions", `{"media_sessions":1,"rtp_packets_analyzed":50,"sdp_to_rtp_correlation_created":false}`, 1, "Media session"},
		{"enhanced_codec", `{"enhanced_codec_analysis":{"g_711_mu_law":{"codec_name":"PCMU","common_issues":["congestion"]}}}`, 1, "PCMU"},
		{"nlp_ips", `Invite from 10.1.1.1 to 10.1.1.2 had multiple BYE timeout failure.`, 1, "Multiple BYE"},
		{"nlp_empty", `unable to inspect`, 0, "parsing error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			art, err := factory.BuildDiagnostic(ctx, BuildContext{
				RawText:      tc.raw,
				ModelName:    "test-model",
				SIPData:      `{"rtp_streams":[{"payload_type":"0"}]}`,
				KnownSecrets: []string{secret},
			})
			if err != nil {
				t.Fatalf("BuildDiagnostic(%s): %v", tc.name, err)
			}
			if art.Kind() != KindDiagnosticReport || art.Report.TotalCallsAnalyzed != tc.wantCalls {
				t.Fatalf("%s TotalCalls=%d, want %d", tc.name, art.Report.TotalCallsAnalyzed, tc.wantCalls)
			}
			jsonBytes, err := art.JSONBytes()
			if err != nil {
				t.Fatal(err)
			}
			md := art.Markdown()
			if strings.Contains(string(jsonBytes), secret) || strings.Contains(md, secret) {
				t.Fatalf("%s leaked secret in output", tc.name)
			}
			if !strings.Contains(string(jsonBytes), tc.wantSub) && !strings.Contains(md, tc.wantSub) {
				t.Fatalf("%s expected %q in json=%s md=%s", tc.name, tc.wantSub, jsonBytes, md)
			}
		})
	}
}

func TestCodecsAndRecoveryHelpers(t *testing.T) {
	if EnrichSIPDataWithCodecContext("") != "" {
		t.Fatal("expected empty string on empty sipData")
	}
	enriched := EnrichSIPDataWithCodecContext(`{"sip_messages":[]}`)
	if !strings.Contains(enriched, "CODEC ANALYSIS CONTEXT") || !strings.Contains(enriched, "G.729") {
		t.Fatalf("unexpected enriched output: %s", enriched)
	}
	for _, tc := range []struct {
		in, want string
	}{
		{`{"rtp_streams":[{"payload_type":"8"}]}`, "G.711 A-law (PCMA)"},
		{`"rtp.p_type": "18"`, "G.729"},
		{`offer pcmu codec`, "G.711 u-law (PCMU)"},
		{`offer pcma codec`, "G.711 A-law (PCMA)"},
		{`g722 wideband`, "G.722"},
		{`g729 narrow`, "G.729"},
		{``, "Unknown"},
		{`random noise`, "Unknown"},
	} {
		if got := ExtractCodecDirectly(tc.in); got != tc.want {
			t.Fatalf("ExtractCodecDirectly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	errMsg := "Adapter failed\nLM Response: {\"totalCalls\":1,\"calls\":[],\"overallAssessment\":\"ok\"}\n\nExpected to find analysis"
	rec, ok := RecoverLMResponseError(errMsg)
	if !ok || !strings.Contains(rec, "overallAssessment") {
		t.Fatalf("RecoverLMResponseError failed: ok=%v rec=%q", ok, rec)
	}
}

func TestOrchestrationCombinedModesPartialAndBatch(t *testing.T) {
	chdirRepoRoot(t)
	ctx := context.Background()
	sipFix := filepath.Join("testdata", "fixtures", "sip_minimal.pcap")
	nonSIPFix := filepath.Join("testdata", "fixtures", "icmp_loss.pcap")

	// Empty SIP input skips cleanly.
	if res := SIPDiagnosticTest(ctx, Deps{}, "ollama", "fast", "", "", ""); res.Status != "skipped" {
		t.Fatalf("expected skipped on empty input, got %+v", res)
	}

	// Stub completer drives combined, error recovery, all-models, and --model-name checks.
	stub := &stubCompleter{
		handler: func(provider, profile, modelName string, msgs []llm.Message, onToken func(string)) (llm.Response, llm.Usage, error) {
			if profile == llm.ProfileDetailed && modelName == "" {
				return llm.Response{Text: `{"totalCalls":1,"calls":[{"callId":"c1","audioQuality":{"codecUsed":"PCMU","potentialIssues":["jitter"]},"diagnosticSummary":"detailed insight"}],"overallAssessment":"Analysis extracted from natural language","recommendations":["Check DSCP"]}`}, llm.Usage{OutputTokens: 12}, nil
			}
			if onToken != nil {
				for _, tok := range []string{`{"calls":[],`, `"overallAssessment":"stub diagnosis",`, `"stub":true}`} {
					onToken(tok)
				}
			}
			return llm.Response{Text: `{"totalCalls":1,"calls":[{"callId":"c1","callerIp":"10.0.0.1","calleeIp":"10.0.0.2","audioQuality":{"codecUsed":"Unknown"},"callFlow":{"callSetupMethod":"INVITE"},"diagnosticSummary":"fast insight"}],"overallAssessment":"fast summary","recommendations":["Inspect firewall"]}`}, llm.Usage{OutputTokens: 15}, nil
		},
	}
	creds, _ := llm.NewCredentialStore("")
	deps := Deps{Completer: stub, Creds: creds}

	// RunAnalysisMode checks: combined + quality + mos, model-name with all refusal, unknown mode, missing file.
	if bad := RunAnalysisMode(ctx, deps, sipFix, "all", false, false, "ollama", "llama3:8b"); bad.Status != "error" || !strings.Contains(bad.Error, "--model-name") {
		t.Fatalf("expected --model-name + all rejection, got %+v", bad)
	}
	if bad := RunAnalysisMode(ctx, deps, sipFix, "bogus", false, false, "ollama", ""); bad.Status != "error" {
		t.Fatalf("expected unknown mode error, got %+v", bad)
	}
	if bad := RunAnalysisMode(ctx, deps, nonSIPFix, "fast", false, false, "ollama", ""); bad.Status != "error" {
		t.Fatalf("expected non-SIP capture error, got %+v", bad)
	}
	res := RunAnalysisMode(ctx, deps, sipFix, "combined", true, true, "ollama", "")
	if res.Status != "success" || res.Output == nil || len(res.QualityAnalysis) == 0 || !strings.Contains(res.Output.DiagnosticReport.Calls[0].DiagnosticSummary, "Enhanced:") {
		t.Fatalf("unexpected combined RunAnalysisMode result: %+v", res)
	}
	allRes := RunAnalysisMode(ctx, deps, sipFix, "all", false, false, "ollama", "")
	if allRes.Status != "success" {
		t.Fatalf("all mode failed: %+v", allRes)
	}

	// Recovery from Completer error wrapping "LM Response: ..."
	errRecoverStub := &stubCompleter{
		handler: func(string, string, string, []llm.Message, func(string)) (llm.Response, llm.Usage, error) {
			return llm.Response{}, llm.Usage{}, errors.New("LM Response: {\"totalCalls\":1,\"calls\":[],\"overallAssessment\":\"recovered\"}\n\nExpected to find")
		},
	}
	if recRes := SIPDiagnosticTest(ctx, Deps{Completer: errRecoverStub, Creds: creds}, "ollama", "fast", "", `{"a":1}`, ""); recRes.Status != "success" || recRes.Output.DiagnosticReport.OverallAssessment != "recovered" {
		t.Fatalf("expected error JSON recovery, got %+v", recRes)
	}
	if bothFail := CombineDiagnosticResults(AnalysisResult{Status: "error"}, AnalysisResult{Status: "error"}); bothFail.Status != "error" {
		t.Fatalf("expected error when both fail: %+v", bothFail)
	}

	// Streaming + PartialStreaming with verbatim stub report pass-through (using OpenAI SSE httptest server!).
	sseSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"{\\\"calls\\\":[],\\\"overallAssessment\\\":\\\"stub diagnosis\\\",\\\"stub\\\":true}\"}}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer sseSrv.Close()
	t.Setenv("OPENAI_BASE_URL", sseSrv.URL)
	t.Setenv("OPENAI_API_KEY", "sk-proj-streamkey1234567890abcd")

	var partialSeen bool
	var streamedBuf strings.Builder
	part := RunPartialAnalysisStreaming(ctx, Deps{}, sipFix, "openai", "", func(tok string) { streamedBuf.WriteString(tok) }, nil, func(snap PartialSnapshot) {
		partialSeen = snap.Status == "partial"
	})
	if part.Status != "success" || !partialSeen || part.StreamingMetadata == nil || part.StreamingMetadata.Tokens != 3 || !strings.Contains(string(part.LLMAnalysis), `"stub":true`) {
		t.Fatalf("unexpected RunPartialAnalysisStreaming: %+v streamed=%q", part, streamedBuf.String())
	}

	// Sequential & Parallel Batch over sip_minimal + non-SIP fixture.
	var progCount int
	var pmu sync.Mutex
	batch := AnalyzeBatch(ctx, deps, []string{sipFix, nonSIPFix}, "anthropic", "fast", ModeParallel, 2, "", func(BatchProgress) {
		pmu.Lock()
		progCount++
		pmu.Unlock()
	}, nil)
	if batch.Status != "success" || batch.Aggregate.Successful != 1 || batch.Aggregate.Failed != 1 || progCount == 0 {
		t.Fatalf("unexpected parallel AnalyzeBatch: %+v progCount=%d", batch, progCount)
	}

	// Verify sequential batch, deep/modelName modes, and factory adapter listing.
	seqBatch := AnalyzeBatch(ctx, deps, []string{sipFix}, "ollama", "fast", ModeSequential, 1, "llama3:8b", nil, nil)
	if seqBatch.Status != "success" || seqBatch.Aggregate.Successful != 1 {
		t.Fatalf("unexpected sequential batch: %+v", seqBatch)
	}
	for _, mode := range []string{"fast", "detailed", "deep", "combined"} {
		r := RunAnalysisMode(ctx, deps, sipFix, mode, false, false, "ollama", "llama3:8b")
		if r.Status != "success" {
			t.Fatalf("mode %s with modelName failed: %+v", mode, r)
		}
	}

	// Verify streaming fallback (ollama), invalid JSON error, and Completer error branches.
	var progress []string
	_, rawFallback := RunCombinedAnalysisStreaming(ctx, deps, `{"sip":true}`, sipFix, "ollama", "", nil, func(s string) {
		progress = append(progress, s)
	})
	if len(rawFallback) == 0 || len(progress) < 2 {
		t.Fatalf("expected ollama non-streaming fallback, got progress=%v", progress)
	}
	badStream := &stubCompleter{
		handler: func(string, string, string, []llm.Message, func(string)) (llm.Response, llm.Usage, error) {
			return llm.Response{Text: "not json at all"}, llm.Usage{}, nil
		},
	}
	if badRes, _ := RunCombinedAnalysisStreaming(ctx, Deps{Completer: badStream, Creds: creds}, `{"a":1}`, "", "anthropic", "", nil, nil); badRes.Status != "error" {
		t.Fatalf("expected invalid JSON streaming error, got %+v", badRes)
	}
	errStream := &stubCompleter{
		handler: func(string, string, string, []llm.Message, func(string)) (llm.Response, llm.Usage, error) {
			return llm.Response{}, llm.Usage{}, errors.New("stream dial failed")
		},
	}
	if er := RunPartialAnalysisStreaming(ctx, Deps{Completer: errStream, Creds: creds}, sipFix, "anthropic", "", nil, nil, nil); er.Status != "error" {
		t.Fatalf("expected partial streaming failure on LLM error, got %+v", er)
	}

	factory := NewArtifactFactory()
	if len(factory.AdapterNames()) < 8 {
		t.Fatalf("expected >=8 adapters, got %v", factory.AdapterNames())
	}
	// Enhanced codec with direct g_711_mu_law + real sip_minimal.pcap FilePath and BuildDiagnostic error recovery.
	artEnh, err := factory.BuildDiagnostic(ctx, BuildContext{
		RawText:  `{"g_711_mu_law":{"codec_name":"PCMU"}}`,
		SIPData:  `{"rtp_streams":[{"payload_type":"0"}]}`,
		FilePath: sipFix,
	})
	if err != nil || artEnh.Report.TotalCallsAnalyzed != 1 {
		t.Fatalf("direct enhanced codec + sipFix failed: err=%v art=%+v", err, artEnh)
	}
	artRec, err := factory.BuildDiagnostic(ctx, BuildContext{
		RawText: "Adapter failed\nLM Response: {\"totalCalls\":1,\"calls\":[],\"overallAssessment\":\"from build\"}\n\nExpected to find",
	})
	if err != nil || artRec.Report.OverallAssessment != "from build" {
		t.Fatalf("BuildDiagnostic LM Response recovery failed: err=%v art=%+v", err, artRec)
	}
}

func TestAIEdgeNormalizationAndErrorFallbacks(t *testing.T) {
	chdirRepoRoot(t)
	ctx := context.Background()
	sipFix := filepath.Join("testdata", "fixtures", "sip_minimal.pcap")
	creds, _ := llm.NewCredentialStore("")

	// 1. Validate fills missing fields on sparse DiagnosticArtifact; snake_case decoding preserves flow pointers.
	art := &DiagnosticArtifact{Report: DiagnosticReport{Calls: []CallDiagnostic{{}}}}
	if err := art.Validate(); err != nil {
		t.Fatal(err)
	}
	if art.Report.Calls[0].CallID != "call-1" || art.Report.Calls[0].AudioQuality.CodecUsed != "Unknown" {
		t.Fatalf("Validate did not populate defaults: %+v", art.Report.Calls[0])
	}
	factory := NewArtifactFactory()
	snakeArt, err := factory.BuildDiagnostic(ctx, BuildContext{
		RawText: `{"total_calls_analyzed":1,"calls":[{"call_id":"s1","caller_ip":"1.1.1.1","callee_ip":"2.2.2.2","audio_quality":{"codec_used":"PCMA","payload_types":["8"],"rtp_port":"16384"},"call_flow":{"call_setup_method":"INVITE","call_termination":"BYE","initiator_ip":"1.1.1.1","disconnect_code":"BYE"},"diagnostic_summary":"ok"}]}`,
	})
	if err != nil || snakeArt.Report.Calls[0].AudioQuality.CodecUsed != "PCMA" || snakeArt.Report.Calls[0].CallFlow.InitiatorIP == nil {
		t.Fatalf("snake_case flex decoding failed: err=%v art=%+v", err, snakeArt)
	}

	// 2. CombineDiagnosticResults falls back when fast fails, and fills missing payloadTypes/RTPPort from detailed.
	fastZero := AnalysisResult{
		Status: "success",
		Output: &ReportOutput{DiagnosticReport: DiagnosticReport{TotalCallsAnalyzed: 1, Calls: []CallDiagnostic{{CallID: "c1", AudioQuality: AudioQuality{CodecUsed: "Unknown", RTPPort: "Unknown"}}}}},
	}
	detRich := AnalysisResult{
		Status: "success",
		Output: &ReportOutput{DiagnosticReport: DiagnosticReport{TotalCallsAnalyzed: 1, Calls: []CallDiagnostic{{CallID: "c1", AudioQuality: AudioQuality{CodecUsed: "G.729", PayloadTypes: []string{"18"}, RTPPort: "20000"}, DiagnosticSummary: "lost packets"}}}},
	}
	merged := CombineDiagnosticResults(fastZero, detRich)
	if merged.Output.DiagnosticReport.Calls[0].AudioQuality.CodecUsed != "G.729" || merged.Output.DiagnosticReport.Calls[0].AudioQuality.RTPPort != "20000" {
		t.Fatalf("mergeCallDiagnostic failed: %+v", merged.Output.DiagnosticReport.Calls[0])
	}
	fallbackOnly := CombineDiagnosticResults(AnalysisResult{Status: "error"}, detRich)
	if fallbackOnly.Status != "success" || len(fallbackOnly.Output.DiagnosticReport.Calls) != 1 {
		t.Fatalf("CombineDiagnosticResults fallback failed: %+v", fallbackOnly)
	}

	// 3. Failing LLM returns error in --model all and increments failed counter in batch.
	failStub := &stubCompleter{
		handler: func(string, string, string, []llm.Message, func(string)) (llm.Response, llm.Usage, error) {
			return llm.Response{}, llm.Usage{}, errors.New("provider down")
		},
	}
	depsFail := Deps{Completer: failStub, Creds: creds}
	if res := RunAnalysisMode(ctx, depsFail, sipFix, "all", false, false, "ollama", ""); res.Status != "error" {
		t.Fatalf("expected error from all failed models, got %+v", res)
	}
	batchFail := AnalyzeBatch(ctx, depsFail, []string{sipFix}, "anthropic", "fast", ModeSequential, 1, "", nil, nil)
	if batchFail.Aggregate.Failed != 1 {
		t.Fatalf("expected 1 failed batch file, got %+v", batchFail.Aggregate)
	}
	if partMissing := RunPartialAnalysisStreaming(ctx, depsFail, "/no/such/sip.pcap", "ollama", "", nil, nil, nil); partMissing.Status != "error" {
		t.Fatalf("expected error on missing capture, got %+v", partMissing)
	}

	// 4. RunStreamingMode extracts SIP capture and runs streaming diagnosis.
	okStub := &stubCompleter{
		handler: func(provider, _, modelName string, _ []llm.Message, onToken func(string)) (llm.Response, llm.Usage, error) {
			txt := `{"totalCalls":1,"calls":[{"callId":"c-stream","callerIp":"10.0.0.1","calleeIp":"10.0.0.2","diagnosticSummary":"ok"}],"overallAssessment":"Good","recommendations":[]}`
			if onToken != nil {
				onToken(txt)
			}
			return llm.Response{Text: txt, OutputTokens: 8, Reported: true, Model: modelName}, llm.Usage{Provider: provider, OutputTokens: 8}, nil
		},
	}
	streamRes := RunStreamingMode(ctx, Deps{Completer: okStub, Creds: creds}, sipFix, "openai", "", nil, nil)
	if streamRes.Status != "success" || streamRes.Output == nil || streamRes.Output.DiagnosticReport.Calls[0].CallID != "c-stream" {
		t.Fatalf("RunStreamingMode failed: %+v", streamRes)
	}
	if streamMissing := RunStreamingMode(ctx, Deps{Completer: okStub, Creds: creds}, "/no/such/sip.pcap", "openai", "", nil, nil); streamMissing.Status != "error" {
		t.Fatalf("expected error from RunStreamingMode on missing file: %+v", streamMissing)
	}

	// 5. CollectBatchPcaps discovers direct *.pcap* files, skipping subdirs and rejecting empty/missing dirs.
	if _, err := CollectBatchPcaps(""); err == nil {
		t.Fatal("expected error for empty dir")
	}
	if _, err := CollectBatchPcaps(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing dir")
	}
	batchDir := t.TempDir()
	if _, err := CollectBatchPcaps(batchDir); err == nil {
		t.Fatal("expected error for dir with zero pcaps")
	}
	subDir := filepath.Join(batchDir, "nested.pcap")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"b.pcapng", "a.pcap", "readme.txt"} {
		if err := os.WriteFile(filepath.Join(batchDir, fn), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	found, err := CollectBatchPcaps(batchDir)
	if err != nil || len(found) != 2 || filepath.Base(found[0]) != "a.pcap" || filepath.Base(found[1]) != "b.pcapng" {
		t.Fatalf("unexpected CollectBatchPcaps result: found=%v err=%v", found, err)
	}
}
