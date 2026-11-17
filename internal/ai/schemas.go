// Package ai defines strongly typed SIP LLM diagnostic schemas, response-envelope
// structs, and orchestration metadata matching models/schemas.py and ai/*.py.
package ai

import "encoding/json"

// ProcessingMode selects sequential or concurrent batch capture processing.
type ProcessingMode string

const (
	// ModeSequential analyzes files one at a time in directory order.
	ModeSequential ProcessingMode = "sequential"
	// ModeParallel analyzes files concurrently with a bounded worker pool.
	ModeParallel ProcessingMode = "parallel"
)

// AudioQuality describes detected voice codecs, RTP port, and potential quality issues.
type AudioQuality struct {
	CodecUsed       string   `json:"codecUsed"`
	PayloadTypes    []string `json:"payloadTypes"`
	RTPPort         string   `json:"rtpPort"`
	PotentialIssues []string `json:"potentialIssues"`
}

// CallFlow describes how a SIP call was set up, answered, and terminated.
type CallFlow struct {
	CallSetupMethod        string   `json:"callSetupMethod"`
	CallTermination        string   `json:"callTermination"`
	ResponseCodes          []string `json:"responseCodes"`
	CallDurationIndicators string   `json:"callDurationIndicators"`
	InitiatorIP            *string  `json:"initiatorIp,omitempty"`
	TerminatorIP           *string  `json:"terminatorIp,omitempty"`
	DisconnectCode         *string  `json:"disconnectCode,omitempty"`
	HangupPattern          *string  `json:"hangupPattern,omitempty"`
}

// NetworkBaseline summarizes deterministic RTP/TCP baseline health attached by enhanced adapters.
type NetworkBaseline struct {
	HealthAssessment     string   `json:"health_assessment,omitempty"`
	HealthScore          float64  `json:"health_score,omitempty"`
	VoIPImpactAssessment string   `json:"voip_impact_assessment,omitempty"`
	QoSRecommendations   []string `json:"qos_recommendations,omitempty"`
}

// CallDiagnostic represents the per-call AI diagnostic summary.
type CallDiagnostic struct {
	CallID            string           `json:"callId"`
	CallerIP          string           `json:"callerIp"`
	CalleeIP          string           `json:"calleeIp"`
	UserAgents        []string         `json:"userAgents"`
	AudioQuality      AudioQuality     `json:"audioQuality"`
	NetworkBaseline   *NetworkBaseline `json:"networkBaseline,omitempty"`
	CallFlow          CallFlow         `json:"callFlow"`
	DiagnosticSummary string           `json:"diagnosticSummary"`
}

// DiagnosticReport is the normalized report schema matching SipDiagnosticReport.
type DiagnosticReport struct {
	TotalCallsAnalyzed int              `json:"total_calls_analyzed"`
	Calls              []CallDiagnostic `json:"calls"`
	OverallAssessment  string           `json:"overall_assessment"`
	Recommendations    []string         `json:"recommendations"`
	AnalysisMethod     string           `json:"analysis_method,omitempty"`
	ModelsUsed         []string         `json:"models_used,omitempty"`
}

// flexReport decodes both snake_case and camelCase field names emitted by LLMs.
type flexReport struct {
	TotalCallsAnalyzed *int       `json:"total_calls_analyzed"`
	TotalCalls         *int       `json:"totalCalls"`
	Calls              []flexCall `json:"calls"`
	OverallAssessment  string     `json:"overall_assessment"`
	OverallAssessCamel string     `json:"overallAssessment"`
	Recommendations    []string   `json:"recommendations"`
	AnalysisMethod     string     `json:"analysis_method"`
	ModelsUsed         []string   `json:"models_used"`
}

type flexAudio struct {
	CodecUsed       string   `json:"codecUsed"`
	CodecSnake      string   `json:"codec_used"`
	PayloadTypes    []string `json:"payloadTypes"`
	PayloadsSnake   []string `json:"payload_types"`
	RTPPort         string   `json:"rtpPort"`
	RTPPortSnake    string   `json:"rtp_port"`
	PotentialIssues []string `json:"potentialIssues"`
	IssuesSnake     []string `json:"potential_issues"`
}

type flexCallFlow struct {
	MethodSnake string   `json:"call_setup_method"`
	MethodCamel string   `json:"callSetupMethod"`
	TermSnake   *string  `json:"call_termination"`
	TermCamel   *string  `json:"callTermination"`
	CodesSnake  []string `json:"response_codes"`
	CodesCamel  []string `json:"responseCodes"`
	DurSnake    string   `json:"call_duration_indicators"`
	DurCamel    string   `json:"callDurationIndicators"`
	InitSnake   *string  `json:"initiator_ip"`
	InitCamel   *string  `json:"initiatorIp"`
	TermIPSnake *string  `json:"terminator_ip"`
	TermIPCamel *string  `json:"terminatorIp"`
	DiscSnake   *string  `json:"disconnect_code"`
	DiscCamel   *string  `json:"disconnectCode"`
	HangSnake   *string  `json:"hangup_pattern"`
	HangCamel   *string  `json:"hangupPattern"`
}

type flexCall struct {
	CallIDSnake  string           `json:"call_id"`
	CallIDCamel  string           `json:"callId"`
	CallerSnake  string           `json:"caller_ip"`
	CallerCamel  string           `json:"callerIp"`
	CalleeSnake  string           `json:"callee_ip"`
	CalleeCamel  string           `json:"calleeIp"`
	UASnake      []string         `json:"user_agents"`
	UACamel      []string         `json:"userAgents"`
	AudioCamel   *flexAudio       `json:"audioQuality"`
	AudioSnake   *flexAudio       `json:"audio_quality"`
	NetBase      *NetworkBaseline `json:"networkBaseline"`
	FlowCamel    *flexCallFlow    `json:"callFlow"`
	FlowSnake    *flexCallFlow    `json:"call_flow"`
	SummaryCamel string           `json:"diagnosticSummary"`
	SummarySnake string           `json:"diagnostic_summary"`
}

// ReportOutput wraps DiagnosticReport inside the standard status/output envelope.
type ReportOutput struct {
	DiagnosticReport DiagnosticReport `json:"diagnostic_report"`
}

// StreamingMeta captures streamed token and provider timing fields.
type StreamingMeta struct {
	TotalTokens int     `json:"total_tokens"`
	Provider    string  `json:"provider"`
	ElapsedTime float64 `json:"elapsed_time,omitempty"`
}

// AnalysisResult is the structured result of SIPDiagnosticTest, RunCombinedAnalysis, and RunAnalysisMode.
type AnalysisResult struct {
	Status            string          `json:"status"`
	Error             string          `json:"error,omitempty"`
	Output            *ReportOutput   `json:"output,omitempty"`
	RawResponse       string          `json:"raw_response,omitempty"`
	SIPData           string          `json:"sip_data,omitempty"`
	AuthData          json.RawMessage `json:"auth_data,omitempty"`
	QualityAnalysis   json.RawMessage `json:"quality_analysis,omitempty"`
	StreamingMetadata *StreamingMeta  `json:"streaming_metadata,omitempty"`
}

// PartialTiming records millisecond stage timings for partial streaming analysis.
type PartialTiming struct {
	PartialResultMS int64 `json:"partial_result_ms"`
	LLMStreamingMS  int64 `json:"llm_streaming_ms"`
	TotalMS         int64 `json:"total_ms"`
}

// PartialStreamMeta summarizes provider and streamed token count for MCP partial streaming.
type PartialStreamMeta struct {
	Provider string `json:"provider"`
	Tokens   int    `json:"tokens"`
}

// PartialSnapshot is emitted to onPartialResult before LLM streaming starts.
type PartialSnapshot struct {
	Status              string          `json:"status"`
	QualityAnalysis     json.RawMessage `json:"quality_analysis"`
	MOSAnalysis         json.RawMessage `json:"mos_analysis"`
	PartialResultTimeMS int64           `json:"partial_result_time_ms"`
}

// PartialStreamingResult matches Python ai/partial_streaming.py and test_mcp_stdio.py.
type PartialStreamingResult struct {
	Status            string             `json:"status"`
	Error             string             `json:"error,omitempty"`
	QualityAnalysis   json.RawMessage    `json:"quality_analysis,omitempty"`
	MOSAnalysis       json.RawMessage    `json:"mos_analysis,omitempty"`
	LLMAnalysis       json.RawMessage    `json:"llm_analysis,omitempty"`
	Timing            *PartialTiming     `json:"timing,omitempty"`
	StreamingMetadata *PartialStreamMeta `json:"streaming_metadata,omitempty"`
}

// BatchProgress reports single-file progress transitions during AnalyzeBatch.
type BatchProgress struct {
	FilePath       string  `json:"file_path"`
	Index          int     `json:"index"`
	TotalFiles     int     `json:"total_files"`
	Status         string  `json:"status"`
	ElapsedTime    float64 `json:"elapsed_time"`
	TokensStreamed int     `json:"tokens_streamed"`
	Error          string  `json:"error,omitempty"`
}

// BatchMetadata describes batch mode, file count, provider, and profile.
type BatchMetadata struct {
	Mode       ProcessingMode `json:"mode"`
	TotalFiles int            `json:"total_files"`
	Provider   string         `json:"provider"`
	Model      string         `json:"model"`
}

// BatchQualitySummary aggregates call quality grades across batch files.
type BatchQualitySummary struct {
	AvgGrade     *string        `json:"avg_grade"`
	CallCount    int            `json:"call_count"`
	CallsByGrade map[string]int `json:"calls_by_grade"`
}

// BatchAggregate holds rollup totals for a batch execution.
type BatchAggregate struct {
	Successful     int                 `json:"successful"`
	Failed         int                 `json:"failed"`
	TotalTokens    int                 `json:"total_tokens"`
	TotalDuration  float64             `json:"total_duration"`
	QualitySummary BatchQualitySummary `json:"quality_summary"`
}

// BatchFileResult holds one capture's streaming diagnostic outcome in a batch.
type BatchFileResult struct {
	Status            string         `json:"status"`
	File              string         `json:"file"`
	Index             int            `json:"index"`
	Output            *ReportOutput  `json:"output,omitempty"`
	Error             string         `json:"error,omitempty"`
	ElapsedTime       float64        `json:"elapsed_time,omitempty"`
	StreamingMetadata *StreamingMeta `json:"streaming_metadata,omitempty"`
}

// BatchResult is the full JSON response returned by AnalyzeBatch and analyze_batch_pcaps.
type BatchResult struct {
	Status        string            `json:"status"`
	Error         string            `json:"error,omitempty"`
	BatchMetadata BatchMetadata     `json:"batch_metadata"`
	Files         []BatchFileResult `json:"files"`
	Aggregate     BatchAggregate    `json:"aggregate"`
}
