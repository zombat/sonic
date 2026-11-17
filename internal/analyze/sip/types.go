// Package sip implements Phase 5 SIP call quality scoring, ITU-T G.107 RTP MOS
// analysis, call tracking, overlap dialing detection, and endpoint profiling.
package sip

import "github.com/zombat/sonic/internal/extract"

// QualityGrade classifies overall VoIP call quality from A+ to F.
type QualityGrade string

const (
	// GradeExcellent represents overall scores from 90 to 100.
	GradeExcellent QualityGrade = "A+"
	// GradeVeryGood represents overall scores from 80 to 89.9.
	GradeVeryGood QualityGrade = "A"
	// GradeGood represents overall scores from 70 to 79.9.
	GradeGood QualityGrade = "B"
	// GradeFair represents overall scores from 60 to 69.9.
	GradeFair QualityGrade = "C"
	// GradePoor represents overall scores from 40 to 59.9.
	GradePoor QualityGrade = "D"
	// GradeFailed represents overall scores below 40.
	GradeFailed QualityGrade = "F"
)

// QualityMetrics holds component scores, details, factors, and grade matching CallQualityScorer.
type QualityMetrics struct {
	NetworkScore       float64            `json:"network_score"`
	ProtocolScore      float64            `json:"protocol_score"`
	CodecScore         float64            `json:"codec_score"`
	CompletionScore    float64            `json:"completion_score"`
	OverallScore       float64            `json:"overall_score"`
	Grade              QualityGrade       `json:"grade"`
	NetworkDetails     map[string]float64 `json:"network_details"`
	ProtocolDetails    map[string]float64 `json:"protocol_details"`
	CodecDetails       map[string]float64 `json:"codec_details"`
	CompletionDetails  map[string]float64 `json:"completion_details"`
	QualityFactors     []string           `json:"quality_factors"`
	DegradationFactors []string           `json:"degradation_factors"`
}

// MOSCategory classifies Mean Opinion Score quality tiers per ITU-T P.800.
type MOSCategory string

const (
	// MOSExcellent corresponds to MOS >= 4.5.
	MOSExcellent MOSCategory = "Excellent"
	// MOSGood corresponds to MOS >= 3.5.
	MOSGood MOSCategory = "Good"
	// MOSFair corresponds to MOS >= 2.5.
	MOSFair MOSCategory = "Fair"
	// MOSPoor corresponds to MOS >= 1.5.
	MOSPoor MOSCategory = "Poor"
	// MOSBad corresponds to MOS < 1.5.
	MOSBad MOSCategory = "Bad"
)

// RTPStreamMetrics holds per-stream impairment counters and E-Model MOS estimates.
type RTPStreamMetrics struct {
	SSRC              string      `json:"ssrc"`
	PacketsSent       int         `json:"packets_sent"`
	PacketsReceived   int         `json:"packets_received"`
	PacketsLost       int         `json:"packets_lost"`
	PacketLossRate    float64     `json:"packet_loss_rate"`
	AvgJitter         float64     `json:"avg_jitter"`
	MaxJitter         float64     `json:"max_jitter"`
	MinJitter         float64     `json:"min_jitter"`
	JitterVariance    float64     `json:"jitter_variance"`
	AvgLatency        float64     `json:"avg_latency"`
	DuplicatePackets  int         `json:"duplicate_packets"`
	OutOfOrderPackets int         `json:"out_of_order_packets"`
	Codec             string      `json:"codec"`
	PayloadType       string      `json:"payload_type"`
	PacketLossMOS     float64     `json:"packet_loss_mos"`
	JitterMOS         float64     `json:"jitter_mos"`
	LatencyMOS        float64     `json:"latency_mos"`
	CodecMOS          float64     `json:"codec_mos"`
	OverallMOS        float64     `json:"overall_mos"`
	MOSCategory       MOSCategory `json:"mos_category"`
}

// MOSAnalysisResult summarizes stream-level and aggregate ITU-T G.107 MOS metrics.
type MOSAnalysisResult struct {
	Streams            []RTPStreamMetrics `json:"streams"`
	AverageMOS         float64            `json:"average_mos"`
	WorstMOS           float64            `json:"worst_mos"`
	BestMOS            float64            `json:"best_mos"`
	OverallCategory    MOSCategory        `json:"overall_category"`
	PacketLossImpact   float64            `json:"packet_loss_impact"`
	JitterImpact       float64            `json:"jitter_impact"`
	LatencyImpact      float64            `json:"latency_impact"`
	CodecImpact        float64            `json:"codec_impact"`
	QualityFactors     []string           `json:"quality_factors"`
	DegradationFactors []string           `json:"degradation_factors"`
	Recommendations    []string           `json:"recommendations"`
}

// NetworkQualityInput provides optional network-level baseline context for CallQualityScorer.
type NetworkQualityInput struct {
	RealIssuesDetected []string `json:"real_issues_detected,omitempty"`
	HasRealIssues      bool     `json:"has_real_issues,omitempty"`
	TCPHealthScore     *float64 `json:"tcp_health_score,omitempty"`
}

// SDPMediaSpec describes one media line used by codec quality scoring.
type SDPMediaSpec struct {
	MediaType    string   `json:"media_type"`
	PayloadTypes []string `json:"payload_types"`
}

// SDPSessionSpec wraps media descriptions associated with a SIP session.
type SDPSessionSpec struct {
	Media []SDPMediaSpec `json:"media"`
}

// ScoringInput supplies parsed SIP/RTP/SDP/Auth inputs to ScoreCallQuality.
type ScoringInput struct {
	SIPPackets   []extract.SIPPacket        `json:"sip_packets"`
	RTPStreams   []extract.RTPStreamSummary `json:"rtp_streams"`
	SDPSessions  []SDPSessionSpec           `json:"sdp_sessions,omitempty"`
	CallSessions []CallSessionSummary       `json:"call_sessions,omitempty"`
	Network      *NetworkQualityInput       `json:"network_analysis,omitempty"`
	Auth         *extract.AuthInfo          `json:"auth_data,omitempty"`
}

// QuickQualityReport matches the JSON shape returned by mcp_server.quick_quality_check.
type QuickQualityReport struct {
	Status          string             `json:"status"`
	File            string             `json:"file,omitempty"`
	Error           string             `json:"error,omitempty"`
	QualityAnalysis *QualityMetrics    `json:"quality_analysis,omitempty"`
	QualityError    string             `json:"quality_error,omitempty"`
	MOSAnalysis     *MOSAnalysisResult `json:"mos_analysis,omitempty"`
	MOSError        string             `json:"mos_error,omitempty"`
}

// NetorchSIPSummary matches the "sip" block of network_orchestrator reports.
type NetorchSIPSummary struct {
	Present         bool               `json:"present"`
	QualityAnalysis *QualityMetrics    `json:"quality_analysis,omitempty"`
	QualityError    string             `json:"quality_error,omitempty"`
	MOSAnalysis     *MOSAnalysisResult `json:"mos_analysis,omitempty"`
	MOSError        string             `json:"mos_error,omitempty"`
	Error           string             `json:"error,omitempty"`
	Note            string             `json:"note,omitempty"`
}
