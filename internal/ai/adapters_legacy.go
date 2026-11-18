// Package ai registers legacy/auxiliary LLM output format adapters
// (elasticsearch, statistics, structured issues, codec analysis, media sessions).
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type elasticsearchAdapter struct{}

func (elasticsearchAdapter) Name() string { return "elasticsearch" }
func (elasticsearchAdapter) Matches(keys map[string]json.RawMessage) bool {
	_, q := keys["query"]
	_, agg := keys["aggregations"]
	return q && agg
}

func (elasticsearchAdapter) Build(_ context.Context, _ BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error) {
	var agg struct {
		CallIDCounts struct {
			Value struct {
				Count int `json:"count"`
			} `json:"value"`
		} `json:"call_id_counts"`
	}
	_ = json.Unmarshal(keys["aggregations"], &agg)
	count := agg.CallIDCounts.Value.Count
	var calls []CallDiagnostic
	if count > 0 {
		calls = append(calls, baseCall("elasticsearch-query-extracted", "Unknown", "Unknown", "Unknown",
			fmt.Sprintf("Query indicates %d call-related events", count),
			fmt.Sprintf("Call data detected in query format with %d events", count),
			[]string{"Analysis format suggests complex SIP data structure"}))
	}
	return DiagnosticReport{
		TotalCallsAnalyzed: count,
		Calls:              calls,
		OverallAssessment:  fmt.Sprintf("Converted from Elasticsearch query format. Detected %d call-related events.", count),
		Recommendations:    []string{"Model provided search query instead of analysis", "Try with a different model for direct analysis"},
	}, nil
}

type statisticsAdapter struct{}

func (statisticsAdapter) Name() string { return "statistics" }
func (statisticsAdapter) Matches(keys map[string]json.RawMessage) bool {
	_, ok := keys["total_numbers_of_calls"]
	return ok
}

func (statisticsAdapter) Build(_ context.Context, _ BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error) {
	var total int
	_ = json.Unmarshal(keys["total_numbers_of_calls"], &total)
	var calls []CallDiagnostic
	if total > 0 {
		calls = append(calls, baseCall("stats-based-analysis", "Statistics-Based", "Analysis", "Multiple",
			fmt.Sprintf("Statistics show %d total calls", total),
			fmt.Sprintf("Statistical analysis of %d calls", total), nil))
	}
	return DiagnosticReport{
		TotalCallsAnalyzed: total,
		Calls:              calls,
		OverallAssessment:  fmt.Sprintf("Statistical analysis shows %d calls.", total),
		Recommendations:    []string{"Consider analyzing individual call patterns"},
	}, nil
}

type structuredIssuesAdapter struct{}

func (structuredIssuesAdapter) Name() string { return "structured_issues" }
func (structuredIssuesAdapter) Matches(keys map[string]json.RawMessage) bool {
	for k := range keys {
		if strings.HasPrefix(k, "audioCodecIssue") || strings.HasPrefix(k, "callSetupMethod") {
			return true
		}
	}
	return false
}

func (structuredIssuesAdapter) Build(_ context.Context, _ BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error) {
	var issues []string
	for k, v := range keys {
		if strings.HasPrefix(k, "audioCodecIssue") {
			issues = append(issues, fmt.Sprintf("%s: %s", k, strings.Trim(string(v), `"`)))
		}
	}
	slices.Sort(issues)
	call := baseCall("structured-issues", "Unknown", "Unknown", "Unknown", "See structured issues", "Structured SIP/codec issues reported", issues)
	return DiagnosticReport{
		TotalCallsAnalyzed: 1,
		Calls:              []CallDiagnostic{call},
		OverallAssessment:  fmt.Sprintf("Detected %d structured SIP/codec findings", len(issues)),
		Recommendations:    []string{"Address audio codec and setup issues identified"},
	}, nil
}

type codecAnalysisAdapter struct{}

func (codecAnalysisAdapter) Name() string { return "codec_analysis" }
func (codecAnalysisAdapter) Matches(keys map[string]json.RawMessage) bool {
	_, ct := keys["codec_types"]
	_, ci := keys["common_issues"]
	return ct && ci
}

func (codecAnalysisAdapter) Build(_ context.Context, _ BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error) {
	var codecTypes, commonIssues, focus []string
	_ = json.Unmarshal(keys["codec_types"], &codecTypes)
	_ = json.Unmarshal(keys["common_issues"], &commonIssues)
	_ = json.Unmarshal(keys["diagnostic_focus"], &focus)
	call := baseCall("codec-analysis", "Codec", "Analysis", "Unknown", "Codec summary",
		fmt.Sprintf("Codec-based analysis detected %s with %d potential issues", strings.Join(codecTypes, ", "), len(commonIssues)), commonIssues)
	if len(codecTypes) > 0 {
		call.AudioQuality.CodecUsed = strings.Join(codecTypes, ", ")
	}
	recs := append([]string{}, focus[:min(len(focus), 5)]...)
	recs = append(recs, "Verify codec compatibility between endpoints")
	return DiagnosticReport{
		TotalCallsAnalyzed: 1,
		Calls:              []CallDiagnostic{call},
		OverallAssessment:  fmt.Sprintf("Codec analysis evaluated %s", strings.Join(codecTypes, ", ")),
		Recommendations:    recs,
	}, nil
}

type mediaSessionsAdapter struct{}

func (mediaSessionsAdapter) Name() string { return "media_sessions" }
func (mediaSessionsAdapter) Matches(keys map[string]json.RawMessage) bool {
	_, ok := keys["media_sessions"]
	return ok
}

func (mediaSessionsAdapter) Build(_ context.Context, _ BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error) {
	var mediaSessions, rtpPackets int
	var corr bool
	_ = json.Unmarshal(keys["media_sessions"], &mediaSessions)
	_ = json.Unmarshal(keys["rtp_packets_analyzed"], &rtpPackets)
	_ = json.Unmarshal(keys["sdp_to_rtp_correlation_created"], &corr)
	var issues []string
	if mediaSessions == 0 {
		issues = append(issues, "No media sessions detected in capture")
	}
	if rtpPackets == 0 {
		issues = append(issues, "No RTP packets found for analysis")
	}
	if !corr {
		issues = append(issues, "Unable to correlate SDP with RTP streams")
	}
	var calls []CallDiagnostic
	if mediaSessions > 0 || rtpPackets > 0 {
		calls = append(calls, baseCall("media-session-analysis", "Media-Session", "Analysis", "Unknown",
			fmt.Sprintf("Media sessions: %d, RTP packets: %d", mediaSessions, rtpPackets),
			fmt.Sprintf("Media session analysis detected %d sessions with %d RTP packets", mediaSessions, rtpPackets), issues))
	}
	return DiagnosticReport{
		TotalCallsAnalyzed: len(calls),
		Calls:              calls,
		OverallAssessment:  fmt.Sprintf("Media session analysis found %d sessions and %d RTP packets.", mediaSessions, rtpPackets),
		Recommendations:    []string{"Check for complete SIP call flows and RTP traffic"},
	}, nil
}
