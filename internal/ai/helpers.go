// Package ai provides capture extraction and quality/MOS bundle helpers
// shared by orchestrator, streaming, and batch execution.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/redact"
)

func extractSIPText(ctx context.Context, filePath string) (string, *extract.SIPExtractionSummary, error) {
	summary, rawText, err := extract.ExtractSIPData(ctx, filePath)
	if err != nil || (summary == nil && rawText == "") {
		return "", nil, fmt.Errorf("no SIP data")
	}
	if summary != nil && len(summary.SIPPackets) == 0 && len(summary.RTPStreams) == 0 && summary.TotalPackets == 0 {
		return "", nil, fmt.Errorf("no SIP data")
	}
	if rawText == "" && summary != nil {
		b, merr := json.Marshal(summary)
		if merr == nil {
			rawText = string(b)
		}
	}
	return rawText, summary, nil
}

func buildQualityBundle(summary *extract.SIPExtractionSummary, _ string, auth *extract.AuthInfo, wantQ, wantMOS bool) json.RawMessage {
	type qBundle struct {
		CallQuality *sip.QualityMetrics    `json:"call_quality,omitempty"`
		MOSAnalysis *sip.MOSAnalysisResult `json:"mos_analysis,omitempty"`
	}
	var b qBundle
	var packets []extract.SIPPacket
	var streams []extract.RTPStreamSummary
	if summary != nil {
		packets = summary.SIPPackets
		streams = summary.RTPStreams
	}
	if wantQ {
		q := sip.ScoreCallQuality(sip.ScoringInput{SIPPackets: packets, RTPStreams: streams, Auth: auth})
		b.CallQuality = &q
	}
	if wantMOS {
		m := sip.AnalyzeRTPStreamsFromSummary(streams)
		b.MOSAnalysis = &m
	}
	raw, _ := json.Marshal(b)
	return json.RawMessage(redact.RedactText(string(raw)))
}

func countTokens(reported int, text string) int {
	if reported > 0 {
		return reported
	}
	return len(strings.Fields(text))
}
