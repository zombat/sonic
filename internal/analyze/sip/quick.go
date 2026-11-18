// Package sip implements the top-level quick_quality_check and network_orchestrator
// SIP summary entrypoints matching mcp_server.py and analyzers/network_orchestrator.py.
package sip

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zombat/sonic/internal/extract"
)

const netorchSIPNote = "SIP/RTP quality from the existing S.O.N.I.C. SIP path; use analyze_pcap for the full LLM-assisted SIP call analysis"

// QuickQualityCheck runs SIP extraction, auth diagnostics, call quality scoring, and MOS analysis.
func QuickQualityCheck(ctx context.Context, filePath string) QuickQualityReport {
	if filePath == "" {
		return QuickQualityReport{Status: "error", Error: fmt.Sprintf("File not found: %s", filePath)}
	}
	if _, err := os.Stat(filePath); err != nil {
		return QuickQualityReport{Status: "error", Error: fmt.Sprintf("File not found: %s", filePath)}
	}

	summary, rawText, err := extract.ExtractSIPData(ctx, filePath)
	if err != nil || (summary == nil && rawText == "") {
		return QuickQualityReport{Status: "error", Error: "No SIP data found in capture"}
	}

	auth := extract.ExtractAuthAndRegistrationInfo(ctx, filePath)
	var qMetrics QualityMetrics
	var mMetrics MOSAnalysisResult
	var clipPtr *MediaClippingSummary
	var dtmfPtr *DTMFEventsSummary

	if summary != nil {
		qMetrics = ScoreCallQuality(ScoringInput{
			SIPPackets: summary.SIPPackets,
			RTPStreams: summary.RTPStreams,
			Auth:       &auth,
		})
		mMetrics = AnalyzeRTPStreamsFromSummary(summary.RTPStreams)
		clipPtr, dtmfPtr = optionalVoIPExtras(summary)
	} else {
		if parsed, ok := tryParseSummaryJSON(rawText); ok {
			qMetrics = ScoreCallQuality(ScoringInput{
				SIPPackets: parsed.SIPPackets,
				RTPStreams: parsed.RTPStreams,
				Auth:       &auth,
			})
			mMetrics = AnalyzeRTPStreamsFromSummary(parsed.RTPStreams)
			clipPtr, dtmfPtr = optionalVoIPExtras(parsed)
		} else {
			qMetrics = ScoreCallQuality(ScoringInput{Auth: &auth})
			mMetrics = AnalyzeRTPStreams(nil)
		}
	}

	return QuickQualityReport{
		Status:          "success",
		File:            filePath,
		QualityAnalysis: &qMetrics,
		MOSAnalysis:     &mMetrics,
		MediaClipping:   clipPtr,
		DTMFEvents:      dtmfPtr,
	}
}

func optionalVoIPExtras(sum *extract.SIPExtractionSummary) (*MediaClippingSummary, *DTMFEventsSummary) {
	if sum == nil {
		return nil, nil
	}
	var clipPtr *MediaClippingSummary
	if len(sum.RTPStreams) > 0 {
		c := AnalyzeMediaClipping(sum.SIPPackets, sum.RTPStreams)
		if c.AnalyzedCalls > 0 {
			clipPtr = &c
		}
	}
	var dtmfPtr *DTMFEventsSummary
	d := AnalyzeDTMFEvents(sum.SIPPackets, sum.RTPEvents)
	if d.TotalPackets > 0 || len(d.NegotiatedPTs) > 0 {
		dtmfPtr = &d
	}
	return clipPtr, dtmfPtr
}

// EvaluateNetorchSIP populates the "sip" block of network_orchestrator reports.
func EvaluateNetorchSIP(ctx context.Context, filePath string, sipSeen, includeSIP bool) NetorchSIPSummary {
	if !sipSeen || !includeSIP {
		note := "no SIP in this capture"
		if sipSeen {
			note = "SIP present; set include_sip to run the SIP quality path"
		}
		return NetorchSIPSummary{Present: sipSeen, Note: note}
	}

	summary, rawText, err := extract.ExtractSIPData(ctx, filePath)
	if err != nil || (summary == nil && rawText == "") {
		return NetorchSIPSummary{
			Present: true,
			Error:   "SIP frames were detected but the SIP extractor returned no data",
		}
	}

	auth := extract.ExtractAuthAndRegistrationInfo(ctx, filePath)
	var qMetrics QualityMetrics
	var mMetrics MOSAnalysisResult
	var clipPtr *MediaClippingSummary
	var dtmfPtr *DTMFEventsSummary
	if summary != nil {
		qMetrics = ScoreCallQuality(ScoringInput{
			SIPPackets: summary.SIPPackets,
			RTPStreams: summary.RTPStreams,
			Auth:       &auth,
		})
		mMetrics = AnalyzeRTPStreamsFromSummary(summary.RTPStreams)
		clipPtr, dtmfPtr = optionalVoIPExtras(summary)
	} else {
		qMetrics = ScoreCallQualityFromJSON(rawText, nil, nil, &auth)
		mMetrics = AnalyzeRTPStreamsFromJSON(rawText)
	}

	return NetorchSIPSummary{
		Present:         true,
		QualityAnalysis: &qMetrics,
		MOSAnalysis:     &mMetrics,
		MediaClipping:   clipPtr,
		DTMFEvents:      dtmfPtr,
		Note:            netorchSIPNote,
	}
}

func tryParseSummaryJSON(raw string) (*extract.SIPExtractionSummary, bool) {
	var sum extract.SIPExtractionSummary
	if err := json.Unmarshal([]byte(raw), &sum); err != nil {
		return nil, false
	}
	return &sum, true
}
