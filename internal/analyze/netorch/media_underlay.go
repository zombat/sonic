// Package netorch correlates VoIP quality, MOS, post-200 OK media clipping,
// and DTMF findings against same-capture underlay and tunnel detector issues.
package netorch

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/model"
)

// UnderlayCorrelationOptions configures concurrent media and underlay diagnosis.
type UnderlayCorrelationOptions struct {
	Peers         []string
	DisplayFilter string
	MaxPackets    *int
	Since         *float64
	Until         *float64
}

// CrossLayerFinding connects an observed VoIP impairment to an underlay root cause.
type CrossLayerFinding struct {
	MediaSymptom string         `json:"media_symptom"`
	UnderlayArea string         `json:"underlay_area"`
	Severity     model.Severity `json:"severity"`
	Summary      string         `json:"summary"`
	IssueCodes   []string       `json:"issue_codes"`
	Frames       []int          `json:"frames"`
}

// MediaUnderlayReport combines deterministic SIP/RTP quality and underlay detector results.
type MediaUnderlayReport struct {
	Status           string                  `json:"status"`
	File             string                  `json:"file"`
	Error            string                  `json:"error,omitempty"`
	VoIP             *sip.QuickQualityReport `json:"voip,omitempty"`
	Network          *NetworkReport          `json:"network,omitempty"`
	CrossLayerLinks  []CrossLayerFinding     `json:"cross_layer_links"`
	CorrelatedCauses int                     `json:"correlated_causes"`
	Verdict          string                  `json:"verdict"`
}

// AnalyzeMediaUnderlay runs SIP quality/clipping/DTMF checks and deterministic
// network detectors concurrently, then links media symptoms to underlay faults.
func AnalyzeMediaUnderlay(ctx context.Context, filePath string, opts UnderlayCorrelationOptions) MediaUnderlayReport {
	var voipRep sip.QuickQualityReport
	var netRep NetworkReport
	incSIP := false

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		voipRep = sip.QuickQualityCheck(ctx, filePath)
	}()
	go func() {
		defer wg.Done()
		netRep = AnalyzeNetworkCapture(ctx, filePath, Options{
			Peers:         opts.Peers,
			DisplayFilter: opts.DisplayFilter,
			MaxPackets:    opts.MaxPackets,
			Since:         opts.Since,
			Until:         opts.Until,
			IncludeSIP:    &incSIP,
		})
	}()
	wg.Wait()

	if voipRep.Status != "success" && netRep.Status != "success" {
		errMsg := voipRep.Error
		if errMsg == "" {
			errMsg = netRep.Error
		}
		return MediaUnderlayReport{
			Status:          "error",
			File:            filePath,
			Error:           errMsg,
			CrossLayerLinks: []CrossLayerFinding{},
			Verdict:         "Capture could not be analyzed cleanly.",
		}
	}

	links := CorrelateMediaAndUnderlay(&voipRep, &netRep)
	return MediaUnderlayReport{
		Status:           "success",
		File:             filePath,
		VoIP:             &voipRep,
		Network:          &netRep,
		CrossLayerLinks:  links,
		CorrelatedCauses: len(links),
		Verdict:          buildMediaUnderlayVerdict(&voipRep, &netRep, links),
	}
}

// CorrelateMediaAndUnderlay matches VoIP quality impairments against deterministic underlay issues.
func CorrelateMediaAndUnderlay(voipRep *sip.QuickQualityReport, netRep *NetworkReport) []CrossLayerFinding {
	symptoms := collectMediaSymptoms(voipRep)
	if len(symptoms) == 0 || netRep == nil || netRep.Status != "success" || len(netRep.Issues) == 0 {
		return []CrossLayerFinding{}
	}

	symptomStr := strings.Join(symptoms, "; ")
	byDetector := make(map[string][]model.Issue)
	detOrder := []string{}
	for _, iss := range netRep.Issues {
		det := iss.Detector
		if det == "" {
			det = "network"
		}
		if _, seen := byDetector[det]; !seen {
			detOrder = append(detOrder, det)
		}
		byDetector[det] = append(byDetector[det], iss)
	}

	links := make([]CrossLayerFinding, 0, len(detOrder))
	for _, det := range detOrder {
		issues := byDetector[det]
		codes := make([]string, 0, len(issues))
		frames := []int{}
		maxSev := model.SeverityInfo
		for _, iss := range issues {
			if !slices.Contains(codes, iss.Code) {
				codes = append(codes, iss.Code)
			}
			for _, f := range iss.Frames {
				if !slices.Contains(frames, f) {
					frames = append(frames, f)
				}
			}
			if model.SeverityOrder(iss.Severity) < model.SeverityOrder(maxSev) {
				maxSev = iss.Severity
			}
		}
		if len(frames) > 25 {
			frames = frames[:25]
		}
		links = append(links, CrossLayerFinding{
			MediaSymptom: symptomStr,
			UnderlayArea: det,
			Severity:     maxSev,
			Summary:      fmt.Sprintf("VoIP symptom (%s) co-occurs with %s fault(s): %s", symptomStr, det, strings.Join(codes, ", ")),
			IssueCodes:   codes,
			Frames:       frames,
		})
	}
	return links
}

func collectMediaSymptoms(rep *sip.QuickQualityReport) []string {
	if rep == nil || rep.Status != "success" {
		return nil
	}
	var out []string
	if rep.MOSAnalysis != nil && rep.MOSAnalysis.AverageMOS > 0 && rep.MOSAnalysis.AverageMOS < 3.5 {
		out = append(out, fmt.Sprintf("low MOS %.2f (%s)", rep.MOSAnalysis.AverageMOS, rep.MOSAnalysis.OverallCategory))
	}
	if rep.MediaClipping != nil {
		if rep.MediaClipping.CriticalCount > 0 || rep.MediaClipping.WarningCount > 0 {
			out = append(out, fmt.Sprintf("post-200 OK clipping %.1f ms", rep.MediaClipping.MaxDelayMS))
		}
		if rep.MediaClipping.NoMediaCount > 0 {
			out = append(out, "200 OK with missing RTP stream")
		}
	}
	if rep.QualityAnalysis != nil && rep.QualityAnalysis.OverallScore < 70 {
		out = append(out, fmt.Sprintf("degraded call quality grade %s (%.1f/100)", rep.QualityAnalysis.Grade, rep.QualityAnalysis.OverallScore))
	}
	return out
}

func buildMediaUnderlayVerdict(voipRep *sip.QuickQualityReport, netRep *NetworkReport, links []CrossLayerFinding) string {
	if len(links) > 0 {
		areas := make([]string, 0, len(links))
		for _, l := range links {
			areas = append(areas, l.UnderlayArea)
		}
		return fmt.Sprintf("Correlated %d underlay area(s) (%s) with observed VoIP degradation.", len(links), strings.Join(areas, ", "))
	}
	if voipRep != nil && voipRep.Status == "success" && voipRep.QualityAnalysis != nil {
		return fmt.Sprintf("VoIP grade %s (%.1f/100); underlay status %s with no correlated faults.",
			voipRep.QualityAnalysis.Grade, voipRep.QualityAnalysis.OverallScore, netRep.OverallStatus)
	}
	return fmt.Sprintf("Underlay analysis completed (%s); no SIP signaling/media correlation triggered.", netRep.OverallStatus)
}
