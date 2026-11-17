// Package convergence timeline sorting, milestone measurement assembly, and verdict/issue construction.
package convergence

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// buildTimeline converts signals and optional caller event_time into a chronologically sorted TimelineEntry slice.
func buildTimeline(signals []convSignal, eventT, origin *float64, failedStr *string, ctx model.Context, delta func(*float64) *float64) []TimelineEntry {
	sorted := slices.Clone(signals)
	slices.SortStableFunc(sorted, func(a, b convSignal) int {
		return cmp.Compare(a.tAbs, b.tAbs)
	})
	timeline := make([]TimelineEntry, 0, len(sorted)+1)
	for _, s := range sorted {
		if origin != nil && s.tAbs < *origin-float64(shiftWindowS) {
			continue
		}
		tv := s.tAbs
		timeline = append(timeline, TimelineEntry{
			T:      ctx.Rel(&tv),
			Time:   model.ISOTime(&tv),
			DeltaS: delta(&tv),
			Phase:  s.phase,
			Signal: s.kind,
			Peer:   s.peer,
			Detail: s.detail,
			Frame:  s.frame,
		})
	}
	if eventT != nil {
		z := 0.0
		timeline = append(timeline, TimelineEntry{
			T:      ctx.Rel(eventT),
			Time:   model.ISOTime(eventT),
			DeltaS: &z,
			Phase:  "event",
			Signal: "event",
			Peer:   failedStr,
			Detail: "event time given by the caller",
			Frame:  nil,
		})
	}
	slices.SortStableFunc(timeline, func(a, b TimelineEntry) int {
		at, bt := 0.0, 0.0
		if a.T != nil {
			at = *a.T
		}
		if b.T != nil {
			bt = *b.T
		}
		if c := cmp.Compare(at, bt); c != 0 {
			return c
		}
		ao, bo := 1, 1
		if a.Phase == "event" {
			ao = 0
		}
		if b.Phase == "event" {
			bo = 0
		}
		return cmp.Compare(ao, bo)
	})
	return timeline
}

// buildMeasurements populates epoch/origin metadata and SignalBrief milestones.
func buildMeasurements(
	eventT, origin *float64,
	firstSign, detection, update, resumed *convSignal,
	ctx model.Context,
	delta func(*float64) *float64,
) Measurements {
	sigBrief := func(s *convSignal) *SignalBrief {
		if s == nil {
			return nil
		}
		tv := s.tAbs
		return &SignalBrief{
			Signal: s.kind,
			T:      ctx.Rel(&tv),
			DeltaS: delta(&tv),
			Frame:  s.frame,
			Detail: s.detail,
		}
	}
	var originName *string
	if eventT != nil {
		s := "event_time"
		originName = &s
	} else if firstSign != nil {
		s := "first_failure_sign"
		originName = &s
	}
	var firstSignT, detectionT, updateT, resumedT *float64
	if firstSign != nil {
		firstSignT = &firstSign.tAbs
	}
	if detection != nil {
		detectionT = &detection.tAbs
	}
	if update != nil {
		updateT = &update.tAbs
	}
	if resumed != nil {
		resumedT = &resumed.tAbs
	}
	return Measurements{
		Origin:                   originName,
		OriginT:                  ctx.Rel(origin),
		FirstFailureSign:         sigBrief(firstSign),
		Detection:                sigBrief(detection),
		FirstUpdateOnSurviving:   sigBrief(update),
		TrafficResumed:           sigBrief(resumed),
		EventToFirstFailureSignS: delta(firstSignT),
		EventToDetectionS:        delta(detectionT),
		EventToFirstUpdateS:      delta(updateT),
		EventToTrafficResumedS:   delta(resumedT),
	}
}

// buildVerdictAndIssues derives status, human-readable verdict text, and CONVERGENCE_NOT_SEEN issues.
func buildVerdictAndIssues(
	present bool,
	eventT, origin *float64,
	failed *string,
	firstSign, detection, resumed *convSignal,
	driver DriverInfo,
	meas Measurements,
	issues *[]model.Issue,
) (model.Status, string) {
	switch {
	case !present:
		return model.StatusNotPresent, "No ESP, IKE, BGP or ICMP in this capture: nothing to measure convergence from."
	case origin == nil:
		verdict := "No failure seen: no ESP direction went quiet, no DPD went unanswered, no BGP session dropped and no ping outage"
		if eventT != nil && *eventT != 0 {
			verdict += " after the event time"
		}
		return model.StatusOK, verdict
	default:
		peerLabel := "unknown"
		if failed != nil && *failed != "" {
			peerLabel = *failed
		}
		parts := []string{"failed peer " + peerLabel}
		if meas.EventToDetectionS != nil && detection != nil {
			parts = append(parts, fmt.Sprintf("detected after %s s (%s)", model.FormatPyFloat(*meas.EventToDetectionS), detection.kind))
		}
		if meas.EventToFirstUpdateS != nil {
			parts = append(parts, fmt.Sprintf("first UPDATE on the surviving path after %s s", model.FormatPyFloat(*meas.EventToFirstUpdateS)))
		}
		if meas.EventToTrafficResumedS != nil && resumed != nil {
			parts = append(parts, fmt.Sprintf("traffic resumed after %s s (%s)", model.FormatPyFloat(*meas.EventToTrafficResumedS), resumed.kind))
		} else {
			parts = append(parts, "traffic not seen resuming before the capture ended")
		}
		parts = append(parts, "driver: "+driver.Mechanism)
		prefix := "the first failure sign"
		if eventT != nil {
			prefix = "the event"
		}
		verdict := "Convergence from " + prefix + ": " + strings.Join(parts, "; ")
		if resumed != nil {
			return model.StatusOK, verdict
		}
		var frames []int
		if firstSign != nil && firstSign.frame != nil && *firstSign.frame != 0 {
			frames = []int{*firstSign.frame}
		}
		*issues = append(*issues, model.MakeIssue(
			model.SeverityWarning, "CONVERGENCE_NOT_SEEN",
			"traffic was not seen resuming after the failure before the capture ended",
			frames,
		))
		return model.StatusWarning, verdict
	}
}
