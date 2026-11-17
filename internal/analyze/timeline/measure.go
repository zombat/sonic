// Package timeline implements selector matching, explicit measurements, and
// automatic ping-outage / routing-convergence measurements over merged events.
package timeline

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/reach"
	"github.com/zombat/sonic/internal/model"
)

// parseEpoch parses an RFC3339 UTC timestamp emitted by model.ISOTime into Unix seconds.
func parseEpoch(iso *string) (float64, bool) {
	if iso == nil || *iso == "" {
		return 0, false
	}
	ts, err := time.Parse(time.RFC3339Nano, *iso)
	if err != nil {
		return 0, false
	}
	return float64(ts.UnixNano()) / 1e9, true
}

// matchesSelector reports whether ev satisfies all non-empty constraints in sel.
func matchesSelector(ev TimelineEvent, sel Selector) bool {
	if sel.Capture != nil && ev.Capture != *sel.Capture {
		return false
	}
	if sel.Detector != nil && ev.Detector != *sel.Detector {
		return false
	}
	if sel.Protocol != nil && ev.Protocol != *sel.Protocol {
		return false
	}
	if sel.Event != nil && ev.Event != *sel.Event {
		return false
	}
	if sel.Contains != nil && *sel.Contains != "" {
		if !strings.Contains(strings.ToLower(ev.Detail), strings.ToLower(*sel.Contains)) {
			return false
		}
	}
	return true
}

// pickEvent selects the first, last, or 1-based indexed match at or after the given epoch.
func pickEvent(events []TimelineEvent, sel Selector, after *float64) *TimelineEvent {
	var hits []TimelineEvent
	for _, ev := range events {
		if after != nil && ev.epoch < *after {
			continue
		}
		if matchesSelector(ev, sel) {
			hits = append(hits, ev)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	occ := strings.TrimSpace(sel.Occurrence)
	switch occ {
	case "", "first":
		ev := hits[0]
		return &ev
	case "last":
		ev := hits[len(hits)-1]
		return &ev
	default:
		idx, err := strconv.Atoi(occ)
		if err != nil {
			return nil
		}
		pos := idx - 1
		if pos < 0 || pos >= len(hits) {
			return nil
		}
		ev := hits[pos]
		return &ev
	}
}

// evaluateMeasurement computes the delta and threshold verdict for one MeasurementSpec.
func evaluateMeasurement(events []TimelineEvent, spec MeasurementSpec) MeasurementResult {
	name := spec.Name
	if name == "" {
		name = "measurement"
	}
	var start *TimelineEvent
	if spec.From != nil {
		start = pickEvent(events, *spec.From, nil)
	}
	var end *TimelineEvent
	if start != nil && spec.To != nil {
		after := start.epoch
		end = pickEvent(events, *spec.To, &after)
	}
	out := MeasurementResult{
		Name: name,
		From: start,
		To:   end,
		MaxS: spec.MaxS,
		MinS: spec.MinS,
	}
	if start == nil || end == nil {
		out.Verdict = "not_found"
		tail := "no event matching 'to' after the 'from' event"
		if start == nil {
			tail = "no event matches 'from'"
		}
		out.Detail = fmt.Sprintf("%s: %s", name, tail)
		return out
	}

	delta := model.Round(end.epoch-start.epoch, 3)
	out.DeltaS = &delta
	switch {
	case spec.MaxS != nil && delta > *spec.MaxS:
		out.Verdict = "exceeded"
	case spec.MinS != nil && delta < *spec.MinS:
		out.Verdict = "below_min"
	default:
		out.Verdict = "within"
	}
	bound := ""
	if spec.MaxS != nil {
		bound = fmt.Sprintf(" (threshold %s s)", strconv.FormatFloat(*spec.MaxS, 'f', -1, 64))
	}
	out.Detail = fmt.Sprintf(
		"%s: %s s from %s %s at t=%s to %s %s at t=%s%s: %s",
		name,
		formatPyFloat(delta),
		start.Capture,
		start.Event,
		formatPyFloat(start.T),
		end.Capture,
		end.Event,
		formatPyFloat(end.T),
		bound,
		out.Verdict,
	)
	return out
}

// buildAutoMeasurements generates ping_outage and routing_convergence rows when no explicit measurements are given.
func buildAutoMeasurements(
	events []TimelineEvent,
	reports []netorch.NetworkReport,
	labels []string,
	failoverMaxS *float64,
) []AutoMeasurement {
	out := []AutoMeasurement{}
	type reachSection struct {
		Echo []reach.EchoPair `json:"echo"`
	}
	for i, label := range labels {
		if len(reports[i].Reachability) == 0 || string(reports[i].Reachability) == "null" {
			continue
		}
		var r reachSection
		if err := json.Unmarshal(reports[i].Reachability, &r); err != nil {
			continue
		}
		for _, pair := range r.Echo {
			for _, outage := range pair.Outages {
				verdict := "measured"
				if outage.DurationS == nil {
					verdict = "not_recovered"
				} else if failoverMaxS != nil {
					if *outage.DurationS > *failoverMaxS {
						verdict = "exceeded"
					} else {
						verdict = "within"
					}
				}
				out = append(out, AutoMeasurement{
					Kind:            "ping_outage",
					Name:            fmt.Sprintf("ping outage %s -> %s at %s", pair.Src, pair.Dst, label),
					Capture:         label,
					StartTInCapture: outage.StartT,
					DeltaS:          outage.DurationS,
					LostRequests:    outage.LostRequests,
					MaxS:            failoverMaxS,
					Verdict:         verdict,
				})
			}
		}
	}

	var routing []TimelineEvent
	for _, ev := range events {
		if ev.Detector == "routing" {
			routing = append(routing, ev)
		}
	}
	for i := range routing {
		down := routing[i]
		if !DownEvents[down.Event] {
			continue
		}
		var up *TimelineEvent
		for j := i + 1; j < len(routing); j++ {
			if UpEvents[routing[j].Event] && routing[j].Protocol == down.Protocol {
				cand := routing[j]
				up = &cand
				break
			}
		}
		var deltaPtr *float64
		verdict := "not_recovered"
		if up != nil {
			delta := model.Round(up.epoch-down.epoch, 3)
			deltaPtr = &delta
			if failoverMaxS != nil {
				if delta > *failoverMaxS {
					verdict = "exceeded"
				} else {
					verdict = "within"
				}
			} else {
				verdict = "measured"
			}
		}
		downCopy := down
		out = append(out, AutoMeasurement{
			Kind:    "routing_convergence",
			Name:    fmt.Sprintf("%s %s at %s to next %s up", down.Protocol, down.Event, down.Capture, down.Protocol),
			From:    &downCopy,
			To:      up,
			MaxS:    failoverMaxS,
			DeltaS:  deltaPtr,
			Verdict: verdict,
		})
	}
	return out
}

// formatPyFloat formats v with at least one fractional digit to match Python float stringification.
func formatPyFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.ContainsRune(s, '.') && !strings.ContainsRune(s, 'e') && !strings.ContainsRune(s, 'E') {
		return s + ".0"
	}
	return s
}
