// Package convergence final Report construction and milestone selection.
package convergence

import (
	"cmp"
	"slices"

	"github.com/zombat/sonic/internal/analyze/routing"
	"github.com/zombat/sonic/internal/model"
)

// Report correlates sub-detector outputs into the final convergence timeline and measurements.
func (d *Detector) Report(ctx model.Context) (Report, error) {
	issues := []model.Issue{}
	events := []model.Event{}

	wide := model.Context{Start: ctx.Start, End: ctx.End, MaxItems: 1000000}
	ipsecRep := d.ipsec.Report(wide)
	routingRep := d.routing.Report(wide)
	reachRep := d.reach.Report(wide)

	eventT, err := ParseEventTime(d.eventTimeRaw, ctx.Start)
	if err != nil {
		return Report{}, err
	}

	liveness := make(map[[2]string]float64)
	for _, sa := range ipsecRep.IKESAs {
		if sa.Negotiation == nil || sa.Initiator == nil || sa.Responder == nil {
			continue
		}
		maxVal := 0.0
		hasVal := false
		for _, v := range sa.Negotiation.Liveness.IntervalSBySender {
			if v != nil && *v != 0 && (!hasVal || *v > maxVal) {
				maxVal = *v
				hasVal = true
			}
		}
		if hasVal {
			key := model.PairKey(*sa.Initiator, *sa.Responder)
			if maxVal > liveness[key] {
				liveness[key] = maxVal
			}
		}
	}

	stops := d.stops(liveness)
	for i := range stops {
		stops[i].oneSided = d.oneSided(stops[i])
	}
	if eventT == nil {
		var filtered []espStop
		for _, s := range stops {
			if s.oneSided {
				filtered = append(filtered, s)
			}
		}
		stops = filtered
	}

	var bgpSessions []routing.BGPSessionReport
	if routingRep.BGP.Present {
		bgpSessions = routingRep.BGP.Sessions
	}

	startVal := 0.0
	if ctx.Start != nil {
		startVal = *ctx.Start
	}

	failed, failedSource := inferFailedPeer(d.failedPeer, stops, bgpSessions, eventT, startVal)
	signals, dpdDead, holdSeen, bfd := d.collectSignals(stops, ipsecRep, bgpSessions, reachRep, failed, startVal)

	var failSignals []convSignal
	for _, s := range signals {
		if s.phase != "failure" {
			continue
		}
		if eventT != nil && s.tAbs < *eventT-1.0 {
			continue
		}
		if failed != nil && s.peer != nil && *s.peer != *failed {
			continue
		}
		failSignals = append(failSignals, s)
	}
	slices.SortStableFunc(failSignals, func(a, b convSignal) int {
		return cmp.Compare(a.tAbs, b.tAbs)
	})

	var firstSign *convSignal
	if len(failSignals) > 0 {
		s := failSignals[0]
		firstSign = &s
	}

	var origin *float64
	if eventT != nil {
		origin = eventT
	} else if firstSign != nil {
		v := firstSign.tAbs
		origin = &v
	}

	shift := d.trafficShift(failed, origin)
	if shift != nil && shift.TAbs != nil && *shift.TAbs != 0 {
		signals = append(signals, convSignal{
			kind:   "traffic_shift",
			tAbs:   *shift.TAbs,
			frame:  shift.Frame,
			detail: shift.Detail,
			phase:  "recovery",
			peer:   nil,
		})
	}

	firstAfter := func(aboutFailed bool, kinds ...string) *convSignal {
		if origin == nil {
			return nil
		}
		kindSet := make(map[string]bool, len(kinds))
		for _, k := range kinds {
			kindSet[k] = true
		}
		var best *convSignal
		for i := range signals {
			s := &signals[i]
			if !kindSet[s.kind] || s.tAbs < *origin {
				continue
			}
			if aboutFailed && failed != nil && s.peer != nil && *s.peer != *failed {
				continue
			}
			if best == nil || s.tAbs < best.tAbs {
				best = s
			}
		}
		return best
	}

	detection := firstAfter(true, "dpd_gave_up", "bgp_hold_expired", "bfd_down", "bgp_down")
	update := firstAfter(false, "bgp_update")
	resumed := firstAfter(true, "icmp_recovered", "traffic_shift", "esp_resumed")

	var reactionT *float64
	for _, s := range []*convSignal{update, resumed} {
		if s != nil && (reactionT == nil || s.tAbs < *reactionT) {
			v := s.tAbs
			reactionT = &v
		}
	}

	driver := d.determineDriver(origin, reactionT, dpdDead, holdSeen, bfd, signals, bgpSessions)

	delta := func(t *float64) *float64 {
		if t == nil || origin == nil {
			return nil
		}
		v := model.Round(*t-*origin, 3)
		return &v
	}

	timeline := buildTimeline(signals, eventT, origin, failed, ctx, delta)
	meas := buildMeasurements(eventT, origin, firstSign, detection, update, resumed, ctx, delta)
	status, verdict := buildVerdictAndIssues(d.Present(), eventT, origin, failed, firstSign, detection, resumed, driver, meas, &issues)

	for _, entry := range timeline {
		if entry.Phase != "event" && entry.T != nil {
			events = append(events, model.MakeEvent(ctx, startVal+*entry.T, "convergence", entry.Signal, entry.Detail, entry.Frame))
		}
	}

	listedTimeline, omitted := model.Cap(timeline, ctx.MaxItems*4)
	return Report{
		Detector:         d.Name(),
		Status:           status,
		Verdict:          verdict,
		EventTime:        model.ISOTime(eventT),
		EventT:           ctx.Rel(eventT),
		FailedPeer:       failed,
		FailedPeerSource: failedSource,
		Driver:           driver,
		Measurements:     meas,
		TrafficShift:     shift,
		Timeline:         listedTimeline,
		TimelineOmitted:  omitted,
		CannotShow:       CannotShow,
		Issues:           issues,
		Events:           events,
	}, nil
}
