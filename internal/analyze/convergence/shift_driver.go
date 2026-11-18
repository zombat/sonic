// Package convergence traffic-shift ESP rate heuristic and failure driver attribution.
package convergence

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/routing"
	"github.com/zombat/sonic/internal/model"
)

// trafficShift estimates when surviving ESP tunnels take over the failed tunnel's rate.
func (d *Detector) trafficShift(failed *string, origin *float64) *TrafficShift {
	if failed == nil || *failed == "" || origin == nil {
		return nil
	}
	failedIP := *failed
	var failedPairs [][2]string
	locals := make(map[string]bool)
	for _, k := range d.espOrder {
		if k[0] == failedIP {
			failedPairs = append(failedPairs, k)
			locals[k[1]] = true
		} else if k[1] == failedIP {
			failedPairs = append(failedPairs, k)
			locals[k[0]] = true
		}
	}
	var surviving [][2]string
	for _, k := range d.espOrder {
		if k[0] != failedIP && k[1] != failedIP && (locals[k[0]] || locals[k[1]]) {
			surviving = append(surviving, k)
		}
	}
	survList := make([][]string, len(surviving))
	for i, k := range surviving {
		survList[i] = []string{k[0], k[1]}
	}
	if len(failedPairs) == 0 || len(surviving) == 0 {
		return &TrafficShift{
			TAbs:           nil,
			Detail:         "no surviving ESP tunnel from the same local router to compare",
			SurvivingPairs: survList,
		}
	}

	start := int(*origin)
	lost := d.rate(failedPairs, start-shiftWindowS, start)
	base := d.rate(surviving, start-shiftWindowS, start)
	method := fmt.Sprintf("first second after the failure in which the surviving tunnels carry their %d s baseline plus %d%% of the failed tunnel's rate, for two seconds running (heuristic on ESP packet rates)",
		shiftWindowS, int(shiftFraction*100))
	out := &TrafficShift{
		LostRatePPS:          model.Round(lost, 2),
		SurvivingBaselinePPS: model.Round(base, 2),
		SurvivingPairs:       survList,
		Method:               method,
		hasRates:             true,
	}
	if lost < 1.0 {
		out.Detail = fmt.Sprintf("the failed tunnel carried %s packets/s before the failure: too little to measure a traffic shift from rates",
			model.FormatPyFloat(model.Round(lost, 2)))
		return out
	}

	need := base + shiftFraction*lost
	last := start
	if d.hasEnd {
		last = int(d.end)
	}
	pairStrs := make([]string, len(surviving))
	for i, k := range surviving {
		pairStrs[i] = k[0] + " <-> " + k[1]
	}
	for sec := start; sec <= last; sec++ {
		r0 := d.rate(surviving, sec, sec+1)
		if r0 >= need && d.rate(surviving, sec+1, sec+2) >= need {
			tVal := float64(sec)
			out.TAbs = &tVal
			out.Detail = fmt.Sprintf("surviving tunnels %s reach %s packets/s (baseline %s, lost %s): traffic moved to the surviving path",
				strings.Join(pairStrs, ", "),
				model.FormatPyFloat(model.Round(r0, 1)),
				model.FormatPyFloat(model.Round(base, 1)),
				model.FormatPyFloat(model.Round(lost, 1)),
			)
			out.shiftFound = true
			return out
		}
	}
	out.Detail = "the surviving tunnels never picked up the failed tunnel's rate before the capture ended"
	return out
}

// determineDriver infers whether BFD, BGP hold expiry, DPD, or explicit close drove failover.
func (d *Detector) determineDriver(origin, reactionT, dpdDead *float64, holdSeen, bfd []float64, signals []convSignal, bgpSessions []routing.BGPSessionReport) DriverInfo {
	if origin == nil {
		return DriverInfo{Mechanism: "undetermined", Reason: "no failure seen"}
	}
	before := math.Inf(1)
	if reactionT != nil {
		before = *reactionT + 1.0
	}
	for _, t := range bfd {
		if t >= *origin-1.0 && t <= before {
			return DriverInfo{Mechanism: "bfd", Reason: "a BGP NOTIFICATION Cease/BFD Down preceded the reaction"}
		}
	}
	var hold []float64
	for _, t := range holdSeen {
		if t >= *origin-1.0 && t <= before {
			hold = append(hold, t)
		}
	}
	dpdOK := dpdDead != nil && *dpdDead >= *origin-1.0 && *dpdDead <= before
	if len(hold) > 0 && (!dpdOK || slices.Min(hold) <= *dpdDead) {
		minHold := slices.Min(hold)
		reason := fmt.Sprintf("the BGP hold timer expired %s s after the start", model.FormatPyFloat(model.Round(minHold-*origin, 3)))
		if dpdOK {
			reason += ", before any DPD gave up"
		}
		return DriverInfo{Mechanism: "bgp_hold_timer", Reason: reason}
	}
	if dpdOK {
		return DriverInfo{
			Mechanism: "dpd",
			Reason:    fmt.Sprintf("DPD gave up on the failed peer %s s after the start, before the routing reaction; no BGP hold expiry was seen first", model.FormatPyFloat(model.Round(*dpdDead-*origin, 3))),
		}
	}
	for _, s := range signals {
		if (s.kind == "bgp_notification" || s.kind == "bgp_down") &&
			(s.cause == "" || s.cause == "notification" || s.cause == "tcp_rst" || s.cause == "tcp_fin") &&
			s.tAbs >= *origin-1.0 {
			return DriverInfo{
				Mechanism: "explicit_close",
				Reason:    fmt.Sprintf("the session was closed explicitly (%s)", s.detail),
			}
		}
	}
	var holdTime float64
	var holdTimeStr string
	if d.holdTime != nil && *d.holdTime != 0 {
		holdTime = *d.holdTime
		holdTimeStr = model.FormatPyFloat(holdTime)
	} else {
		for _, sess := range bgpSessions {
			if sess.NegotiatedHoldTime != nil && *sess.NegotiatedHoldTime != 0 {
				holdTime = float64(*sess.NegotiatedHoldTime)
				holdTimeStr = fmt.Sprintf("%d", *sess.NegotiatedHoldTime)
				break
			}
		}
	}
	if reactionT != nil && holdTime != 0 {
		took := *reactionT - *origin
		if took >= 0.8*holdTime && took <= 1.25*holdTime {
			return DriverInfo{
				Mechanism: "bgp_hold_timer",
				Reason:    fmt.Sprintf("inferred from timing: the reaction came %s s after the start, matching the %s s hold time, and no DPD gave up first", model.FormatPyFloat(model.Round(took, 3)), holdTimeStr),
			}
		}
		return DriverInfo{
			Mechanism: "undetermined",
			Reason:    fmt.Sprintf("the reaction came %s s after the start, which matches neither DPD (none seen giving up) nor the %s s hold time", model.FormatPyFloat(model.Round(took, 3)), holdTimeStr),
		}
	}
	return DriverInfo{
		Mechanism: "undetermined",
		Reason:    "no DPD, BFD or BGP hold expiry seen; pass hold_time to infer the hold timer from timing",
	}
}
