// Package reach implements echo pair outage/RTT analysis and verdict text formatting.
package reach

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// buildEchoPair computes RTT statistics, loss percentage, and outage windows for one ping pair.
func (d *ReachabilityDetector) buildEchoPair(ctx model.Context, pair *echoPairTrack, issues *[]model.Issue, events *[]model.Event) EchoPair {
	reqs := make([]*pingRequest, 0, len(pair.keys))
	for _, k := range pair.keys {
		reqs = append(reqs, d.requests[k])
	}
	slices.SortStableFunc(reqs, func(a, b *pingRequest) int { return cmpFloat(a.t, b.t) })

	var rtts []float64
	var hasLastAnswered bool
	var lastAnsweredT float64
	for _, r := range reqs {
		if r.hasRep && (!hasLastAnswered || r.t > lastAnsweredT) {
			hasLastAnswered = true
			lastAnsweredT = r.t
		}
	}
	var hasPendingCut bool
	var pendingCut float64
	if ctx.End != nil {
		hasPendingCut = true
		pendingCut = *ctx.End - pendingWindowS
	}

	outages := []OutageWindow{}
	var run []*pingRequest
	closeRun := func() {
		if len(run) == 0 {
			return
		}
		st, en := run[0], run[len(run)-1]
		outages = append(outages, OutageWindow{
			StartT: ctx.Rel(&st.t), EndT: ctx.Rel(&en.t),
			LostRequests: len(run), FirstFrame: st.n, LastFrame: en.n,
		})
		run = run[:0]
	}

	lost, pending := 0, 0
	for _, r := range reqs {
		if r.hasRep {
			rtts = append(rtts, (r.replyT-r.t)*1000.0)
			if len(run) > 0 {
				closeRun()
				last := &outages[len(outages)-1]
				rn := r.replyN
				last.NextReplyFrame = &rn
				last.RecoveredT = ctx.Rel(&r.replyT)
			}
		} else if hasPendingCut && r.t > pendingCut && (!hasLastAnswered || r.t > lastAnsweredT) {
			pending++
		} else {
			lost++
			run = append(run, r)
		}
	}
	closeRun()

	for i := range outages {
		o := &outages[i]
		if o.RecoveredT != nil && o.StartT != nil {
			dur := model.Round(*o.RecoveredT-*o.StartT, 3)
			o.DurationS = &dur
		}
	}

	sent := len(reqs)
	counted := sent - pending
	answered := len(rtts)
	lossPct := 0.0
	if counted > 0 {
		lossPct = model.Round(100.0*float64(lost)/float64(counted), 1)
	}
	label := fmt.Sprintf("%s -> %s", pair.src, pair.dst)
	if pair.tunneled {
		label += " (inside GRE)"
	}

	verdict := "ok"
	if counted > 0 && answered == 0 {
		verdict = "no_reply"
		msg := fmt.Sprintf("ping %s: %d request(s), no reply seen at this capture point (destination down, path broken, or replies take another path)", label, counted)
		*issues = append(*issues, model.MakeIssue(model.SeverityError, "ICMP_NO_REPLY", msg, pair.frames))
	} else if lost > 0 {
		verdict = "loss"
		errFrames := make([]int, 0, len(outages))
		for _, o := range outages {
			errFrames = append(errFrames, o.FirstFrame)
		}
		msg := fmt.Sprintf("ping %s: %d of %d lost (%s%%), %d outage window(s)",
			label, lost, counted, model.FormatPyFloat(lossPct), len(outages))
		*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "ICMP_LOSS", msg, errFrames))
	}

	for _, o := range outages {
		txt := fmt.Sprintf("ping %s: %d consecutive request(s) unanswered", label, o.LostRequests)
		if o.DurationS != nil {
			txt += fmt.Sprintf(", recovered after %s s", model.FormatPyFloat(*o.DurationS))
		} else {
			txt += ", not recovered by capture end"
		}
		evT := 0.0
		if ctx.Start != nil && o.StartT != nil {
			evT = *ctx.Start + *o.StartT
		}
		ff := o.FirstFrame
		*events = append(*events, model.MakeEvent(ctx, evT, "icmp", "outage", txt, &ff))
	}

	var rttStats *RTTStats
	if len(rtts) > 0 {
		minR, maxR, sumR := rtts[0], rtts[0], 0.0
		for _, r := range rtts {
			if r < minR {
				minR = r
			}
			if r > maxR {
				maxR = r
			}
			sumR += r
		}
		rttStats = &RTTStats{
			Min: model.Round(minR, 3),
			Avg: model.Round(sumR/float64(len(rtts)), 3),
			Max: model.Round(maxR, 3),
		}
	}
	if ctx.MaxItems >= 0 && len(outages) > ctx.MaxItems {
		outages = outages[:ctx.MaxItems]
	}

	return EchoPair{
		Src: pair.src, Dst: pair.dst, IPv6: pair.v6, Tunneled: pair.tunneled,
		Verdict: verdict, Sent: sent, Answered: answered, Lost: lost,
		PendingAtCaptureEnd: pending, LossPercent: lossPct, DuplicateRequestsSeen: pair.duplicates,
		RTTMs: rttStats, Outages: outages, FirstT: ctx.Rel(&pair.firstT), Frames: nonNilInts(pair.frames),
	}
}

// reachVerdict formats the single-sentence reachability summary across ping, ICMP errors, and ARP.
func reachVerdict(present bool, pairs []EchoPair, errors []ICMPErrorEntry, arp []ARPUnansweredEntry) string {
	if !present {
		return "No ICMP or ARP in this capture."
	}
	var parts []string
	if len(pairs) > 0 {
		var bad []EchoPair
		for _, p := range pairs {
			if p.Verdict != "ok" {
				bad = append(bad, p)
			}
		}
		if len(bad) > 0 {
			var bParts []string
			for _, p := range bad[:min(len(bad), 5)] {
				bParts = append(bParts, fmt.Sprintf("%s->%s %d/%d lost", p.Src, p.Dst, p.Lost, p.Sent-p.PendingAtCaptureEnd))
			}
			parts = append(parts, "ping loss: "+strings.Join(bParts, "; "))
		} else {
			parts = append(parts, fmt.Sprintf("all %d ping pair(s) answered, no loss", len(pairs)))
		}
	}
	if len(errors) > 0 {
		total := 0
		for _, e := range errors {
			total += e.Count
		}
		var eParts []string
		for _, e := range errors[:min(len(errors), 3)] {
			eParts = append(eParts, fmt.Sprintf("%s (%s) from %s", e.TypeName, e.CodeText, e.From))
		}
		parts = append(parts, fmt.Sprintf("%d ICMP error(s): %s", total, strings.Join(eParts, "; ")))
	}
	if len(arp) > 0 {
		var aParts []string
		for _, a := range arp[:min(len(arp), 5)] {
			aParts = append(aParts, a.Target)
		}
		parts = append(parts, "ARP unanswered for "+strings.Join(aParts, ", "))
	}
	if len(parts) == 0 {
		return "ARP seen, all requests answered."
	}
	return strings.Join(parts, "; ")
}

// cmpFloat returns -1, 0, or +1 ordering two float64 values.
func cmpFloat(a, b float64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// nonNilInts ensures a non-nil slice so JSON marshals empty lists as [] rather than null.
func nonNilInts(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}
