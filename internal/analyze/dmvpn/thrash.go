// Package dmvpn hub-relayed traffic checks and NHRP resolution thrashing analysis.
package dmvpn

import (
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// relayedWithoutRedirect finds spoke-to-spoke traffic relayed by a hub that never sent a redirect.
func (d *Detector) relayedWithoutRedirect(hubs []string, ctx model.Context, issues *[]model.Issue) []RelayedEntry {
	hubSet := make(map[string]bool, len(hubs))
	for _, h := range hubs {
		hubSet[h] = true
	}
	redirected := make(map[redirectKey]bool, len(d.indications))
	for _, ind := range d.indications {
		rk := redirectKey{spoke: ind.spoke}
		if ind.origSrc != nil {
			rk.hasSrc, rk.origSrc = true, *ind.origSrc
		}
		if ind.origDst != nil {
			rk.hasDst, rk.origDst = true, *ind.origDst
		}
		redirected[rk] = true
	}

	out := []RelayedEntry{}
	for _, ik := range d.dataOrder {
		flowData := d.data[ik]
		for _, okKey := range flowData.order {
			entry := flowData.outers[okKey]
			if !hubSet[okKey.dst] || hubSet[okKey.src] {
				continue
			}
			var onwardDst string
			hasOnward := false
			for _, cand := range flowData.order {
				if cand.src == okKey.dst && !hubSet[cand.dst] && cand.dst != okKey.src {
					onwardDst = cand.dst
					hasOnward = true
					break
				}
			}
			if !hasOnward {
				continue
			}
			if redirected[redirectKey{spoke: okKey.src, hasSrc: true, origSrc: ik.src, hasDst: true, origDst: ik.dst}] {
				continue
			}
			out = append(out, RelayedEntry{
				Spoke:         okKey.src,
				Hub:           okKey.dst,
				ToSpoke:       onwardDst,
				InnerSrc:      ik.src,
				InnerDst:      ik.dst,
				PacketsViaHub: entry.count,
				FirstT:        ctx.Rel(&entry.firstT),
				Frame:         entry.firstN,
			})
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "PHASE3_NO_REDIRECT",
				fmt.Sprintf("%s -> %s went spoke %s -> hub %s -> spoke %s (%d packet(s)) with no NHRP redirect: %s",
					ik.src, ik.dst, okKey.src, okKey.dst, onwardDst, entry.count, MissingHints["redirect"]),
				[]int{entry.firstN},
			))
		}
	}
	return out
}

// thrashing detects excessive NHRP resolution request rates or repeated unanswered queries per spoke.
func (d *Detector) thrashing(ctx model.Context, issues *[]model.Issue) ThrashingReport {
	type seenReq struct {
		spoke  string
		hasID  bool
		reqID  uint32
		hasTgt bool
		target string
	}
	seen := make(map[seenReq]bool)
	byReq := make(map[string][]nhrpRequestTrack)
	for _, r := range d.requests {
		sk := seenReq{spoke: r.requesterNBMA}
		if r.reqID != nil {
			sk.hasID, sk.reqID = true, *r.reqID
		}
		if r.target != nil {
			sk.hasTgt, sk.target = true, *r.target
		}
		if seen[sk] {
			continue
		}
		seen[sk] = true
		byReq[r.requesterNBMA] = append(byReq[r.requesterNBMA], r)
	}

	spokeNames := make([]string, 0, len(byReq))
	for s := range byReq {
		spokeNames = append(spokeNames, s)
	}
	slices.Sort(spokeNames)

	spokes := make([]SpokeThrash, 0, len(spokeNames))
	isThrashing := false
	for _, spoke := range spokeNames {
		reqs := byReq[spoke]
		times := make([]float64, len(reqs))
		for i, r := range reqs {
			times[i] = r.t
		}
		slices.Sort(times)
		peak := 0
		start := 0
		for end := range times {
			for times[end]-times[start] >= 1.0 {
				start++
			}
			if cur := end - start + 1; cur > peak {
				peak = cur
			}
		}

		type tgtKey struct {
			has bool
			val string
		}
		perTarget := make(map[tgtKey]*TargetThrash)
		var tgtOrder []tgtKey
		for _, r := range reqs {
			var tk tgtKey
			if r.target != nil {
				tk = tgtKey{has: true, val: *r.target}
			}
			tgt, ok := perTarget[tk]
			if !ok {
				tgt = &TargetThrash{Target: r.target, Frames: []int{}}
				perTarget[tk] = tgt
				tgtOrder = append(tgtOrder, tk)
			}
			tgt.Requests++
			if r.reqID != nil && len(d.replies[*r.reqID]) > 0 {
				tgt.Answered++
			} else if r.reqID == nil && len(d.nilReqReplies) > 0 {
				tgt.Answered++
			}
			model.AddFrame(&tgt.Frames, r.n)
		}

		targets := make([]TargetThrash, 0, len(tgtOrder))
		for _, tk := range tgtOrder {
			tgt := perTarget[tk]
			tgt.Unanswered = tgt.Requests - tgt.Answered
			targets = append(targets, *tgt)
		}
		slices.SortStableFunc(targets, func(a, b TargetThrash) int {
			return b.Requests - a.Requests
		})

		var bad []TargetThrash
		for _, x := range targets {
			if x.Unanswered >= thrashUnansweredRepeats {
				bad = append(bad, x)
			}
		}
		spokeThrash := peak >= thrashRatePerS || len(bad) > 0
		isThrashing = isThrashing || spokeThrash

		var avgPtr *float64
		if len(times) > 1 {
			if dur := times[len(times)-1] - times[0]; dur != 0 {
				v := model.Round(float64(len(reqs))/dur, 2)
				avgPtr = &v
			}
		}
		targetsOut := targets
		if len(targetsOut) > 10 {
			targetsOut = targetsOut[:10]
		}
		spokes = append(spokes, SpokeThrash{
			SpokeNBMA:        spoke,
			Requests:         len(reqs),
			PeakPerSecond:    peak,
			AveragePerSecond: avgPtr,
			Targets:          targetsOut,
			Thrashing:        spokeThrash,
		})
		if spokeThrash {
			srcList := bad
			if len(srcList) == 0 {
				srcList = targets
			}
			var details []string
			var frames []int
			for i := 0; i < len(srcList) && i < 3; i++ {
				x := srcList[i]
				details = append(details, fmt.Sprintf("%s asked %d time(s), %d unanswered", optStr(x.Target), x.Requests, x.Unanswered))
			}
			for i := 0; i < len(srcList) && i < 2; i++ {
				fLim := min(len(srcList[i].Frames), 5)
				frames = append(frames, srcList[i].Frames[:fLim]...)
			}
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "NHRP_RESOLUTION_THRASHING",
				fmt.Sprintf("spoke %s sent %d resolution request(s), peaking at %d in one second: %s. Repeated unanswered resolutions usually mean the remote spoke is unreachable over the tunnel, or a redirect loop",
					spoke, len(reqs), peak, joinSemi(details)),
				frames,
			))
		}
	}

	spokesOut, _ := model.Cap(spokes, ctx.MaxItems)
	if spokesOut == nil {
		spokesOut = []SpokeThrash{}
	}
	return ThrashingReport{
		Thrashing: isThrashing,
		Spokes:    spokesOut,
		Thresholds: ThrashThresholds{
			PeakPerSecond:              thrashRatePerS,
			UnansweredRepeatsPerTarget: thrashUnansweredRepeats,
		},
	}
}
