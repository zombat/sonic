// Package correlate assigns path verdicts (`asymmetric`, `reply_lost`, `partial_loss`,
// `seen_only_at`, `not_on_other_paths`, `ok`) to correlated connections.
package correlate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

func judgeConnection(fwd, rev *directionData, labels []string, start *float64, corr *correlator) ConnectionRow {
	frameSets := make(map[string]map[int]bool)
	keep := func(frames map[string]int) {
		for lbl, fn := range frames {
			if frameSets[lbl] == nil {
				frameSets[lbl] = make(map[int]bool)
			}
			frameSets[lbl][fn] = true
		}
	}
	for i := 0; i < len(fwd.patternOrder) && i < 2; i++ {
		keep(fwd.patternMeta[fwd.patternOrder[i]].frames)
	}

	what := fwd.firstTuple
	partial := collectIncomplete(fwd, rev, labels)

	var fwdOnly, revOnly []int
	for _, c := range fwd.caps {
		if rev == nil || !rev.capSet[c] {
			fwdOnly = append(fwdOnly, c)
		}
	}
	if rev != nil {
		for _, c := range rev.caps {
			if !fwd.capSet[c] {
				revOnly = append(revOnly, c)
			}
		}
	}

	verdict, detail := classifyVerdict(fwd, rev, labels, corr, what, fwdOnly, revOnly, partial, keep)

	var firstTPtr *float64
	if fwd.firstT != nil && start != nil {
		v := model.Round(*fwd.firstT-*start, 6)
		firstTPtr = &v
	}
	var repSeen *DirectionSeen
	if rev != nil {
		repSeen = &DirectionSeen{SeenAt: rev.seen}
	}
	framesOut := make(map[string][]int, len(frameSets))
	for lbl, set := range frameSets {
		nums := make([]int, 0, len(set))
		for n := range set {
			nums = append(nums, n)
		}
		slices.Sort(nums)
		if len(nums) > 10 {
			nums = nums[:10]
		}
		framesOut[lbl] = nums
	}
	incLimit := min(5, len(partial))
	return ConnectionRow{
		Flow:                 what,
		Verdict:              verdict,
		Detail:               detail,
		EndpointsByCapture:   fwd.tuples,
		Request:              DirectionSeen{SeenAt: fwd.seen},
		Reply:                repSeen,
		Incomplete:           partial[:incLimit],
		LinkLocalOrMulticast: fwd.multicast,
		FirstT:               firstTPtr,
		Frames:               framesOut,
	}
}

func collectIncomplete(fwd, rev *directionData, labels []string) []IncompleteFlow {
	partial := []IncompleteFlow{}
	type namedDir struct {
		dir  *directionData
		name string
	}
	for _, nd := range []namedDir{{fwd, "request"}, {rev, "reply"}} {
		if nd.dir == nil || len(nd.dir.caps) < 2 {
			continue
		}
		for _, pKey := range nd.dir.patternOrder {
			meta := nd.dir.patternMeta[pKey]
			count := nd.dir.patterns[pKey]
			inOrder := make(map[int]bool, len(meta.order))
			seenLabels := make([]string, len(meta.order))
			for idx, c := range meta.order {
				inOrder[c] = true
				seenLabels[idx] = labels[c]
			}
			var missing []int
			for _, a := range meta.active {
				if nd.dir.capSet[a] && !inOrder[a] {
					missing = append(missing, a)
				}
			}
			if len(missing) > 0 {
				slices.Sort(missing)
				missingLabels := make([]string, len(missing))
				for idx, m := range missing {
					missingLabels[idx] = labels[m]
				}
				frames := make(map[string]int, len(meta.frames))
				for k, v := range meta.frames {
					frames[k] = v
				}
				partial = append(partial, IncompleteFlow{
					Direction:  nd.name,
					Packets:    count,
					SeenAt:     seenLabels,
					LastSeenAt: labels[meta.order[len(meta.order)-1]],
					MissingAt:  missingLabels,
					Frames:     frames,
				})
			}
		}
	}
	return partial
}

func classifyVerdict(
	fwd, rev *directionData,
	labels []string,
	corr *correlator,
	what string,
	fwdOnly, revOnly []int,
	partial []IncompleteFlow,
	keep func(map[string]int),
) (string, string) {
	switch {
	case rev != nil && len(fwd.caps) > 0 && len(rev.caps) > 0 && len(fwdOnly) > 0 && len(revOnly) > 0:
		return "asymmetric", fmt.Sprintf(
			"%s: requests seen at %s, replies at %s: out through %s, back through %s",
			what, joinLabels(labels, fwd.caps), joinLabels(labels, rev.caps),
			joinLabels(labels, fwdOnly), joinLabels(labels, revOnly),
		)
	case rev != nil && len(rev.caps) < len(fwd.caps) && len(revOnly) == 0:
		lastLabel := labels[rev.caps[0]]
		if len(rev.patternOrder) > 0 {
			bestKey, bestCnt := "", -1
			for _, pk := range rev.patternOrder {
				if rev.patterns[pk] > bestCnt {
					bestCnt = rev.patterns[pk]
					bestKey = pk
				}
			}
			ord := rev.patternMeta[bestKey].order
			lastLabel = labels[ord[len(ord)-1]]
		}
		kind := "reply"
		if rev.synack {
			kind = "SYN-ACK"
		}
		missText := joinLabels(labels, fwdOnly)
		for i := 0; i < len(rev.patternOrder) && i < 2; i++ {
			keep(rev.patternMeta[rev.patternOrder[i]].frames)
		}
		return "reply_lost", fmt.Sprintf(
			"%s: the %s was last seen at %s and never reached %s (the request crossed %s): dropped between %s and %s",
			what, kind, lastLabel, missText, joinLabels(labels, fwd.caps), lastLabel, missText,
		)
	case len(partial) > 0:
		totalPartial := 0
		best := partial[0]
		for _, p := range partial {
			totalPartial += p.Packets
			if p.Packets > best.Packets {
				best = p
			}
		}
		for i := 0; i < len(partial) && i < 2; i++ {
			keep(partial[i].Frames)
		}
		return "partial_loss", fmt.Sprintf(
			"%s: %d packet(s) did not cross every capture point, e.g. %d %s packet(s) last seen at %s, missing at %s",
			what, totalPartial, best.Packets, best.Direction, best.LastSeenAt, strings.Join(best.MissingAt, ", "),
		)
	case len(fwd.caps) == 1 && (rev == nil || len(rev.caps) <= 1):
		where := labels[fwd.caps[0]]
		var recording []int
		if fwd.firstT != nil {
			recording = corr.active(*fwd.firstT)
		} else {
			for i := range labels {
				recording = append(recording, i)
			}
		}
		var others []int
		for _, idx := range recording {
			if !fwd.capSet[idx] && (rev == nil || !rev.capSet[idx]) {
				others = append(others, idx)
			}
		}
		var onPath []int
		if !fwd.multicast {
			onPath = onPathElsewhere(corr, fwd, others)
		}
		if len(onPath) > 0 {
			names := joinLabels(labels, onPath)
			replyText := ", no reply"
			if rev != nil {
				replyText = " (with replies)"
			}
			return "seen_only_at", fmt.Sprintf(
				"%s: seen only at %s%s; never at %s, although other traffic between the same addresses crossed %s: it stopped after %s (an ACL, a route or a drop)",
				what, where, replyText, names, names, where,
			)
		}
		detail := fmt.Sprintf("%s: seen only at %s", what, where)
		if len(others) > 0 {
			detail += fmt.Sprintf("; %s never saw these two addresses talk, so this flow does not cross them", joinLabels(labels, others))
		}
		return "not_on_other_paths", detail
	default:
		unionMap := make(map[int]bool)
		for _, c := range fwd.caps {
			unionMap[c] = true
		}
		if rev != nil {
			for _, c := range rev.caps {
				unionMap[c] = true
			}
		}
		var crossed []int
		for c := range unionMap {
			crossed = append(crossed, c)
		}
		slices.Sort(crossed)
		if rev == nil {
			return "ok", fmt.Sprintf("%s: crossed %s (no reply seen at any capture point)", what, joinLabels(labels, crossed))
		}
		return "ok", fmt.Sprintf("%s: both directions crossed %s", what, joinLabels(labels, crossed))
	}
}

func joinLabels(labels []string, indices []int) string {
	parts := make([]string, len(indices))
	for i, idx := range indices {
		parts[i] = labels[idx]
	}
	return strings.Join(parts, ", ")
}
