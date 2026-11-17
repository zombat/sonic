// Package dmvpn cleartext Phase 3 sequence tracing, relayed flow detection,
// and NHRP resolution thrashing analysis.
package dmvpn

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// buildFlow correlates steps 1 through 5 for a single NHRP Traffic Indication.
func (d *Detector) buildFlow(ind *indicationTrack, ctx model.Context, issues *[]model.Issue, events *[]model.Event) FlowReport {
	spoke, hub := ind.spoke, ind.hub
	a, b := optStr(ind.origSrc), optStr(ind.origDst)
	steps := make(map[string]*StepDetail, len(Steps))
	for _, s := range Steps {
		steps[s] = nil
	}

	var forwardedTo *string
	if ind.origSrc != nil && ind.origDst != nil {
		if flowData, ok := d.data[addrPair{src: *ind.origSrc, dst: *ind.origDst}]; ok {
			if toHub, ok := flowData.outers[addrPair{src: spoke, dst: hub}]; ok {
				detail := fmt.Sprintf("%s -> %s inside GRE %s -> %s", a, b, spoke, hub)
				for _, okKey := range flowData.order {
					if okKey.src == hub && okKey.dst != spoke {
						dstCopy := okKey.dst
						forwardedTo = &dstCopy
						detail += ", forwarded by the hub to " + dstCopy
						break
					}
				}
				steps["via_hub"] = &StepDetail{T: ctx.Rel(&toHub.firstT), Frame: toHub.firstN, Detail: detail}
			}
		}
	}

	steps["redirect"] = &StepDetail{
		T:      ctx.Rel(&ind.t),
		Frame:  ind.n,
		Detail: fmt.Sprintf("Traffic Indication %s -> %s for %s -> %s (%d sent)", hub, spoke, a, b, ind.count),
	}

	var matching []nhrpRequestTrack
	var allFromSpoke []nhrpRequestTrack
	for _, r := range d.requests {
		if r.requesterNBMA == spoke && r.t >= ind.t {
			allFromSpoke = append(allFromSpoke, r)
			if strPtrEq(r.target, ind.origDst) {
				matching = append(matching, r)
			}
		}
	}
	if len(matching) == 0 {
		matching = allFromSpoke
	}

	var reqPtr *nhrpRequestTrack
	if len(matching) > 0 {
		r := matching[0]
		reqPtr = &r
	}
	var replyPtr *nhrpReplyTrack
	var reqIDs []uint32
	if reqPtr != nil {
		steps["resolution_request"] = &StepDetail{
			T:      ctx.Rel(&reqPtr.t),
			Frame:  reqPtr.n,
			Detail: fmt.Sprintf("%s asks for %s (request id %s)", optStr(reqPtr.requester), optStr(reqPtr.target), optU32(reqPtr.reqID)),
		}
		seenID := make(map[uint32]bool)
		var answers []nhrpReplyTrack
		for _, r := range matching {
			if r.reqID == nil {
				answers = append(answers, d.nilReqReplies...)
			} else if !seenID[*r.reqID] {
				seenID[*r.reqID] = true
				reqIDs = append(reqIDs, *r.reqID)
				answers = append(answers, d.replies[*r.reqID]...)
			}
		}
		slices.SortStableFunc(answers, func(x, y nhrpReplyTrack) int {
			return cmp.Compare(x.t, y.t)
		})
		for i := range answers {
			if answers[i].code != nil && *answers[i].code == 0 {
				rep := answers[i]
				replyPtr = &rep
				break
			}
		}
		if replyPtr == nil && len(answers) > 0 {
			rep := answers[0]
			replyPtr = &rep
		}
		if replyPtr != nil {
			prefixStr := "None"
			if replyPtr.prefix != nil {
				prefixStr = fmt.Sprintf("%d", *replyPtr.prefix)
			}
			sd := &StepDetail{
				T:     ctx.Rel(&replyPtr.t),
				Frame: replyPtr.n,
				Detail: fmt.Sprintf("%s answers %s: %s is behind tunnel %s at NBMA %s (prefix /%s)",
					replyPtr.from, cieLabel(replyPtr.code), b, optStr(replyPtr.clientProto), optStr(replyPtr.clientNBMA), prefixStr),
			}
			if replyPtr.code == nil || *replyPtr.code != 0 {
				sd.Negative = true
			}
			steps["resolution_reply"] = sd
		}
	}

	if replyPtr != nil && replyPtr.code != nil && *replyPtr.code == 0 && replyPtr.clientNBMA != nil && *replyPtr.clientNBMA != "" {
		targetNBMA := *replyPtr.clientNBMA
		var bestDirect *outerTiming
		var bestInner addrPair
		for _, ik := range d.dataOrder {
			if ik.dst != optStr(ind.origDst) && !inPrefix(ik.dst, ind.origDst, replyPtr.prefix) {
				continue
			}
			entry, ok := d.data[ik].outers[addrPair{src: spoke, dst: targetNBMA}]
			if ok && entry.firstT >= replyPtr.t {
				if bestDirect == nil || entry.firstT < bestDirect.firstT {
					bestDirect = entry
					bestInner = ik
				}
			}
		}
		if bestDirect != nil {
			steps["direct"] = &StepDetail{
				T:     ctx.Rel(&bestDirect.firstT),
				Frame: bestDirect.firstN,
				Detail: fmt.Sprintf("%s -> %s inside GRE %s -> %s (%d packet(s))",
					bestInner.src, bestInner.dst, spoke, targetNBMA, bestDirect.count),
			}
		}
	}

	var missing *string
	for _, name := range Steps[1:] {
		if steps[name] == nil || steps[name].Negative {
			nCopy := name
			missing = &nCopy
			break
		}
	}
	result := "complete"
	if missing != nil {
		result = "incomplete"
	}

	var reqErrTexts []string
	var reqErrs []nhrpErrorTrack
	if reqPtr != nil {
		for _, e := range d.errors {
			for _, r := range matching {
				if e.reqID != nil && r.reqID != nil && *e.reqID == *r.reqID {
					reqErrs = append(reqErrs, e)
					reqErrTexts = append(reqErrTexts, e.errText)
					break
				}
			}
		}
	}
	if reqErrTexts == nil {
		reqErrTexts = []string{}
	}

	diagnosis := "Phase 3 shortcut formed: redirect, resolution and direct spoke-to-spoke data all seen"
	if missing != nil {
		mName := *missing
		diagnosis = MissingHints[mName]
		if mName == "resolution_reply" && len(reqErrs) > 0 {
			diagnosis = "the resolution got an NHRP error indication instead of a reply: " + reqErrs[0].errText
		} else if mName == "resolution_reply" && replyPtr != nil && (replyPtr.code == nil || *replyPtr.code != 0) {
			diagnosis = "the resolution was refused: " + cieFallbackCode(replyPtr.code)
		}
		sev := model.SeverityError
		if mName == "direct" {
			sev = model.SeverityWarning
		}
		var stepFrames []int
		for _, name := range Steps {
			if steps[name] != nil {
				stepFrames = append(stepFrames, steps[name].Frame)
			}
		}
		iss := model.MakeIssue(
			sev, "PHASE3_MISSING_"+upperASCII(mName),
			fmt.Sprintf("Phase 3 flow %s -> %s from spoke %s: stops before %s: %s", a, b, spoke, mName, diagnosis),
			stepFrames,
		)
		iss.Spoke = spoke
		iss.MissingStep = mName
		*issues = append(*issues, iss)
	}

	var timings Timings
	if steps["via_hub"] != nil && steps["redirect"] != nil && steps["via_hub"].T != nil && steps["redirect"].T != nil {
		v := model.Round((*steps["redirect"].T-*steps["via_hub"].T)*1000.0, 1)
		timings.RedirectAfterFirstDataMs = &v
	}
	if steps["resolution_request"] != nil && steps["resolution_reply"] != nil && steps["resolution_request"].T != nil && steps["resolution_reply"].T != nil {
		v := model.Round((*steps["resolution_reply"].T-*steps["resolution_request"].T)*1000.0, 1)
		timings.ResolutionRTTMs = &v
	}
	if steps["direct"] != nil && steps["direct"].T != nil {
		var firstRel *float64
		if steps["via_hub"] != nil {
			firstRel = steps["via_hub"].T
		} else {
			firstRel = steps["redirect"].T
		}
		if firstRel != nil {
			v := model.Round((*steps["direct"].T-*firstRel)*1000.0, 1)
			timings.ShortcutAfterFirstDataMs = &v
		}
	}

	var minRel *float64
	for _, name := range Steps {
		if sd := steps[name]; sd != nil && sd.T != nil {
			if minRel == nil || *sd.T < *minRel {
				tVal := *sd.T
				minRel = &tVal
			}
		}
	}
	evT := ind.t
	if minRel != nil {
		baseStart := 0.0
		if ctx.Start != nil {
			baseStart = *ctx.Start
		}
		evT = baseStart + *minRel
	}
	evName := "phase3_complete"
	evDetail := fmt.Sprintf("%s %s -> %s: shortcut formed", spoke, a, b)
	if result != "complete" && missing != nil {
		evName = "phase3_incomplete"
		evDetail = fmt.Sprintf("%s %s -> %s: stops before %s", spoke, a, b, *missing)
	}
	fr := ind.n
	*events = append(*events, model.MakeEvent(ctx, evT, "nhrp", evName, evDetail, &fr))

	if steps["via_hub"] == nil {
		diagnosis += "; " + MissingHints["via_hub"]
	}

	return FlowReport{
		Spoke:            spoke,
		Hub:              hub,
		OriginalSrc:      ind.origSrc,
		OriginalDst:      ind.origDst,
		ForwardedByHubTo: forwardedTo,
		Result:           result,
		MissingStep:      missing,
		Diagnosis:        diagnosis,
		Steps:            steps,
		Timings:          timings,
		ErrorIndications: reqErrTexts,
	}
}
