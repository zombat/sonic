// Package reach builds ReachabilityReport metrics, ICMP errors, and ARP checks.
package reach

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report finalizes echo/error/ARP metrics and builds the ReachReport.
func (d *ReachabilityDetector) Report(ctx model.Context) ReachReport {
	issues := []model.Issue{}
	events := []model.Event{}

	sortedPairs := make([]*echoPairTrack, 0, len(d.pairOrder))
	for _, pid := range d.pairOrder {
		sortedPairs = append(sortedPairs, d.pairs[pid])
	}
	slices.SortStableFunc(sortedPairs, func(a, b *echoPairTrack) int {
		return cmpFloat(a.firstT, b.firstT)
	})
	echoPairs := make([]EchoPair, 0, len(sortedPairs))
	for _, p := range sortedPairs {
		echoPairs = append(echoPairs, d.buildEchoPair(ctx, p, &issues, &events))
	}

	sortedErrs := make([]*icmpErrTrack, 0, len(d.icmpErrOrder))
	for _, ek := range d.icmpErrOrder {
		sortedErrs = append(sortedErrs, d.icmpErrors[ek])
	}
	slices.SortStableFunc(sortedErrs, func(a, b *icmpErrTrack) int {
		return cmpFloat(a.firstT, b.firstT)
	})
	errorsOut := make([]ICMPErrorEntry, 0, len(sortedErrs))
	totalErrCount := 0
	for _, e := range sortedErrs {
		totalErrCount += e.count
		target := "None"
		if e.originalDst != nil {
			target = *e.originalDst
		}
		protoName := protoNameForICMPError(e.originalProto)
		what := protoName
		if e.originalDport != nil && *e.originalDport != 0 {
			what = fmt.Sprintf("%s/%d", protoName, *e.originalDport)
		}
		msg := fmt.Sprintf("%s sent %s (%s) to %s for %s towards %s (%dx)",
			e.from, e.typeName, e.codeText, e.to, what, target, e.count)
		sev := model.SeverityWarning
		if e.icmpType == 11 || (e.v6 && e.icmpType == 3) {
			sev = model.SeverityInfo
		}
		if (!e.v6 && e.icmpType == 3 && e.code == 4) || (e.v6 && e.icmpType == 2) {
			msg += "; a packet too big for the path with DF set: check tunnel MTU / TCP MSS adjust"
		}
		iss := model.MakeIssue(sev, "ICMP_"+strings.ToUpper(e.typeName), msg, e.frames)
		tCopy, cCopy := e.icmpType, e.code
		iss.ICMPType = &tCopy
		iss.ICMPCode = &cCopy
		issues = append(issues, iss)
		events = append(events, model.MakeEvent(ctx, e.firstT, "icmp", e.typeName, msg, &e.frames[0]))

		errorsOut = append(errorsOut, ICMPErrorEntry{
			From: e.from, To: e.to, V6: e.v6, Type: e.icmpType, Code: e.code,
			TypeName: e.typeName, CodeText: e.codeText,
			OriginalSrc: e.originalSrc, OriginalDst: e.originalDst,
			OriginalProto: e.originalProto, OriginalDport: e.originalDport,
			Count: e.count, FirstT: ctx.Rel(&e.firstT), Frames: nonNilInts(e.frames),
		})
	}

	arpTargets := make([]string, 0, len(d.arpRequests))
	for t := range d.arpRequests {
		arpTargets = append(arpTargets, t)
	}
	slices.SortStableFunc(arpTargets, model.CompareIP)
	arpUnanswered := []ARPUnansweredEntry{}
	arpAnswered := 0
	for _, target := range arpTargets {
		if _, ok := d.arpReplies[target]; ok {
			arpAnswered++
			continue
		}
		req := d.arpRequests[target]
		askers := sortedIPKeys(req.askers)
		arpUnanswered = append(arpUnanswered, ARPUnansweredEntry{
			Target: target, RequestedBy: askers, Requests: req.count,
			FirstT: ctx.Rel(&req.firstT), Frames: nonNilInts(req.frames),
		})
		msg := fmt.Sprintf("ARP for %s asked %d time(s) by %s, never answered (host down, wrong subnet, or not on this segment)",
			target, req.count, strings.Join(askers, ", "))
		issues = append(issues, model.MakeIssue(model.SeverityWarning, "ARP_NO_REPLY", msg, req.frames))
	}

	duplicates := []ARPDupEntry{}
	for _, ip := range d.arpReplyOrder {
		rep := d.arpReplies[ip]
		if len(rep.macs) > 1 {
			duplicates = append(duplicates, ARPDupEntry{IP: ip, MACs: rep.macs, Frames: nonNilInts(rep.frames)})
			issues = append(issues, model.MakeIssue(model.SeverityError, "ARP_DUPLICATE_IP", formatARPDupSummary(ip, rep.macOrder), rep.frames))
		}
	}

	present := d.Present()
	status := model.StatusFromIssues(issues, present)
	verdict := reachVerdict(present, echoPairs, errorsOut, arpUnanswered)

	totalReq, totalAns, totalLost := 0, 0, 0
	for _, p := range echoPairs {
		totalReq += p.Sent
		totalAns += p.Answered
		totalLost += p.Lost
	}
	totalUnmatched := 0
	for _, c := range d.unmatchedReplies {
		totalUnmatched += c
	}

	pairsList, pairsOmitted := model.Cap(echoPairs, ctx.MaxItems)
	errsList, errsOmitted := model.Cap(errorsOut, ctx.MaxItems)
	unansList, unansOmitted := model.Cap(arpUnanswered, ctx.MaxItems)

	return ReachReport{
		Detector: d.Name(), Status: status, Verdict: verdict,
		Summary: ReachSummary{
			EchoPairs: len(echoPairs), EchoRequests: totalReq,
			EchoRepliesMatched: totalAns, EchoLost: totalLost,
			UnmatchedReplies: totalUnmatched, ICMPErrors: totalErrCount,
			ARPTargetsUnanswered: len(arpUnanswered), ARPTargetsAnswered: arpAnswered,
			GratuitousARP: d.gratuitous,
		},
		Echo: pairsList, EchoOmitted: pairsOmitted,
		ICMPErrors: errsList, ICMPErrorsOmitted: errsOmitted,
		ARPUnanswered: unansList, ARPUnansweredOmitted: unansOmitted,
		ARPDuplicateIPs: duplicates,
		Issues:          model.SortIssues(issues), Events: events,
	}
}
