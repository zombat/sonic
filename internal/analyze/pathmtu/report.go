// Package pathmtu builds the top-level PathMtuDetector Report and PTB entries.
package pathmtu

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report finalizes path MTU findings and builds the Report.
func (d *PathMtuDetector) Report(ctx model.Context) Report {
	issues := []model.Issue{}
	events := []model.Event{}

	fragNeeded := d.reportPTB(ctx, &issues, &events)
	blackHoles := d.echoBlackHoles(ctx, &issues, &events)
	blackHoles = append(blackHoles, d.tcpBlackHoles(ctx, &issues, &events)...)
	fragments := d.reportFragments(ctx, &issues, &events)

	for _, to := range d.reassemblyTimeouts {
		msg := fmt.Sprintf("%s gave up reassembling fragments towards it from %s (ICMP fragment reassembly time exceeded): a fragment was lost on the way",
			to.from, to.to)
		issues = append(issues, model.MakeIssue(model.SeverityError, "FRAGMENT_REASSEMBLY_TIMEOUT", msg, []int{to.n}))
		nCopy := to.n
		events = append(events, model.MakeEvent(ctx, to.t, "ip", "reassembly_timeout", msg, &nCopy))
	}

	present := d.Present()
	status := model.StatusFromIssues(issues, present)
	verdict := d.buildVerdict(present, fragNeeded, blackHoles, fragments)

	totalPTB := 0
	var smallestMTU *int
	for _, p := range fragNeeded {
		totalPTB += p.Count
		if p.MTU != nil && *p.MTU != 0 && (smallestMTU == nil || *p.MTU < *smallestMTU) {
			v := *p.MTU
			smallestMTU = &v
		}
	}
	var largestDF *int
	if d.largestDF != 0 {
		v := d.largestDF
		largestDF = &v
	}

	ptbList, ptbOm := model.Cap(fragNeeded, ctx.MaxItems)
	holesList, holesOm := model.Cap(blackHoles, ctx.MaxItems)
	return Report{
		Detector: d.Name(), Status: status, Verdict: verdict,
		Summary: Summary{
			DFPacketsOver576:      d.dfLarge,
			LargestDFPacket:       largestDF,
			FragNeededMessages:    totalPTB,
			SmallestMTUAdvertised: smallestMTU,
			BlackHoles:            len(blackHoles),
			FragmentedDatagrams:   fragments.Datagrams,
			IncompleteDatagrams:   fragments.IncompleteCount,
			ReassemblyTimeouts:    len(d.reassemblyTimeouts),
		},
		FragNeeded: ptbList, FragNeededOmitted: ptbOm,
		BlackHoles: holesList, BlackHolesOmitted: holesOm,
		Fragments: fragments, Limits: Limits,
		Issues: model.SortIssues(issues), Events: events,
	}
}

// reportPTB aggregates ICMP Fragmentation Needed / Packet Too Big entries into sorted PTBEntry slices.
func (d *PathMtuDetector) reportPTB(ctx model.Context, issues *[]model.Issue, events *[]model.Event) []PTBEntry {
	tracks := make([]*ptbTrack, 0, len(d.ptbOrder))
	for _, k := range d.ptbOrder {
		tracks = append(tracks, d.ptb[k])
	}
	slices.SortStableFunc(tracks, func(a, b *ptbTrack) int {
		if a.firstT < b.firstT {
			return -1
		}
		if a.firstT > b.firstT {
			return 1
		}
		return 0
	})
	out := make([]PTBEntry, 0, len(tracks))
	for _, e := range tracks {
		what := "Fragmentation Needed"
		if strings.Contains(e.router, ":") {
			what = "Packet Too Big"
		}
		text := fmt.Sprintf("%s sent %s to %s for packets %s -> %s",
			e.router, what, e.to, strOrNone(e.originalSrc), strOrNone(e.originalDst))
		if e.originalLen != nil && *e.originalLen != 0 {
			text += fmt.Sprintf(" (%d bytes)", *e.originalLen)
		}
		if e.mtu != nil && *e.mtu != 0 {
			text += fmt.Sprintf(": next-hop MTU %d", *e.mtu)
			if e.originalLen != nil && *e.originalLen != 0 && *e.mtu >= *e.originalLen {
				text += " (not smaller than the packet it refers to: a bogus or stale MTU)"
			}
		} else {
			text += ": no next-hop MTU stated (pre-RFC 1191 router; the sender must guess)"
		}
		text += fmt.Sprintf(" (%dx)", e.count)
		if len(e.probeFrames) > 0 {
			pStr := make([]string, 0, min(len(e.probeFrames), 3))
			for _, f := range e.probeFrames[:min(len(e.probeFrames), 3)] {
				pStr = append(pStr, strconv.Itoa(f))
			}
			text += "; refers to frame(s) " + strings.Join(pStr, ", ")
		}

		iss := model.MakeIssue(model.SeverityWarning, "PMTU_FRAG_NEEDED", text, e.frames)
		iss.MTU = e.mtu
		iss.Router = e.router
		*issues = append(*issues, iss)
		var fr *int
		if len(e.frames) > 0 {
			f := e.frames[0]
			fr = &f
		}
		*events = append(*events, model.MakeEvent(ctx, e.firstT, "icmp", "frag_needed", text, fr))

		out = append(out, PTBEntry{
			Router: e.router, To: e.to, OriginalSrc: e.originalSrc, OriginalDst: e.originalDst,
			OriginalProtocol: e.origProto, OriginalDport: e.origDport, MTU: e.mtu, OriginalLen: e.originalLen,
			Count: e.count, FirstT: ctx.Rel(&e.firstT), Frames: e.frames, ProbeFrames: e.probeFrames, Tunneled: e.tunneled,
		})
	}
	return out
}
