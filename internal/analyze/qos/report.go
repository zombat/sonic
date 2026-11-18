// Package qos builds the finalized QosDetector Report from accumulated flow,
// GRE, ESP, ECN, and RTP telemetry.
package qos

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report finalizes all QoS metrics and returns the JSON report.
func (d *QosDetector) Report(ctx model.Context) Report {
	issues := []model.Issue{}
	events := []model.Event{}

	flowTracks := make([]*flowTrack, 0, len(d.flowOrder))
	unmarked := 0
	for _, fk := range d.flowOrder {
		fl := d.flows[fk]
		flowTracks = append(flowTracks, fl)
		if len(fl.dscp) == 1 && fl.dscp[0] > 0 {
			unmarked++
		}
	}
	slices.SortStableFunc(flowTracks, func(a, b *flowTrack) int {
		return b.packets - a.packets
	})
	flowsOut := []MarkedFlow{}
	for _, fl := range flowTracks {
		if len(fl.dscp) == 1 && fl.dscp[0] > 0 {
			continue
		}
		flowsOut = append(flowsOut, MarkedFlow{
			Src: fl.src, Dst: fl.dst, Protocol: fl.label,
			Packets: fl.packets, DSCP: dscpCountsMap(fl.dscp), Frames: fl.frames,
		})
	}

	tunnelsOut := d.reportGRE(&issues)
	sasOut := d.reportESP()
	streamsOut := d.reportRTP(ctx, &issues, &events)

	if d.ce > 0 {
		msg := fmt.Sprintf("%d packet(s) marked ECN Congestion Experienced: a queue on the path was congested", d.ce)
		issues = append(issues, model.MakeIssue(model.SeverityInfo, "QOS_ECN_CE", msg, d.ceFrames))
	}

	present := d.Present()
	status := model.StatusFromIssues(issues, present)
	verdict := qosVerdict(present, flowsOut, unmarked, tunnelsOut, sasOut, streamsOut)

	flowsCap, flowsOm := model.Cap(flowsOut, ctx.MaxItems)
	sasCap, sasOm := model.Cap(sasOut, ctx.MaxItems)
	streamsCap, streamsOm := model.Cap(streamsOut, ctx.MaxItems)
	tunnelsCap, _ := model.Cap(tunnelsOut, ctx.MaxItems)

	return Report{
		Detector: d.Name(), Status: status, Verdict: verdict,
		Summary: Summary{
			MarkedFlows: len(flowsOut), UnmarkedFlows: unmarked,
			GRETunnels: len(tunnelsOut), ESPSAs: len(sasOut),
			RTPStreams: len(streamsOut), ECNCEPackets: d.ce,
			FlowsDroppedAtCap: d.flowsDropped,
		},
		MarkedFlows: flowsCap, MarkedFlowsOmitted: flowsOm,
		GRETunnels: tunnelsCap, ESPSAs: sasCap, ESPSAsOmitted: sasOm,
		RTPStreams: streamsCap, RTPStreamsOmitted: streamsOm,
		Limits: Limits, Issues: model.SortIssues(issues), Events: events,
	}
}

func (d *QosDetector) reportGRE(issues *[]model.Issue) []GRETunnelEntry {
	tunnelsOut := []GRETunnelEntry{}
	for _, gk := range d.greOrder {
		tun := d.gre[gk]
		total, copied, lost := 0, 0, 0
		for gp, c := range tun.pairs {
			total += c
			if gp.inner == gp.outer {
				copied += c
			}
			if gp.inner != 0 && gp.outer == 0 {
				lost += c
			}
		}
		rewritten := total - copied - lost
		orderedPairs := slices.Clone(tun.pairOrder)
		slices.SortStableFunc(orderedPairs, func(a, b grePair) int {
			return tun.pairs[b] - tun.pairs[a]
		})
		if len(orderedPairs) > 10 {
			orderedPairs = orderedPairs[:10]
		}
		pairsOut := make([]GREPairCount, 0, len(orderedPairs))
		for _, gp := range orderedPairs {
			iv, ov := gp.inner, gp.outer
			pairsOut = append(pairsOut, GREPairCount{
				Inner: model.DSCPName(&iv), Outer: model.DSCPName(&ov), Packets: tun.pairs[gp],
			})
		}
		tunnelsOut = append(tunnelsOut, GRETunnelEntry{
			OuterSrc: tun.src, OuterDst: tun.dst, PacketsWithInnerIPv4: total,
			Copied: copied, InnerMarkedOuterZero: lost, Rewritten: rewritten,
			Pairs: pairsOut, Frames: tun.lostFrames,
		})
		if lost > 0 {
			msg := fmt.Sprintf("GRE %s -> %s: %d packet(s) marked inside but DSCP 0 on the delivery header: WAN QoS cannot see the class (check tunnel tos / qos pre-classify)", tun.src, tun.dst, lost)
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "QOS_GRE_DSCP_NOT_COPIED", msg, tun.lostFrames))
		} else if rewritten > 0 {
			msg := fmt.Sprintf("GRE %s -> %s: %d packet(s) carry a different DSCP outside than inside", tun.src, tun.dst, rewritten)
			*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "QOS_GRE_DSCP_REWRITTEN", msg, tun.lostFrames))
		}
	}
	return tunnelsOut
}

func (d *QosDetector) reportESP() []ESPSAEntry {
	sasOut := []ESPSAEntry{}
	for _, ek := range d.espOrder {
		sa := d.esp[ek]
		vals := sortedKeys(sa.dscp)
		var reading string
		if len(vals) > 1 {
			reading = "several markings on one SA: DSCP is copied from the inner header per packet"
		} else if len(vals) == 1 && vals[0] == 0 {
			reading = "every packet DSCP 0: either the inner traffic was unmarked or the router does not copy DSCP into ESP; an inside capture tells which"
		} else {
			v := vals[0]
			reading = fmt.Sprintf("every packet %s: one class inside, or a fixed outer marking (cannot tell from one capture)", model.DSCPName(&v))
		}
		sasOut = append(sasOut, ESPSAEntry{
			Src: sa.src, Dst: sa.dst, SPI: fmt.Sprintf("0x%08x", sa.spi),
			DSCP: dscpCountsMap(sa.dscp), Reading: reading, Frames: sa.frames,
		})
	}
	return sasOut
}

func (d *QosDetector) reportRTP(ctx model.Context, issues *[]model.Issue, events *[]model.Event) []RTPStreamEntry {
	var validStreams []*rtpStream
	for _, rk := range d.rtpOrder {
		st := d.rtp[rk]
		if st.looksLikeRTP() {
			validStreams = append(validStreams, st)
		}
	}
	slices.SortStableFunc(validStreams, func(a, b *rtpStream) int {
		if a.firstT < b.firstT {
			return -1
		}
		if a.firstT > b.firstT {
			return 1
		}
		return 0
	})
	streamsOut := []RTPStreamEntry{}
	for _, st := range validStreams {
		st.finish()
		expected := 0
		if st.hasFirstSeq {
			expected = st.maxExt - int(st.firstSeq) + 1
		}
		received := st.packets - st.dups
		lost := max(expected-received, 0)
		lossPct := 0.0
		if expected > 0 {
			lossPct = model.Round(100.0*float64(lost)/float64(expected), 2)
		}
		jitterMs := model.Round(st.jitter*1000.0, 3)
		meanJitterMs := 0.0
		if st.jitterN > 0 {
			meanJitterMs = model.Round(st.jitterSum/float64(st.jitterN)*1000.0, 3)
		}
		maxJitterMs := model.Round(st.maxJitter*1000.0, 3)
		codec := MapPayloadToCodec(st.pt)
		mos := CalculateEModelMOS(codec, lossPct, meanJitterMs)

		srcEnd := model.Endpoint(st.key.src, &st.key.sport)
		dstEnd := model.Endpoint(st.key.dst, &st.key.dport)
		ssrcHex := fmt.Sprintf("0x%08x", st.ssrc)
		entry := RTPStreamEntry{
			Src: srcEnd, Dst: dstEnd, SSRC: ssrcHex, PayloadType: st.pt, Codec: codec,
			ClockRate: st.clock, ClockRateSource: st.clockSource, Packets: st.packets,
			Expected: expected, Lost: lost, LossPercent: lossPct, Duplicates: st.dups,
			OutOfOrder:  st.ooo,
			JitterMs:    RTPJitterStats{Final: jitterMs, Mean: meanJitterMs, Max: maxJitterMs},
			DurationS:   model.Round(st.lastT-st.firstT, 3),
			DSCP:        dscpCountsMap(st.dscp),
			MOSEstimate: &mos, Latency: "not measurable from one capture point",
			OverGRE: st.tunneled, FirstT: ctx.Rel(&st.firstT), Frames: st.frames,
		}
		streamsOut = append(streamsOut, entry)

		label := fmt.Sprintf("RTP %s -> %s SSRC %s", srcEnd, dstEnd, ssrcHex)
		dscps := sortedKeys(st.dscp)
		var dscpNames []string
		for _, v := range dscps {
			vv := v
			dscpNames = append(dscpNames, model.DSCPName(&vv))
		}
		if !(len(dscps) == 1 && dscps[0] == 46) && audioPT[st.pt] {
			msg := fmt.Sprintf("%s (%s) carries %s, not EF (46): voice will queue with best effort", label, codec, strings.Join(dscpNames, ", "))
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "QOS_RTP_NOT_EF", msg, st.frames))
		} else if !slices.Contains(dscps, 46) && !(len(dscps) == 1 && dscps[0] == 34) {
			msg := fmt.Sprintf("%s (PT %d) carries %s", label, st.pt, strings.Join(dscpNames, ", "))
			*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "QOS_RTP_UNMARKED", msg, st.frames))
		}
		if lossPct > 1.0 {
			sev := model.SeverityWarning
			if lossPct > 5.0 {
				sev = model.SeverityError
			}
			msg := fmt.Sprintf("%s: %d of %d packets lost (%s%%)", label, lost, expected, model.FormatPyFloat(lossPct))
			*issues = append(*issues, model.MakeIssue(sev, "QOS_RTP_LOSS", msg, st.frames))
			evMsg := fmt.Sprintf("%s: %s%% loss", label, model.FormatPyFloat(lossPct))
			var fr *int
			if len(st.frames) > 0 {
				f := st.frames[0]
				fr = &f
			}
			*events = append(*events, model.MakeEvent(ctx, st.firstT, "rtp", "loss", evMsg, fr))
		}
		if meanJitterMs > 30.0 {
			msg := fmt.Sprintf("%s: mean jitter %s ms (max %s)", label, model.FormatPyFloat(meanJitterMs), model.FormatPyFloat(maxJitterMs))
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "QOS_RTP_JITTER", msg, st.frames))
		}
	}
	return streamsOut
}

func qosVerdict(present bool, flows []MarkedFlow, unmarked int, tunnels []GRETunnelEntry, sas []ESPSAEntry, streams []RTPStreamEntry) string {
	if !present {
		return "No DSCP marking, tunnel, ESP or RTP to judge."
	}
	var parts []string
	if len(flows) > 0 {
		parts = append(parts, fmt.Sprintf("%d marked flow(s), %d unmarked", len(flows), unmarked))
	}
	if len(tunnels) > 0 {
		lost := 0
		for _, t := range tunnels {
			lost += t.InnerMarkedOuterZero
		}
		if lost > 0 {
			parts = append(parts, fmt.Sprintf("GRE: %d packet(s) lose their marking", lost))
		} else {
			parts = append(parts, "GRE copies DSCP to the outer header")
		}
	}
	if len(sas) > 0 {
		copied := 0
		for _, s := range sas {
			if strings.Contains(s.Reading, "copied") {
				copied++
			}
		}
		parts = append(parts, fmt.Sprintf("ESP: %d of %d SA(s) show DSCP copied per packet", copied, len(sas)))
	}
	if len(streams) > 0 {
		var worst *float64
		for _, s := range streams {
			if s.MOSEstimate != nil && (worst == nil || *s.MOSEstimate < *worst) {
				v := *s.MOSEstimate
				worst = &v
			}
		}
		item := fmt.Sprintf("%d RTP stream(s)", len(streams))
		if worst != nil {
			item += fmt.Sprintf(", worst MOS estimate %s", model.FormatPyFloat(*worst))
		}
		parts = append(parts, item)
	}
	return strings.Join(parts, "; ") + "."
}

func sortedKeys(m map[int]int) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func dscpCountsMap(m map[int]int) map[string]int {
	out := make(map[string]int, len(m))
	for _, d := range sortedKeys(m) {
		v := d
		out[model.DSCPName(&v)] = m[d]
	}
	return out
}
