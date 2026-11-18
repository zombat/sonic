// Package espoverhead builds JSON reports and cipher-overhead estimates for Detector.
package espoverhead

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report finalizes size estimates, overhead calculations, and outer fragmentation findings.
func (d *Detector) Report(ctx model.Context) Report {
	issues := []model.Issue{}
	events := []model.Event{}

	flowTracks := make([]*espFlowTrack, 0, len(d.flowOrder))
	for _, k := range d.flowOrder {
		flowTracks = append(flowTracks, d.flows[k])
	}
	slices.SortStableFunc(flowTracks, func(a, b *espFlowTrack) int {
		if a.firstT < b.firstT {
			return -1
		}
		if a.firstT > b.firstT {
			return 1
		}
		return 0
	})

	pooledSizes := sortedUniqueSizes(flowTracks)
	pooled := BestFamily(FamiliesFor(pooledSizes))

	var voteOrder []string
	familyVotes := make(map[string]int)
	flowsOut := make([]FlowReport, 0, len(flowTracks))

	for _, flow := range flowTracks {
		sizes := make([]int, 0, len(flow.sizes))
		for s := range flow.sizes {
			sizes = append(sizes, s)
		}
		slices.Sort(sizes)
		families := FamiliesFor(sizes)
		distinct := len(sizes)
		best := BestFamily(families)
		basis := "this flow's sizes"
		confidence := "low"
		if best == nil {
			confidence = "none"
		} else if distinct >= 4 {
			confidence = "high"
		} else if pooled != nil {
			for _, f := range families {
				if f.Family == pooled.Family {
					fc := f
					best = &fc
					confidence = "medium"
					basis = "every ESP flow in the capture, assuming one cipher profile"
					break
				}
			}
		}

		famOut := make([]FamilyDetails, 0, len(families))
		for _, fam := range families {
			var inner []InnerBound
			for i := 0; i < len(sizes) && i < 12; i++ {
				sz := sizes[i]
				body := sz - fam.IV - fam.ICV
				lo := max(body-espTrailerBytes-(fam.Align-1), 0)
				hi := body - espTrailerBytes
				inner = append(inner, InnerBound{
					ESPPayload: sz, Packets: flow.sizes[sz], InnerBytes: [2]int{lo, hi},
				})
			}
			famOut = append(famOut, FamilyDetails{
				Family: fam.Family, Indistinguishable: fam.Also,
				IV: fam.IV, ICV: fam.ICV, Alignment: fam.Align,
				InnerSizeBounds: nonNilBounds(inner), Modes: d.computeOverheads(flow, fam),
			})
		}

		var estPtr *string
		if best != nil {
			if _, ok := familyVotes[best.Family]; !ok {
				voteOrder = append(voteOrder, best.Family)
			}
			familyVotes[best.Family]++
			est := best.Family
			estPtr = &est
		}

		spi := fmt.Sprintf("0x%08x", flow.spi)
		hist := make([]SizeCount, 0, min(len(sizes), 24))
		for i := 0; i < len(sizes) && i < 24; i++ {
			hist = append(hist, SizeCount{ESPPayload: sizes[i], Packets: flow.sizes[sizes[i]]})
		}
		flowsOut = append(flowsOut, FlowReport{
			Src: flow.src, Dst: flow.dst, SPI: spi, NAT_T: flow.udp,
			Packets: flow.packets, DistinctSizes: distinct, LargestOuterPacket: flow.outerMax,
			DFSetPackets: flow.dfSet, SizeHistogram: hist, Estimate: estPtr,
			Confidence: confidence, EstimateBasis: basis, ConsistentFamilies: famOut, Frames: flow.frames,
		})

		if best == nil {
			msg := fmt.Sprintf("ESP %s -> %s SPI %s: no known cipher family fits every size (TFC padding, a cipher not in the table, or not ESP)", flow.src, flow.dst, spi)
			issues = append(issues, model.MakeIssue(model.SeverityInfo, "ESP_SIZES_UNEXPLAINED", msg, flow.frames))
		} else if d.tunnelMTU != nil {
			for _, f := range famOut {
				if f.Family != best.Family {
					continue
				}
				var overParts []string
				for _, modeName := range []string{"tunnel", "transport_over_gre"} {
					me := f.Modes[modeName]
					if me.FitsTransportMTU != nil && !*me.FitsTransportMTU && me.OuterSizeAtTunnelMTU != nil {
						overParts = append(overParts, fmt.Sprintf("%d bytes in %s mode", *me.OuterSizeAtTunnelMTU, strings.ReplaceAll(modeName, "_", " ")))
					}
				}
				if len(overParts) > 0 {
					msg := fmt.Sprintf("ESP %s -> %s SPI %s (estimated %s): a %d-byte inner packet becomes %s, over the %d-byte transport MTU: the router fragments after encryption; lower the tunnel ip mtu",
						flow.src, flow.dst, spi, best.Family, *d.tunnelMTU, strings.Join(overParts, ", "), d.transportMTU)
					iss := model.MakeIssue(model.SeverityWarning, "ESP_EXCEEDS_TRANSPORT_MTU", msg, flow.frames[:min(len(flow.frames), 1)])
					estTrue := true
					iss.Estimate = &estTrue
					issues = append(issues, iss)
				}
				break
			}
		}
	}

	fragTracks := make([]*fragTrack, 0, len(d.fragOrder))
	for _, k := range d.fragOrder {
		fragTracks = append(fragTracks, d.fragments[k])
	}
	slices.SortStableFunc(fragTracks, func(a, b *fragTrack) int {
		if a.firstT < b.firstT {
			return -1
		}
		if a.firstT > b.firstT {
			return 1
		}
		return 0
	})
	fragsOut := []OuterFragEntry{}
	totalESPFrags := 0
	for _, fr := range fragTracks {
		totalESPFrags += fr.fragments
		spis := make([]string, 0, len(fr.spis))
		for s := range fr.spis {
			spis = append(spis, fmt.Sprintf("0x%08x", s))
		}
		slices.Sort(spis)
		fragsOut = append(fragsOut, OuterFragEntry{
			Src: fr.src, Dst: fr.dst, Fragments: fr.fragments, Datagrams: len(fr.datagrams),
			LargestFragment: fr.largest, SPIs: spis, FirstT: ctx.Rel(&fr.firstT), Frames: fr.frames,
		})
		msg := fmt.Sprintf("ESP %s -> %s fragmented after encryption: %d fragment(s) of %d datagram(s), largest %d bytes; the receiver must reassemble before decrypting (CPU cost, drops under load): lower the tunnel ip mtu or adjust the MSS so encrypted packets fit the transport MTU",
			fr.src, fr.dst, fr.fragments, len(fr.datagrams), fr.largest)
		issues = append(issues, model.MakeIssue(model.SeverityWarning, "ESP_OUTER_FRAGMENTED", msg, fr.frames))
		var framePtr *int
		if len(fr.frames) > 0 {
			f := fr.frames[0]
			framePtr = &f
		}
		events = append(events, model.MakeEvent(ctx, fr.firstT, "esp", "outer_fragmented", msg, framePtr))
	}

	present := d.Present()
	status := model.StatusFromIssues(issues, present)
	verdict := espVerdict(present, flowsOut, voteOrder, familyVotes, fragsOut)
	var pooledPtr *string
	if pooled != nil {
		s := pooled.Family
		pooledPtr = &s
	}
	flowsCap, flowsOm := model.Cap(flowsOut, ctx.MaxItems)

	return Report{
		Detector: d.Name(), Status: status, Verdict: verdict, Estimate: true,
		Assumptions: Assumptions{
			TransportMTU: d.transportMTU, TunnelMTU: d.tunnelMTU, GREHeaderBytes: d.greHeaderBytes,
		},
		Summary: Summary{
			ESPFlows: len(d.flows), ESPFragments: totalESPFrags, FlowsDroppedAtCap: d.flowsDropped,
			FamilyEstimates: familyVotes, CaptureWideEstimate: pooledPtr, CaptureWideDistinctSizes: len(pooledSizes),
		},
		Flows: flowsCap, FlowsOmitted: flowsOm, OuterFragmentation: fragsOut,
		Limits: Limits, Issues: model.SortIssues(issues), Events: events,
	}
}

func (d *Detector) computeOverheads(flow *espFlowTrack, fam FamilyCandidate) map[string]ModeEstimate {
	natt := 0
	if flow.udp {
		natt = 8
	}
	outerIP := 20
	if flow.v6 {
		outerIP = 40
	}
	fixed := outerIP + natt + espHeaderBytes + fam.IV + fam.ICV + espTrailerBytes
	padMax := fam.Align - 1
	modes := make(map[string]ModeEstimate, 2)
	specs := []struct {
		name  string
		extra int
	}{
		{"tunnel", 20},
		{"transport_over_gre", d.greHeaderBytes},
	}
	for _, m := range specs {
		outerSize := func(pkt int) int {
			body := pkt + m.extra + espTrailerBytes
			pad := (fam.Align - (body % fam.Align)) % fam.Align
			body += pad
			return outerIP + natt + espHeaderBytes + fam.IV + body + fam.ICV
		}
		largestFit := d.transportMTU - fixed - m.extra
		for largestFit > 0 && outerSize(largestFit) > d.transportMTU {
			largestFit--
		}
		me := ModeEstimate{
			OverheadBytes:           [2]int{fixed + m.extra, fixed + m.extra + padMax},
			LargestInnerWithoutFrag: largestFit,
		}
		if d.tunnelMTU != nil {
			out := outerSize(*d.tunnelMTU)
			fits := out <= d.transportMTU
			me.OuterSizeAtTunnelMTU = &out
			me.FitsTransportMTU = &fits
		}
		modes[m.name] = me
	}
	return modes
}

func espVerdict(present bool, flows []FlowReport, voteOrder []string, votes map[string]int, frags []OuterFragEntry) string {
	if !present {
		return "No ESP in this capture."
	}
	var parts []string
	if len(flows) > 0 {
		if len(votes) > 0 {
			ranked := slices.Clone(voteOrder)
			slices.SortStableFunc(ranked, func(a, b string) int {
				return votes[b] - votes[a]
			})
			var ests []string
			for i := 0; i < len(ranked) && i < 3; i++ {
				ests = append(ests, fmt.Sprintf("%s on %d flow(s)", ranked[i], votes[ranked[i]]))
			}
			parts = append(parts, fmt.Sprintf("%d ESP flow(s); sizes fit %s (estimate)", len(flows), strings.Join(ests, ", ")))
		} else {
			parts = append(parts, fmt.Sprintf("%d ESP flow(s); no known cipher family fits the sizes", len(flows)))
		}
	}
	if len(frags) > 0 {
		total := 0
		for _, f := range frags {
			total += f.Fragments
		}
		parts = append(parts, fmt.Sprintf("%d ESP fragment(s): encrypted packets fragmented at the transport edge", total))
	} else if len(flows) > 0 {
		maxOuter := 0
		for _, f := range flows {
			if f.LargestOuterPacket > maxOuter {
				maxOuter = f.LargestOuterPacket
			}
		}
		parts = append(parts, fmt.Sprintf("no ESP fragmentation, largest outer packet %d bytes", maxOuter))
	}
	return strings.Join(parts, "; ") + "."
}

func nonNilBounds(in []InnerBound) []InnerBound {
	if in == nil {
		return []InnerBound{}
	}
	return in
}
