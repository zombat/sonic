// Package routing EIGRP link mismatch checking, adjacency evaluation, and reporting.
package routing

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// report builds EIGRP link reports, AS/K-value mismatch issues, and hold-expiry events.
func (a *EigrpAnalyzer) report(ctx model.Context, issues *[]model.Issue, events *[]model.Event) EIGRPSection {
	links := a.groupLinks()
	linksOut := make([]EIGRPLinkReport, 0, len(links))

	for _, group := range links {
		addrs := slices.Clone(group)
		slices.SortStableFunc(addrs, model.CompareIP)
		speakers := make([]*eigrpSpeakerState, len(addrs))
		for i, addr := range addrs {
			speakers[i] = a.speakers[addr]
		}
		mismatches := checkEIGRPMismatches(speakers, issues)
		adjacencies := a.buildEIGRPAdjacencies(speakers, issues)
		speakersOut := a.buildEIGRPSpeakerReports(speakers, ctx, issues)
		linksOut = append(linksOut, EIGRPLinkReport{
			Speakers:    speakersOut,
			Mismatches:  mismatches,
			Adjacencies: adjacencies,
		})
	}

	for _, ev := range a.events {
		fr := ev.frame
		*events = append(*events, model.MakeEvent(ctx, ev.t, "eigrp", ev.kind, ev.detail, &fr))
	}
	listed, omitted := model.Cap(linksOut, ctx.MaxItems)
	return EIGRPSection{
		Present:      true,
		Links:        listed,
		LinksOmitted: omitted,
		Packets:      a.packets,
		Speakers:     len(a.speakers),
	}
}

// checkEIGRPMismatches checks AS number parity and per-AS K-value uniformity on one link.
func checkEIGRPMismatches(speakers []*eigrpSpeakerState, issues *[]model.Issue) []EIGRPMismatch {
	mismatches := []EIGRPMismatch{}
	asMap := make(map[string]*int, len(speakers))
	distinctAS := make(map[int]bool)
	hasNilAS := false
	var asParts []string
	for _, sp := range speakers {
		asMap[sp.address] = sp.as
		if sp.as == nil {
			hasNilAS = true
			asParts = append(asParts, fmt.Sprintf("%s=ASNone", sp.address))
		} else {
			distinctAS[*sp.as] = true
			asParts = append(asParts, fmt.Sprintf("%s=AS%d", sp.address, *sp.as))
		}
	}
	asTotalDistinct := len(distinctAS)
	if hasNilAS {
		asTotalDistinct++
	}
	if asTotalDistinct > 1 {
		raw, _ := json.Marshal(asMap)
		mismatches = append(mismatches, EIGRPMismatch{Parameter: "as", Values: raw})
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, "EIGRP_AS_MISMATCH",
			fmt.Sprintf("EIGRP AS differs between speakers on one link: %s; they will not become neighbors", strings.Join(asParts, ", ")),
			nil,
		))
	}

	asList := make([]int, 0, len(distinctAS))
	for asn := range distinctAS {
		asList = append(asList, asn)
	}
	slices.Sort(asList)
	for _, asn := range asList {
		kMap := make(map[string][]int)
		var kOrder []string
		kStrMap := make(map[string]string)
		kStrFreq := make(map[string]int)
		var freqOrder []string
		for _, sp := range speakers {
			if sp.as != nil && *sp.as == asn && sp.k != nil {
				kMap[sp.address] = sp.k
				kOrder = append(kOrder, sp.address)
				ks := formatKSlice(sp.k)
				kStrMap[sp.address] = ks
				if _, exists := kStrFreq[ks]; !exists {
					freqOrder = append(freqOrder, ks)
				}
				kStrFreq[ks]++
			}
		}
		if len(kStrFreq) > 1 {
			common := freqOrder[0]
			for _, ks := range freqOrder[1:] {
				if kStrFreq[ks] > kStrFreq[common] {
					common = ks
				}
			}
			var odd, parts []string
			for _, addr := range kOrder {
				ks := kStrMap[addr]
				parts = append(parts, fmt.Sprintf("%s=%s", addr, ks))
				if ks != common {
					odd = append(odd, addr)
				}
			}
			raw, _ := json.Marshal(kMap)
			mismatches = append(mismatches, EIGRPMismatch{Parameter: "k_values", Values: raw})
			*issues = append(*issues, model.MakeIssue(
				model.SeverityError, "EIGRP_K_VALUE_MISMATCH",
				fmt.Sprintf("EIGRP K-values differ in AS %d: %s; %s cannot form adjacencies with the others",
					asn, strings.Join(parts, ", "), strings.Join(odd, ", ")),
				nil,
			))
		}
	}
	return mismatches
}

// buildEIGRPAdjacencies evaluates bidirectional INIT exchanges and restarts across speaker pairs.
func (a *EigrpAnalyzer) buildEIGRPAdjacencies(speakers []*eigrpSpeakerState, issues *[]model.Issue) []EIGRPAdjacency {
	adjacencies := []EIGRPAdjacency{}
	for i := 0; i < len(speakers); i++ {
		for j := i + 1; j < len(speakers); j++ {
			sa, sb := speakers[i], speakers[j]
			initAB := sa.initTo[sb.address]
			initBA := sb.initTo[sa.address]
			restarts := 0
			if mx := max(initAB, initBA); mx > 0 {
				restarts = mx - 1
			}
			adjacencies = append(adjacencies, EIGRPAdjacency{
				Speakers:      []string{sa.address, sb.address},
				InitExchanged: initAB > 0 && initBA > 0,
				UnicastSeen:   a.unicast[model.PairKey(sa.address, sb.address)],
				Restarts:      restarts,
			})
			if restarts > 0 {
				*issues = append(*issues, model.MakeIssue(
					model.SeverityWarning, "EIGRP_ADJACENCY_RESTART",
					fmt.Sprintf("EIGRP adjacency %s <-> %s restarted %d time(s) (repeated INIT updates)",
						sa.address, sb.address, restarts),
					nil,
				))
			}
		}
	}
	return adjacencies
}

// buildEIGRPSpeakerReports emits per-speaker reports and goodbye/hold-expiry/SIA/query issues.
func (a *EigrpAnalyzer) buildEIGRPSpeakerReports(speakers []*eigrpSpeakerState, ctx model.Context, issues *[]model.Issue) []EIGRPSpeakerReport {
	speakersOut := make([]EIGRPSpeakerReport, 0, len(speakers))
	for _, sp := range speakers {
		for _, gb := range sp.goodbyes {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "EIGRP_GOODBYE",
				fmt.Sprintf("%s sent an EIGRP goodbye: the neighbor was shut down, its configuration removed, or its interface is going down", sp.address),
				[]int{gb.frame},
			))
		}
		for _, gap := range sp.gapsHold {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "EIGRP_HOLD_TIME_EXPIRED",
				fmt.Sprintf("%s sent nothing for %s s (hold time %d s): neighbors declared it down, then it returned",
					sp.address, model.FormatPyFloat(gap.gapS), gap.hold),
				[]int{gap.frame},
			))
		}
		if ctx.End != nil && sp.hold != nil && *sp.hold != 0 && sp.hasLastT {
			if silence := *ctx.End - sp.lastT; silence > float64(*sp.hold) {
				afterGB := len(sp.goodbyes) > 0 && sp.goodbyes[len(sp.goodbyes)-1].t >= sp.lastT-0.001
				if !afterGB {
					*issues = append(*issues, model.MakeIssue(
						model.SeverityError, "EIGRP_NEIGHBOR_SILENT",
						fmt.Sprintf("%s went silent %s s before the capture ended without a goodbye (hold time %d s): it failed or became unreachable",
							sp.address, model.FormatPyFloat(model.Round(silence, 1)), *sp.hold),
						tailFrames(sp.frames, 2),
					))
					lastF := sp.frames[len(sp.frames)-1]
					lastRel := ctx.Rel(&sp.lastT)
					relStr := "None"
					if lastRel != nil {
						relStr = model.FormatPyFloat(*lastRel)
					}
					a.events = append(a.events, eigrpEvent{
						kind: "neighbor_silent", t: sp.lastT + float64(*sp.hold), frame: lastF,
						detail: fmt.Sprintf("%s hold time expired (last packet at %s s); silent until capture end", sp.address, relStr),
					})
				}
			}
		}
		if sq := sp.opcodes["SIA-Query"]; sq > 0 {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "EIGRP_STUCK_IN_ACTIVE",
				fmt.Sprintf("%s sent %d SIA-Query message(s)", sp.address, sq),
				nil,
			))
		}
		if q := sp.opcodes["Query"]; q > 0 {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityInfo, "EIGRP_QUERIES",
				fmt.Sprintf("%s sent %d Query message(s): routes were lost and recomputed", sp.address, q),
				nil,
			))
		}
		var lastT *float64
		if sp.hasLastT {
			lastT = ctx.Rel(&sp.lastT)
		}
		speakersOut = append(speakersOut, EIGRPSpeakerReport{
			Address: sp.address, OverGRE: sp.overGRE, AS: sp.as,
			KValues: sp.k, HoldTime: sp.hold, Hellos: sp.hellos,
			MaxGapS: model.Round(sp.maxGap, 3), Goodbyes: len(sp.goodbyes),
			Messages: maps.Clone(sp.opcodes), InitUpdatesTo: maps.Clone(sp.initTo),
			RouteTLVs: sp.routeTLVs, FirstT: ctx.Rel(&sp.firstT), LastT: lastT,
		})
	}
	return speakersOut
}
