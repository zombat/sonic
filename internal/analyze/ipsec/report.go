// Package ipsec NAT-T summary, negotiation verdict formatting, and top-level Report.
package ipsec

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report compiles IKE SAs, ESP flows, peer encryption verdicts, and NAT-T summary into Report.
func (d *Detector) Report(ctx model.Context) Report {
	issues := []model.Issue{}
	events := []model.Event{}

	espPairs := make(map[[2]string][]*espFlow)
	for _, flow := range d.esp {
		pk := model.PairKey(flow.src, flow.dst)
		espPairs[pk] = append(espPairs[pk], flow)
	}
	for pk, list := range espPairs {
		slices.SortStableFunc(list, func(a, b *espFlow) int {
			return cmp.Compare(a.firstT, b.firstT)
		})
		espPairs[pk] = list
	}

	sasSorted := make([]*ikeSA, 0, len(d.sas))
	for _, sa := range d.sas {
		sasSorted = append(sasSorted, sa)
	}
	slices.SortStableFunc(sasSorted, func(a, b *ikeSA) int {
		at, bt := 0.0, 0.0
		if a.hasTime {
			at = a.firstT
		}
		if b.hasTime {
			bt = b.firstT
		}
		if c := cmp.Compare(at, bt); c != 0 {
			return c
		}
		return cmp.Compare(a.ispi, b.ispi)
	})

	ikeSAs := make([]IKESAReport, 0, len(sasSorted))
	for _, sa := range sasSorted {
		ikeSAs = append(ikeSAs, d.reportSA(sa, ctx, espPairs, &issues, &events))
	}
	reportCollisions(ikeSAs, &issues, &events, ctx)
	espFlows := d.reportESP(ctx, &issues, &events)

	encPairs, encOmitted, cleartext, encCode, encVerdict := d.reportEncryption(ctx, &issues)
	nat := d.reportNAT()

	present := d.Present()
	status := model.StatusFromIssues(issues, present)
	verdict := "No IPsec (IKE/ESP) or GRE tunnel traffic in this capture."
	if present {
		verdict = encVerdict
	}
	negotiationVerdict := buildNegotiationVerdict(ikeSAs)
	anyNotEstablished := false
	establishedCount := 0
	for _, sa := range ikeSAs {
		if sa.Outcome != "established" {
			anyNotEstablished = true
		} else {
			establishedCount++
		}
	}
	if present && anyNotEstablished {
		verdict = fmt.Sprintf("%s; IKE: %s", verdict, negotiationVerdict)
	}

	totalESPPkts := 0
	for _, flow := range d.esp {
		totalESPPkts += flow.packets
	}

	ikeList, ikeOm := model.Cap(ikeSAs, ctx.MaxItems)
	espList, espOm := model.Cap(espFlows, ctx.MaxItems)

	return Report{
		Detector:           d.Name(),
		Status:             status,
		Verdict:            verdict,
		EncryptionVerdict:  encCode.String(),
		NegotiationVerdict: negotiationVerdict,
		Summary: Summary{
			IKEPackets:        d.ikePackets,
			IKESAs:            len(d.sas),
			IKESAsEstablished: establishedCount,
			ESPFlows:          len(d.esp),
			ESPPackets:        totalESPPkts,
			NATKeepalives:     d.keepalives,
		},
		PeerPairs:        encPairs,
		PeerPairsOmitted: encOmitted,
		Cleartext:        cleartext,
		IKESAs:           ikeList,
		IKESAsOmitted:    ikeOm,
		ESPFlows:         espList,
		ESPFlowsOmitted:  espOm,
		NATTraversal:     nat,
		Issues:           model.SortIssues(issues),
		Events:           events,
	}
}

// reportNAT summarizes NAT-T encapsulation, UDP 4500 float, and NAT_DETECTION payloads.
func (d *Detector) reportNAT() NATTraversalReport {
	udpFlows := 0
	for _, fl := range d.esp {
		if fl.udp {
			udpFlows++
		}
	}
	inUse := d.ikeOn4500 > 0 || udpFlows > 0 || d.keepalives > 0
	var verdict string
	switch {
	case inUse:
		var parts []string
		if d.ikeOn4500 > 0 {
			parts = append(parts, fmt.Sprintf("IKE on UDP 4500 (%d packets)", d.ikeOn4500))
		}
		if udpFlows > 0 {
			parts = append(parts, fmt.Sprintf("%d ESP-in-UDP flow(s)", udpFlows))
		}
		if d.keepalives > 0 {
			parts = append(parts, fmt.Sprintf("%d NAT keepalive(s)", d.keepalives))
		}
		verdict = "NAT-T in use: " + strings.Join(parts, ", ")
	case d.natDetection:
		verdict = "NAT detection payloads exchanged; no NAT found (IKE stayed on UDP 500, ESP not encapsulated)"
	default:
		verdict = "NAT-T not in use"
	}
	return NATTraversalReport{
		InUse:                    inUse,
		IKEPacketsOn4500:         d.ikeOn4500,
		ESPInUDPFlows:            udpFlows,
		NATKeepalives:            d.keepalives,
		KeepaliveFrames:          nonNilInts(d.keepaliveFrames),
		NATDetectionPayloadsSeen: d.natDetection,
		Verdict:                  verdict,
	}
}

// buildNegotiationVerdict summarizes observed IKE SA counts grouped by descending frequency.
func buildNegotiationVerdict(ikeSAs []IKESAReport) string {
	if len(ikeSAs) == 0 {
		return "no IKE seen"
	}
	type item struct {
		outcome string
		count   int
		first   int
	}
	idxMap := make(map[string]int)
	var items []item
	for _, sa := range ikeSAs {
		if idx, ok := idxMap[sa.Outcome]; ok {
			items[idx].count++
		} else {
			idxMap[sa.Outcome] = len(items)
			items = append(items, item{outcome: sa.Outcome, count: 1, first: len(items)})
		}
	}
	slices.SortFunc(items, func(a, b item) int {
		if c := cmp.Compare(b.count, a.count); c != 0 {
			return c
		}
		return cmp.Compare(a.first, b.first)
	})
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = fmt.Sprintf("%d %s", it.count, strings.ReplaceAll(it.outcome, "_", " "))
	}
	return fmt.Sprintf("%d IKE SA(s): %s", len(ikeSAs), strings.Join(parts, ", "))
}

// nonNilInts ensures a non-nil slice for JSON [] encoding.
func nonNilInts(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}

// sortedKeys returns lexicographically sorted keys of a string set as a non-nil slice.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// optStr renders *s or "None".
func optStr(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

// optStrEmpty renders *s or "".
func optStrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// optInt renders *v or "None".
func optInt(v *int) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprintf("%d", *v)
}

// strPtrEq compares two optional string pointers by dereferenced value.
func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// filterNonEmpty drops empty strings while preserving slice order.
func filterNonEmpty(items []string) []string {
	var out []string
	for _, s := range items {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
