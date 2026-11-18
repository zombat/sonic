// Package pathmtu implements IPv4 fragment group tracking, reassembly analysis,
// and missing/overlapping piece detection.
package pathmtu

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

type fragGroupKey struct {
	src      string
	dst      string
	hasProto bool
	proto    int
	hasID    bool
	id       int
}

type fragPiece struct {
	off    int
	length int
	mf     int
	n      int
}

type fragGroup struct {
	src              string
	dst              string
	proto            *int
	id               *int
	pieces           []fragPiece
	firstT           float64
	lastT            float64
	frames           []int
	hasFirstFragLen  bool
	firstFragmentLen int
}

func (d *PathMtuDetector) feedFragment(rec *model.Record) {
	ip, dp := rec.IP, rec.DP
	key := fragGroupKey{src: ip.Src, dst: ip.Dst}
	if ip.Proto != nil {
		key.hasProto, key.proto = true, *ip.Proto
	}
	if dp.ID != nil {
		key.hasID, key.id = true, *dp.ID
	}
	group, ok := d.fragGroups[key]
	if !ok {
		if len(d.fragGroups) >= maxFragmentGroups && len(d.fragGroupOrder) > 0 {
			delete(d.fragGroups, d.fragGroupOrder[0])
			d.fragGroupOrder = d.fragGroupOrder[1:]
			d.fragGroupsDropped++
		}
		group = &fragGroup{
			src: ip.Src, dst: ip.Dst, proto: ip.Proto, id: dp.ID,
			firstT: rec.T, lastT: rec.T, frames: []int{},
		}
		d.fragGroups[key] = group
		d.fragGroupOrder = append(d.fragGroupOrder, key)
	}
	group.lastT = rec.T
	model.AddFrame(&group.frames, rec.N)
	mf := 0
	if dp.MF != nil {
		mf = *dp.MF
	}
	if len(group.pieces) < 128 {
		group.pieces = append(group.pieces, fragPiece{
			off: dp.Off, length: max(dp.TL-dp.HL, 0), mf: mf, n: rec.N,
		})
	}
	if dp.Off == 0 {
		group.hasFirstFragLen = true
		group.firstFragmentLen = dp.TL
	}
}

func (d *PathMtuDetector) reportFragments(ctx model.Context, issues *[]model.Issue, events *[]model.Event) FragmentReport {
	complete := 0
	incomplete := []IncompleteGroup{}
	overlapping := []OverlappingGroup{}

	type pairKey struct {
		src      string
		dst      string
		hasProto bool
		proto    int
	}
	type pairAgg struct {
		src        string
		dst        string
		proto      *int
		datagrams  int
		firstSizes map[int]bool
		incomplete int
	}
	var pairOrder []pairKey
	byPair := make(map[pairKey]*pairAgg)

	for _, fk := range d.fragGroupOrder {
		group, ok := d.fragGroups[fk]
		if !ok {
			continue
		}
		pieces := slices.Clone(group.pieces)
		slices.SortFunc(pieces, func(a, b fragPiece) int {
			if a.off != b.off {
				return a.off - b.off
			}
			if a.length != b.length {
				return a.length - b.length
			}
			if a.mf != b.mf {
				return a.mf - b.mf
			}
			return a.n - b.n
		})

		pk := pairKey{src: group.src, dst: group.dst}
		if group.proto != nil {
			pk.hasProto, pk.proto = true, *group.proto
		}
		pa, exists := byPair[pk]
		if !exists {
			pa = &pairAgg{
				src: group.src, dst: group.dst, proto: group.proto, firstSizes: make(map[int]bool),
			}
			byPair[pk] = pa
			pairOrder = append(pairOrder, pk)
		}
		pa.datagrams++
		if group.hasFirstFragLen && group.firstFragmentLen != 0 {
			pa.firstSizes[group.firstFragmentLen] = true
		}

		covered := 0
		gap, overlap := false, false
		seen := make(map[[2]int]bool)
		hasFirst, hasLast := false, false
		for _, p := range pieces {
			if p.off == 0 {
				hasFirst = true
			}
			if p.mf == 0 {
				hasLast = true
			}
			ol := [2]int{p.off, p.length}
			if seen[ol] {
				continue
			}
			seen[ol] = true
			if p.off > covered {
				gap = true
			} else if p.off < covered {
				overlap = true
			}
			if end := p.off + p.length; end > covered {
				covered = end
			}
		}

		var missing []string
		if !hasFirst {
			missing = append(missing, "first")
		}
		if gap {
			missing = append(missing, "middle")
		}
		if !hasLast {
			missing = append(missing, "last")
		}
		if overlap {
			overlapping = append(overlapping, OverlappingGroup{
				Src: group.src, Dst: group.dst, Protocol: group.proto, ID: group.id, Frames: group.frames,
			})
		}
		if len(missing) > 0 {
			pa.incomplete++
			incomplete = append(incomplete, IncompleteGroup{
				Src: group.src, Dst: group.dst, Protocol: group.proto, ID: group.id,
				Missing: missing, PiecesSeen: len(seen),
				FirstT: ctx.Rel(&group.firstT), Frames: group.frames,
			})
		} else {
			complete++
		}
	}

	if len(incomplete) > 0 {
		first := incomplete[0]
		idStr := "None"
		if first.ID != nil {
			idStr = fmt.Sprintf("%d", *first.ID)
		}
		text := fmt.Sprintf("%d fragmented datagram(s) incomplete at this capture point (e.g. %s -> %s id %s: %s fragment missing); the receiver cannot reassemble them",
			len(incomplete), first.Src, first.Dst, idStr, strings.Join(first.Missing, ", "))
		*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "FRAGMENT_INCOMPLETE", text, first.Frames))
		evT := 0.0
		if ctx.Start != nil && first.FirstT != nil {
			evT = *ctx.Start + *first.FirstT
		}
		var fr *int
		if len(first.Frames) > 0 {
			f := first.Frames[0]
			fr = &f
		}
		*events = append(*events, model.MakeEvent(ctx, evT, "ip", "fragment_incomplete", text, fr))
	}
	if len(overlapping) > 0 {
		text := fmt.Sprintf("%d datagram(s) with overlapping fragments (a broken fragmenter or an evasion attempt; many hosts drop them)", len(overlapping))
		*issues = append(*issues, model.MakeIssue(model.SeverityError, "FRAGMENT_OVERLAP", text, overlapping[0].Frames))
	}

	aggs := make([]*pairAgg, 0, len(pairOrder))
	for _, pk := range pairOrder {
		aggs = append(aggs, byPair[pk])
	}
	slices.SortStableFunc(aggs, func(a, b *pairAgg) int {
		return b.datagrams - a.datagrams
	})
	pairsOut := make([]FragmentPair, 0, len(aggs))
	totalDatagrams := 0
	for _, pa := range aggs {
		totalDatagrams += pa.datagrams
		sizes := make([]int, 0, len(pa.firstSizes))
		for s := range pa.firstSizes {
			sizes = append(sizes, s)
		}
		slices.Sort(sizes)
		var splitPtr *int
		if len(sizes) > 0 {
			v := sizes[len(sizes)-1]
			splitPtr = &v
		}
		pairsOut = append(pairsOut, FragmentPair{
			Src: pa.src, Dst: pa.dst, Protocol: pa.proto, Datagrams: pa.datagrams,
			FirstFragmentSizes: sizes, SplitAtMTU: splitPtr, Incomplete: pa.incomplete,
		})
	}
	if len(pairsOut) > 0 && len(incomplete) == 0 {
		top := pairsOut[0]
		mtuStr := "None"
		if top.SplitAtMTU != nil {
			mtuStr = fmt.Sprintf("%d", *top.SplitAtMTU)
		}
		text := fmt.Sprintf("%d datagram(s) fragmented; e.g. %s -> %s split at %s bytes",
			totalDatagrams, top.Src, top.Dst, mtuStr)
		*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "IP_FRAGMENTATION", text, nil))
	}

	incList, incOm := model.Cap(incomplete, ctx.MaxItems)
	pairsList, pairsOm := model.Cap(pairsOut, ctx.MaxItems)
	ovCap, _ := model.Cap(overlapping, ctx.MaxItems)
	return FragmentReport{
		Datagrams: len(d.fragGroups), Complete: complete, IncompleteCount: len(incomplete),
		Incomplete: incList, IncompleteOmitted: incOm, Overlapping: ovCap,
		ByPair: pairsList, ByPairOmitted: pairsOm, GroupsDroppedAtCap: d.fragGroupsDropped,
	}
}
