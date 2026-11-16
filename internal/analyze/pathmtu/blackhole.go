// Package pathmtu implements ICMP Echo and TCP PMTUD black-hole analysis and verdict text.
package pathmtu

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// echoBlackHoles finds ICMP Echo pairs where smaller DF probes passed and larger probes vanished without PTB.
func (d *PathMtuDetector) echoBlackHoles(ctx model.Context, issues *[]model.Issue, events *[]model.Event) []BlackHole {
	var pairOrder [][2]string
	byPair := make(map[[2]string][]*probeEntry)
	for _, pk := range d.probeOrder {
		pr, ok := d.probes[pk]
		if !ok || !pr.hasEcho {
			continue
		}
		key := [2]string{pr.src, pr.dst}
		if _, exists := byPair[key]; !exists {
			pairOrder = append(pairOrder, key)
		}
		byPair[key] = append(byPair[key], pr)
	}

	var hasPendingCut bool
	var pendingCut float64
	if ctx.End != nil {
		hasPendingCut = true
		pendingCut = *ctx.End - pendingWindowS
	}
	out := []BlackHole{}
	for _, key := range pairOrder {
		if d.ptbTargets[key] {
			continue
		}
		probes := byPair[key]
		hasOK, largestOK := false, 0
		var vanished []*probeEntry
		for _, p := range probes {
			if p.answered {
				if !hasOK || p.length > largestOK {
					hasOK, largestOK = true, p.length
				}
			} else if !p.ptb && !(hasPendingCut && p.t > pendingCut) {
				vanished = append(vanished, p)
			}
		}
		if len(vanished) == 0 || !hasOK {
			continue
		}
		slices.SortStableFunc(vanished, func(a, b *probeEntry) int {
			if a.t < b.t {
				return -1
			}
			if a.t > b.t {
				return 1
			}
			return 0
		})
		smallestLost := vanished[0].length
		for _, p := range vanished[1:] {
			if p.length < smallestLost {
				smallestLost = p.length
			}
		}
		if largestOK >= smallestLost {
			continue
		}
		frames := make([]int, 0, min(len(vanished), 10))
		for i := 0; i < len(vanished) && i < 10; i++ {
			frames = append(frames, vanished[i].n)
		}
		src, dst := key[0], key[1]
		text := fmt.Sprintf("PMTUD black hole %s -> %s: DF probes up to %d bytes answered, %d probe(s) of %d bytes or more vanished with no ICMP Fragmentation Needed seen; path MTU is between %d and %d",
			src, dst, largestOK, len(vanished), smallestLost, largestOK, smallestLost-1)
		*issues = append(*issues, model.MakeIssue(model.SeverityError, "PMTU_BLACK_HOLE", text, frames))
		fn := vanished[0].n
		*events = append(*events, model.MakeEvent(ctx, vanished[0].t, "icmp", "pmtu_black_hole", text, &fn))
		out = append(out, BlackHole{
			Kind: "icmp_echo", Src: src, Dst: dst, LargestAnswered: largestOK, SmallestVanish: smallestLost,
			VanishedProbes: len(vanished), PathMTUBetween: [2]int{largestOK, smallestLost - 1}, Frames: frames,
		})
	}
	return out
}

// tcpBlackHoles identifies TCP flows where small DF segments are acknowledged while larger retransmitted DF segments are not.
func (d *PathMtuDetector) tcpBlackHoles(ctx model.Context, issues *[]model.Issue, events *[]model.Event) []BlackHole {
	out := []BlackHole{}
	for _, fk := range d.tcpFlowOrder {
		flow, ok := d.tcpFlows[fk]
		if !ok || d.ptbTargets[[2]string{flow.src, flow.dst}] {
			continue
		}
		var stuck []*tcpSegTrack
		for _, seg := range flow.segments {
			if seg.sent >= 2 {
				stuck = append(stuck, seg)
			}
		}
		if len(stuck) == 0 || flow.maxAckedSize == 0 {
			continue
		}
		slices.SortStableFunc(stuck, func(a, b *tcpSegTrack) int {
			if a.t < b.t {
				return -1
			}
			if a.t > b.t {
				return 1
			}
			return 0
		})
		smallest := stuck[0].length
		for _, s := range stuck[1:] {
			if s.length < smallest {
				smallest = s.length
			}
		}
		if flow.maxAckedSize >= smallest {
			continue
		}
		var frames []int
		for _, s := range stuck {
			frames = append(frames, s.frames...)
		}
		if len(frames) > 10 {
			frames = frames[:10]
		}
		text := fmt.Sprintf("TCP black hole %s:%d -> %s:%d: %d DF segment(s) of %d+ bytes retransmitted and never acknowledged while segments up to %d bytes were; no ICMP seen: lower the MSS (ip tcp adjust-mss) or let ICMP type 3 code 4 through",
			flow.src, flow.sport, flow.dst, flow.dport, len(stuck), smallest, flow.maxAckedSize)
		*issues = append(*issues, model.MakeIssue(model.SeverityError, "TCP_PMTU_BLACK_HOLE", text, frames))
		fn := stuck[0].n
		*events = append(*events, model.MakeEvent(ctx, stuck[0].t, "tcp", "pmtu_black_hole", text, &fn))
		sp, dp := flow.sport, flow.dport
		out = append(out, BlackHole{
			Kind: "tcp", Src: flow.src, Dst: flow.dst, Sport: &sp, Dport: &dp,
			LargestAnswered: flow.maxAckedSize, SmallestVanish: smallest,
			VanishedProbes: len(stuck), PathMTUBetween: [2]int{flow.maxAckedSize, smallest - 1}, Frames: frames,
		})
	}
	return out
}

// buildVerdict summarizes PTB notifications, PMTUD black holes, and IPv4 fragmentation in one sentence.
func (d *PathMtuDetector) buildVerdict(present bool, ptb []PTBEntry, holes []BlackHole, frags FragmentReport) string {
	if !present {
		return "No large DF packets, no Fragmentation Needed and no fragments in this capture."
	}
	var parts []string
	if len(ptb) > 0 {
		total := 0
		mtuSet := make(map[int]bool)
		for _, p := range ptb {
			total += p.Count
			if p.MTU != nil && *p.MTU != 0 {
				mtuSet[*p.MTU] = true
			}
		}
		s := fmt.Sprintf("%d Fragmentation Needed / Packet Too Big", total)
		if len(mtuSet) > 0 {
			mtus := make([]int, 0, len(mtuSet))
			for m := range mtuSet {
				mtus = append(mtus, m)
			}
			slices.Sort(mtus)
			mStr := make([]string, len(mtus))
			for i, m := range mtus {
				mStr[i] = strconv.Itoa(m)
			}
			s += " advertising MTU " + strings.Join(mStr, ", ")
		} else {
			s += " without an MTU"
		}
		parts = append(parts, s)
	}
	if len(holes) > 0 {
		h := holes[0]
		parts = append(parts, fmt.Sprintf("PMTUD black hole %s -> %s (path MTU between %d and %d)",
			h.Src, h.Dst, h.PathMTUBetween[0], h.PathMTUBetween[1]))
	}
	if frags.Datagrams > 0 {
		s := fmt.Sprintf("%d fragmented datagram(s)", frags.Datagrams)
		if frags.IncompleteCount > 0 {
			s += fmt.Sprintf(", %d incomplete", frags.IncompleteCount)
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d DF packet(s) over 576 bytes, largest %d; no Fragmentation Needed, no fragments, no black hole.", d.dfLarge, d.largestDF)
	}
	return strings.Join(parts, "; ") + "."
}

// strOrNone dereferences s or returns Python's "None" string literal.
func strOrNone(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}
