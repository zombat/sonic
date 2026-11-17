// Package correlate aggregates transit timing, NAT mappings, and DSCP rewrite tables.
package correlate

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

type addrPort struct {
	addr    string
	port    int
	hasPort bool
}

func formatAddrPort(ap addrPort) string {
	var p *int
	if ap.hasPort {
		v := ap.port
		p = &v
	}
	return model.Endpoint(ap.addr, p)
}

func canonicalEndpointPair(a, b addrPort) [2]addrPort {
	if a.addr < b.addr {
		return [2]addrPort{a, b}
	}
	if a.addr > b.addr {
		return [2]addrPort{b, a}
	}
	if a.hasPort != b.hasPort {
		if !a.hasPort {
			return [2]addrPort{a, b}
		}
		return [2]addrPort{b, a}
	}
	if a.port <= b.port {
		return [2]addrPort{a, b}
	}
	return [2]addrPort{b, a}
}

func formatPyFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.ContainsRune(s, '.') && !strings.ContainsRune(s, 'e') && !strings.ContainsRune(s, 'E') {
		return s + ".0"
	}
	return s
}

func buildTransit(corr *correlator, labels []string) []TransitRow {
	keys := make([]capPairKey, 0, len(corr.pairs))
	for k := range corr.pairs {
		keys = append(keys, k)
	}
	slices.SortStableFunc(keys, func(a, b capPairKey) int {
		if a.lo != b.lo {
			return a.lo - b.lo
		}
		return a.hi - b.hi
	})
	out := make([]TransitRow, 0, len(keys))
	for _, k := range keys {
		st := corr.pairs[k]
		var deltaPtr *DeltaStats
		var notePtr *string
		if len(st.deltas) > 0 {
			minD, maxD := st.deltas[0], st.deltas[0]
			for _, d := range st.deltas[1:] {
				if d < minD {
					minD = d
				}
				if d > maxD {
					maxD = d
				}
			}
			med := *model.Median(st.deltas)
			medMS := model.Round(med*1000, 3)
			deltaPtr = &DeltaStats{
				Min:    model.Round(minD*1000, 3),
				Median: medMS,
				Max:    model.Round(maxD*1000, 3),
			}
			dir := "after"
			if med < 0 {
				dir = "before"
			}
			note := fmt.Sprintf("%s sees packets %s ms %s %s (median, both directions; includes any clock offset)",
				labels[k.hi], formatPyFloat(math.Abs(medMS)), dir, labels[k.lo])
			notePtr = &note
		}
		var ttlPtr *int
		if len(st.ttlOrder) > 0 {
			bestVal, bestCnt := st.ttlOrder[0], -1
			for _, dec := range st.ttlOrder {
				if st.ttlCount[dec] > bestCnt {
					bestVal, bestCnt = dec, st.ttlCount[dec]
				}
			}
			v := bestVal
			ttlPtr = &v
		}
		out = append(out, TransitRow{
			From:           labels[k.lo],
			To:             labels[k.hi],
			PacketsMatched: st.matched,
			DeltaMS:        deltaPtr,
			TTLDecrement:   ttlPtr,
			Note:           notePtr,
		})
	}
	return out
}

func buildNAT(corr *correlator, labels []string) []NATRow {
	type natMergeKey struct {
		lo    int
		hi    int
		proto int
		pair  [2]addrPort
	}
	merged := make(map[natMergeKey]*NATRow)
	order := []natMergeKey{}

	for _, nk := range corr.natOrder {
		entry := corr.nat[nk]
		lo, x := nk.ca, nk.ta
		hi, y := nk.cb, nk.tb
		if lo > hi {
			lo, x, hi, y = hi, y, lo, x
		}
		type natChange struct {
			kind   string
			before addrPort
			after  addrPort
			remote addrPort
		}
		var changed []natChange
		if x.Proto == 1 || x.Proto == 58 {
			if x.Src != y.Src {
				changed = append(changed, natChange{
					kind:   "source",
					before: addrPort{addr: x.Src, port: x.Sport, hasPort: x.HasSport},
					after:  addrPort{addr: y.Src, port: y.Sport, hasPort: y.HasSport},
					remote: addrPort{addr: x.Dst},
				})
			}
			if x.Dst != y.Dst {
				changed = append(changed, natChange{
					kind:   "destination",
					before: addrPort{addr: x.Dst, port: x.Dport, hasPort: x.HasDport},
					after:  addrPort{addr: y.Dst, port: y.Dport, hasPort: y.HasDport},
					remote: addrPort{addr: x.Src},
				})
			}
		} else {
			if x.Src != y.Src || x.HasSport != y.HasSport || x.Sport != y.Sport {
				changed = append(changed, natChange{
					kind:   "source",
					before: addrPort{addr: x.Src, port: x.Sport, hasPort: x.HasSport},
					after:  addrPort{addr: y.Src, port: y.Sport, hasPort: y.HasSport},
					remote: addrPort{addr: x.Dst, port: x.Dport, hasPort: x.HasDport},
				})
			}
			if x.Dst != y.Dst || x.HasDport != y.HasDport || x.Dport != y.Dport {
				changed = append(changed, natChange{
					kind:   "destination",
					before: addrPort{addr: x.Dst, port: x.Dport, hasPort: x.HasDport},
					after:  addrPort{addr: y.Dst, port: y.Dport, hasPort: y.HasDport},
					remote: addrPort{addr: x.Src, port: x.Sport, hasPort: x.HasSport},
				})
			}
		}

		for _, ch := range changed {
			mk := natMergeKey{lo: lo, hi: hi, proto: x.Proto, pair: canonicalEndpointPair(ch.before, ch.after)}
			item, ok := merged[mk]
			if !ok {
				kindText := ch.kind + " NAT"
				if ch.before.hasPort != ch.after.hasPort || ch.before.port != ch.after.port {
					kindText += " with port/id translation"
				}
				item = &NATRow{
					Protocol: protoLabel(x.Proto),
					Between:  [2]string{labels[lo], labels[hi]},
					AtLoKey:  labels[lo],
					AtLoVal:  formatAddrPort(ch.before),
					AtHiKey:  labels[hi],
					AtHiVal:  formatAddrPort(ch.after),
					Remote:   formatAddrPort(ch.remote),
					Kind:     kindText,
					Frames:   make(map[string]int),
				}
				merged[mk] = item
				order = append(order, mk)
			}
			item.Packets += entry.packets
			for lbl, fn := range entry.frames {
				if _, exists := item.Frames[lbl]; !exists {
					item.Frames[lbl] = fn
				}
			}
		}
	}

	out := make([]NATRow, 0, len(order))
	for _, mk := range order {
		out = append(out, *merged[mk])
	}
	slices.SortStableFunc(out, func(a, b NATRow) int {
		return b.Packets - a.Packets
	})
	return out
}

func buildDSCPChanges(corr *correlator, labels []string) []DSCPChangeRow {
	keys := slices.Clone(corr.dscpOrder)
	slices.SortStableFunc(keys, func(a, b dscpKey) int {
		return corr.dscp[b].packets - corr.dscp[a].packets
	})
	out := make([]DSCPChangeRow, 0, len(keys))
	for _, dk := range keys {
		entry := corr.dscp[dk]
		before, after := dk.da, dk.db
		out = append(out, DSCPChangeRow{
			From:       labels[dk.ca],
			To:         labels[dk.cb],
			Flow:       tupleText(dk.tup),
			DSCPBefore: model.DSCPName(&before),
			DSCPAfter:  model.DSCPName(&after),
			Packets:    entry.packets,
			Frames:     entry.frames,
		})
	}
	return out
}
