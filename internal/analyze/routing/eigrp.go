// Package routing EIGRP packet ingestion, hold-expiry detection, and link clustering.
package routing

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// eigrpHoldGap records an EIGRP silence interval exceeding hold_time.
type eigrpHoldGap struct {
	gapS  float64
	hold  int
	frame int
}

// eigrpGoodbye captures an EIGRP goodbye or peer termination notification frame.
type eigrpGoodbye struct {
	t     float64
	frame int
}

// eigrpEvent captures an EIGRP timeline event prior to Report emission.
type eigrpEvent struct {
	kind   string
	t      float64
	frame  int
	detail string
}

// eigrpSpeakerState accumulates AS, K-values, opcodes, gaps, and INIT targets for one speaker IP.
type eigrpSpeakerState struct {
	address   string
	as        *int
	k         []int
	hold      *int
	hellos    int
	firstT    float64
	hasLastT  bool
	lastT     float64
	maxGap    float64
	gapsHold  []eigrpHoldGap
	goodbyes  []eigrpGoodbye
	initTo    map[string]int
	opcodes   map[string]int
	routeTLVs int
	frames    []int
	overGRE   bool
}

// EigrpAnalyzer tracks EIGRP speakers, unicast pairs, and AS/K-value mismatches.
type EigrpAnalyzer struct {
	speakerOrder []string
	speakers     map[string]*eigrpSpeakerState
	unicast      map[[2]string]bool
	events       []eigrpEvent
	packets      int
}

// NewEigrpAnalyzer constructs an initialized EigrpAnalyzer.
func NewEigrpAnalyzer() *EigrpAnalyzer {
	return &EigrpAnalyzer{
		speakers: make(map[string]*eigrpSpeakerState),
		unicast:  make(map[[2]string]bool),
	}
}

// Present reports whether any EIGRP packets were seen.
func (a *EigrpAnalyzer) Present() bool { return len(a.speakers) > 0 }

// Feed ingests a single normalized record with EIGRP fields into EigrpAnalyzer.
func (a *EigrpAnalyzer) Feed(rec *model.Record, tunneled bool) {
	eigrp := rec.EIGRP
	if eigrp == nil || rec.IP == nil {
		return
	}
	a.packets++
	src, dst := rec.IP.Src, rec.IP.Dst
	t, n := rec.T, rec.N
	sp, ok := a.speakers[src]
	if !ok {
		sp = &eigrpSpeakerState{
			address: src,
			as:      eigrp.AS,
			firstT:  t,
			initTo:  make(map[string]int),
			opcodes: make(map[string]int),
		}
		a.speakers[src] = sp
		a.speakerOrder = append(a.speakerOrder, src)
	}
	sp.overGRE = sp.overGRE || tunneled

	if sp.hasLastT {
		gap := t - sp.lastT
		if gap > sp.maxGap {
			sp.maxGap = gap
		}
		if sp.hold != nil && *sp.hold != 0 && gap > float64(*sp.hold) {
			sp.gapsHold = append(sp.gapsHold, eigrpHoldGap{gapS: model.Round(gap, 3), hold: *sp.hold, frame: n})
			a.events = append(a.events, eigrpEvent{
				kind: "hold_expired", t: sp.lastT + float64(*sp.hold), frame: n,
				detail: fmt.Sprintf("%s silent for %s s (hold %d s): neighbors drop it",
					src, model.FormatPyFloat(model.Round(gap, 1)), *sp.hold),
			})
		}
	}
	sp.hasLastT = true
	sp.lastT = t
	sp.as = eigrp.AS
	model.AddFrame(&sp.frames, n)

	opcode := 0
	if eigrp.Opcode != nil {
		opcode = *eigrp.Opcode
	}
	isAck := opcode == 5 && eigrp.Ack != 0 && len(eigrp.TLVs) == 0
	var opName string
	if isAck {
		opName = "Ack"
	} else if name, found := model.EIGRPOpcodes[opcode]; found {
		opName = name
	} else {
		opName = fmt.Sprintf("opcode_%d", opcode)
	}
	sp.opcodes[opName]++

	if !strings.HasPrefix(dst, "224.") && !strings.HasPrefix(strings.ToLower(dst), "ff0") {
		a.unicast[model.PairKey(src, dst)] = true
	}
	if eigrp.K != nil {
		if isAll255(eigrp.K) {
			sp.goodbyes = append(sp.goodbyes, eigrpGoodbye{t: t, frame: n})
			a.events = append(a.events, eigrpEvent{
				kind: "goodbye", t: t, frame: n,
				detail: src + " sent an EIGRP goodbye (neighbor shut down or removed)",
			})
		} else {
			sp.k = slices.Clone(eigrp.K)
			sp.hold = eigrp.Hold
		}
	}
	if slices.Contains(eigrp.TLVs, 0x0007) {
		sp.goodbyes = append(sp.goodbyes, eigrpGoodbye{t: t, frame: n})
		a.events = append(a.events, eigrpEvent{
			kind: "goodbye", t: t, frame: n,
			detail: src + " sent a peer termination TLV",
		})
	}
	if opcode == 5 && !isAck {
		sp.hellos++
	}
	if opcode == 1 && (eigrp.Flags&0x01) != 0 {
		sp.initTo[dst]++
		a.events = append(a.events, eigrpEvent{
			kind: "adjacency_init", t: t, frame: n,
			detail: fmt.Sprintf("%s sent INIT update to %s (adjacency starting)", src, dst),
		})
	}
	for _, tlv := range eigrp.TLVs {
		switch tlv {
		case 0x0102, 0x0103, 0x0402, 0x0403, 0x0602, 0x0603:
			sp.routeTLVs++
		}
	}
	if opcode == 3 {
		a.events = append(a.events, eigrpEvent{
			kind: "query", t: t, frame: n,
			detail: src + " sent a Query (a route was lost and is being recomputed)",
		})
	} else if opcode == 10 {
		a.events = append(a.events, eigrpEvent{
			kind: "sia_query", t: t, frame: n,
			detail: src + " sent an SIA-Query (route stuck in active)",
		})
	}
}

// groupLinks clusters EIGRP speakers sharing unicast conversations or an IPv4 /24 prefix.
func (a *EigrpAnalyzer) groupLinks() [][]string {
	parent := make(map[string]string, len(a.speakerOrder))
	find := func(x string) string {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(x, y string) {
		rx, ry := find(x), find(y)
		if rx != ry {
			parent[ry] = rx
		}
	}

	for _, addr := range a.speakerOrder {
		parent[addr] = addr
	}
	for pk := range a.unicast {
		if _, okA := a.speakers[pk[0]]; okA {
			if _, okB := a.speakers[pk[1]]; okB {
				union(pk[0], pk[1])
			}
		}
	}
	for i := 0; i < len(a.speakerOrder); i++ {
		aa, errA := netip.ParseAddr(a.speakerOrder[i])
		if errA != nil || !aa.Is4() {
			continue
		}
		pfx := netip.PrefixFrom(aa, 24).Masked()
		for j := i + 1; j < len(a.speakerOrder); j++ {
			ab, errB := netip.ParseAddr(a.speakerOrder[j])
			if errB == nil && ab.Is4() && pfx.Contains(ab) {
				union(a.speakerOrder[i], a.speakerOrder[j])
			}
		}
	}

	var repOrd []string
	groups := make(map[string][]string)
	for _, addr := range a.speakerOrder {
		rep := find(addr)
		if _, exists := groups[rep]; !exists {
			repOrd = append(repOrd, rep)
		}
		groups[rep] = append(groups[rep], addr)
	}
	out := make([][]string, 0, len(repOrd))
	for _, rep := range repOrd {
		out = append(out, groups[rep])
	}
	return out
}

// isAll255 reports whether all 6 K-values equal 255 (EIGRP goodbye encoding).
func isAll255(k []int) bool {
	if len(k) != 6 {
		return false
	}
	for _, v := range k {
		if v != 255 {
			return false
		}
	}
	return true
}

// formatKSlice formats EIGRP K-values like Python list repr ("[1, 0, 1, 0, 0, 0]").
func formatKSlice(k []int) string {
	parts := make([]string, len(k))
	for i, v := range k {
		parts[i] = strconv.Itoa(v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
