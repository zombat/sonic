// Package routing OSPFv2 packet ingestion, Hello neighbor diffing, and DBD tracking.
package routing

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// ospfRouterKey uniquely identifies an OSPF speaker on a link by router ID and IP address.
type ospfRouterKey struct {
	rid  string
	addr string
}

// ospfHelloGap captures an interval between consecutive OSPF Hellos exceeding dead_interval.
type ospfHelloGap struct {
	fromT        float64
	toT          float64
	gapS         float64
	deadInterval int
	frame        int
}

// ospfDBDEntry records a single OSPFv2 Database Description packet on a directional flow.
type ospfDBDEntry struct {
	t     float64
	n     int
	flags int
	seq   *uint32
	mtu   *int
	rid   string
}

// ospfEvent captures an OSPF timeline event prior to final Report emission.
type ospfEvent struct {
	kind   string
	t      float64
	frame  int
	detail string
}

// ospfRouterState accumulates parameters, hello gaps, and neighbor lists for one router.
type ospfRouterState struct {
	rid          string
	address      string
	area         *string
	auth         *int
	mask         *string
	hello        *int
	dead         *int
	prio         *int
	options      *int
	dr           *string
	bdr          *string
	hasNeighbors bool
	neighbors    map[string]bool
	hellos       int
	firstT       float64
	lastT        float64
	hasLastHello bool
	lastHelloT   float64
	maxHelloGap  float64
	gapsOverDead []ospfHelloGap
	mtu          *int
	types        map[int]int
	frames       []int
	everListed   map[string]bool
	overGRE      bool
}

// addrDirKey represents a directional IP pair for OSPF DBD/LSA exchanges.
type addrDirKey struct {
	src string
	dst string
}

// OspfAnalyzer tracks OSPFv2 routers, Hellos, adjacencies, and DBD exchanges.
type OspfAnalyzer struct {
	routerOrd []ospfRouterKey
	routers   map[ospfRouterKey]*ospfRouterState
	exchange  map[addrDirKey]map[int]int
	dbdOrder  []addrDirKey
	dbds      map[addrDirKey][]ospfDBDEntry
	events    []ospfEvent
	packets   int
}

// NewOspfAnalyzer constructs an initialized OspfAnalyzer.
func NewOspfAnalyzer() *OspfAnalyzer {
	return &OspfAnalyzer{
		routers:  make(map[ospfRouterKey]*ospfRouterState),
		exchange: make(map[addrDirKey]map[int]int),
		dbds:     make(map[addrDirKey][]ospfDBDEntry),
	}
}

// Present reports whether any OSPF packets were observed.
func (a *OspfAnalyzer) Present() bool { return len(a.routers) > 0 }

// Feed ingests one normalized record containing OSPF fields into OspfAnalyzer.
func (a *OspfAnalyzer) Feed(rec *model.Record, tunneled bool) {
	ospf := rec.OSPF
	if ospf == nil || rec.IP == nil {
		return
	}
	a.packets++
	src, dst := rec.IP.Src, rec.IP.Dst
	t, n := rec.T, rec.N
	rid := ""
	if ospf.RID != nil {
		rid = *ospf.RID
	}
	key := ospfRouterKey{rid: rid, addr: src}
	r, ok := a.routers[key]
	if !ok {
		r = &ospfRouterState{
			rid:        rid,
			address:    src,
			area:       ospf.Area,
			auth:       ospf.Auth,
			firstT:     t,
			lastT:      t,
			types:      make(map[int]int),
			everListed: make(map[string]bool),
		}
		a.routers[key] = r
		a.routerOrd = append(a.routerOrd, key)
	}
	r.overGRE = r.overGRE || tunneled
	ptype := 0
	if ospf.Type != nil {
		ptype = *ospf.Type
	}
	r.types[ptype]++
	r.lastT = t
	r.area, r.auth = ospf.Area, ospf.Auth
	model.AddFrame(&r.frames, n)

	if ptype == 1 {
		a.feedHello(r, ospf, t, n)
		return
	}
	dk := addrDirKey{src: src, dst: dst}
	if ptype == 2 {
		if ospf.MTU != nil {
			r.mtu = ospf.MTU
		}
		if _, exists := a.dbds[dk]; !exists {
			a.dbdOrder = append(a.dbdOrder, dk)
		}
		if len(a.dbds[dk]) < 500 {
			flags := 0
			if ospf.DBDFlags != nil {
				flags = *ospf.DBDFlags
			}
			a.dbds[dk] = append(a.dbds[dk], ospfDBDEntry{
				t: t, n: n, flags: flags, seq: ospf.DDSeq, mtu: ospf.MTU, rid: rid,
			})
		}
	}
	exMap, ok := a.exchange[dk]
	if !ok {
		exMap = make(map[int]int)
		a.exchange[dk] = exMap
	}
	exMap[ptype]++
}

// feedHello updates hello timing gaps, DR/BDR changes, and neighbor list diffs for router r.
func (a *OspfAnalyzer) feedHello(r *ospfRouterState, ospf *model.OSPFPacket, t float64, n int) {
	label := fmt.Sprintf("%s (%s)", r.rid, r.address)
	if r.hasLastHello {
		gap := t - r.lastHelloT
		if gap > r.maxHelloGap {
			r.maxHelloGap = gap
		}
		dead := ospf.Dead
		if dead == nil {
			dead = r.dead
		}
		if dead != nil && *dead != 0 && gap > float64(*dead) {
			r.gapsOverDead = append(r.gapsOverDead, ospfHelloGap{
				fromT: r.lastHelloT, toT: t, gapS: model.Round(gap, 3), deadInterval: *dead, frame: n,
			})
			a.events = append(a.events,
				ospfEvent{
					kind: "hello_gap", t: r.lastHelloT, frame: n,
					detail: fmt.Sprintf("%s sent no hello for %s s (dead interval %d s), neighbors drop it after the dead interval",
						label, model.FormatPyFloat(model.Round(gap, 1)), *dead),
				},
				ospfEvent{
					kind: "hellos_resumed", t: t, frame: n,
					detail: label + " hellos resumed",
				},
			)
		}
	}
	r.hasLastHello = true
	r.lastHelloT = t
	r.hellos++

	if r.dr != nil && (!strPtrEq(ospf.DR, r.dr) || !strPtrEq(ospf.BDR, r.bdr)) {
		a.events = append(a.events, ospfEvent{
			kind: "dr_change", t: t, frame: n,
			detail: fmt.Sprintf("%s now reports DR %s, BDR %s (was DR %s, BDR %s)",
				label, optStr(ospf.DR), optStr(ospf.BDR), optStr(r.dr), optStr(r.bdr)),
		})
	}

	newNbrs := make(map[string]bool, len(ospf.Neighbors))
	for _, nb := range ospf.Neighbors {
		newNbrs[nb] = true
		r.everListed[nb] = true
	}
	if r.hasNeighbors {
		var added []string
		for nb := range newNbrs {
			if !r.neighbors[nb] {
				added = append(added, nb)
			}
		}
		slices.Sort(added)
		for _, nb := range added {
			a.events = append(a.events, ospfEvent{
				kind: "neighbor_up", t: t, frame: n,
				detail: fmt.Sprintf("%s now lists neighbor %s", label, nb),
			})
		}
		var dropped []string
		for nb := range r.neighbors {
			if !newNbrs[nb] {
				dropped = append(dropped, nb)
			}
		}
		slices.Sort(dropped)
		for _, nb := range dropped {
			a.events = append(a.events, ospfEvent{
				kind: "neighbor_down", t: t, frame: n,
				detail: fmt.Sprintf("%s dropped neighbor %s from its hellos", label, nb),
			})
		}
	} else if len(newNbrs) > 0 {
		all := sortedStringSet(newNbrs)
		a.events = append(a.events, ospfEvent{
			kind: "neighbor_up", t: t, frame: n,
			detail: fmt.Sprintf("%s lists neighbor(s) %s", label, strings.Join(all, ", ")),
		})
	}

	r.mask = ospf.Mask
	r.hello = ospf.Hello
	r.dead = ospf.Dead
	r.prio = ospf.Prio
	r.options = ospf.Options
	r.dr = ospf.DR
	r.bdr = ospf.BDR
	r.hasNeighbors = true
	r.neighbors = newNbrs
}
