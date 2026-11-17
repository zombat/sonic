// Package correlate implements the bounded-window streaming packet matcher and
// state storage matching analyzers/correlate.py:Correlator.
package correlate

import "github.com/zombat/sonic/internal/model"

type capTupleKey struct {
	cap int
	tup DirTuple
}

type nodeRecord struct {
	cap     int
	tup     DirTuple
	packets int
	firstT  float64
	firstN  int
	lastT   float64
	lastN   int
}

type sighting struct {
	cap     int
	t       float64
	n       int
	tup     DirTuple
	dscp    int
	hasDSCP bool
	ttl     int
	hasTTL  bool
	flags   int
}

type matchGroup struct {
	key  MatchKey
	t0   float64
	seen map[int]sighting
	done bool
}

type capPairKey struct {
	lo int
	hi int
}

type pairStats struct {
	matched  int
	deltas   []float64
	ttlCount map[int]int
	ttlOrder []int
}

type natKey struct {
	ca int
	cb int
	ta DirTuple
	tb DirTuple
}

type dscpKey struct {
	ca  int
	cb  int
	da  int
	db  int
	tup DirTuple
}

type countFrames struct {
	packets int
	frames  map[string]int
}

type patternEntry struct {
	order  []int
	active []int
	count  int
	frames map[string]int
	firstT float64
	syn    bool
	synack bool
}

type addrPairKey struct {
	src string
	dst string
}

type streamInfo struct {
	label  string
	path   string
	offset float64
	back   string
	start  *float64
	end    *float64
	done   bool
	warns  []string
}

type correlator struct {
	labels        []string
	infos         []*streamInfo
	addrPairs     []map[addrPairKey]bool
	window        float64
	maxHeld       int
	open          map[MatchKey][]*matchGroup
	queue         []*matchGroup
	qHead         int
	held          int
	evictedEarly  int
	nodes         map[capTupleKey]int
	nodeInfo      []nodeRecord
	nodesDropped  int
	uf            unionFind
	pairs         map[capPairKey]*pairStats
	nat           map[natKey]*countFrames
	natOrder      []natKey
	dscp          map[dscpKey]*countFrames
	dscpOrder     []dscpKey
	patterns      map[int]map[string]*patternEntry
	patternOrder  map[int][]string
	unmatched     []int
	packets       []int
	groupsMatched int
}

func newCorrelator(labels []string, windowS float64, maxHeld int, infos []*streamInfo) *correlator {
	addrPairs := make([]map[addrPairKey]bool, len(labels))
	for i := range addrPairs {
		addrPairs[i] = make(map[addrPairKey]bool)
	}
	return &correlator{
		labels:       labels,
		infos:        infos,
		addrPairs:    addrPairs,
		window:       windowS,
		maxHeld:      maxHeld,
		open:         make(map[MatchKey][]*matchGroup),
		nodes:        make(map[capTupleKey]int),
		pairs:        make(map[capPairKey]*pairStats),
		nat:          make(map[natKey]*countFrames),
		dscp:         make(map[dscpKey]*countFrames),
		patterns:     make(map[int]map[string]*patternEntry),
		patternOrder: make(map[int][]string),
		unmatched:    make([]int, len(labels)),
		packets:      make([]int, len(labels)),
	}
}

func (c *correlator) node(capIdx int, tup DirTuple, t float64, n int) (int, bool) {
	key := capTupleKey{cap: capIdx, tup: tup}
	if id, ok := c.nodes[key]; ok {
		info := &c.nodeInfo[id]
		info.packets++
		info.lastT, info.lastN = t, n
		return id, true
	}
	if len(c.nodes) >= MaxNodes {
		c.nodesDropped++
		return 0, false
	}
	id := c.uf.add()
	c.nodes[key] = id
	c.nodeInfo = append(c.nodeInfo, nodeRecord{
		cap: capIdx, tup: tup, packets: 1, firstT: t, firstN: n, lastT: t, lastN: n,
	})
	return id, true
}

func (c *correlator) feed(capIdx int, t float64, rec *model.Record) {
	c.packets[capIdx]++
	c.expire(t)
	key, tup, ok := PacketIdentity(rec)
	if !ok {
		return
	}
	if len(c.addrPairs[capIdx]) < MaxNodes {
		c.addrPairs[capIdx][addrPairKey{src: tup.Src, dst: tup.Dst}] = true
	}
	var dscp int
	var hasDSCP bool
	if view := model.Transport(rec); view != nil {
		dscp, hasDSCP = view.DSCP, true
	}
	var ttl int
	var hasTTL bool
	if rec.IP != nil && rec.IP.TTL != nil {
		ttl, hasTTL = *rec.IP.TTL, true
	}
	var flags int
	if rec.TCP != nil {
		flags = rec.TCP.Flags
	} else if rec.Inner != nil && rec.Inner.TCP != nil {
		flags = rec.Inner.TCP.Flags
	}
	s := sighting{cap: capIdx, t: t, n: rec.N, tup: tup, dscp: dscp, hasDSCP: hasDSCP, ttl: ttl, hasTTL: hasTTL, flags: flags}

	matched := false
	for _, grp := range c.open[key] {
		if _, exists := grp.seen[capIdx]; !exists && t-grp.t0 <= c.window {
			grp.seen[capIdx] = s
			c.held++
			matched = true
			break
		}
	}
	if !matched {
		grp := &matchGroup{key: key, t0: t, seen: map[int]sighting{capIdx: s}}
		c.open[key] = append(c.open[key], grp)
		c.queue = append(c.queue, grp)
		c.held++
	}
	for c.held > c.maxHeld && c.qHead < len(c.queue) {
		c.evictedEarly++
		grp := c.queue[c.qHead]
		c.qHead++
		c.finish(grp)
	}
	if c.qHead > 4096 && c.qHead*2 >= len(c.queue) {
		c.queue = append([]*matchGroup(nil), c.queue[c.qHead:]...)
		c.qHead = 0
	}
}

func (c *correlator) expire(now float64) {
	for c.qHead < len(c.queue) && now-c.queue[c.qHead].t0 > c.window {
		grp := c.queue[c.qHead]
		c.qHead++
		c.finish(grp)
	}
}

func (c *correlator) flush() {
	for c.qHead < len(c.queue) {
		grp := c.queue[c.qHead]
		c.qHead++
		c.finish(grp)
	}
	c.queue = nil
	c.qHead = 0
}

func (c *correlator) active(t float64) []int {
	var out []int
	for idx, info := range c.infos {
		if info.start == nil || *info.start > t+c.window {
			continue
		}
		if info.done && info.end != nil && *info.end < t-c.window {
			continue
		}
		out = append(out, idx)
	}
	return out
}
