// Package correlate handles NAT/DSCP pairwise accounting and union-find helpers
// for streaming multi-capture correlation.
package correlate

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type unionFind struct {
	parent []int
}

func (u *unionFind) add() int {
	id := len(u.parent)
	u.parent = append(u.parent, id)
	return id
}

func (u *unionFind) find(x int) int {
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		if ra > rb {
			u.parent[ra] = rb
		} else {
			u.parent[rb] = ra
		}
	}
}

func formatIntsKey(nums []int) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

func (c *correlator) finish(grp *matchGroup) {
	if grp.done {
		return
	}
	grp.done = true
	if siblings := c.open[grp.key]; len(siblings) > 0 {
		for i, g := range siblings {
			if g == grp {
				siblings = append(siblings[:i], siblings[i+1:]...)
				break
			}
		}
		if len(siblings) == 0 {
			delete(c.open, grp.key)
		} else {
			c.open[grp.key] = siblings
		}
	}
	sightings := make([]sighting, 0, len(grp.seen))
	for _, s := range grp.seen {
		sightings = append(sightings, s)
	}
	slices.SortStableFunc(sightings, func(a, b sighting) int {
		if a.t < b.t {
			return -1
		}
		if a.t > b.t {
			return 1
		}
		if a.cap < b.cap {
			return -1
		}
		if a.cap > b.cap {
			return 1
		}
		return 0
	})
	c.held -= len(sightings)

	nodeIDs := make([]int, len(sightings))
	nodeValid := make([]bool, len(sightings))
	for i, s := range sightings {
		nodeIDs[i], nodeValid[i] = c.node(s.cap, s.tup, s.t, s.n)
	}
	if len(sightings) == 1 {
		c.unmatched[sightings[0].cap]++
	} else {
		c.groupsMatched++
	}
	for i := 1; i < len(sightings); i++ {
		if nodeValid[i] && nodeValid[0] {
			c.uf.union(nodeIDs[0], nodeIDs[i])
		}
	}
	for i := 0; i < len(sightings); i++ {
		for j := i + 1; j < len(sightings); j++ {
			c.pair(sightings[i], sightings[j])
		}
	}
	if nodeValid[0] {
		order := make([]int, len(sightings))
		for i, s := range sightings {
			order[i] = s.cap
		}
		act := c.active(grp.t0)
		pKey := fmt.Sprintf("%s|%s", formatIntsKey(order), formatIntsKey(act))
		bucket := c.patterns[nodeIDs[0]]
		if bucket == nil {
			bucket = make(map[string]*patternEntry)
			c.patterns[nodeIDs[0]] = bucket
		}
		entry, ok := bucket[pKey]
		if !ok {
			frames := make(map[string]int, len(sightings))
			for _, s := range sightings {
				frames[c.labels[s.cap]] = s.n
			}
			entry = &patternEntry{order: order, active: act, frames: frames, firstT: sightings[0].t}
			bucket[pKey] = entry
			c.patternOrder[nodeIDs[0]] = append(c.patternOrder[nodeIDs[0]], pKey)
		}
		entry.count++
		if sightings[0].flags&0x02 != 0 {
			if sightings[0].flags&0x10 != 0 {
				entry.synack = true
			} else {
				entry.syn = true
			}
		}
	}
}

func (c *correlator) pair(a, b sighting) {
	key := capPairKey{lo: a.cap, hi: b.cap}
	first, second := a, b
	if a.cap > b.cap {
		key = capPairKey{lo: b.cap, hi: a.cap}
		first, second = b, a
	}
	st, ok := c.pairs[key]
	if !ok {
		st = &pairStats{ttlCount: make(map[int]int)}
		c.pairs[key] = st
	}
	st.matched++
	if len(st.deltas) < MaxDeltaSamples {
		st.deltas = append(st.deltas, second.t-first.t)
	}
	if a.hasTTL && b.hasTTL {
		dec := a.ttl - b.ttl
		if _, seen := st.ttlCount[dec]; !seen {
			st.ttlOrder = append(st.ttlOrder, dec)
		}
		st.ttlCount[dec]++
	}
	if a.tup != b.tup {
		nk := natKey{ca: a.cap, cb: b.cap, ta: a.tup, tb: b.tup}
		entry, ok := c.nat[nk]
		if !ok {
			entry = &countFrames{frames: make(map[string]int)}
			c.nat[nk] = entry
			c.natOrder = append(c.natOrder, nk)
		}
		entry.packets++
		if _, has := entry.frames[c.labels[a.cap]]; !has {
			entry.frames[c.labels[a.cap]] = a.n
		}
		if _, has := entry.frames[c.labels[b.cap]]; !has {
			entry.frames[c.labels[b.cap]] = b.n
		}
	}
	if a.hasDSCP && b.hasDSCP && a.dscp != b.dscp {
		dk := dscpKey{ca: a.cap, cb: b.cap, da: a.dscp, db: b.dscp, tup: a.tup}
		entry, ok := c.dscp[dk]
		if !ok {
			entry = &countFrames{frames: make(map[string]int)}
			c.dscp[dk] = entry
			c.dscpOrder = append(c.dscpOrder, dk)
		}
		entry.packets++
		if _, has := entry.frames[c.labels[a.cap]]; !has {
			entry.frames[c.labels[a.cap]] = a.n
		}
		if _, has := entry.frames[c.labels[b.cap]]; !has {
			entry.frames[c.labels[b.cap]] = b.n
		}
	}
}
