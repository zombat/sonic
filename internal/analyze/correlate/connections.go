// Package correlate groups union-find components into paired directional conversations.
package correlate

import (
	"cmp"
	"slices"
)

type directionData struct {
	caps         []int
	capSet       map[int]bool
	seen         map[string]int
	tuples       map[string]string
	firstTuple   string
	firstT       *float64
	patterns     map[string]int
	patternOrder []string
	patternMeta  map[string]*patternEntry
	syn          bool
	synack       bool
	multicast    bool
	originCap    int
	originTuple  DirTuple
}

// buildConnections groups union-find components into paired request/reply ConnectionRows.
func buildConnections(corr *correlator, labels []string, start *float64) []ConnectionRow {
	comps := make(map[int][]int)
	for nodeID := range corr.nodeInfo {
		root := corr.uf.find(nodeID)
		comps[root] = append(comps[root], nodeID)
	}

	partnerCount := make(map[int]map[int]int)
	partnerOrder := make(map[int][]int)
	for nodeID, info := range corr.nodeInfo {
		otherID, ok := corr.nodes[capTupleKey{cap: info.cap, tup: reverseTuple(info.tup)}]
		if !ok {
			continue
		}
		a := corr.uf.find(nodeID)
		b := corr.uf.find(otherID)
		if a == b {
			continue
		}
		if partnerCount[a] == nil {
			partnerCount[a] = make(map[int]int)
		}
		if _, seen := partnerCount[a][b]; !seen {
			partnerOrder[a] = append(partnerOrder[a], b)
		}
		partnerCount[a][b] += corr.nodeInfo[otherID].packets
	}

	roots := make([]int, 0, len(comps))
	minRootT := make(map[int]float64, len(comps))
	for root, nodes := range comps {
		minT := corr.nodeInfo[nodes[0]].firstT
		for _, n := range nodes[1:] {
			if corr.nodeInfo[n].firstT < minT {
				minT = corr.nodeInfo[n].firstT
			}
		}
		roots = append(roots, root)
		minRootT[root] = minT
	}
	slices.SortStableFunc(roots, func(a, b int) int {
		if c := cmp.Compare(minRootT[a], minRootT[b]); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})

	done := make(map[int]bool, len(roots))
	out := make([]ConnectionRow, 0, len(roots))
	for _, root := range roots {
		if done[root] {
			continue
		}
		done[root] = true
		var revRoot *int
		if pCounts := partnerCount[root]; len(pCounts) > 0 {
			bestID, bestVal := -1, -1
			for _, cand := range partnerOrder[root] {
				if pCounts[cand] > bestVal {
					bestID, bestVal = cand, pCounts[cand]
				}
			}
			if bestID >= 0 {
				v := bestID
				revRoot = &v
				done[bestID] = true
			}
		}
		fwd := buildDirection(corr, labels, comps[root])
		var rev *directionData
		if revRoot != nil {
			rev = buildDirection(corr, labels, comps[*revRoot])
		}
		if fwd.firstT != nil && rev != nil && rev.firstT != nil && *rev.firstT < *fwd.firstT {
			fwd, rev = rev, fwd
		}
		out = append(out, judgeConnection(fwd, rev, labels, start, corr))
	}
	return out
}

func buildDirection(corr *correlator, labels []string, nodes []int) *directionData {
	seenCounts := make(map[int]int)
	tuples := make(map[string]string)
	firstTuple := ""
	var firstT *float64
	patterns := make(map[string]int)
	var patternOrder []string
	patternMeta := make(map[string]*patternEntry)
	syn, synack := false, false
	originIdx := nodes[0]

	for _, nID := range nodes {
		info := corr.nodeInfo[nID]
		if info.firstT < corr.nodeInfo[originIdx].firstT {
			originIdx = nID
		}
		seenCounts[info.cap] += info.packets
		lbl := labels[info.cap]
		if _, ok := tuples[lbl]; !ok {
			txt := tupleText(info.tup)
			tuples[lbl] = txt
			if firstTuple == "" {
				firstTuple = txt
			}
		}
		if firstT == nil || info.firstT < *firstT {
			t := info.firstT
			firstT = &t
		}
		for _, pKey := range corr.patternOrder[nID] {
			entry := corr.patterns[nID][pKey]
			if _, ok := patterns[pKey]; !ok {
				patternOrder = append(patternOrder, pKey)
				patternMeta[pKey] = entry
			}
			patterns[pKey] += entry.count
			syn = syn || entry.syn
			synack = synack || entry.synack
		}
	}

	caps := make([]int, 0, len(seenCounts))
	capSet := make(map[int]bool, len(seenCounts))
	for c := range seenCounts {
		caps = append(caps, c)
		capSet[c] = true
	}
	slices.Sort(caps)
	seen := make(map[string]int, len(caps))
	for _, c := range caps {
		seen[labels[c]] = seenCounts[c]
	}
	originInfo := corr.nodeInfo[originIdx]
	return &directionData{
		caps: caps, capSet: capSet, seen: seen, tuples: tuples, firstTuple: firstTuple,
		firstT: firstT, patterns: patterns, patternOrder: patternOrder, patternMeta: patternMeta,
		syn: syn, synack: synack, multicast: isMulticast(originInfo.tup.Dst),
		originCap: originInfo.cap, originTuple: originInfo.tup,
	}
}

func onPathElsewhere(corr *correlator, fwd *directionData, others []int) []int {
	type natAddrKey struct {
		ca   int
		cb   int
		addr string
	}
	addrMap := make(map[natAddrKey]string, len(corr.natOrder)*2)
	for _, nk := range corr.natOrder {
		if _, ok := addrMap[natAddrKey{nk.ca, nk.cb, nk.ta.Src}]; !ok {
			addrMap[natAddrKey{nk.ca, nk.cb, nk.ta.Src}] = nk.tb.Src
		}
		if _, ok := addrMap[natAddrKey{nk.ca, nk.cb, nk.ta.Dst}]; !ok {
			addrMap[natAddrKey{nk.ca, nk.cb, nk.ta.Dst}] = nk.tb.Dst
		}
	}
	found := make([]int, 0, len(others))
	for _, other := range others {
		src := fwd.originTuple.Src
		if mapped, ok := addrMap[natAddrKey{fwd.originCap, other, src}]; ok {
			src = mapped
		}
		dst := fwd.originTuple.Dst
		if mapped, ok := addrMap[natAddrKey{fwd.originCap, other, dst}]; ok {
			dst = mapped
		}
		if corr.addrPairs[other][addrPairKey{src, dst}] || corr.addrPairs[other][addrPairKey{dst, src}] {
			found = append(found, other)
		}
	}
	return found
}
