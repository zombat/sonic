// Package routing OSPFv2 subnet grouping helpers.
package routing

import "net/netip"

// groupLinks clusters OSPF speakers sharing an IPv4 subnet or unicast exchange pair via union-find.
func (a *OspfAnalyzer) groupLinks() [][]ospfRouterKey {
	parent := make(map[ospfRouterKey]ospfRouterKey, len(a.routerOrd))
	find := func(x ospfRouterKey) ospfRouterKey {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(x, y ospfRouterKey) {
		rx, ry := find(x), find(y)
		if rx != ry {
			parent[ry] = rx
		}
	}

	nets := make(map[ospfRouterKey]netip.Prefix)
	for _, k := range a.routerOrd {
		parent[k] = k
		r := a.routers[k]
		if r.mask != nil && *r.mask != "" {
			if pfx, ok := parseMaskNetwork(r.address, *r.mask); ok {
				nets[k] = pfx
			}
		}
	}

	for i := 0; i < len(a.routerOrd); i++ {
		ka := a.routerOrd[i]
		addrA, errA := netip.ParseAddr(a.routers[ka].address)
		for j := i + 1; j < len(a.routerOrd); j++ {
			kb := a.routerOrd[j]
			addrB, errB := netip.ParseAddr(a.routers[kb].address)
			inNet := false
			if netA, ok := nets[ka]; ok && errB == nil && netA.Contains(addrB) {
				inNet = true
			} else if netB, ok := nets[kb]; ok && errA == nil && netB.Contains(addrA) {
				inNet = true
			}
			_, hasAB := a.exchange[addrDirKey{a.routers[ka].address, a.routers[kb].address}]
			_, hasBA := a.exchange[addrDirKey{a.routers[kb].address, a.routers[ka].address}]
			if inNet || hasAB || hasBA {
				union(ka, kb)
			}
		}
	}

	var repOrd []ospfRouterKey
	groups := make(map[ospfRouterKey][]ospfRouterKey)
	for _, k := range a.routerOrd {
		rep := find(k)
		if _, exists := groups[rep]; !exists {
			repOrd = append(repOrd, rep)
		}
		groups[rep] = append(groups[rep], k)
	}
	out := make([][]ospfRouterKey, 0, len(repOrd))
	for _, rep := range repOrd {
		out = append(out, groups[rep])
	}
	return out
}

// parseMaskNetwork parses address + dotted-quad IPv4 subnet mask into a masked netip.Prefix.
func parseMaskNetwork(address, maskStr string) (netip.Prefix, bool) {
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	mask, err := netip.ParseAddr(maskStr)
	if err != nil || !mask.Is4() {
		return netip.Prefix{}, false
	}
	m4 := mask.As4()
	val := uint32(m4[0])<<24 | uint32(m4[1])<<16 | uint32(m4[2])<<8 | uint32(m4[3])
	ones := 0
	for i := 31; i >= 0; i-- {
		if (val & (1 << i)) != 0 {
			ones++
		} else {
			// Verify remaining bits are zero so non-contiguous masks fail safely.
			if (val & ((1 << (i + 1)) - 1)) != 0 {
				return netip.Prefix{}, false
			}
			break
		}
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}
