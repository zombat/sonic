// Package routing OSPFv2 adjacency classification and per-router reporting.
package routing

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// report builds OSPF link reports, parameter mismatch findings, and adjacency events.
func (a *OspfAnalyzer) report(ctx model.Context, issues *[]model.Issue, events *[]model.Event) OSPFSection {
	var ridOrder []string
	ridAddrs := make(map[string]map[string]bool)
	for _, k := range a.routerOrd {
		r := a.routers[k]
		if _, ok := ridAddrs[r.rid]; !ok {
			ridOrder = append(ridOrder, r.rid)
			ridAddrs[r.rid] = make(map[string]bool)
		}
		ridAddrs[r.rid][r.address] = true
	}
	for _, rid := range ridOrder {
		if len(ridAddrs[rid]) > 1 {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityError, "OSPF_DUPLICATE_ROUTER_ID",
				fmt.Sprintf("router ID %s is used by %s", rid, strings.Join(sortedStringSet(ridAddrs[rid]), ", ")),
				nil,
			))
		}
	}

	links := a.groupLinks()
	linksOut := make([]OSPFLinkReport, 0, len(links))
	for _, group := range links {
		keys := slices.Clone(group)
		slices.SortStableFunc(keys, func(x, y ospfRouterKey) int {
			return cmp.Compare(x.addr, y.addr)
		})
		routers := make([]*ospfRouterState, len(keys))
		routerAddrs := make(map[string]bool, len(keys))
		for i, k := range keys {
			routers[i] = a.routers[k]
			routerAddrs[a.routers[k].address] = true
		}

		network, netLabel := resolveOSPFNetwork(routers)
		mismatches := a.checkOSPFMismatches(routers, routerAddrs, netLabel, issues)
		adjacencies := a.buildOSPFAdjacencies(routers, len(mismatches) == 0, ctx, issues)
		routersOut, linkDR := a.buildOSPFRouterReports(routers, ctx, issues)

		linksOut = append(linksOut, OSPFLinkReport{
			Network:     network,
			Routers:     routersOut,
			Mismatches:  mismatches,
			Adjacencies: adjacencies,
			DR:          linkDR,
		})
	}

	for _, ev := range a.events {
		fr := ev.frame
		*events = append(*events, model.MakeEvent(ctx, ev.t, "ospf", ev.kind, ev.detail, &fr))
	}
	listed, omitted := model.Cap(linksOut, ctx.MaxItems)
	return OSPFSection{
		Present:      true,
		Links:        listed,
		LinksOmitted: omitted,
		Packets:      a.packets,
		Routers:      len(a.routers),
	}
}

// resolveOSPFNetwork computes the masked IPv4 prefix string and display label for an OSPF link group.
func resolveOSPFNetwork(routers []*ospfRouterState) (*string, string) {
	for _, r := range routers {
		if r.mask != nil && *r.mask != "" {
			if pfx, ok := parseMaskNetwork(r.address, *r.mask); ok {
				s := pfx.String()
				return &s, s
			}
		}
	}
	return nil, "link"
}

// buildOSPFAdjacencies evaluates pairwise hello symmetry and DBD/LSA progress for one OSPF link.
func (a *OspfAnalyzer) buildOSPFAdjacencies(routers []*ospfRouterState, noMismatches bool, ctx model.Context, issues *[]model.Issue) []OSPFAdjacency {
	adjacencies := []OSPFAdjacency{}
	for i := 0; i < len(routers); i++ {
		for j := i + 1; j < len(routers); j++ {
			ra, rb := routers[i], routers[j]
			aListsB, bListsA := ra.everListed[rb.rid], rb.everListed[ra.rid]
			exch := make(map[int]int)
			for k, v := range a.exchange[addrDirKey{ra.address, rb.address}] {
				exch[k] += v
			}
			for k, v := range a.exchange[addrDirKey{rb.address, ra.address}] {
				exch[k] += v
			}
			var stateHint string
			switch {
			case aListsB && bListsA:
				stateHint = "2-way_or_better"
			case aListsB || bListsA:
				stateHint = "one-way"
				hearer, silent := rb, ra
				if aListsB {
					hearer, silent = ra, rb
				}
				*issues = append(*issues, model.MakeIssue(
					model.SeverityWarning, "OSPF_ONE_WAY",
					fmt.Sprintf("%s hears %s, but %s never lists %s: stuck in INIT (one-way link, multicast filtered, or a parameter mismatch)",
						hearer.rid, silent.rid, silent.rid, hearer.rid),
					nil,
				))
			default:
				stateHint = "none"
				if noMismatches && ra.hellos > 0 && rb.hellos > 0 {
					*issues = append(*issues, model.MakeIssue(
						model.SeverityWarning, "OSPF_NO_ADJACENCY",
						fmt.Sprintf("%s and %s send hellos on the same link but never list each other", ra.rid, rb.rid),
						nil,
					))
				}
			}
			adjacencies = append(adjacencies, OSPFAdjacency{
				Routers:          []string{ra.rid, rb.rid},
				StateHint:        stateHint,
				DBDExchanged:     exch[2] > 0,
				LSAExchangeSeen:  (exch[3] + exch[4] + exch[5]) > 0,
				DatabaseExchange: a.databaseExchange(ra, rb, exch, ctx, issues),
			})
		}
	}
	return adjacencies
}

// buildOSPFRouterReports emits per-router reports, hello gap/silence issues, and link DR vote.
func (a *OspfAnalyzer) buildOSPFRouterReports(routers []*ospfRouterState, ctx model.Context, issues *[]model.Issue) ([]OSPFRouterReport, *string) {
	routersOut := make([]OSPFRouterReport, 0, len(routers))
	var drOrder []string
	drCounts := make(map[string]int)
	for _, r := range routers {
		label := fmt.Sprintf("%s (%s)", r.rid, r.address)
		for _, g := range r.gapsOverDead {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "OSPF_HELLO_GAP",
				fmt.Sprintf("%s sent no hello for %s s (dead interval %d s): its neighbors declared it down, then it returned",
					label, model.FormatPyFloat(g.gapS), g.deadInterval),
				[]int{g.frame},
			))
		}
		if ctx.End != nil && r.hasLastHello && r.dead != nil && *r.dead != 0 {
			if silence := *ctx.End - r.lastHelloT; silence > float64(*r.dead) {
				*issues = append(*issues, model.MakeIssue(
					model.SeverityError, "OSPF_ROUTER_SILENT",
					fmt.Sprintf("%s sent its last hello %s s before the capture ended (dead interval %d s): it is down or unreachable",
						label, model.FormatPyFloat(model.Round(silence, 1)), *r.dead),
					tailFrames(r.frames, 2),
				))
				lastF := r.frames[len(r.frames)-1]
				a.events = append(a.events, ospfEvent{
					kind: "router_silent", t: r.lastHelloT, frame: lastF,
					detail: label + " last hello; silent until capture end",
				})
			}
		}

		listedNbrs := []string{}
		if r.hasNeighbors {
			listedNbrs = sortedStringSet(r.neighbors)
		}
		byType := make(map[string]int, len(r.types))
		for k, v := range r.types {
			byType[strconv.Itoa(k)] = v
		}
		var lastHelloT *float64
		if r.hasLastHello {
			lastHelloT = ctx.Rel(&r.lastHelloT)
		}
		routersOut = append(routersOut, OSPFRouterReport{
			RouterID: r.rid, Address: r.address, OverGRE: r.overGRE,
			Area: r.area, NetworkMask: r.mask, HelloInterval: r.hello,
			DeadInterval: r.dead, Priority: r.prio, AuthType: r.auth,
			DR: r.dr, BDR: r.bdr, NeighborsListed: listedNbrs,
			Hellos: r.hellos, MaxHelloGapS: model.Round(r.maxHelloGap, 3),
			DBDMTU: r.mtu, PacketsByType: byType,
			FirstT: ctx.Rel(&r.firstT), LastHelloT: lastHelloT,
		})
		if r.dr != nil && *r.dr != "" && *r.dr != "0.0.0.0" {
			if _, ok := drCounts[*r.dr]; !ok {
				drOrder = append(drOrder, *r.dr)
			}
			drCounts[*r.dr]++
		}
	}
	var linkDR *string
	bestDRCount := 0
	for _, dr := range drOrder {
		if drCounts[dr] > bestDRCount {
			bestDRCount = drCounts[dr]
			dCopy := dr
			linkDR = &dCopy
		}
	}
	return routersOut, linkDR
}
