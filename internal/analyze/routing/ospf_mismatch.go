// Package routing OSPFv2 link mismatch detection across routers on one subnet.
package routing

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// checkOSPFMismatches checks area, hello/dead timers, mask, auth, E-bit, and DBD MTU across routers.
func (a *OspfAnalyzer) checkOSPFMismatches(routers []*ospfRouterState, routerAddrs map[string]bool, netLabel string, issues *[]model.Issue) []OSPFMismatch {
	mismatches := []OSPFMismatch{}
	var routerFrames2 []int
	for _, r := range routers {
		routerFrames2 = append(routerFrames2, r.frames[:min(len(r.frames), 2)]...)
	}
	checkStr := func(param, code, words string, get func(*ospfRouterState) *string) {
		vals := make(map[string]string)
		distinct := make(map[string]bool)
		var parts []string
		for _, r := range routers {
			if v := get(r); v != nil {
				vals[r.rid] = *v
				distinct[*v] = true
				parts = append(parts, fmt.Sprintf("%s=%s", r.rid, *v))
			}
		}
		if len(distinct) > 1 {
			raw, _ := json.Marshal(vals)
			mismatches = append(mismatches, OSPFMismatch{Parameter: param, Values: raw})
			iss := model.MakeIssue(model.SeverityError, code,
				fmt.Sprintf("OSPF %s mismatch on %s: %s; these routers will not become neighbors", words, netLabel, strings.Join(parts, ", ")),
				routerFrames2)
			iss.Values = raw
			*issues = append(*issues, iss)
		}
	}
	checkInt := func(param, code, words string, get func(*ospfRouterState) *int) {
		vals := make(map[string]int)
		distinct := make(map[int]bool)
		var parts []string
		for _, r := range routers {
			if v := get(r); v != nil {
				vals[r.rid] = *v
				distinct[*v] = true
				parts = append(parts, fmt.Sprintf("%s=%d", r.rid, *v))
			}
		}
		if len(distinct) > 1 {
			raw, _ := json.Marshal(vals)
			mismatches = append(mismatches, OSPFMismatch{Parameter: param, Values: raw})
			iss := model.MakeIssue(model.SeverityError, code,
				fmt.Sprintf("OSPF %s mismatch on %s: %s; these routers will not become neighbors", words, netLabel, strings.Join(parts, ", ")),
				routerFrames2)
			iss.Values = raw
			*issues = append(*issues, iss)
		}
	}

	checkStr("area", "OSPF_AREA_MISMATCH", "area", func(r *ospfRouterState) *string { return r.area })
	checkInt("hello_interval", "OSPF_HELLO_INTERVAL_MISMATCH", "hello interval", func(r *ospfRouterState) *int { return r.hello })
	checkInt("dead_interval", "OSPF_DEAD_INTERVAL_MISMATCH", "dead interval", func(r *ospfRouterState) *int { return r.dead })
	checkStr("network_mask", "OSPF_NETWORK_MASK_MISMATCH", "network mask", func(r *ospfRouterState) *string { return r.mask })
	checkInt("auth_type", "OSPF_AUTH_TYPE_MISMATCH", "authentication type", func(r *ospfRouterState) *int { return r.auth })

	stubVals := make(map[string]bool)
	stubDistinct := make(map[bool]bool)
	var stubParts []string
	for _, r := range routers {
		if r.options != nil && r.hellos > 0 {
			isStub := (*r.options & 0x02) == 0
			stubVals[r.rid] = isStub
			stubDistinct[isStub] = true
			stubText := "False"
			if isStub {
				stubText = "True"
			}
			stubParts = append(stubParts, fmt.Sprintf("%s stub=%s", r.rid, stubText))
		}
	}
	if len(stubDistinct) > 1 {
		raw, _ := json.Marshal(stubVals)
		mismatches = append(mismatches, OSPFMismatch{Parameter: "stub_area_flag", Values: raw})
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, "OSPF_STUB_FLAG_MISMATCH",
			fmt.Sprintf("OSPF E-bit (stub area flag) differs on %s: %s", netLabel, strings.Join(stubParts, ", ")),
			nil,
		))
	}

	mtuVals := make(map[string]int)
	mtuDistinct := make(map[int]bool)
	var mtuParts []string
	for _, r := range routers {
		if r.mtu != nil {
			mtuVals[r.rid] = *r.mtu
			mtuDistinct[*r.mtu] = true
			mtuParts = append(mtuParts, fmt.Sprintf("%s=%d", r.rid, *r.mtu))
		}
	}
	if len(mtuDistinct) > 1 {
		raw, _ := json.Marshal(mtuVals)
		mismatches = append(mismatches, OSPFMismatch{Parameter: "interface_mtu", Values: raw})
		var mtuFrames []int
		for _, dk := range a.dbdOrder {
			if routerAddrs[dk.src] {
				if dl := a.dbds[dk]; len(dl) > 0 {
					mtuFrames = append(mtuFrames, dl[0].n)
				}
			}
		}
		iss := model.MakeIssue(
			model.SeverityError, "OSPF_MTU_MISMATCH",
			fmt.Sprintf("OSPF DB Description MTU differs on %s: %s; the router with the smaller MTU rejects the other's DBD and the adjacency sticks in EXSTART/EXCHANGE (fix the IP MTU, or 'ip ospf mtu-ignore')",
				netLabel, strings.Join(mtuParts, ", ")),
			mtuFrames,
		)
		iss.Values = raw
		*issues = append(*issues, iss)
	}
	return mismatches
}
