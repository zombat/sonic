// Package dmvpn encrypted shortcut analysis, final report assembly, and formatting helpers.
package dmvpn

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// encryptedCandidates returns peer pairs where an IKEv2 SA was initiated between two non-hub nodes.
func (d *Detector) encryptedCandidates(hubs []string) [][2]string {
	hubSet := make(map[string]bool, len(hubs))
	for _, h := range hubs {
		hubSet[h] = true
	}
	if len(hubSet) == 0 {
		return nil
	}
	var out [][2]string
	for key, st := range d.ike {
		if st.hasInit && !hubSet[key[0]] && !hubSet[key[1]] {
			out = append(out, key)
		}
	}
	return out
}

// encrypted evaluates encrypted spoke-to-spoke IKE/ESP shortcuts visible on transport links.
func (d *Detector) encrypted(hubs []string, ctx model.Context, issues *[]model.Issue, events *[]model.Event) EncryptedReport {
	hubSet := make(map[string]bool, len(hubs))
	for _, h := range hubs {
		hubSet[h] = true
	}
	if len(hubSet) == 0 {
		newCount := 0
		for _, st := range d.ike {
			if st.hasInit {
				newCount++
			}
		}
		var note *string
		if newCount > 0 {
			s := fmt.Sprintf("hub addresses unknown (no NHRP visible): pass hubs to classify the %d IKE SA(s) negotiated during the capture as spoke-to-spoke shortcuts", newCount)
			note = &s
		}
		return EncryptedReport{
			Shortcuts:  []EncryptedShortcut{},
			Note:       note,
			NotVisible: EncryptedNotVisible,
		}
	}

	cands := d.encryptedCandidates(hubs)
	slices.SortStableFunc(cands, func(a, b [2]string) int {
		return cmp.Compare(d.ike[a].initT, d.ike[b].initT)
	})

	encOrder := []string{"esp_to_hub_before", "ike_sa_init", "ike_auth", "direct_esp"}
	out := make([]EncryptedShortcut, 0, len(cands))

	for _, key := range cands {
		st := d.ike[key]
		a, b := key[0], key[1]
		initiator := optStr(st.initiator)
		other := a
		if initiator == a {
			other = b
		}
		steps := map[string]*StepDetail{
			"esp_to_hub_before": nil,
			"ike_sa_init":       nil,
			"ike_auth":          nil,
			"direct_esp":        nil,
		}

		var hasBefore bool
		var beforeT float64
		var beforeN int
		var beforeSrc, beforeDst string
		for ak, flow := range d.esp {
			if (ak.src == a || ak.src == b) && hubSet[ak.dst] {
				for _, pt := range flow.times {
					if pt.t <= st.initT && (!hasBefore || pt.t > beforeT) {
						hasBefore = true
						beforeT, beforeN, beforeSrc, beforeDst = pt.t, pt.n, ak.src, ak.dst
					}
				}
			}
		}
		if hasBefore {
			steps["esp_to_hub_before"] = &StepDetail{
				T:      ctx.Rel(&beforeT),
				Frame:  beforeN,
				Detail: fmt.Sprintf("last ESP %s -> hub %s before the shortcut (data and routing keepalives look alike inside ESP)", beforeSrc, beforeDst),
			}
		}

		initDetail := fmt.Sprintf("%s starts IKE_SA_INIT to %s", initiator, other)
		if st.initResponses == 0 {
			initDetail += ", never answered"
		}
		steps["ike_sa_init"] = &StepDetail{
			T:        ctx.Rel(&st.initT),
			Frame:    st.initN,
			Detail:   initDetail,
			Negative: st.initResponses == 0,
		}
		if st.hasAuth {
			steps["ike_auth"] = &StepDetail{
				T:      ctx.Rel(&st.authT),
				Frame:  st.authN,
				Detail: "IKE_AUTH answered",
			}
		}

		var hasDirect bool
		var directT float64
		var directN int
		var directDir addrPair
		for _, dir := range []addrPair{{src: a, dst: b}, {src: b, dst: a}} {
			if flow, ok := d.esp[dir]; ok {
				for _, pt := range flow.times {
					if pt.t >= st.initT && (!hasDirect || pt.t < directT) {
						hasDirect = true
						directT, directN, directDir = pt.t, pt.n, dir
					}
				}
			}
		}
		if hasDirect {
			steps["direct_esp"] = &StepDetail{
				T:      ctx.Rel(&directT),
				Frame:  directN,
				Detail: fmt.Sprintf("first ESP %s -> %s", directDir.src, directDir.dst),
			}
		}

		var missing *string
		for _, name := range encOrder[1:] {
			if steps[name] == nil || steps[name].Negative {
				nCopy := name
				missing = &nCopy
				break
			}
		}
		result := "complete"
		if missing != nil {
			result = "incomplete"
		}

		if missing != nil {
			mName := *missing
			msgByStep := map[string]string{
				"ike_sa_init": fmt.Sprintf("%s never answered IKE_SA_INIT from %s: UDP 500 blocked between the spokes, or the remote spoke has no matching IKEv2 policy", other, initiator),
				"ike_auth":    "IKE_AUTH never completed between the spokes (authentication or NAT-T problem; see the ipsec detector's diagnosis for this SA)",
				"direct_esp":  "the spokes negotiated IPsec but no ESP went directly between them",
			}
			sev := model.SeverityError
			if mName == "direct_esp" {
				sev = model.SeverityWarning
			}
			var frames []int
			for _, name := range encOrder {
				if steps[name] != nil {
					frames = append(frames, steps[name].Frame)
				}
			}
			*issues = append(*issues, model.MakeIssue(
				sev, "SHORTCUT_MISSING_"+upperASCII(mName),
				fmt.Sprintf("spoke-to-spoke shortcut %s <-> %s: %s", a, b, msgByStep[mName]),
				frames,
			))
		} else {
			fr := directN
			*events = append(*events, model.MakeEvent(
				ctx, directT, "ipsec", "shortcut_formed",
				fmt.Sprintf("encrypted spoke-to-spoke shortcut %s <-> %s carries ESP (%s ms after IKE_SA_INIT)",
					a, b, model.FormatPyFloat(model.Round((directT-st.initT)*1000.0, 1))),
				&fr,
			))
		}

		var setupMs *float64
		if hasDirect {
			v := model.Round((directT-st.initT)*1000.0, 1)
			setupMs = &v
		}
		out = append(out, EncryptedShortcut{
			Spokes:      []string{a, b},
			Initiator:   st.initiator,
			Result:      result,
			MissingStep: missing,
			Steps:       steps,
			SetupMs:     setupMs,
		})
	}

	capped, _ := model.Cap(out, ctx.MaxItems)
	return EncryptedReport{
		Shortcuts:  capped,
		Note:       nil,
		NotVisible: EncryptedNotVisible,
	}
}
