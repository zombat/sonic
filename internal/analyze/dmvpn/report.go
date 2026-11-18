// Package dmvpn final report assembly, verdict construction, and formatting helpers.
package dmvpn

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report finalizes all DMVPN Phase 3 flow sequences, thrashing metrics, and encrypted shortcuts into Report.
func (d *Detector) Report(ctx model.Context) Report {
	issues := []model.Issue{}
	events := []model.Event{}
	hubs := d.Hubs()

	inds := make([]*indicationTrack, 0, len(d.indications))
	for _, ind := range d.indications {
		inds = append(inds, ind)
	}
	slices.SortStableFunc(inds, func(a, b *indicationTrack) int {
		return cmp.Compare(a.t, b.t)
	})
	flows := make([]FlowReport, 0, len(inds))
	for _, ind := range inds {
		flows = append(flows, d.buildFlow(ind, ctx, &issues, &events))
	}

	relayed := d.relayedWithoutRedirect(hubs, ctx, &issues)
	thrash := d.thrashing(ctx, &issues)
	errorsOut := make([]ErrorEntry, 0, len(d.errors))
	for _, e := range d.errors {
		tCopy := e.t
		errorsOut = append(errorsOut, ErrorEntry{
			From:      e.from,
			To:        e.to,
			Error:     e.errText,
			ErrorCode: e.code,
			RequestID: e.reqID,
			T:         ctx.Rel(&tCopy),
			Frame:     e.n,
		})
	}
	enc := d.encrypted(hubs, ctx, &issues, &events)

	complete := 0
	for _, f := range flows {
		if f.Result == "complete" {
			complete++
		}
	}
	encOK := 0
	for _, e := range enc.Shortcuts {
		if e.Result == "complete" {
			encOK++
		}
	}
	present := d.Present()
	var verdict string
	if !present {
		negotiated := 0
		for _, st := range d.ike {
			if st.hasInit {
				negotiated++
			}
		}
		verdict = "No GRE/NHRP and no spoke-to-spoke IKE in this capture."
		if negotiated > 0 && len(hubs) == 0 {
			verdict = fmt.Sprintf("No GRE/NHRP visible; %d IKE SA(s) were negotiated during the capture: pass hubs (the hub NBMA addresses) to test them as encrypted spoke-to-spoke shortcuts.", negotiated)
		}
	} else {
		var parts []string
		if len(flows) > 0 {
			parts = append(parts, fmt.Sprintf("%d of %d redirected flow(s) completed the Phase 3 sequence", complete, len(flows)))
			for _, f := range flows {
				if f.Result != "complete" {
					parts = append(parts, fmt.Sprintf("%s -> %s: stops before %s", f.Spoke, optStr(f.OriginalDst), optStr(f.MissingStep)))
				}
			}
		}
		if len(relayed) > 0 {
			parts = append(parts, fmt.Sprintf("%d hub-relayed spoke-to-spoke flow(s) with no redirect", len(relayed)))
		}
		if thrash.Thrashing {
			parts = append(parts, "NHRP resolution thrashing")
		}
		if len(enc.Shortcuts) > 0 {
			parts = append(parts, fmt.Sprintf("%d of %d encrypted spoke-to-spoke shortcut(s) formed (IKE then direct ESP)", encOK, len(enc.Shortcuts)))
		} else if enc.Note != nil && len(flows) == 0 {
			parts = append(parts, *enc.Note)
		}
		if len(parts) > 0 {
			verdict = "Phase 3: " + joinSemi(parts)
		} else {
			verdict = "Phase 3: no redirect, resolution or shortcut seen"
		}
	}

	status := model.StatusFromIssues(issues, present)
	flowsList, flowsOm := model.Cap(flows, ctx.MaxItems)
	relayedCap, _ := model.Cap(relayed, ctx.MaxItems)
	errorsCap, _ := model.Cap(errorsOut, ctx.MaxItems)

	return Report{
		Detector: d.Name(),
		Status:   status,
		Verdict:  verdict,
		Hubs:     hubs,
		HubsSource: HubsSource{
			Given:             nonNilStrings(d.hubsGiven),
			FromRegistrations: sortedSetKeys(d.registeredHubs),
			FromRedirects:     sortedSetKeys(d.tiSenders),
		},
		Flows:                  flowsList,
		FlowsOmitted:           flowsOm,
		HubRelayedWithoutRedir: relayedCap,
		ResolutionThrashing:    thrash,
		ErrorIndications:       errorsCap,
		EncryptedShortcuts:     enc,
		CannotShow: []string{
			EncryptedNotVisible,
			"Which application flow triggered a redirect is known only from the original packet header the hub copies into the Traffic Indication.",
		},
		Issues: model.SortIssues(issues),
		Events: events,
	}
}

// sortedSetKeys returns the keys of a boolean set sorted lexicographically as a non-nil slice.
func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// nonNilStrings ensures an empty slice marshals as [] rather than null.
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// optStr returns *s or "None".
func optStr(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

// optU32 returns formatted uint32 or "None".
func optU32(v *uint32) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprintf("%d", *v)
}

// strPtrEq compares two optional string pointers by value.
func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// cieLabel formats CIE code name matching Python NHRP_CIE_CODES.get(code, code).
func cieLabel(code *int) string {
	if code == nil {
		return "None"
	}
	if name, ok := model.NHRPCIECodes[*code]; ok {
		return name
	}
	return fmt.Sprintf("%d", *code)
}

// cieFallbackCode formats CIE code name matching Python NHRP_CIE_CODES.get(code, "code " + str(code)).
func cieFallbackCode(code *int) string {
	if code == nil {
		return "code None"
	}
	if name, ok := model.NHRPCIECodes[*code]; ok {
		return name
	}
	return fmt.Sprintf("code %d", *code)
}

// upperASCII converts an ASCII snake_case token to upper case.
func upperASCII(s string) string {
	return strings.ToUpper(s)
}

// joinSemi joins strings with "; ".
func joinSemi(parts []string) string {
	return strings.Join(parts, "; ")
}
