// Package grenhrp report building, DMVPN phase hint, and verdict generation.
package grenhrp

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// Report compiles DMVPN hub/spoke roles, registrations, resolutions, and GRE tunnels into Report.
func (d *Detector) Report(ctx model.Context) Report {
	issues := []model.Issue{}
	events := []model.Event{}

	var hubOrder []string
	hubsMap := make(map[string]*HubEntry)
	var spokeOrder []string
	spokesMap := make(map[string]*SpokeEntry)

	regsSorted := make([]*regTrack, 0, len(d.registrations))
	for _, r := range d.registrations {
		regsSorted = append(regsSorted, r)
	}
	slices.SortStableFunc(regsSorted, func(a, b *regTrack) int {
		return cmp.Compare(a.firstT, b.firstT)
	})

	registrations := make([]RegistrationEntry, 0, len(regsSorted))
	for _, reg := range regsSorted {
		hub, ok := hubsMap[reg.hubNBMA]
		if !ok {
			hub = &HubEntry{
				NBMA:             reg.hubNBMA,
				TunnelIP:         reg.hubTunnelIP,
				SpokesRegistered: []string{},
				SpokesRefused:    []string{},
				SpokesUnanswered: []string{},
			}
			hubsMap[reg.hubNBMA] = hub
			hubOrder = append(hubOrder, reg.hubNBMA)
		}
		spoke, ok := spokesMap[reg.spokeNBMA]
		if !ok {
			spoke = &SpokeEntry{
				NBMA:     reg.spokeNBMA,
				TunnelIP: reg.spokeTunnelIP,
				Hubs:     []string{},
			}
			spokesMap[reg.spokeNBMA] = spoke
			spokeOrder = append(spokeOrder, reg.spokeNBMA)
		}
		if !slices.Contains(spoke.Hubs, reg.hubNBMA) {
			spoke.Hubs = append(spoke.Hubs, reg.hubNBMA)
		}

		var resEnum RegResult
		switch {
		case reg.replies == 0:
			resEnum = RegUnanswered
			hub.SpokesUnanswered = append(hub.SpokesUnanswered, reg.spokeNBMA)
			issues = append(issues, model.MakeIssue(
				model.SeverityError, "NHRP_REGISTRATION_UNANSWERED",
				fmt.Sprintf("spoke %s (%s) sent %d registration request(s) to hub %s and got no reply (NHS unreachable, GRE/IPsec down, or the hub has no matching tunnel/network-id)",
					reg.spokeNBMA, optStr(reg.spokeTunnelIP), reg.requests, reg.hubNBMA),
				reg.reqFrames,
			))
		case reg.hasLastCode && reg.lastCode == 0:
			resEnum = RegRegistered
			hub.SpokesRegistered = append(hub.SpokesRegistered, reg.spokeNBMA)
			var lastRep *int
			if len(reg.repFrames) > 0 {
				v := reg.repFrames[len(reg.repFrames)-1]
				lastRep = &v
			}
			if reg.hasSuccess {
				events = append(events, model.MakeEvent(
					ctx, reg.lastSuccessT, "nhrp", "registered",
					fmt.Sprintf("spoke %s (%s) registered with hub %s", reg.spokeNBMA, optStr(reg.spokeTunnelIP), reg.hubNBMA),
					lastRep,
				))
			}
		default:
			resEnum = RegRefused
			hub.SpokesRefused = append(hub.SpokesRefused, reg.spokeNBMA)
			code := reg.lastCode
			name := cieCodeName(&code)
			iss := model.MakeIssue(
				model.SeverityError, "NHRP_REGISTRATION_REFUSED",
				fmt.Sprintf("hub %s refused the registration of spoke %s (%s): %s",
					reg.hubNBMA, reg.spokeNBMA, optStr(reg.spokeTunnelIP), name),
				reg.repFrames,
			)
			iss.NHRPCode = &code
			issues = append(issues, iss)
			var lastRep *int
			if len(reg.repFrames) > 0 {
				v := reg.repFrames[len(reg.repFrames)-1]
				lastRep = &v
			}
			events = append(events, model.MakeEvent(
				ctx, reg.lastT, "nhrp", "registration_refused",
				fmt.Sprintf("hub %s refused spoke %s: %s", reg.hubNBMA, reg.spokeNBMA, name),
				lastRep,
			))
		}

		codesOut := make(map[string]int, len(reg.codes))
		for code, cnt := range reg.codes {
			c := code
			codesOut[cieCodeName(&c)] = cnt
		}
		registrations = append(registrations, RegistrationEntry{
			SpokeNBMA:     reg.spokeNBMA,
			SpokeTunnelIP: reg.spokeTunnelIP,
			HubNBMA:       reg.hubNBMA,
			HubTunnelIP:   reg.hubTunnelIP,
			Result:        resEnum.String(),
			Requests:      reg.requests,
			Replies:       reg.replies,
			ReplyCodes:    codesOut,
			FirstT:        ctx.Rel(&reg.firstT),
			LastT:         ctx.Rel(&reg.lastT),
			RequestFrames: nonNilInts(reg.reqFrames),
			ReplyFrames:   nonNilInts(reg.repFrames),
		})
	}

	resolutions := d.reportResolutions(ctx, &issues, &events)

	redSorted := make([]*redirTrack, 0, len(d.redirects))
	for _, r := range d.redirects {
		redSorted = append(redSorted, r)
	}
	slices.SortStableFunc(redSorted, func(a, b *redirTrack) int {
		return cmp.Compare(a.firstT, b.firstT)
	})
	redirects := make([]RedirectEntry, 0, len(redSorted))
	for _, red := range redSorted {
		redirects = append(redirects, RedirectEntry{
			From:                red.from,
			To:                  red.to,
			RedirectingTunnelIP: red.redirectingTunnelIP,
			OriginalSrc:         red.origSrc,
			OriginalDst:         red.origDst,
			Count:               red.count,
			FirstT:              ctx.Rel(&red.firstT),
			Frames:              nonNilInts(red.frames),
		})
		fr := red.frames[0]
		events = append(events, model.MakeEvent(
			ctx, red.firstT, "nhrp", "redirect",
			fmt.Sprintf("%s redirected %s for traffic to %s (Phase 3 shortcut signal)", red.from, red.to, optStr(red.origDst)),
			&fr,
		))
	}

	errorsOut := make([]ErrorEntry, 0, len(d.errors))
	for _, err := range d.errors {
		errorsOut = append(errorsOut, ErrorEntry{
			From:      err.from,
			To:        err.to,
			ErrorCode: err.errCode,
			Error:     err.errText,
			RequestID: err.reqID,
			Frame:     err.frame,
			T:         ctx.Rel(&err.t),
		})
		iss := model.MakeIssue(
			model.SeverityWarning, "NHRP_ERROR_INDICATION",
			fmt.Sprintf("NHRP error indication %s->%s: %s", err.from, err.to, err.errText),
			[]int{err.frame},
		)
		iss.ErrorCode = err.errCode
		issues = append(issues, iss)
		fr := err.frame
		events = append(events, model.MakeEvent(
			ctx, err.t, "nhrp", "error_indication",
			fmt.Sprintf("%s->%s: %s", err.from, err.to, err.errText),
			&fr,
		))
	}

	tunnels, spokeToSpoke := d.reportTunnels(ctx, hubsMap, spokesMap, &issues, &events)

	phase := "unknown"
	hasResolved := false
	for _, r := range resolutions {
		if r.Result == "resolved" {
			hasResolved = true
			break
		}
	}
	switch {
	case len(redirects) > 0:
		phase = "phase3"
	case hasResolved || len(spokeToSpoke) > 0:
		phase = "phase2_or_phase3"
	case len(registrations) > 0:
		phase = "hub_and_spoke_only"
	}

	present := d.Present()
	status := model.StatusFromIssues(issues, present)

	hubsOut := make([]*HubEntry, 0, len(hubOrder))
	for _, h := range hubOrder {
		hubsOut = append(hubsOut, hubsMap[h])
	}
	spokesOut := make([]*SpokeEntry, 0, len(spokeOrder))
	for _, s := range spokeOrder {
		spokesOut = append(spokesOut, spokesMap[s])
	}
	verdict := buildVerdict(present, hubsOut, registrations, spokeToSpoke, tunnels)

	tunnelsList, tunnelsOm := model.Cap(tunnels, ctx.MaxItems)
	regsList, regsOm := model.Cap(registrations, ctx.MaxItems)
	resList, resOm := model.Cap(resolutions, ctx.MaxItems)
	redList, _ := model.Cap(redirects, ctx.MaxItems)
	errList, _ := model.Cap(errorsOut, ctx.MaxItems)

	grePkts := 0
	for _, tun := range d.tunnels {
		grePkts += tun.packets
	}
	regCount := 0
	for _, r := range registrations {
		if r.Result == "registered" {
			regCount++
		}
	}

	return Report{
		Detector:       d.Name(),
		Status:         status,
		Verdict:        verdict,
		DMVPNPhaseHint: phase,
		Summary: Summary{
			GRETunnels:          len(d.tunnels),
			GREPackets:          grePkts,
			NHRPMessages:        maps.Clone(d.nhrpCounts),
			Hubs:                len(hubsOut),
			Spokes:              len(spokesOut),
			SpokesRegistered:    regCount,
			SpokeToSpokeTunnels: len(spokeToSpoke),
		},
		Hubs:                 hubsOut,
		Spokes:               spokesOut,
		Registrations:        regsList,
		RegistrationsOmitted: regsOm,
		Resolutions:          resList,
		ResolutionsOmitted:   resOm,
		Redirects:            redList,
		ErrorIndications:     errList,
		Purges:               maps.Clone(d.purges),
		Tunnels:              tunnelsList,
		TunnelsOmitted:       tunnelsOm,
		SpokeToSpokeTunnels:  spokeToSpoke,
		Issues:               model.SortIssues(issues),
		Events:               events,
	}
}
