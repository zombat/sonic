// Package routing BGP session reporting and state classification.
package routing

import (
	"cmp"
	"maps"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// report builds BGP session reports, issues, and timeline events.
func (a *BgpAnalyzer) report(ctx model.Context, issues *[]model.Issue, events *[]model.Event) BGPSection {
	sessList := make([]*bgpSessionState, 0, len(a.sessionOrd))
	for _, k := range a.sessionOrd {
		sessList = append(sessList, a.sessions[k])
	}
	slices.SortStableFunc(sessList, func(x, y *bgpSessionState) int {
		xt, yt := 0.0, 0.0
		if x.hasTime {
			xt = x.firstT
		}
		if y.hasTime {
			yt = y.firstT
		}
		return cmp.Compare(xt, yt)
	})

	sessionsOut := make([]BGPSessionReport, 0, len(sessList))
	establishedCount := 0

	for _, sess := range sessList {
		label := sess.peers[0] + " <-> " + sess.peers[1]
		conns := sess.connections
		var last *bgpConnection
		if len(conns) > 0 {
			last = conns[len(conns)-1]
		}

		state := bgpSessionStateLabel(sess, conns, last)
		if state == "established" {
			establishedCount++
		}

		var hold *int
		for i := len(conns) - 1; i >= 0; i-- {
			if h := conns[i].holdTime(); h != nil {
				hold = h
				break
			}
		}

		speakersOut, asSet := buildBGPSpeakerReports(sess, ctx)
		downs := computeBGPDowns(conns, ctx)
		mssChecks := a.checkBGPMSS(conns, label, issues)
		ibgp := len(asSet) == 1 && len(sess.speakers) == 2

		appendBGPIssues(sess, conns, last, state, label, hold, ctx, issues)

		for _, ev := range sess.events {
			fr := ev.frame
			*events = append(*events, model.MakeEvent(ctx, ev.t, "bgp", ev.kind, label+": "+ev.detail, &fr))
		}

		var expKA *float64
		if hold != nil && *hold != 0 {
			v := model.Round(float64(*hold)/3.0, 3)
			expKA = &v
		}
		notesOut := make([]BGPNotificationEntry, 0, len(sess.notifications))
		for _, n := range sess.notifications {
			nt := n.t
			notesOut = append(notesOut, BGPNotificationEntry{
				From: n.from, To: n.to, Code: n.code, Subcode: n.subcode,
				Name: n.name, Hint: n.hint, Frame: n.frame,
				T: ctx.Rel(&nt), WhileEstablished: n.whileEstablished,
			})
		}

		var ft, lt *float64
		if sess.hasTime {
			ft = ctx.Rel(&sess.firstT)
			lt = ctx.Rel(&sess.lastT)
		}
		sessFrames := []int{}
		if len(conns) > 0 {
			sessFrames = conns[0].frames[:min(len(conns[0].frames), 5)]
		}

		sessionsOut = append(sessionsOut, BGPSessionReport{
			Peers:                      []string{sess.peers[0], sess.peers[1]},
			State:                      state,
			IBGP:                       ibgp,
			OverGRE:                    sess.overGRE,
			NegotiatedHoldTime:         hold,
			ExpectedKeepaliveIntervalS: expKA,
			Downs:                      downs,
			TCPMSS:                     mssChecks,
			Speakers:                   speakersOut,
			TCPConnections:             len(conns),
			TimesEstablished:           sess.established,
			TimesDown:                  sess.downs,
			Notifications:              notesOut,
			FirstT:                     ft,
			LastT:                      lt,
			Frames:                     sessFrames,
		})
	}

	listed, omitted := model.Cap(sessionsOut, ctx.MaxItems)
	return BGPSection{
		Present:             true,
		Sessions:            listed,
		SessionsOmitted:     omitted,
		Messages:            a.messages,
		EstablishedSessions: establishedCount,
		ExpectedMSS:         a.expectedMSS,
	}
}

// bgpSessionStateLabel derives Python's summary state string for one BGP session.
func bgpSessionStateLabel(sess *bgpSessionState, conns []*bgpConnection, last *bgpConnection) string {
	anyRSTNoAck := false
	for _, c := range conns {
		if c.rstFrom != nil && !c.synack {
			anyRSTNoAck = true
			break
		}
	}
	allSynNoAns := len(conns) > 0
	for _, c := range conns {
		if c.synCount == 0 || c.synack || c.rstFrom != nil {
			allSynNoAns = false
			break
		}
	}
	switch {
	case sess.established > 0 && last != nil && last.hasEstab && !last.hasDown:
		return "established"
	case sess.established > 0:
		return "down"
	case anyRSTNoAck:
		return "tcp_refused"
	case allSynNoAns:
		return "tcp_no_answer"
	case len(sess.notifications) > 0:
		return "open_rejected"
	default:
		return "not_established"
	}
}

// buildBGPSpeakerReports constructs per-speaker JSON reports and the distinct AS set for a session.
func buildBGPSpeakerReports(sess *bgpSessionState, ctx model.Context) (map[string]BGPSpeakerReport, map[int]bool) {
	speakersOut := make(map[string]BGPSpeakerReport, len(sess.speakers))
	asSet := make(map[int]bool)
	for _, ip := range sess.speakerOrder {
		sp := sess.speakers[ip]
		if sp.as != nil {
			asSet[*sp.as] = true
		}
		var eorT, kaMed, kaMin, kaMax, firstUpdT, lastUpdT *float64
		if sp.hasEoR {
			eorT = ctx.Rel(&sp.eorT)
		}
		if len(sp.kaGaps) > 0 {
			m := model.Median(sp.kaGaps)
			vMed := model.Round(*m, 3)
			kaMed = &vMed
			minG, maxG := sp.kaGaps[0], sp.kaGaps[0]
			for _, g := range sp.kaGaps[1:] {
				minG = min(minG, g)
				maxG = max(maxG, g)
			}
			vMin, vMax := model.Round(minG, 3), model.Round(maxG, 3)
			kaMin, kaMax = &vMin, &vMax
		}
		if sp.hasFirstUpd {
			firstUpdT = ctx.Rel(&sp.firstUpdT)
		}
		if sp.hasLastUpd {
			lastUpdT = ctx.Rel(&sp.lastUpdT)
		}
		lim := min(len(sp.updates), 10)
		updatesOut := make([]BGPUpdateSample, 0, lim)
		for _, u := range sp.updates[:lim] {
			absT := u.AbsT
			updatesOut = append(updatesOut, BGPUpdateSample{
				T: ctx.Rel(&absT), Frame: u.Frame, Announced: u.Announced, Withdrawn: u.Withdrawn,
			})
		}
		speakersOut[ip] = BGPSpeakerReport{
			AS:                    sp.as,
			RouterID:              sp.routerID,
			HoldTimeOffered:       sp.holdTime,
			Capabilities:          sp.capabilities,
			Messages:              maps.Clone(sp.messages),
			PrefixesAnnounced:     sp.announced,
			PrefixesWithdrawn:     sp.withdrawn,
			EndOfRibT:             eorT,
			KeepaliveIntervalS:    kaMed,
			KeepaliveIntervalMinS: kaMin,
			KeepaliveIntervalMaxS: kaMax,
			FirstUpdateT:          firstUpdT,
			LastUpdateT:           lastUpdT,
			Updates:               updatesOut,
		}
	}
	return speakersOut, asSet
}
