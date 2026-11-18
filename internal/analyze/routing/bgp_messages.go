// Package routing BGP message decoding (OPEN, KEEPALIVE, UPDATE EoR, NOTIFICATION).
package routing

import (
	"fmt"

	"github.com/zombat/sonic/internal/model"
)

// fmtDownDetail formats the session down reason suffix for BGP timeline events.
func fmtDownDetail(reason *string) string {
	return fmt.Sprintf("session down (%s)", optStr(reason))
}

// feedUpdateCounts updates per-packet UPDATE NLRI/withdrawn totals once per frame containing UPDATE(s).
func (a *BgpAnalyzer) feedUpdateCounts(rec *model.Record, sess *bgpSessionState, src string) {
	t, n := rec.T, rec.N
	sp := a.speaker(sess, src)
	nlri := 0
	if rec.BGPNLRI != nil {
		nlri = *rec.BGPNLRI
	}
	withdrawn := 0
	if rec.BGPWithdrawn != nil {
		withdrawn = *rec.BGPWithdrawn
	}
	sp.announced += nlri
	sp.withdrawn += withdrawn
	if nlri != 0 || withdrawn != 0 {
		if !sp.hasFirstUpd {
			sp.hasFirstUpd = true
			sp.firstUpdT = t
		}
		sp.hasLastUpd = true
		sp.lastUpdT = t
		if len(sp.updates) < 200 {
			sp.updates = append(sp.updates, BGPUpdateSample{
				AbsT:      t,
				Frame:     n,
				Announced: nlri,
				Withdrawn: withdrawn,
			})
		}
	}
	if withdrawn != 0 {
		sess.events = append(sess.events, bgpSessionEvent{
			kind: "withdraw", t: t, frame: n,
			detail: fmt.Sprintf("%s withdrew %d prefix(es)", src, withdrawn),
		})
	}
	if nlri != 0 {
		sess.events = append(sess.events, bgpSessionEvent{
			kind: "update", t: t, frame: n,
			detail: fmt.Sprintf("%s announced %d prefix(es)", src, nlri),
		})
	}
}

// feedMessage updates speaker state, hold-time violations, End-of-RIB, and NOTIFICATION tracking.
func (a *BgpAnalyzer) feedMessage(rec *model.Record, sess *bgpSessionState, conn *bgpConnection, src, dst string, msg *model.BGPMessage) {
	t, n := rec.T, rec.N
	sp := a.speaker(sess, src)
	mtype := msg.Type
	typeName, ok := model.BGPTypes[mtype]
	if !ok {
		typeName = fmt.Sprintf("type_%d", mtype)
	}
	sp.messages[typeName]++

	if last, hasLast := conn.lastMsgT[src]; hasLast {
		gap := t - last
		if gap > conn.maxGap[src] {
			conn.maxGap[src] = gap
		}
		if hold := conn.holdTime(); conn.hasEstab && hold != nil && *hold != 0 && gap > float64(*hold) {
			conn.overHold = append(conn.overHold, bgpOverHoldGap{
				speaker: src, gapS: model.Round(gap, 3), holdTime: *hold, frame: n,
			})
		}
	}
	conn.lastMsgT[src] = t
	conn.lastMsgN[src] = n

	switch mtype {
	case 1:
		var asn *int
		if msg.AS4 != nil && *msg.AS4 != 0 {
			v := int(*msg.AS4)
			asn = &v
		} else if msg.MyAS != nil && *msg.MyAS != 0 {
			v := *msg.MyAS
			asn = &v
		}
		conn.opens[src] = bgpOpenData{as: asn, hold: msg.Hold, routerID: msg.BGPID}
		sp.as, sp.holdTime, sp.routerID = asn, msg.Hold, msg.BGPID
		if msg.Caps != nil {
			caps := make([]string, len(msg.Caps))
			for i, c := range msg.Caps {
				if name, found := model.BGPCapabilities[c]; found {
					caps[i] = name
				} else {
					caps[i] = fmt.Sprintf("capability %d", c)
				}
			}
			sp.capabilities = &caps
		}
		sess.events = append(sess.events, bgpSessionEvent{
			kind: "open", t: t, frame: n,
			detail: fmt.Sprintf("OPEN from %s: AS %s, hold %s s, router ID %s", src, optInt(asn), optInt(msg.Hold), optStr(msg.BGPID)),
		})
	case 4:
		if sp.hasLastKA {
			sp.kaGaps = append(sp.kaGaps, t-sp.lastKA)
		}
		sp.hasLastKA = true
		sp.lastKA = t
		if _, hasOpen := conn.opens[src]; hasOpen {
			conn.kaAfterOpen[src] = true
		}
		if !conn.hasEstab && len(conn.opens) == 2 && len(conn.kaAfterOpen) == 2 && !conn.closed {
			conn.hasEstab = true
			conn.estabT = t
			sess.established++
			hold := conn.holdTime()
			sess.events = append(sess.events, bgpSessionEvent{
				kind: "established", t: t, frame: n,
				detail: fmt.Sprintf("session established (hold time %s s)", optInt(hold)),
			})
		}
	case 2:
		if msg.Len != nil && *msg.Len == 23 {
			sp.eorCount++
			if !sp.hasEoR || (conn.hasEstab && sp.eorT < conn.estabT) {
				sp.hasEoR = true
				sp.eorT = t
			}
			sess.events = append(sess.events, bgpSessionEvent{
				kind: "end_of_rib", t: t, frame: n,
				detail: fmt.Sprintf("End-of-RIB from %s (initial routing table sent)", src),
			})
		}
	case 3:
		errName := model.BGPErrorName(msg.Major, msg.Minor)
		sess.notifications = append(sess.notifications, bgpNoteTrack{
			from: src, to: dst, code: msg.Major, subcode: msg.Minor,
			name: errName, hint: model.BGPErrorHint(msg.Major, msg.Minor),
			frame: n, t: t, whileEstablished: conn.hasEstab,
		})
		reason := fmt.Sprintf("NOTIFICATION from %s: %s", src, errName)
		conn.downReason = &reason
		cause := "notification"
		if msg.Major != nil && *msg.Major == 4 {
			cause = "hold_timer_expired"
		} else if msg.Major != nil && msg.Minor != nil && *msg.Major == 6 && *msg.Minor == 10 {
			cause = "bfd_down"
		}
		conn.downCause = cause
		sess.events = append(sess.events, bgpSessionEvent{
			kind: "notification", t: t, frame: n,
			detail: fmt.Sprintf("NOTIFICATION %s->%s: %s", src, dst, errName),
		})
		if conn.hasEstab && !conn.hasDown {
			conn.hasDown = true
			conn.downT = t
			fc := n
			conn.downFrame = &fc
			sess.downs++
			sess.events = append(sess.events, bgpSessionEvent{
				kind: "down", t: t, frame: n,
				detail: fmtDownDetail(conn.downReason),
			})
		}
	}
}
