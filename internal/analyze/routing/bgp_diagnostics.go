// Package routing BGP issue emission, connection teardown cause inference, and TCP MSS validation.
package routing

import (
	"fmt"
	"maps"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// appendBGPIssues records BGP notification, hold-expiry, silence, TCP failure, and flap issues.
func appendBGPIssues(sess *bgpSessionState, conns []*bgpConnection, last *bgpConnection, state, label string, hold *int, ctx model.Context, issues *[]model.Issue) {
	for _, note := range sess.notifications {
		sev := model.SeverityError
		if note.code != nil && note.subcode != nil && *note.code == 6 && *note.subcode == 7 {
			sev = model.SeverityInfo
		} else if note.code != nil && note.subcode != nil && *note.code == 6 &&
			(*note.subcode == 2 || *note.subcode == 3 || *note.subcode == 4 || *note.subcode == 6) {
			sev = model.SeverityWarning
		}
		msg := fmt.Sprintf("%s sent NOTIFICATION to %s: %s", note.from, note.to, note.name)
		if note.hint != nil {
			msg += fmt.Sprintf(" (%s)", *note.hint)
		}
		iss := model.MakeIssue(sev, "BGP_NOTIFICATION", msg, []int{note.frame})
		iss.BGPCode = note.code
		iss.BGPSubcode = note.subcode
		iss.Name = note.name
		*issues = append(*issues, iss)
	}
	for _, conn := range conns {
		for _, gap := range conn.overHold {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "BGP_HOLD_TIME_EXCEEDED",
				fmt.Sprintf("%s sent nothing for %s s on %s, longer than the negotiated hold time of %d s",
					gap.speaker, model.FormatPyFloat(gap.gapS), label, gap.holdTime),
				[]int{gap.frame},
			))
		}
	}
	if state == "established" && ctx.End != nil && hold != nil && *hold != 0 && last != nil {
		for _, ip := range sess.speakerOrder {
			tLast, ok := last.lastMsgT[ip]
			if !ok {
				continue
			}
			if silence := *ctx.End - tLast; silence > float64(*hold) {
				*issues = append(*issues, model.MakeIssue(
					model.SeverityError, "BGP_PEER_SILENT",
					fmt.Sprintf("%s has sent nothing for %s s on %s (hold time %d s): the session will drop or already has",
						ip, model.FormatPyFloat(model.Round(silence, 1)), label, *hold),
					tailFrames(last.frames, 3),
				))
			}
		}
	}
	switch state {
	case "tcp_refused":
		var frames []int
		for _, c := range conns {
			if c.rstFrom != nil {
				frames = append(frames, c.frames[:min(len(c.frames), 2)]...)
			}
		}
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, "BGP_TCP_REFUSED",
			fmt.Sprintf("TCP 179 connection on %s refused with RST: the peer has no neighbor configured for this source address, or BGP is not running there", label),
			frames,
		))
		var f0 int
		if len(conns[0].frames) > 0 {
			f0 = conns[0].frames[0]
		}
		sess.events = append(sess.events, bgpSessionEvent{kind: "refused", t: conns[0].firstT, frame: f0, detail: "TCP 179 refused (RST)"})
	case "tcp_no_answer":
		*issues = append(*issues, model.MakeIssue(
			model.SeverityWarning, "BGP_TCP_NO_ANSWER",
			fmt.Sprintf("TCP SYN to port 179 on %s never answered: peer down, no route to it, or TCP 179 filtered", label),
			conns[0].frames[:min(len(conns[0].frames), 3)],
		))
	case "down":
		var tail []int
		reason := "unknown reason"
		if last != nil {
			tail = tailFrames(last.frames, 3)
			if last.downReason != nil {
				reason = *last.downReason
			}
		}
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, "BGP_SESSION_DOWN",
			fmt.Sprintf("BGP session %s was established and is down at the end of the capture (%s)", label, reason),
			tail,
		))
	}
	if sess.downs > 0 && sess.established > 1 {
		*issues = append(*issues, model.MakeIssue(
			model.SeverityWarning, "BGP_SESSION_FLAP",
			fmt.Sprintf("BGP session %s went down %d time(s) and was established %d time(s)", label, sess.downs, sess.established),
			nil,
		))
	}
}

// computeBGPDowns determines the root cause and per-speaker silence before each connection teardown.
func computeBGPDowns(conns []*bgpConnection, ctx model.Context) []BGPDownEntry {
	explanations := map[string]string{
		"hold_timer_expired": "a NOTIFICATION 'Hold Timer Expired' was sent: the other side was silent for the whole hold time",
		"notification":       "an explicit NOTIFICATION closed the session",
		"bfd_down":           "BFD declared the neighbor down (NOTIFICATION Cease / BFD Down)",
		"tcp_rst":            "TCP RST with no NOTIFICATION before it",
		"tcp_fin":            "TCP FIN with no NOTIFICATION before it",
	}
	out := []BGPDownEntry{}
	for _, conn := range conns {
		if !conn.hasDown {
			continue
		}
		hold := conn.holdTime()
		silence := make(map[string]float64)
		var quietIP *string
		var maxSil float64
		for ip, tLast := range conn.lastMsgT {
			if tLast <= conn.downT {
				s := model.Round(conn.downT-tLast, 3)
				silence[ip] = s
				if quietIP == nil || s > maxSil {
					ipCopy := ip
					quietIP = &ipCopy
					maxSil = s
				}
			}
		}
		cause := conn.downCause
		if cause == "" {
			cause = "unknown"
		}
		exp, ok := explanations[cause]
		if !ok {
			exp = "no closing message seen"
		}
		if (cause == "tcp_rst" || cause == "tcp_fin") && hold != nil && *hold != 0 && quietIP != nil && maxSil >= float64(*hold)*0.9 {
			cause = "hold_timer_expired_inferred"
			exp = fmt.Sprintf("%s was silent %s s (hold time %d s) before the TCP close and no NOTIFICATION was captured: the hold timer most likely expired",
				*quietIP, model.FormatPyFloat(maxSil), *hold)
		}
		var qLastT *float64
		var qLastN *int
		if quietIP != nil {
			if tv, ok := conn.lastMsgT[*quietIP]; ok {
				qLastT = ctx.Rel(&tv)
			}
			if nv, ok := conn.lastMsgN[*quietIP]; ok {
				qLastN = &nv
			}
		}
		dt := conn.downT
		out = append(out, BGPDownEntry{
			T:                        ctx.Rel(&dt),
			Frame:                    conn.downFrame,
			Cause:                    cause,
			Reason:                   conn.downReason,
			Explanation:              exp,
			HoldTime:                 hold,
			SilenceBeforeDownS:       silence,
			QuietestSpeaker:          quietIP,
			QuietestLastMessageT:     qLastT,
			QuietestLastMessageFrame: qLastN,
		})
	}
	return out
}

// checkBGPMSS builds TCP MSS tables per connection and flags clamping violations against expectedMSS.
func (a *BgpAnalyzer) checkBGPMSS(conns []*bgpConnection, label string, issues *[]model.Issue) []BGPMSSCheck {
	out := []BGPMSSCheck{}
	for idx, conn := range conns {
		if len(conn.synMSS) == 0 {
			continue
		}
		entry := BGPMSSCheck{
			Connection: idx + 1,
			SYNFrom:    conn.synFrom,
			MSS:        maps.Clone(conn.synMSS),
			Frames:     maps.Clone(conn.synFrames),
		}
		if a.expectedMSS != nil && *a.expectedMSS != 0 {
			verdicts := make(map[string]string, len(conn.synOrder))
			var badParts []string
			var badFrames []int
			for _, ip := range conn.synOrder {
				val := conn.synMSS[ip]
				switch {
				case val == nil:
					verdicts[ip] = "no_mss_option"
					badParts = append(badParts, fmt.Sprintf("%s sent no MSS option", ip))
					badFrames = append(badFrames, conn.synFrames[ip])
				case *val > *a.expectedMSS:
					verdicts[ip] = "above_expected"
					badParts = append(badParts, fmt.Sprintf("%s offered MSS %d", ip, *val))
					badFrames = append(badFrames, conn.synFrames[ip])
				default:
					verdicts[ip] = "ok"
				}
			}
			entry.Check = verdicts
			if len(badParts) > 0 {
				exp := *a.expectedMSS
				iss := model.MakeIssue(
					model.SeverityWarning, "BGP_MSS_NOT_CLAMPED",
					fmt.Sprintf("BGP TCP connection %d on %s: %s (expected %d or less). The value is what crossed this capture point: 'ip tcp adjust-mss' rewrites SYNs as they cross the interface it is on",
						idx+1, label, strings.Join(badParts, ", "), exp),
					badFrames,
				)
				iss.ExpectedMSS = &exp
				*issues = append(*issues, iss)
			}
		}
		out = append(out, entry)
	}
	return out
}
