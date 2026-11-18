// Package convergence failed-peer inference and multi-protocol signal collection.
package convergence

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/ipsec"
	"github.com/zombat/sonic/internal/analyze/reach"
	"github.com/zombat/sonic/internal/analyze/routing"
	"github.com/zombat/sonic/internal/model"
)

// convSignal holds one normalized convergence signal with absolute timestamp.
type convSignal struct {
	kind   string
	tAbs   float64
	frame  *int
	detail string
	phase  string
	peer   *string
	cause  string
}

// inferFailedPeer determines the failed peer IP from options, ESP stop order, or quietest BGP down.
func inferFailedPeer(given string, stops []espStop, bgpSessions []routing.BGPSessionReport, eventT *float64, startVal float64) (*string, *string) {
	if given != "" {
		f := given
		src := "given"
		return &f, &src
	}
	for _, s := range stops {
		if eventT == nil || s.lastT >= *eventT-1.0 {
			f := s.src
			src := "inferred: the first peer whose ESP stopped"
			if eventT != nil && *eventT != 0 {
				src += " after the event"
			}
			return &f, &src
		}
	}
	var allDowns, deadDowns []routing.BGPDownEntry
	for _, sess := range bgpSessions {
		for _, down := range sess.Downs {
			if down.QuietestSpeaker == nil || down.T == nil {
				continue
			}
			if eventT == nil || startVal+*down.T >= *eventT-1.0 {
				allDowns = append(allDowns, down)
				if down.Cause == "hold_timer_expired" || down.Cause == "hold_timer_expired_inferred" || down.Cause == "bfd_down" {
					deadDowns = append(deadDowns, down)
				}
			}
		}
	}
	cands := deadDowns
	if len(cands) == 0 {
		cands = allDowns
	}
	if len(cands) > 0 {
		best := cands[0]
		for _, d := range cands[1:] {
			if *d.T < *best.T {
				best = d
			}
		}
		f := *best.QuietestSpeaker
		src := "inferred: the BGP speaker that went quiet before its session dropped"
		return &f, &src
	}
	return nil, nil
}

// collectSignals gathers ESP, DPD/IKE, BGP, and ICMP signals across all sub-reports.
func (d *Detector) collectSignals(
	stops []espStop,
	ipsecRep ipsec.Report,
	bgpSessions []routing.BGPSessionReport,
	reachRep reach.ReachReport,
	failed *string,
	startVal float64,
) ([]convSignal, *float64, []float64, []float64) {
	var signals []convSignal
	add := func(kind string, tAbs float64, frame *int, detail, phase string, peer *string, cause string) {
		signals = append(signals, convSignal{
			kind: kind, tAbs: tAbs, frame: frame, detail: detail, phase: phase, peer: peer, cause: cause,
		})
	}
	failedIP := ""
	if failed != nil {
		failedIP = *failed
	}

	for _, s := range stops {
		if failed != nil && failedIP != s.src && failedIP != s.dst {
			continue
		}
		if s.src == failedIP || failed == nil {
			suffix := ""
			if s.resumedT == nil {
				suffix = " (until capture end)"
			}
			lf := s.lastFrame
			peer := s.src
			add("esp_stopped", s.lastT, &lf,
				fmt.Sprintf("last ESP %s -> %s before %s s of silence%s", s.src, s.dst, model.FormatPyFloat(s.silenceS), suffix),
				"failure", &peer, "")
			if s.resumedT != nil && *s.resumedT != 0 {
				var rf *int
				if s.resumedFrame != nil {
					v := *s.resumedFrame
					rf = &v
				}
				add("esp_resumed", *s.resumedT, rf, fmt.Sprintf("ESP %s -> %s resumes", s.src, s.dst), "recovery", &peer, "")
			}
		} else {
			lf := s.lastFrame
			peer := s.dst
			add("esp_towards_failed_stopped", s.lastT, &lf,
				fmt.Sprintf("%s stops sending ESP to %s (its SA torn down, or no traffic routed there)", s.src, s.dst),
				"teardown", &peer, "")
		}
	}

	var dpdDead *float64
	for _, sa := range ipsecRep.IKESAs {
		if sa.Negotiation != nil {
			for _, chk := range sa.Negotiation.Liveness.UnansweredChecks {
				if failed != nil && chk.To != failedIP {
					continue
				}
				if chk.FirstT != nil {
					fr := chk.Frame
					peer := chk.To
					add("dpd_unanswered", startVal+*chk.FirstT, &fr,
						fmt.Sprintf("liveness check (DPD) %s -> %s unanswered, %d transmission(s)", chk.From, chk.To, chk.Transmissions),
						"failure", &peer, "")
				}
				if chk.Transmissions >= 2 && chk.LastT != nil {
					lastAbs := startVal + *chk.LastT
					fr := chk.Frame
					peer := chk.To
					add("dpd_gave_up", lastAbs, &fr,
						fmt.Sprintf("last DPD retransmission to %s; the SA is deleted after it", chk.To),
						"detection", &peer, "")
					if dpdDead == nil || lastAbs < *dpdDead {
						v := lastAbs
						dpdDead = &v
					}
				}
			}
		}
		for _, ex := range sa.Exchanges {
			if ex.Exchange == "IKE_SA_INIT" && ex.T != nil {
				peer := sa.Responder
				if sa.Initiator != nil && failed != nil && *sa.Initiator == failedIP {
					peer = sa.Initiator
				}
				var rf *int
				if len(ex.RequestFrames) > 0 {
					v := ex.RequestFrames[0]
					rf = &v
				}
				initStr, respStr := "None", "None"
				if sa.Initiator != nil {
					initStr = *sa.Initiator
				}
				if sa.Responder != nil {
					respStr = *sa.Responder
				}
				add("ike_negotiation", startVal+*ex.T, rf,
					fmt.Sprintf("IKE_SA_INIT %s -> %s (%s)", initStr, respStr, sa.Outcome),
					"reaction", peer, "")
			}
		}
	}

	var holdSeen, bfd []float64
	for _, sess := range bgpSessions {
		involvesFailed := failed != nil && slices.Contains(sess.Peers, failedIP)
		for _, note := range sess.Notifications {
			if note.T == nil {
				continue
			}
			tAbs := startVal + *note.T
			fr := note.Frame
			if note.Code != nil && *note.Code == 4 {
				peer := note.To
				add("bgp_hold_expired", tAbs, &fr,
					fmt.Sprintf("NOTIFICATION Hold Timer Expired %s -> %s", note.From, note.To),
					"detection", &peer, "")
				holdSeen = append(holdSeen, tAbs)
			} else if note.Code != nil && note.Subcode != nil && *note.Code == 6 && *note.Subcode == 10 {
				peer := note.To
				add("bfd_down", tAbs, &fr,
					fmt.Sprintf("NOTIFICATION Cease/BFD Down %s", note.From),
					"detection", &peer, "")
				bfd = append(bfd, tAbs)
			} else {
				peer := note.From
				add("bgp_notification", tAbs, &fr,
					fmt.Sprintf("NOTIFICATION %s %s -> %s", note.Name, note.From, note.To),
					"failure", &peer, "")
			}
		}
		for _, down := range sess.Downs {
			if down.T == nil {
				continue
			}
			tAbs := startVal + *down.T
			if down.QuietestLastMessageT != nil && down.Cause != "tcp_rst" && down.Cause != "tcp_fin" {
				qs := ""
				if down.QuietestSpeaker != nil {
					qs = *down.QuietestSpeaker
				}
				add("bgp_last_message", startVal+*down.QuietestLastMessageT, down.QuietestLastMessageFrame,
					fmt.Sprintf("last BGP message from %s before its session dropped", qs),
					"failure", down.QuietestSpeaker, "")
			}
			add("bgp_down", tAbs, down.Frame,
				fmt.Sprintf("BGP %s down: %s", strings.Join(sess.Peers, " <-> "), down.Explanation),
				"detection", down.QuietestSpeaker, down.Cause)
			if down.Cause == "hold_timer_expired_inferred" {
				holdSeen = append(holdSeen, tAbs)
			}
		}
		if involvesFailed {
			continue
		}
		if len(sess.Peers) == 2 {
			allUp := d.routing.BGPAllUpdates([2]string{sess.Peers[0], sess.Peers[1]})
			for _, ip := range sess.Peers {
				for _, up := range allUp[ip] {
					fr := up.Frame
					peer := ip
					add("bgp_update", up.AbsT, &fr,
						fmt.Sprintf("BGP UPDATE %s on %s: %d announced, %d withdrawn", ip, strings.Join(sess.Peers, " <-> "), up.Announced, up.Withdrawn),
						"reaction", &peer, "")
				}
			}
		}
	}

	for _, pair := range reachRep.Echo {
		for _, outage := range pair.Outages {
			if outage.StartT != nil {
				ff := outage.FirstFrame
				add("icmp_outage", startVal+*outage.StartT, &ff,
					fmt.Sprintf("ping %s -> %s: %d request(s) unanswered", pair.Src, pair.Dst, outage.LostRequests),
					"failure", nil, "")
			}
			if outage.RecoveredT != nil {
				add("icmp_recovered", startVal+*outage.RecoveredT, outage.NextReplyFrame,
					fmt.Sprintf("ping %s -> %s answered again", pair.Src, pair.Dst),
					"recovery", nil, "")
			}
		}
	}
	return signals, dpdDead, holdSeen, bfd
}
