// Package ipsec IKEv2 negotiation detail assembly and per-SA diagnostic classification.
package ipsec

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// buildNegotiation extracts offered/chosen IKEv2 proposals, NAT-D verdict, and DPD liveness metrics.
func buildNegotiation(sa *ikeSA, ctx model.Context, label string, issues *[]model.Issue) *NegotiationDetail {
	offered := make([]model.IKEv2ProposalSummary, 0, len(sa.offered))
	for _, p := range sa.offered {
		offered = append(offered, model.SummarizeIKEv2Proposal(p))
	}
	var chosen *model.IKEv2ProposalSummary
	if len(sa.chosen) > 0 {
		s := model.SummarizeIKEv2Proposal(sa.chosen[0])
		chosen = &s
	}
	if chosen != nil && len(chosen.Weak) > 0 && sa.chosenFrame != nil {
		iss := model.MakeIssue(
			model.SeverityInfo, "IKE_WEAK_ALGORITHM",
			fmt.Sprintf("IKE SA %s negotiated %s, which RFC 8247 says not to use", label, strings.Join(chosen.Weak, ", ")),
			[]int{*sa.chosenFrame},
		)
		iss.Algorithms = chosen.Weak
		*issues = append(*issues, iss)
	}
	for _, note := range sa.notifies {
		if note.typ == 4 || note.typ == 11 {
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "IKE_"+note.name,
				fmt.Sprintf("%s sent %s to %s in cleartext: %s", note.from, note.name, note.to, model.IKEv2NotifyHints[note.typ]),
				[]int{note.frame},
			))
		}
	}

	natDetected := len(sa.natTranslated) > 0
	moved := sa.hasFirst4500
	var natVerdict string
	switch {
	case !sa.natdSeen:
		natVerdict = "no NAT detection payloads seen (IKE_SA_INIT not captured, or the peer does not send them)"
	case natDetected:
		first := sa.natTranslated[0]
		natVerdict = fmt.Sprintf("NAT detected: the %s %s of the %s from %s does not match the NAT_DETECTION hash its sender computed, so an address or port was translated before the capture point",
			first.Field, first.Observed, first.Message, first.Sender)
		if moved {
			natVerdict += "; IKE moved to UDP 4500"
		} else {
			natVerdict += "; IKE never moved to UDP 4500"
		}
	default:
		natVerdict = "no NAT between the peers and this capture point: every NAT_DETECTION hash matches the addresses and ports on the wire"
		if moved {
			natVerdict += "; IKE moved to UDP 4500 anyway (NAT detected beyond the capture point, or forced NAT-T)"
		}
	}

	limit := uint32(3)
	if sa.hasMinLiveLen {
		limit = sa.minLiveLen + 3
	}
	var pending []*livenessEntry
	for _, p := range sa.pendingLive {
		if p.length <= limit {
			pending = append(pending, p)
		}
	}
	slices.SortStableFunc(pending, func(a, b *livenessEntry) int {
		if c := cmp.Compare(a.firstT, b.firstT); c != 0 {
			return c
		}
		if c := cmp.Compare(a.frame, b.frame); c != 0 {
			return c
		}
		return cmp.Compare(a.from, b.from)
	})

	inFlightSet := make(map[*livenessEntry]bool)
	var unanswered []*livenessEntry
	for _, p := range pending {
		if !p.answered && p.tries == 1 && ctx.End != nil && (*ctx.End-p.lastT) < livenessInFlightS {
			inFlightSet[p] = true
		} else if !p.answered {
			unanswered = append(unanswered, p)
		}
	}

	var senderOrder []string
	bySender := make(map[string][]float64)
	for _, p := range pending {
		if _, ok := bySender[p.from]; !ok {
			senderOrder = append(senderOrder, p.from)
		}
		bySender[p.from] = append(bySender[p.from], p.firstT)
	}
	countsBySender := make(map[string]int, len(senderOrder))
	intervals := make(map[string]*float64, len(senderOrder))
	for _, sender := range senderOrder {
		times := bySender[sender]
		countsBySender[sender] = len(times)
		if len(times) > 1 {
			gaps := make([]float64, 0, len(times)-1)
			for i := 1; i < len(times); i++ {
				gaps = append(gaps, times[i]-times[i-1])
			}
			med := model.Median(gaps)
			v := model.Round(*med, 3)
			intervals[sender] = &v
		} else {
			intervals[sender] = nil
		}
	}

	if len(unanswered) > 0 {
		last := unanswered[0]
		tries := 0
		unFrames := make([]int, 0, len(unanswered))
		for _, p := range unanswered {
			if p.lastT > last.lastT {
				last = p
			}
			tries += p.tries
			unFrames = append(unFrames, p.frame)
		}
		iss := model.MakeIssue(
			model.SeverityWarning, "IKE_LIVENESS_UNANSWERED",
			fmt.Sprintf("%s sent %d liveness check(s) (DPD, %d transmission(s)) to %s with no reply; DPD declares the peer dead after its retries and tears the SA down (heuristic: an empty encrypted INFORMATIONAL, the content cannot be read)",
				last.from, len(unanswered), tries, last.to),
			unFrames,
		)
		iss.Peer = last.to
		*issues = append(*issues, iss)
	}

	unansCap, _ := model.Cap(unanswered, ctx.MaxItems)
	unansOut := make([]UnansweredLiveness, 0, len(unansCap))
	for _, p := range unansCap {
		unansOut = append(unansOut, UnansweredLiveness{
			From:          p.from,
			To:            p.to,
			FirstT:        ctx.Rel(&p.firstT),
			LastT:         ctx.Rel(&p.lastT),
			Transmissions: p.tries,
			Frame:         p.frame,
		})
	}
	liveFrames := make([]int, 0, min(len(pending), 10))
	for i := 0; i < len(pending) && i < 10; i++ {
		liveFrames = append(liveFrames, pending[i].frame)
	}

	invalidOut := make([]InvalidKEEntry, 0, len(sa.invalidKE))
	for _, ik := range sa.invalidKE {
		invalidOut = append(invalidOut, InvalidKEEntry{
			GroupRequested: ik.groupRequested,
			GroupOffered:   ik.groupOffered,
			Frame:          ik.frame,
			T:              ctx.Rel(&ik.t),
		})
	}
	var first4500Frame *int
	var first4500T *float64
	if moved {
		fc := sa.first4500Frame
		first4500Frame = &fc
		first4500T = ctx.Rel(&sa.first4500T)
	}
	authPorts := make([]int, 0, len(sa.authPorts))
	for p := range sa.authPorts {
		authPorts = append(authPorts, p)
	}
	slices.Sort(authPorts)
	transOut := sa.natTranslated
	if len(transOut) > 10 {
		transOut = transOut[:10]
	}
	if transOut == nil {
		transOut = []NATTranslatedEntry{}
	}

	return &NegotiationDetail{
		ProposalsOffered: offered,
		OfferedFrame:     sa.offeredFrame,
		ProposalChosen:   chosen,
		ChosenFrame:      sa.chosenFrame,
		KEGroupsOffered:  sa.keOffered,
		KEGroupChosen:    sa.keChosen,
		InvalidKEPayload: invalidOut,
		NATDetection: NATDetectionDetail{
			PayloadsSeen:      sa.natdSeen,
			NATDetected:       natDetected,
			Translated:        transOut,
			MovedToUDP4500:    moved,
			FirstUDP4500Frame: first4500Frame,
			FirstUDP4500T:     first4500T,
			IKEAuthUDPPorts:   authPorts,
			Verdict:           natVerdict,
		},
		Liveness: LivenessDetail{
			Checks:              len(pending),
			Answered:            len(pending) - len(unanswered) - len(inFlightSet),
			Unanswered:          len(unanswered),
			PendingAtCaptureEnd: len(inFlightSet),
			BySender:            countsBySender,
			IntervalSBySender:   intervals,
			UnansweredChecks:    unansOut,
			Frames:              liveFrames,
			Note:                "liveness checks are the SA's smallest INFORMATIONAL requests (empty inside SK, which is what IKEv2 DPD sends); inferred from size because the payload is encrypted",
		},
		ChildSA: "not visible: the child SA proposal, traffic selectors, identities and AUTH payload travel inside the encrypted IKE_AUTH",
	}
}
