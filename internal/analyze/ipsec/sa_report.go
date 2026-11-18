// Package ipsec IKE SA report construction and simultaneous initiation collision detection.
package ipsec

import (
	"fmt"
	"math"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// reportSA converts one tracked ikeSA into its IKESAReport and emits lifecycle issues/events.
func (d *Detector) reportSA(sa *ikeSA, ctx model.Context, espPairs map[[2]string][]*espFlow, issues *[]model.Issue, events *[]model.Event) IKESAReport {
	exNames := model.IKEv1Exchanges
	if sa.version == 2 {
		exNames = model.IKEv2Exchanges
	}
	exchanges := make([]ExchangeEntry, 0, len(sa.order))
	retrans := 0
	for _, exKey := range sa.order {
		ex := sa.exchanges[exKey]
		retrans += ex.retransmissions
		name, ok := exNames[exKey.exch]
		if !ok {
			name = fmt.Sprintf("exchange_%d", exKey.exch)
		}
		exchanges = append(exchanges, ExchangeEntry{
			Exchange:        name,
			MessageID:       exKey.msgID,
			Requests:        ex.requests,
			Responses:       ex.responses,
			Retransmissions: ex.retransmissions,
			Unanswered:      ex.awaiting && sa.version == 2,
			Encrypted:       ex.encrypted,
			T:               ctx.Rel(&ex.firstT),
			RequestFrames:   nonNilInts(ex.reqFrames),
			ResponseFrames:  nonNilInts(ex.respFrames),
		})
	}

	var espAfter []*espFlow
	if sa.initiator != nil && sa.responder != nil {
		pk := model.PairKey(*sa.initiator, *sa.responder)
		saFirst := 0.0
		if sa.hasTime {
			saFirst = sa.firstT
		}
		for _, flow := range espPairs[pk] {
			if flow.hasTime && flow.lastT != 0 && flow.lastT >= saFirst {
				espAfter = append(espAfter, flow)
			}
		}
	}

	label := fmt.Sprintf("%s -> %s", optStr(sa.initiator), optStr(sa.responder))
	rekeys := 0
	var outcome, detail string
	if sa.version == 2 {
		outcome, detail = ikev2Outcome(sa, espAfter, label, ctx, issues, events)
		for k, ex := range sa.exchanges {
			if k.exch == 36 && ex.responses > 0 {
				rekeys++
			}
		}
	} else {
		outcome, detail = ikev1Outcome(sa, espAfter, label, ctx, issues, events)
		qm := 0
		for k := range sa.exchanges {
			if k.exch == 32 {
				qm++
			}
		}
		if qm > 1 {
			rekeys = qm - 1
		}
	}
	if rekeys > 0 && sa.hasTime {
		*events = append(*events, model.MakeEvent(
			ctx, sa.lastT, "ike", "rekey",
			fmt.Sprintf("%d rekey exchange(s) on IKE SA %s (%s)", rekeys, sa.ispi, label),
			nil,
		))
	}

	notifyLimit := min(len(sa.notifies), 20)
	notifies := make([]NotifyEntry, 0, notifyLimit)
	for _, n := range sa.notifies[:notifyLimit] {
		notifies = append(notifies, NotifyEntry{
			Type:  n.typ,
			Name:  n.name,
			From:  n.from,
			Frame: n.frame,
			Error: n.isError,
		})
	}

	var negotiation *NegotiationDetail
	if sa.version == 2 {
		negotiation = buildNegotiation(sa, ctx, label, issues)
	}
	diag := diagnoseSA(sa, outcome, detail, negotiation, label, issues)

	ports := make([]int, 0, len(sa.ports))
	for p := range sa.ports {
		ports = append(ports, p)
	}
	slices.Sort(ports)

	var ft, lt *float64
	if sa.hasTime {
		ft = ctx.Rel(&sa.firstT)
		lt = ctx.Rel(&sa.lastT)
	}

	return IKESAReport{
		IKEVersion:      sa.version,
		Negotiation:     negotiation,
		Diagnosis:       diag,
		InitiatorSPI:    sa.ispi,
		ResponderSPI:    sa.rspi,
		Initiator:       sa.initiator,
		Responder:       sa.responder,
		UDPPorts:        ports,
		NAT_T:           sa.natt,
		Outcome:         outcome,
		Detail:          detail,
		Retransmissions: retrans,
		Rekeys:          rekeys,
		Notifies:        notifies,
		Exchanges:       exchanges[:min(len(exchanges), 20)],
		FirstT:          ft,
		LastT:           lt,
		Frames:          nonNilInts(sa.frames),
	}
}

// reportCollisions flags pairs of simultaneous opposing IKEv2 IKE_SA_INIT negotiations.
func reportCollisions(ikeSAs []IKESAReport, issues *[]model.Issue, events *[]model.Event, ctx model.Context) {
	var startedIdx []int
	for i := range ikeSAs {
		sa := &ikeSAs[i]
		if sa.IKEVersion == 2 && sa.Negotiation != nil && sa.Negotiation.OfferedFrame != nil && sa.FirstT != nil {
			startedIdx = append(startedIdx, i)
		}
	}
	for idxA := 0; idxA < len(startedIdx); idxA++ {
		for idxB := idxA + 1; idxB < len(startedIdx); idxB++ {
			a := &ikeSAs[startedIdx[idxA]]
			b := &ikeSAs[startedIdx[idxB]]
			if strPtrEq(a.Initiator, b.Responder) && strPtrEq(a.Responder, b.Initiator) &&
				math.Abs(*a.FirstT-*b.FirstT) <= collisionWindowS {
				if a.CollidedWith == "" {
					a.CollidedWith = b.InitiatorSPI
				}
				if b.CollidedWith == "" {
					b.CollidedWith = a.InitiatorSPI
				}
				var frA, frB int
				if len(a.Frames) > 0 {
					frA = a.Frames[0]
				}
				if len(b.Frames) > 0 {
					frB = b.Frames[0]
				}
				minFr := min(frA, frB)
				baseStart := 0.0
				if ctx.Start != nil {
					baseStart = *ctx.Start
				}
				*issues = append(*issues, model.MakeIssue(
					model.SeverityInfo, "IKE_SA_COLLISION",
					fmt.Sprintf("%s and %s each started an IKE SA to the other within %s s (SPIs %s and %s); both completed, and the peers normally delete one. Common when both spokes of a DMVPN Phase 3 shortcut resolve each other at once",
						optStr(a.Initiator), optStr(b.Initiator), model.FormatPyFloat(model.Round(math.Abs(*a.FirstT-*b.FirstT), 3)), a.InitiatorSPI, b.InitiatorSPI),
					[]int{frA, frB},
				))
				*events = append(*events, model.MakeEvent(
					ctx, baseStart+min(*a.FirstT, *b.FirstT), "ike", "sa_collision",
					fmt.Sprintf("simultaneous IKE SA initiation %s <-> %s", optStr(a.Initiator), optStr(b.Initiator)),
					&minFr,
				))
			}
		}
	}
}
