// Package ipsec IKEv2 and IKEv1 SA outcome classification helpers.
package ipsec

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// ikev2Outcome determines IKEv2 SA negotiation status and records unanswered/refused issues and events.
func ikev2Outcome(sa *ikeSA, espAfter []*espFlow, label string, ctx model.Context, issues *[]model.Issue, events *[]model.Event) (string, string) {
	var initEx, authEx []*exchangeState
	for _, k := range sa.order {
		if k.exch == 34 {
			initEx = append(initEx, sa.exchanges[k])
		} else if k.exch == 35 {
			authEx = append(authEx, sa.exchanges[k])
		}
	}
	if len(initEx) == 0 && len(authEx) == 0 {
		if len(espAfter) > 0 {
			return "established", "IKE SA was already up when the capture began; ESP is flowing"
		}
		return "in_progress", "only post-authentication exchanges were captured"
	}
	initStr, respStr := optStr(sa.initiator), optStr(sa.responder)

	if len(initEx) > 0 {
		ex := initEx[len(initEx)-1]
		if ex.responses == 0 {
			iss := model.MakeIssue(
				model.SeverityError, "IKE_NO_RESPONSE",
				fmt.Sprintf("%s never answered IKE_SA_INIT from %s (%d request(s), %d retransmission(s)): UDP 500 blocked, wrong peer address, or IKE not configured on the peer",
					respStr, initStr, ex.requests, ex.retransmissions),
				ex.reqFrames,
			)
			iss.Initiator = initStr
			iss.Responder = respStr
			*issues = append(*issues, iss)
			var fr *int
			if len(ex.reqFrames) > 0 {
				v := ex.reqFrames[0]
				fr = &v
			}
			*events = append(*events, model.MakeEvent(ctx, ex.firstT, "ike", "no_response", fmt.Sprintf("IKE_SA_INIT %s unanswered", label), fr))
			return "no_response", fmt.Sprintf("IKE_SA_INIT sent %d time(s), never answered", ex.requests)
		}

		var lastNotifies []int
		if len(ex.respNotifies) > 0 {
			lastNotifies = ex.respNotifies[len(ex.respNotifies)-1]
		}
		var errs []int
		for _, c := range lastNotifies {
			if model.IKENotifyIsError(2, c) {
				errs = append(errs, c)
			}
		}
		if len(errs) > 0 {
			errNames := make([]string, len(errs))
			for i, c := range errs {
				errNames[i] = model.IKENotifyName(2, c)
			}
			names := strings.Join(errNames, ", ")
			hint := model.IKEv2NotifyHints[errs[0]]
			msg := fmt.Sprintf("%s refused IKE_SA_INIT from %s: %s", respStr, initStr, names)
			if hint != "" {
				msg += fmt.Sprintf(" (%s)", hint)
			}
			msg += fmt.Sprintf("; %d attempt(s)", ex.requests)
			iss := model.MakeIssue(model.SeverityError, "IKE_"+model.IKENotifyName(2, errs[0]), msg, ex.respFrames)
			iss.Notify = names
			*issues = append(*issues, iss)
			var fr *int
			if len(ex.respFrames) > 0 {
				v := ex.respFrames[0]
				fr = &v
			}
			*events = append(*events, model.MakeEvent(ctx, ex.firstT, "ike", "negotiation_failed", fmt.Sprintf("IKE_SA_INIT %s refused: %s", label, names), fr))
			return "failed", "IKE_SA_INIT refused: " + names
		}

		if len(ex.respNotifies) > 1 {
			earlySet := make(map[int]bool)
			for _, notes := range ex.respNotifies[:len(ex.respNotifies)-1] {
				for _, c := range notes {
					if model.IKENotifyIsError(2, c) || c == 16390 {
						earlySet[c] = true
					}
				}
			}
			if len(earlySet) > 0 {
				codes := make([]int, 0, len(earlySet))
				for c := range earlySet {
					codes = append(codes, c)
				}
				slices.Sort(codes)
				names := make([]string, len(codes))
				for i, c := range codes {
					names[i] = model.IKENotifyName(2, c)
				}
				*issues = append(*issues, model.MakeIssue(
					model.SeverityInfo, "IKE_RETRIED",
					fmt.Sprintf("IKE_SA_INIT %s succeeded after a retry (%s)", label, strings.Join(names, ", ")),
					ex.respFrames,
				))
			}
		}
	}

	if len(authEx) == 0 {
		if len(espAfter) > 0 {
			return "established", "ESP flows between the peers (IKE_AUTH not captured)"
		}
		return "sa_init_only", "IKE_SA_INIT completed; IKE_AUTH not seen"
	}

	ex := authEx[len(authEx)-1]
	if ex.responses == 0 {
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, "IKE_AUTH_NO_RESPONSE",
			fmt.Sprintf("%s never answered IKE_AUTH from %s (%d request(s)): often a large IKE_AUTH (certificates) fragmented and dropped, or the responder silently rejecting it",
				respStr, initStr, ex.requests),
			ex.reqFrames,
		))
		var fr *int
		if len(ex.reqFrames) > 0 {
			v := ex.reqFrames[0]
			fr = &v
		}
		*events = append(*events, model.MakeEvent(ctx, ex.firstT, "ike", "no_response", fmt.Sprintf("IKE_AUTH %s unanswered", label), fr))
		return "auth_no_response", "IKE_AUTH sent, never answered"
	}

	var respLen uint32
	if len(ex.respLengths) > 0 {
		respLen = ex.respLengths[len(ex.respLengths)-1]
	}
	if len(espAfter) > 0 {
		var fr *int
		if len(ex.respFrames) > 0 {
			v := ex.respFrames[0]
			fr = &v
		}
		*events = append(*events, model.MakeEvent(ctx, ex.firstT, "ike", "established", fmt.Sprintf("IKE SA %s established (IKE_AUTH answered, ESP followed)", label), fr))
		return "established", "IKE_SA_INIT and IKE_AUTH completed and ESP followed"
	}
	if respLen != 0 && respLen <= smallIKEAuthResponse {
		iss := model.MakeIssue(
			model.SeverityWarning, "IKE_AUTH_LIKELY_FAILED",
			fmt.Sprintf("IKE_AUTH response from %s is only %d bytes and no ESP followed: the size of an encrypted error notification (often AUTHENTICATION_FAILED or TS_UNACCEPTABLE). Heuristic: the payload is encrypted and cannot be read",
				respStr, respLen),
			ex.respFrames,
		)
		rl := int(respLen)
		iss.ResponseLength = &rl
		*issues = append(*issues, iss)
		return "auth_likely_failed", fmt.Sprintf("IKE_AUTH answered with a %d-byte response and no ESP followed", respLen)
	}
	*issues = append(*issues, model.MakeIssue(
		model.SeverityInfo, "IKE_NO_ESP_YET",
		fmt.Sprintf("IKE_AUTH %s completed but no ESP was seen afterwards (no traffic yet, or the capture ended)", label),
		ex.respFrames,
	))
	return "authenticated_no_esp", "IKE_AUTH completed; no ESP seen afterwards"
}

// ikev1Outcome classifies an IKEv1 SA using cleartext notify codes and phase 1/2 counts.
func ikev1Outcome(sa *ikeSA, espAfter []*espFlow, label string, ctx model.Context, issues *[]model.Issue, events *[]model.Event) (string, string) {
	var errs []rawNotify
	for _, n := range sa.notifies {
		if n.isError {
			errs = append(errs, n)
		}
	}
	if len(errs) > 0 {
		nameSet := make(map[string]bool)
		var frames []int
		for _, e := range errs {
			nameSet[e.name] = true
			frames = append(frames, e.frame)
		}
		namesSlice := sortedKeys(nameSet)
		names := strings.Join(namesSlice, ", ")
		codeName := "IKEV1_" + strings.ReplaceAll(errs[0].name, "-", "_")
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, codeName,
			fmt.Sprintf("IKEv1 %s: %s (cleartext notification)", label, names),
			frames,
		))
		fr := errs[0].frame
		*events = append(*events, model.MakeEvent(ctx, errs[0].t, "ike", "negotiation_failed", fmt.Sprintf("IKEv1 %s: %s", label, names), &fr))
		return "failed", "IKEv1 notification: " + names
	}

	c := sa.ikev1Counts
	p1Init := c[ikev1CountKey{2, "initiator"}] + c[ikev1CountKey{4, "initiator"}]
	p1Resp := c[ikev1CountKey{2, "responder"}] + c[ikev1CountKey{4, "responder"}]
	quick := c[ikev1CountKey{32, "initiator"}] + c[ikev1CountKey{32, "responder"}]
	if p1Init > 0 && p1Resp == 0 {
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, "IKE_NO_RESPONSE",
			fmt.Sprintf("%s never answered IKEv1 phase 1 from %s (%d message(s))", optStr(sa.responder), optStr(sa.initiator), p1Init),
			sa.frames,
		))
		return "no_response", "IKEv1 phase 1 never answered"
	}
	if len(espAfter) > 0 {
		var fr *int
		if len(sa.frames) > 0 {
			v := sa.frames[len(sa.frames)-1]
			fr = &v
		}
		*events = append(*events, model.MakeEvent(ctx, sa.lastT, "ike", "established", fmt.Sprintf("IKEv1 SA %s established (ESP followed)", label), fr))
		return "established", "IKEv1 negotiated and ESP followed"
	}
	if quick > 0 {
		return "phase2_seen", "IKEv1 Quick Mode seen; no ESP afterwards"
	}
	if p1Init > 0 && p1Resp > 0 {
		return "phase1_seen", "IKEv1 phase 1 exchanged; no Quick Mode or ESP seen"
	}
	return "in_progress", "IKEv1 messages seen; outcome not determinable"
}
