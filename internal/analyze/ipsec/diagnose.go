// Package ipsec per-SA root-cause diagnostic classification.
package ipsec

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// diagnoseSA produces the single-line Diagnosis explaining what packets proved for an SA.
func diagnoseSA(sa *ikeSA, outcome, detail string, neg *NegotiationDetail, label string, issues *[]model.Issue) Diagnosis {
	if sa.version != 2 {
		return Diagnosis{Code: outcome, Text: detail}
	}
	nat := neg.NATDetection
	offeredParts := make([]string, 0, len(neg.ProposalsOffered))
	for _, p := range neg.ProposalsOffered {
		var ints []string
		for _, x := range p.Integrity {
			if !strings.HasPrefix(x, "(") {
				ints = append(ints, x)
			}
		}
		seg := filterNonEmpty([]string{
			strings.Join(p.Encryption, ", "),
			strings.Join(p.PRF, ", "),
			strings.Join(ints, ", "),
			strings.Join(p.DHGroup, ", "),
		})
		offeredParts = append(offeredParts, strings.Join(seg, "/"))
	}
	offeredText := "(proposal not captured)"
	if len(offeredParts) > 0 {
		offeredText = strings.Join(offeredParts, "; ")
	}

	errCodes := make(map[int]bool)
	for _, n := range sa.notifies {
		if n.isError {
			errCodes[n.typ] = true
		}
	}
	natMissing := nat.NATDetected && !nat.MovedToUDP4500

	switch outcome {
	case "established":
		text := detail
		if neg.ProposalChosen != nil {
			c := neg.ProposalChosen
			seg := filterNonEmpty([]string{
				strings.Join(c.Encryption, ", "),
				strings.Join(c.PRF, ", "),
				strings.Join(c.DHGroup, ", "),
			})
			text = "established with " + strings.Join(seg, "/")
		}
		if len(neg.InvalidKEPayload) > 0 {
			ask := neg.InvalidKEPayload[len(neg.InvalidKEPayload)-1]
			text += fmt.Sprintf(" after a DH group retry (offered group %s, responder asked for group %d)",
				optInt(ask.GroupOffered), ask.GroupRequested)
		}
		lostSet := make(map[string]bool)
		for _, n := range sa.notifies {
			if n.typ == 4 || n.typ == 11 {
				lostSet[n.name] = true
			}
		}
		if len(lostSet) > 0 {
			lost := sortedKeys(lostSet)
			return Diagnosis{
				Code: "peer_lost_sa",
				Text: text + fmt.Sprintf("; later the peer answered with %s: it no longer has the SA (restarted or cleared), so traffic on the old SPIs is dropped until a new SA forms",
					strings.Join(lost, ", ")),
			}
		}
		if neg.Liveness.Unanswered > 0 {
			return Diagnosis{
				Code: "liveness_lost",
				Text: text + "; later its liveness checks (DPD) went unanswered: the peer stopped answering",
			}
		}
		return Diagnosis{Code: "ok", Text: text}

	case "failed":
		if errCodes[14] {
			return Diagnosis{
				Code: "proposal_mismatch",
				Text: fmt.Sprintf("proposal mismatch: %s offered %s; %s answered NO_PROPOSAL_CHOSEN. The responder's own proposal never crosses the wire, so compare its configuration with this list",
					optStr(sa.initiator), offeredText, optStr(sa.responder)),
			}
		}
		if errCodes[17] {
			var offered, req string
			if len(neg.InvalidKEPayload) > 0 {
				ask := neg.InvalidKEPayload[len(neg.InvalidKEPayload)-1]
				offered = optInt(ask.GroupOffered)
				req = fmt.Sprintf("%d", ask.GroupRequested)
			} else {
				offered, req = "None", "None"
			}
			return Diagnosis{
				Code: "dh_group_mismatch",
				Text: fmt.Sprintf("DH group mismatch: %s sent a KE for group %s, %s asked for group %s, and no retry with that group succeeded on this IKE SA",
					optStr(sa.initiator), offered, optStr(sa.responder), req),
			}
		}
		if errCodes[24] {
			return Diagnosis{
				Code: "auth_failed",
				Text: "AUTHENTICATION_FAILED sent in cleartext: pre-shared key, certificate or identity mismatch",
			}
		}
		nameSet := make(map[string]bool, len(errCodes))
		for c := range errCodes {
			nameSet[model.IKENotifyName(2, c)] = true
		}
		return Diagnosis{Code: "refused", Text: "refused with " + strings.Join(sortedKeys(nameSet), ", ")}

	case "no_response":
		return Diagnosis{
			Code: "no_reply",
			Text: fmt.Sprintf("no reply: %s never answered IKE_SA_INIT from %s (peer down, UDP 500 filtered, wrong peer address, or no IKEv2 policy matching the front-door VRF)",
				optStr(sa.responder), optStr(sa.initiator)),
		}

	case "auth_no_response":
		if natMissing {
			frames := make([]int, 0, len(nat.Translated))
			for _, tr := range nat.Translated {
				frames = append(frames, tr.Frame)
			}
			*issues = append(*issues, model.MakeIssue(
				model.SeverityError, "IKE_NAT_T_MISSING",
				fmt.Sprintf("IKE SA %s: NAT detected, but IKE_AUTH stayed on UDP 500 and was never answered (NAT traversal disabled on one peer, or the NAT drops UDP 500 after the first exchange)", label),
				frames,
			))
			return Diagnosis{
				Code: "nat_t_missing",
				Text: "NAT-T missing: the NAT_DETECTION hashes show a translation, IKE_AUTH stayed on UDP 500 and got no reply",
			}
		}
		if slices.Contains(nat.IKEAuthUDPPorts, 4500) {
			return Diagnosis{
				Code: "udp_4500_blocked",
				Text: "IKE_AUTH moved to UDP 4500 and got no reply: UDP 4500 filtered on the path",
			}
		}
		return Diagnosis{
			Code: "auth_no_reply",
			Text: "IKE_AUTH never answered: a pre-shared key mismatch can show this way (some peers drop the message silently instead of sending AUTHENTICATION_FAILED); also a large IKE_AUTH fragmented and dropped. The AUTH payload is encrypted, so the key itself is never visible",
		}

	case "auth_likely_failed":
		return Diagnosis{
			Code: "auth_failed",
			Text: "authentication failed (heuristic): the IKE_AUTH response is the size of one encrypted error notification and no ESP followed. A PSK mismatch shows exactly this way (AUTHENTICATION_FAILED inside SK) or as IKE_AUTH retransmissions with no reply; the hash or key is never visible",
		}

	case "authenticated_no_esp":
		return Diagnosis{
			Code: "no_esp_after_auth",
			Text: "IKE_AUTH answered with a full-size response but no ESP followed: no traffic yet, or the child SA was refused inside the encrypted response (NO_PROPOSAL_CHOSEN or TS_UNACCEPTABLE for the child SA cannot be read)",
		}

	case "in_progress":
		if neg.Liveness.Unanswered > 0 {
			return Diagnosis{
				Code: "peer_unresponsive",
				Text: "the SA was up before the capture began; its liveness checks (DPD) went unanswered",
			}
		}

	case "sa_init_only":
		if natMissing {
			return Diagnosis{
				Code: "nat_t_missing",
				Text: "NAT detected, IKE_SA_INIT completed, and IKE_AUTH never appeared on UDP 500 or 4500 at this capture point",
			}
		}
	}
	return Diagnosis{Code: outcome, Text: detail}
}
