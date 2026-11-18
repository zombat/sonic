// Package ipsec IKEv2 proposal, DH group retry, NAT-D verification, and DPD liveness ingestion.
package ipsec

import (
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// feedIKEv2Detail records IKEv2 proposals, KE retries, NAT-D checks, UDP 4500 moves, and DPD checks.
func (d *Detector) feedIKEv2Detail(sa *ikeSA, rec *model.Record, src, dst string, isResponse bool) {
	ike := rec.IKE
	t, n := rec.T, rec.N
	var sport, dport int
	var hasUDP bool
	if rec.UDP != nil && rec.UDP.Sport != nil && rec.UDP.Dport != nil {
		hasUDP = true
		sport, dport = *rec.UDP.Sport, *rec.UDP.Dport
	}
	on4500 := ike.NATT || (hasUDP && (sport == 4500 || dport == 4500))
	if on4500 && !sa.hasFirst4500 {
		sa.hasFirst4500 = true
		sa.first4500T = t
		sa.first4500Frame = n
	}
	if ike.Exch == nil {
		return
	}
	switch *ike.Exch {
	case 35:
		if on4500 {
			sa.authPorts[4500] = true
		} else {
			sa.authPorts[500] = true
		}
	case 34:
		if !isResponse {
			if len(ike.Proposals) > 0 {
				sa.offered = ike.Proposals
				nf := n
				sa.offeredFrame = &nf
			}
			if ike.KEGroup != nil {
				sa.keOffered = append(sa.keOffered, *ike.KEGroup)
			}
		} else {
			if len(ike.Proposals) > 0 {
				sa.chosen = ike.Proposals
				cf := n
				sa.chosenFrame = &cf
			}
			if ike.KEGroup != nil {
				g := *ike.KEGroup
				sa.keChosen = &g
			}
			if ike.InvalidKEGroup != nil {
				var offered *int
				if len(sa.keOffered) > 0 {
					v := sa.keOffered[len(sa.keOffered)-1]
					offered = &v
				}
				sa.invalidKE = append(sa.invalidKE, invalidKETrack{
					groupRequested: *ike.InvalidKEGroup,
					groupOffered:   offered,
					frame:          n,
					t:              t,
				})
			}
		}
		if (len(ike.NATDSrc) > 0 || len(ike.NATDDst) > 0) && hasUDP {
			sa.natdSeen = true
			msgLabel := "IKE_SA_INIT request"
			if isResponse {
				msgLabel = "IKE_SA_INIT response"
			}
			ispiStr, rspiStr := optStrEmpty(ike.ISPI), optStrEmpty(ike.RSPI)
			checks := []struct {
				field  string
				hashes []string
				addr   string
				port   int
			}{
				{"source", ike.NATDSrc, src, sport},
				{"destination", ike.NATDDst, dst, dport},
			}
			for _, ck := range checks {
				if len(ck.hashes) == 0 {
					continue
				}
				if expected, ok := natdHash(ispiStr, rspiStr, ck.addr, ck.port); ok && !slices.Contains(ck.hashes, expected) {
					sa.natTranslated = append(sa.natTranslated, NATTranslatedEntry{
						Message:  msgLabel,
						Sender:   src,
						Field:    ck.field,
						Observed: fmt.Sprintf("%s:%d", ck.addr, ck.port),
						Frame:    n,
					})
				}
			}
		}
	case 37:
		if isResponse {
			if entry, ok := sa.pendingLive[livenessKey{addr: dst, msgID: ike.MsgID}]; ok {
				entry.answered = true
			}
		}
		if ike.Encrypted && ike.Length <= livenessMaxLength {
			if !sa.hasMinLiveLen || ike.Length < sa.minLiveLen {
				sa.hasMinLiveLen = true
				sa.minLiveLen = ike.Length
			}
			if !isResponse {
				lk := livenessKey{addr: src, msgID: ike.MsgID}
				if entry, ok := sa.pendingLive[lk]; ok {
					entry.tries++
					entry.lastT = t
				} else {
					sa.pendingLive[lk] = &livenessEntry{
						from:   src,
						to:     dst,
						firstT: t,
						lastT:  t,
						tries:  1,
						frame:  n,
						length: ike.Length,
					}
				}
			}
		}
	}
}
