// Package ipsec peer-pair encryption audit and cleartext traffic evaluation.
package ipsec

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// candidatePairs returns unordered IP pairs judged by the cleartext vs encrypted audit.
func (d *Detector) candidatePairs() [][2]string {
	var out [][2]string
	if len(d.peers) > 0 {
		for pk := range d.pairs {
			if d.peers[pk[0]] && d.peers[pk[1]] {
				out = append(out, pk)
			}
		}
		return out
	}
	for pk, pair := range d.pairs {
		if len(pair.protected) > 0 {
			out = append(out, pk)
			continue
		}
		for ck := range pair.cleartext {
			if strings.HasPrefix(ck.label, "gre") {
				out = append(out, pk)
				break
			}
		}
	}
	return out
}

// reportEncryption audits protected vs cleartext packet counts across candidate peer pairs.
func (d *Detector) reportEncryption(ctx model.Context, issues *[]model.Issue) ([]PeerPairEntry, int, []CleartextEntry, EncryptionVerdict, string) {
	cands := d.candidatePairs()
	slices.SortFunc(cands, func(a, b [2]string) int {
		if c := cmp.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return cmp.Compare(a[1], b[1])
	})

	pairsOut := make([]PeerPairEntry, 0, len(cands))
	cleartextAll := []CleartextEntry{}
	var noESP [][2]string

	for _, pk := range cands {
		pair := d.pairs[pk]
		type ctEntry struct {
			ck cleartextKey
			ct *cleartextTrack
		}
		// Preserve insertion order before stable descending sort by packet count.
		ctList := make([]ctEntry, 0, len(pair.clearOrder))
		for _, ck := range pair.clearOrder {
			ctList = append(ctList, ctEntry{ck: ck, ct: pair.cleartext[ck]})
		}
		slices.SortStableFunc(ctList, func(a, b ctEntry) int {
			return cmp.Compare(b.ct.packets, a.ct.packets)
		})

		cleartext := make([]CleartextEntry, 0, len(ctList))
		clearPkts := 0
		for _, item := range ctList {
			tVal := item.ct.firstT
			cleartext = append(cleartext, CleartextEntry{
				Protocol: item.ck.label,
				Src:      item.ck.src,
				Dst:      item.ck.dst,
				Packets:  item.ct.packets,
				Bytes:    item.ct.bytes,
				FirstT:   ctx.Rel(&tVal),
				Frames:   nonNilInts(item.ct.frames),
			})
			clearPkts += item.ct.packets
		}

		protected := maps.Clone(pair.protected)
		hasESP := protected["esp"] > 0 || protected["esp-in-udp"] > 0
		var verdict string
		switch {
		case len(cleartext) > 0:
			verdict = "cleartext"
		case hasESP:
			verdict = "encrypted"
		case protected["ike"] > 0:
			verdict = "ike_only"
			noESP = append(noESP, pk)
		default:
			verdict = "no_traffic"
		}

		ctCap := cleartext
		if len(ctCap) > 10 {
			ctCap = ctCap[:10]
		}
		pairsOut = append(pairsOut, PeerPairEntry{
			Endpoints:        []string{pk[0], pk[1]},
			Verdict:          verdict,
			ProtectedPackets: protected,
			CleartextPackets: clearPkts,
			Cleartext:        ctCap,
		})
		cleartextAll = append(cleartextAll, cleartext...)
	}

	slices.SortStableFunc(cleartextAll, func(a, b CleartextEntry) int {
		return cmp.Compare(b.Packets, a.Packets)
	})

	allEncrypted := len(pairsOut) > 0
	encryptedCount := 0
	for _, p := range pairsOut {
		if p.Verdict != "encrypted" {
			allEncrypted = false
		} else {
			encryptedCount++
		}
	}

	var text string
	var code EncryptionVerdict
	switch {
	case len(cleartextAll) > 0:
		lim := min(len(cleartextAll), 5)
		parts := make([]string, 0, lim)
		for i := 0; i < lim; i++ {
			c := cleartextAll[i]
			parts = append(parts, fmt.Sprintf("%s %s->%s %d packets", c.Protocol, c.Src, c.Dst, c.Packets))
		}
		text = "cleartext seen: " + strings.Join(parts, "; ")
		if more := len(cleartextAll) - 5; more > 0 {
			text += fmt.Sprintf("; and %d more", more)
		}
		code = EncCleartextSeen
		pairsLim, _ := model.Cap(pairsOut, ctx.MaxItems)
		for _, pair := range pairsLim {
			if len(pair.Cleartext) == 0 {
				continue
			}
			protoSet := make(map[string]bool)
			onlyICMP := true
			hasGRE := false
			detailParts := make([]string, 0, len(pair.Cleartext))
			var frames []int
			for _, c := range pair.Cleartext {
				protoSet[c.Protocol] = true
				if c.Protocol != "icmp" && c.Protocol != "icmpv6" {
					onlyICMP = false
				}
				if strings.HasPrefix(c.Protocol, "gre") {
					hasGRE = true
				}
				detailParts = append(detailParts, fmt.Sprintf("%s %s->%s %d packets", c.Protocol, c.Src, c.Dst, c.Packets))
				frames = append(frames, c.Frames[:min(len(c.Frames), 3)]...)
			}
			sev := model.SeverityError
			if onlyICMP {
				sev = model.SeverityWarning
			}
			hint := ""
			if hasGRE {
				hint = " GRE without IPsec: the tunnel is not encrypted."
			} else if onlyICMP {
				hint = " Expected if someone pinged or tracerouted the peer's WAN address; otherwise traffic is bypassing the tunnel."
			}
			protos := sortedKeys(protoSet)
			iss := model.MakeIssue(
				sev, "CLEARTEXT_BETWEEN_PEERS",
				fmt.Sprintf("cleartext between %s and %s: %s.%s", pair.Endpoints[0], pair.Endpoints[1], strings.Join(detailParts, "; "), hint),
				frames,
			)
			iss.Endpoints = pair.Endpoints
			iss.Protocols = protos
			cpkts := pair.CleartextPackets
			iss.Packets = &cpkts
			*issues = append(*issues, iss)
		}
	case allEncrypted:
		espPkts := 0
		for _, p := range pairsOut {
			espPkts += p.ProtectedPackets["esp"] + p.ProtectedPackets["esp-in-udp"]
		}
		text = fmt.Sprintf("all inter-site traffic encrypted: %d peer pair(s), %d ESP packets, no cleartext between the same endpoints", len(pairsOut), espPkts)
		code = EncEncrypted
	case len(noESP) > 0:
		lim := min(len(noESP), 5)
		names := make([]string, 0, lim)
		for i := 0; i < lim; i++ {
			names = append(names, fmt.Sprintf("%s<->%s", noESP[i][0], noESP[i][1]))
		}
		text = fmt.Sprintf("no ESP between IKE peers %s: the tunnel carried no protected traffic (or failed to come up)", strings.Join(names, ", "))
		if encryptedCount > 0 {
			text = fmt.Sprintf("%d of %d peer pair(s) encrypted (ESP, no cleartext); %s", encryptedCount, len(pairsOut), text)
		}
		code = EncNoESP
	case len(pairsOut) > 0:
		text = fmt.Sprintf("%d of %d peer pair(s) carry ESP; the others carried no traffic", encryptedCount, len(pairsOut))
		code = EncNoESP
		if encryptedCount > 0 {
			code = EncEncrypted
		}
	default:
		if len(d.peers) > 0 {
			text = "no traffic between the given peers"
		} else {
			text = "no IPsec peers found"
		}
		code = EncNotPresent
	}

	pairsList, omitted := model.Cap(pairsOut, ctx.MaxItems)
	cleartextList, _ := model.Cap(cleartextAll, ctx.MaxItems)
	return pairsList, omitted, cleartextList, code, text
}
