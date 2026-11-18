// Package grenhrp implements GRE tunnel reporting, key mismatch checking, and verdicts.
package grenhrp

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// reportResolutions formats NHRP resolution entries, issues, and resolved timeline events.
func (d *Detector) reportResolutions(ctx model.Context, issues *[]model.Issue, events *[]model.Event) []ResolutionEntry {
	resSorted := make([]*resTrack, 0, len(d.resolutions))
	for _, r := range d.resolutions {
		resSorted = append(resSorted, r)
	}
	slices.SortStableFunc(resSorted, func(a, b *resTrack) int {
		if a.firstT < b.firstT {
			return -1
		}
		if a.firstT > b.firstT {
			return 1
		}
		return 0
	})

	resolutions := make([]ResolutionEntry, 0, len(resSorted))
	for _, res := range resSorted {
		hasMatchErr := false
		if res.reqID != nil {
			for _, e := range d.errors {
				if e.reqID != nil && *e.reqID == *res.reqID {
					hasMatchErr = true
					break
				}
			}
		}
		var resEnum ResResult
		switch {
		case res.replies > 0:
			positive := false
			for _, a := range res.answers {
				if a.Code != nil && *a.Code == 0 {
					positive = true
					break
				}
			}
			if positive {
				resEnum = ResResolved
			} else {
				resEnum = ResNegativeReply
			}
		case hasMatchErr:
			resEnum = ResErrorIndication
		default:
			resEnum = ResUnanswered
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "NHRP_RESOLUTION_UNANSWERED",
				fmt.Sprintf("%s asked to resolve %s and got no reply in this capture",
					optStr(res.requesterTunnelIP), optStr(res.target)),
				res.reqFrames,
			))
		}
		for _, ans := range res.answers {
			if ans.Code != nil && *ans.Code == 0 {
				fr := ans.Frame
				*events = append(*events, model.MakeEvent(
					ctx, res.firstT, "nhrp", "resolved",
					fmt.Sprintf("%s resolved for %s: tunnel %s at NBMA %s",
						optStr(res.target), optStr(res.requesterTunnelIP), optStr(ans.ClientTunnelIP), optStr(ans.ClientNBMA)),
					&fr,
				))
			}
		}
		ansOut := res.answers[:min(len(res.answers), 5)]
		if ansOut == nil {
			ansOut = []ResolutionAnswer{}
		}
		resolutions = append(resolutions, ResolutionEntry{
			RequesterTunnelIP: res.requesterTunnelIP,
			RequesterNBMA:     res.requesterNBMA,
			Target:            res.target,
			RequestID:         res.reqID,
			Result:            resEnum.String(),
			RequestsSeen:      res.requests,
			Replies:           res.replies,
			Answers:           ansOut,
			FirstT:            ctx.Rel(&res.firstT),
			RequestFrames:     nonNilInts(res.reqFrames),
			ReplyFrames:       nonNilInts(res.repFrames),
		})
	}
	return resolutions
}

// reportTunnels emits GRE tunnel statistics, direction key mismatch checks, and spoke-to-spoke sightings.
func (d *Detector) reportTunnels(ctx model.Context, hubs map[string]*HubEntry, spokes map[string]*SpokeEntry, issues *[]model.Issue, events *[]model.Event) ([]TunnelEntry, []SpokeTunnelEntry) {
	sorted := make([]*tunnelTrack, 0, len(d.tunnels))
	for _, t := range d.tunnels {
		sorted = append(sorted, t)
	}
	slices.SortStableFunc(sorted, func(a, b *tunnelTrack) int {
		return cmp.Compare(a.firstT, b.firstT)
	})

	tunnels := make([]TunnelEntry, 0, len(sorted))
	spokeToSpoke := []SpokeTunnelEntry{}
	seenPairs := make(map[[2]string]bool)

	for _, tun := range sorted {
		keys := make([]uint32, 0, len(tun.keys))
		keyless := 0
		for kv, cnt := range tun.keys {
			if kv.hasKey {
				keys = append(keys, kv.key)
			} else {
				keyless += cnt
			}
		}
		slices.Sort(keys)
		tunnels = append(tunnels, TunnelEntry{
			Src:            tun.src,
			Dst:            tun.dst,
			Packets:        tun.packets,
			Bytes:          tun.bytes,
			GREKeys:        keys,
			KeylessPackets: keyless,
			InnerProtocols: maps.Clone(tun.inner),
			FirstT:         ctx.Rel(&tun.firstT),
			LastT:          ctx.Rel(&tun.lastT),
			Frames:         nonNilInts(tun.frames),
		})

		pk := model.PairKey(tun.src, tun.dst)
		if seenPairs[pk] {
			continue
		}
		seenPairs[pk] = true

		rev, hasRev := d.tunnels[tunnelDirKey{src: tun.dst, dst: tun.src}]
		if hasRev && !sameKeySet(tun.keys, rev.keys) {
			var frames []int
			frames = append(frames, tun.frames[:min(len(tun.frames), 3)]...)
			frames = append(frames, rev.frames[:min(len(rev.frames), 3)]...)
			*issues = append(*issues, model.MakeIssue(
				model.SeverityError, "GRE_KEY_MISMATCH",
				fmt.Sprintf("GRE key differs by direction: %s->%s uses %s, %s->%s uses %s; the receiver drops packets whose key does not match its tunnel key",
					tun.src, tun.dst, pyFormatKeySet(tun.keys), tun.dst, tun.src, pyFormatKeySet(rev.keys)),
				frames,
			))
		}
		_, srcIsSpoke := spokes[tun.src]
		_, dstIsSpoke := spokes[tun.dst]
		_, srcIsHub := hubs[tun.src]
		_, dstIsHub := hubs[tun.dst]
		if srcIsSpoke && dstIsSpoke && !srcIsHub && !dstIsHub {
			total := tun.packets
			if hasRev {
				total += rev.packets
			}
			spokeToSpoke = append(spokeToSpoke, SpokeTunnelEntry{
				Endpoints: []string{pk[0], pk[1]},
				Packets:   total,
				FirstT:    ctx.Rel(&tun.firstT),
			})
			fr := tun.frames[0]
			*events = append(*events, model.MakeEvent(
				ctx, tun.firstT, "gre", "spoke_to_spoke",
				fmt.Sprintf("direct spoke-to-spoke GRE %s->%s", tun.src, tun.dst),
				&fr,
			))
		}
	}
	return tunnels, spokeToSpoke
}

// buildVerdict formats the single-sentence GRE/NHRP summary matching GreNhrpDetector._verdict().
func buildVerdict(present bool, hubs []*HubEntry, regs []RegistrationEntry, s2s []SpokeTunnelEntry, tunnels []TunnelEntry) string {
	if !present {
		return "No GRE traffic in this capture."
	}
	if len(regs) == 0 {
		return fmt.Sprintf("%d GRE tunnel direction(s) seen; no NHRP registrations captured (static GRE, or NHRP outside the capture window)", len(tunnels))
	}
	parts := make([]string, 0, len(hubs)+1)
	for _, hub := range hubs {
		ok := len(hub.SpokesRegistered)
		total := ok + len(hub.SpokesRefused) + len(hub.SpokesUnanswered)
		text := fmt.Sprintf("%d of %d spoke(s) registered with hub %s (%s)", ok, total, hub.NBMA, optStr(hub.TunnelIP))
		if len(hub.SpokesRefused) > 0 {
			text += "; refused: " + strings.Join(hub.SpokesRefused, ", ")
		}
		if len(hub.SpokesUnanswered) > 0 {
			text += "; unanswered: " + strings.Join(hub.SpokesUnanswered, ", ")
		}
		parts = append(parts, text)
	}
	if len(s2s) > 0 {
		parts = append(parts, fmt.Sprintf("%d spoke-to-spoke tunnel(s) carried traffic", len(s2s)))
	}
	return "DMVPN overlay: " + strings.Join(parts, "; ")
}
