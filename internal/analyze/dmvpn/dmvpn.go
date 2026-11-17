// Package dmvpn packet ingestion, prefix matching, and state types for Phase 3 analysis.
package dmvpn

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// Detector tracks GRE/NHRP and IKE/ESP state to reconstruct DMVPN Phase 3 shortcuts.
type Detector struct {
	hubsGiven      []string
	registeredHubs map[string]bool
	tiSenders      map[string]bool
	dataOrder      []addrPair
	data           map[addrPair]*innerFlowData
	indications    map[redirectKey]*indicationTrack
	requests       []nhrpRequestTrack
	replies        map[uint32][]nhrpReplyTrack
	nilReqReplies  []nhrpReplyTrack
	errors         []nhrpErrorTrack
	ike            map[[2]string]*ikeShortcutState
	esp            map[addrPair]*espDirTrack
	seen           bool
}

// NewDetector returns an initialized Phase 3 detector with optional preconfigured hub NBMA IPs.
func NewDetector(hubs []string) *Detector {
	given := []string{}
	if len(hubs) > 0 {
		given = slices.Clone(hubs)
	}
	return &Detector{
		hubsGiven:      given,
		registeredHubs: make(map[string]bool),
		tiSenders:      make(map[string]bool),
		data:           make(map[addrPair]*innerFlowData),
		indications:    make(map[redirectKey]*indicationTrack),
		replies:        make(map[uint32][]nhrpReplyTrack),
		ike:            make(map[[2]string]*ikeShortcutState),
		esp:            make(map[addrPair]*espDirTrack),
	}
}

// Name returns "dmvpn_phase3".
func (d *Detector) Name() string { return "dmvpn_phase3" }

// Hubs returns the deduplicated sorted union of given hubs, NHRP registration targets, and TI senders.
func (d *Detector) Hubs() []string {
	set := make(map[string]bool)
	for _, h := range d.hubsGiven {
		set[h] = true
	}
	for h := range d.registeredHubs {
		set[h] = true
	}
	for h := range d.tiSenders {
		set[h] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// Present reports whether NHRP traffic, GRE inner flows, or candidate spoke-to-spoke IKE shortcuts were observed.
func (d *Detector) Present() bool {
	return d.seen || len(d.data) > 0 || len(d.encryptedCandidates(d.Hubs())) > 0
}

// Feed ingests a single normalized packet record into DMVPN Phase 3 tracking.
func (d *Detector) Feed(rec *model.Record) {
	if rec.IP == nil {
		return
	}
	src, dst, t, n := rec.IP.Src, rec.IP.Dst, rec.T, rec.N
	if rec.GRE != nil {
		if rec.Inner != nil && rec.Inner.Src != "" {
			ik := addrPair{src: rec.Inner.Src, dst: rec.Inner.Dst}
			flowData, ok := d.data[ik]
			if !ok {
				flowData = &innerFlowData{outers: make(map[addrPair]*outerTiming)}
				d.data[ik] = flowData
				d.dataOrder = append(d.dataOrder, ik)
			}
			okKey := addrPair{src: src, dst: dst}
			entry, exists := flowData.outers[okKey]
			if !exists {
				if len(flowData.outers) < maxDataOutersPerInner {
					flowData.outers[okKey] = &outerTiming{firstT: t, firstN: n, lastT: t, count: 1}
					flowData.order = append(flowData.order, okKey)
				}
			} else {
				entry.lastT = t
				entry.count++
			}
		}
		if rec.NHRP != nil {
			d.seen = true
			d.feedNHRP(rec.NHRP, src, dst, t, n)
		}
	}
	if rec.IKE != nil {
		pk := model.PairKey(src, dst)
		st, ok := d.ike[pk]
		if !ok {
			st = &ikeShortcutState{}
			d.ike[pk] = st
		}
		isResp := (rec.IKE.Flags & 0x20) != 0
		if rec.IKE.Version == 2 && rec.IKE.Exch != nil && *rec.IKE.Exch == 34 {
			if !isResp {
				st.initRequests++
				if !st.hasInit {
					st.hasInit, st.initT, st.initN = true, t, n
					s := src
					st.initiator = &s
				}
			} else {
				st.initResponses++
			}
		} else if rec.IKE.Version == 2 && rec.IKE.Exch != nil && *rec.IKE.Exch == 35 && isResp && !st.hasAuth {
			st.hasAuth, st.authT, st.authN = true, t, n
		}
	}
	if rec.ESP != nil {
		ak := addrPair{src: src, dst: dst}
		flow, ok := d.esp[ak]
		if !ok {
			flow = &espDirTrack{firstT: t, firstN: n}
			d.esp[ak] = flow
		}
		flow.packets++
		flow.lastT = t
		if len(flow.times) < maxESPTimesPerFlow {
			flow.times = append(flow.times, espTimeEntry{t: t, n: n})
		}
	}
}

// feedNHRP handles NHRP control packets seen inside GRE.
func (d *Detector) feedNHRP(nhrp *model.NHRPPacket, src, dst string, t float64, n int) {
	if nhrp.Op == nil {
		return
	}
	switch *nhrp.Op {
	case 3:
		d.registeredHubs[dst] = true
	case 8:
		d.tiSenders[src] = true
		var rk redirectKey
		rk.spoke = dst
		if nhrp.OrigSrc != nil {
			rk.hasSrc, rk.origSrc = true, *nhrp.OrigSrc
		}
		if nhrp.OrigDst != nil {
			rk.hasDst, rk.origDst = true, *nhrp.OrigDst
		}
		if ind, ok := d.indications[rk]; ok {
			ind.count++
		} else {
			d.indications[rk] = &indicationTrack{
				hub: src, spoke: dst, origSrc: nhrp.OrigSrc, origDst: nhrp.OrigDst,
				t: t, n: n, count: 1,
			}
		}
	case 1:
		if len(d.requests) < maxTrackedRequests {
			nbma := src
			if nhrp.SrcNBMA != nil && *nhrp.SrcNBMA != "" {
				nbma = *nhrp.SrcNBMA
			}
			d.requests = append(d.requests, nhrpRequestTrack{
				requesterNBMA: nbma, requester: nhrp.SrcProto, target: nhrp.DstProto,
				reqID: nhrp.ReqID, t: t, n: n, outerSrc: src, outerDst: dst,
			})
		}
	case 2:
		rep := nhrpReplyTrack{
			t: t, n: n, from: src, code: nhrp.Code, clientNBMA: nhrp.ClientNBMA,
			clientProto: nhrp.ClientProto, prefix: nhrp.Prefix,
		}
		if nhrp.ReqID != nil {
			d.replies[*nhrp.ReqID] = append(d.replies[*nhrp.ReqID], rep)
		} else {
			d.nilReqReplies = append(d.nilReqReplies, rep)
		}
	case 7:
		errText := fmt.Sprintf("error %v", nhrp.ErrCode)
		if nhrp.ErrCode != nil {
			if name, ok := model.NHRPErrorCodes[*nhrp.ErrCode]; ok {
				errText = name
			} else {
				errText = fmt.Sprintf("error %d", *nhrp.ErrCode)
			}
		} else {
			errText = "error None"
		}
		d.errors = append(d.errors, nhrpErrorTrack{
			t: t, n: n, from: src, to: dst, reqID: nhrp.ReqID, code: nhrp.ErrCode, errText: errText,
		})
	}
}

// inPrefix reports whether addr belongs to base/prefix (default /32 or /128 when prefix is nil).
func inPrefix(addr string, base *string, prefix *int) bool {
	if addr == "" || base == nil || *base == "" {
		return false
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	b, err := netip.ParseAddr(*base)
	if err != nil {
		return false
	}
	bits := 32
	if prefix != nil {
		bits = *prefix
	}
	pfx := netip.PrefixFrom(b, bits)
	if !pfx.IsValid() {
		return false
	}
	return pfx.Masked().Contains(a)
}
