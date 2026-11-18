// Package reach implements the ReachabilityDetector (ICMP echo/error tracking
// and ARP monitoring) and ConversationDetector.
package reach

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

const (
	pendingWindowS     = 2.0
	maxRequestsPerPair = 200000
)

// ReachabilityDetector tracks ICMP echo loss/RTT/outages, ICMP errors, and ARP health.
type ReachabilityDetector struct {
	requests         map[requestKey]*pingRequest
	pairs            map[pairID]*echoPairTrack
	pairOrder        []pairID
	unmatchedReplies map[pairID]int
	icmpErrors       map[icmpErrKey]*icmpErrTrack
	icmpErrOrder     []icmpErrKey
	arpRequests      map[string]*arpReqTrack
	arpReplies       map[string]*arpRepTrack
	arpReplyOrder    []string
	gratuitous       int
	icmpSeen         bool
	arpSeen          bool
}

// NewReachabilityDetector returns an initialized ReachabilityDetector.
func NewReachabilityDetector() *ReachabilityDetector {
	return &ReachabilityDetector{
		requests:         make(map[requestKey]*pingRequest),
		pairs:            make(map[pairID]*echoPairTrack),
		unmatchedReplies: make(map[pairID]int),
		icmpErrors:       make(map[icmpErrKey]*icmpErrTrack),
		arpRequests:      make(map[string]*arpReqTrack),
		arpReplies:       make(map[string]*arpRepTrack),
	}
}

// Name returns the canonical detector name "reachability".
func (d *ReachabilityDetector) Name() string { return "reachability" }

// Present reports whether any ICMP or ARP packets were observed.
func (d *ReachabilityDetector) Present() bool { return d.icmpSeen || d.arpSeen }

// Feed ingests one normalized record into reachability tracking.
func (d *ReachabilityDetector) Feed(rec *model.Record) {
	if rec.ICMP != nil {
		d.icmpSeen = true
		d.feedICMP(rec, rec.ICMP)
	}
	if rec.ARP != nil {
		d.arpSeen = true
		d.feedARP(rec, rec.ARP)
	}
}

func echoRequestCode(v6 bool) int {
	if v6 {
		return 128
	}
	return 8
}

func echoReplyCode(v6 bool) int {
	if v6 {
		return 129
	}
	return 0
}

func (d *ReachabilityDetector) feedICMP(rec *model.Record, icmp *model.ICMPPacket) {
	if icmp.Type == nil {
		return
	}
	v6, itype := icmp.V6, *icmp.Type
	src, dst := "", ""
	if icmp.Src != nil {
		src = *icmp.Src
	}
	if icmp.Dst != nil {
		dst = *icmp.Dst
	}
	idVal, hasID := 0, icmp.ID != nil
	if hasID {
		idVal = *icmp.ID
	}
	seqVal, hasSeq := 0, icmp.Seq != nil
	if hasSeq {
		seqVal = *icmp.Seq
	}

	switch itype {
	case echoRequestCode(v6):
		key := requestKey{src: src, dst: dst, hasID: hasID, id: idVal, hasSeq: hasSeq, seq: seqVal, v6: v6}
		pid := pairID{src: src, dst: dst}
		pair, ok := d.pairs[pid]
		if !ok {
			pair = &echoPairTrack{
				src: src, dst: dst, v6: v6, tunneled: icmp.Tunneled, firstT: rec.T,
			}
			d.pairs[pid] = pair
			d.pairOrder = append(d.pairOrder, pid)
		}
		if _, dup := d.requests[key]; dup {
			pair.duplicates++
			return
		}
		if len(pair.keys) >= maxRequestsPerPair {
			return
		}
		d.requests[key] = &pingRequest{t: rec.T, n: rec.N}
		pair.keys = append(pair.keys, key)
		model.AddFrame(&pair.frames, rec.N)

	case echoReplyCode(v6):
		key := requestKey{src: dst, dst: src, hasID: hasID, id: idVal, hasSeq: hasSeq, seq: seqVal, v6: v6}
		req, ok := d.requests[key]
		if !ok {
			d.unmatchedReplies[pairID{src: src, dst: dst}]++
		} else if !req.hasRep {
			req.hasRep = true
			req.replyT = rec.T
			req.replyN = rec.N
		}

	default:
		code := 0
		if icmp.Code != nil {
			code = *icmp.Code
		}
		typeName, codeText := model.ICMPDescribe(v6, itype, code)
		var ek icmpErrKey
		ek.src, ek.dst, ek.v6, ek.icmpType, ek.code = src, dst, v6, itype, code
		var origSrc, origDst *string
		var origProto, origDport *int
		if icmp.Orig != nil {
			s := icmp.Orig.Src
			origSrc = &s
			dt := icmp.Orig.Dst
			origDst = &dt
			ek.hasOrigDst = true
			ek.origDst = dt
			origProto = icmp.Orig.Proto
			if origProto != nil {
				ek.hasOrigProto = true
				ek.origProto = *origProto
			}
			origDport = icmp.Orig.Dport
			if origDport != nil {
				ek.hasOrigDport = true
				ek.origDport = *origDport
			}
		}
		entry, ok := d.icmpErrors[ek]
		if !ok {
			entry = &icmpErrTrack{
				from: src, to: dst, v6: v6, icmpType: itype, code: code,
				typeName: typeName, codeText: codeText,
				originalSrc: origSrc, originalDst: origDst,
				originalProto: origProto, originalDport: origDport,
				firstT: rec.T,
			}
			d.icmpErrors[ek] = entry
			d.icmpErrOrder = append(d.icmpErrOrder, ek)
		}
		entry.count++
		model.AddFrame(&entry.frames, rec.N)
	}
}

func (d *ReachabilityDetector) feedARP(rec *model.Record, arp *model.ARPPacket) {
	if arp.Op == nil {
		return
	}
	spa, tpa := "", ""
	if arp.SPA != nil {
		spa = *arp.SPA
	}
	if arp.TPA != nil {
		tpa = *arp.TPA
	}
	switch *arp.Op {
	case 1:
		if spa == tpa {
			d.gratuitous++
			return
		}
		req, ok := d.arpRequests[tpa]
		if !ok {
			req = &arpReqTrack{target: tpa, askers: make(map[string]bool), firstT: rec.T}
			d.arpRequests[tpa] = req
		}
		req.askers[spa] = true
		req.count++
		model.AddFrame(&req.frames, rec.N)
	case 2:
		if spa == tpa {
			d.gratuitous++
		}
		rep, ok := d.arpReplies[spa]
		if !ok {
			rep = &arpRepTrack{ip: spa, macs: make(map[string]int), firstT: rec.T}
			d.arpReplies[spa] = rep
			d.arpReplyOrder = append(d.arpReplyOrder, spa)
		}
		sha := ""
		if arp.SHA != nil {
			sha = *arp.SHA
		}
		if _, exists := rep.macs[sha]; !exists {
			rep.macOrder = append(rep.macOrder, sha)
		}
		rep.macs[sha]++
		model.AddFrame(&rep.frames, rec.N)
	}
}

func protoNameForICMPError(p *int) string {
	if p == nil {
		return "None"
	}
	switch *p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return strconv.Itoa(*p)
	}
}

func sortedIPKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortStableFunc(out, model.CompareIP)
	return out
}

func formatARPDupSummary(ip string, macOrder []string) string {
	return fmt.Sprintf("%s is claimed by several MAC addresses: %s", ip, strings.Join(macOrder, ", "))
}
