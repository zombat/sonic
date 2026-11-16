// Package pathmtu implements PathMtuDetector packet ingestion for DF probes,
// ICMP Fragmentation Needed / Packet Too Big, TCP DF segments, and IP fragments.
package pathmtu

import "github.com/zombat/sonic/internal/model"

const (
	minProbeBytes         = 576
	maxProbes             = 50000
	maxTCPFlows           = 20000
	maxTCPSegmentsPerFlow = 256
	maxFragmentGroups     = 20000
	pendingWindowS        = 2.0
)

// PathMtuDetector tracks DF probes, PTB messages, TCP black holes, and IP fragments.
type PathMtuDetector struct {
	probes             map[probeKey]*probeEntry
	probeOrder         []probeKey
	echoIndex          map[echoKey]probeKey
	ptb                map[ptbKey]*ptbTrack
	ptbOrder           []ptbKey
	ptbTargets         map[[2]string]bool
	tcpFlows           map[tcpFlowKey]*tcpFlowTrack
	tcpFlowOrder       []tcpFlowKey
	fragGroups         map[fragGroupKey]*fragGroup
	fragGroupOrder     []fragGroupKey
	fragGroupsDropped  int
	reassemblyTimeouts []reassemblyTimeout
	dfLarge            int
	largestDF          int
}

// NewPathMtuDetector returns an initialized PathMtuDetector.
func NewPathMtuDetector() *PathMtuDetector {
	return &PathMtuDetector{
		probes:     make(map[probeKey]*probeEntry),
		echoIndex:  make(map[echoKey]probeKey),
		ptb:        make(map[ptbKey]*ptbTrack),
		ptbTargets: make(map[[2]string]bool),
		tcpFlows:   make(map[tcpFlowKey]*tcpFlowTrack),
		fragGroups: make(map[fragGroupKey]*fragGroup),
	}
}

// Name returns "path_mtu".
func (d *PathMtuDetector) Name() string { return "path_mtu" }

// Present reports whether any large DF packets, PTB messages, fragments, or timeouts were seen.
func (d *PathMtuDetector) Present() bool {
	return d.dfLarge > 0 || len(d.ptb) > 0 || len(d.fragGroups) > 0 || len(d.reassemblyTimeouts) > 0
}

// Feed consumes one normalized record.
func (d *PathMtuDetector) Feed(rec *model.Record) {
	if rec.DP == nil || rec.IP == nil {
		return
	}
	if model.IsFragment(rec) {
		d.feedFragment(rec)
	}
	if rec.ICMP != nil {
		d.feedICMP(rec, rec.ICMP)
	}
	view := model.Transport(rec)
	if view == nil {
		return
	}
	df := view.V6 || (view.DF != nil && *view.DF != 0)
	size := view.TL
	if df && size > minProbeBytes {
		d.dfLarge++
		if size > d.largestDF {
			d.largestDF = size
		}
		d.rememberProbe(rec, view)
	}
	if view.TCP != nil && view.DTCP != nil {
		d.feedTCP(rec, view, df, size)
	}
}

func (d *PathMtuDetector) rememberProbe(rec *model.Record, view *model.TransportView) {
	pk := probeKey{src: view.Src, dst: view.Dst}
	if view.V6 {
		pk.byLen, pk.hasVal, pk.val = true, true, view.TL
	} else if view.ID != nil {
		pk.hasVal, pk.val = true, *view.ID
	}
	if _, exists := d.probes[pk]; exists {
		return
	}
	if len(d.probes) >= maxProbes && len(d.probeOrder) > 0 {
		delete(d.probes, d.probeOrder[0])
		d.probeOrder = d.probeOrder[1:]
	}
	hasEcho := false
	var ek echoKey
	if icmp := rec.ICMP; icmp != nil && icmp.Type != nil {
		wantType := 8
		if icmp.V6 {
			wantType = 128
		}
		if *icmp.Type == wantType {
			hasEcho = true
			ek = echoKey{src: strOrEmpty(icmp.Src), dst: strOrEmpty(icmp.Dst)}
			if icmp.ID != nil {
				ek.hasID, ek.id = true, *icmp.ID
			}
			if icmp.Seq != nil {
				ek.hasSeq, ek.seq = true, *icmp.Seq
			}
		}
	}
	d.probes[pk] = &probeEntry{
		t: rec.T, n: rec.N, src: view.Src, dst: view.Dst, length: view.TL, hasEcho: hasEcho,
	}
	d.probeOrder = append(d.probeOrder, pk)
	if hasEcho {
		d.echoIndex[ek] = pk
	}
}

func (d *PathMtuDetector) feedICMP(rec *model.Record, icmp *model.ICMPPacket) {
	if icmp.Type == nil {
		return
	}
	v6, itype := icmp.V6, *icmp.Type
	code := 0
	if icmp.Code != nil {
		code = *icmp.Code
	}
	replyCode := 0
	if v6 {
		replyCode = 129
	}
	if itype == replyCode {
		ek := echoKey{src: strOrEmpty(icmp.Dst), dst: strOrEmpty(icmp.Src)}
		if icmp.ID != nil {
			ek.hasID, ek.id = true, *icmp.ID
		}
		if icmp.Seq != nil {
			ek.hasSeq, ek.seq = true, *icmp.Seq
		}
		if pk, ok := d.echoIndex[ek]; ok {
			if pr, exists := d.probes[pk]; exists {
				pr.answered = true
			}
		}
		return
	}

	if (!v6 && itype == 11 && code == 1) || (v6 && itype == 3 && code == 1) {
		d.reassemblyTimeouts = append(d.reassemblyTimeouts, reassemblyTimeout{
			from: strOrEmpty(icmp.Src), to: strOrEmpty(icmp.Dst), t: rec.T, n: rec.N,
		})
		return
	}
	if !((!v6 && itype == 3 && code == 4) || (v6 && itype == 2)) {
		return
	}

	var detail *model.DPICMP
	if rec.DP != nil {
		detail = rec.DP.ICMP
	}
	var mtu, origLen, origID *int
	if detail != nil {
		mtu, origLen, origID = detail.MTU, detail.OrigLen, detail.OrigID
	}
	var origSrc, origDst *string
	var origProto, origDport *int
	if icmp.Orig != nil {
		s, dt := icmp.Orig.Src, icmp.Orig.Dst
		origSrc, origDst = &s, &dt
		origProto, origDport = icmp.Orig.Proto, icmp.Orig.Dport
	}

	key := ptbKey{router: strOrEmpty(icmp.Src), to: strOrEmpty(icmp.Dst)}
	if icmp.Orig != nil {
		key.hasOrig, key.origSrc, key.origDst = true, icmp.Orig.Src, icmp.Orig.Dst
	}
	if mtu != nil {
		key.hasMTU, key.mtu = true, *mtu
	}
	entry, ok := d.ptb[key]
	if !ok {
		entry = &ptbTrack{
			router: key.router, to: key.to, originalSrc: origSrc, originalDst: origDst,
			origProto: origProto, origDport: origDport, mtu: mtu, originalLen: origLen,
			firstT: rec.T, frames: []int{}, probeFrames: []int{}, tunneled: icmp.Tunneled,
		}
		d.ptb[key] = entry
		d.ptbOrder = append(d.ptbOrder, key)
	}
	entry.count++
	model.AddFrame(&entry.frames, rec.N)
	d.ptbTargets[[2]string{strOrEmpty(origSrc), strOrEmpty(origDst)}] = true

	pk := probeKey{src: strOrEmpty(origSrc), dst: strOrEmpty(origDst)}
	if v6 {
		pk.byLen = true
		if origLen != nil {
			pk.hasVal, pk.val = true, *origLen
		}
	} else if origID != nil {
		pk.hasVal, pk.val = true, *origID
	}
	if probe, exists := d.probes[pk]; exists {
		probe.ptb = true
		model.AddFrame(&entry.probeFrames, probe.n)
	}
}

func (d *PathMtuDetector) feedTCP(rec *model.Record, view *model.TransportView, df bool, size int) {
	if view.TCP.Sport == nil || view.TCP.Dport == nil {
		return
	}
	sport, dport := *view.TCP.Sport, *view.TCP.Dport
	fwd := tcpFlowKey{src: view.Src, sport: sport, dst: view.Dst, dport: dport}
	rev := tcpFlowKey{src: view.Dst, sport: dport, dst: view.Src, dport: sport}
	if (view.TCP.Flags & 0x10) != 0 {
		if flow, ok := d.tcpFlows[rev]; ok {
			ack := view.DTCP.Ack
			for seq, seg := range flow.segments {
				if model.SeqDelta(ack, seq+uint32(seg.plen)) >= 0 {
					if seg.length > flow.maxAckedSize {
						flow.maxAckedSize = seg.length
					}
					delete(flow.segments, seq)
				}
			}
		}
	}
	plen := view.TCP.Len
	if plen <= 0 || !df {
		return
	}
	flow, ok := d.tcpFlows[fwd]
	if !ok {
		if len(d.tcpFlows) >= maxTCPFlows && len(d.tcpFlowOrder) > 0 {
			delete(d.tcpFlows, d.tcpFlowOrder[0])
			d.tcpFlowOrder = d.tcpFlowOrder[1:]
		}
		flow = &tcpFlowTrack{
			segments: make(map[uint32]*tcpSegTrack), src: view.Src, dst: view.Dst,
			sport: sport, dport: dport,
		}
		d.tcpFlows[fwd] = flow
		d.tcpFlowOrder = append(d.tcpFlowOrder, fwd)
	}
	seg, exists := flow.segments[view.DTCP.Seq]
	if !exists {
		if len(flow.segments) >= maxTCPSegmentsPerFlow {
			return
		}
		flow.segments[view.DTCP.Seq] = &tcpSegTrack{
			length: size, plen: plen, sent: 1, t: rec.T, n: rec.N, frames: []int{rec.N},
		}
		return
	}
	seg.sent++
	model.AddFrame(&seg.frames, rec.N)
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
