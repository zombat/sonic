// Package qos implements QosDetector for per-flow DSCP, GRE/ESP marking
// visibility, ECN congestion counts, and RTP stream quality scoring.
package qos

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/zombat/sonic/internal/model"
)

const maxQoSFlows = 5000

type flowKey struct {
	src    string
	dst    string
	label  string
	hasSPI bool
	spi    uint32
}

type flowTrack struct {
	src     string
	dst     string
	label   string
	dscp    map[int]int
	packets int
	frames  []int
}

type greKey struct {
	src string
	dst string
}

type grePair struct {
	inner int
	outer int
}

type greTrack struct {
	src        string
	dst        string
	pairOrder  []grePair
	pairs      map[grePair]int
	lostFrames []int
}

type espSAKey struct {
	src string
	dst string
	spi uint32
}

type espSATrack struct {
	src    string
	dst    string
	spi    uint32
	dscp   map[int]int
	frames []int
}

// QosDetector inspects DSCP markings, GRE/ESP copying, ECN CE, and RTP streams.
type QosDetector struct {
	flows        map[flowKey]*flowTrack
	flowOrder    []flowKey
	flowsDropped int
	gre          map[greKey]*greTrack
	greOrder     []greKey
	esp          map[espSAKey]*espSATrack
	espOrder     []espSAKey
	rtp          map[rtpKey]*rtpStream
	rtpOrder     []rtpKey
	notRTP       map[rtpKey]bool
	ce           int
	ceFrames     []int
	marked       bool
}

// NewQosDetector returns an initialized QosDetector.
func NewQosDetector() *QosDetector {
	return &QosDetector{
		flows:    make(map[flowKey]*flowTrack),
		gre:      make(map[greKey]*greTrack),
		esp:      make(map[espSAKey]*espSATrack),
		rtp:      make(map[rtpKey]*rtpStream),
		notRTP:   make(map[rtpKey]bool),
		ceFrames: []int{},
	}
}

// Name returns "qos".
func (d *QosDetector) Name() string { return "qos" }

// Present reports whether any QoS markings, GRE/ESP tunnels, ECN CE, or RTP streams were seen.
func (d *QosDetector) Present() bool {
	if d.marked || len(d.esp) > 0 || len(d.gre) > 0 || d.ce > 0 {
		return true
	}
	for _, k := range d.rtpOrder {
		if d.rtp[k].looksLikeRTP() {
			return true
		}
	}
	return false
}

// Feed consumes one normalized record.
func (d *QosDetector) Feed(rec *model.Record) {
	if rec.IP == nil || rec.DP == nil {
		return
	}
	dp := rec.DP
	dscp := dp.DSCP
	if dscp != 0 {
		d.marked = true
	}
	if dp.ECN == 3 {
		d.ce++
		model.AddFrame(&d.ceFrames, rec.N)
	}
	label := model.ProtocolLabel(rec)
	fk := flowKey{src: rec.IP.Src, dst: rec.IP.Dst, label: label}
	if rec.ESP != nil {
		fk.hasSPI = true
		fk.spi = rec.ESP.SPI
	}
	flow, ok := d.flows[fk]
	if !ok {
		if len(d.flows) >= maxQoSFlows {
			d.flowsDropped++
		} else {
			flow = &flowTrack{
				src: rec.IP.Src, dst: rec.IP.Dst, label: label,
				dscp: make(map[int]int), frames: []int{},
			}
			d.flows[fk] = flow
			d.flowOrder = append(d.flowOrder, fk)
		}
	}
	if flow != nil {
		flow.packets++
		flow.dscp[dscp]++
		if dscp != 0 {
			model.AddFrame(&flow.frames, rec.N)
		}
	}
	if rec.ESP != nil {
		ek := espSAKey{src: rec.IP.Src, dst: rec.IP.Dst, spi: rec.ESP.SPI}
		sa, exists := d.esp[ek]
		if !exists {
			sa = &espSATrack{
				src: rec.IP.Src, dst: rec.IP.Dst, spi: rec.ESP.SPI,
				dscp: make(map[int]int), frames: []int{},
			}
			d.esp[ek] = sa
			d.espOrder = append(d.espOrder, ek)
		}
		sa.dscp[dscp]++
		if dscp != 0 {
			model.AddFrame(&sa.frames, rec.N)
		}
	}
	if dp.Inner != nil {
		gk := greKey{src: rec.IP.Src, dst: rec.IP.Dst}
		tun, exists := d.gre[gk]
		if !exists {
			tun = &greTrack{
				src: rec.IP.Src, dst: rec.IP.Dst,
				pairs: make(map[grePair]int), lostFrames: []int{},
			}
			d.gre[gk] = tun
			d.greOrder = append(d.greOrder, gk)
		}
		gp := grePair{inner: dp.Inner.DSCP, outer: dscp}
		if _, seen := tun.pairs[gp]; !seen {
			tun.pairOrder = append(tun.pairOrder, gp)
		}
		tun.pairs[gp]++
		if dp.Inner.DSCP != 0 {
			d.marked = true
		}
		if dp.Inner.DSCP != dscp {
			model.AddFrame(&tun.lostFrames, rec.N)
		}
	}
	if view := model.Transport(rec); view != nil && view.UDP != nil && dp.PL != "" {
		d.feedRTP(rec, view, dp.PL)
	}
}

func (d *QosDetector) feedRTP(rec *model.Record, view *model.TransportView, plHex string) {
	if view.UDP.Sport == nil || view.UDP.Dport == nil {
		return
	}
	sport, dport := *view.UDP.Sport, *view.UDP.Dport
	if sport < 1024 || dport < 1024 {
		return
	}
	if _, ok := model.ServiceNames[sport]; ok {
		return
	}
	if _, ok := model.ServiceNames[dport]; ok {
		return
	}
	payload, err := hex.DecodeString(plHex)
	if err != nil || len(payload) < 12 || (payload[0]>>6) != 2 {
		return
	}
	pt := int(payload[1] & 0x7F)
	if pt >= 72 && pt <= 76 {
		return
	}
	seq := binary.BigEndian.Uint16(payload[2:4])
	ts := binary.BigEndian.Uint32(payload[4:8])
	ssrc := binary.BigEndian.Uint32(payload[8:12])
	rk := rtpKey{src: view.Src, sport: sport, dst: view.Dst, dport: dport, ssrc: ssrc}
	stream, ok := d.rtp[rk]
	if !ok {
		if d.notRTP[rk] || len(d.rtp) >= maxRTPStreams {
			return
		}
		stream = newRTPStream(rk, pt, rec.T, view.Tunneled)
		d.rtp[rk] = stream
		d.rtpOrder = append(d.rtpOrder, rk)
	}
	stream.add(rec.T, rec.N, seq, ts, view.DSCP, view.TL)
}
