// Package espoverhead implements EspOverheadDetector for estimating ESP
// cipher families, per-packet tunneling overhead, and outer ESP fragmentation.
package espoverhead

import (
	"slices"

	"github.com/zombat/sonic/internal/model"
)

const (
	espHeaderBytes  = 8
	espTrailerBytes = 2
	minInnerBytes   = 20
	maxESPFlows     = 5000
	maxSizesPerFlow = 256
)

// Limits documents the size-estimation boundaries emitted in every report.
var Limits = []string{
	"ESP is encrypted: the cipher, tunnel or transport mode, and the inner packets are estimates from packet sizes, never read from the packet. Families with equal IV, ICV and alignment (AES-GCM, AES-CCM, ChaCha20-Poly1305) cannot be told apart.",
	"Padding is assumed minimal (no TFC padding); an implementation that pads more makes the inner sizes smaller than the bounds shown.",
	"Tunnel versus transport mode cannot be read from sizes alone; both are computed. The IKE exchange that agreed the mode is encrypted (IKEv2 IKE_AUTH, IKEv1 Quick Mode).",
}

type cipherFamilySpec struct {
	name  string
	iv    int
	icv   int
	align int
}

var cipherFamilies = []cipherFamilySpec{
	{"AES-GCM / AES-CCM / ChaCha20-Poly1305 (16-byte ICV)", 8, 16, 4},
	{"AES-CBC + HMAC-SHA1-96", 16, 12, 16},
	{"AES-CBC + HMAC-SHA256-128", 16, 16, 16},
	{"AES-CBC + HMAC-SHA384-192", 16, 24, 16},
	{"AES-CBC + HMAC-SHA512-256", 16, 32, 16},
	{"3DES/DES-CBC + HMAC-SHA1-96", 8, 12, 8},
	{"3DES/DES-CBC + HMAC-MD5-96", 8, 12, 8},
	{"NULL encryption + HMAC-SHA1-96", 0, 12, 4},
}

// FamilyCandidate represents one cipher family profile consistent with observed ESP sizes.
type FamilyCandidate struct {
	Family string
	IV     int
	ICV    int
	Align  int
	Also   []string
}

// FamiliesFor returns all cipher families consistent with every ESP payload size.
func FamiliesFor(sizes []int) []FamilyCandidate {
	type shapeKey struct{ iv, icv, align int }
	var out []FamilyCandidate
	idxMap := make(map[shapeKey]int)

	for _, spec := range cipherFamilies {
		sk := shapeKey{iv: spec.iv, icv: spec.icv, align: spec.align}
		if idx, exists := idxMap[sk]; exists {
			out[idx].Also = append(out[idx].Also, spec.name)
			continue
		}
		ok := true
		for _, sz := range sizes {
			body := sz - spec.iv - spec.icv
			if body < espTrailerBytes+minInnerBytes || body%spec.align != 0 {
				ok = false
				break
			}
		}
		if ok {
			idxMap[sk] = len(out)
			out = append(out, FamilyCandidate{
				Family: spec.name, IV: spec.iv, ICV: spec.icv, Align: spec.align, Also: []string{},
			})
		}
	}
	return out
}

// BestFamily selects the strictest fitting cipher family (preferring encryption over NULL).
func BestFamily(families []FamilyCandidate) *FamilyCandidate {
	if len(families) == 0 {
		return nil
	}
	bestIdx := 0
	for i := 1; i < len(families); i++ {
		if familyGreater(families[i], families[bestIdx]) {
			bestIdx = i
		}
	}
	c := families[bestIdx]
	return &c
}

func familyGreater(a, b FamilyCandidate) bool {
	aEnc, bEnc := a.IV > 0, b.IV > 0
	if aEnc != bEnc {
		return aEnc
	}
	if a.Align != b.Align {
		return a.Align > b.Align
	}
	return a.ICV > b.ICV
}

type espFlowKey struct {
	src string
	dst string
	spi uint32
	udp bool
}

type espFlowTrack struct {
	src      string
	dst      string
	spi      uint32
	udp      bool
	v6       bool
	sizes    map[int]int
	packets  int
	outerMax int
	frames   []int
	firstT   float64
	dfSet    int
}

type fragTrack struct {
	src       string
	dst       string
	fragments int
	datagrams map[int]bool
	spis      map[uint32]bool
	largest   int
	firstT    float64
	frames    []int
}

type datagramID struct {
	src string
	dst string
	id  int
}

// Detector audits ESP packet size distributions, overhead margins, and outer fragmentation.
type Detector struct {
	transportMTU   int
	tunnelMTU      *int
	greHeaderBytes int
	flows          map[espFlowKey]*espFlowTrack
	flowOrder      []espFlowKey
	fragments      map[[2]string]*fragTrack
	fragOrder      [][2]string
	espDatagrams   map[datagramID]bool
	flowsDropped   int
}

// Options configures optional MTU assumptions for Detector.
type Options struct {
	TransportMTU   int
	TunnelMTU      *int
	GREHeaderBytes *int
}

// NewDetector returns an initialized ESP overhead Detector.
func NewDetector(opts Options) *Detector {
	tMTU := opts.TransportMTU
	if tMTU == 0 {
		tMTU = 1500
	}
	var tunMTU *int
	if opts.TunnelMTU != nil && *opts.TunnelMTU != 0 {
		v := *opts.TunnelMTU
		tunMTU = &v
	}
	greBytes := 8
	if opts.GREHeaderBytes != nil {
		greBytes = *opts.GREHeaderBytes
	}
	return &Detector{
		transportMTU:   tMTU,
		tunnelMTU:      tunMTU,
		greHeaderBytes: greBytes,
		flows:          make(map[espFlowKey]*espFlowTrack),
		fragments:      make(map[[2]string]*fragTrack),
		espDatagrams:   make(map[datagramID]bool),
	}
}

// Name returns "esp_overhead".
func (d *Detector) Name() string { return "esp_overhead" }

// Present reports whether any ESP flows or ESP fragments were observed.
func (d *Detector) Present() bool {
	return len(d.flows) > 0 || len(d.fragments) > 0
}

// Feed consumes one normalized packet record.
func (d *Detector) Feed(rec *model.Record) {
	if rec.DP == nil || rec.IP == nil {
		return
	}
	ip, dp := rec.IP, rec.DP
	frag := model.IsFragment(rec)
	if frag {
		if dp.ID != nil {
			dg := datagramID{src: ip.Src, dst: ip.Dst, id: *dp.ID}
			if rec.ESP != nil && ip.Proto != nil && *ip.Proto == 17 && len(d.espDatagrams) < 100000 {
				d.espDatagrams[dg] = true
			}
			isESPProto := ip.Proto != nil && *ip.Proto == 50
			if isESPProto || rec.ESP != nil || d.espDatagrams[dg] {
				d.feedFragment(rec)
			}
		} else if (ip.Proto != nil && *ip.Proto == 50) || rec.ESP != nil {
			d.feedFragment(rec)
		}
		return
	}
	if rec.ESP == nil {
		return
	}
	key := espFlowKey{src: ip.Src, dst: ip.Dst, spi: rec.ESP.SPI, udp: rec.ESP.UDP}
	flow, ok := d.flows[key]
	if !ok {
		if len(d.flows) >= maxESPFlows {
			d.flowsDropped++
			return
		}
		flow = &espFlowTrack{
			src: ip.Src, dst: ip.Dst, spi: rec.ESP.SPI, udp: rec.ESP.UDP,
			v6: ip.V == 6, sizes: make(map[int]int), frames: []int{}, firstT: rec.T,
		}
		d.flows[key] = flow
		d.flowOrder = append(d.flowOrder, key)
	}
	natt := 0
	if rec.ESP.UDP {
		natt = 8
	}
	payload := dp.TL - dp.HL - natt - espHeaderBytes
	flow.packets++
	if dp.TL > flow.outerMax {
		flow.outerMax = dp.TL
	}
	if dp.DF != nil && *dp.DF != 0 {
		flow.dfSet++
	}
	if _, seen := flow.sizes[payload]; seen || len(flow.sizes) < maxSizesPerFlow {
		flow.sizes[payload]++
	}
	model.AddFrame(&flow.frames, rec.N)
}

func (d *Detector) feedFragment(rec *model.Record) {
	ip, dp := rec.IP, rec.DP
	key := [2]string{ip.Src, ip.Dst}
	entry, ok := d.fragments[key]
	if !ok {
		entry = &fragTrack{
			src: ip.Src, dst: ip.Dst, datagrams: make(map[int]bool),
			spis: make(map[uint32]bool), firstT: rec.T, frames: []int{},
		}
		d.fragments[key] = entry
		d.fragOrder = append(d.fragOrder, key)
	}
	entry.fragments++
	if dp.ID != nil && len(entry.datagrams) < 100000 {
		entry.datagrams[*dp.ID] = true
	}
	if dp.TL > entry.largest {
		entry.largest = dp.TL
	}
	if rec.ESP != nil {
		entry.spis[rec.ESP.SPI] = true
	}
	model.AddFrame(&entry.frames, rec.N)
}

func sortedUniqueSizes(flows []*espFlowTrack) []int {
	seen := make(map[int]bool)
	var out []int
	for _, f := range flows {
		for sz := range f.sizes {
			if !seen[sz] {
				seen[sz] = true
				out = append(out, sz)
			}
		}
	}
	slices.Sort(out)
	return out
}
