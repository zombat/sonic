// Package ipsec IKE/pair packet feeding, NAT-D hash verification, and Detector state.
package ipsec

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Detector tracks IKE negotiations, ESP sequences, NAT-T state, and peer encryption purity.
type Detector struct {
	peers           map[string]bool
	sas             map[string]*ikeSA
	esp             map[espFlowKey]*espFlow
	espCurrent      map[dirKey]*espFlow
	pairs           map[[2]string]*pairTrack
	keepalives      int
	keepaliveFrames []int
	ikePackets      int
	ikeOn4500       int
	natDetection    bool
	seenIPsec       bool
}

// NewDetector returns an initialized IPsecDetector constrained optionally to specific peer IPs.
func NewDetector(peers []string) *Detector {
	pMap := make(map[string]bool, len(peers))
	for _, p := range peers {
		pMap[p] = true
	}
	return &Detector{
		peers:           pMap,
		sas:             make(map[string]*ikeSA),
		esp:             make(map[espFlowKey]*espFlow),
		espCurrent:      make(map[dirKey]*espFlow),
		pairs:           make(map[[2]string]*pairTrack),
		keepaliveFrames: []int{},
	}
}

// Name returns "ipsec".
func (d *Detector) Name() string { return "ipsec" }

// Present reports whether IKE, ESP, NAT keepalives, or candidate tunnel peer traffic were seen.
func (d *Detector) Present() bool {
	return d.seenIPsec || len(d.candidatePairs()) > 0
}

// Feed ingests a single normalized record into peer-pair, IKE, ESP, and keepalive state.
func (d *Detector) Feed(rec *model.Record) {
	if rec.IP == nil {
		return
	}
	src, dst := rec.IP.Src, rec.IP.Dst
	label := model.ProtocolLabel(rec)
	pk := model.PairKey(src, dst)
	pair, ok := d.pairs[pk]
	if !ok {
		pair = &pairTrack{
			protected: make(map[string]int),
			cleartext: make(map[cleartextKey]*cleartextTrack),
			firstT:    rec.T,
		}
		d.pairs[pk] = pair
	}
	if model.ProtectedLabels[label] {
		pair.protected[label]++
	} else {
		ck := cleartextKey{label: label, src: src, dst: dst}
		ct, exists := pair.cleartext[ck]
		if !exists {
			ct = &cleartextTrack{frames: []int{}, firstT: rec.T}
			pair.cleartext[ck] = ct
			pair.clearOrder = append(pair.clearOrder, ck)
		}
		ct.packets++
		ct.bytes += rec.Len
		model.AddFrame(&ct.frames, rec.N)
	}

	if rec.IKE != nil {
		d.seenIPsec = true
		d.feedIKE(rec, src, dst)
	}
	if rec.ESP != nil {
		d.seenIPsec = true
		d.feedESPRecord(rec, src, dst)
	}
	if rec.NATKeepalive != nil && *rec.NATKeepalive {
		d.seenIPsec = true
		d.keepalives++
		model.AddFrame(&d.keepaliveFrames, rec.N)
	}
}

// natdHash computes the RFC 7296 2.23 SHA-1(SPIi | SPIr | IP | port) hex digest.
func natdHash(ispi, rspi, address string, port int) (string, bool) {
	if ispi == "" || rspi == "" {
		return "", false
	}
	bi, err := hex.DecodeString(ispi)
	if err != nil {
		return "", false
	}
	br, err := hex.DecodeString(rspi)
	if err != nil {
		return "", false
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", false
	}
	var pbuf [2]byte
	binary.BigEndian.PutUint16(pbuf[:], uint16(port))
	h := sha1.New()
	_, _ = h.Write(bi)
	_, _ = h.Write(br)
	_, _ = h.Write(addr.AsSlice())
	_, _ = h.Write(pbuf[:])
	return hex.EncodeToString(h.Sum(nil)), true
}

// feedIKE tracks SA creation, exchange request/response retransmissions, notifies, and IKEv2 details.
func (d *Detector) feedIKE(rec *model.Record, src, dst string) {
	ike := rec.IKE
	d.ikePackets++
	if ike.NATT {
		d.ikeOn4500++
	}
	if slices.Contains(ike.Notify, 16388) || slices.Contains(ike.Notify, 16389) {
		d.natDetection = true
	}
	ispi := ""
	if ike.ISPI != nil {
		ispi = *ike.ISPI
	}
	sa, ok := d.sas[ispi]
	if !ok {
		sa = &ikeSA{
			ispi:           ispi,
			version:        ike.Version,
			ports:          make(map[int]bool),
			frames:         []int{},
			exchanges:      make(map[exchangeKey]*exchangeState),
			messagesBySide: make(map[string]int),
			ikev1Counts:    make(map[ikev1CountKey]int),
			keOffered:      []int{},
			authPorts:      make(map[int]bool),
			pendingLive:    make(map[livenessKey]*livenessEntry),
		}
		d.sas[ispi] = sa
	}
	if !sa.hasTime {
		sa.hasTime = true
		sa.firstT = rec.T
	}
	sa.lastT = rec.T
	model.AddFrame(&sa.frames, rec.N)
	if ike.RSPI != nil && strings.Trim(*ike.RSPI, "0") != "" && sa.rspi == nil {
		rCopy := *ike.RSPI
		sa.rspi = &rCopy
	}
	if rec.UDP != nil && rec.UDP.Dport != nil {
		sa.ports[*rec.UDP.Dport] = true
	}
	sa.natt = sa.natt || ike.NATT

	exchCode := 0
	if ike.Exch != nil {
		exchCode = *ike.Exch
	}
	var isResponse bool
	if ike.Version == 2 {
		isResponse = (ike.Flags & 0x20) != 0
		fromInit := (ike.Flags & 0x08) != 0
		if sa.initiator == nil {
			s, dt := src, dst
			if fromInit {
				sa.initiator, sa.responder = &s, &dt
			} else {
				sa.initiator, sa.responder = &dt, &s
			}
		}
	} else {
		if sa.initiator == nil {
			s, dt := src, dst
			sa.initiator, sa.responder = &s, &dt
		}
		isResponse = sa.initiator != nil && src != *sa.initiator
		side := "initiator"
		if isResponse {
			side = "responder"
		}
		sa.ikev1Counts[ikev1CountKey{exch: exchCode, side: side}]++
	}
	sideLabel := "initiator"
	if sa.responder != nil && src == *sa.responder {
		sideLabel = "responder"
	}
	sa.messagesBySide[sideLabel]++

	exKey := exchangeKey{exch: exchCode, msgID: ike.MsgID}
	ex, exists := sa.exchanges[exKey]
	if !exists {
		ex = &exchangeState{
			firstT:     rec.T,
			lastT:      rec.T,
			reqFrames:  []int{},
			respFrames: []int{},
			encrypted:  ike.Encrypted,
		}
		sa.exchanges[exKey] = ex
		sa.order = append(sa.order, exKey)
	}
	ex.lastT = rec.T
	if isResponse {
		ex.responses++
		ex.awaiting = false
		model.AddFrame(&ex.respFrames, rec.N)
		ex.respLengths = append(ex.respLengths, ike.Length)
		ex.respNotifies = append(ex.respNotifies, slices.Clone(ike.Notify))
	} else {
		if ex.awaiting {
			ex.retransmissions++
		}
		ex.requests++
		ex.awaiting = true
		model.AddFrame(&ex.reqFrames, rec.N)
		ex.reqNotifies = append(ex.reqNotifies, slices.Clone(ike.Notify))
	}
	for _, code := range ike.Notify {
		sa.notifies = append(sa.notifies, rawNotify{
			typ:      code,
			name:     model.IKENotifyName(ike.Version, code),
			from:     src,
			to:       dst,
			frame:    rec.N,
			t:        rec.T,
			exchange: ike.Exch,
			isError:  model.IKENotifyIsError(ike.Version, code),
		})
	}
	if ike.Version == 2 {
		d.feedIKEv2Detail(sa, rec, src, dst, isResponse)
	}
}
