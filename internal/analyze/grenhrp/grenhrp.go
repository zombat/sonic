// Package grenhrp packet feeding and state accumulation for GRE/NHRP overlay detection.
package grenhrp

import (
	"fmt"

	"github.com/zombat/sonic/internal/model"
)

// Detector tracks GRE tunnels and NHRP registration, resolution, redirect, and error control traffic.
type Detector struct {
	tunnels       map[tunnelDirKey]*tunnelTrack
	registrations map[regKey]*regTrack
	resolutions   map[resKey]*resTrack
	redirects     map[redirKey]*redirTrack
	errors        []errorTrack
	purges        map[string]int
	nhrpCounts    map[string]int
}

// NewDetector returns an initialized GRE/NHRP detector.
func NewDetector() *Detector {
	return &Detector{
		tunnels:       make(map[tunnelDirKey]*tunnelTrack),
		registrations: make(map[regKey]*regTrack),
		resolutions:   make(map[resKey]*resTrack),
		redirects:     make(map[redirKey]*redirTrack),
		purges:        make(map[string]int),
		nhrpCounts:    make(map[string]int),
	}
}

// Name returns "gre_nhrp".
func (d *Detector) Name() string { return "gre_nhrp" }

// Present reports whether any GRE packets were seen in the capture.
func (d *Detector) Present() bool { return len(d.tunnels) > 0 }

// Feed ingests one normalized record into GRE and NHRP trackers.
func (d *Detector) Feed(rec *model.Record) {
	if rec.GRE == nil || rec.IP == nil {
		return
	}
	src, dst := rec.IP.Src, rec.IP.Dst
	dk := tunnelDirKey{src: src, dst: dst}
	tun, ok := d.tunnels[dk]
	if !ok {
		tun = &tunnelTrack{
			src:    src,
			dst:    dst,
			keys:   make(map[tunnelKeyVal]int),
			inner:  make(map[string]int),
			frames: []int{},
			firstT: rec.T,
			lastT:  rec.T,
		}
		d.tunnels[dk] = tun
	}
	tun.packets++
	tun.bytes += rec.Len
	var kv tunnelKeyVal
	if rec.GRE.Key != nil {
		kv = tunnelKeyVal{hasKey: true, key: *rec.GRE.Key}
	}
	tun.keys[kv]++
	tun.inner[grePtypeLabel(rec.GRE.Ptype)]++
	tun.lastT = rec.T
	model.AddFrame(&tun.frames, rec.N)

	if rec.NHRP != nil {
		d.feedNHRP(rec, src, dst, rec.NHRP)
	}
}

// feedNHRP processes one NHRP control packet carried inside GRE.
func (d *Detector) feedNHRP(rec *model.Record, src, dst string, nhrp *model.NHRPPacket) {
	if nhrp.Op == nil {
		return
	}
	op := *nhrp.Op
	opName, ok := model.NHRPOps[op]
	if !ok {
		opName = fmt.Sprintf("type_%d", op)
	}
	d.nhrpCounts[opName]++
	t, n := rec.T, rec.N

	switch op {
	case 3, 4:
		spokeNBMA := src
		if op == 4 {
			spokeNBMA = dst
		}
		if nhrp.SrcNBMA != nil && *nhrp.SrcNBMA != "" {
			spokeNBMA = *nhrp.SrcNBMA
		}
		hubNBMA := dst
		if op == 4 {
			hubNBMA = src
		}
		rk := regKey{spoke: spokeNBMA, hub: hubNBMA}
		reg, exists := d.registrations[rk]
		if !exists {
			reg = &regTrack{
				spokeNBMA:     spokeNBMA,
				spokeTunnelIP: nhrp.SrcProto,
				hubNBMA:       hubNBMA,
				hubTunnelIP:   nhrp.DstProto,
				codes:         make(map[int]int),
				reqFrames:     []int{},
				repFrames:     []int{},
				firstT:        t,
				lastT:         t,
			}
			d.registrations[rk] = reg
		}
		reg.lastT = t
		if op == 3 {
			reg.requests++
			model.AddFrame(&reg.reqFrames, n)
		} else {
			reg.replies++
			code := 0
			if nhrp.Code != nil {
				code = *nhrp.Code
			}
			if nhrp.Code != nil {
				reg.codes[code]++
				reg.hasLastCode = true
				reg.lastCode = code
			}
			model.AddFrame(&reg.repFrames, n)
			if nhrp.Code != nil && code == 0 {
				reg.hasSuccess = true
				reg.lastSuccessT = t
			}
		}

	case 1, 2:
		k := makeResKey(nhrp.SrcProto, nhrp.DstProto, nhrp.ReqID)
		res, exists := d.resolutions[k]
		if !exists {
			res = &resTrack{
				requesterTunnelIP: nhrp.SrcProto,
				requesterNBMA:     nhrp.SrcNBMA,
				target:            nhrp.DstProto,
				reqID:             nhrp.ReqID,
				answers:           []ResolutionAnswer{},
				reqFrames:         []int{},
				repFrames:         []int{},
				firstT:            t,
			}
			d.resolutions[k] = res
		}
		if op == 1 {
			res.requests++
			model.AddFrame(&res.reqFrames, n)
		} else {
			res.replies++
			model.AddFrame(&res.repFrames, n)
			ans := ResolutionAnswer{
				Code:           nhrp.Code,
				CodeName:       cieCodeName(nhrp.Code),
				ClientNBMA:     nhrp.ClientNBMA,
				ClientTunnelIP: nhrp.ClientProto,
				PrefixLength:   nhrp.Prefix,
				AnsweredBy:     src,
				Frame:          n,
			}
			if !answerPresent(res.answers, ans) {
				res.answers = append(res.answers, ans)
			}
		}

	case 8:
		rk := redirKey{from: src, to: dst}
		if nhrp.OrigDst != nil {
			rk.hasOrigDst = true
			rk.origDst = *nhrp.OrigDst
		}
		red, exists := d.redirects[rk]
		if !exists {
			red = &redirTrack{
				from:                src,
				to:                  dst,
				redirectingTunnelIP: nhrp.SrcProto,
				origSrc:             nhrp.OrigSrc,
				origDst:             nhrp.OrigDst,
				frames:              []int{},
				firstT:              t,
			}
			d.redirects[rk] = red
		}
		red.count++
		model.AddFrame(&red.frames, n)

	case 7:
		d.errors = append(d.errors, errorTrack{
			from:    src,
			to:      dst,
			errCode: nhrp.ErrCode,
			errText: errCodeName(nhrp.ErrCode),
			reqID:   nhrp.ReqID,
			frame:   n,
			t:       t,
		})

	case 5:
		d.purges["requests"]++

	case 6:
		d.purges["replies"]++
	}
}

// grePtypeLabel resolves a GRE Ethertype code to its symbolic label or 0xNNNN.
func grePtypeLabel(ptype *int) string {
	if ptype == nil {
		return "None"
	}
	if name, ok := GREProtocolTypes[*ptype]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", *ptype)
}

// makeResKey constructs a comparable resKey from optional NHRP address and ID fields.
func makeResKey(srcProto, dstProto *string, reqID *uint32) resKey {
	var k resKey
	if srcProto != nil {
		k.hasSrc, k.srcProto = true, *srcProto
	}
	if dstProto != nil {
		k.hasDst, k.dstProto = true, *dstProto
	}
	if reqID != nil {
		k.hasReqID, k.reqID = true, *reqID
	}
	return k
}

// answerPresent checks value equality against previously recorded ResolutionAnswer rows.
func answerPresent(list []ResolutionAnswer, item ResolutionAnswer) bool {
	for _, x := range list {
		if ptrIntEq(x.Code, item.Code) &&
			x.CodeName == item.CodeName &&
			ptrStrEq(x.ClientNBMA, item.ClientNBMA) &&
			ptrStrEq(x.ClientTunnelIP, item.ClientTunnelIP) &&
			ptrIntEq(x.PrefixLength, item.PrefixLength) &&
			x.AnsweredBy == item.AnsweredBy &&
			x.Frame == item.Frame {
			return true
		}
	}
	return false
}
