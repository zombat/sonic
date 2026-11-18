// Package extract implements pure-Go ICMPv4 and ICMPv6 packet decoding
// for OpenFastPathRecords.
package extract

import (
	"encoding/binary"
	"net/netip"

	"github.com/zombat/sonic/internal/model"
)

func parseFastICMPv4(outer *model.IPHeader, pkt []byte, tunneled bool) (*model.ICMPPacket, *model.DPICMP) {
	if outer == nil || len(pkt) < 8 {
		return nil, nil
	}
	tp := int(pkt[0])
	cd := int(pkt[1])
	src, dst := outer.Src, outer.Dst
	out := &model.ICMPPacket{V6: false, Type: &tp, Code: &cd, Src: &src, Dst: &dst, Tunneled: tunneled}
	if !icmpErrorTypes[tp] {
		id := int(binary.BigEndian.Uint16(pkt[4:6]))
		seq := int(binary.BigEndian.Uint16(pkt[6:8]))
		out.ID = &id
		out.Seq = &seq
		return out, nil
	}
	var dpICMP *model.DPICMP
	if len(pkt) >= 28 && (pkt[8]>>4) == 4 {
		emb := pkt[8:]
		embProto := int(emb[9])
		embID := int(binary.BigEndian.Uint16(emb[4:6]))
		embLen := int(binary.BigEndian.Uint16(emb[2:4]))
		embDF := int((binary.BigEndian.Uint16(emb[6:8]) >> 14) & 1)
		orig := &model.ICMPOrig{
			Src:   netip.AddrFrom4([4]byte(emb[12:16])).String(),
			Dst:   netip.AddrFrom4([4]byte(emb[16:20])).String(),
			Proto: &embProto,
		}
		embIHL := int(emb[0]&0x0f) * 4
		if embIHL >= 20 && embIHL+4 <= len(emb) && (embProto == 6 || embProto == 17) {
			dp := int(binary.BigEndian.Uint16(emb[embIHL+2 : embIHL+4]))
			orig.Dport = &dp
		}
		out.Orig = orig
		var mtu *int
		if tp == 3 && cd == 4 {
			m := int(binary.BigEndian.Uint16(pkt[6:8]))
			mtu = &m
		}
		dpICMP = &model.DPICMP{MTU: mtu, OrigID: &embID, OrigLen: &embLen, OrigDF: &embDF}
	}
	return out, dpICMP
}

func parseFastICMPv6(outer *model.IPHeader, pkt []byte) (*model.ICMPPacket, *model.DPICMP) {
	if outer == nil || len(pkt) < 8 {
		return nil, nil
	}
	tp := int(pkt[0])
	cd := int(pkt[1])
	src, dst := outer.Src, outer.Dst
	out := &model.ICMPPacket{V6: true, Type: &tp, Code: &cd, Src: &src, Dst: &dst}
	if !icmpv6ErrorTypes[tp] {
		id := int(binary.BigEndian.Uint16(pkt[4:6]))
		seq := int(binary.BigEndian.Uint16(pkt[6:8]))
		out.ID = &id
		out.Seq = &seq
		return out, nil
	}
	var dpICMP *model.DPICMP
	if len(pkt) >= 48 && (pkt[8]>>4) == 6 {
		emb := pkt[8:]
		embNxt := int(emb[6])
		embLen := 40 + int(binary.BigEndian.Uint16(emb[4:6]))
		orig := &model.ICMPOrig{
			Src:   netip.AddrFrom16([16]byte(emb[8:24])).String(),
			Dst:   netip.AddrFrom16([16]byte(emb[24:40])).String(),
			Proto: &embNxt,
		}
		if (embNxt == 6 || embNxt == 17) && len(emb) >= 44 {
			dp := int(binary.BigEndian.Uint16(emb[42:44]))
			orig.Dport = &dp
		}
		out.Orig = orig
		var mtu *int
		if tp == 2 {
			m := int(binary.BigEndian.Uint32(pkt[4:8]))
			mtu = &m
		}
		dpICMP = &model.DPICMP{MTU: mtu, OrigLen: &embLen}
	}
	return out, dpICMP
}
