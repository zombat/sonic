// Package extract implements pure-Go Ethernet, VLAN, IPv4, IPv6, GRE, ESP,
// TCP, UDP, ICMP, ICMPv6, and ARP frame decoding into normalized model.Record structs.
package extract

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/zombat/sonic/internal/model"
)

func decodeFastFrame(n int, epoch float64, origLen int, frame []byte, linkType uint32) model.Record {
	if origLen < len(frame) {
		origLen = len(frame)
	}
	rec := model.Record{N: n, T: epoch, Len: origLen}
	l3, et, isLLC, llcKind := stripFastLinkLayer(frame, linkType)
	if isLLC {
		rec.LLC = llcKind
		return rec
	}
	if et == 0x0806 {
		rec.ARP = decodeFastARP(l3)
		return rec
	}
	if len(l3) == 0 {
		if et != 0 {
			v := int(et)
			rec.EthType = &v
		}
		return rec
	}
	if et == 0 && len(l3) > 0 {
		switch l3[0] >> 4 {
		case 4:
			et = 0x0800
		case 6:
			et = 0x86dd
		}
	}
	switch et {
	case 0x0800:
		decodeFastIPv4(&rec, l3)
	case 0x86dd:
		decodeFastIPv6(&rec, l3)
	default:
		if et != 0 {
			v := int(et)
			rec.EthType = &v
		}
	}
	return rec
}

func stripFastLinkLayer(frame []byte, linkType uint32) (l3 []byte, ethType uint16, isLLC bool, llcKind string) {
	switch linkType {
	case 1: // DLT_EN10MB
		if len(frame) < 14 {
			return nil, 0, false, ""
		}
		et := binary.BigEndian.Uint16(frame[12:14])
		off := 14
		for (et == 0x8100 || et == 0x88a8) && off+4 <= len(frame) {
			et = binary.BigEndian.Uint16(frame[off+2 : off+4])
			off += 4
		}
		if et <= 1500 && off+3 <= len(frame) {
			if frame[off] == 0x42 && frame[off+1] == 0x42 {
				return nil, 0, true, "stp"
			}
			if frame[off] == 0xaa && frame[off+1] == 0xaa && off+8 <= len(frame) && binary.BigEndian.Uint16(frame[off+6:off+8]) == 0x2000 {
				return nil, 0, true, "cdp"
			}
			return nil, 0, true, "llc"
		}
		return frame[off:], et, false, ""
	case 0: // DLT_NULL / BSD loopback
		if len(frame) < 4 {
			return nil, 0, false, ""
		}
		fam := binary.LittleEndian.Uint32(frame[0:4])
		if fam == 2 {
			return frame[4:], 0x0800, false, ""
		}
		if fam == 24 || fam == 28 || fam == 30 {
			return frame[4:], 0x86dd, false, ""
		}
		return frame[4:], 0, false, ""
	case 101: // DLT_RAW
		return frame, 0, false, ""
	case 113: // DLT_LINUX_SLL
		if len(frame) < 16 {
			return nil, 0, false, ""
		}
		return frame[16:], binary.BigEndian.Uint16(frame[14:16]), false, ""
	case 276: // DLT_LINUX_SLL2
		if len(frame) < 20 {
			return nil, 0, false, ""
		}
		return frame[20:], binary.BigEndian.Uint16(frame[0:2]), false, ""
	default:
		return nil, 0, false, ""
	}
}

func decodeFastARP(pkt []byte) *model.ARPPacket {
	if len(pkt) < 28 {
		return nil
	}
	op := int(binary.BigEndian.Uint16(pkt[6:8]))
	hlen, plen := int(pkt[4]), int(pkt[5])
	if hlen != 6 || plen != 4 || len(pkt) < 8+2*hlen+2*plen {
		return &model.ARPPacket{Op: &op}
	}
	sha := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", pkt[8], pkt[9], pkt[10], pkt[11], pkt[12], pkt[13])
	spa := netip.AddrFrom4([4]byte(pkt[14:18])).String()
	tpa := netip.AddrFrom4([4]byte(pkt[24:28])).String()
	return &model.ARPPacket{Op: &op, SPA: &spa, TPA: &tpa, SHA: &sha}
}

func decodeFastIPv4(rec *model.Record, pkt []byte) {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	id := int(binary.BigEndian.Uint16(pkt[4:6]))
	flagsOff := binary.BigEndian.Uint16(pkt[6:8])
	df := int((flagsOff >> 14) & 1)
	mf := int((flagsOff >> 13) & 1)
	fragBytes := int(flagsOff&0x1fff) * 8
	ttl := int(pkt[8])
	proto := int(pkt[9])
	dscp := int(pkt[1] >> 2)
	ecn := int(pkt[1] & 0x03)

	rec.IP = &model.IPHeader{
		V:     4,
		Src:   netip.AddrFrom4([4]byte(pkt[12:16])).String(),
		Dst:   netip.AddrFrom4([4]byte(pkt[16:20])).String(),
		Proto: &proto,
		TTL:   &ttl,
	}
	dp := &model.DataPlane{
		HL: ihl, TL: totalLen, ID: &id, DF: &df, MF: &mf, Off: fragBytes, DSCP: dscp, ECN: ecn,
	}
	rec.DP = dp

	payload := pkt[ihl:totalLen]
	isFrag := mf != 0 || fragBytes > 0
	if isFrag && fragBytes > 0 {
		return
	}
	decodeFastL4(rec, dp, proto, payload, isFrag, false)
}

func decodeFastIPv6(rec *model.Record, pkt []byte) {
	if len(pkt) < 40 || (pkt[0]>>4) != 6 {
		return
	}
	tc := ((int(pkt[0]) & 0x0f) << 4) | (int(pkt[1]) >> 4)
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	nxt := int(pkt[6])
	hlim := int(pkt[7])
	src := netip.AddrFrom16([16]byte(pkt[8:24])).String()
	dst := netip.AddrFrom16([16]byte(pkt[24:40])).String()

	body := pkt[40:]
	if plen < len(body) {
		body = body[:plen]
	}
	off := 0
	isFrag := false
	for off < len(body) {
		switch nxt {
		case 0, 43, 60:
			if off+2 > len(body) {
				off = len(body)
				break
			}
			extLen := (int(body[off+1]) + 1) * 8
			nxt = int(body[off])
			if off+extLen > len(body) {
				off = len(body)
				break
			}
			off += extLen
		case 44:
			if off+8 > len(body) {
				off = len(body)
				break
			}
			nxt = int(body[off])
			fragOff := int(binary.BigEndian.Uint16(body[off+2:off+4]) >> 3)
			mf := int(body[off+3] & 1)
			isFrag = fragOff > 0 || mf != 0
			off += 8
		default:
			goto doneExt
		}
	}
doneExt:
	rec.IP = &model.IPHeader{V: 6, Src: src, Dst: dst, Proto: &nxt, TTL: &hlim}
	dp := &model.DataPlane{HL: 40, TL: 40 + plen, DSCP: tc >> 2, ECN: tc & 0x03}
	rec.DP = dp
	if isFrag {
		return
	}
	decodeFastL4(rec, dp, nxt, body[off:], false, true)
}
