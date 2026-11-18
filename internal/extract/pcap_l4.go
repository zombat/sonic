// Package extract implements pure-Go GRE, TCP, UDP, and ESP
// layer decoding for OpenFastPathRecords.
package extract

import (
	"encoding/binary"
	"net/netip"

	"github.com/zombat/sonic/internal/model"
)

func decodeFastL4(rec *model.Record, dp *model.DataPlane, proto int, payload []byte, isFrag, v6 bool) {
	switch proto {
	case 47: // GRE
		if v6 {
			return
		}
		decodeFastGRE(rec, dp, payload)
	case 50: // ESP
		if esp := parseFastESP(payload, false); esp != nil {
			rec.ESP = esp
		}
	case 6: // TCP
		tcpHdr, dpTCP, app := parseFastTCP(payload)
		if tcpHdr != nil {
			rec.TCP = tcpHdr
			dp.TCP = dpTCP
			if !isFrag && len(app) > 0 {
				setPayload(dp, app)
			}
		}
	case 17: // UDP
		udpHdr, app := parseFastUDP(payload)
		if udpHdr != nil {
			rec.UDP = udpHdr
			if !isFrag && len(app) > 0 {
				setPayload(dp, app)
			}
			applyFastNATTEncap(udpHdr, app, &rec.ESP, &rec.NATKeepalive)
		}
	case 1: // ICMPv4
		if !v6 {
			rec.ICMP, dp.ICMP = parseFastICMPv4(rec.IP, payload, false)
		}
	case 58: // ICMPv6
		if v6 {
			rec.ICMP, dp.ICMP = parseFastICMPv6(rec.IP, payload)
		}
	}
}

func decodeFastGRE(rec *model.Record, dp *model.DataPlane, payload []byte) {
	if len(payload) < 4 {
		return
	}
	flags := binary.BigEndian.Uint16(payload[0:2])
	ptype := int(binary.BigEndian.Uint16(payload[2:4]))
	off := 4
	if (flags & 0x8000) != 0 { // C bit
		off += 4
	}
	var keyPtr *uint32
	if (flags & 0x2000) != 0 { // K bit
		if off+4 > len(payload) {
			return
		}
		k := binary.BigEndian.Uint32(payload[off : off+4])
		keyPtr = &k
		off += 4
	}
	if (flags & 0x1000) != 0 { // S bit
		off += 4
	}
	rec.GRE = &model.GREHeader{Key: keyPtr, Ptype: &ptype}
	if ptype != 0x0800 || off+20 > len(payload) {
		return
	}
	ip := payload[off:]
	if (ip[0] >> 4) != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ip) {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		totalLen = len(ip)
	}
	id := int(binary.BigEndian.Uint16(ip[4:6]))
	df := int((binary.BigEndian.Uint16(ip[6:8]) >> 14) & 1)
	dscp := int(ip[1] >> 2)
	ecn := int(ip[1] & 0x03)
	inProto := int(ip[9])
	inner := &model.InnerPacket{
		Src:   netip.AddrFrom4([4]byte(ip[12:16])).String(),
		Dst:   netip.AddrFrom4([4]byte(ip[16:20])).String(),
		Proto: &inProto,
	}
	rec.Inner = inner
	dp.Inner = &model.DPInner{TL: totalLen, ID: &id, DF: df, DSCP: dscp, ECN: ecn}

	inBody := ip[ihl:totalLen]
	switch inProto {
	case 6:
		tcpHdr, dpTCP, app := parseFastTCP(inBody)
		inner.TCP = tcpHdr
		dp.TCP = dpTCP
		setPayload(dp, app)
	case 17:
		udpHdr, app := parseFastUDP(inBody)
		inner.UDP = udpHdr
		setPayload(dp, app)
		applyFastNATTEncap(udpHdr, app, &inner.ESP, &inner.NATKeepalive)
	case 50:
		inner.ESP = parseFastESP(inBody, false)
	case 1:
		fakeOuter := &model.IPHeader{V: 4, Src: inner.Src, Dst: inner.Dst, Proto: &inProto}
		rec.ICMP, dp.ICMP = parseFastICMPv4(fakeOuter, inBody, true)
	}
}

func parseFastTCP(pkt []byte) (*model.TCPHeader, *model.DPTCP, []byte) {
	if len(pkt) < 20 {
		return nil, nil, nil
	}
	sport := int(binary.BigEndian.Uint16(pkt[0:2]))
	dport := int(binary.BigEndian.Uint16(pkt[2:4]))
	seq := binary.BigEndian.Uint32(pkt[4:8])
	ack := binary.BigEndian.Uint32(pkt[8:12])
	hl := int(pkt[12]>>4) * 4
	if hl < 20 || hl > len(pkt) {
		hl = 20
	}
	flags := int(pkt[13])
	win := int(binary.BigEndian.Uint16(pkt[14:16]))

	var mssPtr, wsPtr *int
	var hasSACK, hasTS bool
	opts := pkt[20:hl]
	for pos := 0; pos < len(opts); {
		kind := opts[pos]
		if kind == 0 {
			break
		}
		if kind == 1 {
			pos++
			continue
		}
		if pos+1 >= len(opts) {
			break
		}
		olen := int(opts[pos+1])
		if olen < 2 || pos+olen > len(opts) {
			break
		}
		switch kind {
		case 2:
			if olen == 4 {
				v := int(binary.BigEndian.Uint16(opts[pos+2 : pos+4]))
				mssPtr = &v
			}
		case 3:
			if olen == 3 {
				v := int(opts[pos+2])
				wsPtr = &v
			}
		case 4:
			hasSACK = true
		case 8:
			hasTS = true
		}
		pos += olen
	}

	var synMSS *int
	if (flags & 0x02) != 0 {
		synMSS = mssPtr
	}
	app := pkt[hl:]
	hdr := &model.TCPHeader{
		Sport: &sport,
		Dport: &dport,
		Flags: flags,
		Len:   len(app),
		MSS:   synMSS,
	}
	dpTCP := &model.DPTCP{
		Seq:  seq,
		Ack:  ack,
		Win:  win,
		HL:   hl,
		MSS:  mssPtr,
		WS:   wsPtr,
		SACK: hasSACK,
		TS:   hasTS,
	}
	return hdr, dpTCP, app
}

func parseFastUDP(pkt []byte) (*model.UDPHeader, []byte) {
	if len(pkt) < 8 {
		return nil, nil
	}
	sport := int(binary.BigEndian.Uint16(pkt[0:2]))
	dport := int(binary.BigEndian.Uint16(pkt[2:4]))
	ulen := int(binary.BigEndian.Uint16(pkt[4:6]))
	bodyLen := max(ulen-8, 0)
	if ulen < 8 {
		bodyLen = len(pkt) - 8
	}
	end := min(len(pkt), 8+bodyLen)
	app := pkt[8:end]
	return &model.UDPHeader{Sport: &sport, Dport: &dport, Len: bodyLen}, app
}

func parseFastESP(pkt []byte, udpWrapped bool) *model.ESPHeader {
	if len(pkt) < 8 {
		return nil
	}
	spi := binary.BigEndian.Uint32(pkt[0:4])
	seq := binary.BigEndian.Uint32(pkt[4:8])
	return &model.ESPHeader{SPI: spi, Seq: seq, UDP: udpWrapped}
}

func applyFastNATTEncap(u *model.UDPHeader, app []byte, esp **model.ESPHeader, natKA **bool) {
	if u == nil || u.Sport == nil || u.Dport == nil || (*u.Sport != 4500 && *u.Dport != 4500) {
		return
	}
	if len(app) == 1 && app[0] == 0xff {
		t := true
		*natKA = &t
		return
	}
	if len(app) >= 8 && binary.BigEndian.Uint32(app[0:4]) != 0 {
		*esp = parseFastESP(app, true)
	}
}
