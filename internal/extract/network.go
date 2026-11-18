// Package extract builds normalized packet records from streaming tshark rows.
package extract

import (
	"context"
	"strings"

	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// RecordFromTShark converts one parsed tshark Row into a normalized model.Record.
func RecordFromTShark(row tshark.Row, versionMajor int) model.Record {
	tVal, _ := row.Float64("frame.time_epoch")
	rec := model.Record{
		N:   intOr(row.Int("frame.number"), 0),
		T:   tVal,
		Len: intOr(row.Int("frame.len"), 0),
	}
	protocols, _ := row.First("frame.protocols")
	ipSrcs := row.All("ip.src")
	if len(ipSrcs) > 0 {
		dst, _ := row.First("ip.dst")
		rec.IP = &model.IPHeader{
			V:     4,
			Src:   ipSrcs[0],
			Dst:   dst,
			Proto: row.Int("ip.proto"),
			TTL:   row.Int("ip.ttl"),
		}
	} else if row.Has("ipv6.src") {
		src, _ := row.First("ipv6.src")
		dst, _ := row.First("ipv6.dst")
		rec.IP = &model.IPHeader{
			V:     6,
			Src:   src,
			Dst:   dst,
			Proto: row.Int("ipv6.nxt"),
			TTL:   row.Int("ipv6.hlim"),
		}
	} else if row.Has("eth.type") {
		rec.EthType = row.Int("eth.type")
	} else if strings.Contains(protocols, ":llc") {
		switch {
		case strings.Contains(protocols, ":cdp"):
			rec.LLC = "cdp"
		case strings.Contains(protocols, ":stp"):
			rec.LLC = "stp"
		default:
			rec.LLC = "llc"
		}
	}

	tunneled := false
	if row.Has("gre.proto") {
		ptype := row.Int("gre.proto")
		rec.GRE = &model.GREHeader{Key: row.Uint32("gre.key"), Ptype: ptype}
		if ptype != nil && *ptype == 0x0800 && len(ipSrcs) > 1 {
			tunneled = true
			dst, _ := row.At("ip.dst", 1)
			rec.Inner = &model.InnerPacket{
				Src:   ipSrcs[1],
				Dst:   dst,
				Proto: row.Int("ip.proto", 1),
			}
		}
	}

	var l4Proto *int
	if tunneled {
		l4Proto = rec.Inner.Proto
	} else if rec.IP != nil {
		l4Proto = rec.IP.Proto
	}

	var targetTCP *model.TCPHeader
	var targetUDP *model.UDPHeader
	if row.Has("tcp.srcport") && l4Proto != nil && *l4Proto == 6 {
		flags := intOr(row.Int("tcp.flags"), 0)
		targetTCP = &model.TCPHeader{
			Sport: row.Int("tcp.srcport"),
			Dport: row.Int("tcp.dstport"),
			Flags: flags,
			Len:   intOr(row.Int("tcp.len"), 0),
		}
		if (flags&0x02) != 0 && row.Has("dp.tcp.mss") {
			targetTCP.MSS = row.Int("dp.tcp.mss")
		}
	}
	if row.Has("udp.srcport") && l4Proto != nil && *l4Proto == 17 {
		length := intOr(row.Int("udp.length"), 8)
		targetUDP = &model.UDPHeader{
			Sport: row.Int("udp.srcport"),
			Dport: row.Int("udp.dstport"),
			Len:   max(length-8, 0),
		}
	}

	ike := extractIKE(row, targetUDP)
	var esp *model.ESPHeader
	if row.Has("esp.spi") {
		esp = &model.ESPHeader{
			SPI: uint32Or(row.Uint32("esp.spi"), 0),
			Seq: uint32Or(row.Uint32("esp.sequence"), 0),
			UDP: targetUDP != nil,
		}
	}
	var natKeepalive *bool
	if row.Has("udpencap.nat_keepalive") {
		v := true
		natKeepalive = &v
	}

	bgpMsgs, nlri, withdrawn := extractBGP(row)
	ospf := extractOSPF(row)
	eigrp := extractEIGRP(row)

	if tunneled {
		rec.Inner.TCP = targetTCP
		rec.Inner.UDP = targetUDP
		rec.Inner.IKE = ike
		rec.Inner.ESP = esp
		rec.Inner.NATKeepalive = natKeepalive
		rec.Inner.BGP = bgpMsgs
		rec.Inner.BGPNLRI = nlri
		rec.Inner.BGPWithdrawn = withdrawn
		rec.Inner.OSPF = ospf
		rec.Inner.EIGRP = eigrp
	} else {
		rec.TCP = targetTCP
		rec.UDP = targetUDP
		rec.IKE = ike
		rec.ESP = esp
		rec.NATKeepalive = natKeepalive
		rec.BGP = bgpMsgs
		rec.BGPNLRI = nlri
		rec.BGPWithdrawn = withdrawn
		rec.OSPF = ospf
		rec.EIGRP = eigrp
	}

	rec.NHRP = extractNHRP(row, ipSrcs)

	carriesOther := rec.GRE != nil && rec.Inner == nil
	if !carriesOther && rec.IP != nil {
		if row.Has("icmp.type") {
			rec.ICMP = extractICMP(&rec, row, ipSrcs, false)
		} else if row.Has("icmpv6.type") {
			rec.ICMP = extractICMP(&rec, row, row.All("ipv6.src"), true)
		}
	}

	if row.Has("arp.opcode") {
		rec.ARP = &model.ARPPacket{
			Op:  row.Int("arp.opcode"),
			SPA: row.FirstPtr("arp.spa"),
			TPA: row.FirstPtr("arp.tpa"),
			SHA: row.FirstPtr("arp.sha"),
		}
	}
	if strings.Contains(protocols, ":sip") {
		v := true
		rec.SIP = &v
	}

	FillDataPlaneFromTShark(&rec, row, versionMajor)
	return rec
}

// OpenNetworkRecords extracts, normalizes, and service-annotates all records from a capture via tshark.
func OpenNetworkRecords(ctx context.Context, opts tshark.StreamOptions) (model.RecordsOutput, error) {
	out := model.RecordsOutput{
		Backend:       "tshark",
		MissingFields: []string{},
		Warnings:      []string{},
		Records:       []model.Record{},
	}
	binary := opts.Binary
	if binary == "" {
		binary = tshark.DefaultBinary
	}
	verMajor := tshark.VersionMajor(ctx, binary)

	res, err := tshark.StreamFields(ctx, opts, func(row tshark.Row) error {
		out.Records = append(out.Records, RecordFromTShark(row, verMajor))
		return nil
	})
	if res.MissingFields != nil {
		out.MissingFields = res.MissingFields
	}
	if err != nil {
		return out, err
	}
	AnnotateServicePorts(out.Records)
	out.Records = FilterRecordWindow(out.Records, opts.Since, opts.Until)
	return out, nil
}
