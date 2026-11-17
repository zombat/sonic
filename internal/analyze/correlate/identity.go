// Package correlate computes NAT-invariant packet match identities and directional
// flow tuples from normalized packet records.
package correlate

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// DirTuple captures one directional L3/L4 flow tuple observed at a capture point.
type DirTuple struct {
	Proto    int
	Src      string
	Sport    int
	HasSport bool
	Dst      string
	Dport    int
	HasDport bool
}

// MatchKey represents fields NAT preserves so packets match across capture points.
type MatchKey struct {
	Kind  string
	U1    uint32
	U2    uint32
	I1    int
	HasI1 bool
	I2    int
	HasI2 bool
	I3    int
	HasI3 bool
	S1    string
	S2    string
}

// isMulticast reports whether addr is IP multicast or an IPv4 broadcast address.
func isMulticast(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return ip.IsMulticast() || addr == "255.255.255.255" || (ip.Is4() && strings.HasSuffix(addr, ".255"))
}

// PacketIdentity extracts a NAT-invariant MatchKey and capture-local DirTuple from rec.
func PacketIdentity(rec *model.Record) (MatchKey, DirTuple, bool) {
	view := model.Transport(rec)
	if view == nil {
		return MatchKey{}, DirTuple{}, false
	}
	dp := rec.DP
	proto := -1
	if view.Proto != nil {
		proto = *view.Proto
	}

	var tup DirTuple
	switch {
	case view.TCP != nil:
		tup = DirTuple{Proto: 6, Src: view.Src, Dst: view.Dst}
		if view.TCP.Sport != nil {
			tup.Sport, tup.HasSport = *view.TCP.Sport, true
		}
		if view.TCP.Dport != nil {
			tup.Dport, tup.HasDport = *view.TCP.Dport, true
		}
	case view.UDP != nil:
		tup = DirTuple{Proto: 17, Src: view.Src, Dst: view.Dst}
		if view.UDP.Sport != nil {
			tup.Sport, tup.HasSport = *view.UDP.Sport, true
		}
		if view.UDP.Dport != nil {
			tup.Dport, tup.HasDport = *view.UDP.Dport, true
		}
	case rec.ICMP != nil && rec.ICMP.ID != nil:
		id := *rec.ICMP.ID
		tup = DirTuple{Proto: proto, Src: view.Src, Sport: id, HasSport: true, Dst: view.Dst, Dport: id, HasDport: true}
	default:
		tup = DirTuple{Proto: proto, Src: view.Src, Dst: view.Dst}
	}

	if rec.ESP != nil {
		return MatchKey{Kind: "esp", U1: rec.ESP.SPI, U2: rec.ESP.Seq}, tup, true
	}
	if rec.IKE != nil {
		var ispi, rspi string
		var hasISPI, hasRSPI bool
		if rec.IKE.ISPI != nil {
			ispi, hasISPI = *rec.IKE.ISPI, true
		}
		if rec.IKE.RSPI != nil {
			rspi, hasRSPI = *rec.IKE.RSPI, true
		}
		return MatchKey{
			Kind:  "ike",
			S1:    ispi,
			HasI1: hasISPI,
			S2:    rspi,
			HasI2: hasRSPI,
			U1:    rec.IKE.MsgID,
			U2:    rec.IKE.Length,
			I3:    rec.IKE.Flags,
		}, tup, true
	}
	if view.TCP != nil && view.DTCP != nil {
		return MatchKey{
			Kind: "tcp",
			U1:   view.DTCP.Seq,
			U2:   view.DTCP.Ack,
			I1:   view.TCP.Flags & 0x17,
			I2:   view.TCP.Len,
			S1:   dp.PH,
		}, tup, true
	}
	if view.UDP != nil {
		if dp.PH != "" {
			return MatchKey{Kind: "udp-ph", I1: view.UDP.Len, S1: dp.PH}, tup, true
		}
		id, hasID := 0, false
		if view.ID != nil {
			id, hasID = *view.ID, true
		}
		return MatchKey{Kind: "udp-id", I1: view.UDP.Len, I2: id, HasI2: hasID}, tup, true
	}
	if rec.ICMP != nil && rec.ICMP.Seq != nil {
		tp, hasType := 0, false
		if rec.ICMP.Type != nil {
			tp, hasType = *rec.ICMP.Type, true
		}
		id, hasID := 0, false
		if view.ID != nil {
			id, hasID = *view.ID, true
		}
		return MatchKey{
			Kind:  "icmp",
			I1:    tp,
			HasI1: hasType,
			I2:    *rec.ICMP.Seq,
			U1:    uint32(view.TL),
			I3:    id,
			HasI3: hasID,
		}, tup, true
	}
	if view.ID == nil {
		return MatchKey{}, DirTuple{}, false
	}
	return MatchKey{Kind: "ip", I1: proto, I2: *view.ID, I3: view.TL}, tup, true
}

// reverseTuple flips source and destination addresses and ports on tup.
func reverseTuple(tup DirTuple) DirTuple {
	return DirTuple{
		Proto:    tup.Proto,
		Src:      tup.Dst,
		Sport:    tup.Dport,
		HasSport: tup.HasDport,
		Dst:      tup.Src,
		Dport:    tup.Sport,
		HasDport: tup.HasSport,
	}
}

// protoLabel returns the canonical lowercase protocol prefix for a tuple.
func protoLabel(proto int) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 50:
		return "esp"
	case 47:
		return "gre"
	default:
		return fmt.Sprintf("ip-proto-%d", proto)
	}
}

// tupleText renders tup identically to analyzers/correlate.py:_tuple_text.
func tupleText(tup DirTuple) string {
	name := protoLabel(tup.Proto)
	if (tup.Proto == 1 || tup.Proto == 58) && tup.HasSport {
		return fmt.Sprintf("%s %s -> %s id %d", name, tup.Src, tup.Dst, tup.Sport)
	}
	var sport, dport *int
	if tup.HasSport {
		v := tup.Sport
		sport = &v
	}
	if tup.HasDport {
		v := tup.Dport
		dport = &v
	}
	return fmt.Sprintf("%s %s -> %s", name, model.Endpoint(tup.Src, sport), model.Endpoint(tup.Dst, dport))
}
