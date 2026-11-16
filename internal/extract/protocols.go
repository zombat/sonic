// Package extract contains protocol-specific field extraction helpers for
// IKE, NHRP, BGP, OSPF, EIGRP, and ICMP/ICMPv6 tshark rows.
package extract

import (
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

var (
	icmpErrorTypes   = map[int]bool{3: true, 4: true, 5: true, 11: true, 12: true}
	icmpv6ErrorTypes = map[int]bool{1: true, 2: true, 3: true, 4: true}
	bgpMinorKeys     = []string{
		"bgp.minor", "bgp.minor_open", "bgp.minor_update", "bgp.minor_expired",
		"bgp.minor_state", "bgp.minor_cease", "bgp.minor_capability",
	}
)

// extractNHRP builds a normalized NHRPPacket from tshark nhrp.* fields.
func extractNHRP(row tshark.Row, ipSrcs []string) *model.NHRPPacket {
	if !row.Has("nhrp.op") {
		return nil
	}
	op := row.Int("nhrp.op")
	nhrp := &model.NHRPPacket{
		Op:       op,
		SrcNBMA:  row.FirstPtr("nhrp.src_nbma"),
		SrcProto: row.FirstPtr("nhrp.src_proto"),
		DstProto: row.FirstPtr("nhrp.dst_proto"),
		ReqID:    row.Uint32("nhrp.reqid"),
	}
	if op != nil {
		switch *op {
		case 2:
			nhrp.Code = row.Int("nhrp.code")
			nhrp.ClientNBMA = row.FirstPtr("nhrp.client_nbma")
			nhrp.ClientProto = row.FirstPtr("nhrp.client_proto")
			nhrp.Prefix = row.Int("nhrp.prefix")
		case 4, 6:
			nhrp.Code = row.Int("nhrp.code")
		case 7:
			nhrp.ErrCode = row.Int("nhrp.err_code")
		case 8:
			if len(ipSrcs) > 1 {
				origSrc := ipSrcs[1]
				nhrp.OrigSrc = &origSrc
				if dst, ok := row.At("ip.dst", 1); ok {
					nhrp.OrigDst = &dst
				}
			}
		}
	}
	return nhrp
}

// extractBGP builds BGP messages plus frame-level NLRI and withdrawn prefix counts.
func extractBGP(row tshark.Row) (msgs []model.BGPMessage, nlri *int, withdrawn *int) {
	if !row.Has("bgp.type") {
		return nil, nil, nil
	}
	types := row.Ints("bgp.type")
	lengths := row.Ints("bgp.length")
	myas := row.Ints("bgp.myas")
	holds := row.Ints("bgp.hold")
	ids := row.All("bgp.id")
	as4s := row.All("bgp.as4")
	majors := row.Ints("bgp.major")
	var minors []int
	for _, key := range bgpMinorKeys {
		minors = append(minors, row.Ints(key)...)
	}
	caps := nonNilInts(row.Ints("bgp.caps"))

	msgs = make([]model.BGPMessage, 0, len(types))
	openIdx := 0
	notifyIdx := 0
	for idx, mtype := range types {
		msg := model.BGPMessage{Type: mtype}
		if idx < len(lengths) {
			msg.Len = &lengths[idx]
		}
		if mtype == 1 {
			if openIdx < len(myas) {
				msg.MyAS = &myas[openIdx]
			}
			if openIdx < len(holds) {
				msg.Hold = &holds[openIdx]
			}
			if openIdx < len(ids) {
				id := ids[openIdx]
				msg.BGPID = &id
			}
			if openIdx < len(as4s) {
				if v, ok := tshark.ParseInt64(as4s[openIdx]); ok && v >= 0 {
					u := uint32(v)
					msg.AS4 = &u
				}
			}
			if openIdx == 0 {
				msg.Caps = caps
			} else {
				msg.Caps = []int{}
			}
			openIdx++
		} else if mtype == 3 {
			if notifyIdx < len(majors) {
				msg.Major = &majors[notifyIdx]
			}
			if notifyIdx < len(minors) {
				msg.Minor = &minors[notifyIdx]
			}
			notifyIdx++
		}
		msgs = append(msgs, msg)
	}
	nCount := len(row.All("bgp.nlri"))
	wCount := len(row.All("bgp.withdrawn"))
	return msgs, &nCount, &wCount
}

// extractOSPF builds a normalized OSPFPacket from tshark ospf.* fields.
func extractOSPF(row tshark.Row) *model.OSPFPacket {
	if !row.Has("ospf.msg") {
		return nil
	}
	neighbors := row.All("ospf.neighbors")
	if neighbors == nil {
		neighbors = []string{}
	}
	return &model.OSPFPacket{
		Type:      row.Int("ospf.msg"),
		RID:       row.FirstPtr("ospf.rid"),
		Area:      row.FirstPtr("ospf.area"),
		Auth:      row.Int("ospf.auth"),
		Mask:      row.FirstPtr("ospf.mask"),
		Hello:     row.Int("ospf.hello"),
		Dead:      row.Int("ospf.dead"),
		Prio:      row.Int("ospf.prio"),
		DR:        row.FirstPtr("ospf.dr"),
		BDR:       row.FirstPtr("ospf.bdr"),
		Neighbors: neighbors,
		Options:   row.Int("ospf.options"),
		MTU:       row.Int("ospf.mtu"),
		DBDFlags:  row.Int("ospf.dbd"),
		DDSeq:     row.Uint32("ospf.dd_seq"),
	}
}

// extractEIGRP builds a normalized EIGRPPacket from tshark eigrp.* fields.
func extractEIGRP(row tshark.Row) *model.EIGRPPacket {
	if !row.Has("eigrp.opcode") {
		return nil
	}
	kKeys := []string{"eigrp.k1", "eigrp.k2", "eigrp.k3", "eigrp.k4", "eigrp.k5", "eigrp.k6"}
	kVals := make([]int, 0, len(kKeys))
	allK := true
	for _, k := range kKeys {
		v := row.Int(k)
		if v == nil {
			allK = false
			break
		}
		kVals = append(kVals, *v)
	}
	var kSlice []int
	if allK {
		kSlice = kVals
	}
	return &model.EIGRPPacket{
		Opcode: row.Int("eigrp.opcode"),
		AS:     row.Int("eigrp.as"),
		Flags:  uint32Or(row.Uint32("eigrp.flags"), 0),
		Seq:    uint32Or(row.Uint32("eigrp.seq"), 0),
		Ack:    uint32Or(row.Uint32("eigrp.ack"), 0),
		TLVs:   nonNilInts(row.Ints("eigrp.tlv")),
		K:      kSlice,
		Hold:   row.Int("eigrp.hold"),
	}
}

// extractICMP builds an ICMPv4 or ICMPv6 summary, handling GRE tunneling and embedded error packets.
func extractICMP(rec *model.Record, row tshark.Row, srcs []string, v6 bool) *model.ICMPPacket {
	prefix := "icmp"
	dstKey := "ip.dst"
	protoKey := "ip.proto"
	errors := icmpErrorTypes
	if v6 {
		prefix = "icmpv6"
		dstKey = "ipv6.dst"
		protoKey = "ipv6.nxt"
		errors = icmpv6ErrorTypes
	}

	tunneled := rec.Inner != nil && !v6
	layer := 0
	if tunneled {
		layer = 1
	}
	if len(srcs) <= layer {
		return nil
	}

	icmpType := row.Int(prefix + ".type")
	src := srcs[layer]
	var dst *string
	if d, ok := row.At(dstKey, layer); ok {
		dst = &d
	}
	out := &model.ICMPPacket{
		V6:       v6,
		Type:     icmpType,
		Code:     row.Int(prefix + ".code"),
		Src:      &src,
		Dst:      dst,
		Tunneled: tunneled,
	}
	if icmpType != nil && errors[*icmpType] {
		if len(srcs) > layer+1 {
			proto := row.Int(protoKey, layer+1)
			var dport *int
			if proto != nil {
				switch *proto {
				case 17:
					dport = row.Int("udp.dstport")
				case 6:
					dport = row.Int("tcp.dstport")
				}
			}
			origDst, _ := row.At(dstKey, layer+1)
			out.Orig = &model.ICMPOrig{
				Src:   srcs[layer+1],
				Dst:   origDst,
				Proto: proto,
				Dport: dport,
			}
		}
	} else {
		out.ID = row.Int(prefix + ".ident")
		out.Seq = row.Int(prefix + ".seq")
	}
	return out
}

func hexFieldPtr(row tshark.Row, key string) *string {
	raw, ok := row.First(key)
	if !ok {
		return nil
	}
	hx, ok := tshark.HexBytes(raw)
	if !ok || hx == "" {
		return nil
	}
	return &hx
}

func nonNilInts(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}
