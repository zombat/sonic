// Package extract decodes data-plane IP, TCP, ICMP, and payload head fields
// from tshark output rows.
package extract

import (
	"encoding/hex"
	"slices"

	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// PayloadHead caps the prefix of each TCP/UDP payload retained in rec.DP.PL.
const PayloadHead = 2048

// FillDataPlaneFromTShark populates rec.DP from a tshark Row, matching extractors/dataplane.py.
func FillDataPlaneFromTShark(rec *model.Record, row tshark.Row, versionMajor int) {
	if rec == nil || rec.IP == nil {
		return
	}
	var dp model.DataPlane
	if rec.IP.V == 6 {
		plen := intOr(row.Int("dp.ip6.plen"), 0)
		dp = model.DataPlane{
			HL:   40,
			TL:   40 + plen,
			DSCP: intOr(row.Int("dp.ip6.dscp"), 0),
			ECN:  intOr(row.Int("dp.ip6.ecn"), 0),
		}
	} else {
		df := intOr(row.Int("dp.ip.df"), 0)
		mf := intOr(row.Int("dp.ip.mf"), 0)
		dp = model.DataPlane{
			HL:   intOr(row.Int("dp.ip.hl"), 20),
			TL:   intOr(row.Int("dp.ip.len"), 0),
			ID:   row.Int("dp.ip.id"),
			DF:   &df,
			MF:   &mf,
			Off:  tshark.FragOffsetBytes(intOr(row.Int("ip.frag_offset"), 0), versionMajor),
			DSCP: intOr(row.Int("dp.ip.dscp"), 0),
			ECN:  intOr(row.Int("dp.ip.ecn"), 0),
		}
	}
	rec.DP = &dp

	fragment := (dp.MF != nil && *dp.MF != 0) || dp.Off > 0
	tunneled := rec.Inner != nil
	if tunneled {
		dp.Inner = &model.DPInner{
			TL:   intOr(row.Int("dp.ip.len", 1), 0),
			ID:   row.Int("dp.ip.id", 1),
			DF:   intOr(row.Int("dp.ip.df", 1), 0),
			DSCP: intOr(row.Int("dp.ip.dscp", 1), 0),
			ECN:  intOr(row.Int("dp.ip.ecn", 1), 0),
		}
	}

	hasTCP := rec.TCP != nil
	hasUDP := rec.UDP != nil
	if tunneled {
		hasTCP = rec.Inner.TCP != nil
		hasUDP = rec.Inner.UDP != nil
	}

	if hasTCP {
		kinds := row.Ints("dp.tcp.kinds")
		dp.TCP = &model.DPTCP{
			Seq:  uint32Or(row.Uint32("dp.tcp.seq"), 0),
			Ack:  uint32Or(row.Uint32("dp.tcp.ack"), 0),
			Win:  intOr(row.Int("dp.tcp.win"), 0),
			HL:   intOr(row.Int("dp.tcp.hl"), 20),
			MSS:  row.Int("dp.tcp.mss"),
			WS:   row.Int("dp.tcp.ws"),
			SACK: slices.Contains(kinds, 4),
			TS:   slices.Contains(kinds, 8),
		}
		if !fragment {
			setPayload(&dp, bytesFromHexField(row, "dp.tcp.payload"))
		}
	} else if hasUDP && !fragment {
		setPayload(&dp, bytesFromHexField(row, "dp.udp.payload"))
	}

	if rec.ICMP != nil && rec.ICMP.Orig != nil {
		layer := 1
		if rec.ICMP.Tunneled {
			layer = 2
		}
		if rec.ICMP.V6 {
			var mtu *int
			if rec.ICMP.Type != nil && *rec.ICMP.Type == 2 {
				mtu = row.Int("dp.icmpv6.mtu")
			}
			plen := row.Int("dp.ip6.plen", layer)
			var origLen *int
			if plen != nil {
				v := 40 + *plen
				origLen = &v
			}
			dp.ICMP = &model.DPICMP{
				MTU:     mtu,
				OrigLen: origLen,
			}
		} else {
			var mtu *int
			if rec.ICMP.Type != nil && rec.ICMP.Code != nil && *rec.ICMP.Type == 3 && *rec.ICMP.Code == 4 {
				mtu = row.Int("dp.icmp.mtu")
			}
			dp.ICMP = &model.DPICMP{
				MTU:     mtu,
				OrigID:  row.Int("dp.ip.id", layer),
				OrigLen: row.Int("dp.ip.len", layer),
				OrigDF:  row.Int("dp.ip.df", layer),
			}
		}
	}
}

// bytesFromHexField decodes the first colon-separated hex string at key, returning nil on empty/error.
func bytesFromHexField(row tshark.Row, key string) []byte {
	raw, ok := row.First(key)
	if !ok {
		return nil
	}
	hx, ok := tshark.HexBytes(raw)
	if !ok || hx == "" {
		return nil
	}
	b, err := hex.DecodeString(hx)
	if err != nil {
		return nil
	}
	return b
}

// setPayload stores the truncated hex head and full BLAKE2b digest on dp when payload is non-empty.
func setPayload(dp *model.DataPlane, payload []byte) {
	if len(payload) == 0 {
		return
	}
	dp.PL = hex.EncodeToString(payload[:min(len(payload), PayloadHead)])
	dp.PH = PayloadHash(payload)
}

// intOr returns *p if non-nil, or fallback otherwise.
func intOr(p *int, fallback int) int {
	if p != nil {
		return *p
	}
	return fallback
}

// uint32Or returns *p if non-nil, or fallback otherwise.
func uint32Or(p *uint32, fallback uint32) uint32 {
	if p != nil {
		return *p
	}
	return fallback
}
