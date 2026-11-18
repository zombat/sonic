// Package extract provides byte-level IKEv1/IKEv2 header and SA proposal parsing.
package extract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"slices"

	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// ParseIKEv2SA decodes an IKEv2 SA payload body (RFC 7296 section 3.3) into proposals.
func ParseIKEv2SA(body []byte) []model.IKEProposal {
	proposals := []model.IKEProposal{}
	pos := 0
	for pos+8 <= len(body) && len(proposals) < 32 {
		last := body[pos]
		plen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		num := int(body[pos+4])
		proto := int(body[pos+5])
		spiSize := int(body[pos+6])
		count := int(body[pos+7])
		if plen < 8 || pos+plen > len(body) {
			break
		}
		if 8+spiSize > plen {
			break
		}
		var spi *string
		if spiSize > 0 {
			s := hex.EncodeToString(body[pos+8 : pos+8+spiSize])
			spi = &s
		}

		transforms := []model.IKETransform{}
		tpos := pos + 8 + spiSize
		end := pos + plen
		maxTransforms := max(count, 1) * 2
		for tpos+8 <= end && len(transforms) < maxTransforms && len(transforms) < 64 {
			tlen := int(binary.BigEndian.Uint16(body[tpos+2 : tpos+4]))
			ttype := int(body[tpos+4])
			tid := int(binary.BigEndian.Uint16(body[tpos+6 : tpos+8]))
			if tlen < 8 {
				break
			}
			var keyLength *int
			apos := tpos + 8
			tend := min(tpos+tlen, len(body))
			for apos+4 <= tend {
				atype := binary.BigEndian.Uint16(body[apos : apos+2])
				avalue := binary.BigEndian.Uint16(body[apos+2 : apos+4])
				if atype&0x8000 != 0 {
					if atype&0x7FFF == 14 {
						kl := int(avalue)
						keyLength = &kl
					}
					apos += 4
				} else {
					apos += 4 + int(avalue)
				}
			}
			transforms = append(transforms, model.IKETransform{
				Type:      ttype,
				ID:        tid,
				KeyLength: keyLength,
			})
			tpos += tlen
		}

		proposals = append(proposals, model.IKEProposal{
			Num:        num,
			Protocol:   proto,
			SPI:        spi,
			Transforms: transforms,
		})
		pos += plen
		if last == 0 {
			break
		}
	}
	return proposals
}

// ParseIKE decodes an IKEv1 or IKEv2 header and its cleartext payload chain.
func ParseIKE(data []byte, natt bool) *model.IKEHeader {
	if len(data) < 28 {
		return nil
	}
	ispi := hex.EncodeToString(data[0:8])
	rspi := hex.EncodeToString(data[8:16])
	first := int(data[16])
	versionRaw := data[17]
	exchVal := int(data[18])
	flags := int(data[19])
	msgid := binary.BigEndian.Uint32(data[20:24])
	length := binary.BigEndian.Uint32(data[24:28])

	major := versionRaw >> 4
	if major != 1 && major != 2 {
		return nil
	}
	version := 1
	if major == 2 {
		version = 2
	}

	out := &model.IKEHeader{
		Version:     version,
		ISPI:        &ispi,
		RSPI:        &rspi,
		Exch:        &exchVal,
		Flags:       flags,
		MsgID:       msgid,
		Length:      length,
		Notify:      []int{},
		Encrypted:   false,
		NATT:        natt,
		Payloads:    []int{},
		Proposals:   []model.IKEProposal{},
		NATDSrc:     []string{},
		NATDDst:     []string{},
		InvalidSPIs: []string{},
	}

	encrypted := version == 1 && (flags&0x01) != 0
	nxt := first
	offset := 28
	end := len(data)
	if length > 0 && int(length) < end {
		end = int(length)
	}

	for steps := 0; nxt != 0 && !encrypted && offset+4 <= end && steps < 64; steps++ {
		if version == 2 && (nxt == 46 || nxt == 53) {
			break
		}
		nextPayload := int(data[offset])
		plen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if plen < 4 {
			break
		}
		out.Payloads = append(out.Payloads, nxt)
		bodyEnd := min(offset+plen, len(data))
		var body []byte
		if offset+4 <= bodyEnd {
			body = data[offset+4 : bodyEnd]
		}

		if version == 2 && nxt == 41 && len(body) >= 4 {
			spiSize := int(body[1])
			ntype := int(binary.BigEndian.Uint16(body[2:4]))
			out.Notify = append(out.Notify, ntype)
			var ndata []byte
			if 4+spiSize <= len(body) {
				ndata = body[4+spiSize:]
			}
			switch ntype {
			case 16388:
				out.NATDSrc = append(out.NATDSrc, hex.EncodeToString(ndata))
			case 16389:
				out.NATDDst = append(out.NATDDst, hex.EncodeToString(ndata))
			case 17:
				if len(ndata) >= 2 {
					g := int(binary.BigEndian.Uint16(ndata[0:2]))
					out.InvalidKEGroup = &g
				}
			case 11:
				spiBytes := ndata[:min(4, len(ndata))]
				if len(spiBytes) == 0 && spiSize > 0 {
					endSPI := min(4+spiSize, len(body))
					if 4 <= endSPI {
						spiBytes = body[4:endSPI]
					}
				}
				out.InvalidSPIs = append(out.InvalidSPIs, hex.EncodeToString(spiBytes))
			}
		} else if version == 2 && nxt == 33 {
			out.Proposals = ParseIKEv2SA(body)
		} else if version == 2 && nxt == 34 && len(body) >= 2 {
			g := int(binary.BigEndian.Uint16(body[0:2]))
			out.KEGroup = &g
		} else if version == 1 && nxt == 11 && len(body) >= 8 {
			out.Notify = append(out.Notify, int(binary.BigEndian.Uint16(body[6:8])))
		}
		nxt = nextPayload
		offset += plen
	}

	if version == 2 && (nxt == 46 || nxt == 53) {
		encrypted = true
		out.Payloads = append(out.Payloads, nxt)
	}
	out.Encrypted = encrypted
	return out
}

// extractIKE decodes an IKE header from UDP payload bytes when available,
// falling back to tshark isakmp.* fields otherwise.
func extractIKE(row tshark.Row, targetUDP *model.UDPHeader) *model.IKEHeader {
	if !row.Has("isakmp.exchtype") {
		return nil
	}
	if row.Has("dp.udp.payload") && targetUDP != nil {
		if raw := bytesFromHexField(row, "dp.udp.payload"); len(raw) > 0 {
			sport := intOr(targetUDP.Sport, -1)
			dport := intOr(targetUDP.Dport, -1)
			if (sport == 4500 || dport == 4500) && len(raw) >= 4 && bytes.Equal(raw[:4], []byte{0, 0, 0, 0}) {
				if ike := ParseIKE(raw[4:], true); ike != nil {
					return ike
				}
			} else if sport == 500 || dport == 500 || sport == 4500 || dport == 4500 {
				if ike := ParseIKE(raw, false); ike != nil {
					return ike
				}
			}
		}
	}

	versionRaw := intOr(row.Int("isakmp.version"), 0)
	version := 1
	if (versionRaw >> 4) == 2 {
		version = 2
	}
	flags := intOr(row.Int("isakmp.flags"), 0)
	types := row.Ints("isakmp.typepayload")
	encrypted := (flags & 0x01) != 0
	if version == 2 {
		encrypted = slices.Contains(types, 46)
	}
	return &model.IKEHeader{
		Version:     version,
		ISPI:        hexFieldPtr(row, "isakmp.ispi"),
		RSPI:        hexFieldPtr(row, "isakmp.rspi"),
		Exch:        row.Int("isakmp.exchtype"),
		Flags:       flags,
		MsgID:       uint32Or(row.Uint32("isakmp.messageid"), 0),
		Length:      uint32Or(row.Uint32("isakmp.length"), 0),
		Notify:      nonNilInts(row.Ints("isakmp.notify.msgtype")),
		Encrypted:   encrypted,
		NATT:        row.Has("udpencap.non_esp_marker"),
		Payloads:    []int{},
		Proposals:   []model.IKEProposal{},
		NATDSrc:     []string{},
		NATDDst:     []string{},
		InvalidSPIs: []string{},
	}
}
