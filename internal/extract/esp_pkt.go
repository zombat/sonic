// Package extract validates decrypted ESP trailers and rebuilds inner IP packets.
package extract

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// ESPTrailer verifies RFC 4303 sequential padding (1..padLen) and known next headers.
func ESPTrailer(data []byte) ([]byte, int, bool) {
	if len(data) < 2 {
		return nil, 0, false
	}
	padLen := int(data[len(data)-2])
	nextHeader := int(data[len(data)-1])
	if padLen > len(data)-2 {
		return nil, 0, false
	}
	padStart := len(data) - 2 - padLen
	for i := 0; i < padLen; i++ {
		if int(data[padStart+i]) != i+1 {
			return nil, 0, false
		}
	}
	if _, ok := TunnelNextHeaders[nextHeader]; !ok {
		if _, ok := TransportNextHeaders[nextHeader]; !ok && nextHeader != NoNextHeader {
			return nil, 0, false
		}
	}
	return data[:padStart], nextHeader, true
}

// innerIPPacket validates that a tunnel-mode payload's IP length matches len(payload).
func innerIPPacket(payload []byte, nextHeader int) []byte {
	if nextHeader == 4 && len(payload) >= 20 && (payload[0]>>4) == 4 {
		if int(binary.BigEndian.Uint16(payload[2:4])) == len(payload) {
			return payload
		}
	}
	if nextHeader == 41 && len(payload) >= 40 && (payload[0]>>4) == 6 {
		if 40+int(binary.BigEndian.Uint16(payload[4:6])) == len(payload) {
			return payload
		}
	}
	return nil
}

// transportIPPacket wraps an ESP transport-mode payload in a reconstructed outer IPv4 or IPv6 header.
func transportIPPacket(src, dst string, nextHeader int, payload []byte) []byte {
	sAddr, errS := netip.ParseAddr(src)
	dAddr, errD := netip.ParseAddr(dst)
	if errS != nil || errD != nil || nextHeader < 0 || nextHeader > 255 {
		return nil
	}
	if strings.Contains(src, ":") {
		if !sAddr.Is6() || !dAddr.Is6() || len(payload) > 65535 {
			return nil
		}
		pkt := make([]byte, 40+len(payload))
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
		pkt[6] = byte(nextHeader)
		pkt[7] = 64
		sBytes := sAddr.As16()
		dBytes := dAddr.As16()
		copy(pkt[8:24], sBytes[:])
		copy(pkt[24:40], dBytes[:])
		copy(pkt[40:], payload)
		return pkt
	}
	if !sAddr.Is4() || !dAddr.Is4() || 20+len(payload) > 65535 {
		return nil
	}
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	pkt[8] = 64
	pkt[9] = byte(nextHeader)
	sBytes := sAddr.As4()
	dBytes := dAddr.As4()
	copy(pkt[12:16], sBytes[:])
	copy(pkt[16:20], dBytes[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:20]))
	copy(pkt[20:], payload)
	return pkt
}

// ipv4Checksum computes the RFC 1071 ones-complement header checksum for a 20-byte IPv4 header.
func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
