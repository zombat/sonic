// Package espdecrypt writes decrypted inner IP packets into a temporary libpcap capture.
package espdecrypt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"slices"

	"github.com/zombat/sonic/internal/extract"
)

const (
	pcapMagicLE    = 0xa1b2c3d4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	pcapSnapLen    = 65535
	pcapLinkEth    = 1
	ethHeaderLen   = 14
	etherTypeIPv4  = 0x0800
	etherTypeIPv6  = 0x86dd
)

// writeInnerPCAP reconstructs decrypted inner IP packets into a standard Ethernet libpcap file.
func writeInnerPCAP(inner []extract.DecryptedInnerPacket, path string) (int, error) {
	sorted := slices.Clone(inner)
	slices.SortStableFunc(sorted, func(a, b extract.DecryptedInnerPacket) int {
		if a.Time < b.Time {
			return -1
		}
		if a.Time > b.Time {
			return 1
		}
		return 0
	})

	var buf bytes.Buffer
	var gh [24]byte
	binary.LittleEndian.PutUint32(gh[0:4], pcapMagicLE)
	binary.LittleEndian.PutUint16(gh[4:6], pcapVersionMaj)
	binary.LittleEndian.PutUint16(gh[6:8], pcapVersionMin)
	binary.LittleEndian.PutUint32(gh[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(gh[20:24], pcapLinkEth)
	buf.Write(gh[:])

	var eth [ethHeaderLen]byte
	// dst = 02:00:00:00:00:02, src = 02:00:00:00:00:01 matching Python fixture builder.
	eth[0], eth[5] = 0x02, 0x02
	eth[6], eth[11] = 0x02, 0x01

	written := 0
	for _, pkt := range sorted {
		raw := pkt.Bytes
		if len(raw) < 20 {
			continue
		}
		ver := raw[0] >> 4
		var etherType uint16
		switch {
		case ver == 4 && len(raw) >= 20 && int(raw[0]&0x0f)*4 >= 20:
			etherType = etherTypeIPv4
		case ver == 6 && len(raw) >= 40:
			etherType = etherTypeIPv6
		default:
			continue
		}
		sec, usec := splitTimestamp(pkt.Time)
		totalLen := uint32(ethHeaderLen + len(raw))
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], sec)
		binary.LittleEndian.PutUint32(rh[4:8], usec)
		binary.LittleEndian.PutUint32(rh[8:12], totalLen)
		binary.LittleEndian.PutUint32(rh[12:16], totalLen)
		binary.BigEndian.PutUint16(eth[12:14], etherType)
		buf.Write(rh[:])
		buf.Write(eth[:])
		buf.Write(raw)
		written++
	}
	if written == 0 {
		return 0, nil
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return 0, fmt.Errorf("write inner pcap: %w", err)
	}
	return written, nil
}

// splitTimestamp converts epoch float seconds into (sec, usec) libpcap header fields.
func splitTimestamp(t float64) (uint32, uint32) {
	if t <= 0 || math.IsNaN(t) || math.IsInf(t, 0) {
		return 0, 0
	}
	sec := math.Floor(t)
	usec := math.Round((t - sec) * 1_000_000)
	if usec >= 1_000_000 {
		sec++
		usec -= 1_000_000
	}
	return uint32(sec), uint32(usec)
}
