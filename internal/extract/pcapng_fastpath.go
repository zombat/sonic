// Package extract implements pure-Go PCAPNG block decoding for OpenFastPathRecords.
package extract

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/zombat/sonic/internal/model"
)

type pcapngInterface struct {
	linkType uint32
	tsUnit   float64
}

func readFastPCAPNG(r io.Reader, first4 [4]byte, opts FastPathOptions, out *[]model.Record) error {
	var shbHeader [24]byte
	if _, err := io.ReadFull(r, shbHeader[:]); err != nil {
		return fmt.Errorf("read pcapng shb: %w", err)
	}
	var order binary.ByteOrder = binary.LittleEndian
	if binary.LittleEndian.Uint32(shbHeader[4:8]) != 0x1a2b3c4d {
		if binary.BigEndian.Uint32(shbHeader[4:8]) != 0x1a2b3c4d {
			return errors.New("invalid pcapng byte-order magic")
		}
		order = binary.BigEndian
	}
	shbLen := order.Uint32(shbHeader[0:4])
	if shbLen < 28 || shbLen > maxCapturedFrameBytes {
		return fmt.Errorf("invalid pcapng shb length %d", shbLen)
	}
	if _, err := io.CopyN(io.Discard, r, int64(shbLen-28)); err != nil {
		return err
	}

	ifaces := []pcapngInterface{}
	var hdr [8]byte
	frameNum := 0
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		bType := order.Uint32(hdr[0:4])
		bLen := order.Uint32(hdr[4:8])
		if bLen < 12 || bLen > maxCapturedFrameBytes+128 {
			return fmt.Errorf("invalid pcapng block length %d", bLen)
		}
		bodyLen := int(bLen) - 8
		body, err := readExactBounded(r, bodyLen)
		if err != nil {
			return err
		}
		switch bType {
		case 0x0a0d0d0a:
			ifaces = ifaces[:0]
		case 0x00000001:
			if len(body) >= 12 {
				lt := uint32(order.Uint16(body[0:2]))
				ifaces = append(ifaces, pcapngInterface{linkType: lt, tsUnit: parseIDBTSResol(body[8:len(body)-4], order)})
			}
		case 0x00000006:
			if len(body) >= 24 {
				ifID := int(order.Uint32(body[0:4]))
				tsHigh := uint64(order.Uint32(body[4:8]))
				tsLow := uint64(order.Uint32(body[8:12]))
				capLen := int(order.Uint32(body[12:16]))
				origLen := int(order.Uint32(body[16:20]))
				if capLen >= 0 && 20+capLen <= len(body)-4 && ifID >= 0 && ifID < len(ifaces) {
					frameNum++
					epoch := float64((tsHigh<<32)|tsLow) * ifaces[ifID].tsUnit
					if inEpochWindow(epoch, opts.Since, opts.Until) {
						*out = append(*out, decodeFastFrame(frameNum, epoch, origLen, body[20:20+capLen], ifaces[ifID].linkType))
					}
				}
			}
		case 0x00000003:
			if len(body) >= 8 && len(ifaces) > 0 {
				origLen := int(order.Uint32(body[0:4]))
				frame := body[4 : len(body)-4]
				frameNum++
				if inEpochWindow(0, opts.Since, opts.Until) {
					*out = append(*out, decodeFastFrame(frameNum, 0, origLen, frame, ifaces[0].linkType))
				}
			}
		}
		if opts.MaxPackets != nil && *opts.MaxPackets > 0 && len(*out) >= *opts.MaxPackets {
			break
		}
	}
	return nil
}

func parseIDBTSResol(opts []byte, order binary.ByteOrder) float64 {
	pos := 0
	for pos+4 <= len(opts) {
		code := order.Uint16(opts[pos : pos+2])
		vlen := int(order.Uint16(opts[pos+2 : pos+4]))
		pos += 4
		if code == 0 {
			break
		}
		if pos+vlen > len(opts) {
			break
		}
		if code == 9 && vlen >= 1 {
			b := opts[pos]
			if (b & 0x80) != 0 {
				return math.Pow(2, -float64(b&0x7f))
			}
			return math.Pow(10, -float64(b))
		}
		pad := (vlen + 3) &^ 3
		pos += pad
	}
	return 1e-6
}
