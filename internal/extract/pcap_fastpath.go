// Package extract provides a pure-Go PCAP and PCAPNG binary reader for
// low-latency L2-L4, GRE, ESP, and data-plane extraction without spawning tshark.
package extract

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

const maxCapturedFrameBytes = 16 * 1024 * 1024

// FastPathOptions configures pure-Go packet extraction and time-window slicing.
type FastPathOptions struct {
	MaxPackets *int
	Since      *float64
	Until      *float64
}

type pcapngInterface struct {
	linkType uint32
	tsUnit   float64
}

// CanUseFastPath reports whether the requested detectors and display filter can
// run safely on pure-Go L2-L4 packet decoding without invoking tshark.
func CanUseFastPath(detectors []string, displayFilter string) bool {
	if displayFilter != "" || len(detectors) == 0 {
		return false
	}
	for _, d := range detectors {
		switch d {
		case "conversations", "esp_overhead", "path_mtu", "qos", "reachability", "tcp":
		default:
			return false
		}
	}
	return true
}

// FilterRecordWindow retains only records whose timestamp falls within [since, until].
func FilterRecordWindow(records []model.Record, since, until *float64) []model.Record {
	if since == nil && until == nil {
		return records
	}
	out := make([]model.Record, 0, len(records))
	for _, r := range records {
		if since != nil && r.T < *since {
			continue
		}
		if until != nil && r.T > *until {
			continue
		}
		out = append(out, r)
	}
	return out
}

// OpenFastPathRecords reads a PCAP or PCAPNG file directly in pure Go and returns
// normalized records matching the L2-L4/ESP/ICMP/ARP schema of OpenNetworkRecords.
func OpenFastPathRecords(filePath string, opts FastPathOptions) (model.RecordsOutput, error) {
	out := model.RecordsOutput{
		Backend:       "go-fast",
		MissingFields: []string{},
		Warnings:      []string{},
		Records:       []model.Record{},
	}
	if filePath == "" {
		return out, errors.New("empty capture file path")
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return out, fmt.Errorf("capture file stat failed: %w", err)
	}
	if info.IsDir() {
		return out, fmt.Errorf("capture path is a directory: %s", filePath)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return out, err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	var magicBuf [4]byte
	if _, err := io.ReadFull(br, magicBuf[:]); err != nil {
		return out, fmt.Errorf("read capture magic: %w", err)
	}
	switch binary.LittleEndian.Uint32(magicBuf[:]) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		err = readFastPCAP(br, magicBuf, opts, &out.Records)
	case 0x0a0d0d0a:
		err = readFastPCAPNG(br, magicBuf, opts, &out.Records)
	default:
		return out, fmt.Errorf("unsupported capture magic: 0x%x", magicBuf)
	}
	if err != nil {
		return out, err
	}
	AnnotateServicePorts(out.Records)
	if opts.MaxPackets != nil && *opts.MaxPackets > 0 && len(out.Records) > *opts.MaxPackets {
		out.Records = out.Records[:*opts.MaxPackets]
	}
	return out, nil
}

func readFastPCAP(r io.Reader, first4 [4]byte, opts FastPathOptions, out *[]model.Record) error {
	var rest [20]byte
	if _, err := io.ReadFull(r, rest[:]); err != nil {
		return fmt.Errorf("read pcap global header: %w", err)
	}
	var order binary.ByteOrder = binary.LittleEndian
	nsRes := false
	switch binary.LittleEndian.Uint32(first4[:]) {
	case 0xa1b23c4d:
		nsRes = true
	case 0xd4c3b2a1:
		order = binary.BigEndian
	case 0x4d3cb2a1:
		order = binary.BigEndian
		nsRes = true
	}
	linkType := order.Uint32(rest[16:20])

	var ph [16]byte
	frameNum := 0
	for {
		if _, err := io.ReadFull(r, ph[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return err
		}
		tsSec := float64(order.Uint32(ph[0:4]))
		tsSub := float64(order.Uint32(ph[4:8]))
		inclLen := int(order.Uint32(ph[8:12]))
		origLen := int(order.Uint32(ph[12:16]))
		if inclLen < 0 || inclLen > maxCapturedFrameBytes {
			return fmt.Errorf("invalid pcap frame length %d", inclLen)
		}
		frame := make([]byte, inclLen)
		if _, err := io.ReadFull(r, frame); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return err
		}
		frameNum++
		divisor := 1e6
		if nsRes {
			divisor = 1e9
		}
		epoch := tsSec + tsSub/divisor
		if !inEpochWindow(epoch, opts.Since, opts.Until) {
			continue
		}
		*out = append(*out, decodeFastFrame(frameNum, epoch, origLen, frame, linkType))
		if opts.MaxPackets != nil && *opts.MaxPackets > 0 && len(*out) >= *opts.MaxPackets {
			break
		}
	}
	return nil
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
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
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
				if capLen >= 0 && 20+capLen <= len(body)-4 && ifID < len(ifaces) {
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

func inEpochWindow(epoch float64, since, until *float64) bool {
	if since != nil && epoch < *since {
		return false
	}
	if until != nil && epoch > *until {
		return false
	}
	return true
}

func appendUniqueInt(s []int, v int) []int {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}
