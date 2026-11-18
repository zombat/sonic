// Package extract provides a pure-Go PCAP and PCAPNG binary reader for
// low-latency L2-L4, GRE, ESP, and data-plane extraction without spawning tshark.
package extract

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	if err := readFastPathReader(br, opts, &out); err != nil {
		return out, err
	}
	return out, nil
}

// readFastPathReader decodes a PCAP or PCAPNG byte stream from r into out.
func readFastPathReader(r io.Reader, opts FastPathOptions, out *model.RecordsOutput) error {
	var magicBuf [4]byte
	if _, err := io.ReadFull(r, magicBuf[:]); err != nil {
		return fmt.Errorf("read capture magic: %w", err)
	}
	var err error
	switch binary.LittleEndian.Uint32(magicBuf[:]) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		err = readFastPCAP(r, magicBuf, opts, &out.Records)
	case 0x0a0d0d0a:
		err = readFastPCAPNG(r, magicBuf, opts, &out.Records)
	default:
		return fmt.Errorf("unsupported capture magic: 0x%x", magicBuf)
	}
	if err != nil {
		return err
	}
	AnnotateServicePorts(out.Records)
	if opts.MaxPackets != nil && *opts.MaxPackets > 0 && len(out.Records) > *opts.MaxPackets {
		out.Records = out.Records[:*opts.MaxPackets]
	}
	return nil
}

// readExactBounded avoids upfront multi-MiB allocations on truncated frame lengths.
func readExactBounded(r io.Reader, n int) ([]byte, error) {
	if n <= 65536 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	buf := make([]byte, 0, 65536)
	var chunk [65536]byte
	rem := n
	for rem > 0 {
		take := min(rem, len(chunk))
		if _, err := io.ReadFull(r, chunk[:take]); err != nil {
			return nil, err
		}
		buf = append(buf, chunk[:take]...)
		rem -= take
	}
	return buf, nil
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
		frame, err := readExactBounded(r, inclLen)
		if err != nil {
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
