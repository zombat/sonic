// Package extract parses TLS NSS key logs and pcapng Decryption Secrets Blocks
// without retaining or exposing secret key material.
package extract

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"strings"
)

const (
	// PCAPNGSection is the palindromic pcapng Section Header Block type ID.
	PCAPNGSection uint32 = 0x0A0D0D0A
	// PCAPNGDSB is the pcapng Decryption Secrets Block type ID.
	PCAPNGDSB uint32 = 0x0000000A
	// DSBTLS is the pcapng DSB secret type identifier for NSS TLS key logs ("TLSK").
	DSBTLS uint32 = 0x544C534B
	// ByteOrderMagic identifies the endianness of a pcapng Section Header Block.
	ByteOrderMagic uint32 = 0x1A2B3C4D
	// MaxSecretsBlock caps single DSB allocations to 64 MiB.
	MaxSecretsBlock int64 = 64 * 1024 * 1024
)

// TLS13Labels lists the NSS key-log labels required to decrypt TLS 1.3 handshakes and data.
var TLS13Labels = []string{
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
	"SERVER_HANDSHAKE_TRAFFIC_SECRET",
	"CLIENT_TRAFFIC_SECRET_0",
	"SERVER_TRAFFIC_SECRET_0",
}

// KnownLabels contains every recognized NSS SSLKEYLOGFILE label.
var KnownLabels = map[string]bool{
	"CLIENT_RANDOM":                   true,
	"CLIENT_EARLY_TRAFFIC_SECRET":     true,
	"EARLY_EXPORTER_SECRET":           true,
	"EXPORTER_SECRET":                 true,
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET": true,
	"SERVER_HANDSHAKE_TRAFFIC_SECRET": true,
	"CLIENT_TRAFFIC_SECRET_0":         true,
	"SERVER_TRAFFIC_SECRET_0":         true,
}

// PCAPNGSecretsResult holds DSB counts and client-random label sets found in a pcapng file.
type PCAPNGSecretsResult struct {
	Blocks int
	Labels map[string]map[string]bool
}

// parseKeyLogLine parses one NSS key-log line into out without retaining the secret column.
func parseKeyLogLine(line string, out map[string]map[string]bool) {
	parts := strings.Fields(line)
	if len(parts) < 3 || !KnownLabels[parts[0]] {
		return
	}
	label := parts[0]
	randomHex := strings.ToLower(parts[1])
	if len(randomHex) != 64 {
		return
	}
	set, ok := out[randomHex]
	if !ok {
		set = make(map[string]bool)
		out[randomHex] = set
	}
	set[label] = true
}

// LabelsByRandom maps 64-hex-char lowercase ClientHello randoms to their present key-log labels.
func LabelsByRandom(lines []string) map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	for _, line := range lines {
		parseKeyLogLine(line, out)
	}
	return out
}

// KeyLogLabels streams an NSS key log file line by line and indexes labels by ClientHello random.
func KeyLogLabels(path string) (map[string]map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := make(map[string]map[string]bool)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		parseKeyLogLine(sc.Text(), out)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// PCAPNGSecrets extracts TLS DSB metadata from a pcapng file without loading non-DSB blocks.
// Returns (nil, nil) if path is not a pcapng file.
func PCAPNGSecrets(path string) (*PCAPNGSecretsResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	head := make([]byte, 12)
	if n, err := io.ReadFull(f, head); err != nil || n < 12 {
		return nil, nil
	}
	if binary.LittleEndian.Uint32(head[:4]) != PCAPNGSection {
		return nil, nil
	}

	var bo binary.ByteOrder = binary.BigEndian
	if binary.LittleEndian.Uint32(head[8:12]) == ByteOrderMagic {
		bo = binary.LittleEndian
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()

	blocks := 0
	labels := make(map[string]map[string]bool)
	var pos int64
	header := make([]byte, 8)
	magic := make([]byte, 4)

	for pos+12 <= size {
		if _, err := f.Seek(pos, io.SeekStart); err != nil {
			break
		}
		if _, err := io.ReadFull(f, header); err != nil {
			break
		}
		btype := binary.LittleEndian.Uint32(header[:4])
		if btype == PCAPNGSection {
			if _, err := io.ReadFull(f, magic); err != nil {
				break
			}
			if binary.LittleEndian.Uint32(magic) == ByteOrderMagic {
				bo = binary.LittleEndian
			} else {
				bo = binary.BigEndian
			}
		} else {
			btype = bo.Uint32(header[:4])
		}

		length := int64(bo.Uint32(header[4:8]))
		if length < 12 || length%4 != 0 || pos+length > size {
			break
		}
		if btype == PCAPNGDSB && length-12 <= MaxSecretsBlock {
			body := make([]byte, length-12)
			if _, err := io.ReadFull(f, body); err != nil {
				break
			}
			if len(body) >= 8 {
				stype := bo.Uint32(body[:4])
				slen := int64(bo.Uint32(body[4:8]))
				if stype == DSBTLS {
					blocks++
					end := 8 + slen
					if end > int64(len(body)) {
						end = int64(len(body))
					}
					text := string(body[8:end])
					for randomHex, names := range LabelsByRandom(strings.Split(text, "\n")) {
						dst, ok := labels[randomHex]
						if !ok {
							dst = make(map[string]bool)
							labels[randomHex] = dst
						}
						for k := range names {
							dst[k] = true
						}
					}
				}
			}
		}
		pos += length
	}
	return &PCAPNGSecretsResult{Blocks: blocks, Labels: labels}, nil
}

// MissingLabels lists key-log labels absent from labels for the negotiated TLS version.
func MissingLabels(labels map[string]bool, version string) []string {
	switch version {
	case "TLS1.3":
		var missing []string
		for _, lbl := range TLS13Labels {
			if !labels[lbl] {
				missing = append(missing, lbl)
			}
		}
		return missing
	case "TLS1.2", "TLS1.1", "TLS1.0", "SSL3.0":
		if labels["CLIENT_RANDOM"] {
			return []string{}
		}
		return []string{"CLIENT_RANDOM"}
	default:
		return []string{}
	}
}
