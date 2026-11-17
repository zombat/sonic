// Package extract decrypts ESP packets via ephemeral tshark UAT tables and
// reconstructs validated tunnel-mode and transport-mode inner IP payloads.
package extract

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/wsconfig"
)

const (
	// NoNextHeader marks RFC 4303 dummy ESP packets carrying no inner payload.
	NoNextHeader = 59
)

var (
	// ESPFields lists tshark fields extracted for ESP decryption and ICV verification.
	ESPFields = []string{
		"frame.number", "frame.time_epoch", "ip.src", "ip.dst",
		"ipv6.src", "ipv6.dst", "esp.spi", "esp.decrypted_data",
		"esp.icv_good", "esp.icv_bad",
	}

	// TunnelNextHeaders maps IP-in-IP protocol numbers inside ESP tunnel trailers.
	TunnelNextHeaders = map[int]string{4: "IPv4", 41: "IPv6"}

	// TransportNextHeaders maps inner L4/L3 next-header numbers for ESP transport mode.
	TransportNextHeaders = map[int]string{
		1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
	}
)

// ESPKey uniquely identifies one ESP Security Association tuple.
type ESPKey struct {
	Src string
	Dst string
	SPI string
}

// DecryptedInnerPacket represents one validated decrypted inner IP packet.
type DecryptedInnerPacket struct {
	Frame int
	Time  float64
	Bytes []byte
	SPI   string
	Src   string
	Dst   string
	Mode  string
}

// ESPStatsRow tracks decryption and ICV verification counts for one SA.
type ESPStatsRow struct {
	Src        string  `json:"src"`
	Dst        string  `json:"dst"`
	SPI        string  `json:"spi"`
	Encryption *string `json:"encryption"`
	Integrity  *string `json:"integrity"`
	Packets    int     `json:"packets"`
	Decrypted  int     `json:"decrypted"`
	Tunnel     int     `json:"tunnel"`
	Transport  int     `json:"transport"`
	ICVGood    int     `json:"icv_good"`
	ICVBad     int     `json:"icv_bad"`
	nullICV    int
}

// ESPDecryptResult holds decrypted inner IP packets, per-SA stats, and table warnings.
type ESPDecryptResult struct {
	Inner    []DecryptedInnerPacket
	Stats    map[ESPKey]*ESPStatsRow
	Warnings []string
}

// DecryptESP runs tshark with an ephemeral esp_sa UAT directory to decrypt ESP packets.
func DecryptESP(
	ctx context.Context,
	filePath string,
	sas []EspSA,
	displayFilter string,
	maxPackets *int,
) (ESPDecryptResult, error) {
	uatRows := make([]string, 0, len(sas))
	stats := make(map[ESPKey]*ESPStatsRow, len(sas))
	for _, sa := range sas {
		row, err := SAUATRow(sa)
		if err != nil {
			return ESPDecryptResult{}, err
		}
		uatRows = append(uatRows, row)
		spi, _ := CanonicalSPI(sa.SPI)
		key := ESPKey{Src: sa.Src, Dst: sa.Dst, SPI: spi}
		stats[key] = &ESPStatsRow{
			Src:        sa.Src,
			Dst:        sa.Dst,
			SPI:        spi,
			Encryption: sa.Encryption,
			Integrity:  sa.Integrity,
			nullICV:    nullICVBytes(sa),
		}
	}

	prefs := map[string]string{
		"esp.enable_encryption_decode":    "TRUE",
		"esp.enable_authentication_check": "TRUE",
	}
	filter := "esp"
	if displayFilter != "" {
		filter = fmt.Sprintf("(%s) && esp", displayFilter)
	}

	var inner []DecryptedInnerPacket
	var rawErr string
	err := wsconfig.WithConfig(prefs, map[string][]string{"esp_sa": uatRows}, func(dir string) error {
		var runErr error
		rawErr, runErr = streamTsharkFields(
			ctx,
			filePath,
			nil,
			filter,
			ESPFields,
			"\x1f",
			maxPackets,
			wsconfig.Env(dir),
			func(row map[string]string) error {
				processESPRow(row, &inner, stats)
				return nil
			},
		)
		return runErr
	})
	if err != nil {
		return ESPDecryptResult{}, err
	}

	warnings := []string{}
	for _, line := range strings.Split(rawErr, "\n") {
		if strings.Contains(line, "esp_sa") || strings.Contains(line, "ESP SAs") {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 300 {
				trimmed = trimmed[:300]
			}
			warnings = append(warnings, trimmed)
		}
	}
	return ESPDecryptResult{Inner: inner, Stats: stats, Warnings: warnings}, nil
}

// firstAgg returns the first item in a tshark aggregator-joined field value.
func firstAgg(s string) string {
	if idx := strings.IndexByte(s, '\x1f'); idx >= 0 {
		return s[:idx]
	}
	return s
}

// processESPRow validates one tshark ESP field row and appends any reconstructed inner packet.
func processESPRow(row map[string]string, inner *[]DecryptedInnerPacket, stats map[ESPKey]*ESPStatsRow) {
	src := firstAgg(row["ip.src"])
	if src == "" {
		src = firstAgg(row["ipv6.src"])
	}
	dst := firstAgg(row["ip.dst"])
	if dst == "" {
		dst = firstAgg(row["ipv6.dst"])
	}
	spi, err := CanonicalSPI(firstAgg(row["esp.spi"]))
	if err != nil {
		return
	}
	stat, ok := stats[ESPKey{Src: src, Dst: dst, SPI: spi}]
	if !ok {
		return
	}
	stat.Packets++
	if v := firstAgg(row["esp.icv_good"]); v == "1" || v == "True" {
		stat.ICVGood++
	}
	if v := firstAgg(row["esp.icv_bad"]); v == "1" || v == "True" {
		stat.ICVBad++
		return
	}
	hexClean := strings.ReplaceAll(firstAgg(row["esp.decrypted_data"]), ":", "")
	data, err := hex.DecodeString(hexClean)
	if err != nil {
		return
	}
	payload, nextHeader, ok := ESPTrailer(data)
	if !ok && stat.nullICV > 0 && len(data) >= stat.nullICV {
		payload, nextHeader, ok = ESPTrailer(data[:len(data)-stat.nullICV])
	}
	if !ok {
		return
	}

	frame, _ := strconv.Atoi(firstAgg(row["frame.number"]))
	t, _ := strconv.ParseFloat(row["frame.time_epoch"], 64)
	if _, isTunnel := TunnelNextHeaders[nextHeader]; isTunnel {
		packet := innerIPPacket(payload, nextHeader)
		if packet == nil {
			return
		}
		stat.Decrypted++
		stat.Tunnel++
		*inner = append(*inner, DecryptedInnerPacket{
			Frame: frame, Time: t, Bytes: packet, SPI: spi, Src: src, Dst: dst, Mode: "tunnel",
		})
		return
	}
	if _, isTransport := TransportNextHeaders[nextHeader]; isTransport {
		stat.Decrypted++
		stat.Transport++
		if packet := transportIPPacket(src, dst, nextHeader, payload); packet != nil {
			*inner = append(*inner, DecryptedInnerPacket{
				Frame: frame, Time: t, Bytes: packet, SPI: spi, Src: src, Dst: dst, Mode: "transport",
			})
		}
		return
	}
	if nextHeader == NoNextHeader {
		stat.Decrypted++
	}
}

// nullICVBytes returns the trailing ICV byte length tshark leaves in decrypted_data for NULL encryption.
func nullICVBytes(sa EspSA) int {
	encName := "null"
	if sa.Encryption != nil {
		encName = *sa.Encryption
	}
	encLabel, err := resolveLabel(EncryptionLabels, encName, "encryption")
	if err != nil || encLabel != "NULL" {
		return 0
	}
	intName := "none"
	if sa.Integrity != nil {
		intName = *sa.Integrity
	}
	intLabel, err := resolveLabel(IntegrityLabels, intName, "integrity")
	if err != nil {
		return 0
	}
	return ICVBytes[intLabel]
}
