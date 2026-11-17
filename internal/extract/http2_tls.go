// Package extract provides TLS handshake decryption coverage inspection via tshark.
package extract

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// TLSDecryptionInfo reports decrypted handshake/app-data status for one TLS tcp.stream.
type TLSDecryptionInfo struct {
	ClientRandom     *string
	ClientHelloFrame *int
	Handshake        bool
	ApplicationData  []string
	Certificate      []byte
}

// TLSDecryption probes which TLS streams tshark decrypted given an optional SSLKEYLOGFILE
// path (and any embedded pcapng DSBs) across the given decode-as options.
func TLSDecryption(
	ctx context.Context,
	filePath string,
	decodeAs []string,
	keylogFile string,
	displayFilter string,
	maxPackets *int,
	outOfOrder bool,
) (map[int]*TLSDecryptionInfo, error) {
	flt := "tls.handshake.type || tls.app_data_proto"
	if displayFilter != "" {
		flt = fmt.Sprintf("(%s) && (%s)", displayFilter, flt)
	}
	preArgs := make([]string, 0, len(decodeAs)+4)
	preArgs = append(preArgs, decodeAs...)
	if outOfOrder {
		preArgs = append(preArgs, "-o", "tcp.reassemble_out_of_order:TRUE")
	}
	if keylogFile != "" {
		preArgs = append(preArgs, "-o", "tls.keylog_file:"+keylogFile)
	}
	fields := []string{
		"frame.number", "tcp.stream", "tls.handshake.type",
		"tls.handshake.random", "tls.handshake.certificate", "tls.app_data_proto",
	}
	out := make(map[int]*TLSDecryptionInfo)
	_, err := streamTsharkFields(ctx, filePath, preArgs, flt, fields, "|", maxPackets, nil, func(row map[string]string) error {
		frame, _ := parseFieldInt(row["frame.number"])
		index, ok := parseFieldInt(firstPipe(row["tcp.stream"]))
		if !ok {
			return nil
		}
		entry, exists := out[index]
		if !exists {
			entry = &TLSDecryptionInfo{ApplicationData: []string{}}
			out[index] = entry
		}

		var types []int
		for _, tok := range strings.Split(row["tls.handshake.type"], "|") {
			if tok != "" {
				if v, ok := parseFieldInt(tok); ok {
					types = append(types, v)
				}
			}
		}
		var randoms []string
		for _, r := range strings.Split(row["tls.handshake.random"], "|") {
			if r != "" {
				randoms = append(randoms, r)
			}
		}
		var helloTypes []int
		for _, tp := range types {
			if tp == 1 || tp == 2 {
				helloTypes = append(helloTypes, tp)
			}
		}
		for i := 0; i < len(helloTypes) && i < len(randoms); i++ {
			if helloTypes[i] == 1 && entry.ClientRandom == nil {
				cr := strings.ToLower(strings.ReplaceAll(randoms[i], ":", ""))
				entry.ClientRandom = &cr
				fr := frame
				entry.ClientHelloFrame = &fr
			}
		}
		for _, tp := range types {
			if tp == 8 || tp == 20 {
				entry.Handshake = true
			}
		}
		if certRaw := firstPipe(row["tls.handshake.certificate"]); certRaw != "" && entry.Certificate == nil {
			if rawBytes, err := hex.DecodeString(strings.ReplaceAll(certRaw, ":", "")); err == nil {
				entry.Certificate = rawBytes
			}
		}
		for _, proto := range strings.Split(row["tls.app_data_proto"], "|") {
			for _, name := range strings.Split(proto, ",") {
				if name != "" && !slices.Contains(entry.ApplicationData, name) {
					entry.ApplicationData = append(entry.ApplicationData, name)
				}
			}
		}
		return nil
	})
	return out, err
}
