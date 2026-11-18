// Package extract parses operator ESP SA files and Linux `ip xfrm state` dumps.
package extract

import (
	"errors"
	"strconv"
	"strings"
)

// ParseSAFile parses operator key-value SA files or delegates Linux ip xfrm state dumps.
func ParseSAFile(text string) ([]EspSA, error) {
	if xfrmHeaderRe.MatchString(text) && (strings.Contains(text, "proto esp") || strings.Contains(text, "spi ")) {
		return ParseXfrmState(text)
	}
	var records []EspSA
	var current EspSA
	hasFields := false
	flush := func() {
		if hasFields {
			records = append(records, current)
			current = EspSA{}
			hasFields = false
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || line == "---" || strings.EqualFold(line, "[sa]") {
			flush()
			continue
		}
		colonIdx := strings.IndexByte(line, ':')
		eqIdx := strings.IndexByte(line, '=')
		sep := byte('=')
		if colonIdx >= 0 && (eqIdx < 0 || colonIdx < eqIdx) {
			sep = ':'
		} else if eqIdx < 0 {
			continue
		}
		idx := strings.IndexByte(line, sep)
		canon, ok := saFieldAliases[strings.ToLower(strings.TrimSpace(line[:idx]))]
		if !ok {
			continue
		}
		val := strings.Trim(strings.Trim(strings.TrimSpace(line[idx+1:]), `"`), `'`)
		applySAField(&current, canon, val)
		hasFields = true
	}
	flush()
	var out []EspSA
	for _, sa := range records {
		if sa.Src != "" && sa.Dst != "" && sa.SPI != "" {
			out = append(out, sa)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no Security Association with src, dst and spi found in the SA file")
	}
	return out, nil
}

// ParseXfrmState parses `ip -s xfrm state` output into EspSA entries.
func ParseXfrmState(text string) ([]EspSA, error) {
	var sas []EspSA
	var current *EspSA
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if m := xfrmSrcDstRe.FindStringSubmatch(line); m != nil {
			if current != nil && current.SPI != "" {
				sas = append(sas, *current)
			}
			proto := "IPv4"
			if strings.Contains(m[1], ":") {
				proto = "IPv6"
			}
			current = &EspSA{Src: m[1], Dst: m[2], Protocol: proto}
			continue
		}
		if current == nil {
			continue
		}
		if m := xfrmProtoRe.FindStringSubmatch(line); m != nil {
			current.SPI = m[1]
		}
		if m := xfrmAEADRe.FindStringSubmatch(line); m != nil {
			algo, key := m[1], m[2]
			icvBits, _ := strconv.Atoi(m[3])
			enc := algo
			if strings.Contains(algo, "gcm(aes)") {
				switch icvBits {
				case 96:
					enc = "aes-gcm-12"
				case 64:
					enc = "aes-gcm-8"
				default:
					enc = "aes-gcm-16"
				}
			}
			none := "none"
			current.Encryption = &enc
			current.EncryptionKey = key
			current.Integrity = &none
			continue
		}
		if m := xfrmEncRe.FindStringSubmatch(line); m != nil {
			algo, key := m[1], m[2]
			mapped := map[string]string{
				"cbc(aes)":         "aes-cbc",
				"cbc(des3_ede)":    "3des-cbc",
				"cbc(des)":         "des-cbc",
				"ecb(cipher_null)": "null",
			}
			enc := algo
			if v, ok := mapped[algo]; ok {
				enc = v
			}
			current.Encryption = &enc
			current.EncryptionKey = key
			continue
		}
		if m := xfrmAuthRe.FindStringSubmatch(line); m != nil {
			algo, key := m[1], m[2]
			mapped := map[string]string{
				"hmac(sha1)":   "hmac-sha1-96",
				"hmac(sha256)": "hmac-sha256-128",
				"hmac(sha384)": "hmac-sha384-192",
				"hmac(sha512)": "hmac-sha512-256",
				"hmac(md5)":    "hmac-md5-96",
			}
			integ := algo
			if v, ok := mapped[algo]; ok {
				integ = v
			}
			current.Integrity = &integ
			current.IntegrityKey = key
		}
	}
	if current != nil && current.SPI != "" {
		sas = append(sas, *current)
	}
	var out []EspSA
	for _, sa := range sas {
		if sa.Src != "" && sa.Dst != "" && sa.SPI != "" {
			out = append(out, sa)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no ESP Security Association found in the xfrm state dump")
	}
	return out, nil
}

// applySAField sets one canonical field on sa.
func applySAField(sa *EspSA, canon, val string) {
	switch canon {
	case "src":
		sa.Src = val
	case "dst":
		sa.Dst = val
	case "spi":
		sa.SPI = val
	case "protocol":
		sa.Protocol = val
	case "encryption":
		v := val
		sa.Encryption = &v
	case "encryption_key":
		sa.EncryptionKey = val
	case "integrity":
		v := val
		sa.Integrity = &v
	case "integrity_key":
		sa.IntegrityKey = val
	}
}
