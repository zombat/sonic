// Package extract parses IPsec ESP Security Association files, Linux xfrm state
// dumps, and Wireshark esp_sa UAT rows without exposing secret key material.
package extract

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// EncryptionLabels maps friendly and xfrm cipher names to Wireshark esp_sa labels.
	EncryptionLabels = map[string]string{
		"aes-cbc":           "AES-CBC [RFC3602]",
		"aes":               "AES-CBC [RFC3602]",
		"cbc(aes)":          "AES-CBC [RFC3602]",
		"aes-ctr":           "AES-CTR [RFC3686]",
		"rfc3686(ctr(aes))": "AES-CTR [RFC3686]",
		"3des-cbc":          "TripleDES-CBC [RFC2451]",
		"3des":              "TripleDES-CBC [RFC2451]",
		"cbc(des3_ede)":     "TripleDES-CBC [RFC2451]",
		"des-cbc":           "DES-CBC [RFC2405]",
		"des":               "DES-CBC [RFC2405]",
		"cbc(des)":          "DES-CBC [RFC2405]",
		"null":              "NULL",
		"ecb(cipher_null)":  "NULL",
		"aes-gcm":           "AES-GCM with 16 octet ICV [RFC4106]",
		"aes-gcm-16":        "AES-GCM with 16 octet ICV [RFC4106]",
		"rfc4106(gcm(aes))": "AES-GCM with 16 octet ICV [RFC4106]",
		"aes-gcm-12":        "AES-GCM with 12 octet ICV [RFC4106]",
		"aes-gcm-8":         "AES-GCM with 8 octet ICV [RFC4106]",
	}

	// IntegrityLabels maps friendly and xfrm HMAC names to Wireshark esp_sa labels.
	IntegrityLabels = map[string]string{
		"hmac-sha1-96":    "HMAC-SHA-1-96 [RFC2404]",
		"hmac(sha1)":      "HMAC-SHA-1-96 [RFC2404]",
		"sha1":            "HMAC-SHA-1-96 [RFC2404]",
		"hmac-sha256-128": "HMAC-SHA-256-128 [RFC4868]",
		"hmac(sha256)":    "HMAC-SHA-256-128 [RFC4868]",
		"sha256":          "HMAC-SHA-256-128 [RFC4868]",
		"hmac-sha384-192": "HMAC-SHA-384-192 [RFC4868]",
		"hmac(sha384)":    "HMAC-SHA-384-192 [RFC4868]",
		"hmac-sha512-256": "HMAC-SHA-512-256 [RFC4868]",
		"hmac(sha512)":    "HMAC-SHA-512-256 [RFC4868]",
		"hmac-md5-96":     "HMAC-MD5-96 [RFC2403]",
		"hmac(md5)":       "HMAC-MD5-96 [RFC2403]",
		"md5":             "HMAC-MD5-96 [RFC2403]",
		"none":            "NULL",
		"null":            "NULL",
		"":                "NULL",
		"any-96":          "ANY 96 bit authentication [no checking]",
		"any-128":         "ANY 128 bit authentication [no checking]",
	}

	// AEADLabels identifies Wireshark encryption labels that bundle integrity verification.
	AEADLabels = map[string]bool{
		"AES-GCM with 16 octet ICV [RFC4106]": true,
		"AES-GCM with 12 octet ICV [RFC4106]": true,
		"AES-GCM with 8 octet ICV [RFC4106]":  true,
	}

	// ICVBytes maps Wireshark integrity labels to their trailing ICV byte length.
	ICVBytes = map[string]int{
		"HMAC-SHA-1-96 [RFC2404]":                  12,
		"HMAC-MD5-96 [RFC2403]":                    12,
		"HMAC-SHA-256-128 [RFC4868]":               16,
		"HMAC-SHA-384-192 [RFC4868]":               24,
		"HMAC-SHA-512-256 [RFC4868]":               32,
		"ANY 96 bit authentication [no checking]":  12,
		"ANY 128 bit authentication [no checking]": 16,
		"NULL": 0,
	}

	saHexRe      = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	xfrmHeaderRe = regexp.MustCompile(`(?m)^\s*src\s+\S+\s+dst\s+\S+`)
	xfrmSrcDstRe = regexp.MustCompile(`^src\s+(\S+)\s+dst\s+(\S+)`)
	xfrmProtoRe  = regexp.MustCompile(`\bproto\s+esp\s+spi\s+(\S+)`)
	xfrmAEADRe   = regexp.MustCompile(`^aead\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(\d+)`)
	xfrmEncRe    = regexp.MustCompile(`^enc\s+(\S+)\s+(0x[0-9a-fA-F]+)`)
	xfrmAuthRe   = regexp.MustCompile(`^auth(?:-trunc)?\s+(\S+)\s+(0x[0-9a-fA-F]+)(?:\s+(\d+))?`)

	saFieldAliases = map[string]string{
		"src":                 "src",
		"source":              "src",
		"dst":                 "dst",
		"dest":                "dst",
		"destination":         "dst",
		"spi":                 "spi",
		"protocol":            "protocol",
		"proto":               "protocol",
		"encryption":          "encryption",
		"enc":                 "encryption",
		"cipher":              "encryption",
		"encryption_algo":     "encryption",
		"encryption_key":      "encryption_key",
		"enc_key":             "encryption_key",
		"key":                 "encryption_key",
		"integrity":           "integrity",
		"auth":                "integrity",
		"authentication":      "integrity",
		"authentication_algo": "integrity",
		"integrity_key":       "integrity_key",
		"auth_key":            "integrity_key",
		"authentication_key":  "integrity_key",
	}
)

// EspSA describes a parsed IPsec ESP Security Association with optional secret keys.
type EspSA struct {
	Src           string
	Dst           string
	SPI           string
	Protocol      string
	Encryption    *string
	EncryptionKey string
	Integrity     *string
	IntegrityKey  string
}

func init() {
	for _, label := range EncryptionLabels {
		EncryptionLabels[strings.ToLower(label)] = label
	}
	for _, label := range IntegrityLabels {
		IntegrityLabels[strings.ToLower(label)] = label
	}
}

// hexKey normalizes a hexadecimal key to lowercase 0x-prefixed hex without echoing invalid key text.
func hexKey(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	body := trimmed
	if len(body) >= 2 && strings.EqualFold(body[:2], "0x") {
		body = body[2:]
	}
	body = strings.ReplaceAll(body, ":", "")
	body = strings.ReplaceAll(body, " ", "")
	if body == "" {
		return "", nil
	}
	if !saHexRe.MatchString(body) {
		return "", errors.New("a key is not hexadecimal (0x followed by hex digits)")
	}
	return "0x" + strings.ToLower(body), nil
}

// resolveLabel resolves a friendly algorithm name or full Wireshark label against mapping.
func resolveLabel(mapping map[string]string, name, what string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if label, ok := mapping[key]; ok {
		return label, nil
	}
	for _, label := range mapping {
		if name == label {
			return label, nil
		}
	}
	return "", fmt.Errorf("unknown %s algorithm: %q", what, name)
}

// CanonicalSPI formats an SPI value into canonical lowercase 0x-prefixed 8-hex-digit form.
func CanonicalSPI(value string) (string, error) {
	text := strings.ToLower(strings.TrimSpace(value))
	var number uint64
	var err error
	if strings.HasPrefix(text, "0x") {
		number, err = strconv.ParseUint(text[2:], 16, 32)
	} else if strings.ContainsAny(text, "abcdef") {
		number, err = strconv.ParseUint(text, 16, 32)
	} else {
		number, err = strconv.ParseUint(text, 10, 32)
	}
	if err != nil {
		return "", fmt.Errorf("SPI is not a number or out of range: %q", value)
	}
	return fmt.Sprintf("0x%08x", number), nil
}

// SAUATRow formats one Wireshark esp_sa UAT CSV record for sa.
func SAUATRow(sa EspSA) (string, error) {
	proto := sa.Protocol
	if proto == "" {
		proto = "IPv4"
	}
	encName := "null"
	if sa.Encryption != nil {
		encName = *sa.Encryption
	}
	encLabel, err := resolveLabel(EncryptionLabels, encName, "encryption")
	if err != nil {
		return "", err
	}
	encKey, err := hexKey(sa.EncryptionKey)
	if err != nil {
		return "", err
	}
	authLabel := "NULL"
	authKey := ""
	if !AEADLabels[encLabel] {
		intName := "none"
		if sa.Integrity != nil {
			intName = *sa.Integrity
		}
		authLabel, err = resolveLabel(IntegrityLabels, intName, "integrity")
		if err != nil {
			return "", err
		}
		authKey, err = hexKey(sa.IntegrityKey)
		if err != nil {
			return "", err
		}
	}
	spi, err := CanonicalSPI(sa.SPI)
	if err != nil {
		return "", err
	}
	fields := []string{proto, sa.Src, sa.Dst, spi, encLabel, encKey, authLabel, authKey}
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(strings.ReplaceAll(f, `"`, ""))
		b.WriteByte('"')
	}
	return b.String(), nil
}
