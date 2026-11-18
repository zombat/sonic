// Package tlsinspect provides TLS cipher suite, version, and handshake
// parsing shared by the cleartext audit and TLS inspection detectors.
package tlsinspect

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// EncState models the encryption security classification of a session or cipher suite.
type EncState int

const (
	// StateEncrypted indicates an authenticated, non-weak encryption cipher.
	StateEncrypted EncState = iota
	// StateWeak indicates deprecated TLS versions (< 1.2) or weak ciphers/hashes.
	StateWeak
	// StateUnverified indicates midstream or unrecognised cipher/handshake state.
	StateUnverified
	// StateCleartext indicates unencrypted traffic (NULL, anon, export, integrity-only).
	StateCleartext
	// StateNotStarted indicates a session with TCP control frames only and no app payload.
	StateNotStarted
)

// String returns the canonical lowercase JSON token for EncState.
func (e EncState) String() string {
	switch e {
	case StateEncrypted:
		return "encrypted"
	case StateWeak:
		return "weak"
	case StateUnverified:
		return "unverified"
	case StateCleartext:
		return "cleartext"
	case StateNotStarted:
		return "not_started"
	default:
		return "unverified"
	}
}

// Versions maps wire protocol version codes to canonical S.O.N.I.C. labels.
var Versions = map[uint16]string{
	0x0300: "SSL3.0",
	0x0301: "TLS1.0",
	0x0302: "TLS1.1",
	0x0303: "TLS1.2",
	0x0304: "TLS1.3",
}

// VersionRank orders SSL/TLS versions from weakest (0) to newest (4).
var VersionRank = map[string]int{
	"SSL3.0": 0,
	"TLS1.0": 1,
	"TLS1.1": 2,
	"TLS1.2": 3,
	"TLS1.3": 4,
}

// CipherSuites maps 16-bit TLS cipher suite IDs to Wireshark/IANA names.
var CipherSuites = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256", 0x1305: "TLS_AES_128_CCM_8_SHA256",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA", 0x003B: "TLS_RSA_WITH_NULL_SHA256", 0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x5600: "TLS_FALLBACK_SCSV",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256", 0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
	0x00AA: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", 0x00AB: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
	0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	0xC05C: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", 0xC05D: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
	0xC060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", 0xC061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC08A: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", 0xC08B: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC09C: "TLS_RSA_WITH_AES_128_CCM", 0xC09D: "TLS_RSA_WITH_AES_256_CCM", 0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
	0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM", 0xC0A0: "TLS_RSA_WITH_AES_128_CCM_8",
	0xC0A1: "TLS_RSA_WITH_AES_256_CCM_8", 0xC0A2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
	0xC0A3: "TLS_DHE_RSA_WITH_AES_256_CCM_8", 0xC0A4: "TLS_PSK_WITH_AES_128_CCM", 0xC0A5: "TLS_PSK_WITH_AES_256_CCM",
	0xC0A6: "TLS_DHE_PSK_WITH_AES_128_CCM", 0xC0A7: "TLS_DHE_PSK_WITH_AES_256_CCM",
	0xC0A8: "TLS_PSK_WITH_AES_128_CCM_8", 0xC0A9: "TLS_PSK_WITH_AES_256_CCM_8",
	0xC0AA: "TLS_PSK_DHE_WITH_AES_128_CCM_8", 0xC0AB: "TLS_PSK_DHE_WITH_AES_256_CCM_8",
	0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", 0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
	0xD001: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", 0xD002: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
	0xD003: "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", 0xD005: "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", 0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", 0x001C: "SSL_FORTEZZA_KEA_WITH_NULL_SHA",
	0x0026: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", 0x0027: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
	0x0028: "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", 0x0029: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
	0x002A: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", 0x002B: "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
	0x002C: "TLS_PSK_WITH_NULL_SHA", 0x002D: "TLS_DHE_PSK_WITH_NULL_SHA", 0x002E: "TLS_RSA_PSK_WITH_NULL_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x0046: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", 0x0060: "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
	0x0061: "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", 0x0062: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
	0x0063: "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", 0x0064: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
	0x0065: "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", 0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256", 0x0082: "TLS_GOSTR341094_WITH_NULL_GOSTR3411",
	0x0083: "TLS_GOSTR341001_WITH_NULL_GOSTR3411", 0x0089: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	0x009B: "TLS_DH_anon_WITH_SEED_CBC_SHA", 0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384", 0x00B0: "TLS_PSK_WITH_NULL_SHA256",
	0x00B1: "TLS_PSK_WITH_NULL_SHA384", 0x00B4: "TLS_DHE_PSK_WITH_NULL_SHA256",
	0x00B5: "TLS_DHE_PSK_WITH_NULL_SHA384", 0x00B8: "TLS_RSA_PSK_WITH_NULL_SHA256",
	0x00B9: "TLS_RSA_PSK_WITH_NULL_SHA384", 0x00BF: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
	0x00C5: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", 0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA", 0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA", 0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0xC039: "TLS_ECDHE_PSK_WITH_NULL_SHA", 0xC03A: "TLS_ECDHE_PSK_WITH_NULL_SHA256",
	0xC03B: "TLS_ECDHE_PSK_WITH_NULL_SHA384", 0xC046: "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
	0xC047: "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", 0xC05A: "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
	0xC05B: "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", 0xC084: "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
	0xC085: "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", 0xC0B4: "TLS_SHA256_SHA256", 0xC0B5: "TLS_SHA384_SHA384",
}

// WeakMarkers lists substrings identifying weak or broken TLS cipher suites.
var WeakMarkers = []string{
	"RC4", "3DES", "_DES_", "DES40", "NULL", "EXPORT", "anon", "_MD5",
	"TLS_SHA256_SHA256", "TLS_SHA384_SHA384",
}

// Signaling holds pseudo-cipher suite SCSV values.
var Signaling = map[uint16]bool{0x00FF: true, 0x5600: true}

// TLS13Suites holds the RFC 8446 / RFC 9150 TLS 1.3 cipher suite codes.
var TLS13Suites = map[uint16]bool{
	0x1301: true, 0x1302: true, 0x1303: true, 0x1304: true,
	0x1305: true, 0xC0B4: true, 0xC0B5: true,
}

// Groups maps TLS named group / curve IDs to canonical names.
var Groups = map[uint16]string{
	0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
	0x001D: "x25519", 0x001E: "x448",
	0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
	0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768",
	0x6399: "X25519Kyber768Draft00", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
}

// HRRRandom is the special SHA-256("HelloRetryRequest") ServerHello random value (RFC 8446).
var HRRRandom = mustDecodeHex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// IsHRRRandom reports whether a ServerHello 32-byte random matches HelloRetryRequest.
func IsHRRRandom(random []byte) bool {
	return bytes.Equal(random, HRRRandom)
}

// IsGrease reports whether a TLS extension/suite/group code is an RFC 8701 GREASE value.
func IsGrease(value uint16) bool {
	return (value&0x0F0F) == 0x0A0A && (value>>8) == (value&0xFF)
}

// SuiteName returns the IANA/Wireshark name of cipher suite code, or "0xNNNN".
func SuiteName(code uint16) string {
	if name, ok := CipherSuites[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", code)
}

// SuiteIsWeak reports whether a cipher suite name contains a weak or broken primitive marker.
func SuiteIsWeak(name string) bool {
	for _, marker := range WeakMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// SuiteHasForwardSecrecy reports whether the named cipher suite guarantees forward secrecy.
func SuiteHasForwardSecrecy(name string) bool {
	return strings.HasPrefix(name, "TLS_ECDHE_") ||
		strings.HasPrefix(name, "TLS_DHE_") ||
		(strings.HasPrefix(name, "TLS_") && !strings.Contains(name, "_WITH_"))
}

// SuiteEncryption classifies a chosen TLS cipher suite into StateEncrypted, StateWeak,
// StateUnverified, or StateCleartext along with a human-readable explanation when non-encrypted.
func SuiteEncryption(code uint16) (EncState, string) {
	name := SuiteName(code)
	if Signaling[code] {
		return StateUnverified, name + " is a signalling value, not a cipher suite"
	}
	if name == "TLS_SHA256_SHA256" || name == "TLS_SHA384_SHA384" {
		return StateCleartext, name + " is an RFC 9150 integrity-only suite: records carry plaintext with an HMAC"
	}
	if name == "TLS_NULL_WITH_NULL_NULL" {
		return StateCleartext, name + ": no cipher and no MAC"
	}
	if strings.Contains(name, "NULL") {
		return StateCleartext, name + " has a NULL cipher: records carry plaintext with only a MAC"
	}
	if strings.Contains(name, "EXPORT") {
		return StateCleartext, name + " is an export suite (40 or 56 bit keys, broken in hours)"
	}
	if strings.Contains(name, "anon") {
		return StateCleartext, name + " has anonymous key exchange: the server is not authenticated, so anyone on the path can intercept and read the session"
	}
	if strings.HasPrefix(name, "0x") {
		return StateUnverified, "cipher suite " + name + " is not in S.O.N.I.C.'s table, so its cipher is not known"
	}
	if SuiteIsWeak(name) {
		return StateWeak, name + " uses a broken cipher or hash (RC4, DES, 3DES or MD5)"
	}
	return StateEncrypted, ""
}

// VersionIsWeak reports whether version is TLS 1.1 or older (RFC 8996 deprecated).
func VersionIsWeak(version string) bool {
	rank, ok := VersionRank[version]
	return ok && rank < VersionRank["TLS1.2"]
}

// NormalizeVersion normalizes strings like "TLSv1.3", "1.3", or "SSL3" to "TLS1.3"/"SSL3.0".
func NormalizeVersion(value string) (string, bool) {
	text := strings.TrimSpace(strings.ToUpper(value))
	text = strings.ReplaceAll(text, " ", "")
	text = strings.ReplaceAll(text, "V1", "1")
	if strings.HasPrefix(text, "1.") {
		text = "TLS" + text
	}
	if text == "SSL3" || text == "SSL3.0" || text == "SSLV3" {
		return "SSL3.0", true
	}
	_, ok := VersionRank[text]
	return text, ok
}

// NormalizeSuite resolves a hex string or suite name into its canonical table name if known.
func NormalizeSuite(value string) string {
	text := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(text), "0x") {
		if code, err := strconv.ParseUint(text[2:], 16, 16); err == nil {
			return SuiteName(uint16(code))
		}
		return text
	}
	upper := strings.ToUpper(text)
	for _, v := range CipherSuites {
		if strings.ToUpper(v) == upper {
			return v
		}
	}
	return text
}
