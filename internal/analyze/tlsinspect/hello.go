// Package tlsinspect parses TLS ClientHello and ServerHello handshake messages.
package tlsinspect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ClientHello holds decoded extensions and offered ciphers from a TLS ClientHello body.
type ClientHello struct {
	SNI            *string
	LegacyVersion  string
	Versions       []string
	CipherSuites   []string
	ALPN           []string
	Groups         []string
	KeyShareGroups []string
	ECHOffered     bool
	Extensions     int
}

// ServerHello holds the selected parameters from a TLS ServerHello body.
type ServerHello struct {
	Version           string
	CipherSuite       string
	ALPN              *string
	KeyShareGroup     *string
	HelloRetryRequest bool
}

// ServerHelloSuite extracts only the chosen 16-bit cipher suite code from a ServerHello body.
func ServerHelloSuite(body []byte) (uint16, bool) {
	if len(body) <= 34 {
		return 0, false
	}
	pos := 35 + int(body[34])
	if pos+2 > len(body) {
		return 0, false
	}
	return binary.BigEndian.Uint16(body[pos : pos+2]), true
}

// ParseClientHello decodes a TLS ClientHello handshake body, returning nil when truncated.
func ParseClientHello(body []byte) *ClientHello {
	if len(body) <= 34 {
		return nil
	}
	legacy := binary.BigEndian.Uint16(body[0:2])
	pos := 35 + int(body[34])
	if pos+2 > len(body) {
		return nil
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+csLen > len(body) {
		return nil
	}
	var suites []uint16
	for i := 0; i < csLen; i += 2 {
		if i+2 > csLen {
			return nil
		}
		suites = append(suites, binary.BigEndian.Uint16(body[pos+i:pos+i+2]))
	}
	pos += csLen
	if pos >= len(body) {
		return nil
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos > len(body) {
		return nil
	}

	var exts map[uint16][]byte
	if pos+2 <= len(body) {
		extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		extEnd := min(pos+2+extLen, len(body))
		exts = parseExtensions(body[pos+2 : extEnd])
	} else {
		exts = map[uint16][]byte{}
	}

	var sni *string
	if ext0, ok := exts[0]; ok && len(ext0) >= 5 && ext0[2] == 0 {
		nameLen := int(binary.BigEndian.Uint16(ext0[3:5]))
		end := min(5+nameLen, len(ext0))
		s := decodeASCIIReplace(ext0[5:end])
		sni = &s
	}

	var rawVersions []uint16
	if ext43, ok := exts[43]; ok && len(ext43) > 0 {
		end := min(1+int(ext43[0]), len(ext43))
		raw := ext43[1:end]
		for i := 0; i < len(raw)-1; i += 2 {
			rawVersions = append(rawVersions, binary.BigEndian.Uint16(raw[i:i+2]))
		}
	}
	var versionCodes []uint16
	for _, v := range rawVersions {
		if !IsGrease(v) {
			versionCodes = append(versionCodes, v)
		}
	}
	if len(versionCodes) == 0 {
		versionCodes = []uint16{legacy}
	}

	var groupsRaw []uint16
	if ext10, ok := exts[10]; ok && len(ext10) >= 2 {
		listLen := int(binary.BigEndian.Uint16(ext10[0:2]))
		for i := 0; i < listLen; i += 2 {
			if 2+i+2 <= len(ext10) {
				groupsRaw = append(groupsRaw, binary.BigEndian.Uint16(ext10[2+i:2+i+2]))
			}
		}
	}

	var sharesRaw []uint16
	if ext51, ok := exts[51]; ok && len(ext51) >= 2 {
		p := 2
		for p+4 <= len(ext51) {
			grp := binary.BigEndian.Uint16(ext51[p : p+2])
			klen := int(binary.BigEndian.Uint16(ext51[p+2 : p+4]))
			sharesRaw = append(sharesRaw, grp)
			p += 4 + klen
		}
	}

	versionsOut := make([]string, 0, len(versionCodes))
	for _, v := range versionCodes {
		versionsOut = append(versionsOut, versionLabel(v))
	}
	suitesOut := make([]string, 0, len(suites))
	for _, s := range suites {
		if !IsGrease(s) {
			suitesOut = append(suitesOut, SuiteName(s))
		}
	}
	alpnOut := []string{}
	if ext16, ok := exts[16]; ok {
		alpnOut = parseALPNList(ext16)
	}
	groupsOut := make([]string, 0, len(groupsRaw))
	for _, g := range groupsRaw {
		if !IsGrease(g) {
			groupsOut = append(groupsOut, groupLabel(g))
		}
	}
	sharesOut := make([]string, 0, len(sharesRaw))
	for _, g := range sharesRaw {
		if !IsGrease(g) {
			sharesOut = append(sharesOut, groupLabel(g))
		}
	}
	_, echOffered := exts[0xFE0D]

	return &ClientHello{
		SNI:            sni,
		LegacyVersion:  versionLabel(legacy),
		Versions:       versionsOut,
		CipherSuites:   suitesOut,
		ALPN:           alpnOut,
		Groups:         groupsOut,
		KeyShareGroups: sharesOut,
		ECHOffered:     echOffered,
		Extensions:     len(exts),
	}
}

// ParseServerHello decodes a TLS ServerHello handshake body, returning nil when truncated.
func ParseServerHello(body []byte) *ServerHello {
	if len(body) <= 34 {
		return nil
	}
	legacy := binary.BigEndian.Uint16(body[0:2])
	random := body[2:34]
	pos := 35 + int(body[34])
	if pos+3 > len(body) {
		return nil
	}
	suite := binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 3

	var exts map[uint16][]byte
	if pos+2 <= len(body) {
		extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		extEnd := min(pos+2+extLen, len(body))
		exts = parseExtensions(body[pos+2 : extEnd])
	} else {
		exts = map[uint16][]byte{}
	}

	version := legacy
	if ext43, ok := exts[43]; ok && len(ext43) >= 2 {
		version = binary.BigEndian.Uint16(ext43[0:2])
	}
	var alpnPtr *string
	if ext16, ok := exts[16]; ok {
		alpn := parseALPNList(ext16)
		if len(alpn) > 0 {
			alpnPtr = &alpn[0]
		}
	}
	var groupPtr *string
	if ext51, ok := exts[51]; ok && len(ext51) >= 2 {
		g := binary.BigEndian.Uint16(ext51[0:2])
		if g != 0 {
			label := groupLabel(g)
			groupPtr = &label
		}
	}

	return &ServerHello{
		Version:           versionLabel(version),
		CipherSuite:       SuiteName(suite),
		ALPN:              alpnPtr,
		KeyShareGroup:     groupPtr,
		HelloRetryRequest: IsHRRRandom(random),
	}
}

func versionLabel(code uint16) string {
	if name, ok := Versions[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", code)
}

func groupLabel(code uint16) string {
	if name, ok := Groups[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", code)
}

func parseExtensions(data []byte) map[uint16][]byte {
	out := make(map[uint16][]byte)
	pos := 0
	for pos+4 <= len(data) {
		etype := binary.BigEndian.Uint16(data[pos : pos+2])
		elen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if _, exists := out[etype]; !exists {
			end := min(pos+4+elen, len(data))
			out[etype] = data[pos+4 : end]
		}
		pos += 4 + elen
	}
	return out
}

func parseALPNList(body []byte) []string {
	out := []string{}
	if len(body) < 2 {
		return out
	}
	end := min(2+int(binary.BigEndian.Uint16(body[0:2])), len(body))
	pos := 2
	for pos < end {
		length := int(body[pos])
		if pos+1 > end {
			break
		}
		strEnd := min(pos+1+length, len(body))
		out = append(out, decodeASCIIReplace(body[pos+1:strEnd]))
		pos += 1 + length
	}
	return out
}

func decodeASCIIReplace(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c < 0x80 {
			sb.WriteByte(c)
		} else {
			sb.WriteRune('\ufffd')
		}
	}
	return sb.String()
}
