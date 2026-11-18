// Package extract parses individual HTTP/1.x tshark field rows and hex/text bodies.
package extract

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

var (
	escCRLFRe = regexp.MustCompile(`\\r\\n,?`)
	hexRe     = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// firstHTTPVal returns the first occurrence from a FIELD_SEP-joined HTTP field value.
func firstHTTPVal(row map[string]string, name string) string {
	raw := row[name]
	if idx := strings.Index(raw, HTTPFieldSep); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

// maskHTTPSecret adds val (and any bearer/basic token suffix) to the in-memory scrub set.
func maskHTTPSecret(secrets map[string]bool, val string) {
	if len(val) < 4 {
		return
	}
	secrets[val] = true
	if sp := strings.IndexAny(val, " \t"); sp >= 0 {
		if rest := strings.TrimSpace(val[sp+1:]); rest != "" {
			secrets[rest] = true
		}
	}
}

// parseHTTP1Row decodes one HTTP/1.x frame row into an HTTPMessage while masking credential headers.
func parseHTTP1Row(row map[string]string, secrets map[string]bool) *HTTPMessage {
	streamIdx, ok := parseFieldInt(firstHTTPVal(row, "tcp.stream"))
	if !ok {
		return nil
	}
	methodStr := firstHTTPVal(row, "http.request.method")
	code, hasCode := parseFieldInt(firstHTTPVal(row, "http.response.code"))
	if methodStr == "" && !hasCode {
		return nil
	}
	src := firstHTTPVal(row, "ip.src")
	if src == "" {
		src = firstHTTPVal(row, "ipv6.src")
	}
	dst := firstHTTPVal(row, "ip.dst")
	if dst == "" {
		dst = firstHTTPVal(row, "ipv6.dst")
	}
	var sportPtr, dportPtr *int
	if v, ok := parseFieldInt(firstHTTPVal(row, "tcp.srcport")); ok {
		sportPtr = &v
	}
	if v, ok := parseFieldInt(firstHTTPVal(row, "tcp.dstport")); ok {
		dportPtr = &v
	}

	rawLines := row["http.request.line"]
	if rawLines == "" {
		rawLines = row["http.response.line"]
	}
	var creds []HTTPCredentialFlag
	var splitLines []string
	if strings.Contains(rawLines, HTTPFieldSep) {
		splitLines = strings.Split(rawLines, HTTPFieldSep)
	} else if rawLines != "" {
		splitLines = escCRLFRe.Split(rawLines, -1)
	}
	for _, ln := range splitLines {
		ln = strings.TrimSuffix(strings.TrimRight(ln, "\r\n"), `\r\n`)
		colon := strings.IndexByte(ln, ':')
		if colon < 0 {
			continue
		}
		hName := strings.TrimSpace(ln[:colon])
		hVal := strings.TrimSpace(ln[colon+1:])
		low := strings.ToLower(hName)
		switch low {
		case "authorization", "proxy-authorization", "cookie", "set-cookie", "host", "content-type", "accept", "content-length", "user-agent", "location", "www-authenticate":
			continue
		}
		if CredentialNameRe.MatchString(low) {
			maskHTTPSecret(secrets, hVal)
			creds = append(creds, HTTPCredentialFlag{Header: hName, Kind: "token", Value: "masked"})
		}
	}

	auth := firstHTTPVal(row, "http.authorization")
	if auth == "" {
		auth = firstHTTPVal(row, "http.proxy_authorization")
	}
	cookie := row["http.cookie"] != "" || row["http.set_cookie"] != ""
	if auth != "" {
		maskHTTPSecret(secrets, auth)
	}
	for _, field := range []string{row["http.cookie"], row["http.set_cookie"]} {
		for _, v := range strings.Split(field, HTTPFieldSep) {
			maskHTTPSecret(secrets, v)
		}
	}

	body := decodeHTTPFileData(firstHTTPVal(row, "http.file_data"))
	if len(body) > MaxBodyKeep {
		body = body[:MaxBodyKeep]
	}
	var respBody []byte
	if methodStr == "" {
		respBody = body
	}
	ver := firstHTTPVal(row, "http.request.version")
	if ver == "" {
		ver = firstHTTPVal(row, "http.response.version")
	}
	if ver == "" {
		ver = "HTTP/1.1"
	}
	ver = strings.TrimPrefix(ver, "HTTP/")

	frame, _ := parseFieldInt(row["frame.number"])
	tVal, _ := strconv.ParseFloat(row["frame.time_epoch"], 64)

	strOrNil := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	var statusPtr, reqFramePtr *int
	if hasCode {
		statusPtr = &code
	}
	if rf, ok := parseFieldInt(firstHTTPVal(row, "http.request_in")); ok {
		reqFramePtr = &rf
	}
	var timingPtr *float64
	if ts := firstHTTPVal(row, "http.time"); ts != "" {
		if fv, ferr := strconv.ParseFloat(ts, 64); ferr == nil {
			timingPtr = &fv
		}
	}
	var schemePtr *string
	if auth != "" {
		fields := strings.Fields(auth)
		s := "credentials"
		if len(fields) > 0 {
			s = fields[0]
		}
		schemePtr = &s
	}

	return &HTTPMessage{
		HTTPVersion: ver, TCPStream: streamIdx, Src: src, Dst: dst, Sport: sportPtr, Dport: dportPtr,
		Frame: frame, T: tVal, IsRequest: methodStr != "",
		Method: strOrNil(methodStr), URI: strOrNil(firstHTTPVal(row, "http.request.uri")),
		Host: strOrNil(firstHTTPVal(row, "http.host")), Status: statusPtr,
		Phrase:           strOrNil(firstHTTPVal(row, "http.response.phrase")),
		ContentType:      strOrNil(firstHTTPVal(row, "http.content_type")),
		Location:         strOrNil(firstHTTPVal(row, "http.location")),
		TimeSinceRequest: timingPtr, RequestFrame: reqFramePtr,
		BodyLen: len(body), Body: respBody, Credentials: creds,
		HasAuth: auth != "", AuthScheme: schemePtr, HasCookie: cookie,
	}
}

// decodeHTTPFileData decodes tshark's http.file_data colon-hex bytes or UTF-8 text payload.
func decodeHTTPFileData(raw string) []byte {
	if raw == "" {
		return nil
	}
	compact := strings.ReplaceAll(raw, ":", "")
	if compact != "" && len(compact)%2 == 0 && hexRe.MatchString(compact) {
		if b, err := hex.DecodeString(compact); err == nil {
			return b
		}
	}
	return []byte(raw)
}
