// Package extract handles HTTP/1.1 request/response tshark extraction,
// RESTCONF classification, and HTTP decode-as planning.
package extract

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

const (
	// HTTPFieldSep separates repeated field occurrences inside one HTTP/1.1 row.
	HTTPFieldSep = "\x1f"
	// MaxBodyKeep caps stored HTTP/1.x/HTTP/2 response body bytes at 64 KiB.
	MaxBodyKeep = 1 << 16
)

// HTTPPorts maps common HTTP/HTTPS/RESTCONF ports to service names.
var HTTPPorts = map[int]string{
	80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt",
	8008: "http-alt", 8888: "http-alt", 4443: "https-alt",
}

// RestconfTypes enumerates RFC 8040 media types identifying RESTCONF payloads.
var RestconfTypes = []string{
	"application/yang-data+json", "application/yang-data+xml",
	"application/yang.data+json", "application/yang.data+xml",
	"application/yang-patch+json", "application/yang-patch+xml",
	"application/yang.patch+json", "application/yang.patch+xml",
	"application/yang.api+json", "application/yang.api+xml",
	"application/yang-errors+json", "application/yang-errors+xml",
}

// HTTP1Fields lists tshark fields read by HTTP1Messages.
var HTTP1Fields = []string{
	"frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
	"tcp.srcport", "tcp.dstport",
	"http.request.method", "http.request.uri", "http.request.version", "http.host",
	"http.response.code", "http.response.phrase", "http.response.version",
	"http.content_type", "http.location", "http.time", "http.request_in", "http.response_in",
	"http.authorization", "http.proxy_authorization", "http.www_authenticate", "http.cookie", "http.set_cookie",
	"http.request.line", "http.response.line", "http.content_length_header", "http.file_data",
}

// HTTPCredentialFlag notes a credential-bearing HTTP header with its secret value omitted.
type HTTPCredentialFlag struct {
	Header string  `json:"header"`
	Kind   string  `json:"kind"`
	Scheme *string `json:"scheme,omitempty"`
	Value  string  `json:"value"`
}

// MarshalJSON always writes "scheme" for authorization headers and omits it when unset otherwise.
func (f HTTPCredentialFlag) MarshalJSON() ([]byte, error) {
	if f.Kind == "authorization" || f.Scheme != nil {
		type withScheme struct {
			Header string  `json:"header"`
			Kind   string  `json:"kind"`
			Scheme *string `json:"scheme"`
			Value  string  `json:"value"`
		}
		return json.Marshal(withScheme(f))
	}
	type withoutScheme struct {
		Header string `json:"header"`
		Kind   string `json:"kind"`
		Value  string `json:"value"`
	}
	return json.Marshal(withoutScheme{
		Header: f.Header,
		Kind:   f.Kind,
		Value:  f.Value,
	})
}

// HTTPMessage holds normalized HTTP/1.1 or assembled HTTP/2 request/response metadata.
type HTTPMessage struct {
	HTTPVersion      string
	TCPStream        int
	StreamID         *int
	Src              string
	Dst              string
	Sport            *int
	Dport            *int
	Frame            int
	T                float64
	IsRequest        bool
	Method           *string
	URI              *string
	Host             *string
	Status           *int
	Phrase           *string
	ContentType      *string
	Location         *string
	TimeSinceRequest *float64
	RequestFrame     *int
	BodyLen          int
	Body             []byte
	Credentials      []HTTPCredentialFlag
	HasAuth          bool
	AuthScheme       *string
	HasCookie        bool
}

// IsRestconf reports whether an HTTP exchange looks like RESTCONF from its URI path or media types.
func IsRestconf(path string, contentTypes ...string) bool {
	if path != "" && (strings.Contains(path, "/restconf") || strings.Contains(path, "/.well-known/host-meta")) {
		return true
	}
	for _, ct := range contentTypes {
		low := strings.ToLower(ct)
		if low == "" {
			continue
		}
		for _, prefix := range RestconfTypes {
			if strings.HasPrefix(low, prefix) {
				return true
			}
		}
	}
	return false
}

// PlanHTTPDecodeAs returns tshark -d flags and rationale strings for HTTP/1.1 and HTTP/2 decoding.
func PlanHTTPDecodeAs(conns map[int]*TCPConnection, extraPorts []int) ([]string, map[int]string) {
	want := make(map[int]bool, len(HTTPPorts)+len(GrpcPorts)+len(extraPorts))
	plain := make(map[int]bool, len(HTTPPorts)+len(extraPorts))
	for p := range HTTPPorts {
		want[p] = true
		plain[p] = true
	}
	for p := range GrpcPorts {
		want[p] = true
	}
	for _, p := range extraPorts {
		want[p] = true
		plain[p] = true
	}

	sorted := make([]*TCPConnection, 0, len(conns))
	for _, c := range conns {
		sorted = append(sorted, c)
	}
	slices.SortStableFunc(sorted, func(a, b *TCPConnection) int {
		return cmp.Compare(a.FirstFrame, b.FirstFrame)
	})

	reasons := make(map[int]string)
	for _, c := range sorted {
		port := c.ServicePort()
		hasH2Or11 := slices.Contains(c.ALPN, "h2") || slices.Contains(c.ALPN, "http/1.1")
		if c.IsTLS() && (want[port] || hasH2Or11) {
			if _, ok := reasons[port]; !ok {
				reasons[port] = "tls_http"
			}
		} else if !c.IsTLS() && c.PrefaceFrame != nil {
			if _, ok := reasons[port]; !ok {
				reasons[port] = "h2c"
			}
		} else if !c.IsTLS() && plain[port] {
			if _, ok := reasons[port]; !ok {
				reasons[port] = "http_port"
			}
		}
	}

	decode := map[string]string{"tls_http": "tls", "h2c": "http2", "http_port": "http"}
	ports := make([]int, 0, len(reasons))
	for p := range reasons {
		ports = append(ports, p)
	}
	slices.Sort(ports)
	var opts []string
	for _, p := range ports {
		opts = append(opts, "-d", fmt.Sprintf("tcp.port==%d,%s", p, decode[reasons[p]]))
	}
	return opts, reasons
}

// HTTP1Messages extracts HTTP/1.x messages via tshark while masking credential headers at the source.
func HTTP1Messages(
	ctx context.Context,
	filePath string,
	decodeAs []string,
	keylogFile string,
	displayFilter string,
	maxPackets *int,
	outOfOrder bool,
) ([]HTTPMessage, map[string]bool, error) {
	flt := "http"
	if displayFilter != "" {
		flt = fmt.Sprintf("(%s) && http", displayFilter)
	}
	preArgs := make([]string, 0, len(decodeAs)+4)
	preArgs = append(preArgs, decodeAs...)
	if outOfOrder {
		preArgs = append(preArgs, "-o", "tcp.reassemble_out_of_order:TRUE")
	}
	if keylogFile != "" {
		preArgs = append(preArgs, "-o", "tls.keylog_file:"+keylogFile)
	}

	secrets := make(map[string]bool)
	var msgs []HTTPMessage
	_, err := streamTsharkFields(ctx, filePath, preArgs, flt, HTTP1Fields, HTTPFieldSep, maxPackets, nil, func(row map[string]string) error {
		if m := parseHTTP1Row(row, secrets); m != nil {
			msgs = append(msgs, *m)
		}
		return nil
	})
	return msgs, secrets, err
}
