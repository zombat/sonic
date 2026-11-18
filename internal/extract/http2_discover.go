// Package extract provides HTTP/2 connection types, port tables, and header classification.
package extract

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// HTTP2Preface is the cleartext HTTP/2 connection preface string.
var HTTP2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP2PrefaceFilter is the Wireshark byte-match filter literal for HTTP2Preface.
const HTTP2PrefaceFilter = "50:52:49:20:2a:20:48:54:54:50:2f:32:2e:30:0d:0a:0d:0a:53:4d:0d:0a:0d:0a"

// MinScrubLength skips redacting short header values under 4 characters to avoid false positives.
const MinScrubLength = 4

// GrpcPorts lists well-known gRPC / gNMI / p4runtime management ports.
var GrpcPorts = map[int]string{
	9339:  "gnmi-gnoi (IANA)",
	9340:  "gribi (IANA)",
	9559:  "p4runtime (IANA)",
	57400: "gnmi (Nokia SR Linux, Cisco IOS XR)",
	6030:  "gnmi (Arista EOS)",
	50001: "gnmi (Stratum)",
	50051: "grpc (common default; Cisco NX-OS gNMI)",
	50052: "gnmi insecure (Cisco IOS XE)",
	32767: "gnmi (Juniper Junos)",
}

// ShownHeaders lists safe HTTP/2 headers permitted in diagnostic reports.
var ShownHeaders = map[string]bool{
	":method": true, ":scheme": true, ":path": true, ":authority": true, ":status": true,
	"content-type": true, "te": true, "user-agent": true, "grpc-status": true,
	"grpc-message": true, "grpc-timeout": true, "grpc-encoding": true,
	"grpc-accept-encoding": true, "accept-encoding": true, "content-encoding": true,
	"grpc-message-type": true, "server": true, "date": true, "content-length": true,
	"grpc-previous-rpc-attempts": true, "grpc-retry-pushback-ms": true,
}

var (
	// CredentialNameRe identifies header names that carry credentials or bearer tokens.
	CredentialNameRe = regexp.MustCompile(`(?i)^(username|user|user-name|login|password|passwd|pass|pwd|authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|api_key|x-auth-token|auth-token|x-access-token|access-token|token|x-token|secret|client-secret|x-client-secret|x-amz-security-token)$|(password|passwd|secret|token|api-?key|credential|authorization)`)
	// IdentityNameRe identifies identity-only header names scrubbed only on standalone word tokens.
	IdentityNameRe = regexp.MustCompile(`(?i)^(username|user|user-name|login)$`)
)

// DiscoveryFields lists tshark fields read during HTTP/2 and TLS stream discovery.
var DiscoveryFields = []string{
	"frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
	"tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len", "frame.protocols",
	"tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
}

// Endpoint pairs a network address with a TCP port.
type Endpoint struct {
	IP   string
	Port int
}

// TCPReset records a TCP RST segment observed during discovery.
type TCPReset struct {
	Frame int
	T     float64
	From  Endpoint
}

// TCPConnection summarizes TCP role, TLS ClientHello/ServerHello, SNI, ALPN, and HTTP/2 preface metadata.
type TCPConnection struct {
	Index             int
	A                 Endpoint
	B                 Endpoint
	Client            *Endpoint
	Server            *Endpoint
	ServerKnownBy     string
	FirstFrame        int
	FirstT            float64
	LastT             float64
	PrefaceFrame      *int
	PrefaceFrom       *Endpoint
	TLSClientHello    *int
	TLSServerHello    *int
	SNI               *string
	ALPN              []string
	Resets            []TCPReset
	FirstPayloadTLS   *bool
	FirstPayloadFrame *int
	SynFrame          *int
}

// HeaderKind classifies an HTTP header name as "shown", "credential", or "masked".
func HeaderKind(name string) string {
	lower := strings.ToLower(name)
	if ShownHeaders[lower] {
		return "shown"
	}
	if CredentialNameRe.MatchString(lower) {
		return "credential"
	}
	return "masked"
}

// SetServer assigns client/server endpoints on c using Python's evidence-strength precedence.
func (c *TCPConnection) SetServer(srv Endpoint, how string) {
	rank := map[string]int{"syn": 4, "syn-ack": 3, "preface": 2, "client_hello": 2, "port": 1}
	if c.ServerKnownBy != "" && rank[c.ServerKnownBy] >= rank[how] {
		return
	}
	sCopy := srv
	cli := c.A
	if srv == c.A {
		cli = c.B
	}
	c.Server = &sCopy
	c.Client = &cli
	c.ServerKnownBy = how
}

// ServicePort returns the best-known TCP server port for c.
func (c *TCPConnection) ServicePort() int {
	if c.Server != nil {
		return c.Server.Port
	}
	for _, end := range []Endpoint{c.A, c.B} {
		if _, ok := GrpcPorts[end.Port]; ok {
			return end.Port
		}
	}
	return min(c.A.Port, c.B.Port)
}

// IsTLS reports whether TLS handshakes or TLS record layers were observed on c.
func (c *TCPConnection) IsTLS() bool {
	return c.TLSClientHello != nil || c.TLSServerHello != nil || (c.FirstPayloadTLS != nil && *c.FirstPayloadTLS)
}

// CarriesHTTP2 reports whether c should be decoded by the HTTP/2 PDML pass.
func (c *TCPConnection) CarriesHTTP2(extraPorts ...int) bool {
	port := c.ServicePort()
	_, isGrpc := GrpcPorts[port]
	return c.PrefaceFrame != nil ||
		(c.IsTLS() && (slices.Contains(c.ALPN, "h2") || isGrpc)) ||
		(isGrpc && c.FirstPayloadFrame != nil) ||
		slices.Contains(extraPorts, port)
}

// DiscoveryFilter returns the narrow display filter used during Pass 1 TCP/TLS/HTTP2 discovery.
func DiscoveryFilter(extraPorts []int) string {
	portSet := make(map[int]bool, len(GrpcPorts)+len(extraPorts))
	for p := range GrpcPorts {
		portSet[p] = true
	}
	for _, p := range extraPorts {
		portSet[p] = true
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	slices.Sort(ports)
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	return fmt.Sprintf("tcp.flags.syn==1 || tcp.flags.reset==1 || tls.handshake.type==1 || tls.handshake.type==2 || (tcp.len>=24 && tcp.payload[0:24]==%s) || (tcp.port in {%s} && tcp.len>0)",
		HTTP2PrefaceFilter, strings.Join(portStrs, ", "))
}
