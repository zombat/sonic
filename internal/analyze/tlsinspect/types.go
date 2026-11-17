// Package tlsinspect implements TLS handshake reassembly, X.509 certificate
// inspection, and baseline verification matching analyzers/tls_inspect.py.
package tlsinspect

import (
	"fmt"

	"github.com/zombat/sonic/internal/model"
)

const (
	maxStreamBytes     = 16384
	maxStreams         = 4000
	maxPendingSegments = 32
	maxRecordLen       = 18432
)

// Alerts maps TLS alert description byte codes to RFC alert names.
var Alerts = map[uint8]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	22:  "record_overflow",
	40:  "handshake_failure",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	49:  "access_denied",
	50:  "decode_error",
	51:  "decrypt_error",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	86:  "inappropriate_fallback",
	90:  "user_canceled",
	109: "missing_extension",
	110: "unsupported_extension",
	112: "unrecognized_name",
	116: "certificate_required",
	120: "no_application_protocol",
}

// AlertHintKey identifies a TLS alert explanation by alert description and sender role.
type AlertHintKey struct {
	Desc   string
	Sender string
}

// AlertHints maps (description, sender) pairs to operator-facing alert explanations.
var AlertHints = map[AlertHintKey]string{
	{Desc: "unknown_ca", Sender: "client"}:              "the client refused the server's certificate: it does not trust the CA that signed it (a self-signed or private-CA certificate); give the client that CA (for example gnmic --tls-ca), or in a lab only skip verification",
	{Desc: "bad_certificate", Sender: "client"}:         "the client refused the server's certificate: it failed the client's checks, often the name (the name or address the client dialled is not in the SANs; dialling an IP needs an IP SAN)",
	{Desc: "certificate_unknown", Sender: "client"}:     "the client refused the server's certificate for a reason it did not name (an untrusted CA or a name mismatch, most often)",
	{Desc: "certificate_expired", Sender: "client"}:     "the client refused the server's certificate: outside its validity period (or one of the clocks is wrong)",
	{Desc: "certificate_revoked", Sender: "client"}:     "the client refused the server's certificate: it is revoked",
	{Desc: "unsupported_certificate", Sender: "client"}: "the client refused the server's certificate: its key type or usage is not supported",
	{Desc: "bad_certificate", Sender: "server"}:         "the server refused the client's certificate (mutual TLS)",
	{Desc: "unknown_ca", Sender: "server"}:              "the server refused the client's certificate: it does not trust its CA (mutual TLS)",
	{Desc: "certificate_unknown", Sender: "server"}:     "the server refused the client's certificate (mutual TLS)",
	{Desc: "certificate_expired", Sender: "server"}:     "the server refused the client's certificate: expired (mutual TLS)",
	{Desc: "certificate_required", Sender: "server"}:    "the server requires a client certificate (mutual TLS) and the client sent none",
	{Desc: "handshake_failure", Sender: ""}:             "no cipher suite, version or group both sides accept, or a client certificate was required",
	{Desc: "protocol_version", Sender: ""}:              "no TLS version both sides support",
	{Desc: "no_application_protocol", Sender: ""}:       "the server offers none of the client's ALPN protocols (a gRPC client needs h2)",
	{Desc: "unrecognized_name", Sender: ""}:             "the server does not recognise the SNI name the client sent",
	{Desc: "decrypt_error", Sender: ""}:                 "a signature or key check failed (the private key does not match the certificate, or a corrupted handshake)",
	{Desc: "access_denied", Sender: ""}:                 "the peer refused the connection by policy",
	{Desc: "insufficient_security", Sender: ""}:         "the peer requires stronger parameters than were offered",
	{Desc: "illegal_parameter", Sender: ""}:             "a handshake field had a value the peer does not accept",
	{Desc: "internal_error", Sender: ""}:                "the peer hit an internal error",
}

// AlertHint returns an explanation for a TLS alert given who sent it ("client" or "server").
func AlertHint(description, sender string) *string {
	if msg, ok := AlertHints[AlertHintKey{Desc: description, Sender: sender}]; ok {
		return &msg
	}
	if msg, ok := AlertHints[AlertHintKey{Desc: description, Sender: ""}]; ok {
		return &msg
	}
	return nil
}

// Limits lists the analytical boundaries included in every TLS inspector report.
var Limits = []string{
	"Only the cleartext handshake is read. In TLS 1.3 everything after the ServerHello is encrypted: the certificate, the server's extensions and any later alert cannot be seen. In TLS 1.2 and older the certificate is visible and is read here.",
	"Certificate trust (chain to a trusted root, revocation) is not judged; only what the certificate says.",
	"In TLS 1.3 the server's ALPN choice travels in the encrypted EncryptedExtensions message, so server_chose.alpn is null and an ALPN baseline is checked only for TLS 1.2 and older.",
	"With Encrypted Client Hello the visible SNI is the outer, public name, not the real server name.",
	"A handshake split across segments is reassembled from the first bytes of each direction; one that starts before the capture, or whose segments were lost before the capture point, cannot be read.",
	"QUIC, DTLS and STARTTLS are not decoded.",
}

// Baseline holds optional TLS policy constraints checked against observed handshakes.
type Baseline struct {
	MinVersion            string   `json:"min_version,omitempty"`
	Versions              []string `json:"versions,omitempty"`
	CipherSuites          []string `json:"cipher_suites,omitempty"`
	RequireSNI            *bool    `json:"require_sni,omitempty"`
	ALPN                  []string `json:"alpn,omitempty"`
	RequireForwardSecrecy *bool    `json:"require_forward_secrecy,omitempty"`
	ForbidWeakOffers      *bool    `json:"forbid_weak_offers,omitempty"`
}

// active reports whether Baseline is non-nil and configures at least one constraint.
func (b *Baseline) active() bool {
	if b == nil {
		return false
	}
	return b.MinVersion != "" ||
		len(b.Versions) > 0 ||
		len(b.CipherSuites) > 0 ||
		b.RequireSNI != nil ||
		len(b.ALPN) > 0 ||
		b.RequireForwardSecrecy != nil ||
		b.ForbidWeakOffers != nil
}

// CertificateInfo represents visibility and parsed fields of a leaf X.509 certificate.
type CertificateInfo struct {
	Visible             bool      `json:"visible"`
	Reason              string    `json:"reason,omitempty"`
	ChainLength         *int      `json:"chain_length,omitempty"`
	Parsed              *bool     `json:"parsed,omitempty"`
	Note                string    `json:"note,omitempty"`
	Subject             *string   `json:"subject,omitempty"`
	Issuer              *string   `json:"issuer,omitempty"`
	SelfSigned          *bool     `json:"self_signed,omitempty"`
	NotBefore           *string   `json:"not_before,omitempty"`
	NotAfter            *string   `json:"not_after,omitempty"`
	ValidAtCaptureTime  *bool     `json:"valid_at_capture_time,omitempty"`
	DNSNames            *[]string `json:"dns_names,omitempty"`
	IPAddresses         *[]string `json:"ip_addresses,omitempty"`
	DecryptedWithKeyLog *bool     `json:"decrypted_with_key_log,omitempty"`
}

// AlertRecord describes a decoded or encrypted TLS Alert record observed on a session.
type AlertRecord struct {
	From        string  `json:"from"`
	Level       string  `json:"level"`
	Description string  `json:"description"`
	Frame       int     `json:"frame"`
	Sender      string  `json:"sender"`
	Hint        *string `json:"hint,omitempty"`
	t           float64
}

// HintRecord represents an operational hint derived from SNI and certificate SANs.
type HintRecord struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Text     string `json:"text"`
}

// Session summarizes one reassembled TLS client/server handshake and policy check.
type Session struct {
	Client            string          `json:"client"`
	Server            string          `json:"server"`
	SNI               *string         `json:"sni"`
	ClientOffered     *ClientHello    `json:"client_offered"`
	ServerChose       *ServerHello    `json:"server_chose"`
	HelloRetryRequest bool            `json:"hello_retry_request"`
	Certificate       CertificateInfo `json:"certificate"`
	Hints             []HintRecord    `json:"hints"`
	Alerts            []AlertRecord   `json:"alerts"`
	BaselinePass      *bool           `json:"baseline_pass"`
	Findings          []model.Issue   `json:"findings"`
	Frames            map[string]int  `json:"frames"`
	FirstT            *float64        `json:"first_t"`
}

// Summary holds session counts and baseline failure totals for the TLS report.
type Summary struct {
	Handshakes          int `json:"handshakes"`
	StreamsDroppedAtCap int `json:"streams_dropped_at_cap"`
	BaselineFailures    int `json:"baseline_failures"`
}

// Report is the top-level JSON report emitted by the TLS inspector.
type Report struct {
	Detector        string        `json:"detector"`
	Status          model.Status  `json:"status"`
	Verdict         string        `json:"verdict"`
	Baseline        *Baseline     `json:"baseline"`
	Summary         Summary       `json:"summary"`
	Sessions        []Session     `json:"sessions"`
	SessionsOmitted int           `json:"sessions_omitted"`
	Limits          []string      `json:"limits"`
	Issues          []model.Issue `json:"issues"`
	Events          []model.Event `json:"events"`
}

// addrEndpoint holds an IP/port pair used as a deterministic map key.
type addrEndpoint struct {
	addr    string
	port    int
	hasPort bool
}

// format renders addrEndpoint using model.Endpoint rules.
func (e addrEndpoint) format() string {
	if !e.hasPort {
		return e.addr
	}
	p := e.port
	return model.Endpoint(e.addr, &p)
}

// flowKey identifies a directional TCP flow.
type flowKey struct {
	src addrEndpoint
	dst addrEndpoint
}

// sessionKey identifies a TLS client -> server conversation pair.
type sessionKey struct {
	client addrEndpoint
	server addrEndpoint
}

// makeEndpoint converts an address string and optional port pointer into an addrEndpoint.
func makeEndpoint(addr string, port *int) addrEndpoint {
	if port == nil {
		return addrEndpoint{addr: addr}
	}
	return addrEndpoint{addr: addr, port: *port, hasPort: true}
}

// alertDescription formats a TLS alert byte code to its canonical name or numeric fallback.
func alertDescription(code uint8) string {
	if name, ok := Alerts[code]; ok {
		return name
	}
	return fmt.Sprintf("alert %d", code)
}
