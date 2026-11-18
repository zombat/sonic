// Package httpinspect implements HTTP/1.1, HTTP/2, RESTCONF, and TLS decryption reporting.
package httpinspect

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

// ReportSchema identifies the JSON output contract for HTTP/RESTCONF reports.
const ReportSchema = "sonic.http_report/1"

// Options controls capture filtering, secret decryption, and output item bounds.
type Options struct {
	KeylogFile    string
	Ports         []int
	DisplayFilter string
	MaxPackets    *int
	MaxItems      int
}

// TLSSecretsSummary records where TLS decryption secrets were found (never the secret values).
type TLSSecretsSummary struct {
	Source                        *string `json:"source"`
	KeyLogFile                    bool    `json:"key_log_file"`
	PCAPNGDecryptionSecretsBlocks int     `json:"pcapng_decryption_secrets_blocks"`
	SessionsInKeyLog              int     `json:"sessions_in_key_log"`
	SessionsInPCAPNG              int     `json:"sessions_in_pcapng"`
}

// CaptureInfo summarizes capture time span, tshark decoding hints, and secret availability.
type CaptureInfo struct {
	Start           *string           `json:"start"`
	End             *string           `json:"end"`
	HTTPMessages    int               `json:"http_messages"`
	HTTP2Packets    int               `json:"http2_packets"`
	TShark          *string           `json:"tshark"`
	DecodeAs        []string          `json:"decode_as"`
	DecodeAsReasons map[string]string `json:"decode_as_reasons"`
	KeylogFileGiven bool              `json:"keylog_file_given"`
	TLSSecrets      TLSSecretsSummary `json:"tls_secrets"`
	DisplayFilter   *string           `json:"display_filter"`
	MaxPackets      *int              `json:"max_packets"`
	Warnings        []string          `json:"warnings"`
}

// Summary provides aggregate connection, request, status, and credential metrics.
type Summary struct {
	Connections          int            `json:"connections"`
	Requests             int            `json:"requests"`
	RestconfRequests     int            `json:"restconf_requests"`
	StatusCounts         map[string]int `json:"status_counts"`
	RestconfErrors       int            `json:"restconf_errors"`
	CleartextCredentials int            `json:"cleartext_credentials"`
}

// ConnectionRow summarizes one TCP connection inspected for HTTP/1.1 or HTTP/2 traffic.
type ConnectionRow struct {
	Flow         string   `json:"flow"`
	Service      string   `json:"service"`
	ServiceName  *string  `json:"service_name"`
	Transport    string   `json:"transport"`
	HTTPVersions []string `json:"http_versions"`
	Requests     int      `json:"requests"`
	Restconf     *bool    `json:"restconf"`
	SNI          *string  `json:"sni"`
	ALPNOffered  []string `json:"alpn_offered"`
	Decrypted    *bool    `json:"decrypted"`
}

// FramesRef records packet frame numbers for an HTTP request and its paired response.
type FramesRef struct {
	Request  *int `json:"request"`
	Response *int `json:"response"`
}

// RequestRow captures metadata and sanitized credentials for one HTTP request/response pair.
type RequestRow struct {
	Flow                string                       `json:"flow"`
	Service             string                       `json:"service"`
	Transport           string                       `json:"transport"`
	HTTPVersion         *string                      `json:"http_version"`
	StreamID            *int                         `json:"stream_id"`
	Method              *string                      `json:"method"`
	Path                *string                      `json:"path"`
	Host                *string                      `json:"host"`
	Status              *int                         `json:"status"`
	Phrase              *string                      `json:"phrase"`
	RequestContentType  *string                      `json:"request_content_type"`
	ResponseContentType *string                      `json:"response_content_type"`
	RequestBodyBytes    int                          `json:"request_body_bytes"`
	ResponseBodyBytes   int                          `json:"response_body_bytes"`
	TimingMS            *float64                     `json:"timing_ms"`
	Location            *string                      `json:"location"`
	Restconf            bool                         `json:"restconf"`
	RestconfErrors      []map[string]string          `json:"restconf_errors"`
	Credentials         []extract.HTTPCredentialFlag `json:"credentials"`
	Frames              FramesRef                    `json:"frames"`
	T                   *float64                     `json:"t"`
	Outcome             string                       `json:"outcome"`
}

// CredentialRow aggregates usage of one masked credential header across a TCP flow.
type CredentialRow struct {
	Flow      string  `json:"flow"`
	Service   string  `json:"service"`
	Header    string  `json:"header"`
	Kind      string  `json:"kind"`
	Scheme    *string `json:"scheme"`
	Cleartext bool    `json:"cleartext"`
	Requests  int     `json:"requests"`
	Frames    []int   `json:"frames"`
	Value     string  `json:"value"`
}

// TLSSessionRow explains whether a TLS session decrypted and why if it did not.
type TLSSessionRow struct {
	Flow             string   `json:"flow"`
	Service          string   `json:"service"`
	TCPStream        int      `json:"tcp_stream"`
	ClientHelloFrame *int     `json:"client_hello_frame"`
	Decrypted        bool     `json:"decrypted"`
	ApplicationData  []string `json:"application_data"`
	SecretIn         []string `json:"secret_in"`
	Labels           []string `json:"labels"`
	Reason           *string  `json:"reason"`
}

// TLSDecryptionSummary summarizes per-session TLS decryption outcomes across the capture.
type TLSDecryptionSummary struct {
	Verdict         string          `json:"verdict"`
	Decrypted       int             `json:"decrypted"`
	Total           int             `json:"total"`
	SecretsSource   *string         `json:"secrets_source"`
	Sessions        []TLSSessionRow `json:"sessions"`
	SessionsOmitted int             `json:"sessions_omitted"`
}

// Report represents the complete HTTP/RESTCONF inspection output or an error payload.
type Report struct {
	Status          string                `json:"status"`
	Error           string                `json:"error,omitempty"`
	Schema          string                `json:"schema"`
	File            string                `json:"file"`
	OverallStatus   model.Status          `json:"overall_status"`
	Verdict         string                `json:"verdict"`
	Capture         CaptureInfo           `json:"capture"`
	Summary         Summary               `json:"summary"`
	Connections     []ConnectionRow       `json:"connections"`
	Requests        []RequestRow          `json:"requests"`
	RequestsOmitted int                   `json:"requests_omitted"`
	Credentials     []CredentialRow       `json:"credentials"`
	TLSDecryption   *TLSDecryptionSummary `json:"tls_decryption"`
	Issues          []model.Issue         `json:"issues"`
	Limits          []string              `json:"limits"`
}

// MarshalJSON emits {"status":"error","error":...} on errors or the full report on success.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		type errPayload struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		return json.Marshal(errPayload{Status: r.Status, Error: r.Error})
	}
	type successReport Report
	return json.Marshal(successReport(r))
}
