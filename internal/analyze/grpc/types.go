// Package grpc defines top-level configuration and connection/report JSON structs for gRPC inspection.
package grpc

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/model"
)

// Options configures TLS decryption, .proto paths, extra ports, and output caps for AnalyzeCapture.
type Options struct {
	KeylogFile            string
	ProtoPaths            []string
	Ports                 []int
	DisplayFilter         string
	MaxPackets            *int
	MaxItems              int
	IncludeTLS            *bool
	IgnoreDefaultProtoDir bool
}

// TLSSecretsSummary reports secret sources and counts without revealing secret material.
type TLSSecretsSummary struct {
	Source                        *string `json:"source"`
	KeyLogFile                    bool    `json:"key_log_file"`
	PCAPNGDecryptionSecretsBlocks int     `json:"pcapng_decryption_secrets_blocks"`
	SessionsInKeyLog              int     `json:"sessions_in_key_log"`
	SessionsInPCAPNG              int     `json:"sessions_in_pcapng"`
}

// RereadRow records streams re-parsed without TCP out-of-order reassembly.
type RereadRow struct {
	TCPStream          int     `json:"tcp_stream"`
	HTTP2PacketsBefore int     `json:"http2_packets_before"`
	HTTP2PacketsAfter  int     `json:"http2_packets_after"`
	Flow               *string `json:"flow,omitempty"`
}

// CaptureInfo summarizes capture window bounds, decode-as hints, and warnings.
type CaptureInfo struct {
	Start                   *string           `json:"start"`
	End                     *string           `json:"end"`
	HTTP2Packets            int               `json:"http2_packets"`
	TShark                  *string           `json:"tshark"`
	DecodeAs                []string          `json:"decode_as"`
	DecodeAsReasons         map[string]string `json:"decode_as_reasons"`
	KeylogFileGiven         bool              `json:"keylog_file_given"`
	TLSSecrets              TLSSecretsSummary `json:"tls_secrets"`
	RereadWithoutOutOfOrder []RereadRow       `json:"reread_without_out_of_order"`
	ProtoPaths              []string          `json:"proto_paths"`
	DisplayFilter           *string           `json:"display_filter"`
	MaxPackets              *int              `json:"max_packets"`
	Warnings                []string          `json:"warnings"`
}

// Summary provides aggregate connection, RPC status, and credential metrics.
type Summary struct {
	Connections          int            `json:"connections"`
	RPCs                 int            `json:"rpcs"`
	RPCStatus            map[string]int `json:"rpc_status"`
	CleartextCredentials int            `json:"cleartext_credentials"`
}

// TLSView attaches handshake, certificate, alert, and troubleshooting hints to a TLS connection.
type TLSView struct {
	SNI               *string                     `json:"sni"`
	ALPNOffered       []string                    `json:"alpn_offered"`
	Decrypted         bool                        `json:"decrypted"`
	Version           *string                     `json:"version"`
	CipherSuite       *string                     `json:"cipher_suite"`
	ALPNChosen        *string                     `json:"alpn_chosen"`
	Certificate       *tlsinspect.CertificateInfo `json:"certificate"`
	Alerts            []tlsinspect.AlertRecord    `json:"alerts"`
	HelloRetryRequest *bool                       `json:"hello_retry_request"`
	Hints             []tlsinspect.HintRecord     `json:"hints"`
	hasSession        bool
}

// MarshalJSON matches Python _tls_view exact field presence based on whether a TLS session matched.
func (v TLSView) MarshalJSON() ([]byte, error) {
	if !v.hasSession {
		return json.Marshal(struct {
			SNI         *string                 `json:"sni"`
			ALPNOffered []string                `json:"alpn_offered"`
			Decrypted   bool                    `json:"decrypted"`
			Hints       []tlsinspect.HintRecord `json:"hints"`
		}{
			SNI:         v.SNI,
			ALPNOffered: v.ALPNOffered,
			Decrypted:   v.Decrypted,
			Hints:       v.Hints,
		})
	}
	type fullTLS TLSView
	return json.Marshal(fullTLS(v))
}

// ConnectionRow summarizes one discovered HTTP/2/gRPC or TLS connection.
type ConnectionRow struct {
	Flow                     string                     `json:"flow"`
	Client                   *string                    `json:"client"`
	Server                   *string                    `json:"server"`
	Service                  *string                    `json:"service"`
	ServiceName              *string                    `json:"service_name"`
	ServerKnownBy            string                     `json:"server_known_by"`
	Transport                string                     `json:"transport"`
	DetectedBy               *string                    `json:"detected_by"`
	Protocol                 string                     `json:"protocol"`
	Services                 []string                   `json:"services"`
	FirstFrame               *int                       `json:"first_frame"`
	T                        *float64                   `json:"t"`
	DurationS                *float64                   `json:"duration_s"`
	RPCs                     int                        `json:"rpcs"`
	RPCStatus                map[string]int             `json:"rpc_status"`
	FramesByType             map[string]int             `json:"frames_by_type"`
	Settings                 map[string]map[string]*int `json:"settings"`
	MaxConcurrentStreamsUsed int                        `json:"max_concurrent_streams_used"`
	Pings                    map[string]PingStats       `json:"pings"`
	Goaways                  []GoawayRow                `json:"goaways"`
	RstStreams               []ResetInfo                `json:"rst_streams"`
	FlowControl              FlowControlInfo            `json:"flow_control"`
	OversizeFrames           []OversizeFrameRow         `json:"oversize_frames"`
	OversizeHeaderLists      []OversizeHeaderRow        `json:"oversize_header_lists"`
	TCPResets                []TCPResetRow              `json:"tcp_resets"`
	CredentialKeys           []string                   `json:"credential_keys"`
	MetadataKeys             []string                   `json:"metadata_keys"`
	Capabilities             *DecodedResponse           `json:"capabilities,omitempty"`
	TLS                      *TLSView                   `json:"tls,omitempty"`
}

// Report is the top-level gRPC inspection JSON document or error payload.
type Report struct {
	Status             string                `json:"status"`
	Error              string                `json:"error,omitempty"`
	Schema             string                `json:"schema"`
	File               string                `json:"file"`
	OverallStatus      model.Status          `json:"overall_status"`
	Verdict            string                `json:"verdict"`
	Capture            CaptureInfo           `json:"capture"`
	Summary            Summary               `json:"summary"`
	Connections        []ConnectionRow       `json:"connections"`
	ConnectionsOmitted int                   `json:"connections_omitted"`
	RPCs               []RPCRow              `json:"rpcs"`
	RPCsOmitted        int                   `json:"rpcs_omitted"`
	Credentials        []CredentialFinding   `json:"credentials"`
	TLSDecryption      *TLSDecryptionSummary `json:"tls_decryption"`
	Issues             []model.Issue         `json:"issues"`
	Timeline           []model.Event         `json:"timeline"`
	TimelineOmitted    int                   `json:"timeline_omitted"`
	Limits             []string              `json:"limits"`
}

// MarshalJSON encodes {"status":"error","error":...} on error or the full report on success.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		type errPayload struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		return json.Marshal(errPayload{Status: r.Status, Error: r.Error})
	}
	type fullReport Report
	return json.Marshal(fullReport(r))
}
