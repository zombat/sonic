// Package grpc defines HTTP/2 framing, RPC row, credential, and TLS decryption report structs.
package grpc

import "github.com/zombat/sonic/internal/extract"

// PingStats summarizes client or server HTTP/2 PING counts, RTT, and intervals.
type PingStats struct {
	Sent            int      `json:"sent"`
	Acked           int      `json:"acked"`
	RTTMSMedian     *float64 `json:"rtt_ms_median"`
	IntervalSMin    *float64 `json:"interval_s_min"`
	IntervalSMedian *float64 `json:"interval_s_median"`
	FirstFrame      *int     `json:"first_frame"`
}

// GoawayRow captures an HTTP/2 GOAWAY frame event on a connection.
type GoawayRow struct {
	From         string  `json:"from"`
	LastStreamID *int    `json:"last_stream_id"`
	ErrorCode    *int    `json:"error_code"`
	Error        string  `json:"error"`
	DebugData    *string `json:"debug_data"`
	Frame        int     `json:"frame"`
	t            float64
}

// ResetInfo captures an HTTP/2 RST_STREAM frame event.
type ResetInfo struct {
	From      string  `json:"from"`
	StreamID  int     `json:"stream_id"`
	ErrorCode *int    `json:"error_code"`
	Error     string  `json:"error"`
	Frame     int     `json:"frame"`
	Method    *string `json:"method"`
	AfterEnd  *bool   `json:"after_end,omitempty"`
	t         float64
}

// StallRow describes a zero-window flow-control stall per direction and stream.
type StallRow struct {
	Sender        string   `json:"sender"`
	StreamID      int      `json:"stream_id"`
	Method        *string  `json:"method"`
	Window        string   `json:"window"`
	Frame         int      `json:"frame"`
	T             *float64 `json:"t"`
	DurationS     float64  `json:"duration_s"`
	ReopenedFrame *int     `json:"reopened_frame"`
	Resolved      bool     `json:"resolved"`
	EndedBy       *string  `json:"ended_by"`
	DataWaiting   bool     `json:"data_waiting"`
}

// FlowControlInfo holds whether flow windows were tracked and all observed stalls.
type FlowControlInfo struct {
	Followed bool       `json:"followed"`
	Stalls   []StallRow `json:"stalls"`
}

// OversizeFrameRow records an HTTP/2 frame exceeding peer SETTINGS_MAX_FRAME_SIZE.
type OversizeFrameRow struct {
	From             string `json:"from"`
	Type             string `json:"type"`
	Length           int    `json:"length"`
	PeerMaxFrameSize int    `json:"peer_max_frame_size"`
	Frame            int    `json:"frame"`
	StreamID         *int   `json:"stream_id"`
}

// OversizeHeaderRow records an HTTP/2 header block exceeding peer SETTINGS_MAX_HEADER_LIST_SIZE.
type OversizeHeaderRow struct {
	From           string `json:"from"`
	StreamID       int    `json:"stream_id"`
	Frame          int    `json:"frame"`
	HeaderListSize int    `json:"header_list_size"`
	PeerLimit      int    `json:"peer_limit"`
}

// TCPResetRow summarizes one TCP RST packet attributed to an endpoint.
type TCPResetRow struct {
	Frame int     `json:"frame"`
	From  *string `json:"from"`
}

// FramerSummary summarizes parsed gRPC length-prefixed messages in one direction.
type FramerSummary struct {
	Messages    int  `json:"messages"`
	Bytes       int  `json:"bytes"`
	Largest     *int `json:"largest"`
	Compressed  int  `json:"compressed"`
	FramingLost bool `json:"framing_lost"`
}

// TimingInfo captures millisecond elapsed timings relative to the RPC request frame.
type TimingInfo struct {
	ToFirstResponseMS *float64 `json:"to_first_response_ms,omitempty"`
	ToEndMS           *float64 `json:"to_end_ms,omitempty"`
}

// DecodedBlock holds decoded gNMI/gNOI/health request/response summaries for one RPC.
type DecodedBlock struct {
	Request             *DecodedRequest  `json:"request,omitempty"`
	Polls               int              `json:"polls,omitempty"`
	Response            *DecodedResponse `json:"response,omitempty"`
	ResponsesNotDecoded int              `json:"responses_not_decoded,omitempty"`
	DecodeErrors        []string         `json:"decode_errors,omitempty"`
}

// ProtobufView records one Wireshark-dissected protobuf message attached to an RPC.
type ProtobufView struct {
	Frame       int                     `json:"frame"`
	Direction   *string                 `json:"direction"`
	MessageType *string                 `json:"message_type"`
	Fields      []extract.ProtobufField `json:"fields"`
}

// RPCRow represents one diagnosed gRPC / HTTP/2 stream exchange.
type RPCRow struct {
	Flow               string         `json:"flow"`
	StreamID           int            `json:"stream_id"`
	Method             *string        `json:"method"`
	Family             *string        `json:"family"`
	Service            *string        `json:"service"`
	RPC                *string        `json:"rpc"`
	Authority          *string        `json:"authority"`
	ContentType        *string        `json:"content_type"`
	UserAgent          *string        `json:"user_agent"`
	GrpcTimeoutS       *float64       `json:"grpc_timeout_s"`
	GrpcEncoding       *string        `json:"grpc_encoding"`
	MetadataKeys       []string       `json:"metadata_keys"`
	Request            FramerSummary  `json:"request"`
	Response           FramerSummary  `json:"response"`
	HTTPStatus         *int           `json:"http_status"`
	GrpcStatus         *int           `json:"grpc_status"`
	GrpcStatusName     *string        `json:"grpc_status_name"`
	GrpcStatusFromHTTP bool           `json:"grpc_status_from_http"`
	GrpcMessage        *string        `json:"grpc_message"`
	TrailersOnly       bool           `json:"trailers_only"`
	Outcome            string         `json:"outcome"`
	Reset              *ResetInfo     `json:"reset"`
	ResetAfterEnd      bool           `json:"reset_after_end"`
	Timing             TimingInfo     `json:"timing"`
	T                  *float64       `json:"t"`
	Frames             map[string]int `json:"frames"`
	StateChanging      bool           `json:"state_changing"`
	Decoded            *DecodedBlock  `json:"decoded,omitempty"`
	WiresharkProtobuf  []ProtobufView `json:"wireshark_protobuf,omitempty"`
	HeadersDecoded     *bool          `json:"headers_decoded,omitempty"`
	Diagnosis          string         `json:"diagnosis"`
}

// CredentialFinding records a credential-bearing metadata key observed across a flow.
type CredentialFinding struct {
	Flow       string  `json:"flow"`
	Service    *string `json:"service"`
	Key        string  `json:"key"`
	Cleartext  bool    `json:"cleartext"`
	Transport  string  `json:"transport"`
	Requests   int     `json:"requests"`
	FirstFrame int     `json:"first_frame"`
	Frames     []int   `json:"frames"`
	Value      string  `json:"value"`
}

// TLSSessionRow summarizes per-session TLS decryption status and failure rationale.
type TLSSessionRow struct {
	Flow               string   `json:"flow"`
	Service            string   `json:"service"`
	TCPStream          int      `json:"tcp_stream"`
	ClientHelloFrame   *int     `json:"client_hello_frame"`
	Version            *string  `json:"version"`
	Decrypted          bool     `json:"decrypted"`
	HandshakeDecrypted bool     `json:"handshake_decrypted"`
	ApplicationData    []string `json:"application_data"`
	SecretIn           []string `json:"secret_in"`
	Labels             []string `json:"labels"`
	Reason             *string  `json:"reason"`
}

// TLSDecryptionSummary aggregates TLS decryption outcomes for the capture.
type TLSDecryptionSummary struct {
	Verdict         string          `json:"verdict"`
	Decrypted       int             `json:"decrypted"`
	Total           int             `json:"total"`
	SecretsSource   *string         `json:"secrets_source"`
	Sessions        []TLSSessionRow `json:"sessions"`
	SessionsOmitted int             `json:"sessions_omitted"`
}
