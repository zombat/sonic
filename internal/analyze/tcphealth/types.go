// Package tcphealth defines JSON report types and constants for TcpHealthDetector.
package tcphealth

import "github.com/zombat/sonic/internal/model"

// Limits documents visibility boundaries included in every TCP health report.
var Limits = []string{
	"Retransmissions, gaps and RTT are what this capture point saw: a segment lost after the capture point shows as a retransmission here, one lost before it shows as a gap. RTT is from the capture point to the receiver and back, not end to end unless the capture was taken on the sender.",
	"A connection whose handshake was not captured has no window scale, so window-full checks and options are skipped for it.",
	"Payload contents are not judged here (see the tls detector for TLS handshakes).",
}

var verdictOrder = []string{
	"no_answer", "refused", "receiver_buffer_exhausted",
	"loss_on_path", "receive_window_limited", "reset", "healthy",
}

// Report is the normalized JSON structure emitted by TcpHealthDetector.
type Report struct {
	Detector           string            `json:"detector"`
	Status             model.Status      `json:"status"`
	Verdict            string            `json:"verdict"`
	Summary            Summary           `json:"summary"`
	Connections        []ConnectionEntry `json:"connections"`
	ConnectionsOmitted int               `json:"connections_omitted"`
	Limits             []string          `json:"limits"`
	Issues             []model.Issue     `json:"issues"`
	Events             []model.Event     `json:"events"`
}

// Summary aggregates connection counts by verdict and offered MSS values.
type Summary struct {
	Connections           int            `json:"connections"`
	ByVerdict             map[string]int `json:"by_verdict"`
	MSSOffered            []int          `json:"mss_offered"`
	ConnectionsDroppedCap int            `json:"connections_dropped_at_cap"`
}

// ConnectionEntry summarizes TCP handshake, loss, RTO, and window telemetry for one connection.
type ConnectionEntry struct {
	Client          string                      `json:"client"`
	Server          string                      `json:"server"`
	HandshakeSeen   bool                        `json:"handshake_seen"`
	OverGRE         bool                        `json:"over_gre"`
	Verdict         string                      `json:"verdict"`
	Detail          string                      `json:"detail"`
	OtherConditions []string                    `json:"other_conditions"`
	Packets         int                         `json:"packets"`
	FirstT          *float64                    `json:"first_t"`
	LastT           *float64                    `json:"last_t"`
	Handshake       *HandshakeInfo              `json:"handshake"`
	Directions      map[string]DirectionMetrics `json:"directions"`
	Frames          []int                       `json:"frames"`
}

// HandshakeInfo holds SYN/SYN-ACK frame numbers and measured handshake latencies.
type HandshakeInfo struct {
	SynFrames            []int    `json:"syn_frames"`
	SynCount             int      `json:"syn_count"`
	SynAckFrame          *int     `json:"synack_frame"`
	CapturePointToServer *float64 `json:"capture_point_to_server_ms"`
	CapturePointToClient *float64 `json:"capture_point_to_client_ms"`
}

// DirectionMetrics captures reliability, RTT, RTO, and window metrics for one flow direction.
type DirectionMetrics struct {
	From                   string          `json:"from"`
	SegmentsWithData       int             `json:"segments_with_data"`
	Bytes                  int             `json:"bytes"`
	MSS                    *int            `json:"mss"`
	WindowScale            *int            `json:"window_scale"`
	SACKPermitted          bool            `json:"sack_permitted"`
	Timestamps             bool            `json:"timestamps"`
	Retransmissions        int             `json:"retransmissions"`
	FastRetransmissions    int             `json:"fast_retransmissions"`
	TimeoutRetransmissions int             `json:"timeout_retransmissions"`
	ObservedRTOMs          *ObservedRTO    `json:"observed_retransmission_timeout_ms"`
	GapsBeforeCapturePoint int             `json:"gaps_before_capture_point"`
	GapBytes               int             `json:"gap_bytes"`
	OutOfOrder             int             `json:"out_of_order"`
	DuplicateACKsSent      int             `json:"duplicate_acks_sent"`
	DuplicateACKRunsOf3    int             `json:"duplicate_ack_runs_of_3"`
	ZeroWindowAdv          int             `json:"zero_window_advertisements"`
	ZeroWindowSeconds      float64         `json:"zero_window_seconds"`
	ZeroWindowOpenAtEnd    bool            `json:"zero_window_open_at_end"`
	WindowFullEvents       int             `json:"window_full_events"`
	RTTMs                  *RTTSummary     `json:"rtt_ms"`
	SRTTMs                 *float64        `json:"srtt_ms,omitempty"`
	RFC6298RTOMs           *float64        `json:"rfc6298_rto_ms"`
	LinuxRTOMs             *float64        `json:"linux_rto_ms,omitempty"`
	Frames                 DirectionFrames `json:"frames"`
}

// ObservedRTO summarizes empirically observed timeout retransmission delays in ms.
type ObservedRTO struct {
	Min    float64 `json:"min"`
	Median float64 `json:"median"`
	Max    float64 `json:"max"`
}

// RTTSummary holds summary statistics of measured RTT samples in milliseconds.
type RTTSummary struct {
	Min     float64 `json:"min"`
	Median  float64 `json:"median"`
	P95     float64 `json:"p95"`
	Max     float64 `json:"max"`
	Samples int     `json:"samples"`
}

// DirectionFrames holds bounded sample frame lists for direction anomalies.
type DirectionFrames struct {
	Retransmissions []int `json:"retransmissions"`
	Gaps            []int `json:"gaps"`
	DuplicateACKs   []int `json:"duplicate_acks"`
	ZeroWindow      []int `json:"zero_window"`
	WindowFull      []int `json:"window_full"`
}
