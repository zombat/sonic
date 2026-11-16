// Package model defines detector report structures and shared helper types.
package model

import (
	"encoding/json"
	"fmt"
)

// Status represents the health classification produced by a network detector.
type Status int

const (
	// StatusNotPresent indicates no traffic relevant to the detector was seen.
	StatusNotPresent Status = iota
	// StatusOK indicates all checks passed without warnings or errors.
	StatusOK
	// StatusWarning indicates non-fatal anomalies or unverified states.
	StatusWarning
	// StatusProblem indicates critical policy failures or protocol errors.
	StatusProblem
)

// String returns the canonical lowercase JSON token for a Status.
func (s Status) String() string {
	switch s {
	case StatusNotPresent:
		return "not_present"
	case StatusOK:
		return "ok"
	case StatusWarning:
		return "warning"
	case StatusProblem:
		return "problem"
	default:
		return "not_present"
	}
}

// MarshalJSON encodes Status as its canonical JSON string token.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes a canonical JSON status token into Status.
func (s *Status) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	switch text {
	case "not_present":
		*s = StatusNotPresent
	case "ok":
		*s = StatusOK
	case "warning":
		*s = StatusWarning
	case "problem":
		*s = StatusProblem
	default:
		return fmt.Errorf("unknown status: %s", text)
	}
	return nil
}

// StatusOrder returns the severity rank of s matching network_common.STATUS_ORDER.
func StatusOrder(s Status) int {
	switch s {
	case StatusNotPresent:
		return 0
	case StatusOK:
		return 1
	case StatusWarning:
		return 2
	case StatusProblem:
		return 3
	default:
		return 0
	}
}

// Severity represents the importance level of a detector or audit issue.
type Severity int

const (
	// SeverityError indicates a critical issue or policy violation.
	SeverityError Severity = iota
	// SeverityWarning indicates a degraded, weak, or unverified condition.
	SeverityWarning
	// SeverityInfo indicates informational operational guidance.
	SeverityInfo
)

// String returns the canonical lowercase JSON token for a Severity.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "info"
	}
}

// MarshalJSON encodes Severity as its canonical JSON string token.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes a canonical JSON severity token into Severity.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	switch text {
	case "error":
		*s = SeverityError
	case "warning":
		*s = SeverityWarning
	case "info":
		*s = SeverityInfo
	default:
		return fmt.Errorf("unknown severity: %s", text)
	}
	return nil
}

// SeverityOrder returns the sort rank of s (lower is more severe).
func SeverityOrder(s Severity) int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	case SeverityInfo:
		return 2
	default:
		return 9
	}
}

// Issue represents one structured finding emitted by a detector or audit run.
type Issue struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Frames   []int    `json:"frames"`
	Category string   `json:"category,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
}

// Event represents one chronological timeline entry from a detector run.
type Event struct {
	T        *float64 `json:"t"`
	Time     *string  `json:"time"`
	Protocol string   `json:"protocol"`
	Event    string   `json:"event"`
	Detail   string   `json:"detail"`
	Frame    *int     `json:"frame"`
}

// CaptureInfo summarizes the capture metadata and extractor diagnostics.
type CaptureInfo struct {
	Backend             string   `json:"backend"`
	Packets             int      `json:"packets"`
	Bytes               int      `json:"bytes"`
	Start               *string  `json:"start"`
	End                 *string  `json:"end"`
	DurationS           *float64 `json:"duration_s"`
	DisplayFilter       *string  `json:"display_filter"`
	MaxPackets          *int     `json:"max_packets"`
	MissingTsharkFields []string `json:"missing_tshark_fields"`
	Warnings            []string `json:"warnings"`
}

// AuditReport is the full JSON report produced by cleartext_audit.
type AuditReport struct {
	Status                 string            `json:"status"`
	Error                  string            `json:"error,omitempty"`
	Passed                 bool              `json:"passed"`
	Clean                  bool              `json:"clean"`
	Result                 string            `json:"result"`
	Verdict                string            `json:"verdict"`
	Allowlist              []string          `json:"allowlist"`
	FramesAudited          int               `json:"frames_audited"`
	FramesAllowed          int               `json:"frames_allowed"`
	FramesOutsideAllowlist int               `json:"frames_outside_allowlist"`
	CleartextFrames        int               `json:"cleartext_frames"`
	Protection             map[string]int    `json:"protection"`
	Encryption             EncryptionSummary `json:"encryption"`
	FirstViolationFrame    *int              `json:"first_violation_frame"`
	ByProtocol             []ByProtocol      `json:"by_protocol"`
	Violations             []AuditViolation  `json:"violations"`
	ViolationsOmitted      int               `json:"violations_omitted"`
	TCPSessions            []TCPSession      `json:"tcp_sessions"`
	TCPSessionsOmitted     int               `json:"tcp_sessions_omitted"`
	AllowedByRule          map[string]int    `json:"allowed_by_rule"`
	CannotShow             []string          `json:"cannot_show"`
	Issues                 []Issue           `json:"issues"`
	File                   string            `json:"file"`
	Capture                CaptureInfo       `json:"capture"`
	ProtocolsPresent       []string          `json:"protocols_present"`
}

// EncryptionSummary aggregates session counts across SSH and TLS encryption states.
type EncryptionSummary struct {
	Sessions   int `json:"sessions"`
	Encrypted  int `json:"encrypted"`
	Weak       int `json:"weak"`
	Unverified int `json:"unverified"`
	Cleartext  int `json:"cleartext"`
	NotStarted int `json:"not_started"`
}

// ByProtocol summarizes out-of-allowlist traffic grouped by protocol label.
type ByProtocol struct {
	Protocol   string `json:"protocol"`
	Category   string `json:"category"`
	Packets    int    `json:"packets"`
	Bytes      int    `json:"bytes"`
	Pairs      int    `json:"pairs"`
	FirstFrame int    `json:"first_frame"`
}

// AuditViolation describes one (protocol, src, dst) bucket of frames outside the allowlist.
type AuditViolation struct {
	Protocol   string         `json:"protocol"`
	Category   string         `json:"category"`
	Hint       string         `json:"hint"`
	Src        *string        `json:"src"`
	Dst        *string        `json:"dst"`
	Packets    int            `json:"packets"`
	Bytes      int            `json:"bytes"`
	FirstFrame int            `json:"first_frame"`
	LastFrame  int            `json:"last_frame"`
	FirstT     float64        `json:"first_t"`
	LastT      float64        `json:"last_t"`
	Frames     []int          `json:"frames"`
	Protection map[string]int `json:"protection"`
	Reasons    []string       `json:"reasons,omitempty"`
}

// TCPSession summarizes one observed TCP flow and its SSH/TLS verdict.
type TCPSession struct {
	Service            string             `json:"service"`
	Protocol           string             `json:"protocol"`
	Category           string             `json:"category"`
	Client             string             `json:"client"`
	Server             string             `json:"server"`
	ServerKnownBy      *string            `json:"server_known_by"`
	Packets            int                `json:"packets"`
	FirstFrame         int                `json:"first_frame"`
	Protection         map[string]int     `json:"protection"`
	Encryption         *SessionEncryption `json:"encryption,omitempty"`
	AllowedAsEncrypted *bool              `json:"allowed_as_encrypted,omitempty"`
}

// SessionEncryption captures TLS or SSH encryption diagnostics for one TCP session.
type SessionEncryption struct {
	State               string         `json:"state"`
	HandshakeCaptured   bool           `json:"handshake_captured"`
	Reason              *string        `json:"reason"`
	Version             *string        `json:"version,omitempty"`
	CipherSuite         *string        `json:"cipher_suite,omitempty"`
	ServerHelloFrame    *int           `json:"server_hello_frame,omitempty"`
	KexInitFrames       *KexInitFrames `json:"kexinit_frames,omitempty"`
	CipherClientToServe *string        `json:"cipher_client_to_server,omitempty"`
	MACClientToServer   *string        `json:"mac_client_to_server,omitempty"`
	CipherServerToClien *string        `json:"cipher_server_to_client,omitempty"`
	MACServerToClient   *string        `json:"mac_server_to_client,omitempty"`
}

// KexInitFrames records the frame numbers of SSH KEXINIT messages in each direction.
type KexInitFrames struct {
	Client *int `json:"client"`
	Server *int `json:"server"`
}
