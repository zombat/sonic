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
	Severity       Severity        `json:"severity"`
	Code           string          `json:"code"`
	Message        string          `json:"message"`
	Frames         []int           `json:"frames"`
	Category       string          `json:"category,omitempty"`
	Protocol       string          `json:"protocol,omitempty"`
	ICMPType       *int            `json:"icmp_type,omitempty"`
	ICMPCode       *int            `json:"icmp_code,omitempty"`
	MTU            *int            `json:"mtu,omitempty"`
	Router         string          `json:"router,omitempty"`
	Estimate       *bool           `json:"estimate,omitempty"`
	Connections    *int            `json:"connections,omitempty"`
	NHRPCode       *int            `json:"nhrp_code,omitempty"`
	ErrorCode      *int            `json:"error_code,omitempty"`
	Spoke          string          `json:"spoke,omitempty"`
	MissingStep    string          `json:"missing_step,omitempty"`
	Algorithms     []string        `json:"algorithms,omitempty"`
	Peer           string          `json:"peer,omitempty"`
	Initiator      string          `json:"initiator,omitempty"`
	Responder      string          `json:"responder,omitempty"`
	Notify         string          `json:"notify,omitempty"`
	ResponseLength *int            `json:"response_length,omitempty"`
	SPI            string          `json:"spi,omitempty"`
	NewerSPI       string          `json:"newer_spi,omitempty"`
	Endpoints      []string        `json:"endpoints,omitempty"`
	Protocols      []string        `json:"protocols,omitempty"`
	Packets        *int            `json:"packets,omitempty"`
	BGPCode        *int            `json:"bgp_code,omitempty"`
	BGPSubcode     *int            `json:"bgp_subcode,omitempty"`
	Name           string          `json:"name,omitempty"`
	ExpectedMSS    *int            `json:"expected_mss,omitempty"`
	Values         json.RawMessage `json:"values,omitempty"`
	Version        string          `json:"version,omitempty"`
	Counter        string          `json:"counter,omitempty"`
	User           *string         `json:"user,omitempty"`
	Username       *string         `json:"username,omitempty"`
	Status         *int            `json:"status,omitempty"`
	ErrorTag       string          `json:"error_tag,omitempty"`
	Header         string          `json:"header,omitempty"`
	Method         string          `json:"method,omitempty"`
	GrpcStatus     *int            `json:"grpc_status,omitempty"`
	Key            string          `json:"key,omitempty"`
	Flow           string          `json:"flow,omitempty"`
	Error          string          `json:"error,omitempty"`
	Detector       string          `json:"detector,omitempty"`
}

// Event represents one chronological timeline entry from a detector run.
type Event struct {
	T        *float64 `json:"t"`
	Time     *string  `json:"time"`
	Protocol string   `json:"protocol"`
	Event    string   `json:"event"`
	Detail   string   `json:"detail"`
	Frame    *int     `json:"frame"`
	Detector string   `json:"detector,omitempty"`
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
