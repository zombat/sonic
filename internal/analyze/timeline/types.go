// Package timeline defines types, selector unmarshaling, and report schemas for
// multi-capture event timeline merging and failover measurement.
package timeline

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/model"
)

// ReportSchema identifies the JSON output contract for merged timelines.
const ReportSchema = "sonic.merged_timeline/1"

var (
	// DownEvents lists timeline event names recognized as failure/outage starts.
	DownEvents = map[string]bool{
		"down": true, "neighbor_down": true, "notification": true, "hold_expired": true,
		"goodbye": true, "router_silent": true, "hello_gap": true, "outage": true,
		"no_answer": true, "rst": true, "pmtu_black_hole": true,
	}
	// UpEvents lists timeline event names recognized as routing recovery markers.
	UpEvents = map[string]bool{
		"established": true, "neighbor_up": true, "adjacency_init": true, "eor": true,
	}
	// SelectorKeys lists valid JSON keys on measurement event selectors.
	SelectorKeys = map[string]bool{
		"capture": true, "detector": true, "protocol": true,
		"event": true, "contains": true, "occurrence": true,
	}
	// Limits documents clock, cap, and packet-visibility boundaries of merged timelines.
	Limits = []string{
		"Event times are packet timestamps at each capture point, to the millisecond; captures from different hosts are only as comparable as their clocks (use clock_offsets_s).",
		"Each capture's timeline is capped by the detectors (max_items x 8 events per capture); a very busy capture can lose late events, reported as timeline_omitted per capture.",
		"A measurement is the time between two packets as captured; protocol timers that run inside a router between packets are invisible.",
	}
)

// CaptureInput names a capture file path and display label to include in MergeTimelines.
type CaptureInput struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}

// Selector matches events by optional capture, detector, protocol, event, substring, and occurrence.
type Selector struct {
	Capture     *string
	Detector    *string
	Protocol    *string
	Event       *string
	Contains    *string
	Occurrence  string
	UnknownKeys []string
}

// UnmarshalJSON parses a selector object while tracking unknown keys and integer/string occurrences.
func (s *Selector) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = Selector{Occurrence: "first"}
	var unknown []string
	for k, v := range raw {
		if !SelectorKeys[k] {
			unknown = append(unknown, k)
			continue
		}
		if k == "occurrence" {
			if string(v) == "null" {
				continue
			}
			var str string
			if err := json.Unmarshal(v, &str); err == nil {
				s.Occurrence = str
				continue
			}
			var num int
			if err := json.Unmarshal(v, &num); err == nil {
				s.Occurrence = strconv.Itoa(num)
				continue
			}
			s.Occurrence = strings.TrimSpace(string(v))
			continue
		}
		if string(v) == "null" {
			continue
		}
		var str string
		if err := json.Unmarshal(v, &str); err != nil {
			str = strings.TrimSpace(string(v))
		}
		switch k {
		case "capture":
			s.Capture = &str
		case "detector":
			s.Detector = &str
		case "protocol":
			s.Protocol = &str
		case "event":
			s.Event = &str
		case "contains":
			s.Contains = &str
		}
	}
	slices.Sort(unknown)
	s.UnknownKeys = unknown
	return nil
}

// MeasurementSpec defines one named duration assertion between From and To events.
type MeasurementSpec struct {
	Name string    `json:"name"`
	From *Selector `json:"from"`
	To   *Selector `json:"to"`
	MaxS *float64  `json:"max_s,omitempty"`
	MinS *float64  `json:"min_s,omitempty"`
}

// Options configures measurements, detector filters, clock offsets, bounds, and JSON export.
type Options struct {
	Measurements  []MeasurementSpec
	Detectors     []string
	FailoverMaxS  *float64
	ClockOffsetsS map[string]float64
	MaxEvents     int
	OutputPath    string
	Overwrite     bool
	DetectorOpts  netorch.DetectorOptions
}

// TimelineEvent represents one capture event positioned on the merged multi-capture clock.
type TimelineEvent struct {
	Capture  string  `json:"capture"`
	Detector string  `json:"detector"`
	Protocol string  `json:"protocol"`
	Event    string  `json:"event"`
	Detail   string  `json:"detail"`
	Frame    *int    `json:"frame"`
	T        float64 `json:"t"`
	Time     *string `json:"time"`
	epoch    float64
	capIdx   int
}

// MeasurementResult summarizes one evaluated MeasurementSpec against the merged timeline.
type MeasurementResult struct {
	Name    string         `json:"name"`
	From    *TimelineEvent `json:"from"`
	To      *TimelineEvent `json:"to"`
	MaxS    *float64       `json:"max_s"`
	MinS    *float64       `json:"min_s"`
	DeltaS  *float64       `json:"delta_s"`
	Verdict string         `json:"verdict"`
	Detail  string         `json:"detail"`
}

// AutoMeasurement records either an automatic ping outage or routing convergence interval.
type AutoMeasurement struct {
	Kind            string
	Name            string
	Capture         string
	StartTInCapture *float64
	LostRequests    int
	From            *TimelineEvent
	To              *TimelineEvent
	MaxS            *float64
	DeltaS          *float64
	Verdict         string
}

// MarshalJSON encodes ping_outage or routing_convergence objects matching analyzers/timeline.py.
func (m AutoMeasurement) MarshalJSON() ([]byte, error) {
	if m.Kind == "ping_outage" {
		type pingOutageJSON struct {
			Name            string   `json:"name"`
			Kind            string   `json:"kind"`
			Capture         string   `json:"capture"`
			StartTInCapture *float64 `json:"start_t_in_capture"`
			DeltaS          *float64 `json:"delta_s"`
			LostRequests    int      `json:"lost_requests"`
			MaxS            *float64 `json:"max_s"`
			Verdict         string   `json:"verdict"`
		}
		return json.Marshal(pingOutageJSON{
			Name: m.Name, Kind: m.Kind, Capture: m.Capture,
			StartTInCapture: m.StartTInCapture, DeltaS: m.DeltaS,
			LostRequests: m.LostRequests, MaxS: m.MaxS, Verdict: m.Verdict,
		})
	}
	type routingConvJSON struct {
		Name    string         `json:"name"`
		Kind    string         `json:"kind"`
		From    *TimelineEvent `json:"from"`
		To      *TimelineEvent `json:"to"`
		MaxS    *float64       `json:"max_s"`
		DeltaS  *float64       `json:"delta_s"`
		Verdict string         `json:"verdict"`
	}
	return json.Marshal(routingConvJSON{
		Name: m.Name, Kind: m.Kind, From: m.From, To: m.To,
		MaxS: m.MaxS, DeltaS: m.DeltaS, Verdict: m.Verdict,
	})
}

// CaptureSummary records timing metadata and per-detector verdicts for one input capture.
type CaptureSummary struct {
	Label           string            `json:"label"`
	Path            string            `json:"path"`
	Packets         int               `json:"packets"`
	Start           *string           `json:"start"`
	End             *string           `json:"end"`
	ClockOffsetS    float64           `json:"clock_offset_s"`
	OverallStatus   model.Status      `json:"overall_status"`
	Events          int               `json:"events"`
	TimelineOmitted int               `json:"timeline_omitted"`
	Verdicts        map[string]string `json:"verdicts"`
}

// Report is the top-level sonic.merged_timeline/1 output or structured error payload.
type Report struct {
	Status           string              `json:"status"`
	Error            string              `json:"error,omitempty"`
	Labels           []string            `json:"labels,omitempty"`
	ValidKeys        []string            `json:"valid_keys,omitempty"`
	Capture          string              `json:"capture,omitempty"`
	Schema           string              `json:"schema"`
	Verdict          string              `json:"verdict"`
	Origin           *string             `json:"origin"`
	Captures         []CaptureSummary    `json:"captures"`
	Measurements     []MeasurementResult `json:"measurements"`
	AutoMeasurements []AutoMeasurement   `json:"auto_measurements"`
	Timeline         []TimelineEvent     `json:"timeline"`
	TimelineOmitted  int                 `json:"timeline_omitted"`
	Detectors        []string            `json:"detectors"`
	Limits           []string            `json:"limits"`
	WrittenTo        string              `json:"written_to,omitempty"`
}

// MarshalJSON encodes error metadata on failure or full timeline output on success.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		type errPayload struct {
			Status    string   `json:"status"`
			Error     string   `json:"error"`
			Labels    []string `json:"labels,omitempty"`
			ValidKeys []string `json:"valid_keys,omitempty"`
			Capture   string   `json:"capture,omitempty"`
		}
		return json.Marshal(errPayload{
			Status:    r.Status,
			Error:     r.Error,
			Labels:    r.Labels,
			ValidKeys: r.ValidKeys,
			Capture:   r.Capture,
		})
	}
	type fullReport Report
	return json.Marshal(fullReport(r))
}
