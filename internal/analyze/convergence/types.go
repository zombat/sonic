// Package convergence implements failover timeline correlation across IPsec,
// routing (BGP/OSPF/EIGRP), and ICMP reachability matching analyzers/convergence.py.
package convergence

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/zombat/sonic/internal/model"
)

const (
	gapRecordS     = 0.5
	defaultSilence = 3.0
	shiftWindowS   = 10
	shiftFraction  = 0.5
	relativeLimit  = 1e9
)

// CannotShow documents the four capture-vantage limitations emitted with every report.
var CannotShow = []string{
	"On a transport-link capture of a protected tunnel, BGP, NHRP and the user traffic travel inside ESP: routing reaction and traffic resumption are then inferred from ESP packet rates, not read from BGP.",
	"A liveness check (DPD) is recognised by size because its payload is encrypted.",
	"An event time from the runbook host and the capture's timestamps come from different clocks; a skew between them shifts every delta measured from the event.",
	"Only this capture point is seen: a failure elsewhere shows only through its effect on these links.",
}

// Options configures ConvergenceDetector correlation parameters.
type Options struct {
	EventTime  string
	FailedPeer string
	HoldTime   *float64
	SilenceS   *float64
}

// Report is the top-level JSON structure returned by ConvergenceDetector.
type Report struct {
	Detector         string          `json:"detector"`
	Status           model.Status    `json:"status"`
	Verdict          string          `json:"verdict"`
	EventTime        *string         `json:"event_time"`
	EventT           *float64        `json:"event_t"`
	FailedPeer       *string         `json:"failed_peer"`
	FailedPeerSource *string         `json:"failed_peer_source"`
	Driver           DriverInfo      `json:"driver"`
	Measurements     Measurements    `json:"measurements"`
	TrafficShift     *TrafficShift   `json:"traffic_shift"`
	Timeline         []TimelineEntry `json:"timeline"`
	TimelineOmitted  int             `json:"timeline_omitted"`
	CannotShow       []string        `json:"cannot_show"`
	Issues           []model.Issue   `json:"issues"`
	Events           []model.Event   `json:"events"`
}

// DriverInfo records the inferred failure detection mechanism and explanatory reason.
type DriverInfo struct {
	Mechanism string `json:"mechanism"`
	Reason    string `json:"reason"`
}

// SignalBrief summarizes one milestone signal inside Measurements.
type SignalBrief struct {
	Signal string   `json:"signal"`
	T      *float64 `json:"t"`
	DeltaS *float64 `json:"delta_s"`
	Frame  *int     `json:"frame"`
	Detail string   `json:"detail"`
}

// Measurements summarizes origin timing, milestone signals, and epoch-to-milestone deltas.
type Measurements struct {
	Origin                   *string      `json:"origin"`
	OriginT                  *float64     `json:"origin_t"`
	FirstFailureSign         *SignalBrief `json:"first_failure_sign"`
	Detection                *SignalBrief `json:"detection"`
	FirstUpdateOnSurviving   *SignalBrief `json:"first_update_on_surviving_path"`
	TrafficResumed           *SignalBrief `json:"traffic_resumed"`
	EventToFirstFailureSignS *float64     `json:"event_to_first_failure_sign_s"`
	EventToDetectionS        *float64     `json:"event_to_detection_s"`
	EventToFirstUpdateS      *float64     `json:"event_to_first_update_s"`
	EventToTrafficResumedS   *float64     `json:"event_to_traffic_resumed_s"`
}

// TrafficShift describes ESP packet-rate shift detection onto surviving tunnels.
type TrafficShift struct {
	TAbs                 *float64
	Detail               string
	SurvivingPairs       [][]string
	LostRatePPS          float64
	SurvivingBaselinePPS float64
	Method               string
	Frame                *int
	hasRates             bool
	shiftFound           bool
}

// MarshalJSON encodes TrafficShift matching Python's exact key presence per outcome branch.
func (t TrafficShift) MarshalJSON() ([]byte, error) {
	if !t.hasRates {
		return json.Marshal(struct {
			TAbs           *float64   `json:"t_abs"`
			Detail         string     `json:"detail"`
			SurvivingPairs [][]string `json:"surviving_pairs"`
		}{
			TAbs:           t.TAbs,
			Detail:         t.Detail,
			SurvivingPairs: t.SurvivingPairs,
		})
	}
	if !t.shiftFound {
		return json.Marshal(struct {
			LostRatePPS          float64    `json:"lost_rate_pps"`
			SurvivingBaselinePPS float64    `json:"surviving_baseline_pps"`
			SurvivingPairs       [][]string `json:"surviving_pairs"`
			TAbs                 *float64   `json:"t_abs"`
			Method               string     `json:"method"`
			Detail               string     `json:"detail"`
		}{
			LostRatePPS:          t.LostRatePPS,
			SurvivingBaselinePPS: t.SurvivingBaselinePPS,
			SurvivingPairs:       t.SurvivingPairs,
			TAbs:                 t.TAbs,
			Method:               t.Method,
			Detail:               t.Detail,
		})
	}
	return json.Marshal(struct {
		LostRatePPS          float64    `json:"lost_rate_pps"`
		SurvivingBaselinePPS float64    `json:"surviving_baseline_pps"`
		SurvivingPairs       [][]string `json:"surviving_pairs"`
		TAbs                 *float64   `json:"t_abs"`
		Method               string     `json:"method"`
		Detail               string     `json:"detail"`
		Frame                *int       `json:"frame"`
	}{
		LostRatePPS:          t.LostRatePPS,
		SurvivingBaselinePPS: t.SurvivingBaselinePPS,
		SurvivingPairs:       t.SurvivingPairs,
		TAbs:                 t.TAbs,
		Method:               t.Method,
		Detail:               t.Detail,
		Frame:                t.Frame,
	})
}

// TimelineEntry represents one chronologically ordered convergence milestone or event marker.
type TimelineEntry struct {
	T      *float64 `json:"t"`
	Time   *string  `json:"time"`
	DeltaS *float64 `json:"delta_s"`
	Phase  string   `json:"phase"`
	Signal string   `json:"signal"`
	Peer   *string  `json:"peer"`
	Detail string   `json:"detail"`
	Frame  *int     `json:"frame"`
}

// ParseEventTime parses epoch seconds, capture-relative seconds ("+12.5" or < 1e9),
// or timezone-aware ISO-8601 timestamps into Unix epoch seconds.
func ParseEventTime(raw string, start *float64) (*float64, error) {
	if raw == "" {
		return nil, nil
	}
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, fmt.Errorf("event_time %q is not epoch seconds, seconds from the first frame, or an ISO-8601 time", raw)
	}
	base := 0.0
	if start != nil {
		base = *start
	}
	if num, err := strconv.ParseFloat(text, 64); err == nil && !math.IsNaN(num) && !math.IsInf(num, 0) {
		if strings.HasPrefix(text, "+") || num < relativeLimit {
			v := base + num
			return &v, nil
		}
		return &num, nil
	}
	iso := strings.ReplaceAll(text, "Z", "+00:00")
	tzLayouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05-07:00",
	}
	for _, layout := range tzLayouts {
		if parsed, err := time.Parse(layout, iso); err == nil {
			v := float64(parsed.UnixNano()) / 1e9
			return &v, nil
		}
	}
	naiveLayouts := []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range naiveLayouts {
		if _, err := time.Parse(layout, iso); err == nil {
			return nil, fmt.Errorf("event_time %q has no time zone; add Z or an offset", raw)
		}
	}
	return nil, fmt.Errorf("event_time %q is not epoch seconds, seconds from the first frame, or an ISO-8601 time", raw)
}
