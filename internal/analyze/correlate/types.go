// Package correlate defines report schemas, matching parameters, and limits for
// cross-capture packet correlation (NAT, asymmetric paths, drops, and DSCP shifts).
package correlate

import "encoding/json"

const (
	// ReportSchema identifies the JSON output contract for correlation reports.
	ReportSchema = "sonic.correlation_report/1"
	// DefaultWindowS sets the default matching window in seconds.
	DefaultWindowS = 2.0
	// DefaultMaxHeld sets the default cap on simultaneously open matching groups.
	DefaultMaxHeld = 200000
	// MaxNodes bounds distinct (capture, 5-tuple) graph vertices tracked per run.
	MaxNodes = 200000
	// MaxDeltaSamples caps stored latency delta samples per capture pair.
	MaxDeltaSamples = 20000
)

// Limits documents matching assumptions, clock effects, and buffer eviction bounds.
var Limits = []string{
	"Only packets that reached at least one capture point are known; a packet dropped before the first capture point is invisible.",
	"Matching relies on fields NAT normally keeps (TCP sequence numbers, ESP SPI/sequence, payload hashes, IP identification). A device that randomizes TCP sequence numbers or rewrites payloads (an ALG) breaks matching for those flows.",
	"Times between capture points include the difference between the capturing clocks; captures written by one host (for example the CML controller) share a clock.",
	"A packet is held for matching for window_s seconds and at most max_packets_held packets are held; a packet that reaches the next capture point later than that, or after an early eviction, counts as unmatched.",
	"seen_only_at is an observation, not a verdict on intent: a flow that never needed to cross the other capture points looks the same as one that was dropped.",
}

// CaptureInput identifies a capture file path and its correlation label.
type CaptureInput struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}

// Options configures correlation window, eviction cap, clock offsets, and list bounds.
type Options struct {
	WindowS        *float64
	MaxPacketsHeld int
	ClockOffsetsS  map[string]float64
	MaxPackets     *int
	MaxItems       int
}

// CaptureRow describes extraction metadata and unmatched packet counts per capture point.
type CaptureRow struct {
	Label            string   `json:"label"`
	Path             string   `json:"path"`
	Backend          string   `json:"backend"`
	Packets          int      `json:"packets"`
	UnmatchedPackets int      `json:"unmatched_packets"`
	Start            *string  `json:"start"`
	End              *string  `json:"end"`
	ClockOffsetS     float64  `json:"clock_offset_s"`
	Warnings         []string `json:"warnings"`
}

// MatchingInfo records matching window parameters and capacity/eviction counters.
type MatchingInfo struct {
	WindowS           float64 `json:"window_s"`
	MaxPacketsHeld    int     `json:"max_packets_held"`
	EvictedEarly      int     `json:"evicted_early"`
	FlowsDroppedAtCap int     `json:"flows_dropped_at_cap"`
	PacketsMatched    int     `json:"packets_matched"`
}

// Summary aggregates connection verdict totals, NAT mappings, and DSCP rewrites.
type Summary struct {
	Connections     int            `json:"connections"`
	ByVerdict       map[string]int `json:"by_verdict"`
	NATTranslations int            `json:"nat_translations"`
	DSCPChanges     int            `json:"dscp_changes"`
}

// DeltaStats holds minimum, median, and maximum inter-capture transit times in milliseconds.
type DeltaStats struct {
	Min    float64 `json:"min"`
	Median float64 `json:"median"`
	Max    float64 `json:"max"`
}

// TransitRow summarizes matched packet delay and dominant TTL decrement between two captures.
type TransitRow struct {
	From           string      `json:"from"`
	To             string      `json:"to"`
	PacketsMatched int         `json:"packets_matched"`
	DeltaMS        *DeltaStats `json:"delta_ms"`
	TTLDecrement   *int        `json:"ttl_decrement"`
	Note           *string     `json:"note"`
}

// NATRow describes one observed address/port translation across two capture points.
type NATRow struct {
	Protocol string
	Between  [2]string
	AtLoKey  string
	AtLoVal  string
	AtHiKey  string
	AtHiVal  string
	Remote   string
	Kind     string
	Packets  int
	Frames   map[string]int
}

// MarshalJSON encodes NATRow with dynamic "at_<label>" fields matching analyzers/correlate.py.
func (n NATRow) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, 8)
	var err error
	if fields["protocol"], err = json.Marshal(n.Protocol); err != nil {
		return nil, err
	}
	if fields["between"], err = json.Marshal(n.Between); err != nil {
		return nil, err
	}
	if fields["at_"+n.AtLoKey], err = json.Marshal(n.AtLoVal); err != nil {
		return nil, err
	}
	if fields["at_"+n.AtHiKey], err = json.Marshal(n.AtHiVal); err != nil {
		return nil, err
	}
	if fields["remote"], err = json.Marshal(n.Remote); err != nil {
		return nil, err
	}
	if fields["kind"], err = json.Marshal(n.Kind); err != nil {
		return nil, err
	}
	if fields["packets"], err = json.Marshal(n.Packets); err != nil {
		return nil, err
	}
	if fields["frames"], err = json.Marshal(n.Frames); err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

// DSCPChangeRow records a packet's DSCP value changing between two capture points.
type DSCPChangeRow struct {
	From       string         `json:"from"`
	To         string         `json:"to"`
	Flow       string         `json:"flow"`
	DSCPBefore string         `json:"dscp_before"`
	DSCPAfter  string         `json:"dscp_after"`
	Packets    int            `json:"packets"`
	Frames     map[string]int `json:"frames"`
}

// DirectionSeen tracks per-capture packet counts for one flow direction.
type DirectionSeen struct {
	SeenAt map[string]int `json:"seen_at"`
}

// IncompleteFlow records packets of one direction that dropped partway along a path.
type IncompleteFlow struct {
	Direction  string         `json:"direction"`
	Packets    int            `json:"packets"`
	SeenAt     []string       `json:"seen_at"`
	LastSeenAt string         `json:"last_seen_at"`
	MissingAt  []string       `json:"missing_at"`
	Frames     map[string]int `json:"frames"`
}

// ConnectionRow describes an end-to-end correlated conversation and its path verdict.
type ConnectionRow struct {
	Flow                 string            `json:"flow"`
	Verdict              string            `json:"verdict"`
	Detail               string            `json:"detail"`
	EndpointsByCapture   map[string]string `json:"endpoints_by_capture"`
	Request              DirectionSeen     `json:"request"`
	Reply                *DirectionSeen    `json:"reply"`
	Incomplete           []IncompleteFlow  `json:"incomplete"`
	LinkLocalOrMulticast bool              `json:"link_local_or_multicast"`
	FirstT               *float64          `json:"first_t"`
	Frames               map[string][]int  `json:"frames"`
}

// CorrelateIssue stores correlation findings whose frame maps may hold []int or int values.
type CorrelateIssue struct {
	Severity string          `json:"severity"`
	Code     string          `json:"code"`
	Message  string          `json:"message"`
	Frames   json.RawMessage `json:"frames"`
}

// Report represents the top-level sonic.correlation_report/1 JSON payload or error output.
type Report struct {
	Status             string           `json:"status"`
	Error              string           `json:"error,omitempty"`
	Labels             []string         `json:"labels,omitempty"`
	Schema             string           `json:"schema"`
	Verdict            string           `json:"verdict"`
	Captures           []CaptureRow     `json:"captures"`
	Matching           MatchingInfo     `json:"matching"`
	Summary            Summary          `json:"summary"`
	Issues             []CorrelateIssue `json:"issues"`
	Transit            []TransitRow     `json:"transit"`
	NAT                []NATRow         `json:"nat"`
	NATOmitted         int              `json:"nat_omitted"`
	Connections        []ConnectionRow  `json:"connections"`
	ConnectionsOmitted int              `json:"connections_omitted"`
	DSCPChanges        []DSCPChangeRow  `json:"dscp_changes"`
	Limits             []string         `json:"limits"`
}

// MarshalJSON encodes error metadata on failure or full correlation output on success.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		type errPayload struct {
			Status string   `json:"status"`
			Error  string   `json:"error"`
			Labels []string `json:"labels,omitempty"`
		}
		return json.Marshal(errPayload{Status: r.Status, Error: r.Error, Labels: r.Labels})
	}
	type fullReport Report
	return json.Marshal(fullReport(r))
}
