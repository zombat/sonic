// Package qos defines normalized JSON report types for QosDetector.
package qos

import "github.com/zombat/sonic/internal/model"

// Limits documents the inherent QoS visibility caveats emitted in every report.
var Limits = []string{
	"ESP hides the inner header: from one capture the inner DSCP of encrypted traffic is unknown, so 'copied' is inferred from several markings on one SA. Compare an inside and an outside capture with correlate_captures to see the rewrite directly.",
	"RTP latency is not measurable from one capture point; jitter and loss are what arrived here. RTP is found by its header shape, so a non-RTP UDP flow that looks like RTP for 10+ packets can be counted.",
	"Clock rate is 8000 Hz for static audio payload types and estimated from timestamps for dynamic ones.",
}

// Report is the normalized JSON structure returned by QosDetector.
type Report struct {
	Detector           string           `json:"detector"`
	Status             model.Status     `json:"status"`
	Verdict            string           `json:"verdict"`
	Summary            Summary          `json:"summary"`
	MarkedFlows        []MarkedFlow     `json:"marked_flows"`
	MarkedFlowsOmitted int              `json:"marked_flows_omitted"`
	GRETunnels         []GRETunnelEntry `json:"gre_tunnels"`
	ESPSAs             []ESPSAEntry     `json:"esp_sas"`
	ESPSAsOmitted      int              `json:"esp_sas_omitted"`
	RTPStreams         []RTPStreamEntry `json:"rtp_streams"`
	RTPStreamsOmitted  int              `json:"rtp_streams_omitted"`
	Limits             []string         `json:"limits"`
	Issues             []model.Issue    `json:"issues"`
	Events             []model.Event    `json:"events"`
}

// Summary aggregates QoS counts across flows, tunnels, ESP SAs, and RTP streams.
type Summary struct {
	MarkedFlows       int `json:"marked_flows"`
	UnmarkedFlows     int `json:"unmarked_flows"`
	GRETunnels        int `json:"gre_tunnels"`
	ESPSAs            int `json:"esp_sas"`
	RTPStreams        int `json:"rtp_streams"`
	ECNCEPackets      int `json:"ecn_ce_packets"`
	FlowsDroppedAtCap int `json:"flows_dropped_at_cap"`
}

// MarkedFlow describes non-zero DSCP markings observed on a flow.
type MarkedFlow struct {
	Src      string         `json:"src"`
	Dst      string         `json:"dst"`
	Protocol string         `json:"protocol"`
	Packets  int            `json:"packets"`
	DSCP     map[string]int `json:"dscp"`
	Frames   []int          `json:"frames"`
}

// GREPairCount records packet count for one (inner, outer) DSCP pair.
type GREPairCount struct {
	Inner   string `json:"inner"`
	Outer   string `json:"outer"`
	Packets int    `json:"packets"`
}

// GRETunnelEntry summarizes inner vs outer DSCP behavior on a GRE tunnel.
type GRETunnelEntry struct {
	OuterSrc             string         `json:"outer_src"`
	OuterDst             string         `json:"outer_dst"`
	PacketsWithInnerIPv4 int            `json:"packets_with_inner_ipv4"`
	Copied               int            `json:"copied"`
	InnerMarkedOuterZero int            `json:"inner_marked_outer_zero"`
	Rewritten            int            `json:"rewritten"`
	Pairs                []GREPairCount `json:"pairs"`
	Frames               []int          `json:"frames"`
}

// ESPSAEntry summarizes outer DSCP markings observed on an ESP SA.
type ESPSAEntry struct {
	Src     string         `json:"src"`
	Dst     string         `json:"dst"`
	SPI     string         `json:"spi"`
	DSCP    map[string]int `json:"dscp"`
	Reading string         `json:"reading"`
	Frames  []int          `json:"frames"`
}

// RTPJitterStats holds final, mean, and max interarrival jitter in milliseconds.
type RTPJitterStats struct {
	Final float64 `json:"final"`
	Mean  float64 `json:"mean"`
	Max   float64 `json:"max"`
}

// RTPStreamEntry summarizes quality and DSCP metrics for one RTP stream.
type RTPStreamEntry struct {
	Src             string         `json:"src"`
	Dst             string         `json:"dst"`
	SSRC            string         `json:"ssrc"`
	PayloadType     int            `json:"payload_type"`
	Codec           string         `json:"codec"`
	ClockRate       int            `json:"clock_rate"`
	ClockRateSource string         `json:"clock_rate_source"`
	Packets         int            `json:"packets"`
	Expected        int            `json:"expected"`
	Lost            int            `json:"lost"`
	LossPercent     float64        `json:"loss_percent"`
	Duplicates      int            `json:"duplicates"`
	OutOfOrder      int            `json:"out_of_order"`
	JitterMs        RTPJitterStats `json:"jitter_ms"`
	DurationS       float64        `json:"duration_s"`
	DSCP            map[string]int `json:"dscp"`
	MOSEstimate     *float64       `json:"mos_estimate"`
	Latency         string         `json:"latency"`
	OverGRE         bool           `json:"over_gre"`
	FirstT          *float64       `json:"first_t"`
	Frames          []int          `json:"frames"`
}
