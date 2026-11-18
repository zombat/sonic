// Package espoverhead defines the JSON report schemas emitted by EspOverheadDetector.
package espoverhead

import "github.com/zombat/sonic/internal/model"

// Report is the normalized JSON structure returned by EspOverheadDetector.
type Report struct {
	Detector           string           `json:"detector"`
	Status             model.Status     `json:"status"`
	Verdict            string           `json:"verdict"`
	Estimate           bool             `json:"estimate"`
	Assumptions        Assumptions      `json:"assumptions"`
	Summary            Summary          `json:"summary"`
	Flows              []FlowReport     `json:"flows"`
	FlowsOmitted       int              `json:"flows_omitted"`
	OuterFragmentation []OuterFragEntry `json:"outer_fragmentation"`
	Limits             []string         `json:"limits"`
	Issues             []model.Issue    `json:"issues"`
	Events             []model.Event    `json:"events"`
}

// Assumptions records the MTU and GRE header parameters used in estimates.
type Assumptions struct {
	TransportMTU   int  `json:"transport_mtu"`
	TunnelMTU      *int `json:"tunnel_mtu"`
	GREHeaderBytes int  `json:"gre_header_bytes"`
}

// Summary aggregates capture-wide ESP flow, size, and fragmentation counts.
type Summary struct {
	ESPFlows                 int            `json:"esp_flows"`
	ESPFragments             int            `json:"esp_fragments"`
	FlowsDroppedAtCap        int            `json:"flows_dropped_at_cap"`
	FamilyEstimates          map[string]int `json:"family_estimates"`
	CaptureWideEstimate      *string        `json:"capture_wide_estimate"`
	CaptureWideDistinctSizes int            `json:"capture_wide_distinct_sizes"`
}

// FlowReport summarizes observed packet sizes and consistent cipher families for one SPI.
type FlowReport struct {
	Src                string          `json:"src"`
	Dst                string          `json:"dst"`
	SPI                string          `json:"spi"`
	NAT_T              bool            `json:"nat_t"`
	Packets            int             `json:"packets"`
	DistinctSizes      int             `json:"distinct_sizes"`
	LargestOuterPacket int             `json:"largest_outer_packet"`
	DFSetPackets       int             `json:"df_set_packets"`
	SizeHistogram      []SizeCount     `json:"size_histogram"`
	Estimate           *string         `json:"estimate"`
	Confidence         string          `json:"confidence"`
	EstimateBasis      string          `json:"estimate_basis"`
	ConsistentFamilies []FamilyDetails `json:"consistent_families"`
	Frames             []int           `json:"frames"`
}

// SizeCount records one ESP payload byte length and its packet frequency.
type SizeCount struct {
	ESPPayload int `json:"esp_payload"`
	Packets    int `json:"packets"`
}

// FamilyDetails reports overhead bounds and MTU fit for one consistent cipher family.
type FamilyDetails struct {
	Family            string                  `json:"family"`
	Indistinguishable []string                `json:"indistinguishable_from"`
	IV                int                     `json:"iv"`
	ICV               int                     `json:"icv"`
	Alignment         int                     `json:"alignment"`
	InnerSizeBounds   []InnerBound            `json:"inner_size_bounds"`
	Modes             map[string]ModeEstimate `json:"modes"`
}

// InnerBound reports deduced inner packet size range for one ESP payload length.
type InnerBound struct {
	ESPPayload int    `json:"esp_payload"`
	Packets    int    `json:"packets"`
	InnerBytes [2]int `json:"inner_bytes"`
}

// ModeEstimate holds overhead bounds and optional tunnel MTU fit in tunnel or GRE transport mode.
type ModeEstimate struct {
	OverheadBytes           [2]int `json:"overhead_bytes"`
	LargestInnerWithoutFrag int    `json:"largest_inner_packet_without_fragmentation"`
	OuterSizeAtTunnelMTU    *int   `json:"outer_size_at_tunnel_mtu,omitempty"`
	FitsTransportMTU        *bool  `json:"fits_transport_mtu,omitempty"`
}

// OuterFragEntry summarizes post-encryption IP fragmentation per source/destination pair.
type OuterFragEntry struct {
	Src             string   `json:"src"`
	Dst             string   `json:"dst"`
	Fragments       int      `json:"fragments"`
	Datagrams       int      `json:"datagrams"`
	LargestFragment int      `json:"largest_fragment"`
	SPIs            []string `json:"spis"`
	FirstT          *float64 `json:"first_t"`
	Frames          []int    `json:"frames"`
}
