// Package pathmtu defines JSON report structures and public constants for PathMtuDetector.
package pathmtu

import "github.com/zombat/sonic/internal/model"

// Limits documents PathMtuDetector visibility boundaries emitted in every report.
var Limits = []string{
	"Only what crossed this capture point is visible: a Fragmentation Needed sent towards a host on another segment, or dropped by an ACL before this point, is invisible here, so a black hole verdict means 'no ICMP seen here', not proof that no router sent one.",
	"A vanished probe can be loss rather than MTU; the black hole verdict needs smaller probes to the same destination answered and larger ones never answered.",
	"Fragments captured on one side of the reassembling host show whether pieces arrived here; whether the host reassembled them is not visible.",
	"IPv6 extension headers (including fragment headers) are not decoded.",
}

// Report is the normalized JSON structure emitted by PathMtuDetector.
type Report struct {
	Detector          string         `json:"detector"`
	Status            model.Status   `json:"status"`
	Verdict           string         `json:"verdict"`
	Summary           Summary        `json:"summary"`
	FragNeeded        []PTBEntry     `json:"frag_needed"`
	FragNeededOmitted int            `json:"frag_needed_omitted"`
	BlackHoles        []BlackHole    `json:"black_holes"`
	BlackHolesOmitted int            `json:"black_holes_omitted"`
	Fragments         FragmentReport `json:"fragments"`
	Limits            []string       `json:"limits"`
	Issues            []model.Issue  `json:"issues"`
	Events            []model.Event  `json:"events"`
}

// Summary holds capture-wide path MTU, black-hole, and fragment statistics.
type Summary struct {
	DFPacketsOver576      int  `json:"df_packets_over_576"`
	LargestDFPacket       *int `json:"largest_df_packet"`
	FragNeededMessages    int  `json:"frag_needed_messages"`
	SmallestMTUAdvertised *int `json:"smallest_mtu_advertised"`
	BlackHoles            int  `json:"black_holes"`
	FragmentedDatagrams   int  `json:"fragmented_datagrams"`
	IncompleteDatagrams   int  `json:"incomplete_datagrams"`
	ReassemblyTimeouts    int  `json:"reassembly_timeouts"`
}

// PTBEntry summarizes one aggregated ICMP Fragmentation Needed or Packet Too Big stream.
type PTBEntry struct {
	Router           string   `json:"router"`
	To               string   `json:"to"`
	OriginalSrc      *string  `json:"original_src"`
	OriginalDst      *string  `json:"original_dst"`
	OriginalProtocol *int     `json:"original_protocol"`
	OriginalDport    *int     `json:"original_dport"`
	MTU              *int     `json:"mtu"`
	OriginalLen      *int     `json:"original_len"`
	Count            int      `json:"count"`
	FirstT           *float64 `json:"first_t"`
	Frames           []int    `json:"frames"`
	ProbeFrames      []int    `json:"probe_frames"`
	Tunneled         bool     `json:"tunneled"`
}

// BlackHole represents an inferred ICMP-echo or TCP DF path MTU black hole.
type BlackHole struct {
	Kind            string `json:"kind"`
	Src             string `json:"src"`
	Dst             string `json:"dst"`
	Sport           *int   `json:"sport,omitempty"`
	Dport           *int   `json:"dport,omitempty"`
	LargestAnswered int    `json:"largest_answered"`
	SmallestVanish  int    `json:"smallest_vanished"`
	VanishedProbes  int    `json:"vanished_probes"`
	PathMTUBetween  [2]int `json:"path_mtu_between"`
	Frames          []int  `json:"frames"`
}

// FragmentReport summarizes IPv4 fragmented datagrams observed in the capture.
type FragmentReport struct {
	Datagrams          int                `json:"datagrams"`
	Complete           int                `json:"complete"`
	IncompleteCount    int                `json:"incomplete_count"`
	Incomplete         []IncompleteGroup  `json:"incomplete"`
	IncompleteOmitted  int                `json:"incomplete_omitted"`
	Overlapping        []OverlappingGroup `json:"overlapping"`
	ByPair             []FragmentPair     `json:"by_pair"`
	ByPairOmitted      int                `json:"by_pair_omitted"`
	GroupsDroppedAtCap int                `json:"groups_dropped_at_cap"`
}

// IncompleteGroup describes a fragmented datagram missing first, middle, or last pieces.
type IncompleteGroup struct {
	Src        string   `json:"src"`
	Dst        string   `json:"dst"`
	Protocol   *int     `json:"protocol"`
	ID         *int     `json:"id"`
	Missing    []string `json:"missing"`
	PiecesSeen int      `json:"pieces_seen"`
	FirstT     *float64 `json:"first_t"`
	Frames     []int    `json:"frames"`
}

// OverlappingGroup identifies an IPv4 datagram carrying overlapping fragment byte ranges.
type OverlappingGroup struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Protocol *int   `json:"protocol"`
	ID       *int   `json:"id"`
	Frames   []int  `json:"frames"`
}

// FragmentPair summarizes fragmentation counts and split sizes for one (src, dst, protocol) tuple.
type FragmentPair struct {
	Src                string `json:"src"`
	Dst                string `json:"dst"`
	Protocol           *int   `json:"protocol"`
	Datagrams          int    `json:"datagrams"`
	FirstFragmentSizes []int  `json:"first_fragment_sizes"`
	SplitAtMTU         *int   `json:"split_at_mtu"`
	Incomplete         int    `json:"incomplete"`
}
