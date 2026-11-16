// Package reach defines the normalized JSON report structs for
// ReachabilityDetector and ConversationDetector.
package reach

import "github.com/zombat/sonic/internal/model"

// ReachReport is the normalized JSON output produced by ReachabilityDetector.
type ReachReport struct {
	Detector             string               `json:"detector"`
	Status               model.Status         `json:"status"`
	Verdict              string               `json:"verdict"`
	Summary              ReachSummary         `json:"summary"`
	Echo                 []EchoPair           `json:"echo"`
	EchoOmitted          int                  `json:"echo_omitted"`
	ICMPErrors           []ICMPErrorEntry     `json:"icmp_errors"`
	ICMPErrorsOmitted    int                  `json:"icmp_errors_omitted"`
	ARPUnanswered        []ARPUnansweredEntry `json:"arp_unanswered"`
	ARPUnansweredOmitted int                  `json:"arp_unanswered_omitted"`
	ARPDuplicateIPs      []ARPDupEntry        `json:"arp_duplicate_ips"`
	Issues               []model.Issue        `json:"issues"`
	Events               []model.Event        `json:"events"`
}

// ReachSummary holds aggregate reachability counts.
type ReachSummary struct {
	EchoPairs            int `json:"echo_pairs"`
	EchoRequests         int `json:"echo_requests"`
	EchoRepliesMatched   int `json:"echo_replies_matched"`
	EchoLost             int `json:"echo_lost"`
	UnmatchedReplies     int `json:"unmatched_replies"`
	ICMPErrors           int `json:"icmp_errors"`
	ARPTargetsUnanswered int `json:"arp_targets_unanswered"`
	ARPTargetsAnswered   int `json:"arp_targets_answered"`
	GratuitousARP        int `json:"gratuitous_arp"`
}

// EchoPair summarizes one (src, dst) ICMP echo sequence.
type EchoPair struct {
	Src                   string         `json:"src"`
	Dst                   string         `json:"dst"`
	IPv6                  bool           `json:"ipv6"`
	Tunneled              bool           `json:"tunneled"`
	Verdict               string         `json:"verdict"`
	Sent                  int            `json:"sent"`
	Answered              int            `json:"answered"`
	Lost                  int            `json:"lost"`
	PendingAtCaptureEnd   int            `json:"pending_at_capture_end"`
	LossPercent           float64        `json:"loss_percent"`
	DuplicateRequestsSeen int            `json:"duplicate_requests_seen"`
	RTTMs                 *RTTStats      `json:"rtt_ms"`
	Outages               []OutageWindow `json:"outages"`
	FirstT                *float64       `json:"first_t"`
	Frames                []int          `json:"frames"`
}

// RTTStats holds min/avg/max echo round-trip times in milliseconds.
type RTTStats struct {
	Min float64 `json:"min"`
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
}

// OutageWindow represents a contiguous run of lost echo requests.
type OutageWindow struct {
	StartT         *float64 `json:"start_t"`
	EndT           *float64 `json:"end_t"`
	RecoveredT     *float64 `json:"recovered_t"`
	DurationS      *float64 `json:"duration_s"`
	LostRequests   int      `json:"lost_requests"`
	FirstFrame     int      `json:"first_frame"`
	LastFrame      int      `json:"last_frame"`
	NextReplyFrame *int     `json:"next_reply_frame"`
}

// ICMPErrorEntry summarizes aggregated non-echo ICMP errors.
type ICMPErrorEntry struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	V6            bool     `json:"v6"`
	Type          int      `json:"type"`
	Code          int      `json:"code"`
	TypeName      string   `json:"type_name"`
	CodeText      string   `json:"code_text"`
	OriginalSrc   *string  `json:"original_src"`
	OriginalDst   *string  `json:"original_dst"`
	OriginalProto *int     `json:"original_protocol"`
	OriginalDport *int     `json:"original_dport"`
	Count         int      `json:"count"`
	FirstT        *float64 `json:"first_t"`
	Frames        []int    `json:"frames"`
}

// ARPUnansweredEntry records one target IP whose ARP requests received no reply.
type ARPUnansweredEntry struct {
	Target      string   `json:"target"`
	RequestedBy []string `json:"requested_by"`
	Requests    int      `json:"requests"`
	FirstT      *float64 `json:"first_t"`
	Frames      []int    `json:"frames"`
}

// ARPDupEntry reports an IP address answered by multiple MAC addresses.
type ARPDupEntry struct {
	IP     string         `json:"ip"`
	MACs   map[string]int `json:"macs"`
	Frames []int          `json:"frames"`
}
