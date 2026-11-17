// Package grenhrp implements the GRE tunnel and NHRP (DMVPN) detector
// matching analyzers/gre_nhrp.py.
package grenhrp

import "github.com/zombat/sonic/internal/model"

// GREProtocolTypes maps GRE Ethertype protocol numbers to readable names.
var GREProtocolTypes = map[int]string{
	0x0800: "ipv4",
	0x86DD: "ipv6",
	0x2001: "nhrp",
	0x6558: "ethernet",
	0x8847: "mpls",
}

// RegResult represents the outcome of an NHRP registration conversation.
type RegResult int

const (
	// RegUnanswered indicates a spoke sent requests with no hub reply seen.
	RegUnanswered RegResult = iota
	// RegRegistered indicates the latest hub reply succeeded (CIE code 0).
	RegRegistered
	// RegRefused indicates the hub replied with a non-zero CIE failure code.
	RegRefused
)

// String returns the canonical snake_case JSON label for RegResult.
func (r RegResult) String() string {
	switch r {
	case RegUnanswered:
		return "unanswered"
	case RegRegistered:
		return "registered"
	case RegRefused:
		return "refused"
	default:
		return "unknown"
	}
}

// ResResult represents the outcome of an NHRP resolution request.
type ResResult int

const (
	// ResResolved indicates at least one positive reply (CIE code 0) was received.
	ResResolved ResResult = iota
	// ResNegativeReply indicates replies arrived without a positive CIE code 0.
	ResNegativeReply
	// ResErrorIndication indicates no reply arrived and an NHRP error matched reqid.
	ResErrorIndication
	// ResUnanswered indicates neither reply nor matching error was captured.
	ResUnanswered
)

// String returns the canonical snake_case JSON label for ResResult.
func (r ResResult) String() string {
	switch r {
	case ResResolved:
		return "resolved"
	case ResNegativeReply:
		return "negative_reply"
	case ResErrorIndication:
		return "error_indication"
	case ResUnanswered:
		return "unanswered"
	default:
		return "unknown"
	}
}

// Report is the top-level JSON structure returned by Detector.
type Report struct {
	Detector             string              `json:"detector"`
	Status               model.Status        `json:"status"`
	Verdict              string              `json:"verdict"`
	DMVPNPhaseHint       string              `json:"dmvpn_phase_hint"`
	Summary              Summary             `json:"summary"`
	Hubs                 []*HubEntry         `json:"hubs"`
	Spokes               []*SpokeEntry       `json:"spokes"`
	Registrations        []RegistrationEntry `json:"registrations"`
	RegistrationsOmitted int                 `json:"registrations_omitted"`
	Resolutions          []ResolutionEntry   `json:"resolutions"`
	ResolutionsOmitted   int                 `json:"resolutions_omitted"`
	Redirects            []RedirectEntry     `json:"redirects"`
	ErrorIndications     []ErrorEntry        `json:"error_indications"`
	Purges               map[string]int      `json:"purges"`
	Tunnels              []TunnelEntry       `json:"tunnels"`
	TunnelsOmitted       int                 `json:"tunnels_omitted"`
	SpokeToSpokeTunnels  []SpokeTunnelEntry  `json:"spoke_to_spoke_tunnels"`
	Issues               []model.Issue       `json:"issues"`
	Events               []model.Event       `json:"events"`
}

// Summary holds aggregate GRE tunnel and NHRP message counts.
type Summary struct {
	GRETunnels          int            `json:"gre_tunnels"`
	GREPackets          int            `json:"gre_packets"`
	NHRPMessages        map[string]int `json:"nhrp_messages"`
	Hubs                int            `json:"hubs"`
	Spokes              int            `json:"spokes"`
	SpokesRegistered    int            `json:"spokes_registered"`
	SpokeToSpokeTunnels int            `json:"spoke_to_spoke_tunnels"`
}

// HubEntry summarizes NHRP registration outcomes for one hub NBMA address.
type HubEntry struct {
	NBMA             string   `json:"nbma"`
	TunnelIP         *string  `json:"tunnel_ip"`
	SpokesRegistered []string `json:"spokes_registered"`
	SpokesRefused    []string `json:"spokes_refused"`
	SpokesUnanswered []string `json:"spokes_unanswered"`
}

// SpokeEntry summarizes the hubs contacted by one spoke NBMA address.
type SpokeEntry struct {
	NBMA     string   `json:"nbma"`
	TunnelIP *string  `json:"tunnel_ip"`
	Hubs     []string `json:"hubs"`
}

// RegistrationEntry details one spoke-to-hub NHRP registration conversation.
type RegistrationEntry struct {
	SpokeNBMA     string         `json:"spoke_nbma"`
	SpokeTunnelIP *string        `json:"spoke_tunnel_ip"`
	HubNBMA       string         `json:"hub_nbma"`
	HubTunnelIP   *string        `json:"hub_tunnel_ip"`
	Result        string         `json:"result"`
	Requests      int            `json:"requests"`
	Replies       int            `json:"replies"`
	ReplyCodes    map[string]int `json:"reply_codes"`
	FirstT        *float64       `json:"first_t"`
	LastT         *float64       `json:"last_t"`
	RequestFrames []int          `json:"request_frames"`
	ReplyFrames   []int          `json:"reply_frames"`
}

// ResolutionAnswer captures a single NHRP Resolution Reply answer record.
type ResolutionAnswer struct {
	Code           *int    `json:"code"`
	CodeName       string  `json:"code_name"`
	ClientNBMA     *string `json:"client_nbma"`
	ClientTunnelIP *string `json:"client_tunnel_ip"`
	PrefixLength   *int    `json:"prefix_length"`
	AnsweredBy     string  `json:"answered_by"`
	Frame          int     `json:"frame"`
}

// ResolutionEntry summarizes one NHRP Resolution Request and its answers.
type ResolutionEntry struct {
	RequesterTunnelIP *string            `json:"requester_tunnel_ip"`
	RequesterNBMA     *string            `json:"requester_nbma"`
	Target            *string            `json:"target"`
	RequestID         *uint32            `json:"request_id"`
	Result            string             `json:"result"`
	RequestsSeen      int                `json:"requests_seen"`
	Replies           int                `json:"replies"`
	Answers           []ResolutionAnswer `json:"answers"`
	FirstT            *float64           `json:"first_t"`
	RequestFrames     []int              `json:"request_frames"`
	ReplyFrames       []int              `json:"reply_frames"`
}

// RedirectEntry counts NHRP Traffic Indication redirects for an original flow.
type RedirectEntry struct {
	From                string   `json:"from"`
	To                  string   `json:"to"`
	RedirectingTunnelIP *string  `json:"redirecting_tunnel_ip"`
	OriginalSrc         *string  `json:"original_src"`
	OriginalDst         *string  `json:"original_dst"`
	Count               int      `json:"count"`
	FirstT              *float64 `json:"first_t"`
	Frames              []int    `json:"frames"`
}

// ErrorEntry records one NHRP Error Indication packet.
type ErrorEntry struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	ErrorCode *int     `json:"error_code"`
	Error     string   `json:"error"`
	RequestID *uint32  `json:"request_id"`
	Frame     int      `json:"frame"`
	T         *float64 `json:"t"`
}

// TunnelEntry reports unidirectional GRE traffic and inner protocols.
type TunnelEntry struct {
	Src            string         `json:"src"`
	Dst            string         `json:"dst"`
	Packets        int            `json:"packets"`
	Bytes          int            `json:"bytes"`
	GREKeys        []uint32       `json:"gre_keys"`
	KeylessPackets int            `json:"keyless_packets"`
	InnerProtocols map[string]int `json:"inner_protocols"`
	FirstT         *float64       `json:"first_t"`
	LastT          *float64       `json:"last_t"`
	Frames         []int          `json:"frames"`
}

// SpokeTunnelEntry summarizes observed direct GRE traffic between two spokes.
type SpokeTunnelEntry struct {
	Endpoints []string `json:"endpoints"`
	Packets   int      `json:"packets"`
	FirstT    *float64 `json:"first_t"`
}
