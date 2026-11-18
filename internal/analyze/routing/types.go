// Package routing implements combined BGP, OSPFv2, and EIGRP health analysis
// and failover timeline construction matching analyzers/routing_health.py.
package routing

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/model"
)

// FailoverEvents names timeline event tokens surfaced in routing failover_timeline.
var FailoverEvents = map[string]bool{
	"established": true, "down": true, "notification": true, "refused": true,
	"end_of_rib": true, "withdraw": true, "update": true, "dbd_stuck": true,
	"hello_gap": true, "hellos_resumed": true, "neighbor_up": true, "neighbor_down": true,
	"dr_change": true, "router_silent": true, "goodbye": true, "hold_expired": true,
	"adjacency_init": true, "query": true, "sia_query": true, "neighbor_silent": true,
}

// Report is the top-level JSON structure returned by Detector.
type Report struct {
	Detector         string        `json:"detector"`
	Status           model.Status  `json:"status"`
	Verdict          string        `json:"verdict"`
	BGP              BGPSection    `json:"bgp"`
	OSPF             OSPFSection   `json:"ospf"`
	EIGRP            EIGRPSection  `json:"eigrp"`
	Issues           []model.Issue `json:"issues"`
	Events           []model.Event `json:"events"`
	FailoverTimeline []model.Event `json:"failover_timeline"`
}

// BGPSection holds BGP health results, serializing as {"present": false} when absent.
type BGPSection struct {
	Present             bool
	Status              model.Status
	Verdict             string
	Sessions            []BGPSessionReport
	SessionsOmitted     int
	Messages            int
	EstablishedSessions int
	ExpectedMSS         *int
	Issues              []model.Issue
}

// bgpSectionFull mirrors BGPSection fields for JSON marshaling when Present is true.
type bgpSectionFull struct {
	Present             bool               `json:"present"`
	Status              model.Status       `json:"status"`
	Verdict             string             `json:"verdict"`
	Sessions            []BGPSessionReport `json:"sessions"`
	SessionsOmitted     int                `json:"sessions_omitted"`
	Messages            int                `json:"messages"`
	EstablishedSessions int                `json:"established_sessions"`
	ExpectedMSS         *int               `json:"expected_mss"`
	Issues              []model.Issue      `json:"issues"`
}

// MarshalJSON encodes BGPSection as {"present": false} when absent or full fields when present.
func (s BGPSection) MarshalJSON() ([]byte, error) {
	if !s.Present {
		return []byte(`{"present":false}`), nil
	}
	return json.Marshal(bgpSectionFull(s))
}

// BGPUpdateSample records a single BGP UPDATE's announced/withdrawn prefix counts.
type BGPUpdateSample struct {
	T         *float64 `json:"t"`
	AbsT      float64  `json:"-"`
	Frame     int      `json:"frame"`
	Announced int      `json:"announced"`
	Withdrawn int      `json:"withdrawn"`
}

// BGPSpeakerReport summarizes ASN, router ID, capabilities, keepalive intervals, and updates per peer.
type BGPSpeakerReport struct {
	AS                    *int              `json:"as"`
	RouterID              *string           `json:"router_id"`
	HoldTimeOffered       *int              `json:"hold_time_offered"`
	Capabilities          *[]string         `json:"capabilities"`
	Messages              map[string]int    `json:"messages"`
	PrefixesAnnounced     int               `json:"prefixes_announced"`
	PrefixesWithdrawn     int               `json:"prefixes_withdrawn"`
	EndOfRibT             *float64          `json:"end_of_rib_t"`
	KeepaliveIntervalS    *float64          `json:"keepalive_interval_s"`
	KeepaliveIntervalMinS *float64          `json:"keepalive_interval_min_s"`
	KeepaliveIntervalMaxS *float64          `json:"keepalive_interval_max_s"`
	FirstUpdateT          *float64          `json:"first_update_t"`
	LastUpdateT           *float64          `json:"last_update_t"`
	Updates               []BGPUpdateSample `json:"updates"`
}

// BGPDownEntry describes one established BGP connection termination and preceding silence.
type BGPDownEntry struct {
	T                        *float64           `json:"t"`
	Frame                    *int               `json:"frame"`
	Cause                    string             `json:"cause"`
	Reason                   *string            `json:"reason"`
	Explanation              string             `json:"explanation"`
	HoldTime                 *int               `json:"hold_time"`
	SilenceBeforeDownS       map[string]float64 `json:"silence_before_down_s"`
	QuietestSpeaker          *string            `json:"quietest_speaker"`
	QuietestLastMessageT     *float64           `json:"quietest_last_message_t"`
	QuietestLastMessageFrame *int               `json:"quietest_last_message_frame"`
}

// BGPMSSCheck records TCP SYN/SYN-ACK MSS options and optional expected_mss check results.
type BGPMSSCheck struct {
	Connection int               `json:"connection"`
	SYNFrom    *string           `json:"syn_from"`
	MSS        map[string]*int   `json:"mss"`
	Frames     map[string]int    `json:"frames"`
	Check      map[string]string `json:"check,omitempty"`
}

// BGPNotificationEntry describes a decoded BGP NOTIFICATION error.
type BGPNotificationEntry struct {
	From             string   `json:"from"`
	To               string   `json:"to"`
	Code             *int     `json:"code"`
	Subcode          *int     `json:"subcode"`
	Name             string   `json:"name"`
	Hint             *string  `json:"hint"`
	Frame            int      `json:"frame"`
	T                *float64 `json:"t"`
	WhileEstablished bool     `json:"while_established"`
}

// BGPSessionReport summarizes one BGP peer pair across its TCP connection attempts.
type BGPSessionReport struct {
	Peers                      []string                    `json:"peers"`
	State                      string                      `json:"state"`
	IBGP                       bool                        `json:"ibgp"`
	OverGRE                    bool                        `json:"over_gre"`
	NegotiatedHoldTime         *int                        `json:"negotiated_hold_time"`
	ExpectedKeepaliveIntervalS *float64                    `json:"expected_keepalive_interval_s"`
	Downs                      []BGPDownEntry              `json:"downs"`
	TCPMSS                     []BGPMSSCheck               `json:"tcp_mss"`
	Speakers                   map[string]BGPSpeakerReport `json:"speakers"`
	TCPConnections             int                         `json:"tcp_connections"`
	TimesEstablished           int                         `json:"times_established"`
	TimesDown                  int                         `json:"times_down"`
	Notifications              []BGPNotificationEntry      `json:"notifications"`
	FirstT                     *float64                    `json:"first_t"`
	LastT                      *float64                    `json:"last_t"`
	Frames                     []int                       `json:"frames"`
}
