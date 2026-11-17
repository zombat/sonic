// Package ipsec implements IPsec/IKE/ESP negotiation, NAT-T, DPD liveness,
// replay/stale-SPI, and cleartext leak detection matching analyzers/ipsec_vpn.py.
package ipsec

import "github.com/zombat/sonic/internal/model"

const (
	smallIKEAuthResponse = 112
	livenessMaxLength    = 96
	livenessInFlightS    = 2.0
	replayWindow         = 2048
	staleSPIGraceS       = 2.0
	collisionWindowS     = 2.0
)

// EncryptionVerdict enumerates capture-level peer pair encryption outcomes.
type EncryptionVerdict int

const (
	// EncNotPresent indicates no IPsec peers or tunnel traffic were found.
	EncNotPresent EncryptionVerdict = iota
	// EncEncrypted indicates all peer pairs carried ESP with no cleartext.
	EncEncrypted
	// EncCleartextSeen indicates unencrypted traffic was seen between IPsec peers.
	EncCleartextSeen
	// EncNoESP indicates IKE or candidate pairs were seen without ESP flow.
	EncNoESP
)

// String returns the canonical snake_case code for EncryptionVerdict.
func (v EncryptionVerdict) String() string {
	switch v {
	case EncNotPresent:
		return "not_present"
	case EncEncrypted:
		return "encrypted"
	case EncCleartextSeen:
		return "cleartext_seen"
	case EncNoESP:
		return "no_esp"
	default:
		return "not_present"
	}
}

// Report is the top-level JSON structure returned by Detector.
type Report struct {
	Detector           string             `json:"detector"`
	Status             model.Status       `json:"status"`
	Verdict            string             `json:"verdict"`
	EncryptionVerdict  string             `json:"encryption_verdict"`
	NegotiationVerdict string             `json:"negotiation_verdict"`
	Summary            Summary            `json:"summary"`
	PeerPairs          []PeerPairEntry    `json:"peer_pairs"`
	PeerPairsOmitted   int                `json:"peer_pairs_omitted"`
	Cleartext          []CleartextEntry   `json:"cleartext"`
	IKESAs             []IKESAReport      `json:"ike_sas"`
	IKESAsOmitted      int                `json:"ike_sas_omitted"`
	ESPFlows           []ESPFlowReport    `json:"esp_flows"`
	ESPFlowsOmitted    int                `json:"esp_flows_omitted"`
	NATTraversal       NATTraversalReport `json:"nat_traversal"`
	Issues             []model.Issue      `json:"issues"`
	Events             []model.Event      `json:"events"`
}

// Summary holds aggregate counts for IKE SAs, ESP flows, and NAT keepalives.
type Summary struct {
	IKEPackets        int `json:"ike_packets"`
	IKESAs            int `json:"ike_sas"`
	IKESAsEstablished int `json:"ike_sas_established"`
	ESPFlows          int `json:"esp_flows"`
	ESPPackets        int `json:"esp_packets"`
	NATKeepalives     int `json:"nat_keepalives"`
}

// CleartextEntry summarizes unencrypted packets observed between IPsec peer endpoints.
type CleartextEntry struct {
	Protocol string   `json:"protocol"`
	Src      string   `json:"src"`
	Dst      string   `json:"dst"`
	Packets  int      `json:"packets"`
	Bytes    int      `json:"bytes"`
	FirstT   *float64 `json:"first_t"`
	Frames   []int    `json:"frames"`
}

// PeerPairEntry reports encryption status and packet mix between two endpoints.
type PeerPairEntry struct {
	Endpoints        []string         `json:"endpoints"`
	Verdict          string           `json:"verdict"`
	ProtectedPackets map[string]int   `json:"protected_packets"`
	CleartextPackets int              `json:"cleartext_packets"`
	Cleartext        []CleartextEntry `json:"cleartext"`
}

// IKESAReport details negotiation outcome, exchanges, notifies, and heuristics for one IKE SA.
type IKESAReport struct {
	IKEVersion      int                `json:"ike_version"`
	Negotiation     *NegotiationDetail `json:"negotiation"`
	Diagnosis       Diagnosis          `json:"diagnosis"`
	InitiatorSPI    string             `json:"initiator_spi"`
	ResponderSPI    *string            `json:"responder_spi"`
	Initiator       *string            `json:"initiator"`
	Responder       *string            `json:"responder"`
	UDPPorts        []int              `json:"udp_ports"`
	NAT_T           bool               `json:"nat_t"`
	Outcome         string             `json:"outcome"`
	Detail          string             `json:"detail"`
	Retransmissions int                `json:"retransmissions"`
	Rekeys          int                `json:"rekeys"`
	Notifies        []NotifyEntry      `json:"notifies"`
	Exchanges       []ExchangeEntry    `json:"exchanges"`
	FirstT          *float64           `json:"first_t"`
	LastT           *float64           `json:"last_t"`
	Frames          []int              `json:"frames"`
	CollidedWith    string             `json:"collided_with,omitempty"`
}

// Diagnosis summarizes an IKE SA outcome and root-cause explanation.
type Diagnosis struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// NotifyEntry records a single cleartext IKE Notify payload.
type NotifyEntry struct {
	Type  int    `json:"type"`
	Name  string `json:"name"`
	From  string `json:"from"`
	Frame int    `json:"frame"`
	Error bool   `json:"error"`
}

// ExchangeEntry summarizes request/response/retransmission metrics per IKE exchange and message ID.
type ExchangeEntry struct {
	Exchange        string   `json:"exchange"`
	MessageID       uint32   `json:"message_id"`
	Requests        int      `json:"requests"`
	Responses       int      `json:"responses"`
	Retransmissions int      `json:"retransmissions"`
	Unanswered      bool     `json:"unanswered"`
	Encrypted       bool     `json:"encrypted"`
	T               *float64 `json:"t"`
	RequestFrames   []int    `json:"request_frames"`
	ResponseFrames  []int    `json:"response_frames"`
}

// InvalidKEEntry records an IKE_SA_INIT INVALID_KE_PAYLOAD group retry request.
type InvalidKEEntry struct {
	GroupRequested int      `json:"group_requested"`
	GroupOffered   *int     `json:"group_offered"`
	Frame          int      `json:"frame"`
	T              *float64 `json:"t"`
}

// NATTranslatedEntry records a mismatched NAT_DETECTION address/port hash on the wire.
type NATTranslatedEntry struct {
	Message  string `json:"message"`
	Sender   string `json:"sender"`
	Field    string `json:"field"`
	Observed string `json:"observed"`
	Frame    int    `json:"frame"`
}

// NATDetectionDetail summarizes NAT_DETECTION payloads and UDP 4500 float behavior.
type NATDetectionDetail struct {
	PayloadsSeen      bool                 `json:"payloads_seen"`
	NATDetected       bool                 `json:"nat_detected"`
	Translated        []NATTranslatedEntry `json:"translated"`
	MovedToUDP4500    bool                 `json:"moved_to_udp_4500"`
	FirstUDP4500Frame *int                 `json:"first_udp_4500_frame"`
	FirstUDP4500T     *float64             `json:"first_udp_4500_t"`
	IKEAuthUDPPorts   []int                `json:"ike_auth_udp_ports"`
	Verdict           string               `json:"verdict"`
}

// UnansweredLiveness records a small encrypted INFORMATIONAL check left unanswered.
type UnansweredLiveness struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	FirstT        *float64 `json:"first_t"`
	LastT         *float64 `json:"last_t"`
	Transmissions int      `json:"transmissions"`
	Frame         int      `json:"frame"`
}

// LivenessDetail reports heuristic DPD liveness check rates and unanswered checks.
type LivenessDetail struct {
	Checks              int                  `json:"checks"`
	Answered            int                  `json:"answered"`
	Unanswered          int                  `json:"unanswered"`
	PendingAtCaptureEnd int                  `json:"pending_at_capture_end"`
	BySender            map[string]int       `json:"by_sender"`
	IntervalSBySender   map[string]*float64  `json:"interval_s_by_sender"`
	UnansweredChecks    []UnansweredLiveness `json:"unanswered_checks"`
	Frames              []int                `json:"frames"`
	Note                string               `json:"note"`
}

// NegotiationDetail holds cleartext IKEv2 proposal, DH group, NAT-T, and liveness inspection details.
type NegotiationDetail struct {
	ProposalsOffered []model.IKEv2ProposalSummary `json:"proposals_offered"`
	OfferedFrame     *int                         `json:"offered_frame"`
	ProposalChosen   *model.IKEv2ProposalSummary  `json:"proposal_chosen"`
	ChosenFrame      *int                         `json:"chosen_frame"`
	KEGroupsOffered  []int                        `json:"ke_groups_offered"`
	KEGroupChosen    *int                         `json:"ke_group_chosen"`
	InvalidKEPayload []InvalidKEEntry             `json:"invalid_ke_payload"`
	NATDetection     NATDetectionDetail           `json:"nat_detection"`
	Liveness         LivenessDetail               `json:"liveness"`
	ChildSA          string                       `json:"child_sa"`
}

// ESPFlowReport reports sequence continuity, replay/out-of-order counts, and stale SPI usage per flow.
type ESPFlowReport struct {
	Src                      string   `json:"src"`
	Dst                      string   `json:"dst"`
	SPI                      string   `json:"spi"`
	UDPEncapsulated          bool     `json:"udp_encapsulated"`
	Packets                  int      `json:"packets"`
	Bytes                    int      `json:"bytes"`
	FirstT                   *float64 `json:"first_t"`
	LastT                    *float64 `json:"last_t"`
	FirstSeq                 *uint32  `json:"first_seq"`
	LastSeq                  *uint32  `json:"last_seq"`
	MissingSequenceNumbers   int      `json:"missing_sequence_numbers"`
	DuplicateSequenceNumbers int      `json:"duplicate_sequence_numbers"`
	OutOfOrder               int      `json:"out_of_order"`
	Frames                   []int    `json:"frames"`
	StalePackets             int      `json:"stale_packets"`
	StaleFrames              []int    `json:"stale_frames"`
}

// NATTraversalReport summarizes capture-wide IKE on UDP 4500, ESP-in-UDP, and keepalives.
type NATTraversalReport struct {
	InUse                    bool   `json:"in_use"`
	IKEPacketsOn4500         int    `json:"ike_packets_on_4500"`
	ESPInUDPFlows            int    `json:"esp_in_udp_flows"`
	NATKeepalives            int    `json:"nat_keepalives"`
	KeepaliveFrames          []int  `json:"keepalive_frames"`
	NATDetectionPayloadsSeen bool   `json:"nat_detection_payloads_seen"`
	Verdict                  string `json:"verdict"`
}
