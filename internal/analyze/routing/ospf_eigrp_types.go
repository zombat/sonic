// Package routing OSPFv2 and EIGRP JSON report structures.
package routing

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/model"
)

// OSPFSection holds OSPF link and adjacency health, serializing as {"present": false} when absent.
type OSPFSection struct {
	Present      bool
	Status       model.Status
	Verdict      string
	Links        []OSPFLinkReport
	LinksOmitted int
	Packets      int
	Routers      int
	Issues       []model.Issue
}

// ospfSectionFull mirrors OSPFSection for JSON marshaling when Present is true.
type ospfSectionFull struct {
	Present      bool             `json:"present"`
	Status       model.Status     `json:"status"`
	Verdict      string           `json:"verdict"`
	Links        []OSPFLinkReport `json:"links"`
	LinksOmitted int              `json:"links_omitted"`
	Packets      int              `json:"packets"`
	Routers      int              `json:"routers"`
	Issues       []model.Issue    `json:"issues"`
}

// MarshalJSON encodes OSPFSection cleanly when absent vs present.
func (s OSPFSection) MarshalJSON() ([]byte, error) {
	if !s.Present {
		return []byte(`{"present":false}`), nil
	}
	return json.Marshal(ospfSectionFull(s))
}

// OSPFMismatch records a hello/MTU/options mismatch parameter across routers on one link.
type OSPFMismatch struct {
	Parameter string          `json:"parameter"`
	Values    json.RawMessage `json:"values"`
}

// OSPFDBDSide summarizes one router's DB Description exchange packets and unacked sequences.
type OSPFDBDSide struct {
	Router                 string         `json:"router"`
	DBDSent                int            `json:"dbd_sent"`
	InitialDBDSent         int            `json:"initial_dbd_sent"`
	NonInitialDBDSent      int            `json:"non_initial_dbd_sent"`
	MTU                    *int           `json:"mtu"`
	UnacknowledgedSequence map[string]int `json:"unacknowledged_sequences"`
	FirstT                 *float64       `json:"first_t"`
	LastT                  *float64       `json:"last_t"`
	Frames                 []int          `json:"frames"`
}

// OSPFDatabaseExchange reports EXSTART/EXCHANGE stuck detection and cause between two neighbors.
type OSPFDatabaseExchange struct {
	StateHint       string        `json:"state_hint"`
	Stuck           *string       `json:"stuck"`
	Cause           *string       `json:"cause"`
	Sides           []OSPFDBDSide `json:"sides"`
	LSAExchangeSeen bool          `json:"lsa_exchange_seen"`
}

// OSPFAdjacency reports bidirectional hello visibility and DBD exchange state for a pair of routers.
type OSPFAdjacency struct {
	Routers          []string              `json:"routers"`
	StateHint        string                `json:"state_hint"`
	DBDExchanged     bool                  `json:"dbd_exchanged"`
	LSAExchangeSeen  bool                  `json:"lsa_exchange_seen"`
	DatabaseExchange *OSPFDatabaseExchange `json:"database_exchange"`
}

// OSPFRouterReport summarizes parameters, neighbor lists, and hello gaps for one OSPF router.
type OSPFRouterReport struct {
	RouterID        string         `json:"router_id"`
	Address         string         `json:"address"`
	OverGRE         bool           `json:"over_gre"`
	Area            *string        `json:"area"`
	NetworkMask     *string        `json:"network_mask"`
	HelloInterval   *int           `json:"hello_interval"`
	DeadInterval    *int           `json:"dead_interval"`
	Priority        *int           `json:"priority"`
	AuthType        *int           `json:"auth_type"`
	DR              *string        `json:"dr"`
	BDR             *string        `json:"bdr"`
	NeighborsListed []string       `json:"neighbors_listed"`
	Hellos          int            `json:"hellos"`
	MaxHelloGapS    float64        `json:"max_hello_gap_s"`
	DBDMTU          *int           `json:"dbd_mtu"`
	PacketsByType   map[string]int `json:"packets_by_type"`
	FirstT          *float64       `json:"first_t"`
	LastHelloT      *float64       `json:"last_hello_t"`
}

// OSPFLinkReport groups OSPF routers, parameter mismatches, and adjacencies on one subnet.
type OSPFLinkReport struct {
	Network     *string            `json:"network"`
	Routers     []OSPFRouterReport `json:"routers"`
	Mismatches  []OSPFMismatch     `json:"mismatches"`
	Adjacencies []OSPFAdjacency    `json:"adjacencies"`
	DR          *string            `json:"dr"`
}

// EIGRPSection holds EIGRP speaker, link mismatch, and query metrics.
type EIGRPSection struct {
	Present      bool
	Status       model.Status
	Verdict      string
	Links        []EIGRPLinkReport
	LinksOmitted int
	Packets      int
	Speakers     int
	Issues       []model.Issue
}

// eigrpSectionFull mirrors EIGRPSection for JSON marshaling when Present is true.
type eigrpSectionFull struct {
	Present      bool              `json:"present"`
	Status       model.Status      `json:"status"`
	Verdict      string            `json:"verdict"`
	Links        []EIGRPLinkReport `json:"links"`
	LinksOmitted int               `json:"links_omitted"`
	Packets      int               `json:"packets"`
	Speakers     int               `json:"speakers"`
	Issues       []model.Issue     `json:"issues"`
}

// MarshalJSON encodes EIGRPSection cleanly when absent vs present.
func (s EIGRPSection) MarshalJSON() ([]byte, error) {
	if !s.Present {
		return []byte(`{"present":false}`), nil
	}
	return json.Marshal(eigrpSectionFull(s))
}

// EIGRPMismatch records AS or K-value mismatches across EIGRP speakers on one link.
type EIGRPMismatch struct {
	Parameter string          `json:"parameter"`
	Values    json.RawMessage `json:"values"`
}

// EIGRPAdjacency tracks INIT exchange and restart counts between two EIGRP speakers.
type EIGRPAdjacency struct {
	Speakers      []string `json:"speakers"`
	InitExchanged bool     `json:"init_exchanged"`
	UnicastSeen   bool     `json:"unicast_seen"`
	Restarts      int      `json:"restarts"`
}

// EIGRPSpeakerReport details AS, K-values, hold times, goodbyes, and opcodes for one EIGRP speaker.
type EIGRPSpeakerReport struct {
	Address       string         `json:"address"`
	OverGRE       bool           `json:"over_gre"`
	AS            *int           `json:"as"`
	KValues       []int          `json:"k_values"`
	HoldTime      *int           `json:"hold_time"`
	Hellos        int            `json:"hellos"`
	MaxGapS       float64        `json:"max_gap_s"`
	Goodbyes      int            `json:"goodbyes"`
	Messages      map[string]int `json:"messages"`
	InitUpdatesTo map[string]int `json:"init_updates_to"`
	RouteTLVs     int            `json:"route_tlvs"`
	FirstT        *float64       `json:"first_t"`
	LastT         *float64       `json:"last_t"`
}

// EIGRPLinkReport groups EIGRP speakers, parameter mismatches, and adjacencies on one link.
type EIGRPLinkReport struct {
	Speakers    []EIGRPSpeakerReport `json:"speakers"`
	Mismatches  []EIGRPMismatch      `json:"mismatches"`
	Adjacencies []EIGRPAdjacency     `json:"adjacencies"`
}
