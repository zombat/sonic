// Package ipsec defines internal state accumulators and map keys for Detector.
package ipsec

import "github.com/zombat/sonic/internal/model"

// exchangeKey indexes an exchange inside an IKE SA by exchange code and message ID.
type exchangeKey struct {
	exch  int
	msgID uint32
}

// exchangeState accumulates request, response, retransmission, and notify stats for one exchange.
type exchangeState struct {
	requests        int
	responses       int
	retransmissions int
	awaiting        bool
	firstT          float64
	lastT           float64
	reqFrames       []int
	respFrames      []int
	respLengths     []uint32
	respNotifies    [][]int
	reqNotifies     [][]int
	encrypted       bool
}

// ikev1CountKey counts IKEv1 messages by exchange code and sender role.
type ikev1CountKey struct {
	exch int
	side string
}

// livenessKey keys pending empty INFORMATIONAL DPD checks by sender IP and message ID.
type livenessKey struct {
	addr  string
	msgID uint32
}

// livenessEntry tracks one candidate IKEv2 DPD check.
type livenessEntry struct {
	from     string
	to       string
	firstT   float64
	lastT    float64
	tries    int
	answered bool
	frame    int
	length   uint32
}

// rawNotify captures one parsed Notify payload inside an IKE SA.
type rawNotify struct {
	typ      int
	name     string
	from     string
	to       string
	frame    int
	t        float64
	exchange *int
	isError  bool
}

// invalidKETrack captures an INVALID_KE_PAYLOAD reply paired with the offered DH group.
type invalidKETrack struct {
	groupRequested int
	groupOffered   *int
	frame          int
	t              float64
}

// ikeSA accumulates all state observed for one IKE SA keyed by initiator SPI.
type ikeSA struct {
	ispi           string
	version        int
	rspi           *string
	initiator      *string
	responder      *string
	ports          map[int]bool
	natt           bool
	hasTime        bool
	firstT         float64
	lastT          float64
	frames         []int
	exchanges      map[exchangeKey]*exchangeState
	order          []exchangeKey
	notifies       []rawNotify
	messagesBySide map[string]int
	ikev1Counts    map[ikev1CountKey]int
	offered        []model.IKEProposal
	offeredFrame   *int
	chosen         []model.IKEProposal
	chosenFrame    *int
	keOffered      []int
	keChosen       *int
	invalidKE      []invalidKETrack
	natdSeen       bool
	natTranslated  []NATTranslatedEntry
	hasFirst4500   bool
	first4500T     float64
	first4500Frame int
	authPorts      map[int]bool
	pendingLive    map[livenessKey]*livenessEntry
	hasMinLiveLen  bool
	minLiveLen     uint32
}

// cleartextKey identifies one (protocol, src, dst) cleartext traffic flow between IPsec peers.
type cleartextKey struct {
	label string
	src   string
	dst   string
}

// cleartextTrack counts cleartext packets/bytes for one cleartextKey.
type cleartextTrack struct {
	packets int
	bytes   int
	frames  []int
	firstT  float64
}

// pairTrack aggregates protected vs cleartext traffic for an unordered IP peer pair.
type pairTrack struct {
	protected  map[string]int
	clearOrder []cleartextKey
	cleartext  map[cleartextKey]*cleartextTrack
	firstT     float64
}
