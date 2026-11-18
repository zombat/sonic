// Package dmvpn defines internal tracking keys and state accumulators for Detector.
package dmvpn

// addrPair represents an ordered (src, dst) IPv4/IPv6 pair.
type addrPair struct {
	src string
	dst string
}

// innerFlowData tracks outer GRE tunnels that carried one inner (src, dst) flow.
type innerFlowData struct {
	order  []addrPair
	outers map[addrPair]*outerTiming
}

// outerTiming captures packet count and boundary timestamps on one outer GRE direction.
type outerTiming struct {
	firstT float64
	firstN int
	lastT  float64
	count  int
}

// redirectKey uniquely indexes an NHRP Traffic Indication by spoke and inner tuple.
type redirectKey struct {
	spoke   string
	hasSrc  bool
	origSrc string
	hasDst  bool
	origDst string
}

// indicationTrack records the first redirect frame and total count per redirectKey.
type indicationTrack struct {
	hub     string
	spoke   string
	origSrc *string
	origDst *string
	t       float64
	n       int
	count   int
}

// nhrpRequestTrack captures one NHRP Resolution Request transmission.
type nhrpRequestTrack struct {
	requesterNBMA string
	requester     *string
	target        *string
	reqID         *uint32
	t             float64
	n             int
	outerSrc      string
	outerDst      string
}

// nhrpReplyTrack captures one NHRP Resolution Reply answer record.
type nhrpReplyTrack struct {
	t           float64
	n           int
	from        string
	code        *int
	clientNBMA  *string
	clientProto *string
	prefix      *int
}

// nhrpErrorTrack captures one NHRP Error Indication packet.
type nhrpErrorTrack struct {
	t       float64
	n       int
	from    string
	to      string
	reqID   *uint32
	code    *int
	errText string
}

// ikeShortcutState tracks IKEv2 IKE_SA_INIT and IKE_AUTH progress between an unordered peer pair.
type ikeShortcutState struct {
	hasInit       bool
	initT         float64
	initN         int
	initiator     *string
	hasAuth       bool
	authT         float64
	authN         int
	initRequests  int
	initResponses int
}

// espTimeEntry records timestamp and frame number of one ESP packet.
type espTimeEntry struct {
	t float64
	n int
}

// espDirTrack records ESP packet timestamps for one (src, dst) outer flow.
type espDirTrack struct {
	times   []espTimeEntry
	firstT  float64
	firstN  int
	lastT   float64
	packets int
}
