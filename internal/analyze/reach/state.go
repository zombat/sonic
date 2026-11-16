// Package reach defines internal tracking keys and state structures for ReachabilityDetector.
package reach

// requestKey uniquely identifies an ICMP Echo Request for reply correlation.
type requestKey struct {
	src    string
	dst    string
	hasID  bool
	id     int
	hasSeq bool
	seq    int
	v6     bool
}

// pingRequest holds timing and match state for a tracked Echo Request.
type pingRequest struct {
	t      float64
	n      int
	hasRep bool
	replyT float64
	replyN int
}

// pairID identifies an ordered (source, destination) IP ping endpoint pair.
type pairID struct {
	src string
	dst string
}

// echoPairTrack aggregates Echo requests, duplicates, and frame numbers for one pairID.
type echoPairTrack struct {
	src        string
	dst        string
	v6         bool
	tunneled   bool
	keys       []requestKey
	duplicates int
	firstT     float64
	frames     []int
}

// icmpErrKey groups ICMP error messages by reporter, target, type/code, and inner tuple.
type icmpErrKey struct {
	src          string
	dst          string
	v6           bool
	icmpType     int
	code         int
	hasOrigDst   bool
	origDst      string
	hasOrigProto bool
	origProto    int
	hasOrigDport bool
	origDport    int
}

// icmpErrTrack records counts and sample metadata for one grouped ICMP error class.
type icmpErrTrack struct {
	from          string
	to            string
	v6            bool
	icmpType      int
	code          int
	typeName      string
	codeText      string
	originalSrc   *string
	originalDst   *string
	originalProto *int
	originalDport *int
	count         int
	firstT        float64
	frames        []int
}

// arpReqTrack accumulates unanswered ARP request askers and frame numbers per target IP.
type arpReqTrack struct {
	target string
	askers map[string]bool
	count  int
	firstT float64
	frames []int
}

// arpRepTrack records distinct MAC addresses seen replying for a given IPv4 address.
type arpRepTrack struct {
	ip       string
	macOrder []string
	macs     map[string]int
	firstT   float64
	frames   []int
}
