// Package pathmtu defines internal tracking keys and state structs for PathMtuDetector.
package pathmtu

// probeKey identifies an outbound DF probe by endpoints and IP ID or IPv6 length.
type probeKey struct {
	src    string
	dst    string
	byLen  bool
	hasVal bool
	val    int
}

// echoKey matches an ICMP Echo reply back to an outbound DF Echo request probe.
type echoKey struct {
	src    string
	dst    string
	hasID  bool
	id     int
	hasSeq bool
	seq    int
}

// probeEntry records timing and delivery outcomes for a single tracked DF probe.
type probeEntry struct {
	t        float64
	n        int
	src      string
	dst      string
	length   int
	hasEcho  bool
	answered bool
	ptb      bool
}

// ptbKey groups ICMP Fragmentation Needed / Packet Too Big events by router, target, original endpoints, and MTU.
type ptbKey struct {
	router  string
	to      string
	hasOrig bool
	origSrc string
	origDst string
	hasMTU  bool
	mtu     int
}

// ptbTrack aggregates repeated PTB messages matching a single ptbKey.
type ptbTrack struct {
	router      string
	to          string
	originalSrc *string
	originalDst *string
	origProto   *int
	origDport   *int
	mtu         *int
	originalLen *int
	count       int
	firstT      float64
	frames      []int
	probeFrames []int
	tunneled    bool
}

// tcpFlowKey identifies a directional TCP 4-tuple for black-hole tracking.
type tcpFlowKey struct {
	src   string
	sport int
	dst   string
	dport int
}

// tcpSegTrack records an unacknowledged DF TCP segment's transmission count and size.
type tcpSegTrack struct {
	length int
	plen   int
	sent   int
	t      float64
	n      int
	frames []int
}

// tcpFlowTrack holds unacknowledged DF segments and the largest acknowledged segment size on a TCP flow.
type tcpFlowTrack struct {
	segments     map[uint32]*tcpSegTrack
	maxAckedSize int
	src          string
	dst          string
	sport        int
	dport        int
}

// reassemblyTimeout captures an ICMP Time Exceeded fragment-reassembly timeout message.
type reassemblyTimeout struct {
	from string
	to   string
	t    float64
	n    int
}
