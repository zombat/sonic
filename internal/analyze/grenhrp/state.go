// Package grenhrp defines internal tracking keys and accumulators for Detector.
package grenhrp

// tunnelDirKey identifies one directional GRE outer address flow.
type tunnelDirKey struct {
	src string
	dst string
}

// tunnelKeyVal tracks counted GRE key presence (nil vs uint32).
type tunnelKeyVal struct {
	hasKey bool
	key    uint32
}

// tunnelTrack accumulates packet/byte counters, GRE keys, and inner protocol counts.
type tunnelTrack struct {
	src     string
	dst     string
	packets int
	bytes   int
	keys    map[tunnelKeyVal]int
	inner   map[string]int
	frames  []int
	firstT  float64
	lastT   float64
}

// regKey keys NHRP registration sessions by spoke and hub NBMA addresses.
type regKey struct {
	spoke string
	hub   string
}

// regTrack records NHRP registration request/reply counts and CIE result codes.
type regTrack struct {
	spokeNBMA     string
	spokeTunnelIP *string
	hubNBMA       string
	hubTunnelIP   *string
	requests      int
	replies       int
	codes         map[int]int
	hasLastCode   bool
	lastCode      int
	reqFrames     []int
	repFrames     []int
	firstT        float64
	lastT         float64
	hasSuccess    bool
	lastSuccessT  float64
}

// resKey groups NHRP resolution requests and replies by requester, target, and reqid.
type resKey struct {
	hasSrc   bool
	srcProto string
	hasDst   bool
	dstProto string
	hasReqID bool
	reqID    uint32
}

// resTrack accumulates NHRP resolution requests, replies, and unique answers.
type resTrack struct {
	requesterTunnelIP *string
	requesterNBMA     *string
	target            *string
	reqID             *uint32
	requests          int
	replies           int
	answers           []ResolutionAnswer
	reqFrames         []int
	repFrames         []int
	firstT            float64
}

// redirKey groups NHRP Traffic Indications by endpoints and original destination IP.
type redirKey struct {
	from       string
	to         string
	hasOrigDst bool
	origDst    string
}

// redirTrack aggregates repeated NHRP Traffic Indications.
type redirTrack struct {
	from                string
	to                  string
	redirectingTunnelIP *string
	origSrc             *string
	origDst             *string
	count               int
	frames              []int
	firstT              float64
}

// errorTrack stores one raw NHRP Error Indication record.
type errorTrack struct {
	from    string
	to      string
	errCode *int
	errText string
	reqID   *uint32
	frame   int
	t       float64
}
