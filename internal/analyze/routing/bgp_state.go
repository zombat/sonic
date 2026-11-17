// Package routing internal BGP connection and session state structs.
package routing

// bgpOpenData holds AS, hold time, and router ID parsed from a speaker's BGP OPEN.
type bgpOpenData struct {
	as       *int
	hold     *int
	routerID *string
}

// bgpOverHoldGap records a gap between BGP messages exceeding the negotiated hold time.
type bgpOverHoldGap struct {
	speaker  string
	gapS     float64
	holdTime int
	frame    int
}

// bgpConnKey uniquely identifies one TCP 4-tuple (lexicographically ordered endpoints).
type bgpConnKey struct {
	aIP   string
	aPort int
	bIP   string
	bPort int
}

// bgpConnection accumulates TCP handshake, OPENs, keepalives, gaps, and teardown for one TCP 179 socket.
type bgpConnection struct {
	firstT      float64
	synFrom     *string
	synCount    int
	synack      bool
	rstFrom     *string
	finFrom     map[string]bool
	closed      bool
	opens       map[string]bgpOpenData
	kaAfterOpen map[string]bool
	hasEstab    bool
	estabT      float64
	hasDown     bool
	downT       float64
	downReason  *string
	downCause   string
	downFrame   *int
	lastMsgT    map[string]float64
	lastMsgN    map[string]int
	maxGap      map[string]float64
	overHold    []bgpOverHoldGap
	frames      []int
	synOrder    []string
	synMSS      map[string]*int
	synFrames   map[string]int
}

// holdTime returns the smaller offered hold time once both speakers have sent OPEN.
func (c *bgpConnection) holdTime() *int {
	if len(c.opens) != 2 {
		return nil
	}
	var holds []int
	for _, o := range c.opens {
		if o.hold != nil {
			holds = append(holds, *o.hold)
		}
	}
	if len(holds) != 2 {
		return nil
	}
	m := min(holds[0], holds[1])
	return &m
}

// bgpSpeakerTrack accumulates aggregate BGP stats for one IP inside a session pair.
type bgpSpeakerTrack struct {
	as           *int
	routerID     *string
	holdTime     *int
	messages     map[string]int
	announced    int
	withdrawn    int
	hasEoR       bool
	eorT         float64
	eorCount     int
	kaGaps       []float64
	hasLastKA    bool
	lastKA       float64
	capabilities *[]string
	hasFirstUpd  bool
	firstUpdT    float64
	hasLastUpd   bool
	lastUpdT     float64
	updates      []BGPUpdateSample
}

// bgpSessionEvent captures a raw BGP session timeline event with absolute timestamp.
type bgpSessionEvent struct {
	kind   string
	t      float64
	frame  int
	detail string
}

// bgpNoteTrack stores one decoded BGP NOTIFICATION packet along with absolute timestamp.
type bgpNoteTrack struct {
	from             string
	to               string
	code             *int
	subcode          *int
	name             string
	hint             *string
	frame            int
	t                float64
	whileEstablished bool
}

// bgpSessionState aggregates connections, speakers, notifications, and events for one peer pair.
type bgpSessionState struct {
	peers         [2]string
	speakerOrder  []string
	speakers      map[string]*bgpSpeakerTrack
	notifications []bgpNoteTrack
	events        []bgpSessionEvent
	established   int
	downs         int
	connections   []*bgpConnection
	hasTime       bool
	firstT        float64
	lastT         float64
	overGRE       bool
}
