// Package tcphealth tracks TCP connection state, ordered segment/pending maps,
// and ICMP error correlations for TcpHealthDetector.
package tcphealth

import "github.com/zombat/sonic/internal/model"

const (
	maxConnections  = 20000
	maxSeenSegments = 4096
	maxRTTPending   = 1024
	maxRTTSamples   = 2000

	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

type tcpEp struct {
	ip   string
	port int
}

type connKey struct {
	tunneled bool
	a        tcpEp
	b        tcpEp
}

func makeConnKey(a, b tcpEp, tunneled bool) connKey {
	if a.ip < b.ip || (a.ip == b.ip && a.port <= b.port) {
		return connKey{tunneled: tunneled, a: a, b: b}
	}
	return connKey{tunneled: tunneled, a: b, b: a}
}

type orderedFloatMap struct {
	order []int64
	vals  map[int64]float64
}

func newOrderedFloatMap() orderedFloatMap {
	return orderedFloatMap{vals: make(map[int64]float64)}
}

func (m *orderedFloatMap) set(k int64, v float64, limit int) {
	if _, ok := m.vals[k]; !ok {
		m.order = append(m.order, k)
	}
	m.vals[k] = v
	for len(m.vals) > limit && len(m.order) > 0 {
		old := m.order[0]
		m.order = m.order[1:]
		delete(m.vals, old)
	}
}

func (m *orderedFloatMap) del(k int64) {
	delete(m.vals, k)
}

func (m *orderedFloatMap) popFrontLE(ackRel int64) {
	for len(m.order) > 0 {
		k := m.order[0]
		if _, ok := m.vals[k]; !ok {
			m.order = m.order[1:]
			continue
		}
		if k <= ackRel {
			delete(m.vals, k)
			m.order = m.order[1:]
			continue
		}
		break
	}
}

type directionTrack struct {
	hasBase       bool
	base          uint32
	maxEnd        int64
	hasAcked      bool
	acked         int64
	mss           *int
	ws            *int
	sack          bool
	ts            bool
	segments      int
	bytes         int
	retrans       int
	fastRetrans   int
	timeoutRet    int
	rtoObserved   []float64
	ooo           int
	gaps          int
	gapBytes      int64
	seen          orderedFloatMap
	pending       orderedFloatMap
	rtt           []float64
	hasLastACK    bool
	lastACK       uint32
	hasLastWin    bool
	lastWin       int
	dupRun        int
	dupacks       int
	dupackRuns    int
	dupackOrder   []int64
	dupacksFor    map[int64]int
	hasWinScaled  bool
	winScaled     int64
	zeroWindow    int
	hasZWStart    bool
	zwStart       float64
	zwTotal       float64
	windowFull    int
	framesRetrans []int
	framesZero    []int
	framesFull    []int
	framesGap     []int
	framesDup     []int
}

func newDirectionTrack(base uint32) *directionTrack {
	return &directionTrack{
		hasBase:       true,
		base:          base,
		seen:          newOrderedFloatMap(),
		pending:       newOrderedFloatMap(),
		dupacksFor:    make(map[int64]int),
		framesRetrans: []int{},
		framesZero:    []int{},
		framesFull:    []int{},
		framesGap:     []int{},
		framesDup:     []int{},
	}
}

type synTrack struct {
	count  int
	firstT float64
	lastT  float64
	frames []int
}

type synAckTrack struct {
	t     float64
	n     int
	count int
}

type rstEvent struct {
	from       tcpEp
	t          float64
	n          int
	afterBytes int
}

type connEventItem struct {
	kind string
	t    float64
	n    int
}

type tcpConnTrack struct {
	a, b      tcpEp
	tunneled  bool
	hasClient bool
	client    tcpEp
	hasServer bool
	server    tcpEp
	syn       *synTrack
	synack    *synAckTrack
	hasHSAck  bool
	hsAckT    float64
	dirOrder  []tcpEp
	dirs      map[tcpEp]*directionTrack
	rst       []rstEvent
	fin       map[tcpEp]float64
	firstT    float64
	lastT     float64
	firstN    int
	packets   int
	eventsCnt int
	eventList []connEventItem
	spoke     map[tcpEp]bool
}

type icmpRefKey struct {
	src      string
	dst      string
	hasDport bool
	dport    int
}

type icmpRefTrack struct {
	from     string
	icmpType int
	code     int
	v6       bool
	frames   []int
}

// Detector tracks per-connection TCP health, retransmissions, RTT, and window behavior.
type Detector struct {
	conns     map[connKey]*tcpConnTrack
	connOrder []connKey
	dropped   int
	icmpRefs  map[icmpRefKey]*icmpRefTrack
}

// NewDetector returns an initialized TCP health Detector.
func NewDetector() *Detector {
	return &Detector{
		conns:    make(map[connKey]*tcpConnTrack),
		icmpRefs: make(map[icmpRefKey]*icmpRefTrack),
	}
}

// Name returns "tcp".
func (d *Detector) Name() string { return "tcp" }

// Present reports whether at least one TCP connection was observed.
func (d *Detector) Present() bool { return len(d.conns) > 0 }

// Feed consumes one normalized record into TCP health tracking.
func (d *Detector) Feed(rec *model.Record) {
	if icmp := rec.ICMP; icmp != nil && icmp.Orig != nil && icmp.Orig.Proto != nil && *icmp.Orig.Proto == 6 {
		key := icmpRefKey{src: icmp.Orig.Src, dst: icmp.Orig.Dst}
		if icmp.Orig.Dport != nil {
			key.hasDport, key.dport = true, *icmp.Orig.Dport
		}
		ref, ok := d.icmpRefs[key]
		if !ok {
			tVal, cVal := 0, 0
			if icmp.Type != nil {
				tVal = *icmp.Type
			}
			if icmp.Code != nil {
				cVal = *icmp.Code
			}
			from := ""
			if icmp.Src != nil {
				from = *icmp.Src
			}
			ref = &icmpRefTrack{from: from, icmpType: tVal, code: cVal, v6: icmp.V6, frames: []int{}}
			d.icmpRefs[key] = ref
		}
		model.AddFrame(&ref.frames, rec.N)
		return
	}

	view := model.Transport(rec)
	if view == nil || view.TCP == nil || view.DTCP == nil || view.TCP.Sport == nil || view.TCP.Dport == nil {
		return
	}
	src := tcpEp{ip: view.Src, port: *view.TCP.Sport}
	dst := tcpEp{ip: view.Dst, port: *view.TCP.Dport}
	key := makeConnKey(src, dst, view.Tunneled)
	conn, ok := d.conns[key]
	if !ok {
		if len(d.conns) >= maxConnections {
			d.dropped++
			return
		}
		conn = &tcpConnTrack{
			a: src, b: dst, tunneled: view.Tunneled,
			dirs: make(map[tcpEp]*directionTrack), fin: make(map[tcpEp]float64),
			firstT: rec.T, lastT: rec.T, firstN: rec.N, spoke: make(map[tcpEp]bool),
		}
		d.conns[key] = conn
		d.connOrder = append(d.connOrder, key)
	}
	conn.packets++
	conn.lastT = rec.T
	d.processSegment(conn, rec, src, dst, view.TCP, view.DTCP)
}
