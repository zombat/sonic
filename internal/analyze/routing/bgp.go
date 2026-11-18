// Package routing BGP analyzer initialization, TCP 179 tracking, and update sampling.
package routing

import (
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// BgpAnalyzer tracks BGP TCP connections and protocol messages across sessions.
type BgpAnalyzer struct {
	connections map[bgpConnKey][]*bgpConnection
	sessionOrd  [][2]string
	sessions    map[[2]string]*bgpSessionState
	messages    int
	expectedMSS *int
}

// NewBgpAnalyzer constructs an initialized BgpAnalyzer.
func NewBgpAnalyzer(expectedMSS *int) *BgpAnalyzer {
	return &BgpAnalyzer{
		connections: make(map[bgpConnKey][]*bgpConnection),
		sessions:    make(map[[2]string]*bgpSessionState),
		expectedMSS: expectedMSS,
	}
}

// Present reports whether any TCP 179 BGP activity was observed.
func (a *BgpAnalyzer) Present() bool { return len(a.sessions) > 0 }

// session looks up or initializes the bgpSessionState for peer pair (x, y).
func (a *BgpAnalyzer) session(x, y string) *bgpSessionState {
	pk := model.PairKey(x, y)
	if sess, ok := a.sessions[pk]; ok {
		return sess
	}
	sess := &bgpSessionState{
		peers:    pk,
		speakers: make(map[string]*bgpSpeakerTrack),
	}
	a.sessions[pk] = sess
	a.sessionOrd = append(a.sessionOrd, pk)
	return sess
}

// speaker looks up or initializes per-speaker counters within sess.
func (a *BgpAnalyzer) speaker(sess *bgpSessionState, ip string) *bgpSpeakerTrack {
	if sp, ok := sess.speakers[ip]; ok {
		return sp
	}
	sp := &bgpSpeakerTrack{
		messages: make(map[string]int),
	}
	sess.speakers[ip] = sp
	sess.speakerOrder = append(sess.speakerOrder, ip)
	return sp
}

// orderedConnKey builds a canonical bgpConnKey ordered by IP then TCP port.
func orderedConnKey(src string, sport int, dst string, dport int) bgpConnKey {
	if src < dst || (src == dst && sport <= dport) {
		return bgpConnKey{aIP: src, aPort: sport, bIP: dst, bPort: dport}
	}
	return bgpConnKey{aIP: dst, aPort: dport, bIP: src, bPort: sport}
}

// Feed ingests a normalized packet record carrying TCP port 179 into BGP state.
func (a *BgpAnalyzer) Feed(rec *model.Record, tunneled bool) {
	if rec.TCP == nil || rec.IP == nil || rec.TCP.Sport == nil || rec.TCP.Dport == nil {
		return
	}
	sport, dport := *rec.TCP.Sport, *rec.TCP.Dport
	if sport != 179 && dport != 179 {
		return
	}
	src, dst := rec.IP.Src, rec.IP.Dst
	t, n, flags := rec.T, rec.N, rec.TCP.Flags
	sess := a.session(src, dst)
	sess.overGRE = sess.overGRE || tunneled
	if !sess.hasTime {
		sess.hasTime = true
		sess.firstT = t
	}
	sess.lastT = t

	ck := orderedConnKey(src, sport, dst, dport)
	conns := a.connections[ck]
	synOnly := (flags&0x02) != 0 && (flags&0x10) == 0
	if len(conns) == 0 || (synOnly && (conns[len(conns)-1].closed || conns[len(conns)-1].hasEstab)) {
		c := &bgpConnection{
			firstT:      t,
			finFrom:     make(map[string]bool),
			opens:       make(map[string]bgpOpenData),
			kaAfterOpen: make(map[string]bool),
			lastMsgT:    make(map[string]float64),
			lastMsgN:    make(map[string]int),
			maxGap:      make(map[string]float64),
			synMSS:      make(map[string]*int),
			synFrames:   make(map[string]int),
		}
		conns = append(conns, c)
		a.connections[ck] = conns
		sess.connections = append(sess.connections, c)
	}
	conn := conns[len(conns)-1]
	model.AddFrame(&conn.frames, n)

	if synOnly {
		if conn.synFrom == nil {
			s := src
			conn.synFrom = &s
		}
		conn.synCount++
	} else if (flags&0x02) != 0 && (flags&0x10) != 0 {
		conn.synack = true
	}
	if (flags & 0x02) != 0 {
		if _, seen := conn.synMSS[src]; !seen {
			conn.synOrder = append(conn.synOrder, src)
			conn.synMSS[src] = rec.TCP.MSS
			conn.synFrames[src] = n
		}
	}
	if (flags & 0x04) != 0 {
		s := src
		conn.rstFrom = &s
		a.closeConn(sess, conn, t, n, "TCP RST from "+src, "tcp_rst")
	}
	if (flags & 0x01) != 0 {
		conn.finFrom[src] = true
		a.closeConn(sess, conn, t, n, "TCP FIN from "+src, "tcp_fin")
	}

	hasUpdate := false
	for i := range rec.BGP {
		a.messages++
		if rec.BGP[i].Type == 2 {
			hasUpdate = true
		}
		a.feedMessage(rec, sess, conn, src, dst, &rec.BGP[i])
	}
	if hasUpdate {
		a.feedUpdateCounts(rec, sess, src)
	}
}

// closeConn marks a BGP TCP connection closed and records a session down transition if established.
func (a *BgpAnalyzer) closeConn(sess *bgpSessionState, conn *bgpConnection, t float64, n int, reason, cause string) {
	if conn.closed {
		return
	}
	conn.closed = true
	if conn.hasEstab && !conn.hasDown {
		conn.hasDown = true
		conn.downT = t
		if conn.downReason == nil {
			r := reason
			conn.downReason = &r
		}
		if conn.downCause == "" {
			conn.downCause = cause
		}
		f := n
		conn.downFrame = &f
		sess.downs++
		sess.events = append(sess.events, bgpSessionEvent{
			kind: "down", t: t, frame: n,
			detail: fmtDownDetail(conn.downReason),
		})
	}
}

// allUpdates returns all buffered updates (up to 200 per speaker) for convergence analysis.
func (a *BgpAnalyzer) allUpdates(peers [2]string) map[string][]BGPUpdateSample {
	sess, ok := a.sessions[peers]
	if !ok {
		return nil
	}
	out := make(map[string][]BGPUpdateSample, len(sess.speakers))
	for _, ip := range sess.speakerOrder {
		sp := sess.speakers[ip]
		if len(sp.updates) > 0 {
			out[ip] = slices.Clone(sp.updates)
		}
	}
	return out
}
