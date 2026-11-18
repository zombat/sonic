// Package tlsinspect stream reassembly and TLS record/handshake state machine.
package tlsinspect

import (
	"encoding/binary"
	"encoding/hex"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// tcpStream reassembles the first maxStreamBytes of one TCP direction for TLS record parsing.
type tcpStream struct {
	base      uint32
	buf       []byte
	pending   map[int64][]byte
	pos       int
	hs        []byte
	encrypted bool
	done      bool
	full      bool
}

// newTCPStream initializes a reassembly buffer anchored at TCP sequence base.
func newTCPStream(base uint32) *tcpStream {
	return &tcpStream{
		base:    base,
		pending: make(map[int64][]byte),
	}
}

// add appends in-order bytes or caches out-of-order segments up to maxPendingSegments.
func (s *tcpStream) add(seq uint32, payload []byte, truncated bool) {
	rel := model.SeqDelta(seq, s.base)
	if rel > int64(len(s.buf)) {
		if len(s.pending) < maxPendingSegments {
			s.pending[rel] = slices.Clone(payload)
		}
		return
	}
	if rel+int64(len(payload)) > int64(len(s.buf)) {
		offset := int64(len(s.buf)) - rel
		s.buf = append(s.buf, payload[offset:]...)
	}
	for {
		part, ok := s.pending[int64(len(s.buf))]
		if !ok {
			break
		}
		delete(s.pending, int64(len(s.buf)))
		s.buf = append(s.buf, part...)
	}
	if truncated || len(s.buf) >= maxStreamBytes {
		// Parse buffered prefix bytes and close reassembly afterward.
		s.full = true
	}
}

// sessionState accumulates parsed handshake messages, alerts, and frames for one TLS session.
type sessionState struct {
	client            addrEndpoint
	server            addrEndpoint
	clientHello       *ClientHello
	serverHello       *ServerHello
	helloRetryRequest bool
	certificate       *CertificateInfo
	alerts            []AlertRecord
	frames            map[string]int
	firstT            float64
	serverHelloT      *float64
	serverSpokeTLS    bool
}

// Detector reassembles TCP TLS flows, inspects handshakes and alerts, and checks baselines.
type Detector struct {
	baseline *Baseline
	streams  map[flowKey]*tcpStream
	sessions map[sessionKey]*sessionState
	order    []sessionKey
	ignored  map[flowKey]bool
	dropped  int
}

// NewDetector creates a TLS Detector checked against optional policy baseline rules.
func NewDetector(baseline *Baseline) *Detector {
	return &Detector{
		baseline: baseline,
		streams:  make(map[flowKey]*tcpStream),
		sessions: make(map[sessionKey]*sessionState),
		ignored:  make(map[flowKey]bool),
	}
}

// Present reports whether at least one TLS session or alert stream was observed.
func (d *Detector) Present() bool {
	return len(d.sessions) > 0
}

// Feed ingests a single normalized packet record into the TLS detector.
func (d *Detector) Feed(rec *model.Record) {
	view := model.Transport(rec)
	if view == nil || view.TCP == nil || view.DTCP == nil || rec.DP == nil || rec.DP.PL == "" {
		return
	}
	payload, err := hex.DecodeString(rec.DP.PL)
	if err != nil || len(payload) == 0 {
		return
	}

	src := makeEndpoint(view.Src, view.TCP.Sport)
	dst := makeEndpoint(view.Dst, view.TCP.Dport)
	key := flowKey{src: src, dst: dst}
	if d.ignored[key] {
		return
	}

	st, ok := d.streams[key]
	if !ok {
		if len(payload) < 3 || (payload[0] != 0x15 && payload[0] != 0x16) || payload[1] != 3 || payload[2] > 4 {
			d.ignored[key] = true
			return
		}
		if len(d.streams) >= maxStreams {
			d.dropped++
			return
		}
		st = newTCPStream(view.DTCP.Seq)
		d.streams[key] = st
	}
	if st.done {
		return
	}

	st.add(view.DTCP.Seq, payload, view.TCP.Len > len(payload))
	d.parseRecords(st, src, dst, rec)
	if st.full && !st.done {
		st.done = true
		st.buf = nil
		clear(st.pending)
	}
}

// getSession retrieves or creates the sessionState for (src, dst) oriented by clientSide.
func (d *Detector) getSession(src, dst addrEndpoint, rec *model.Record, clientSide bool) *sessionState {
	client, server := src, dst
	if !clientSide {
		client, server = dst, src
	}
	key := sessionKey{client: client, server: server}
	if sess, ok := d.sessions[key]; ok {
		return sess
	}
	sess := &sessionState{
		client: client,
		server: server,
		frames: make(map[string]int),
		firstT: rec.T,
	}
	d.sessions[key] = sess
	d.order = append(d.order, key)
	return sess
}

// findSession finds an existing session for either flow direction or creates a client-initiated entry.
func (d *Detector) findSession(src, dst addrEndpoint, rec *model.Record) *sessionState {
	if sess, ok := d.sessions[sessionKey{client: src, server: dst}]; ok {
		return sess
	}
	if sess, ok := d.sessions[sessionKey{client: dst, server: src}]; ok {
		return sess
	}
	return d.getSession(src, dst, rec, true)
}

// lookupPairSession looks up an existing session matching (src, dst) in either orientation without creating one.
func (d *Detector) lookupPairSession(src, dst addrEndpoint) *sessionState {
	if sess, ok := d.sessions[sessionKey{client: src, server: dst}]; ok {
		return sess
	}
	return d.sessions[sessionKey{client: dst, server: src}]
}

// parseRecords walks complete TLS record frames buffered in st and updates handshake/alert state.
func (d *Detector) parseRecords(st *tcpStream, src, dst addrEndpoint, rec *model.Record) {
	for !st.done && st.pos+5 <= len(st.buf) {
		ctype := st.buf[st.pos]
		length := int(binary.BigEndian.Uint16(st.buf[st.pos+3 : st.pos+5]))
		if (ctype != 20 && ctype != 21 && ctype != 22 && ctype != 23) || length > maxRecordLen {
			st.done = true
			break
		}
		if st.pos+5+length > len(st.buf) {
			break
		}
		body := st.buf[st.pos+5 : st.pos+5+length]
		st.pos += 5 + length

		switch ctype {
		case 20:
			// TLS 1.3 middlebox ChangeCipherSpec precedes/follows HRR; transition only for pre-TLS1.3 handshakes.
			sess := d.lookupPairSession(src, dst)
			if sess != nil && sess.serverHello != nil && sess.serverHello.Version != "" && sess.serverHello.Version != "TLS1.3" {
				st.encrypted = true
			}
		case 23:
			st.done = true
		case 21:
			sess := d.findSession(src, dst, rec)
			if !st.encrypted && len(body) == 2 {
				level := "warning"
				if body[0] == 2 {
					level = "fatal"
				}
				sess.alerts = append(sess.alerts, AlertRecord{
					From:        src.format(),
					Level:       level,
					Description: alertDescription(body[1]),
					Frame:       rec.N,
					t:           rec.T,
				})
			} else {
				sess.alerts = append(sess.alerts, AlertRecord{
					From:        src.format(),
					Level:       "encrypted",
					Description: "encrypted alert (content not visible)",
					Frame:       rec.N,
					t:           rec.T,
				})
			}
		case 22:
			if !st.encrypted {
				st.hs = append(st.hs, body...)
				d.parseHandshake(st, src, dst, rec)
			}
		}
	}
	if st.done {
		st.buf = nil
		clear(st.pending)
	}
}

// parseHandshake consumes complete TLS handshake messages from st.hs.
func (d *Detector) parseHandshake(st *tcpStream, src, dst addrEndpoint, rec *model.Record) {
	for len(st.hs) >= 4 {
		htype := st.hs[0]
		hlen := int(st.hs[1])<<16 | int(st.hs[2])<<8 | int(st.hs[3])
		if len(st.hs) < 4+hlen {
			break
		}
		body := slices.Clone(st.hs[4 : 4+hlen])
		st.hs = st.hs[4+hlen:]

		switch htype {
		case 1:
			sess := d.getSession(src, dst, rec, true)
			sess.clientHello = ParseClientHello(body)
			sess.frames["client_hello"] = rec.N
			if rec.T < sess.firstT {
				sess.firstT = rec.T
			}
		case 2:
			sess := d.getSession(src, dst, rec, false)
			parsed := ParseServerHello(body)
			sess.serverSpokeTLS = true
			if parsed != nil && parsed.HelloRetryRequest {
				sess.helloRetryRequest = true
				sess.frames["hello_retry_request"] = rec.N
				continue
			}
			sess.serverHello = parsed
			sess.frames["server_hello"] = rec.N
			tCopy := rec.T
			sess.serverHelloT = &tCopy
			if parsed != nil && parsed.Version == "TLS1.3" {
				st.encrypted = true
				st.done = true
				return
			}
		case 11:
			sess := d.getSession(src, dst, rec, false)
			cert := ParseCertificate(body, rec.T)
			sess.certificate = &cert
			sess.frames["certificate"] = rec.N
		case 14:
			// ServerHelloDone completes the cleartext server handshake flight in TLS <= 1.2.
			st.done = true
			return
		}
	}
}
