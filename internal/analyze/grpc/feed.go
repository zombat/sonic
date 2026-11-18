// Package grpc feeds HTTP/2 PDML packets into per-connection gRPC state tracking.
package grpc

import "github.com/zombat/sonic/internal/extract"

type grpcAnalysis struct {
	disc          map[int]*extract.TCPConnection
	conns         map[int]*connTrack
	packets       int
	start         *float64
	end           *float64
	secretsSource string
}

func newGrpcAnalysis(disc map[int]*extract.TCPConnection, secretsSource string) *grpcAnalysis {
	if secretsSource == "" {
		secretsSource = "the key log"
	}
	return &grpcAnalysis{
		disc:          disc,
		conns:         make(map[int]*connTrack),
		secretsSource: secretsSource,
	}
}

func newConnTrack(index int, disc *extract.TCPConnection) *connTrack {
	ct := &connTrack{
		index:            index,
		disc:             disc,
		framesByType:     make(map[string]int),
		settingsClient:   make(map[string]*int),
		settingsServer:   make(map[string]*int),
		rpcs:             make(map[int]*rpcTrack),
		pendingPings:     make(map[pingKey]float64),
		connWindowClient: defaultWindow,
		connWindowServer: defaultWindow,
		streamWindow:     make(map[stallKey]int),
		openStall:        make(map[stallKey]*stallTrack),
		credentials:      make(map[string]*credTrack),
		metadataKeys:     make(map[string]int),
	}
	if disc != nil {
		if disc.Client != nil {
			ep := *disc.Client
			ct.client = &ep
		}
		if disc.Server != nil {
			ep := *disc.Server
			ct.server = &ep
		}
		ct.serverKnownBy = disc.ServerKnownBy
		if ct.server == nil {
			ct.serverKnownBy = "port"
			port := disc.ServicePort()
			if disc.A.Port == port {
				srv, cli := disc.A, disc.B
				ct.server, ct.client = &srv, &cli
			} else {
				srv, cli := disc.B, disc.A
				ct.server, ct.client = &srv, &cli
			}
		}
		ct.trackFlow = disc.SynFrame != nil || disc.PrefaceFrame != nil
	}
	return ct
}

func (c *connTrack) sideOf(src string, sport *int) string {
	if sport == nil {
		return "unknown"
	}
	ep := extract.Endpoint{IP: src, Port: *sport}
	if c.server != nil && ep == *c.server {
		return "server"
	}
	if c.client != nil && ep == *c.client {
		return "client"
	}
	return "unknown"
}

func peerSide(side string) string {
	if side == "client" {
		return "server"
	}
	return "client"
}

func (c *connTrack) receiverSetting(sender, name string, def *int) *int {
	target := c.settingsClient
	if peerSide(sender) == "server" {
		target = c.settingsServer
	}
	if v, ok := target[name]; ok && v != nil {
		return v
	}
	return def
}

func (c *connTrack) connWindow(side string) int {
	if side == "client" {
		return c.connWindowClient
	}
	return c.connWindowServer
}

func (c *connTrack) addConnWindow(side string, delta int) {
	if side == "client" {
		c.connWindowClient += delta
	} else {
		c.connWindowServer += delta
	}
}

func (a *grpcAnalysis) connFor(streamIdx int) *connTrack {
	if c, ok := a.conns[streamIdx]; ok {
		return c
	}
	c := newConnTrack(streamIdx, a.disc[streamIdx])
	a.conns[streamIdx] = c
	return c
}

func (a *grpcAnalysis) feed(pkt *extract.HTTP2Packet) {
	a.packets++
	t, n := pkt.T, pkt.N
	if a.start == nil || t < *a.start {
		v := t
		a.start = &v
	}
	if a.end == nil || t > *a.end {
		v := t
		a.end = &v
	}
	conn := a.connFor(pkt.TCPStream)
	if conn.firstFrame == nil {
		nf := n
		tv := t
		conn.firstFrame = &nf
		conn.firstT = &tv
	}
	lt := t
	conn.lastT = &lt
	conn.tlsSeen = conn.tlsSeen || pkt.TLS
	side := conn.sideOf(pkt.Src, pkt.Sport)
	if side == "unknown" {
		side = a.inferSide(conn, pkt)
	}
	switch side {
	case "client":
		conn.packetsClient++
	case "server":
		conn.packetsServer++
	default:
		conn.packetsUnknown++
	}

	defMax := defaultMaxFrame
	for i := range pkt.Frames {
		fr := &pkt.Frames[i]
		conn.framesByType[fr.Type]++
		if fr.Type == "MAGIC" {
			if conn.magicFrame == nil {
				mf := n
				conn.magicFrame = &mf
			}
			conn.trackFlow = true
			continue
		}
		maxFrame := *conn.receiverSetting(side, "max_frame_size", &defMax)
		if fr.Length > maxFrame && len(conn.oversizeFrames) < 10 {
			sid := fr.StreamID
			conn.oversizeFrames = append(conn.oversizeFrames, OversizeFrameRow{
				From: side, Type: fr.Type, Length: fr.Length,
				PeerMaxFrameSize: maxFrame, Frame: n, StreamID: &sid,
			})
		}
		switch fr.Type {
		case "SETTINGS":
			a.onSettings(conn, side, fr, n)
		case "HEADERS":
			a.onHeaders(conn, side, fr, n, t)
		case "DATA":
			a.onData(conn, side, fr, n, t)
		case "WINDOW_UPDATE":
			a.onWindowUpdate(conn, side, fr, n, t)
		case "RST_STREAM":
			a.onRstStream(conn, side, fr, n, t)
		case "GOAWAY":
			a.onGoaway(conn, side, fr, n, t)
		case "PING":
			a.onPing(conn, side, fr, n, t)
		}
	}
	for i := range pkt.Protobuf {
		a.onProtobuf(conn, &pkt.Protobuf[i], n)
	}
}

func (a *grpcAnalysis) inferSide(conn *connTrack, pkt *extract.HTTP2Packet) string {
	sport, dport := 0, 0
	if pkt.Sport != nil {
		sport = *pkt.Sport
	}
	if pkt.Dport != nil {
		dport = *pkt.Dport
	}
	srcEP := extract.Endpoint{IP: pkt.Src, Port: sport}
	dstEP := extract.Endpoint{IP: pkt.Dst, Port: dport}
	for _, fr := range pkt.Frames {
		if fr.Type == "MAGIC" {
			conn.client, conn.server = &srcEP, &dstEP
			return "client"
		}
		for _, h := range fr.Headers {
			if h.Name == ":method" || h.Name == ":path" {
				conn.client, conn.server = &srcEP, &dstEP
				return "client"
			}
		}
		for _, h := range fr.Headers {
			if h.Name == ":status" {
				conn.server, conn.client = &srcEP, &dstEP
				return "server"
			}
		}
	}
	return "unknown"
}
