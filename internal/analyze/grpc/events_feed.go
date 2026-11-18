// Package grpc handles HTTP/2 DATA, flow-control, RST_STREAM, GOAWAY, PING, and protobuf frames.
package grpc

import (
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func (a *grpcAnalysis) onData(conn *connTrack, side string, fr *extract.HTTP2Frame, n int, t float64) {
	sid := fr.StreamID
	rpc := a.rpc(conn, sid, n, t, false)
	if rpc != nil && (side == "client" || side == "server") {
		if side == "client" {
			rpc.clientFramer.feed(fr.Data, fr.DataLen, n, t)
		} else {
			rpc.serverFramer.feed(fr.Data, fr.DataLen, n, t)
			if rpc.tFirstResponse == nil {
				tv := t
				rpc.tFirstResponse = &tv
				rpc.frames["first_response"] = n
			}
		}
		if fr.EndStream {
			if side == "client" {
				rpc.clientEnded = true
			} else {
				rpc.serverEnded = true
				tv := t
				rpc.tEnd = &tv
			}
		}
	}
	if !conn.trackFlow || (side != "client" && side != "server") {
		return
	}
	conn.addConnWindow(side, -fr.Length)
	sk := stallKey{sender: side, streamID: sid}
	if _, ok := conn.streamWindow[sk]; ok {
		conn.streamWindow[sk] -= fr.Length
	}
	if st := conn.openStall[sk]; st != nil && st.reopenedT != nil {
		st.dataWaiting = true
		delete(conn.openStall, sk)
	}
	if fr.EndStream {
		return
	}
	exhausted := ""
	if conn.connWindow(side) <= 0 {
		exhausted = "connection"
	} else if win, ok := conn.streamWindow[sk]; ok && win <= 0 {
		exhausted = "stream"
	}
	if exhausted != "" && conn.openStall[sk] == nil {
		var meth *string
		if rpc != nil {
			meth = rpc.method()
		}
		st := &stallTrack{sender: side, streamID: sid, window: exhausted, frame: n, t: t, method: meth}
		conn.openStall[sk] = st
		conn.stalls = append(conn.stalls, st)
	}
}

func (a *grpcAnalysis) onWindowUpdate(conn *connTrack, side string, fr *extract.HTTP2Frame, n int, t float64) {
	if !conn.trackFlow || (side != "client" && side != "server") {
		return
	}
	sender := peerSide(side)
	if fr.StreamID == 0 {
		conn.addConnWindow(sender, fr.Increment)
	} else if _, ok := conn.streamWindow[stallKey{sender: sender, streamID: fr.StreamID}]; ok {
		conn.streamWindow[stallKey{sender: sender, streamID: fr.StreamID}] += fr.Increment
	}
	for k, st := range conn.openStall {
		if k.sender != sender || st.reopenedT != nil {
			continue
		}
		streamWin, hasStream := conn.streamWindow[k]
		if conn.connWindow(sender) > 0 && (!hasStream || streamWin > 0) {
			tv, nf := t, n
			st.reopenedT = &tv
			st.reopenedFrame = &nf
		}
	}
}

func (a *grpcAnalysis) closeStalls(conn *connTrack, sid int, t float64, why string) {
	for k, st := range conn.openStall {
		if k.streamID != sid {
			continue
		}
		delete(conn.openStall, k)
		if st.reopenedT == nil {
			w := why
			tv := t
			st.endedBy = &w
			st.endedT = &tv
		}
	}
}

func (a *grpcAnalysis) onRstStream(conn *connTrack, side string, fr *extract.HTTP2Frame, n int, t float64) {
	sid := fr.StreamID
	rpc := a.rpc(conn, sid, n, t, false)
	errStr := "code None"
	if fr.ErrorCode != nil {
		if name, ok := H2Errors[*fr.ErrorCode]; ok {
			errStr = name
		} else {
			errStr = fmt.Sprintf("code %d", *fr.ErrorCode)
		}
	}
	var meth *string
	if rpc != nil {
		meth = rpc.method()
	}
	entry := ResetInfo{From: side, StreamID: sid, ErrorCode: fr.ErrorCode, Error: errStr, Frame: n, Method: meth, t: t}
	if rpc != nil {
		ae := rpc.serverEnded
		entry.AfterEnd = &ae
	}
	conn.rstStreams = append(conn.rstStreams, entry)
	if rpc != nil && rpc.reset == nil {
		cp := entry
		rpc.reset = &cp
		rpc.serverEndedBeforeReset = rpc.serverEnded
		if rpc.tEnd == nil {
			tv := t
			rpc.tEnd = &tv
		}
	}
	a.closeStalls(conn, sid, t, "the stream was reset")
}

func (a *grpcAnalysis) onGoaway(conn *connTrack, side string, fr *extract.HTTP2Frame, n int, t float64) {
	errStr := "code None"
	if fr.ErrorCode != nil {
		if name, ok := H2Errors[*fr.ErrorCode]; ok {
			errStr = name
		} else {
			errStr = fmt.Sprintf("code %d", *fr.ErrorCode)
		}
	}
	conn.goaways = append(conn.goaways, GoawayRow{
		From: side, LastStreamID: fr.LastStreamID, ErrorCode: fr.ErrorCode,
		Error: errStr, DebugData: fr.DebugData, Frame: n, t: t,
	})
}

func (a *grpcAnalysis) onPing(conn *connTrack, side string, fr *extract.HTTP2Frame, n int, t float64) {
	if side != "client" && side != "server" {
		return
	}
	peer := peerSide(side)
	stats := &conn.pingsClient
	peerStats := &conn.pingsServer
	if side == "server" {
		stats = &conn.pingsServer
		peerStats = &conn.pingsClient
	}
	if fr.Ack {
		pk := pingKey{side: peer, opaque: fr.Opaque}
		if sent, ok := conn.pendingPings[pk]; ok {
			delete(conn.pendingPings, pk)
			peerStats.acked++
			if len(peerStats.rttMS) < 1000 {
				peerStats.rttMS = append(peerStats.rttMS, model.Round((t-sent)*1000, 3))
			}
		}
		return
	}
	stats.sent++
	if stats.firstFrame == nil {
		nf := n
		stats.firstFrame = &nf
	}
	if len(stats.times) < 1000 {
		stats.times = append(stats.times, t)
	}
	anyOpen := false
	for _, r := range conn.rpcs {
		if r.isOpen() {
			anyOpen = true
			break
		}
	}
	if !anyOpen {
		stats.idle++
	}
	conn.pendingPings[pingKey{side: side, opaque: fr.Opaque}] = t
}

func (a *grpcAnalysis) onProtobuf(conn *connTrack, proto *extract.ProtobufMsg, n int) {
	if proto.Path == nil || *proto.Path == "" {
		return
	}
	var best *rpcTrack
	bestDist := 0
	for _, r := range conn.rpcs {
		m := r.method()
		if m == nil || *m != *proto.Path {
			continue
		}
		rf := r.frames["request"]
		d := rf - n
		if d < 0 {
			d = -d
		}
		if best == nil || d < bestDist || (d == bestDist && r.streamID < best.streamID) {
			best = r
			bestDist = d
		}
	}
	if best == nil || len(best.protobuf) >= 20 {
		return
	}
	fields := []extract.ProtobufField{}
	if len(proto.Fields) > 0 {
		fields = slices.Clone(proto.Fields)
	}
	best.protobuf = append(best.protobuf, ProtobufView{
		Frame: n, Direction: proto.Direction, MessageType: proto.MessageType, Fields: fields,
	})
}
