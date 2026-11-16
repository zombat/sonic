// Package tcphealth processes individual TCP segments, acknowledgments,
// retransmission classification, and receive-window telemetry.
package tcphealth

import "github.com/zombat/sonic/internal/model"

func (d *Detector) processSegment(conn *tcpConnTrack, rec *model.Record, src, dst tcpEp, tcp *model.TCPHeader, dtcp *model.DPTCP) {
	t, n, flags := rec.T, rec.N, tcp.Flags
	seq, plen := dtcp.Seq, tcp.Len
	out := conn.dirs[src]
	if (flags & flagSYN) != 0 {
		if out == nil || !out.hasBase || out.segments == 0 {
			out = newDirectionTrack(seq)
			if _, exists := conn.dirs[src]; !exists {
				conn.dirOrder = append(conn.dirOrder, src)
			}
			conn.dirs[src] = out
		}
		out.mss, out.ws, out.sack, out.ts = dtcp.MSS, dtcp.WS, dtcp.SACK, dtcp.TS
		if (flags & flagACK) == 0 {
			if !conn.hasClient {
				conn.hasClient, conn.client = true, src
			}
			if !conn.hasServer {
				conn.hasServer, conn.server = true, dst
			}
			if conn.syn == nil {
				conn.syn = &synTrack{count: 1, firstT: t, lastT: t, frames: []int{n}}
			} else {
				conn.syn.count++
				conn.syn.lastT = t
				model.AddFrame(&conn.syn.frames, n)
			}
		} else if conn.synack == nil {
			conn.synack = &synAckTrack{t: t, n: n, count: 1}
			if !conn.hasServer {
				conn.hasServer, conn.server = true, src
			}
			if !conn.hasClient {
				conn.hasClient, conn.client = true, dst
			}
		} else {
			conn.synack.count++
		}
	}
	if out == nil {
		// Midstream flow: treat the byte before the first observed sequence as base.
		out = newDirectionTrack(seq - 1)
		conn.dirOrder = append(conn.dirOrder, src)
		conn.dirs[src] = out
	}
	peer := conn.dirs[dst]
	if (flags & flagRST) == 0 {
		conn.spoke[src] = true
	}
	if (flags & flagRST) != 0 {
		conn.rst = append(conn.rst, rstEvent{from: src, t: t, n: n, afterBytes: out.bytes})
	}
	if (flags & flagFIN) != 0 {
		if _, seen := conn.fin[src]; !seen {
			conn.fin[src] = t
		}
	}
	if (flags&flagACK) != 0 && peer != nil {
		if conn.synack != nil && !conn.hasHSAck && conn.hasClient && src == conn.client && (flags&flagSYN) == 0 {
			conn.hasHSAck = true
			conn.hsAckT = t
		}
		d.processACK(rec, out, peer, dtcp, flags, plen)
	}
	if (flags & (flagSYN | flagRST)) == 0 {
		d.processWindow(conn, rec, out, peer, dtcp)
	}
	if plen > 0 {
		d.processData(conn, rec, out, peer, seq, plen)
	} else if (flags & flagFIN) != 0 {
		rel := model.SeqDelta(seq, out.base)
		if rel+1 > out.maxEnd {
			out.maxEnd = rel + 1
		}
	}
}

func (d *Detector) processData(conn *tcpConnTrack, rec *model.Record, out, peer *directionTrack, seq uint32, plen int) {
	t, n := rec.T, rec.N
	rel := model.SeqDelta(seq, out.base)
	out.segments++
	out.bytes += plen

	if lastT, dup := out.seen.vals[rel]; dup {
		out.retrans++
		model.AddFrame(&out.framesRetrans, n)
		if out.dupacksFor[rel] >= 2 {
			out.fastRetrans++
		} else {
			out.timeoutRet++
			if len(out.rtoObserved) < 1000 {
				out.rtoObserved = append(out.rtoObserved, (t-lastT)*1000.0)
			}
		}
		out.seen.set(rel, t, maxSeenSegments)
		// Karn's rule: never sample RTT for retransmitted data.
		out.pending.del(rel + int64(plen))
		if conn.eventsCnt < 6 && out.retrans == 1 {
			conn.eventsCnt++
			conn.eventList = append(conn.eventList, connEventItem{kind: "retransmission", t: t, n: n})
		}
		return
	}

	if rel < out.maxEnd {
		out.ooo++
	} else if rel > out.maxEnd && out.segments > 1 {
		out.gaps++
		out.gapBytes += rel - out.maxEnd
		model.AddFrame(&out.framesGap, n)
	}

	out.seen.set(rel, t, maxSeenSegments)
	out.pending.set(rel+int64(plen), t, maxRTTPending)
	if rel+int64(plen) > out.maxEnd {
		out.maxEnd = rel + int64(plen)
	}

	if peer != nil && peer.hasWinScaled && out.hasAcked {
		inFlight := out.maxEnd - out.acked
		if peer.winScaled > 0 && inFlight >= peer.winScaled {
			out.windowFull++
			model.AddFrame(&out.framesFull, n)
		}
	}
}

func (d *Detector) processACK(rec *model.Record, out, peer *directionTrack, dtcp *model.DPTCP, flags, plen int) {
	if !peer.hasBase {
		return
	}
	ackRel := model.SeqDelta(dtcp.Ack, peer.base)
	if sentT, ok := peer.pending.vals[ackRel]; ok && len(peer.rtt) < maxRTTSamples {
		peer.rtt = append(peer.rtt, (rec.T-sentT)*1000.0)
	}
	peer.pending.popFrontLE(ackRel)

	pure := plen == 0 && (flags&(flagSYN|flagFIN|flagRST)) == 0
	outstanding := ackRel < peer.maxEnd
	if pure && outstanding && out.hasLastACK && out.lastACK == dtcp.Ack && out.hasLastWin && out.lastWin == dtcp.Win {
		out.dupacks++
		out.dupRun++
		model.AddFrame(&out.framesDup, rec.N)
		if _, exists := peer.dupacksFor[ackRel]; !exists {
			peer.dupackOrder = append(peer.dupackOrder, ackRel)
		}
		peer.dupacksFor[ackRel]++
		if len(peer.dupacksFor) > maxRTTPending && len(peer.dupackOrder) > 0 {
			oldest := peer.dupackOrder[0]
			peer.dupackOrder = peer.dupackOrder[1:]
			delete(peer.dupacksFor, oldest)
		}
		if out.dupRun == 3 {
			out.dupackRuns++
		}
	} else {
		out.dupRun = 0
	}
	out.hasLastACK, out.lastACK = true, dtcp.Ack
	out.hasLastWin, out.lastWin = true, dtcp.Win
	if !peer.hasAcked || ackRel > peer.acked {
		peer.hasAcked, peer.acked = true, ackRel
	}
}

func (d *Detector) processWindow(conn *tcpConnTrack, rec *model.Record, out, peer *directionTrack, dtcp *model.DPTCP) {
	win := dtcp.Win
	if peer != nil && out.ws != nil && peer.ws != nil {
		out.hasWinScaled = true
		out.winScaled = int64(win) << uint(*out.ws)
	} else if conn.syn != nil && conn.synack != nil {
		out.hasWinScaled = true
		out.winScaled = int64(win)
	} else {
		out.hasWinScaled = false
	}

	if win == 0 {
		if !out.hasZWStart {
			out.hasZWStart = true
			out.zwStart = rec.T
			out.zeroWindow++
			model.AddFrame(&out.framesZero, rec.N)
			if conn.eventsCnt < 6 {
				conn.eventsCnt++
				conn.eventList = append(conn.eventList, connEventItem{kind: "zero_window", t: rec.T, n: rec.N})
			}
		}
	} else if out.hasZWStart {
		out.zwTotal += rec.T - out.zwStart
		out.hasZWStart = false
	}
}
