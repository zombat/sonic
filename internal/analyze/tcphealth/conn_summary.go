// Package tcphealth summarizes per-connection RTT/RTO metrics and connection verdicts.
package tcphealth

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// computeRTO computes RFC 6298 SRTT, RTTVAR, and RTO estimates from millisecond RTT samples.
func computeRTO(samples []float64) (*RTTSummary, *float64, *float64, *float64) {
	if len(samples) == 0 {
		return nil, nil, nil, nil
	}
	srtt := samples[0]
	rttvar := samples[0] / 2.0
	for _, r := range samples[1:] {
		rttvar = 0.75*rttvar + 0.25*math.Abs(srtt-r)
		srtt = 0.875*srtt + 0.125*r
	}
	minR, maxR := samples[0], samples[0]
	for _, r := range samples[1:] {
		if r < minR {
			minR = r
		}
		if r > maxR {
			maxR = r
		}
	}
	med := model.Median(samples)
	p95 := model.Percentile(samples, 0.95)
	summary := &RTTSummary{
		Min:     model.Round(minR, 3),
		Median:  model.Round(*med, 3),
		P95:     model.Round(*p95, 3),
		Max:     model.Round(maxR, 3),
		Samples: len(samples),
	}
	srttR := model.Round(srtt, 3)
	rfcRTO := model.Round(max(1000.0, srtt+4*rttvar), 1)
	linRTO := model.Round(max(200.0, srtt+4*rttvar), 1)
	return summary, &srttR, &rfcRTO, &linRTO
}

// summarizeConnection builds the directional metrics, handshake timing, and verdict for one TCP connection.
func (d *Detector) summarizeConnection(ctx model.Context, conn *tcpConnTrack, endT float64) ConnectionEntry {
	client, server := conn.a, conn.b
	if conn.hasClient {
		client = conn.client
	}
	if conn.hasServer {
		server = conn.server
	}
	dirs := make(map[string]DirectionMetrics)
	dirNames := make([]string, 0, 2)
	for _, item := range []struct {
		name string
		ep   tcpEp
	}{
		{"client_to_server", client},
		{"server_to_client", server},
	} {
		dt := conn.dirs[item.ep]
		if dt == nil {
			continue
		}
		zwTotal := dt.zwTotal
		if dt.hasZWStart {
			zwTotal += endT - dt.zwStart
		}
		rttSum, srttR, rfcRTO, linRTO := computeRTO(dt.rtt)
		var obsRTO *ObservedRTO
		if len(dt.rtoObserved) > 0 {
			minO, maxO := dt.rtoObserved[0], dt.rtoObserved[0]
			for _, v := range dt.rtoObserved[1:] {
				if v < minO {
					minO = v
				}
				if v > maxO {
					maxO = v
				}
			}
			medO := model.Median(dt.rtoObserved)
			obsRTO = &ObservedRTO{
				Min: model.Round(minO, 1), Median: model.Round(*medO, 1), Max: model.Round(maxO, 1),
			}
		}
		dirs[item.name] = DirectionMetrics{
			From: model.Endpoint(item.ep.ip, &item.ep.port), SegmentsWithData: dt.segments,
			Bytes: dt.bytes, MSS: dt.mss, WindowScale: dt.ws, SACKPermitted: dt.sack,
			Timestamps: dt.ts, Retransmissions: dt.retrans, FastRetransmissions: dt.fastRetrans,
			TimeoutRetransmissions: dt.timeoutRet, ObservedRTOMs: obsRTO,
			GapsBeforeCapturePoint: dt.gaps, GapBytes: int(dt.gapBytes), OutOfOrder: dt.ooo,
			DuplicateACKsSent: dt.dupacks, DuplicateACKRunsOf3: dt.dupackRuns,
			ZeroWindowAdv: dt.zeroWindow, ZeroWindowSeconds: model.Round(zwTotal, 3),
			ZeroWindowOpenAtEnd: dt.hasZWStart, WindowFullEvents: dt.windowFull,
			RTTMs: rttSum, SRTTMs: srttR, RFC6298RTOMs: rfcRTO, LinuxRTOMs: linRTO,
			Frames: DirectionFrames{
				Retransmissions: dt.framesRetrans, Gaps: dt.framesGap, DuplicateACKs: dt.framesDup,
				ZeroWindow: dt.framesZero, WindowFull: dt.framesFull,
			},
		}
		dirNames = append(dirNames, item.name)
	}

	var serverRST []rstEvent
	for _, r := range conn.rst {
		if r.from == server {
			serverRST = append(serverRST, r)
		}
	}

	var frames []int
	conditions := []string{}
	verdict, detail := "", ""
	if conn.syn != nil && conn.synack == nil && !conn.spoke[server] {
		if len(serverRST) > 0 {
			verdict = "refused"
			detail = fmt.Sprintf("%s answered the SYN with RST: nothing listening, or a firewall rejecting the connection",
				model.Endpoint(server.ip, &server.port))
			frames = []int{conn.syn.frames[0], serverRST[0].n}
		} else {
			verdict = "no_answer"
			detail = fmt.Sprintf("%d SYN(s) from %s, no SYN-ACK seen at this capture point: the server is down, a filter drops it silently, or the reply returns by another path",
				conn.syn.count, model.Endpoint(client.ip, &client.port))
			frames = append(frames, conn.syn.frames...)
			if ref, ok := d.icmpRefs[icmpRefKey{src: client.ip, dst: server.ip, hasDport: true, dport: server.port}]; ok {
				tName, cText := model.ICMPDescribe(ref.v6, ref.icmpType, ref.code)
				detail += fmt.Sprintf("; %s answered with ICMP %s (%s)", ref.from, tName, cText)
				frames = append(frames, ref.frames...)
			}
		}
	} else {
		var zeroList []tcpEp
		lossTotal, fullTotal := 0, 0
		for _, ep := range conn.dirOrder {
			dt := conn.dirs[ep]
			if dt.zeroWindow > 0 {
				zeroList = append(zeroList, ep)
			}
			lossTotal += dt.retrans + dt.gaps + dt.dupackRuns
			fullTotal += dt.windowFull
		}
		if len(zeroList) > 0 {
			bestEP := zeroList[0]
			for _, ep := range zeroList[1:] {
				if conn.dirs[ep].zwTotal > conn.dirs[bestEP].zwTotal {
					bestEP = ep
				}
			}
			dt := conn.dirs[bestEP]
			verdict = "receiver_buffer_exhausted"
			totalZW := dt.zwTotal
			if dt.hasZWStart {
				totalZW += endT - dt.zwStart
			}
			openSuffix := ""
			if dt.hasZWStart {
				openSuffix = ", still closed at capture end"
			}
			detail = fmt.Sprintf("the endpoint's receive buffer is exhausted: %s advertised a zero window %d time(s), %s s in total%s; the application is not reading fast enough, the network is not the bottleneck",
				model.Endpoint(bestEP.ip, &bestEP.port), dt.zeroWindow, model.FormatPyFloat(model.Round(totalZW, 3)), openSuffix)
			frames = append(frames, dt.framesZero...)
		} else if lossTotal > 0 {
			verdict = "loss_on_path"
			var parts []string
			dupRuns := 0
			for _, dName := range dirNames {
				dm := dirs[dName]
				var bits []string
				if dm.Retransmissions > 0 {
					t := fmt.Sprintf("%d retransmission(s) (%d fast, %d after timeout",
						dm.Retransmissions, dm.FastRetransmissions, dm.TimeoutRetransmissions)
					if dm.ObservedRTOMs != nil {
						t += fmt.Sprintf(", timeout ~%s ms", model.FormatPyFloat(dm.ObservedRTOMs.Median))
					}
					bits = append(bits, t+")")
				}
				if dm.GapsBeforeCapturePoint > 0 {
					bits = append(bits, fmt.Sprintf("%d gap(s) lost before this capture point", dm.GapsBeforeCapturePoint))
				}
				if len(bits) > 0 {
					parts = append(parts, fmt.Sprintf("%s sent %s", dm.From, strings.Join(bits, ", ")))
					frames = append(frames, dm.Frames.Retransmissions...)
					frames = append(frames, dm.Frames.Gaps...)
				}
			}
			for _, ep := range conn.dirOrder {
				dupRuns += conn.dirs[ep].dupackRuns
			}
			detail = "loss on the path: " + strings.Join(parts, "; ")
			if dupRuns > 0 {
				detail += fmt.Sprintf("; %d run(s) of 3+ duplicate ACKs", dupRuns)
			}
		} else if fullTotal > 0 {
			verdict = "receive_window_limited"
			detail = fmt.Sprintf("bytes in flight reached the receiver's advertised window %d time(s): throughput is capped by the receive window (raise the buffer or window scaling), not by loss", fullTotal)
			for _, ep := range conn.dirOrder {
				frames = append(frames, conn.dirs[ep].framesFull...)
			}
		} else if len(conn.rst) > 0 {
			verdict = "reset"
			r := conn.rst[0]
			detail = fmt.Sprintf("reset by %s after %d byte(s) from it", model.Endpoint(r.from.ip, &r.from.port), r.afterBytes)
			frames = []int{r.n}
		} else {
			verdict = "healthy"
			detail = "no retransmissions, gaps, zero windows or resets seen"
		}
		if conn.syn != nil && conn.syn.count > 1 {
			conditions = append(conditions, fmt.Sprintf("%d SYN retransmission(s)", conn.syn.count-1))
		}
		if conn.syn != nil && conn.synack == nil {
			conditions = append(conditions, "SYN-ACK not seen at this capture point although the server answered later (it took another path, or the capture missed it)")
		}
	}
	if len(conn.rst) > 0 && verdict != "refused" && verdict != "reset" {
		r := conn.rst[0]
		conditions = append(conditions, fmt.Sprintf("reset by %s", model.Endpoint(r.from.ip, &r.from.port)))
	}

	var hs *HandshakeInfo
	if conn.syn != nil {
		var synackFrame *int
		var toSrv, toCli *float64
		if conn.synack != nil {
			f := conn.synack.n
			synackFrame = &f
			srvMs := model.Round((conn.synack.t-conn.syn.lastT)*1000.0, 3)
			toSrv = &srvMs
			if conn.hasHSAck {
				cliMs := model.Round((conn.hsAckT-conn.synack.t)*1000.0, 3)
				toCli = &cliMs
			}
		}
		hs = &HandshakeInfo{
			SynFrames: conn.syn.frames, SynCount: conn.syn.count, SynAckFrame: synackFrame,
			CapturePointToServer: toSrv, CapturePointToClient: toCli,
		}
	}

	return ConnectionEntry{
		Client: model.Endpoint(client.ip, &client.port), Server: model.Endpoint(server.ip, &server.port),
		HandshakeSeen: conn.syn != nil, OverGRE: conn.tunneled, Verdict: verdict, Detail: detail,
		OtherConditions: conditions, Packets: conn.packets,
		FirstT: ctx.Rel(&conn.firstT), LastT: ctx.Rel(&conn.lastT),
		Handshake: hs, Directions: dirs, Frames: dedupSortedFrames(frames),
	}
}

// dedupSortedFrames deduplicates and sorts frame numbers capped at model.MaxFrames.
func dedupSortedFrames(in []int) []int {
	if len(in) == 0 {
		return []int{}
	}
	set := make(map[int]bool, len(in))
	out := make([]int, 0, len(in))
	for _, f := range in {
		if !set[f] {
			set[f] = true
			out = append(out, f)
		}
	}
	slices.Sort(out)
	if len(out) > model.MaxFrames {
		out = out[:model.MaxFrames]
	}
	return out
}
