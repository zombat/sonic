// Package grpc processes HTTP/2 SETTINGS and HEADERS/HPACK frames per stream.
package grpc

import (
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func (a *grpcAnalysis) onSettings(conn *connTrack, side string, fr *extract.HTTP2Frame, n int) {
	if fr.Ack || side == "unknown" {
		return
	}
	dst := conn.settingsClient
	if side == "server" {
		dst = conn.settingsServer
		if conn.settingsFrameSrv == nil {
			f := n
			conn.settingsFrameSrv = &f
		}
	} else if conn.settingsFrameCli == nil {
		f := n
		conn.settingsFrameCli = &f
	}
	oldInit := defaultWindow
	if v := dst["initial_window_size"]; v != nil {
		oldInit = *v
	}
	for k, v := range fr.Settings {
		if v != nil {
			val := *v
			dst[k] = &val
		} else {
			dst[k] = nil
		}
	}
	if v, ok := fr.Settings["initial_window_size"]; ok && v != nil {
		delta := *v - oldInit
		sender := peerSide(side)
		for key := range conn.streamWindow {
			if key.sender == sender {
				conn.streamWindow[key] += delta
			}
		}
	}
}

func (a *grpcAnalysis) rpc(conn *connTrack, sid, n int, t float64, create bool) *rpcTrack {
	rpc, ok := conn.rpcs[sid]
	if ok || !create {
		return rpc
	}
	tv := t
	rpc = &rpcTrack{
		conn:     conn,
		streamID: sid,
		frames:   map[string]int{"request": n},
		tRequest: &tv,
	}
	conn.rpcs[sid] = rpc
	defWin := defaultWindow
	for _, sender := range []string{"client", "server"} {
		initWin := *conn.receiverSetting(sender, "initial_window_size", &defWin)
		conn.streamWindow[stallKey{sender: sender, streamID: sid}] = initWin
	}
	openNow := 0
	for _, r := range conn.rpcs {
		if r.isOpen() {
			openNow++
		}
	}
	if openNow > conn.maxOpen {
		conn.maxOpen = openNow
		nf := n
		conn.maxOpenFrame = &nf
	}
	return rpc
}

func (a *grpcAnalysis) onHeaders(conn *connTrack, side string, fr *extract.HTTP2Frame, n int, t float64) {
	sid := fr.StreamID
	if fr.DecodeFailed {
		conn.hpackFailures = append(conn.hpackFailures, n)
	}
	isReq := side == "client"
	if !isReq {
		for _, h := range fr.Headers {
			if h.Name == ":method" {
				isReq = true
				break
			}
		}
	}
	rpc := a.rpc(conn, sid, n, t, isReq)
	if rpc == nil {
		rpc = a.rpc(conn, sid, n, t, true)
		delete(rpc.frames, "request")
		rpc.tRequest = nil
	}
	if fr.DecodeFailed {
		rpc.decodeFailed = true
	}
	if limit := conn.receiverSetting(side, "max_header_list_size", nil); limit != nil && fr.HeaderListSize > *limit && len(conn.oversizeHeaders) < 10 {
		conn.oversizeHeaders = append(conn.oversizeHeaders, OversizeHeaderRow{
			From: side, StreamID: sid, Frame: n, HeaderListSize: fr.HeaderListSize, PeerLimit: *limit,
		})
	}
	if side == "client" {
		rpc.headerBlocksClient++
		if rpc.headerBlocksClient == 1 {
			rpc.requestHeaders = fr.Headers
			rpc.frames["request"] = n
			if rpc.tRequest == nil {
				tv := t
				rpc.tRequest = &tv
			}
			for _, h := range fr.Headers {
				low := strings.ToLower(h.Name)
				if !strings.HasPrefix(h.Name, ":") && !ReservedHeaders[low] {
					conn.metadataKeys[low]++
				}
				if h.Credential {
					entry, ok := conn.credentials[low]
					if !ok {
						entry = &credTrack{firstFrame: n, firstT: t}
						conn.credentials[low] = entry
					}
					entry.requests++
					model.AddFrame(&entry.frames, n)
				}
			}
		} else if len(rpc.trailers) == 0 {
			rpc.trailers = fr.Headers
		}
		if fr.EndStream {
			rpc.clientEnded = true
		}
		return
	}
	rpc.headerBlocksServer++
	if rpc.tFirstResponse == nil {
		tv := t
		rpc.tFirstResponse = &tv
		rpc.frames["first_response"] = n
	}
	if rpc.headerBlocksServer == 1 && !fr.EndStream {
		rpc.responseHeaders = fr.Headers
	} else if rpc.headerBlocksServer == 1 {
		for _, h := range fr.Headers {
			if h.Name == ":status" || h.Name == "content-type" {
				rpc.responseHeaders = append(rpc.responseHeaders, h)
			}
		}
		rpc.trailers = fr.Headers
		rpc.frames["trailers"] = n
	} else {
		rpc.trailers = fr.Headers
		rpc.frames["trailers"] = n
	}
	if fr.EndStream {
		rpc.serverEnded = true
		tv := t
		rpc.tEnd = &tv
		a.closeStalls(conn, rpc.streamID, t, "the stream ended")
	}
}
