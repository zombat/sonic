// Package extract assembles HTTP/2 HEADERS/CONTINUATION/DATA PDML frames into paired HTTPMessage values.
package extract

import (
	"context"
	"strings"
)

type h2SideState struct {
	frame      *int
	t          *float64
	headers    map[string]string
	creds      []HTTPCredentialFlag
	hasAuth    bool
	authScheme *string
	hasCookie  bool
	bodyLen    int
	body       []byte
}

type h2StreamPair struct {
	tcpStream int
	streamID  int
	src       string
	dst       string
	sport     *int
	dport     *int
	req       h2SideState
	resp      h2SideState
}

// HTTP2Messages runs IterHTTP2Packets across wanted TCP streams and reassembles request/response HTTPMessage items.
func HTTP2Messages(
	ctx context.Context,
	filePath string,
	decodeAs []string,
	wanted map[int]bool,
	keylogFile string,
	displayFilter string,
	maxPackets *int,
	outOfOrder bool,
) ([]HTTPMessage, map[string]bool, int, map[string]string, error) {
	ext, err := IterHTTP2Packets(ctx, filePath, decodeAs, keylogFile, nil, displayFilter, maxPackets, outOfOrder)
	if err != nil {
		return nil, nil, 0, nil, err
	}

	type streamKey struct {
		tcpStream int
		streamID  int
	}
	streams := make(map[streamKey]*h2StreamPair)
	var order []streamKey
	packetsRead := 0

	for i := range ext.Packets {
		pkt := &ext.Packets[i]
		if !wanted[pkt.TCPStream] {
			continue
		}
		packetsRead++
		for j := range pkt.Frames {
			fr := &pkt.Frames[j]
			if fr.Type != "HEADERS" && fr.Type != "CONTINUATION" && fr.Type != "DATA" {
				continue
			}
			key := streamKey{tcpStream: pkt.TCPStream, streamID: fr.StreamID}
			sp, exists := streams[key]
			if !exists {
				sp = &h2StreamPair{
					tcpStream: pkt.TCPStream, streamID: fr.StreamID,
					src: pkt.Src, dst: pkt.Dst, sport: pkt.Sport, dport: pkt.Dport,
					req:  h2SideState{headers: make(map[string]string)},
					resp: h2SideState{headers: make(map[string]string)},
				}
				streams[key] = sp
				order = append(order, key)
			}
			switch fr.Type {
			case "HEADERS", "CONTINUATION":
				applyH2Headers(sp, fr, pkt)
			case "DATA":
				applyH2Data(sp, fr, pkt)
			}
		}
	}

	var msgs []HTTPMessage
	for _, k := range order {
		msgs = append(msgs, splitH2Pair(streams[k])...)
	}
	return msgs, ext.SecretValues, packetsRead, ext.Status, nil
}

func applyH2Headers(sp *h2StreamPair, fr *HTTP2Frame, pkt *HTTP2Packet) {
	hdrMap := make(map[string]HTTP2Header, len(fr.Headers))
	for _, h := range fr.Headers {
		hdrMap[h.Name] = h
	}
	_, hasStatus := hdrMap[":status"]
	methodHdr, hasMethod := hdrMap[":method"]
	isResp := hasStatus || ((!hasMethod || methodHdr.Value == nil || *methodHdr.Value == "") && len(sp.req.headers) > 0)
	side := &sp.req
	if isResp {
		side = &sp.resp
	}

	for _, h := range fr.Headers {
		if h.Value != nil {
			if _, exists := side.headers[h.Name]; !exists {
				side.headers[h.Name] = *h.Value
			}
		}
		if h.Credential {
			low := strings.ToLower(h.Name)
			if low == "authorization" || low == "proxy-authorization" {
				side.hasAuth = true
				if h.Value != nil && *h.Value != "" {
					if fields := strings.Fields(*h.Value); len(fields) > 0 {
						s := fields[0]
						side.authScheme = &s
					}
				}
			} else if low == "cookie" || low == "set-cookie" {
				side.hasCookie = true
			} else {
				side.creds = append(side.creds, HTTPCredentialFlag{Header: h.Name, Kind: "token", Value: "masked"})
			}
		}
	}
	if side.frame == nil {
		f := pkt.N
		tv := pkt.T
		side.frame = &f
		side.t = &tv
	}
}

func applyH2Data(sp *h2StreamPair, fr *HTTP2Frame, pkt *HTTP2Packet) {
	side := &sp.req
	if len(sp.req.headers) > 0 {
		side = &sp.resp
	}
	dlen := fr.DataLen
	if dlen == 0 {
		dlen = len(fr.Data)
	}
	side.bodyLen += dlen
	if side == &sp.resp && len(side.body) < MaxBodyKeep && len(fr.Data) > 0 {
		rem := MaxBodyKeep - len(side.body)
		if rem > len(fr.Data) {
			side.body = append(side.body, fr.Data...)
		} else {
			side.body = append(side.body, fr.Data[:rem]...)
		}
	}
	if side.frame == nil {
		f := pkt.N
		tv := pkt.T
		side.frame = &f
		side.t = &tv
	}
}

func splitH2Pair(sp *h2StreamPair) []HTTPMessage {
	var out []HTTPMessage
	sid := sp.streamID
	hdrPtr := func(m map[string]string, k string) *string {
		if v, ok := m[k]; ok {
			return &v
		}
		return nil
	}
	if len(sp.req.headers) > 0 || sp.req.frame != nil {
		frVal := 0
		if sp.req.frame != nil {
			frVal = *sp.req.frame
		}
		tVal := 0.0
		if sp.req.t != nil {
			tVal = *sp.req.t
		}
		out = append(out, HTTPMessage{
			HTTPVersion: "2", TCPStream: sp.tcpStream, StreamID: &sid,
			Src: sp.src, Dst: sp.dst, Sport: sp.sport, Dport: sp.dport,
			Frame: frVal, T: tVal, IsRequest: true,
			Method: hdrPtr(sp.req.headers, ":method"), URI: hdrPtr(sp.req.headers, ":path"),
			Host: hdrPtr(sp.req.headers, ":authority"), ContentType: hdrPtr(sp.req.headers, "content-type"),
			BodyLen: sp.req.bodyLen, Credentials: sp.req.creds,
			HasAuth: sp.req.hasAuth, AuthScheme: sp.req.authScheme, HasCookie: sp.req.hasCookie,
		})
	}
	if len(sp.resp.headers) > 0 || sp.resp.frame != nil {
		frVal := 0
		if sp.resp.frame != nil {
			frVal = *sp.resp.frame
		}
		tVal := 0.0
		if sp.resp.t != nil {
			tVal = *sp.resp.t
		}
		var statusPtr *int
		if sStr := sp.resp.headers[":status"]; sStr != "" {
			if code, ok := parseFieldInt(sStr); ok {
				statusPtr = &code
			}
		}
		var timingPtr *float64
		if sp.resp.t != nil && sp.req.t != nil {
			dt := *sp.resp.t - *sp.req.t
			timingPtr = &dt
		}
		out = append(out, HTTPMessage{
			HTTPVersion: "2", TCPStream: sp.tcpStream, StreamID: &sid,
			Src: sp.src, Dst: sp.dst, Sport: sp.sport, Dport: sp.dport,
			Frame: frVal, T: tVal, IsRequest: false,
			ContentType: hdrPtr(sp.resp.headers, "content-type"),
			Status:      statusPtr, Location: hdrPtr(sp.resp.headers, "location"),
			TimeSinceRequest: timingPtr, RequestFrame: sp.req.frame,
			BodyLen: sp.resp.bodyLen, Body: sp.resp.body,
		})
	}
	return out
}
