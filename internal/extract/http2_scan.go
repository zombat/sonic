// Package extract provides tshark discovery execution, preface detection, and decode-as planning.
package extract

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// parseFieldInt parses an integer string (decimal, hex, or float) returning (val, ok).
func parseFieldInt(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	if v, err := strconv.ParseInt(s, 0, 64); err == nil {
		return int(v), true
	}
	if fv, ferr := strconv.ParseFloat(s, 64); ferr == nil {
		return int(fv), true
	}
	return 0, false
}

// firstPipe returns the first '|'-separated token from raw.
func firstPipe(raw string) string {
	if idx := strings.IndexByte(raw, '|'); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

// Discover runs Pass 1 (SYN/RST/TLS/HTTP2-preface discovery) and returns connections keyed by tcp.stream.
func Discover(
	ctx context.Context,
	filePath, displayFilter string,
	maxPackets *int,
	status map[string]string,
	extraPorts []int,
) (map[int]*TCPConnection, error) {
	flt := DiscoveryFilter(extraPorts)
	if displayFilter != "" {
		flt = fmt.Sprintf("(%s) && (%s)", displayFilter, flt)
	}
	conns := make(map[int]*TCPConnection)
	stderr, err := streamTsharkFields(ctx, filePath, nil, flt, DiscoveryFields, "|", maxPackets, nil, func(row map[string]string) error {
		applyDiscoveryRow(conns, row)
		return nil
	})
	if status != nil && stderr != "" {
		status["discovery_stderr"] = stderr
	}
	if err != nil {
		return nil, err
	}
	prefaces := FindPrefaces(ctx, filePath, displayFilter, maxPackets)
	for index, pref := range prefaces {
		conn, ok := conns[index]
		if !ok {
			continue
		}
		fr := pref.frame
		snd := pref.sender
		conn.PrefaceFrame = &fr
		conn.PrefaceFrom = &snd
		target := conn.A
		if snd == conn.A {
			target = conn.B
		}
		conn.SetServer(target, "preface")
	}
	return conns, nil
}

// applyDiscoveryRow merges one tshark discovery row into conns.
func applyDiscoveryRow(conns map[int]*TCPConnection, row map[string]string) {
	index, ok := parseFieldInt(firstPipe(row["tcp.stream"]))
	if !ok {
		return
	}
	src := firstPipe(row["ip.src"])
	if src == "" {
		src = firstPipe(row["ipv6.src"])
	}
	dst := firstPipe(row["ip.dst"])
	if dst == "" {
		dst = firstPipe(row["ipv6.dst"])
	}
	sport, okS := parseFieldInt(firstPipe(row["tcp.srcport"]))
	dport, okD := parseFieldInt(firstPipe(row["tcp.dstport"]))
	if src == "" || dst == "" || !okS || !okD {
		return
	}
	frame, _ := parseFieldInt(row["frame.number"])
	tVal, _ := strconv.ParseFloat(row["frame.time_epoch"], 64)
	me := Endpoint{IP: src, Port: sport}
	peer := Endpoint{IP: dst, Port: dport}
	conn, exists := conns[index]
	if !exists {
		conn = &TCPConnection{Index: index, A: me, B: peer, FirstFrame: frame, FirstT: tVal, LastT: tVal}
		conns[index] = conn
	}
	conn.LastT = max(conn.LastT, tVal)

	flags, _ := parseFieldInt(firstPipe(row["tcp.flags"]))
	syn, ack, rst := (flags&0x02) != 0, (flags&0x10) != 0, (flags&0x04) != 0
	if syn && !ack {
		conn.SetServer(peer, "syn")
		if conn.SynFrame == nil {
			f := frame
			conn.SynFrame = &f
		}
	} else if syn && ack {
		conn.SetServer(me, "syn-ack")
	}
	if rst {
		conn.Resets = append(conn.Resets, TCPReset{Frame: frame, T: tVal, From: me})
	}

	payloadLen, _ := parseFieldInt(firstPipe(row["tcp.len"]))
	protocols := row["frame.protocols"]
	for _, tok := range strings.Split(row["tls.handshake.type"], "|") {
		hs, ok := parseFieldInt(tok)
		if !ok {
			continue
		}
		if hs == 1 {
			if conn.TLSClientHello == nil {
				f := frame
				conn.TLSClientHello = &f
			}
			conn.SetServer(peer, "client_hello")
			if sni := firstPipe(row["tls.handshake.extensions_server_name"]); sni != "" && conn.SNI == nil {
				s := sni
				conn.SNI = &s
			}
			if alpnRaw := row["tls.handshake.extensions_alpn_str"]; alpnRaw != "" && len(conn.ALPN) == 0 {
				for _, a := range strings.Split(alpnRaw, "|") {
					if a != "" {
						conn.ALPN = append(conn.ALPN, a)
					}
				}
			}
		} else if hs == 2 && conn.TLSServerHello == nil {
			f := frame
			conn.TLSServerHello = &f
		}
	}
	if payloadLen != 0 && conn.FirstPayloadFrame == nil {
		f := frame
		conn.FirstPayloadFrame = &f
		isTLS := strings.Contains(protocols, ":tls") || strings.Contains(protocols, ":ssl")
		conn.FirstPayloadTLS = &isTLS
	}
}

type prefaceLoc struct {
	frame  int
	sender Endpoint
}

// FindPrefaces scans the capture for cleartext HTTP/2 connection prefaces across all ports.
func FindPrefaces(ctx context.Context, filePath, displayFilter string, maxPackets *int) map[int]prefaceLoc {
	flt := "tcp.len>=24 && tcp.payload[0:24]==" + HTTP2PrefaceFilter
	if displayFilter != "" {
		flt = fmt.Sprintf("(%s) && (%s)", displayFilter, flt)
	}
	fields := []string{"frame.number", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport"}
	out := make(map[int]prefaceLoc)
	_, _ = streamTsharkFields(ctx, filePath, nil, flt, fields, "|", maxPackets, nil, func(row map[string]string) error {
		idx, ok := parseFieldInt(row["tcp.stream"])
		if !ok {
			return nil
		}
		if _, exists := out[idx]; exists {
			return nil
		}
		fr, _ := parseFieldInt(row["frame.number"])
		src := row["ip.src"]
		if src == "" {
			src = row["ipv6.src"]
		}
		if comma := strings.IndexByte(src, ','); comma >= 0 {
			src = src[:comma]
		}
		sport, _ := parseFieldInt(row["tcp.srcport"])
		out[idx] = prefaceLoc{frame: fr, sender: Endpoint{IP: src, Port: sport}}
		return nil
	})
	return out
}

// PlanDecodeAs returns tshark -d options and human-readable reasons for HTTP/2/gRPC decoding.
func PlanDecodeAs(conns map[int]*TCPConnection, extraPorts []int) ([]string, map[int]string) {
	reasons := make(map[int]string)
	sorted := make([]*TCPConnection, 0, len(conns))
	for _, c := range conns {
		sorted = append(sorted, c)
	}
	slices.SortStableFunc(sorted, func(a, b *TCPConnection) int {
		return cmp.Compare(a.FirstFrame, b.FirstFrame)
	})
	for _, c := range sorted {
		port := c.ServicePort()
		_, isGrpc := GrpcPorts[port]
		if c.PrefaceFrame != nil && !c.IsTLS() {
			reasons[port] = "preface"
		} else if c.IsTLS() && (slices.Contains(c.ALPN, "h2") || isGrpc) {
			if _, exists := reasons[port]; !exists {
				reasons[port] = "tls_h2"
			}
		} else if isGrpc && c.FirstPayloadFrame != nil && !c.IsTLS() {
			if _, exists := reasons[port]; !exists {
				reasons[port] = "grpc_port"
			}
		}
	}
	for _, p := range extraPorts {
		if _, exists := reasons[p]; !exists {
			reasons[p] = "requested"
		}
	}
	ports := make([]int, 0, len(reasons))
	for p := range reasons {
		ports = append(ports, p)
	}
	slices.Sort(ports)
	var options []string
	for _, p := range ports {
		if reasons[p] == "tls_h2" {
			options = append(options, "-d", fmt.Sprintf("tcp.port==%d,tls", p))
		} else {
			options = append(options, "-d", fmt.Sprintf("tcp.port==%d,http2", p))
		}
	}
	return options, reasons
}
