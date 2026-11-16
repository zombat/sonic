// Package model defines data-plane DSCP, fragmentation, sequence arithmetic,
// math rounding, ICMP descriptions, and endpoint formatting helpers.
package model

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

// DSCPNames maps Differentiated Services Code Point numbers to RFC names.
var DSCPNames = map[int]string{
	0: "CS0/BE", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13", 16: "CS2", 18: "AF21", 20: "AF22",
	22: "AF23", 24: "CS3", 26: "AF31", 28: "AF32", 30: "AF33", 32: "CS4", 34: "AF41", 36: "AF42",
	38: "AF43", 40: "CS5", 44: "VOICE-ADMIT", 46: "EF", 48: "CS6", 56: "CS7",
}

// DSCPName returns the symbolic DSCP class name or "DSCP <n>" fallback.
func DSCPName(value *int) string {
	if value == nil {
		return "unknown"
	}
	if name, ok := DSCPNames[*value]; ok {
		return name
	}
	return fmt.Sprintf("DSCP %d", *value)
}

// TransportView holds the effective data-plane L3/L4 view of a frame.
type TransportView struct {
	Src      string
	Dst      string
	Proto    *int
	TCP      *TCPHeader
	UDP      *UDPHeader
	DTCP     *DPTCP
	Tunneled bool
	DSCP     int
	ECN      int
	ID       *int
	TL       int
	DF       *int
	HasOuter bool
	OuterSrc string
	OuterDst string
	V6       bool
}

// Transport extracts the inner packet view when GRE carries IPv4, or the outer packet otherwise.
func Transport(rec *Record) *TransportView {
	if rec == nil || rec.IP == nil || rec.DP == nil {
		return nil
	}
	if rec.Inner != nil && rec.DP.Inner != nil {
		hdr := rec.DP.Inner
		df := hdr.DF
		return &TransportView{
			Src: rec.Inner.Src, Dst: rec.Inner.Dst, Proto: rec.Inner.Proto,
			TCP: rec.Inner.TCP, UDP: rec.Inner.UDP, DTCP: rec.DP.TCP,
			Tunneled: true, DSCP: hdr.DSCP, ECN: hdr.ECN, ID: hdr.ID,
			TL: hdr.TL, DF: &df, HasOuter: true, OuterSrc: rec.IP.Src, OuterDst: rec.IP.Dst, V6: false,
		}
	}
	return &TransportView{
		Src: rec.IP.Src, Dst: rec.IP.Dst, Proto: rec.IP.Proto,
		TCP: rec.TCP, UDP: rec.UDP, DTCP: rec.DP.TCP,
		Tunneled: false, DSCP: rec.DP.DSCP, ECN: rec.DP.ECN, ID: rec.DP.ID,
		TL: rec.DP.TL, DF: rec.DP.DF, V6: rec.IP.V == 6,
	}
}

// IsFragment reports whether rec carries the IPv4 More-Fragments flag or a positive fragment offset.
func IsFragment(rec *Record) bool {
	if rec == nil || rec.DP == nil {
		return false
	}
	return (rec.DP.MF != nil && *rec.DP.MF != 0) || rec.DP.Off > 0
}

// SeqDelta computes signed difference (a - b) in 32-bit TCP sequence space.
func SeqDelta(a, b uint32) int64 {
	// Signed int32 conversion maps 0x80000000..0xFFFFFFFF directly to -2^31..-1.
	return int64(int32(a - b))
}

// Endpoint formats addr and optional port, bracketing IPv6 literals.
func Endpoint(addr string, port *int) string {
	if port == nil {
		return addr
	}
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, *port)
	}
	return fmt.Sprintf("%s:%d", addr, *port)
}

// Round rounds val to decimals places using IEEE round-half-to-even and normalizes -0.0.
func Round(val float64, decimals int) float64 {
	pow := math.Pow10(decimals)
	res := math.RoundToEven(val*pow) / pow
	if res == 0 {
		res = 0
	}
	return res
}

// Median computes the statistical median of values, or nil when values is empty.
func Median(values []float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	ordered := slices.Clone(values)
	slices.Sort(ordered)
	mid := len(ordered) / 2
	var m float64
	if len(ordered)%2 == 1 {
		m = ordered[mid]
	} else {
		m = (ordered[mid-1] + ordered[mid]) / 2.0
	}
	return &m
}

// Percentile returns the nearest-rank percentile of values matching dataplane_common.percentile.
func Percentile(values []float64, fraction float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	ordered := slices.Clone(values)
	slices.Sort(ordered)
	idx := min(len(ordered)-1, max(0, int(math.RoundToEven(fraction*float64(len(ordered)-1)))))
	v := ordered[idx]
	return &v
}

var (
	icmpTypes = map[int]string{
		0: "echo_reply", 3: "destination_unreachable", 4: "source_quench", 5: "redirect",
		8: "echo_request", 11: "time_exceeded", 12: "parameter_problem",
	}
	icmpUnreachCodes = map[int]string{
		0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable",
		3: "port unreachable", 4: "fragmentation needed and DF set", 5: "source route failed",
		6: "destination network unknown", 7: "destination host unknown",
		9: "network administratively prohibited", 10: "host administratively prohibited",
		11: "network unreachable for ToS", 12: "host unreachable for ToS",
		13: "communication administratively prohibited (ACL)", 14: "host precedence violation",
		15: "precedence cutoff",
	}
	icmpTimeExceededCodes = map[int]string{
		0: "TTL exceeded in transit", 1: "fragment reassembly time exceeded",
	}
	icmpRedirectCodes = map[int]string{
		0: "redirect for network", 1: "redirect for host",
		2: "redirect for ToS and network", 3: "redirect for ToS and host",
	}
	icmpv6Types = map[int]string{
		1: "destination_unreachable", 2: "packet_too_big", 3: "time_exceeded",
		4: "parameter_problem", 128: "echo_request", 129: "echo_reply",
	}
	icmpv6UnreachCodes = map[int]string{
		0: "no route to destination", 1: "administratively prohibited", 2: "beyond scope of source",
		3: "address unreachable", 4: "port unreachable", 5: "source address failed policy",
		6: "reject route",
	}
)

// ICMPDescribe returns (typeName, codeText) for an ICMPv4 or ICMPv6 type and code.
func ICMPDescribe(v6 bool, icmpType, code int) (string, string) {
	if v6 {
		name, ok := icmpv6Types[icmpType]
		if !ok {
			name = fmt.Sprintf("type_%d", icmpType)
		}
		if icmpType == 1 {
			if txt, ok := icmpv6UnreachCodes[code]; ok {
				return name, txt
			}
			return name, fmt.Sprintf("code %d", code)
		}
		if icmpType == 3 {
			if code == 0 {
				return name, "hop limit exceeded in transit"
			}
			return name, "fragment reassembly time exceeded"
		}
		return name, fmt.Sprintf("code %d", code)
	}

	name, ok := icmpTypes[icmpType]
	if !ok {
		name = fmt.Sprintf("type_%d", icmpType)
	}
	switch icmpType {
	case 3:
		if txt, ok := icmpUnreachCodes[code]; ok {
			return name, txt
		}
	case 11:
		if txt, ok := icmpTimeExceededCodes[code]; ok {
			return name, txt
		}
	case 5:
		if txt, ok := icmpRedirectCodes[code]; ok {
			return name, txt
		}
	}
	return name, fmt.Sprintf("code %d", code)
}

// FormatPyFloat formats v identically to Python str(float), keeping ".0" on whole values.
func FormatPyFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.ContainsRune(s, '.') {
		s += ".0"
	}
	return s
}
