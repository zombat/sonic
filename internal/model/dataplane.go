// Package model defines data-plane DSCP, fragmentation, sequence arithmetic,
// and endpoint formatting helpers.
package model

import (
	"fmt"
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
