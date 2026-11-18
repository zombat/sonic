// Package model provides capture context, time formatting, protocol labeling,
// and data-plane transport view helpers matching Python network/dataplane common.
package model

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxFrames caps the number of frame numbers stored on an issue or bucket.
const MaxFrames = 10

// Context carries capture-wide timing bounds and display caps for detectors.
type Context struct {
	Start    *float64
	End      *float64
	MaxItems int
}

// Rel returns seconds elapsed since Context.Start, rounded to the millisecond.
func (c Context) Rel(t *float64) *float64 {
	if t == nil || c.Start == nil {
		return nil
	}
	v := math.Round((*t-*c.Start)*1000) / 1000
	if v == 0 {
		// Normalize -0.0 to +0.0 so JSON always renders 0.0.
		v = 0
	}
	return &v
}

// ISOTime formats Unix epoch seconds as a millisecond UTC ISO-8601 string.
func ISOTime(t *float64) *string {
	if t == nil {
		return nil
	}
	// Match CPython datetime.fromtimestamp (microsecond rounding) followed by millisecond truncation.
	us := int64(math.Round(*t * 1e6))
	s := time.UnixMicro(us).UTC().Format("2006-01-02T15:04:05.000Z")
	return &s
}

// MakeIssue constructs an Issue with frames capped at MaxFrames and a non-nil slice.
func MakeIssue(severity Severity, code, message string, frames []int) Issue {
	capped := make([]int, 0, min(len(frames), MaxFrames))
	for i := 0; i < len(frames) && i < MaxFrames; i++ {
		capped = append(capped, frames[i])
	}
	return Issue{
		Severity: severity,
		Code:     code,
		Message:  message,
		Frames:   capped,
	}
}

// MakeEvent builds one timeline Event using Context relative time and ISO-8601 UTC.
func MakeEvent(ctx Context, t float64, protocol, event, detail string, frame *int) Event {
	return Event{
		T:        ctx.Rel(&t),
		Time:     ISOTime(&t),
		Protocol: protocol,
		Event:    event,
		Detail:   detail,
		Frame:    frame,
	}
}

// StatusFromIssues returns StatusNotPresent when present is false; otherwise the worst issue severity decides.
func StatusFromIssues(issues []Issue, present bool) Status {
	if !present {
		return StatusNotPresent
	}
	hasWarning := false
	for _, issue := range issues {
		switch issue.Severity {
		case SeverityError:
			return StatusProblem
		case SeverityWarning:
			hasWarning = true
		case SeverityInfo:
		}
	}
	if hasWarning {
		return StatusWarning
	}
	return StatusOK
}

// WorstStatus returns the highest Status in statuses, or StatusNotPresent when empty.
func WorstStatus(statuses []Status) Status {
	worst := StatusNotPresent
	for _, s := range statuses {
		if StatusOrder(s) > StatusOrder(worst) {
			worst = s
		}
	}
	return worst
}

// SortIssues returns a copy of issues sorted stably from most to least severe.
func SortIssues(issues []Issue) []Issue {
	out := slices.Clone(issues)
	slices.SortStableFunc(out, func(a, b Issue) int {
		return SeverityOrder(a.Severity) - SeverityOrder(b.Severity)
	})
	return out
}

// CompareIP orders IPv4 numerically before IPv6, with non-IP strings sorted last and equal to each other.
func CompareIP(a, b string) int {
	pa, errA := netip.ParseAddr(a)
	pb, errB := netip.ParseAddr(b)
	va, vb := 9, 9
	if errA == nil {
		if pa.Is4() {
			va = 4
		} else {
			va = 6
		}
	}
	if errB == nil {
		if pb.Is4() {
			vb = 4
		} else {
			vb = 6
		}
	}
	if va != vb {
		return va - vb
	}
	if va == 9 {
		return 0
	}
	return pa.Compare(pb)
}

// PairKey returns (a, b) ordered deterministically via CompareIP.
func PairKey(a, b string) [2]string {
	if CompareIP(a, b) <= 0 {
		return [2]string{a, b}
	}
	return [2]string{b, a}
}

// Cap slices items to limit and returns the sliced view plus the count omitted.
func Cap[T any](items []T, limit int) ([]T, int) {
	if limit < 0 || len(items) <= limit {
		return items, 0
	}
	return items[:limit], len(items) - limit
}

// AddFrame appends frame if fewer than MaxFrames have been recorded.
func AddFrame(frames *[]int, frame int) {
	if len(*frames) < MaxFrames {
		*frames = append(*frames, frame)
	}
}

// ServiceNames maps well-known TCP/UDP ports to human-readable service labels.
var ServiceNames = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 49: "tacacs", 53: "dns",
	67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 123: "ntp", 161: "snmp", 162: "snmp-trap",
	179: "bgp", 443: "https", 500: "ike", 514: "syslog", 520: "rip", 646: "ldp", 830: "netconf",
	1812: "radius", 1813: "radius-acct", 1985: "hsrp", 3784: "bfd", 3785: "bfd-echo",
	4500: "ipsec-nat-t", 4789: "vxlan", 5060: "sip", 5061: "sips", 6633: "openflow", 6653: "openflow",
}

// IPProtocolNames maps IP protocol numbers to canonical lowercase protocol names.
var IPProtocolNames = map[int]string{
	1: "icmp", 2: "igmp", 4: "ipip", 6: "tcp", 17: "udp", 41: "ipv6-in-ipv4",
	47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 88: "eigrp", 89: "ospf",
	103: "pim", 112: "vrrp", 115: "l2tp", 132: "sctp",
}

// EthertypeNames maps non-IP Ethernet EtherTypes to canonical names.
var EthertypeNames = map[int]string{
	0x0806: "arp", 0x8035: "rarp", 0x8100: "vlan", 0x88CC: "lldp", 0x8847: "mpls",
	0x8863: "pppoe-discovery", 0x8864: "pppoe", 0x88A8: "qinq", 0x8809: "lacp", 0x9000: "loopback",
}

// ServicePort chooses the service-naming port between sport and dport.
func ServicePort(sport, dport *int) *int {
	if sport == nil || dport == nil {
		if dport != nil {
			return dport
		}
		return sport
	}
	if _, ok := ServiceNames[*dport]; ok {
		return dport
	}
	if _, ok := ServiceNames[*sport]; ok {
		return sport
	}
	if *dport <= 1023 || *sport <= 1023 {
		if *sport <= *dport {
			return sport
		}
		return dport
	}
	low := *sport
	if *dport < low {
		low = *dport
	}
	if low <= 49151 {
		v := low
		return &v
	}
	return dport
}

// ProtocolLabel produces the canonical single-frame protocol label matching network_common.protocol_label.
func ProtocolLabel(rec *Record) string {
	if rec.ESP != nil {
		if rec.ESP.UDP {
			return "esp-in-udp"
		}
		return "esp"
	}
	if rec.IKE != nil {
		return "ike"
	}
	if rec.NATKeepalive != nil && *rec.NATKeepalive {
		return "nat-keepalive"
	}
	if rec.GRE != nil {
		if rec.GRE.Ptype != nil {
			switch *rec.GRE.Ptype {
			case 0x2001:
				return "gre/nhrp"
			case 0x0800:
				return "gre/ipv4"
			case 0x86DD:
				return "gre/ipv6"
			}
		}
		return "gre"
	}
	if rec.IP == nil {
		if rec.ARP != nil {
			return "arp"
		}
		if rec.LLC != "" {
			return rec.LLC
		}
		if rec.EthType != nil {
			if name, ok := EthertypeNames[*rec.EthType]; ok {
				return name
			}
			return fmt.Sprintf("ethertype-0x%04x", *rec.EthType)
		}
		return "other"
	}
	if rec.TCP != nil {
		svc := rec.TCP.Svc
		if svc == nil {
			svc = ServicePort(rec.TCP.Sport, rec.TCP.Dport)
		}
		if svc != nil {
			return fmt.Sprintf("tcp/%d", *svc)
		}
		return "tcp/None"
	}
	if rec.UDP != nil {
		svc := ServicePort(rec.UDP.Sport, rec.UDP.Dport)
		if svc != nil {
			return fmt.Sprintf("udp/%d", *svc)
		}
		return "udp/None"
	}
	if rec.IP.Proto != nil {
		if name, ok := IPProtocolNames[*rec.IP.Proto]; ok {
			return name
		}
		return fmt.Sprintf("ip-proto-%d", *rec.IP.Proto)
	}
	return "ip-proto-None"
}

// LabelService returns the human service name for a tcp/<port> or udp/<port> label.
func LabelService(label string) (string, bool) {
	prefix, rest, ok := strings.Cut(label, "/")
	if !ok || (prefix != "tcp" && prefix != "udp") {
		return "", false
	}
	port, err := strconv.Atoi(rest)
	if err != nil {
		return "", false
	}
	name, found := ServiceNames[port]
	return name, found
}
