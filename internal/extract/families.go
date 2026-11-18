// Package extract provides TCP service-port inference and protocol family
// discovery over normalized packet records.
package extract

import (
	"bytes"
	"encoding/hex"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

const maxTrackedConnections = 200000

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type tcpEndpoint struct {
	addr string
	port int
}

type connKey struct {
	a tcpEndpoint
	b tcpEndpoint
}

func makeConnKey(a, b tcpEndpoint) connKey {
	if a.addr < b.addr || (a.addr == b.addr && a.port <= b.port) {
		return connKey{a: a, b: b}
	}
	return connKey{a: b, b: a}
}

// AnnotateServicePorts infers and populates TCP.Svc on outer TCP records using SYN,
// SYN-ACK, HTTP/2 preface, and TLS ClientHello hints.
func AnnotateServicePorts(records []model.Record) {
	servers := make(map[connKey]tcpEndpoint)
	for i := range records {
		rec := &records[i]
		if rec.TCP == nil || rec.IP == nil || rec.TCP.Sport == nil || rec.TCP.Dport == nil {
			continue
		}
		a := tcpEndpoint{addr: rec.IP.Src, port: *rec.TCP.Sport}
		b := tcpEndpoint{addr: rec.IP.Dst, port: *rec.TCP.Dport}
		key := makeConnKey(a, b)
		server, hasServer := servers[key]

		flags := rec.TCP.Flags
		if (flags&0x02) != 0 && (flags&0x10) == 0 {
			server = b
			hasServer = true
		} else if (flags&0x02) != 0 && !hasServer {
			server = a
			hasServer = true
		} else if !hasServer && rec.DP != nil && rec.DP.PL != "" {
			head, err := hex.DecodeString(rec.DP.PL[:min(len(rec.DP.PL), len(http2Preface)*2)])
			if err == nil {
				isHTTP2 := bytes.HasPrefix(head, http2Preface)
				isTLSClientHello := len(head) > 5 && head[0] == 22 && head[1] == 3 && head[5] == 1
				if isHTTP2 || isTLSClientHello {
					server = b
					hasServer = true
				}
			}
		}
		if hasServer {
			if _, exists := servers[key]; exists || len(servers) < maxTrackedConnections {
				servers[key] = server
			}
			svc := server.port
			rec.TCP.Svc = &svc
		}
	}
}

// DetectFamilies returns the sorted unique set of protocol family labels across records.
func DetectFamilies(records []model.Record) []string {
	set := make(map[string]struct{})
	for i := range records {
		collectRecordFamilies(&records[i], set)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func collectRecordFamilies(rec *model.Record, set map[string]struct{}) {
	if rec.Inner != nil {
		in := rec.Inner
		if in.IKE != nil {
			set["ike"] = struct{}{}
			if in.IKE.NATT {
				set["nat-t"] = struct{}{}
			}
		}
		if in.ESP != nil {
			set["esp"] = struct{}{}
			if in.ESP.UDP {
				set["nat-t"] = struct{}{}
			}
		}
		if in.BGP != nil {
			set["bgp"] = struct{}{}
		}
		if in.OSPF != nil {
			set["ospf"] = struct{}{}
		}
		if in.EIGRP != nil {
			set["eigrp"] = struct{}{}
		}
		if in.NATKeepalive != nil && *in.NATKeepalive {
			set["nat-t"] = struct{}{}
		}
		if in.TCP != nil {
			set["tcp"] = struct{}{}
		}
		if in.UDP != nil {
			set["udp"] = struct{}{}
		}
	}

	if rec.IKE != nil {
		set["ike"] = struct{}{}
		if rec.IKE.NATT {
			set["nat-t"] = struct{}{}
		}
	}
	if rec.ESP != nil {
		set["esp"] = struct{}{}
		if rec.ESP.UDP {
			set["nat-t"] = struct{}{}
		}
	}
	if rec.GRE != nil {
		set["gre"] = struct{}{}
	}
	if rec.NHRP != nil {
		set["nhrp"] = struct{}{}
	}
	if rec.BGP != nil {
		set["bgp"] = struct{}{}
	}
	if rec.OSPF != nil {
		set["ospf"] = struct{}{}
	}
	if rec.EIGRP != nil {
		set["eigrp"] = struct{}{}
	}
	if rec.ARP != nil {
		set["arp"] = struct{}{}
	}
	if rec.SIP != nil && *rec.SIP {
		set["sip"] = struct{}{}
	}
	if rec.NATKeepalive != nil && *rec.NATKeepalive {
		set["nat-t"] = struct{}{}
	}
	if rec.ICMP != nil {
		if rec.ICMP.V6 {
			set["icmpv6"] = struct{}{}
		} else {
			set["icmp"] = struct{}{}
		}
	}
	if rec.TCP != nil {
		set["tcp"] = struct{}{}
	}
	if rec.UDP != nil {
		set["udp"] = struct{}{}
	}
	if rec.IP != nil && rec.IP.V == 6 {
		set["ipv6"] = struct{}{}
	}
	if rec.DP != nil && rec.DP.PL != "" && rec.TCP != nil {
		head, err := hex.DecodeString(rec.DP.PL[:min(len(rec.DP.PL), len(http2Preface)*2)])
		if err == nil {
			switch {
			case bytes.HasPrefix(head, http2Preface):
				set["http2"] = struct{}{}
			case bytes.HasPrefix(head, []byte("SSH-")):
				set["ssh"] = struct{}{}
			case len(head) > 5 && head[0] == 22 && head[1] == 3 && head[5] == 1:
				set["tls"] = struct{}{}
			}
		}
	}
}
