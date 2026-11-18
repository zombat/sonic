// Package audit classifies individual frames and TCP sessions into audit
// allowlist tokens, human-readable protocol labels, and categories.
package audit

import (
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// PortNames maps TCP/UDP port numbers to non-confidential allowlist tokens.
var PortNames = map[int]string{
	179: "bgp", 520: "rip", 646: "ldp", 3784: "bfd", 3785: "bfd", 1985: "hsrp",
	67: "dhcp", 68: "dhcp", 53: "dns", 123: "ntp", 161: "snmp", 162: "snmp",
	514: "syslog", 49: "tacacs", 1812: "radius", 1813: "radius",
}

// ProtoNames maps IP protocol numbers to canonical audit tokens.
var ProtoNames = map[int]string{
	50: "esp", 51: "ah", 47: "gre", 89: "ospf", 88: "eigrp",
	103: "pim", 112: "vrrp", 1: "icmp", 58: "icmpv6",
}

// EthertypeTokens maps non-IP EtherType values to layer-2 token names.
var EthertypeTokens = map[int]string{
	0x0806: "arp", 0x88CC: "lldp", 0x8809: "lacp", 0x9000: "loop",
}

// Category maps token names to audit violation categories.
var Category = map[string]string{
	"esp": "crypto", "ike": "crypto", "nat-t": "crypto", "ah": "authenticated_only",
	"gre": "tunnel_without_encryption", "icmp": "icmp", "icmpv6": "icmp",
	"arp": "layer2", "cdp": "layer2", "stp": "layer2", "lldp": "layer2",
	"lacp": "layer2", "loop": "layer2", "llc": "layer2",
}

var protectionMap = map[string]string{
	"authenticated_only": "authenticated_only",
	"layer2":             "layer2",
}

// TokensFor classifies one non-TCP (or GRE/fragment) record into (tokens, protocolName, category).
func TokensFor(rec *model.Record) (map[string]bool, string, string) {
	label := model.ProtocolLabel(rec)
	tokens := make(map[string]bool)
	if rec.IP == nil {
		if rec.ARP != nil {
			tokens["arp"] = true
			tokens["ethertype:0x0806"] = true
			return tokens, "arp", "layer2"
		}
		if rec.LLC != "" {
			tokens[rec.LLC] = true
			return tokens, rec.LLC, "layer2"
		}
		if rec.EthType != nil {
			name, ok := EthertypeTokens[*rec.EthType]
			if !ok {
				name = fmt.Sprintf("ethertype-0x%04x", *rec.EthType)
			}
			tokens[name] = true
			tokens[fmt.Sprintf("ethertype:0x%04x", *rec.EthType)] = true
			cat := Category[name]
			if cat == "" {
				cat = "layer2"
			}
			return tokens, name, cat
		}
		tokens["other"] = true
		return tokens, "other", "layer2"
	}

	proto := rec.IP.Proto
	if proto != nil {
		tokens[fmt.Sprintf("proto:%d", *proto)] = true
		if name, ok := ProtoNames[*proto]; ok {
			tokens[name] = true
		}
	}
	if rec.ESP != nil {
		tokens["esp"] = true
		if rec.ESP.UDP {
			tokens["nat-t"] = true
		}
	}
	if rec.IKE != nil {
		tokens["ike"] = true
		if rec.IKE.NATT {
			tokens["nat-t"] = true
		}
	}
	if rec.NATKeepalive != nil && *rec.NATKeepalive {
		tokens["nat-t"] = true
		tokens["nat-keepalive"] = true
	}
	if rec.TCP != nil {
		addPortTokens(tokens, "tcp", rec.TCP.Sport, rec.TCP.Dport)
	}
	if rec.UDP != nil {
		addPortTokens(tokens, "udp", rec.UDP.Sport, rec.UDP.Dport)
	}
	if rec.UDP != nil && rec.DP != nil && rec.DP.MF != nil && *rec.DP.MF != 0 && rec.DP.Off == 0 {
		if hasPort(rec.UDP.Sport, rec.UDP.Dport, 500) {
			tokens["ike"] = true
		}
		if hasPort(rec.UDP.Sport, rec.UDP.Dport, 4500) {
			tokens["ike"] = true
			tokens["nat-t"] = true
		}
	}

	if rec.IKE != nil || (rec.NATKeepalive != nil && *rec.NATKeepalive) || rec.ESP != nil || tokens["ike"] || tokens["nat-t"] {
		return tokens, label, "crypto"
	}
	if rec.GRE != nil {
		name := label
		if in := rec.Inner; in != nil {
			switch {
			case in.TCP != nil && hasPort(in.TCP.Sport, in.TCP.Dport, 179):
				name = "gre/ipv4 (bgp inside)"
			case in.OSPF != nil:
				name = "gre/ipv4 (ospf inside)"
			case in.EIGRP != nil:
				name = "gre/ipv4 (eigrp inside)"
			case rec.NHRP != nil:
				name = "gre/nhrp"
			}
		} else if rec.NHRP != nil {
			name = "gre/nhrp"
		}
		return tokens, name, "tunnel_without_encryption"
	}

	var matchedRouting []string
	for tok := range tokens {
		if routingSet[tok] {
			matchedRouting = append(matchedRouting, tok)
		}
	}
	if len(matchedRouting) > 0 {
		slices.Sort(matchedRouting)
		return tokens, matchedRouting[0], "routing"
	}
	if rec.ICMP != nil {
		return tokens, label, "icmp"
	}
	if proto != nil && *proto == 51 {
		return tokens, "ah", "authenticated_only"
	}
	if rec.SNMP != nil {
		// Each SNMP token names only what it covers, so allowing one never admits cleartext SNMP.
		switch {
		case snmpPrivate(rec.SNMP):
			tokens["snmp-v3-privacy"] = true
		case rec.SNMP.Discovery:
			tokens["snmp-v3-discovery"] = true
		}
		return tokens, snmpLabel(rec.SNMP), snmpCategory(rec.SNMP)
	}
	return tokens, label, "cleartext"
}

// ProtectionOf returns the protection bucket for a non-session frame.
func ProtectionOf(rec *model.Record, category string) string {
	if category == "crypto" {
		if rec.ESP != nil {
			return "encrypted"
		}
		return "key_exchange"
	}
	if category == "encrypted" || category == "key_exchange" {
		return category
	}
	if p, ok := protectionMap[category]; ok {
		return p
	}
	return "cleartext"
}

// SessionLabel derives (protocolName, category, tokens) for a classified TCP session.
func SessionLabel(kind string, svc *int) (string, string, map[string]bool) {
	port := "tcp"
	if svc != nil {
		port = fmt.Sprintf("tcp/%d", *svc)
	}
	toks := make(map[string]bool)
	switch kind {
	case "ssh":
		toks["ssh"] = true
		if svc != nil && *svc == 830 {
			toks["netconf"] = true
			return fmt.Sprintf("netconf over ssh (%s)", port), "encrypted", toks
		}
		return fmt.Sprintf("ssh (%s)", port), "encrypted", toks
	case "tls":
		toks["tls"] = true
		if svc != nil {
			if name, ok := model.ServiceNames[*svc]; ok {
				return fmt.Sprintf("tls (%s %s)", port, name), "encrypted", toks
			}
		}
		return fmt.Sprintf("tls (%s)", port), "encrypted", toks
	case "http2":
		toks["http2"] = true
		return fmt.Sprintf("http2 (%s)", port), "cleartext_management", toks
	default:
		return port, "cleartext", toks
	}
}

func addPortTokens(tokens map[string]bool, prefix string, sport, dport *int) {
	for _, p := range []*int{sport, dport} {
		if p == nil {
			continue
		}
		tokens[fmt.Sprintf("%s:%d", prefix, *p)] = true
		if name, ok := PortNames[*p]; ok {
			tokens[name] = true
		}
	}
}

func hasPort(sport, dport *int, target int) bool {
	return (sport != nil && *sport == target) || (dport != nil && *dport == target)
}
