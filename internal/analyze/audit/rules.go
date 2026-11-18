// Package audit defines allowlist rules, token groups, and IP/CIDR matching.
package audit

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// DefaultAllow defines the allowlist used when no tokens are supplied.
var DefaultAllow = []string{"encrypted"}

// Groups expands high-level allowlist group tokens into concrete protocol tokens.
var Groups = map[string][]string{
	"crypto":     {"esp", "ike", "nat-t"},
	"encrypted":  {"esp", "ike", "nat-t", "ssh", "tls"},
	"routing":    {"bgp", "ospf", "eigrp", "rip", "ldp", "bfd", "pim", "vrrp", "hsrp"},
	"l2-control": {"cdp", "stp", "lldp", "lacp", "loop"},
}

// Single holds all valid single-protocol allowlist tokens.
var Single = map[string]bool{
	"esp": true, "ike": true, "nat-t": true, "nat-keepalive": true, "ah": true,
	"arp": true, "icmp": true, "icmpv6": true, "bgp": true, "ospf": true,
	"eigrp": true, "rip": true, "ldp": true, "bfd": true, "pim": true,
	"vrrp": true, "hsrp": true, "gre": true, "cdp": true, "stp": true,
	"lldp": true, "lacp": true, "loop": true, "dhcp": true, "dns": true,
	"ntp": true, "ssh": true, "netconf": true, "tls": true, "http2": true,
	"snmp": true, "syslog": true, "tacacs": true, "radius": true,
}

// Hints explains what each audit category represents on a link.
var Hints = map[string]string{
	"tunnel_without_encryption": "GRE outside ESP: the overlay (and whatever it carries) crosses this link unencrypted",
	"routing":                   "a routing protocol in cleartext on the transport link (to the provider, or leaked from the overlay)",
	"icmp":                      "ICMP in cleartext: a ping or traceroute of the transport addresses, or traffic bypassing the tunnel",
	"layer2":                    "link-local layer 2 control traffic (it does not leave the link, but CDP/LLDP disclose device details to the provider side)",
	"cleartext":                 "application or management traffic outside the tunnel",
	"authenticated_only":        "AH authenticates but does not encrypt",
	"encrypted":                 "an encrypted session (SSH or TLS) that is not on the allowlist: not cleartext, but not one of the protocols this link may carry (allow ssh, tls, netconf or encrypted, the default, to accept it)",
	"unencrypted_session":       "an SSH or TLS session whose handshake chose no real encryption (TLS: a NULL, anonymous, export or integrity-only suite; SSH: the cipher none): what it carries crosses the link readable",
	"cleartext_management":      "cleartext HTTP/2 (gRPC, gNMI or gNOI without TLS): every request, response and metadata value, credentials included, is readable on the wire",
}

// CannotShow documents the visibility boundaries reported with every audit result.
var CannotShow = []string{
	"Only frames that crossed this capture point and that the capture kept are audited: a capture filter, a snap length or a full buffer can hide frames, and traffic on other links is not seen.",
	"ESP payload is opaque: ESP with NULL encryption or a weak cipher passes, because the cipher is negotiated inside IKE (visible only in IKE_SA_INIT for the IKE SA, never for the child SA).",
	"A non-first IP fragment carries no port: it follows its datagram's first fragment (same addresses and IP identification); when that first fragment is not in the capture it is reported as plain udp (fail-closed).",
	"SSH and TLS are judged by their handshake: the TLS suite in the ServerHello, the SSH cipher from both KEXINITs. Without the handshake (a session that began before the capture) a NULL cipher looks like a real one, so such a session passes only as encrypted, unverified (a warning). A TLS session is recognised that way only when a segment begins at a record boundary, an SSH session only on tcp/22 or tcp/830 and only when its payload looks like ciphertext; anything else is reported as cleartext (fail-closed).",
	"Encryption is judged by the cipher's name: key sizes, certificate trust and the strength of the key exchange are not (analyze_network_pcap's tls detector reads certificates and checks a baseline).",
}

var routingSet = map[string]bool{
	"bgp": true, "ospf": true, "eigrp": true, "rip": true, "ldp": true,
	"bfd": true, "pim": true, "vrrp": true, "hsrp": true,
}

// Rule represents one parsed allowlist entry with optional IP/CIDR address scoping.
type Rule struct {
	Text     string
	Tokens   map[string]bool
	Networks []netip.Prefix
}

// ParseRule parses a single allowlist token such as "encrypted", "tcp:443@10.0.0.0/8", or "ethertype:0x9000".
func ParseRule(text string) (Rule, error) {
	raw := strings.ToLower(strings.TrimSpace(text))
	protoPart, scope, hasScope := strings.Cut(raw, "@")

	tokens := make(map[string]bool)
	switch {
	case len(Groups[protoPart]) > 0:
		for _, tok := range Groups[protoPart] {
			tokens[tok] = true
		}
	case Single[protoPart]:
		tokens[protoPart] = true
	case strings.HasPrefix(protoPart, "tcp:") || strings.HasPrefix(protoPart, "udp:") || strings.HasPrefix(protoPart, "proto:"):
		kind, val, _ := strings.Cut(protoPart, ":")
		if !isASCIIAllDigits(val) {
			return Rule{}, fmt.Errorf("allowlist token %q: %s: needs a number", text, kind)
		}
		num, err := strconv.Atoi(val)
		if err != nil {
			return Rule{}, fmt.Errorf("allowlist token %q: %s: needs a number", text, kind)
		}
		tokens[fmt.Sprintf("%s:%d", kind, num)] = true
	case strings.HasPrefix(protoPart, "ethertype:"):
		_, hexStr, _ := strings.Cut(protoPart, ":")
		hexStr = strings.TrimPrefix(strings.ToLower(hexStr), "0x")
		if hexStr == "" {
			return Rule{}, fmt.Errorf("allowlist token %q: ethertype: needs a hex number such as 0x9000", text)
		}
		val, err := strconv.ParseUint(hexStr, 16, 32)
		if err != nil {
			return Rule{}, fmt.Errorf("allowlist token %q: ethertype: needs a hex number such as 0x9000", text)
		}
		tokens[fmt.Sprintf("ethertype:0x%04x", val)] = true
	default:
		return Rule{}, fmt.Errorf("unknown allowlist token %q", text)
	}

	var nets []netip.Prefix
	if hasScope && scope != "" {
		for _, part := range strings.Split(scope, ",") {
			pfx, err := parseCIDROrAddr(strings.TrimSpace(part))
			if err != nil {
				return Rule{}, fmt.Errorf("allowlist token %q: %q is not an address or network", text, scope)
			}
			nets = append(nets, pfx)
		}
	}

	return Rule{Text: text, Tokens: tokens, Networks: nets}, nil
}

// ParseAllowlist parses all allowlist strings, defaulting to DefaultAllow when allow is empty.
func ParseAllowlist(allow []string) ([]string, []Rule, error) {
	items := allow
	if len(items) == 0 {
		items = DefaultAllow
	}
	texts := slices.Clone(items)
	rules := make([]Rule, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			continue
		}
		rule, err := ParseRule(item)
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, rule)
	}
	return texts, rules, nil
}

// Matches reports whether r permits the frame given its token set and endpoint IP addresses.
func (r Rule) Matches(tokens map[string]bool, addresses []string) bool {
	tokHit := false
	for tok := range r.Tokens {
		if tokens[tok] {
			tokHit = true
			break
		}
	}
	if !tokHit {
		return false
	}
	if len(r.Networks) == 0 {
		return true
	}
	for _, raw := range addresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		for _, pfx := range r.Networks {
			if pfx.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func isASCIIAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseCIDROrAddr(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
