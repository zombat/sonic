#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Zero-Cleartext Audit

An assertion over a capture of a crypto transport link: every frame must match
an allowlist, and anything else is reported by protocol and address pair with
frame numbers, then the audit passes or fails. One leaked GRE, BGP, OSPF, ICMP
or other cleartext packet fails it, so a runbook or an agent can gate on it.

Allowlist tokens (case-insensitive; combine freely):
    crypto          the default: esp, ike and nat-t below
    esp             IP protocol 50, and ESP-in-UDP on 4500
    ike             ISAKMP/IKE on UDP 500 and 4500
    nat-t           ESP-in-UDP, IKE on 4500 and NAT-T keepalives
    ah              IP protocol 51 (authenticates, does not encrypt)
    arp             ARP
    icmp / icmpv6   ICMP or ICMPv6
    routing         bgp, ospf, eigrp, rip, ldp, bfd, pim, vrrp, hsrp
    bgp / ospf / eigrp / rip / ldp / bfd / pim / vrrp / hsrp
    gre             plain GRE (an unencrypted tunnel)
    l2-control      CDP, STP, LLDP, LACP, Cisco loopback keepalives (EtherType 0x9000)
    cdp / stp / lldp / lacp / loop
    dhcp / dns / ntp / ssh / snmp / syslog / tacacs / radius
    tcp:N udp:N     a TCP or UDP port (either side)
    proto:N         an IP protocol number
    ethertype:0xN   an EtherType
A token may be scoped to addresses with @: "icmp@203.0.113.1" allows ICMP only
when one end is 203.0.113.1, "bgp@198.51.100.0/30" only inside that network.

What the audit cannot show, reported with every result:
- it covers only frames that crossed this capture point, and only frames the
  capture kept (a capture filter or a full ring buffer hides the rest);
- ESP with NULL encryption, or a weak cipher, looks like any other ESP;
- a non-first IP fragment carries no port, so a fragment of an allowed UDP
  protocol is reported as "udp" (fail-closed) unless tshark reassembled it.

Author: Raymond A Rizzo | Zombat
"""

import ipaddress
from typing import Any, Dict, List, Optional, Set, Tuple

from analyzers.network_common import Context, add_frame, cap, make_event, make_issue, protocol_label

DEFAULT_ALLOW = ["crypto"]

GROUPS = {
    "crypto": {"esp", "ike", "nat-t"},
    "routing": {"bgp", "ospf", "eigrp", "rip", "ldp", "bfd", "pim", "vrrp", "hsrp"},
    "l2-control": {"cdp", "stp", "lldp", "lacp", "loop"},
}
SINGLE = {"esp", "ike", "nat-t", "nat-keepalive", "ah", "arp", "icmp", "icmpv6", "bgp", "ospf", "eigrp", "rip",
          "ldp", "bfd", "pim", "vrrp", "hsrp", "gre", "cdp", "stp", "lldp", "lacp", "loop", "dhcp", "dns", "ntp",
          "ssh", "snmp", "syslog", "tacacs", "radius"}
PORT_NAMES = {179: "bgp", 520: "rip", 646: "ldp", 3784: "bfd", 3785: "bfd", 1985: "hsrp", 67: "dhcp", 68: "dhcp",
              53: "dns", 123: "ntp", 22: "ssh", 161: "snmp", 162: "snmp", 514: "syslog", 49: "tacacs",
              1812: "radius", 1813: "radius"}
PROTO_NAMES = {50: "esp", 51: "ah", 47: "gre", 89: "ospf", 88: "eigrp", 103: "pim", 112: "vrrp", 1: "icmp",
               58: "icmpv6"}
ETHERTYPE_TOKENS = {0x0806: "arp", 0x88CC: "lldp", 0x8809: "lacp", 0x9000: "loop"}
CATEGORY = {
    "esp": "crypto", "ike": "crypto", "nat-t": "crypto", "ah": "authenticated_only",
    "gre": "tunnel_without_encryption", "icmp": "icmp", "icmpv6": "icmp", "arp": "layer2",
    "cdp": "layer2", "stp": "layer2", "lldp": "layer2", "lacp": "layer2", "loop": "layer2", "llc": "layer2",
}
HINTS = {
    "tunnel_without_encryption": "GRE outside ESP: the overlay (and whatever it carries) crosses this link unencrypted",
    "routing": "a routing protocol in cleartext on the transport link (to the provider, or leaked from the overlay)",
    "icmp": "ICMP in cleartext: a ping or traceroute of the transport addresses, or traffic bypassing the tunnel",
    "layer2": "link-local layer 2 control traffic (it does not leave the link, but CDP/LLDP disclose device "
              "details to the provider side)",
    "cleartext": "application or management traffic outside the tunnel",
    "authenticated_only": "AH authenticates but does not encrypt",
}

CANNOT_SHOW = [
    "Only frames that crossed this capture point and that the capture kept are audited: a capture filter, "
    "a snap length or a full buffer can hide frames, and traffic on other links is not seen.",
    "ESP payload is opaque: ESP with NULL encryption or a weak cipher passes, because the cipher is negotiated "
    "inside IKE (visible only in IKE_SA_INIT for the IKE SA, never for the child SA).",
    "A non-first IP fragment carries no port; tshark reassembles fragments, the scapy fallback does not, so a "
    "fragment of an allowed UDP protocol can be reported as plain udp (fail-closed).",
]


def _tokens_for(rec: Dict[str, Any]) -> Tuple[Set[str], str, str]:
    """(every token this frame satisfies, its protocol name, its category)."""
    label = protocol_label(rec)
    tokens: Set[str] = set()
    ip = rec.get("ip")
    if not ip:
        if "arp" in rec:
            return {"arp", "ethertype:0x0806"}, "arp", "layer2"
        if "llc" in rec:
            name = rec["llc"]
            return {name} if name != "llc" else {"llc"}, name, "layer2"
        eth_type = rec.get("eth_type")
        if eth_type is not None:
            name = ETHERTYPE_TOKENS.get(eth_type, f"ethertype-0x{eth_type:04x}")
            return {name, f"ethertype:0x{eth_type:04x}"}, name, CATEGORY.get(name, "layer2")
        return {"other"}, "other", "layer2"
    proto = ip.get("proto")
    if proto is not None:
        tokens.add(f"proto:{proto}")
        if proto in PROTO_NAMES:
            tokens.add(PROTO_NAMES[proto])
    if "esp" in rec:
        tokens.add("esp")
        if rec["esp"].get("udp"):
            tokens.add("nat-t")
    if "ike" in rec:
        tokens.add("ike")
        if rec["ike"].get("natt"):
            tokens.add("nat-t")
    if rec.get("nat_keepalive"):
        tokens |= {"nat-t", "nat-keepalive"}
    for l4 in ("tcp", "udp"):
        if l4 in rec:
            for port in (rec[l4]["sport"], rec[l4]["dport"]):
                tokens.add(f"{l4}:{port}")
                if port in PORT_NAMES:
                    tokens.add(PORT_NAMES[port])
    if "ike" in rec or rec.get("nat_keepalive") or "esp" in rec:
        return tokens, label, "crypto"
    if "gre" in rec:
        name = label
        inner = rec.get("inner") or {}
        if "tcp" in inner and 179 in (inner["tcp"]["sport"], inner["tcp"]["dport"]):
            name = "gre/ipv4 (bgp inside)"
        elif "ospf" in inner:
            name = "gre/ipv4 (ospf inside)"
        elif "eigrp" in inner:
            name = "gre/ipv4 (eigrp inside)"
        elif "nhrp" in rec:
            name = "gre/nhrp"
        return tokens, name, "tunnel_without_encryption"
    routing = tokens & GROUPS["routing"]
    if routing:
        return tokens, sorted(routing)[0], "routing"
    if "icmp" in rec:
        return tokens, label, "icmp"
    if proto == 51:
        return tokens, "ah", "authenticated_only"
    return tokens, label, "cleartext"


class _Rule:
    """One allowlist token: a set of protocol tokens, optionally scoped to networks."""

    def __init__(self, text: str):
        self.text = text
        raw = text.strip().lower()
        scope = None
        if "@" in raw:
            raw, scope = raw.split("@", 1)
        if raw in GROUPS:
            self.tokens = set(GROUPS[raw])
        elif raw in SINGLE:
            self.tokens = {raw}
        elif raw.startswith(("tcp:", "udp:", "proto:")):
            kind, _, value = raw.partition(":")
            if not value.isdigit():
                raise ValueError(f"allowlist token {text!r}: {kind}: needs a number")
            self.tokens = {f"{kind}:{int(value)}"}
        elif raw.startswith("ethertype:"):
            try:
                value = int(raw.split(":", 1)[1], 16)
            except ValueError:
                raise ValueError(f"allowlist token {text!r}: ethertype: needs a hex number such as 0x9000")
            self.tokens = {f"ethertype:0x{value:04x}"}
        else:
            raise ValueError(f"unknown allowlist token {text!r}")
        self.networks = None
        if scope:
            try:
                self.networks = [ipaddress.ip_network(part.strip(), strict=False) for part in scope.split(",")]
            except ValueError:
                raise ValueError(f"allowlist token {text!r}: {scope!r} is not an address or network")

    def matches(self, tokens: Set[str], addresses: List[str]) -> bool:
        if not (self.tokens & tokens):
            return False
        if self.networks is None:
            return True
        for addr in addresses:
            try:
                parsed = ipaddress.ip_address(addr)
            except (ValueError, TypeError):
                continue
            if any(parsed in net for net in self.networks):
                return True
        return False


def parse_allowlist(allow: Optional[List[str]]) -> List[_Rule]:
    """Parse allowlist tokens; raises ValueError naming the first bad one."""
    items = list(allow) if allow else list(DEFAULT_ALLOW)
    return [_Rule(item) for item in items if str(item).strip()]


class CleartextAuditDetector:
    """Every frame against the allowlist; pass only when nothing falls outside it."""

    name = "cleartext_audit"

    def __init__(self, allow: Optional[List[str]] = None):
        self.allow_text = list(allow) if allow else list(DEFAULT_ALLOW)
        self.rules = parse_allowlist(self.allow_text)
        self.frames = 0
        self.allowed = 0
        self.allowed_by: Dict[str, int] = {}
        self.violations: Dict[tuple, Dict[str, Any]] = {}

    def feed(self, rec: Dict[str, Any]):
        self.frames += 1
        tokens, name, category = _tokens_for(rec)
        ip = rec.get("ip")
        if ip:
            src, dst = ip["src"], ip["dst"]
        elif "arp" in rec:
            src, dst = rec["arp"]["spa"], rec["arp"]["tpa"]
        else:
            src = dst = None
        for rule in self.rules:
            if rule.matches(tokens, [a for a in (src, dst) if a]):
                self.allowed += 1
                self.allowed_by[rule.text] = self.allowed_by.get(rule.text, 0) + 1
                return
        key = (name, src, dst)
        entry = self.violations.get(key)
        if entry is None:
            entry = {"protocol": name, "category": category, "src": src, "dst": dst, "packets": 0, "bytes": 0,
                     "first_frame": rec["n"], "first_t": rec["t"], "last_frame": rec["n"], "last_t": rec["t"],
                     "frames": []}
            self.violations[key] = entry
        entry["packets"] += 1
        entry["bytes"] += rec.get("len", 0)
        entry["last_frame"], entry["last_t"] = rec["n"], rec["t"]
        add_frame(entry["frames"], rec["n"])

    def present(self) -> bool:
        return self.frames > 0

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        rows = sorted(self.violations.values(), key=lambda v: v["first_frame"])
        by_protocol: Dict[str, Dict[str, Any]] = {}
        for v in rows:
            agg = by_protocol.setdefault(v["protocol"], {"protocol": v["protocol"], "category": v["category"],
                                                        "packets": 0, "bytes": 0, "pairs": 0,
                                                        "first_frame": v["first_frame"]})
            agg["packets"] += v["packets"]
            agg["bytes"] += v["bytes"]
            agg["pairs"] += 1
        violations_out = []
        for v in rows:
            pair = f"{v['src']} -> {v['dst']}" if v["src"] else "(layer 2, no addresses)"
            violations_out.append({
                "protocol": v["protocol"], "category": v["category"], "src": v["src"], "dst": v["dst"],
                "packets": v["packets"], "bytes": v["bytes"], "first_frame": v["first_frame"],
                "first_t": ctx.rel(v["first_t"]), "last_frame": v["last_frame"], "last_t": ctx.rel(v["last_t"]),
                "frames": v["frames"], "hint": HINTS.get(v["category"], HINTS["cleartext"])})
            severity = "warning" if v["category"] == "layer2" else "error"
            issues.append(make_issue(severity, "CLEARTEXT_OUTSIDE_ALLOWLIST",
                                     f"{v['packets']} {v['protocol']} frame(s) {pair} outside the allowlist "
                                     f"({HINTS.get(v['category'], HINTS['cleartext'])})", v["frames"],
                                     protocol=v["protocol"], category=v["category"]))
            events.append(make_event(ctx, v["first_t"], "audit", "first_leak",
                                     f"first {v['protocol']} frame outside the allowlist {pair}", v["first_frame"]))
        violating = sum(v["packets"] for v in rows)
        passed = violating == 0 and self.frames > 0
        if not self.frames:
            verdict = "FAIL: the capture is empty, so nothing proves the link carried only allowed traffic"
            issues.append(make_issue("error", "AUDIT_EMPTY_CAPTURE", verdict))
        elif passed:
            verdict = (f"PASS: all {self.frames} frames match the allowlist ({', '.join(self.allow_text)}); "
                       "no cleartext outside it")
        else:
            parts = [f"{agg['packets']} {name}" for name, agg in
                     sorted(by_protocol.items(), key=lambda kv: kv[1]["first_frame"])]
            first = rows[0]
            verdict = (f"FAIL: {violating} of {self.frames} frames outside the allowlist ({', '.join(parts)}); "
                       f"first at frame {first['first_frame']}")
        listed, omitted = cap(violations_out, ctx.max_items)
        return {
            "detector": self.name,
            "status": "ok" if passed else "problem",
            "verdict": verdict,
            "passed": passed,
            "result": "pass" if passed else "fail",
            "allowlist": self.allow_text,
            "frames_audited": self.frames,
            "frames_allowed": self.allowed,
            "frames_outside_allowlist": violating,
            "allowed_by_rule": self.allowed_by,
            "by_protocol": sorted(by_protocol.values(), key=lambda a: a["first_frame"]),
            "violations": listed,
            "violations_omitted": omitted,
            "first_violation_frame": rows[0]["first_frame"] if rows else None,
            "cannot_show": CANNOT_SHOW,
            "issues": issues,
            "events": events,
        }
