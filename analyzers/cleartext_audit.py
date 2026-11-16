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
    dhcp / dns / ntp / snmp / syslog / tacacs / radius
    ssh             an SSH session, recognised by its SSH-2.0 banner on any port (not by port 22)
    netconf         an SSH session to port 830 (NETCONF over SSH)
    tls             a TLS session, recognised by its record header on any port (not by port 443)
    http2           cleartext HTTP/2 (h2c, gRPC without TLS), recognised by its connection preface
    encrypted       the default crypto group plus ssh and tls: transport encryption of any kind
    tcp:N udp:N     a TCP or UDP port (either side)
    proto:N         an IP protocol number
    ethertype:0xN   an EtherType
A token may be scoped to addresses with @: "icmp@203.0.113.1" allows ICMP only
when one end is 203.0.113.1, "bgp@198.51.100.0/30" only inside that network.

Protection by content: every TCP connection is recognised from its first payload
in either direction, on any port. SSH by its "SSH-2.0-" banner: the banner and the
key exchange (KEXINIT up to NEWKEYS) are key_exchange, everything after NEWKEYS is
encrypted. TLS by its record header (content type 20 to 23, version 3.1 to 3.4):
handshake, ChangeCipherSpec and alerts before encryption are key_exchange, records of
type 23 (application data, and TLS 1.3's encrypted handshake) are encrypted. HTTP/2 by
its connection preface: cleartext management traffic, named "grpc" when its requests
are gRPC (read with Wireshark's HPACK decoder, which also finds credentials sent in
gRPC metadata; see analyzers/grpc_inspect.py). Each flow is labelled by its service
port: the SYN's destination, not the client's ephemeral port. Every frame is counted
once in "protection" (encrypted, key_exchange, cleartext, authenticated_only, layer2),
whatever the allowlist says, so "is anything cleartext" is answered even when the
allowlist fails an encrypted session that is simply not on it.

What the audit cannot show, reported with every result:
- it covers only frames that crossed this capture point, and only frames the
  capture kept (a capture filter or a full ring buffer hides the rest);
- ESP with NULL encryption, or a weak cipher, looks like any other ESP;
- a non-first IP fragment carries no port: it is allowed when the first
  fragment of the same datagram (same addresses and IP identification) was,
  and reported as "udp" (fail-closed) when that first fragment was not captured.

Author: Raymond A Rizzo | Zombat
"""

import ipaddress
from typing import Any, Dict, List, Optional, Set, Tuple

from analyzers.dataplane_common import seq_delta
from analyzers.network_common import (
    SERVICE_NAMES, Context, MAX_FRAMES, add_frame, cap, make_event, make_issue, protocol_label, service_port,
)

DEFAULT_ALLOW = ["crypto"]

GROUPS = {
    "crypto": {"esp", "ike", "nat-t"},
    "encrypted": {"esp", "ike", "nat-t", "ssh", "tls"},
    "routing": {"bgp", "ospf", "eigrp", "rip", "ldp", "bfd", "pim", "vrrp", "hsrp"},
    "l2-control": {"cdp", "stp", "lldp", "lacp", "loop"},
}
SINGLE = {"esp", "ike", "nat-t", "nat-keepalive", "ah", "arp", "icmp", "icmpv6", "bgp", "ospf", "eigrp", "rip",
          "ldp", "bfd", "pim", "vrrp", "hsrp", "gre", "cdp", "stp", "lldp", "lacp", "loop", "dhcp", "dns", "ntp",
          "ssh", "netconf", "tls", "http2", "snmp", "syslog", "tacacs", "radius"}
# ssh, tls and http2 come from the payload (see _TcpSession), never from a port number alone.
PORT_NAMES = {179: "bgp", 520: "rip", 646: "ldp", 3784: "bfd", 3785: "bfd", 1985: "hsrp", 67: "dhcp", 68: "dhcp",
              53: "dns", 123: "ntp", 161: "snmp", 162: "snmp", 514: "syslog", 49: "tacacs",
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
    "encrypted": "an encrypted session (SSH or TLS) that is not on the allowlist: not cleartext, but not one of the "
                 "protocols this link may carry (allow ssh, tls, netconf or encrypted to accept it)",
    "cleartext_management": "cleartext HTTP/2 (gRPC, gNMI or gNOI without TLS): every request, response and "
                            "metadata value, credentials included, is readable on the wire",
}
# Each frame's protection, whatever the allowlist: by category, and for SSH/TLS by the frame's own class.
PROTECTION = {"crypto": None, "authenticated_only": "authenticated_only", "layer2": "layer2"}
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_SESSIONS = 100000
MAX_SSH_KEX_BYTES = 65536

CANNOT_SHOW = [
    "Only frames that crossed this capture point and that the capture kept are audited: a capture filter, "
    "a snap length or a full buffer can hide frames, and traffic on other links is not seen.",
    "ESP payload is opaque: ESP with NULL encryption or a weak cipher passes, because the cipher is negotiated "
    "inside IKE (visible only in IKE_SA_INIT for the IKE SA, never for the child SA).",
    "A non-first IP fragment carries no port: it follows its datagram's first fragment (same addresses and IP "
    "identification); when that first fragment is not in the capture it is reported as plain udp (fail-closed).",
]


def _is_tls_record(data: bytes) -> bool:
    return len(data) >= 5 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] <= 4 and \
        int.from_bytes(data[3:5], "big") <= 18432


class _Direction:
    """One direction of a recognised TCP session: where its key exchange ends (SSH) or its records are (TLS)."""

    __slots__ = ("base", "buf", "lost", "kex_end", "next_record", "last_type", "encrypted_from")

    def __init__(self, base: int):
        self.base = base
        self.buf = bytearray()
        self.lost = False
        self.kex_end: Optional[int] = None  # SSH: stream offset where NEWKEYS ends
        self.next_record = 0  # TLS: stream offset of the next record header
        self.last_type: Optional[int] = None
        self.encrypted_from: Optional[int] = None

    def ssh_classify(self, rel: int, payload: bytes) -> str:
        """key_exchange or encrypted for one SSH segment starting at stream offset rel."""
        if self.kex_end is not None:
            return "encrypted" if rel >= self.kex_end else "key_exchange"
        if self.lost:
            return "encrypted"
        if rel != len(self.buf):
            if rel < len(self.buf):
                return "key_exchange"  # a retransmission of bytes already read
            self.lost = True  # a gap: the key exchange cannot be followed further
            return "encrypted"
        self.buf += payload
        pos = self.buf.find(b"\n") + 1 if self.buf.startswith(b"SSH-") else 0
        if self.buf.startswith(b"SSH-") and pos == 0:
            return "key_exchange"
        while pos + 6 <= len(self.buf):
            length = int.from_bytes(self.buf[pos:pos + 4], "big")
            if length < 2 or length > 35000:
                self.lost = True
                break
            code = self.buf[pos + 5]
            if code == 21:  # SSH_MSG_NEWKEYS: the next packet is encrypted
                self.kex_end = pos + 4 + length
                self.buf = bytearray()
                break
            pos += 4 + length
        if len(self.buf) > MAX_SSH_KEX_BYTES:
            self.lost = True
            self.buf = bytearray()
        return "key_exchange"

    def tls_classify(self, rel: int, payload: bytes, length: int) -> str:
        """key_exchange or encrypted for one TLS segment: application data records (23) are encrypted."""
        if self.lost:
            return "encrypted"
        end = rel + length
        if end <= self.next_record:
            return self._continuing()  # inside a record already being read, or a retransmission
        types: List[int] = []
        carry = self.buf
        while self.next_record < end:
            offset = self.next_record - rel
            if offset < 0 and not carry:
                self.lost = True  # the segment holding this header was not captured
                break
            if carry:
                header = bytes(carry) + payload[:5 - len(carry)]
                carry = self.buf = bytearray()
            else:
                header = payload[offset:offset + 5]
            if len(header) < 5:
                if offset + 5 <= length:
                    self.lost = True  # the header is past the bytes the extractor kept
                else:
                    self.buf = bytearray(header)  # the header continues in the next segment
                break
            if not _is_tls_record(header):
                self.lost = True
                break
            types.append(header[0])
            self.last_type = header[0]
            self.next_record += 5 + int.from_bytes(header[3:5], "big")
        if self.lost or 23 in types:
            return "encrypted"
        if types:
            return "key_exchange"
        return self._continuing()

    def _continuing(self) -> str:
        return "encrypted" if self.last_type == 23 else "key_exchange"


class _TcpSession:
    """One TCP connection, recognised by content (ssh, tls, http2 or other) and bucketed per direction and class."""

    __slots__ = ("server", "client", "kind", "spoke", "dirs", "buckets", "svc")

    def __init__(self):
        self.server: Optional[Tuple[str, int]] = None
        self.client: Optional[Tuple[str, int]] = None
        self.kind: Optional[str] = None
        self.spoke: Set[Tuple[str, int]] = set()
        self.dirs: Dict[Tuple[str, int], _Direction] = {}
        self.buckets: Dict[Tuple[Tuple[str, int], str], Dict[str, Any]] = {}
        self.svc: Optional[int] = None

    def add(self, src, cls: str, rec: Dict[str, Any]):
        bucket = self.buckets.get((src, cls))
        if bucket is None:
            bucket = {"packets": 0, "bytes": 0, "first_frame": rec["n"], "first_t": rec["t"],
                      "last_frame": rec["n"], "last_t": rec["t"], "frames": []}
            self.buckets[(src, cls)] = bucket
        bucket["packets"] += 1
        bucket["bytes"] += rec.get("len", 0)
        bucket["last_frame"], bucket["last_t"] = rec["n"], rec["t"]
        add_frame(bucket["frames"], rec["n"])


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
    dp = rec.get("dp") or {}
    if "udp" in rec and dp.get("mf") and not dp.get("off"):
        # The first fragment of a large IKE or ESP-in-UDP datagram: too short to parse, known by its ports.
        ports = {rec["udp"]["sport"], rec["udp"]["dport"]}
        if 500 in ports:
            tokens.add("ike")
        if 4500 in ports:
            tokens |= {"ike", "nat-t"}
    if "ike" in rec or rec.get("nat_keepalive") or "esp" in rec or tokens & {"ike", "nat-t"}:
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


def _protection_of(rec: Dict[str, Any], category: str) -> str:
    """encrypted, key_exchange, authenticated_only, layer2 or cleartext for a frame on the per-frame path."""
    if category == "crypto":
        return "encrypted" if "esp" in rec else "key_exchange"
    return PROTECTION.get(category) or "cleartext"


def _session_label(kind: Optional[str], svc: Optional[int]) -> Tuple[str, str, Set[str]]:
    """(protocol name, category, tokens) of a recognised TCP session."""
    port = f"tcp/{svc}" if svc is not None else "tcp"
    if kind == "ssh":
        if svc == 830:
            return f"netconf over ssh ({port})", "encrypted", {"ssh", "netconf"}
        return f"ssh ({port})", "encrypted", {"ssh"}
    if kind == "tls":
        name = SERVICE_NAMES.get(svc) if svc is not None else None
        return (f"tls ({port} {name})" if name else f"tls ({port})"), "encrypted", {"tls"}
    if kind == "http2":
        return f"http2 ({port})", "cleartext_management", {"http2"}
    return port, "cleartext", set()


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
        self.allowed_datagrams: Dict[tuple, str] = {}  # (src, dst, ip id) of allowed first fragments
        self.sessions: Dict[tuple, _TcpSession] = {}
        self.protection: Dict[str, int] = {}
        self.sessions_dropped = 0

    def _protect(self, cls: str, count: int = 1):
        self.protection[cls] = self.protection.get(cls, 0) + count

    def _tcp(self, rec: Dict[str, Any]) -> bool:
        """Route an outer TCP frame into its session; False when it must take the per-frame path."""
        ip, tcp, dp = rec.get("ip"), rec.get("tcp"), rec.get("dp") or {}
        if not ip or not tcp or "gre" in rec or dp.get("mf") or dp.get("off"):
            return False
        src, dst = (ip["src"], tcp["sport"]), (ip["dst"], tcp["dport"])
        key = (src, dst) if (src, dst) <= (dst, src) else (dst, src)
        session = self.sessions.get(key)
        if session is None:
            if len(self.sessions) >= MAX_SESSIONS:
                self.sessions_dropped += 1
                return False
            session = _TcpSession()
            self.sessions[key] = session
        flags = tcp.get("flags", 0)
        if flags & 0x02 and not flags & 0x10:
            session.server, session.client = dst, src
        elif flags & 0x02 and flags & 0x10 and session.server is None:
            session.server, session.client = src, dst
        payload = dp.get("pl") or b""
        seq = (dp.get("tcp") or {}).get("seq")
        cls = "pending"
        if payload and seq is not None:
            if session.kind is None:
                if payload.startswith(b"SSH-"):
                    session.kind = "ssh"
                elif payload.startswith(PREFACE):
                    session.kind = "http2"
                    if session.server is None:
                        session.server, session.client = dst, src
                elif _is_tls_record(payload) and payload[0] == 22:
                    session.kind = "tls"
                    if session.server is None and len(payload) > 5 and payload[5] == 1:  # ClientHello
                        session.server, session.client = dst, src
                else:
                    session.spoke.add(src)
                    if len(session.spoke) == 2:
                        session.kind = "other"
            direction = session.dirs.get(src)
            if direction is None and session.kind in ("ssh", "tls"):
                direction = _Direction(seq)
                session.dirs[src] = direction
            rel = seq_delta(seq, direction.base) if direction is not None else 0
            if session.kind == "ssh":
                cls = direction.ssh_classify(rel, payload)
            elif session.kind == "tls":
                cls = direction.tls_classify(rel, payload, tcp.get("len", len(payload)))
            elif session.kind == "http2":
                cls = "cleartext"
        elif session.kind in ("ssh", "tls"):
            direction = session.dirs.get(src)
            cls = "encrypted" if direction is not None and (direction.kex_end is not None or
                                                            direction.last_type == 23) else "pending"
        elif session.kind in ("http2", "other"):
            cls = "cleartext"
        session.add(src, cls, rec)
        return True

    def feed(self, rec: Dict[str, Any]):
        self.frames += 1
        if self._tcp(rec):
            return
        tokens, name, category = _tokens_for(rec)
        self._protect(_protection_of(rec, category))
        ip = rec.get("ip")
        if ip:
            src, dst = ip["src"], ip["dst"]
        elif "arp" in rec:
            src, dst = rec["arp"]["spa"], rec["arp"]["tpa"]
        else:
            src = dst = None
        dp = rec.get("dp") or {}
        datagram = (src, dst, dp.get("id")) if ip and dp.get("id") is not None else None
        if datagram and dp.get("off") and datagram in self.allowed_datagrams:
            rule_text = self.allowed_datagrams[datagram]  # a later fragment of an allowed datagram
            self.allowed += 1
            self.allowed_by[rule_text] = self.allowed_by.get(rule_text, 0) + 1
            return
        for rule in self.rules:
            if rule.matches(tokens, [a for a in (src, dst) if a]):
                self.allowed += 1
                self.allowed_by[rule.text] = self.allowed_by.get(rule.text, 0) + 1
                if datagram and dp.get("mf") and not dp.get("off") and len(self.allowed_datagrams) < 65536:
                    self.allowed_datagrams[datagram] = rule.text
                return
        self._violate(name, category, src, dst, {"packets": 1, "bytes": rec.get("len", 0), "first_frame": rec["n"],
                                                 "first_t": rec["t"], "last_frame": rec["n"], "last_t": rec["t"],
                                                 "frames": [rec["n"]]}, _protection_of(rec, category))

    def _violate(self, name, category, src, dst, bucket: Dict[str, Any], protection: str):
        key = (name, src, dst)
        entry = self.violations.get(key)
        if entry is None:
            entry = {"protocol": name, "category": category, "src": src, "dst": dst, "packets": 0, "bytes": 0,
                     "first_frame": bucket["first_frame"], "first_t": bucket["first_t"],
                     "last_frame": bucket["last_frame"], "last_t": bucket["last_t"], "frames": [], "protection": {}}
            self.violations[key] = entry
        entry["packets"] += bucket["packets"]
        entry["bytes"] += bucket["bytes"]
        if bucket["first_frame"] < entry["first_frame"]:
            entry["first_frame"], entry["first_t"] = bucket["first_frame"], bucket["first_t"]
        if bucket["last_frame"] >= entry["last_frame"]:
            entry["last_frame"], entry["last_t"] = bucket["last_frame"], bucket["last_t"]
        entry["frames"] = sorted(set(entry["frames"]) | set(bucket["frames"]))[:MAX_FRAMES]
        entry["protection"][protection] = entry["protection"].get(protection, 0) + bucket["packets"]

    def _settle_sessions(self) -> List[Dict[str, Any]]:
        """Judge every TCP session's frames now that each session's protocol is known."""
        summaries = []
        for (end_a, end_b), session in self.sessions.items():
            kind = session.kind or "other"
            if session.server is not None:
                svc = session.server[1]
            else:
                svc = service_port(end_a[1], end_b[1])
            server = session.server or (end_a if end_a[1] == svc else end_b)
            client = end_b if server == end_a else end_a
            name, category, kind_tokens = _session_label(kind, svc)
            ports = {f"tcp:{end_a[1]}", f"tcp:{end_b[1]}", "proto:6"}
            ports |= {PORT_NAMES[p] for p in (end_a[1], end_b[1]) if p in PORT_NAMES}
            if kind == "other":
                routing = ports & GROUPS["routing"]
                if routing:
                    name, category = sorted(routing)[0], "routing"
            tokens = ports | kind_tokens
            if kind == "ssh" and svc != 830:
                tokens.discard("netconf")
            totals: Dict[str, int] = {}
            packets = 0
            for (src, cls), bucket in sorted(session.buckets.items(), key=lambda kv: kv[1]["first_frame"]):
                if cls == "pending":
                    cls = "key_exchange" if kind in ("ssh", "tls") else "cleartext"
                if category == "routing":
                    cls = "cleartext"
                dst = end_b if src == end_a else end_a
                self._protect(cls, bucket["packets"])
                totals[cls] = totals.get(cls, 0) + bucket["packets"]
                packets += bucket["packets"]
                for rule in self.rules:
                    if rule.matches(tokens, [src[0], dst[0]]):
                        self.allowed += bucket["packets"]
                        self.allowed_by[rule.text] = self.allowed_by.get(rule.text, 0) + bucket["packets"]
                        break
                else:
                    self._violate(name, category, src[0], dst[0], bucket, cls)
            summaries.append({"protocol": name, "client": f"{client[0]}:{client[1]}",
                              "server": f"{server[0]}:{server[1]}", "service": f"tcp/{svc}",
                              "server_known_by": "syn" if session.server is not None else "port",
                              "category": category, "packets": packets, "protection": totals,
                              "first_frame": min(b["first_frame"] for b in session.buckets.values())})
        self.sessions = {}
        return sorted(summaries, key=lambda x: x["first_frame"])

    def present(self) -> bool:
        return self.frames > 0

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        sessions = self._settle_sessions()
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
                "frames": v["frames"], "protection": v["protection"],
                "hint": HINTS.get(v["category"], HINTS["cleartext"])})
            text = (f"{v['packets']} {v['protocol']} frame(s) {pair} outside the allowlist "
                    f"({HINTS.get(v['category'], HINTS['cleartext'])})")
            if v["category"] == "encrypted":
                issues.append(make_issue("warning", "ENCRYPTED_OUTSIDE_ALLOWLIST", text, v["frames"],
                                         protocol=v["protocol"], category=v["category"]))
            else:
                severity = "warning" if v["category"] == "layer2" else "error"
                issues.append(make_issue(severity, "CLEARTEXT_OUTSIDE_ALLOWLIST", text, v["frames"],
                                         protocol=v["protocol"], category=v["category"]))
            events.append(make_event(ctx, v["first_t"], "audit", "first_leak",
                                     f"first {v['protocol']} frame outside the allowlist {pair}", v["first_frame"]))
        violating = sum(v["packets"] for v in rows)
        passed = violating == 0 and self.frames > 0
        cleartext = self.protection.get("cleartext", 0)
        protected = ", ".join(f"{self.protection[k]} {k.replace('_', ' ')}" for k in
                              ("encrypted", "key_exchange", "authenticated_only", "layer2", "cleartext")
                              if self.protection.get(k))
        if not self.frames:
            verdict = "FAIL: the capture is empty, so nothing proves the link carried only allowed traffic"
            issues.append(make_issue("error", "AUDIT_EMPTY_CAPTURE", verdict))
        elif passed:
            verdict = (f"PASS: all {self.frames} frames match the allowlist ({', '.join(self.allow_text)}); "
                       f"no cleartext outside it ({protected})")
        else:
            parts = [f"{agg['packets']} {name}" for name, agg in
                     sorted(by_protocol.items(), key=lambda kv: kv[1]["first_frame"])]
            first = rows[0]
            verdict = (f"FAIL: {violating} of {self.frames} frames outside the allowlist ({', '.join(parts)}); "
                       f"first at frame {first['first_frame']}")
            outside_clear = sum(v["protection"].get("cleartext", 0) for v in rows)
            if not outside_clear:
                verdict += (f"; none of them is cleartext ({protected}): allow ssh, tls, netconf or encrypted to "
                            "accept transport encryption")
            else:
                verdict += f"; {outside_clear} of them cleartext"
                if protected != f"{cleartext} cleartext":
                    verdict += f" (all frames: {protected})"
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
            "cleartext_frames": cleartext,
            "protection": {k: self.protection.get(k, 0) for k in
                           ("encrypted", "key_exchange", "authenticated_only", "layer2", "cleartext")},
            "tcp_sessions": cap(sessions, ctx.max_items)[0],
            "tcp_sessions_omitted": cap(sessions, ctx.max_items)[1],
            "allowed_by_rule": self.allowed_by,
            "by_protocol": sorted(by_protocol.values(), key=lambda a: a["first_frame"]),
            "violations": listed,
            "violations_omitted": omitted,
            "first_violation_frame": rows[0]["first_frame"] if rows else None,
            "cannot_show": CANNOT_SHOW,
            "issues": issues,
            "events": events,
        }


def add_grpc_findings(section: Dict[str, Any], file_path: str, display_filter: Optional[str] = None,
                      max_packets: Optional[int] = None) -> None:
    """
    Name cleartext HTTP/2 as gRPC and flag credentials in its metadata, in place.

    HPACK Huffman-codes header values, so a byte search cannot find a password sent in
    gRPC metadata; Wireshark's HPACK decoder can (analyzers/grpc_inspect.py, through
    tshark). Each credential key on a flow becomes one CLEARTEXT_CREDENTIAL issue, with
    the value never read into the report. Without tshark the section says why the
    credential check did not run.
    """
    rows = list(section.get("tcp_sessions", [])) + list(section.get("violations", []))
    if not any(str(r.get("protocol", "")).startswith("http2 (") for r in rows):
        return
    from analyzers.grpc_inspect import analyze_grpc_capture
    report = analyze_grpc_capture(file_path, display_filter=display_filter, max_packets=max_packets,
                                  include_tls=False, max_items=100)
    if report.get("status") != "success":
        section["grpc"] = {"checked": False, "error": report.get("error")}
        return
    grpc_ports = {}
    for conn in report.get("connections", []):
        if conn.get("protocol") == "grpc" and conn.get("service"):
            grpc_ports.setdefault(conn["service"], set()).update(conn.get("services", []))
    renamed = {}
    for port, services in grpc_ports.items():
        renamed[f"http2 ({port})"] = f"grpc ({port})"
    for key in ("violations", "by_protocol", "tcp_sessions"):
        for row in section.get(key, []):
            new = renamed.get(row.get("protocol"))
            if new:
                row["protocol"] = new
                row["grpc_services"] = sorted(grpc_ports[new[6:-1]])
    for old, new in renamed.items():
        section["verdict"] = section["verdict"].replace(old, new)
        for issue in section.get("issues", []):
            issue["message"] = issue["message"].replace(old, new)
            if issue.get("protocol") == old:
                issue["protocol"] = new
    credentials = report.get("credentials", [])
    section["credentials"] = credentials
    section["grpc"] = {"checked": True, "connections": len(report.get("connections", [])),
                       "rpcs": report.get("summary", {}).get("rpcs", 0),
                       "services": sorted({svc for svcs in grpc_ports.values() for svc in svcs})}
    for issue in report.get("issues", []):
        if issue["code"] == "CLEARTEXT_CREDENTIAL":
            section.setdefault("issues", []).append(dict(issue))
    clear = sorted({c["key"] for c in credentials if c.get("cleartext")})
    if clear:
        section["verdict"] += (f"; credentials in cleartext gRPC metadata: {', '.join(clear)} "
                               "(values masked)")
