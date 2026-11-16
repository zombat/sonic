#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Zero-Cleartext Audit

An assertion over a capture of a crypto transport link: every frame must match
an allowlist, and anything else is reported by protocol and address pair with
frame numbers, then the audit passes or fails. One leaked GRE, BGP, OSPF, ICMP
or other cleartext packet fails it, so a runbook or an agent can gate on it.

Allowlist tokens (case-insensitive; combine freely):
    encrypted       the default: crypto below plus ssh and tls, each only when its handshake shows real
                    encryption (see "Encryption proven by the handshake")
    crypto          IPsec only: esp, ike and nat-t below (the tunnel question: SSH and TLS then fail)
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
    ssh             an SSH session, recognised by its SSH-2.0 banner on any port (not by port 22), whose
                    key exchange did not choose the cipher none
    netconf         an SSH session to port 830 (NETCONF over SSH), on the same terms
    tls             a TLS session, recognised by its record header on any port (not by port 443), whose
                    ServerHello did not choose a suite that leaves the records readable
    http2           cleartext HTTP/2 (h2c, gRPC without TLS), recognised by its connection preface
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

Encryption proven by the handshake: an SSH or TLS session passes the ssh, tls, netconf and
encrypted tokens only when its handshake shows that the records really are encrypted.
    TLS   the suite the ServerHello chose (analyzers/tls_inspect.py's suite table). NULL
          ciphers, anonymous and export key exchange and the RFC 9150 integrity-only suites
          (TLS_SHA256_SHA256, TLS_SHA384_SHA384) count as cleartext; TLS 1.1 and older, RC4,
          DES, 3DES and MD5 pass as weak (a warning).
    SSH   the cipher of each direction, derived from both KEXINITs as RFC 4253 7.1 does (the
          first algorithm on the client's list that the server also offers). The cipher none
          counts as cleartext; arcfour, CBC modes and 64-bit block ciphers pass as weak.
A session that does not encrypt is named "<protocol> without encryption" (category
unencrypted_session), its frames after the handshake count as cleartext, and no ssh or tls
token matches it. A session whose handshake is not in the capture passes as "encrypted,
unverified" (a warning, never a clean pass): a TLS session already past its handshake is
recognised by its application data records, and an SSH session that began before the capture
by its port (22 or 830) and by payload that looks like ciphertext. Each session's finding is
in tcp_sessions[].encryption, the totals in "encryption", and "clean" is true only for a pass
with no weak or unverified session. An SSH or TLS session that passes is still reported, as
information (ENCRYPTED_OUTSIDE_TUNNEL), as protected by its own encryption rather than by
IPsec; allow crypto alone to require the tunnel.

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
from analyzers.tls_inspect import (
    TLS13_SUITES, parse_server_hello, server_hello_suite, suite_encryption, suite_name, version_is_weak,
)

DEFAULT_ALLOW = ["encrypted"]

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
                 "protocols this link may carry (allow ssh, tls, netconf or encrypted, the default, to accept it)",
    "unencrypted_session": "an SSH or TLS session whose handshake chose no real encryption (TLS: a NULL, anonymous, "
                           "export or integrity-only suite; SSH: the cipher none): what it carries crosses the link "
                           "readable",
    "cleartext_management": "cleartext HTTP/2 (gRPC, gNMI or gNOI without TLS): every request, response and "
                            "metadata value, credentials included, is readable on the wire",
}
# Each frame's protection, whatever the allowlist: by category, and for SSH/TLS by the frame's own class.
PROTECTION = {"crypto": None, "authenticated_only": "authenticated_only", "layer2": "layer2"}
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_SESSIONS = 100000
MAX_SSH_KEX_BYTES = 65536
MAX_HELLO_BYTES = 8192  # bytes of a TLS direction read for its ServerHello

# SSH ciphers (RFC 4253 6.3, RFC 4344, RFC 5647 and OpenSSH's): AEAD ones carry their own MAC.
SSH_AEAD = {"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm",
            "aes256-gcm", "aead_aes_128_gcm", "aead_aes_256_gcm"}
SSH_STRONG = SSH_AEAD | {"aes128-ctr", "aes192-ctr", "aes256-ctr"}
SSH_NAME_LISTS = ("kex", "host_key", "cipher_client_to_server", "cipher_server_to_client", "mac_client_to_server",
                  "mac_server_to_client", "compression_client_to_server", "compression_server_to_client")
# An SSH session that began before the capture: recognised only on these ports, and only by ciphertext.
SSH_PORTS = {22, 830}
MIN_PROBE_BYTES = 128
MAX_PROBE_BYTES = 65536
PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\r\n"
STATE_RANK = {"encrypted": 0, "not_started": 0, "weak": 1, "unverified": 2, "cleartext": 3}

CANNOT_SHOW = [
    "Only frames that crossed this capture point and that the capture kept are audited: a capture filter, "
    "a snap length or a full buffer can hide frames, and traffic on other links is not seen.",
    "ESP payload is opaque: ESP with NULL encryption or a weak cipher passes, because the cipher is negotiated "
    "inside IKE (visible only in IKE_SA_INIT for the IKE SA, never for the child SA).",
    "A non-first IP fragment carries no port: it follows its datagram's first fragment (same addresses and IP "
    "identification); when that first fragment is not in the capture it is reported as plain udp (fail-closed).",
    "SSH and TLS are judged by their handshake: the TLS suite in the ServerHello, the SSH cipher from both "
    "KEXINITs. Without the handshake (a session that began before the capture) a NULL cipher looks like a real "
    "one, so such a session passes only as encrypted, unverified (a warning). A TLS session is recognised that "
    "way only when a segment begins at a record boundary, an SSH session only on tcp/22 or tcp/830 and only when "
    "its payload looks like ciphertext; anything else is reported as cleartext (fail-closed).",
    "Encryption is judged by the cipher's name: key sizes, certificate trust and the strength of the key "
    "exchange are not (analyze_network_pcap's tls detector reads certificates and checks a baseline).",
]


def _is_tls_record(data: bytes) -> bool:
    return len(data) >= 5 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] <= 4 and \
        int.from_bytes(data[3:5], "big") <= 18432


def _tls_midstream(payload: bytes) -> bool:
    """A segment of a TLS session already past its handshake: application data or alert records from byte 0."""
    if len(payload) < 5 or payload[0] not in (21, 23) or payload[1] != 3 or not 1 <= payload[2] <= 3:
        return False
    version, pos = payload[1:3], 0
    while pos + 5 <= len(payload):
        length = int.from_bytes(payload[pos + 3:pos + 5], "big")
        if payload[pos] not in (20, 21, 22, 23) or payload[pos + 1:pos + 3] != version or not 0 < length <= 18432:
            return False
        pos += 5 + length
    return True


def _parse_kexinit(payload: bytes) -> Optional[Dict[str, List[str]]]:
    """The name-lists of one SSH_MSG_KEXINIT payload (RFC 4253 7.1), or None when it is malformed."""
    if len(payload) < 17 or payload[0] != 20:
        return None
    out: Dict[str, List[str]] = {}
    pos = 17  # message code and the 16-byte cookie
    for field in SSH_NAME_LISTS:
        if pos + 4 > len(payload):
            return None
        length = int.from_bytes(payload[pos:pos + 4], "big")
        if pos + 4 + length > len(payload):
            return None
        out[field] = [n for n in payload[pos + 4:pos + 4 + length].decode("ascii", "replace").split(",") if n]
        pos += 4 + length
    return out


def _ssh_choose(client: List[str], server: List[str]) -> Optional[str]:
    """RFC 4253 7.1: the first algorithm on the client's name-list that is also on the server's."""
    offered = set(server)
    return next((name for name in client if name in offered), None)


def _ssh_cipher(name: Optional[str]) -> Tuple[str, Optional[str]]:
    """(encrypted | weak | unverified | cleartext, why) for one negotiated SSH cipher."""
    if name is None:
        return "unverified", "the two KEXINITs offer no cipher in common, so the key exchange cannot complete"
    low = name.lower()
    if low == "none":
        return "cleartext", "the cipher none: SSH packets cross the link unencrypted"
    if low.startswith("arcfour"):
        return "weak", f"{name} is RC4, which RFC 8758 forbids"
    if "-cbc" in low or low in ("des", "3des"):
        return "weak", f"{name} is a CBC mode, open to plaintext recovery (CVE-2008-5161)"
    if low in SSH_STRONG:
        return "encrypted", None
    if low.startswith(("3des", "blowfish", "cast128", "idea", "des")):
        return "weak", f"{name} has a 64-bit block (Sweet32)"
    return "unverified", f"the cipher {name} is not one S.O.N.I.C. knows"


class _HelloReader:
    """The in-order first bytes of one TLS direction, read until its first handshake message."""

    __slots__ = ("buf", "pos", "hs")

    def __init__(self):
        self.buf = bytearray()
        self.pos = 0
        self.hs = bytearray()

    def parse(self):
        """None (more bytes needed), "stop" (no ServerHello here) or (parsed ServerHello, suite code)."""
        buf = self.buf
        while self.pos + 5 <= len(buf):
            ctype, length = buf[self.pos], int.from_bytes(buf[self.pos + 3:self.pos + 5], "big")
            if ctype not in (20, 22) or buf[self.pos + 1] != 3 or length > 18432:
                return "stop"  # application data or an alert before any ServerHello, or not TLS at all
            if self.pos + 5 + length > len(buf):
                return None
            body = bytes(buf[self.pos + 5:self.pos + 5 + length])
            self.pos += 5 + length
            if ctype == 20:
                continue  # TLS 1.3's middlebox-compatibility ChangeCipherSpec after a HelloRetryRequest
            self.hs += body
            while len(self.hs) >= 4:
                if self.hs[0] != 2:
                    return "stop"  # a ClientHello: the client's direction
                length = int.from_bytes(self.hs[1:4], "big")
                if len(self.hs) < 4 + length:
                    break
                message = bytes(self.hs[4:4 + length])
                del self.hs[:4 + length]
                parsed = parse_server_hello(message)
                if parsed is None:
                    return "stop"
                if parsed["hello_retry_request"]:
                    continue  # the real ServerHello follows the client's second ClientHello
                return parsed, server_hello_suite(message)
        return None


class _Direction:
    """One direction of a recognised TCP session: where its key exchange ends (SSH) or its records are (TLS)."""

    __slots__ = ("base", "buf", "lost", "kex_end", "next_record", "last_type", "encrypted_from", "kexinit",
                 "kexinit_frame", "hello", "server_hello", "hello_frame")

    def __init__(self, base: int, read_hello: bool = False):
        self.base = base
        self.buf = bytearray()
        self.lost = False
        self.kex_end: Optional[int] = None  # SSH: stream offset where NEWKEYS ends
        self.next_record = 0  # TLS: stream offset of the next record header
        self.last_type: Optional[int] = None
        self.encrypted_from: Optional[int] = None
        self.kexinit: Optional[Dict[str, List[str]]] = None  # SSH: this side's KEXINIT name-lists
        self.kexinit_frame: Optional[int] = None
        self.hello: Optional[_HelloReader] = _HelloReader() if read_hello else None  # TLS, until read
        self.server_hello: Optional[Dict[str, Any]] = None  # TLS: the ServerHello this side sent
        self.hello_frame: Optional[int] = None

    def read_hello(self, rel: int, payload: bytes, complete: bool, frame: int):
        """Feed one TLS segment to the ServerHello reader (in order only; a gap ends it)."""
        reader = self.hello
        if reader is None:
            return
        if rel > len(reader.buf):
            self.hello = None  # a segment before it was not captured
            return
        if rel + len(payload) > len(reader.buf):
            reader.buf += payload[len(reader.buf) - rel:]
        found = reader.parse()
        if isinstance(found, tuple):
            parsed, code = found
            version = "TLS1.3" if code in TLS13_SUITES else parsed["version"]
            self.server_hello = {"version": version, "cipher_suite": parsed["cipher_suite"], "code": code}
            self.hello_frame = frame
        if found is not None or not complete or len(reader.buf) >= MAX_HELLO_BYTES:
            self.hello = None

    def ssh_classify(self, rel: int, payload: bytes, frame: Optional[int] = None) -> str:
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
            if code == 20 and self.kexinit is None and pos + 4 + length <= len(self.buf):
                padding = self.buf[pos + 4]
                if padding < length:
                    self.kexinit = _parse_kexinit(bytes(self.buf[pos + 5:pos + 4 + length - padding]))
                    self.kexinit_frame = frame
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

    __slots__ = ("server", "client", "kind", "spoke", "dirs", "buckets", "svc", "midstream", "probe")

    def __init__(self, ssh_port: bool = False):
        self.server: Optional[Tuple[str, int]] = None
        self.client: Optional[Tuple[str, int]] = None
        self.kind: Optional[str] = None
        self.spoke: Set[Tuple[str, int]] = set()
        self.dirs: Dict[Tuple[str, int], _Direction] = {}
        self.buckets: Dict[Tuple[Tuple[str, int], str], Dict[str, Any]] = {}
        self.svc: Optional[int] = None
        self.midstream = False  # recognised without its handshake (the session began before the capture)
        # On tcp/22 and tcp/830: [payload bytes, printable bytes, byte values seen] while unrecognised.
        self.probe: Optional[List[int]] = [0, 0, 0] if ssh_port else None

    def sample(self, payload: bytes):
        """Count an unrecognised payload toward the ciphertext test (an SSH session already under way)."""
        probe = self.probe
        if probe is None or probe[0] >= MAX_PROBE_BYTES:
            return
        probe[0] += len(payload)
        probe[1] += len(payload) - len(payload.translate(None, PRINTABLE))
        for value in set(payload):
            probe[2] |= 1 << value

    def looks_like_ciphertext(self) -> bool:
        """Random-looking payload: few printable bytes and nearly as many byte values as random data has."""
        if self.probe is None or self.probe[0] < MIN_PROBE_BYTES:
            return False
        total, printable, values = self.probe
        expected = 256 * (1 - (255 / 256) ** total)
        return printable / total <= 0.6 and bin(values).count("1") >= 0.6 * expected

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


def _ssh_encryption(session: "_TcpSession", client, server) -> Dict[str, Any]:
    """The SSH session's cipher per direction, from both KEXINITs (RFC 4253 7.1)."""
    mine, theirs = session.dirs.get(client), session.dirs.get(server)
    ckex, skex = (mine.kexinit if mine else None), (theirs.kexinit if theirs else None)
    if not ckex or not skex:
        missing = " and ".join(side for side, kex in (("client's", ckex), ("server's", skex)) if not kex)
        return {"state": "unverified", "handshake_captured": False,
                "reason": f"the {missing} KEXINIT is not in the capture, so the cipher cannot be read"}
    out: Dict[str, Any] = {"state": "encrypted", "handshake_captured": True,
                           "kexinit_frames": {"client": mine.kexinit_frame, "server": theirs.kexinit_frame}}
    whys, readable = [], []
    for direction, sender in (("client_to_server", client), ("server_to_client", server)):
        cipher = _ssh_choose(ckex[f"cipher_{direction}"], skex[f"cipher_{direction}"])
        state, why = _ssh_cipher(cipher)
        aead = (cipher or "").lower() in SSH_AEAD
        mac = None if aead else _ssh_choose(ckex[f"mac_{direction}"], skex[f"mac_{direction}"])
        if state == "encrypted" and not aead and (mac or "").lower() == "none":
            state, why = "weak", f"{cipher} with the MAC none: encrypted, but not integrity-protected"
        out[f"cipher_{direction}"] = cipher
        out[f"mac_{direction}"] = "implicit (AEAD cipher)" if aead else mac
        if state == "cleartext":
            readable.append(sender)
        if why:
            whys.append((direction.replace("_", " "), why))
        if STATE_RANK[state] > STATE_RANK[out["state"]]:
            out["state"] = state
    if len({why for _d, why in whys}) == 1 and len(whys) == 2:
        out["reason"] = whys[0][1]  # the same in both directions
    else:
        out["reason"] = "; ".join(f"{direction}: {why}" for direction, why in whys) or None
    out["cleartext_from"] = readable
    return out


def _tls_encryption(session: "_TcpSession", client, server) -> Dict[str, Any]:
    """The TLS session's encryption from the suite and version its ServerHello chose."""
    hello_side = next((d for d in session.dirs.values() if d.server_hello), None)
    if session.midstream:
        return {"state": "unverified", "handshake_captured": False,
                "reason": "the session began before the capture: its records look encrypted, but without the "
                          "ServerHello a NULL cipher cannot be told from a real one"}
    if hello_side is None:
        return {"state": "unverified", "handshake_captured": False,
                "reason": "no ServerHello in the capture (or one S.O.N.I.C. could not read), so the cipher suite "
                          "is not known"}
    chosen = hello_side.server_hello
    code = chosen["code"]
    state, why = suite_encryption(code) if code is not None else ("unverified", "the ServerHello is truncated")
    version = chosen["version"]
    if version_is_weak(version) and state in ("encrypted", "weak"):
        why = "; ".join(w for w in (f"{version} is deprecated (RFC 8996)", why) if w)
        state = "weak"
    return {"state": state, "handshake_captured": True, "version": version,
            "cipher_suite": suite_name(code) if code is not None else None,
            "server_hello_frame": hello_side.hello_frame, "reason": why,
            "cleartext_from": [client, server] if state == "cleartext" else []}


def _encryption(kind: str, session: "_TcpSession", client, server, has_encrypted: bool) -> Dict[str, Any]:
    """
    One SSH or TLS session's encryption: state encrypted, weak, unverified, cleartext or not_started
    (no handshake to read and nothing past it), with the cipher and why.
    """
    if kind == "ssh" and session.midstream:
        out = {"state": "unverified", "handshake_captured": False,
               "reason": "no SSH banner or key exchange in the capture (the session began before it): recognised "
                         "by its port and by payload that looks like ciphertext, so the cipher cannot be read"}
    elif kind == "ssh":
        out = _ssh_encryption(session, client, server)
    else:
        out = _tls_encryption(session, client, server)
    if out["state"] == "unverified" and not has_encrypted:
        out["state"] = "not_started"
        out["reason"] = "nothing was sent past the handshake, so there is no encrypted traffic to judge"
    return out


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
            session = _TcpSession(ssh_port=bool({src[1], dst[1]} & SSH_PORTS))
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
                elif _tls_midstream(payload):
                    session.kind, session.midstream = "tls", True
                else:
                    session.sample(payload)
                    session.spoke.add(src)
                    if len(session.spoke) == 2:
                        session.kind = "other"
            elif session.kind == "other":
                session.sample(payload)
            direction = session.dirs.get(src)
            if direction is None and session.kind in ("ssh", "tls"):
                direction = _Direction(seq, read_hello=session.kind == "tls" and not session.midstream)
                session.dirs[src] = direction
            rel = seq_delta(seq, direction.base) if direction is not None else 0
            length = tcp.get("len", len(payload))
            if session.kind == "ssh":
                cls = direction.ssh_classify(rel, payload, rec["n"])
            elif session.kind == "tls":
                cls = direction.tls_classify(rel, payload, length)
                direction.read_hello(rel, payload, len(payload) >= length, rec["n"])
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

    def _violate(self, name, category, src, dst, bucket: Dict[str, Any], protection: str,
                 reason: Optional[str] = None):
        key = (name, src, dst)
        entry = self.violations.get(key)
        if entry is None:
            entry = {"protocol": name, "category": category, "src": src, "dst": dst, "packets": 0, "bytes": 0,
                     "first_frame": bucket["first_frame"], "first_t": bucket["first_t"],
                     "last_frame": bucket["last_frame"], "last_t": bucket["last_t"], "frames": [], "protection": {},
                     "reasons": []}
            self.violations[key] = entry
        if reason and category == "unencrypted_session" and reason not in entry["reasons"] and \
                len(entry["reasons"]) < 3:
            entry["reasons"].append(reason)
        entry["packets"] += bucket["packets"]
        entry["bytes"] += bucket["bytes"]
        if bucket["first_frame"] < entry["first_frame"]:
            entry["first_frame"], entry["first_t"] = bucket["first_frame"], bucket["first_t"]
        if bucket["last_frame"] >= entry["last_frame"]:
            entry["last_frame"], entry["last_t"] = bucket["last_frame"], bucket["last_t"]
        entry["frames"] = sorted(set(entry["frames"]) | set(bucket["frames"]))[:MAX_FRAMES]
        entry["protection"][protection] = entry["protection"].get(protection, 0) + bucket["packets"]

    def _settle_sessions(self) -> List[Dict[str, Any]]:
        """Judge every TCP session's frames now that each session's protocol and encryption are known."""
        summaries = []
        for (end_a, end_b), session in self.sessions.items():
            kind = session.kind or "other"
            if session.server is not None:
                svc = session.server[1]
            else:
                svc = service_port(end_a[1], end_b[1])
            server = session.server or (end_a if end_a[1] == svc else end_b)
            client = end_b if server == end_a else end_a
            if kind == "other" and svc in SSH_PORTS and session.looks_like_ciphertext():
                kind, session.midstream = "ssh", True  # an SSH session that began before the capture
            name, category, kind_tokens = _session_label(kind, svc)
            ports = {f"tcp:{end_a[1]}", f"tcp:{end_b[1]}", "proto:6"}
            ports |= {PORT_NAMES[p] for p in (end_a[1], end_b[1]) if p in PORT_NAMES}
            if kind == "other":
                routing = ports & GROUPS["routing"]
                if routing:
                    name, category = sorted(routing)[0], "routing"
            classes = []
            for (src, cls), bucket in sorted(session.buckets.items(), key=lambda kv: kv[1]["first_frame"]):
                if session.midstream and cls in ("pending", "cleartext"):
                    cls = "encrypted"  # recognised without its handshake: past the key exchange
                elif cls == "pending":
                    cls = "key_exchange" if kind in ("ssh", "tls") else "cleartext"
                if category == "routing":
                    cls = "cleartext"
                classes.append((src, cls, bucket))
            encryption = None
            if kind in ("ssh", "tls"):
                encryption = _encryption(kind, session, client, server,
                                         any(cls == "encrypted" for _s, cls, _b in classes))
                if encryption["state"] == "cleartext":
                    name, category, kind_tokens = f"{name} without encryption", "unencrypted_session", set()
            readable = encryption.pop("cleartext_from", ()) if encryption else ()
            tokens = ports | kind_tokens
            if kind == "ssh" and svc != 830:
                tokens.discard("netconf")
            totals: Dict[str, int] = {}
            packets = 0
            by_transport = False
            for src, cls, bucket in classes:
                if cls == "encrypted" and src in readable:
                    cls = "cleartext"  # the handshake chose no encryption for this direction
                dst = end_b if src == end_a else end_a
                self._protect(cls, bucket["packets"])
                totals[cls] = totals.get(cls, 0) + bucket["packets"]
                packets += bucket["packets"]
                for rule in self.rules:
                    if rule.matches(tokens, [src[0], dst[0]]):
                        self.allowed += bucket["packets"]
                        self.allowed_by[rule.text] = self.allowed_by.get(rule.text, 0) + bucket["packets"]
                        by_transport = by_transport or bool(rule.tokens & {"ssh", "tls", "netconf"})
                        break
                else:
                    self._violate(name, category, src[0], dst[0], bucket, cls,
                                  encryption.get("reason") if encryption else None)
            summary = {"protocol": name, "client": f"{client[0]}:{client[1]}",
                       "server": f"{server[0]}:{server[1]}", "service": f"tcp/{svc}",
                       "server_known_by": "syn" if session.server is not None else "port",
                       "category": category, "packets": packets, "protection": totals,
                       "first_frame": min(b["first_frame"] for b in session.buckets.values())}
            if encryption:
                summary["encryption"] = encryption
                summary["allowed_as_encrypted"] = by_transport
            summaries.append(summary)
        self.sessions = {}
        return sorted(summaries, key=lambda x: x["first_frame"])

    def present(self) -> bool:
        return self.frames > 0

    @staticmethod
    def _encryption_findings(sessions: List[Dict[str, Any]],
                             issues: List[Dict[str, Any]]) -> Tuple[Dict[str, int], int]:
        """
        Count the SSH and TLS sessions by encryption state, add one warning per protocol for weak and
        unverified ones and one info issue for those passed as encrypted outside IPsec; returns
        (the counts, how many passed as encrypted).
        """
        judged = [s for s in sessions if s.get("encryption")]
        counts = {"sessions": len(judged)}
        for state in ("encrypted", "weak", "unverified", "cleartext", "not_started"):
            counts[state] = sum(1 for s in judged if s["encryption"]["state"] == state)
        for state, code, what in (("weak", "WEAK_ENCRYPTION", "passed with weak encryption"),
                                  ("unverified", "ENCRYPTION_UNVERIFIED", "passed as encrypted, unverified")):
            groups: Dict[str, List[Dict[str, Any]]] = {}
            for s in judged:
                if s["encryption"]["state"] == state:
                    groups.setdefault(s["protocol"], []).append(s)
            for protocol, members in groups.items():
                reasons = []
                for s in members:
                    if s["encryption"].get("reason") and s["encryption"]["reason"] not in reasons:
                        reasons.append(s["encryption"]["reason"])
                first = members[0]
                text = (f"{len(members)} {protocol} session(s) {what}: {'; '.join(reasons[:3])} (first "
                        f"{first['client']} -> {first['server']})")
                issues.append(make_issue("warning", code, text, sorted(s["first_frame"] for s in members)[:MAX_FRAMES],
                                         protocol=protocol))
        outside = [s for s in judged if s.get("allowed_as_encrypted")]
        if outside:
            names: Dict[str, int] = {}
            for s in outside:
                names[s["protocol"]] = names.get(s["protocol"], 0) + 1
            listed = ", ".join(f"{n} {name}" for name, n in names.items())
            text = (f"{len(outside)} SSH or TLS session(s) passed as encrypted by their own transport, not inside "
                    f"IPsec ({listed}); allow crypto alone to require the tunnel")
            issues.append(make_issue("info", "ENCRYPTED_OUTSIDE_TUNNEL", text,
                                     sorted(s["first_frame"] for s in outside)[:MAX_FRAMES]))
        return counts, len(outside)

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
            if v["reasons"]:
                violations_out[-1]["reasons"] = v["reasons"]
            text = (f"{v['packets']} {v['protocol']} frame(s) {pair} outside the allowlist "
                    f"({HINTS.get(v['category'], HINTS['cleartext'])})")
            if v["reasons"]:
                text += f": {'; '.join(v['reasons'])}"
            if v["category"] == "encrypted":
                issues.append(make_issue("warning", "ENCRYPTED_OUTSIDE_ALLOWLIST", text, v["frames"],
                                         protocol=v["protocol"], category=v["category"]))
            else:
                severity = "warning" if v["category"] == "layer2" else "error"
                issues.append(make_issue(severity, "CLEARTEXT_OUTSIDE_ALLOWLIST", text, v["frames"],
                                         protocol=v["protocol"], category=v["category"]))
            events.append(make_event(ctx, v["first_t"], "audit", "first_leak",
                                     f"first {v['protocol']} frame outside the allowlist {pair}", v["first_frame"]))
        encryption, outside_tunnel = self._encryption_findings(sessions, issues)
        violating = sum(v["packets"] for v in rows)
        passed = violating == 0 and self.frames > 0
        clean = passed and not encryption["weak"] and not encryption["unverified"]
        cleartext = self.protection.get("cleartext", 0)
        protected = ", ".join(f"{self.protection[k]} {k.replace('_', ' ')}" for k in
                              ("encrypted", "key_exchange", "authenticated_only", "layer2", "cleartext")
                              if self.protection.get(k))
        if not self.frames:
            verdict = "FAIL: the capture is empty, so nothing proves the link carried only allowed traffic"
            issues.append(make_issue("error", "AUDIT_EMPTY_CAPTURE", verdict))
        elif passed:
            verdict = (f"{'PASS' if clean else 'PASS with warnings'}: all {self.frames} frames match the allowlist "
                       f"({', '.join(self.allow_text)}); no cleartext outside it ({protected})")
            doubts = [f"{encryption[k]} {label}" for k, label in
                      (("unverified", "encrypted, unverified (see ENCRYPTION_UNVERIFIED)"),
                       ("weak", "weakly encrypted (see WEAK_ENCRYPTION)")) if encryption[k]]
            if doubts:
                verdict += f"; but of the SSH and TLS sessions {' and '.join(doubts)}"
            if outside_tunnel:
                verdict += (f"; {outside_tunnel} SSH or TLS session(s) protected by their own encryption, not by "
                            "IPsec (allow crypto alone to require the tunnel)")
        else:
            parts = [f"{agg['packets']} {name}" for name, agg in
                     sorted(by_protocol.items(), key=lambda kv: kv[1]["first_frame"])]
            first = rows[0]
            verdict = (f"FAIL: {violating} of {self.frames} frames outside the allowlist ({', '.join(parts)}); "
                       f"first at frame {first['first_frame']}")
            outside_clear = sum(v["protection"].get("cleartext", 0) for v in rows)
            if not outside_clear:
                verdict += (f"; none of them is cleartext ({protected}): allow ssh, tls, netconf or encrypted (the "
                            "default) to accept transport encryption")
            else:
                verdict += f"; {outside_clear} of them cleartext"
                if protected != f"{cleartext} cleartext":
                    verdict += f" (all frames: {protected})"
            unencrypted = [v for v in rows if v["category"] == "unencrypted_session"]
            if unencrypted:
                verdict += (f"; {encryption['cleartext']} SSH or TLS session(s) negotiated no encryption "
                            f"({unencrypted[0]['reasons'][0] if unencrypted[0]['reasons'] else 'see violations'})")
        listed, omitted = cap(violations_out, ctx.max_items)
        return {
            "detector": self.name,
            "status": "ok" if clean else ("warning" if passed else "problem"),
            "verdict": verdict,
            "passed": passed,
            "clean": clean,
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
            "encryption": encryption,
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
