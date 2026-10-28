#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Data Plane Test Fixtures (synthetic)

Generates the small, deterministic pcaps the data plane detector and
multi-capture tests read. Every file is synthetic: built with scapy and struct,
fixed addresses (RFC 5737 documentation ranges and 10.0.0.0/8), fixed
timestamps, fixed MAC addresses and no randomness, so two runs produce identical
files. Names start with dp_.

Usage:
    python3 tests/fixtures/generate_dataplane_fixtures.py            # writes next to this script
    python3 tests/fixtures/generate_dataplane_fixtures.py OUT_DIR    # writes into OUT_DIR

Fixtures:
    dp_pmtu_frag_needed.pcap   DF pings: 1500 bytes answered by ICMP 3/4 MTU 1400, then 1400 bytes answered
    dp_pmtu_black_hole.pcap    DF pings up to 1400 answered, 1500 vanish with no ICMP; random loss on another
                               pair (not a black hole); a TCP connection whose large DF segments are never acked
    dp_fragments.pcap          one complete fragmented UDP datagram, one missing its middle fragment,
                               an overlapping pair, an ICMP reassembly-time-exceeded
    dp_esp_sizes.pcap          ESP SAs with AES-GCM sizes (DSCP mixed), AES-CBC/SHA1 sizes, NAT-T GCM sizes,
                               and an ESP packet fragmented after encryption
    dp_tcp_health.pcap         healthy, no answer (+ICMP admin prohibited), refused, zero window, loss with
                               timeout and fast retransmits, window full, MSS 1360, reset mid-connection
    dp_tls.pcap                TLS 1.3 (GREASE, ALPN h2), TLS 1.2 ClientHello split in two segments with an expired
                               certificate, TLS 1.0 with RC4 chosen, ClientHello answered by a fatal alert
    dp_qos_rtp.pcap            RTP PCMU marked EF with 2 losses, RTP PCMU unmarked with jitter, Opus PT 111,
                               GRE copying DSCP and GRE losing it, ECN CE marks
    dp_corr_inside.pcap        inside of a NAT router (pair with dp_corr_outside.pcap)
    dp_corr_outside.pcap       outside: source NAT 10.0.0.x -> 203.0.113.5, a SYN-ACK that never reaches the
                               inside, a UDP probe the router drops, ICMP echo with PAT, DSCP EF rewritten to 0
    dp_corr_lan.pcap           a LAN capture (with dp_corr_wan1/wan2): requests leave on WAN1, replies return on WAN2
    dp_corr_wan1.pcap
    dp_corr_wan2.pcap
"""

import os
import struct
import sys

from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

BASE_TIME = 1767225600.0  # 2026-01-01T00:00:00Z
MAC_A = "02:00:00:00:01:0a"
MAC_B = "02:00:00:00:01:0b"


class Capture:
    def __init__(self):
        self.packets = []

    def add(self, offset, pkt):
        pkt.time = BASE_TIME + offset
        self.packets.append(pkt)

    def write(self, path):
        wrpcap(path, self.packets)


def eth(ip_layer, mac_src=MAC_A, mac_dst=MAC_B):
    return Ether(src=mac_src, dst=mac_dst) / ip_layer


def pad(label: str, length: int) -> bytes:
    seed = label.encode() or b"x"
    return (seed * (length // len(seed) + 1))[:length]


def ping(cap, t, src, dst, ident, seq, size, df=True, reply_after=None, tos=0, ttl=64):
    """An echo request of `size` bytes total IP length; an echo reply after `reply_after` seconds."""
    data = pad(f"p{seq}", size - 28)
    flags = "DF" if df else 0
    cap.add(t, eth(IP(src=src, dst=dst, id=(ident * 7 + seq) & 0xFFFF, flags=flags, tos=tos, ttl=ttl)
                   / ICMP(type=8, id=ident, seq=seq) / Raw(data)))
    if reply_after is not None:
        cap.add(t + reply_after, eth(IP(src=dst, dst=src, id=(ident * 11 + seq) & 0xFFFF, flags=flags, ttl=ttl)
                                     / ICMP(type=0, id=ident, seq=seq) / Raw(data), MAC_B, MAC_A))


# ---------------------------------------------------------------------------
# Path MTU
# ---------------------------------------------------------------------------

def build_pmtu_frag_needed():
    cap = Capture()
    host, far, router = "10.1.1.10", "10.2.2.20", "10.1.1.1"
    ping(cap, 0.0, host, far, 1, 1, 100, reply_after=0.01)
    ping(cap, 1.0, host, far, 1, 2, 1500)
    probe = IP(src=host, dst=far, id=(7 + 2) & 0xFFFF, flags="DF", ttl=63, len=1500) / ICMP(type=8, id=1, seq=2)
    cap.add(1.001, eth(IP(src=router, dst=host, id=500) / ICMP(type=3, code=4, nexthopmtu=1400)
                       / Raw(bytes(probe)[:28]), MAC_B, MAC_A))
    ping(cap, 2.0, host, far, 1, 3, 1400, reply_after=0.012)
    ping(cap, 3.0, host, far, 1, 4, 1400, reply_after=0.011)
    return cap


class Tcp:
    """One TCP connection; the caller controls sequence numbers for retransmissions."""

    def __init__(self, cap, a, ap, b, bp, isn_a, isn_b, tos=0, ttl=64, df=True):
        self.cap, self.ends = cap, {True: (a, ap), False: (b, bp)}
        self.seq = {True: isn_a, False: isn_b}
        self.tos, self.ttl, self.df = tos, ttl, df
        self.ipid = {True: 100, False: 200}

    def send(self, from_a, t, flags, payload=b"", seq=None, ack=None, window=65535, options=None, advance=True):
        (src, sport), (dst, dport) = self.ends[from_a], self.ends[not from_a]
        use_seq = self.seq[from_a] if seq is None else seq
        use_ack = (self.seq[not from_a] if ack is None else ack) if "A" in flags else 0
        self.ipid[from_a] += 1
        segment = (IP(src=src, dst=dst, id=self.ipid[from_a], flags="DF" if self.df else 0, tos=self.tos, ttl=self.ttl)
                   / TCP(sport=sport, dport=dport, flags=flags, seq=use_seq, ack=use_ack, window=window,
                         options=options or []))
        if payload:
            segment = segment / Raw(payload)
        self.cap.add(t, eth(segment, *((MAC_A, MAC_B) if from_a else (MAC_B, MAC_A))))
        if advance and seq is None:
            self.seq[from_a] = use_seq + len(payload) + (1 if "S" in flags else 0) + (1 if "F" in flags else 0)
        return use_seq

    def handshake(self, t, mss_a=1460, mss_b=1460, ws_a=7, ws_b=7, rtt=0.02):
        opts = lambda mss, ws: [("MSS", mss), ("NOP", None), ("WScale", ws), ("SAckOK", b"")]
        self.send(True, t, "S", options=opts(mss_a, ws_a), window=64240)
        self.send(False, t + rtt / 2, "SA", options=opts(mss_b, ws_b), window=65160)
        self.send(True, t + rtt, "A", window=502)


def build_pmtu_black_hole():
    cap = Capture()
    host, far = "10.1.1.10", "10.3.3.30"
    ping(cap, 0.0, host, far, 2, 1, 1000, reply_after=0.02)
    ping(cap, 1.0, host, far, 2, 2, 1400, reply_after=0.02)
    for i in range(3):
        ping(cap, 2.0 + i, host, far, 2, 3 + i, 1500)
    ping(cap, 5.0, host, far, 2, 6, 1400, reply_after=0.02)
    # random loss, same size answered and lost: not a black hole
    other = "10.1.1.11"
    for i in range(6):
        ping(cap, 6.0 + i * 0.5, other, far, 3, i + 1, 1400, reply_after=0.02 if i % 2 == 0 else None)
    # TCP: small request acked, large DF segments retransmitted and never acked
    conn = Tcp(cap, host, 40100, far, 80, 1000, 5000)
    conn.handshake(10.0)
    conn.send(True, 10.05, "PA", pad("GET", 100))
    conn.send(False, 10.07, "PA", pad("hdr", 200), window=502)
    conn.send(True, 10.08, "A", window=502)
    start = conn.seq[False]
    for t in (10.1, 10.4, 11.0, 12.2):
        conn.send(False, t, "A", pad("big", 1448), seq=start, window=502)
    return cap


def build_fragments():
    cap = Capture()
    a, b = "10.4.4.40", "10.5.5.50"
    from scapy.all import fragment
    whole = IP(src=a, dst=b, id=4242) / UDP(sport=5001, dport=5002) / Raw(pad("frag", 3000))
    for i, frag in enumerate(fragment(whole, fragsize=1480)):
        cap.add(0.1 + i * 0.001, eth(frag))
    broken = IP(src=a, dst=b, id=4343) / UDP(sport=5001, dport=5002) / Raw(pad("lost", 3000))
    pieces = fragment(broken, fragsize=1480)
    for i, frag in enumerate(pieces):
        if i != 1:
            cap.add(1.0 + i * 0.001, eth(frag))
    raw = pad("ovl", 64)
    cap.add(2.0, eth(IP(src=a, dst=b, id=4444, flags="MF", frag=0, proto=17) / Raw(raw[:48])))
    cap.add(2.001, eth(IP(src=a, dst=b, id=4444, flags=0, frag=4, proto=17) / Raw(raw[32:])))
    orig = IP(src=a, dst=b, id=4343, proto=17, flags="MF", len=1500)
    cap.add(32.0, eth(IP(src=b, dst=a, id=900) / ICMP(type=11, code=1) / Raw(bytes(orig)[:20] + pad("u", 8)),
                      MAC_B, MAC_A))
    return cap


# ---------------------------------------------------------------------------
# ESP sizes
# ---------------------------------------------------------------------------

def esp_size(inner, iv, icv, align, extra=8):
    body = inner + extra + 2
    body += (-body) % align
    return 8 + iv + body + icv


def esp(cap, t, src, dst, spi, seq, payload_len, tos=0, udp=False, df=False):
    data = struct.pack("!II", spi, seq) + pad(f"e{spi}{seq}", payload_len)
    layer = IP(src=src, dst=dst, id=(seq * 3) & 0xFFFF, tos=tos, flags="DF" if df else 0,
               proto=17 if udp else 50)
    if udp:
        pkt = layer / UDP(sport=4500, dport=4500) / Raw(data)
    else:
        pkt = layer / Raw(data)
    cap.add(t, eth(pkt))
    return pkt


def build_esp_sizes():
    cap = Capture()
    hub, spoke, spoke2, natted = "192.0.2.1", "198.51.100.2", "198.51.100.3", "203.0.113.9"
    inner_sizes = [60, 100, 128, 576, 1000, 1400]
    tos_cycle = [0, 0xB8, 0xC0]  # 0, EF, CS6
    for i, size in enumerate(inner_sizes * 2):
        esp(cap, 0.1 * i, spoke, hub, 0xC0000001, i + 1, esp_size(size, 8, 16, 4) - 8,
            tos=tos_cycle[i % 3])
    for i, size in enumerate(inner_sizes):
        esp(cap, 2 + 0.1 * i, spoke2, hub, 0xCB000001, i + 1, esp_size(size, 16, 12, 16) - 8)
    for i, size in enumerate(inner_sizes[:4]):
        esp(cap, 3 + 0.1 * i, natted, hub, 0xAB000001, i + 1, esp_size(size, 8, 16, 4) - 8, udp=True)
    from scapy.all import fragment
    big = IP(src=spoke2, dst=hub, id=777, proto=50) / Raw(struct.pack("!II", 0xCB000001, 99)
                                                          + pad("big", esp_size(1476, 16, 12, 16) - 8))
    for i, frag in enumerate(fragment(big, fragsize=1480)):
        cap.add(4 + i * 0.001, eth(frag))
    return cap


# ---------------------------------------------------------------------------
# TCP health
# ---------------------------------------------------------------------------

def build_tcp_health():
    cap = Capture()
    client, server = "10.6.6.60", "203.0.113.70"
    # healthy
    c = Tcp(cap, client, 41000, server, 443, 10000, 90000)
    c.handshake(0.0)
    c.send(True, 0.05, "PA", pad("req", 200))
    c.send(False, 0.07, "PA", pad("resp", 1000), window=502)
    c.send(True, 0.09, "A", window=502)
    c.send(True, 0.10, "FA", window=502)
    c.send(False, 0.11, "FA", window=502)
    c.send(True, 0.12, "A", window=502)
    # no answer, with an ICMP administratively prohibited from a router
    n = Tcp(cap, client, 41001, server, 8080, 20000, 0)
    for t in (1.0, 2.0, 4.0):
        n.send(True, t, "S", options=[("MSS", 1460)], seq=20000)
    orig = IP(src=client, dst=server, id=9, proto=6) / TCP(sport=41001, dport=8080, flags="S", seq=20000)
    cap.add(4.001, eth(IP(src="10.6.6.1", dst=client, id=901) / ICMP(type=3, code=13) / Raw(bytes(orig)[:28]),
                       MAC_B, MAC_A))
    # refused
    r = Tcp(cap, client, 41002, server, 25, 30000, 0)
    r.send(True, 5.0, "S", options=[("MSS", 1460)])
    r.send(False, 5.01, "RA", ack=30001, window=0)
    # zero window: the client stops reading
    z = Tcp(cap, client, 41003, server, 443, 40000, 140000)
    z.handshake(6.0, ws_a=0, ws_b=0)
    z.send(True, 6.03, "PA", pad("get", 100), window=8192)
    for i in range(4):
        z.send(False, 6.05 + i * 0.001, "A", pad("bulk", 1000), window=8192)
    z.send(True, 6.1, "A", window=0)
    z.send(False, 6.6, "A", pad("probe", 1), window=8192, advance=False)
    z.send(True, 6.61, "A", window=0)
    z.send(False, 7.6, "A", pad("probe", 1), window=8192, advance=False)
    z.send(True, 8.1, "A", window=8192)
    # loss: one timeout retransmission, one gap then fast retransmit after three duplicate ACKs
    lo = Tcp(cap, client, 41004, server, 443, 50000, 150000)
    lo.handshake(10.0)
    lo.send(True, 10.03, "PA", pad("get", 100))
    first = lo.send(False, 10.05, "A", pad("d1", 1000), window=502)
    lo.send(False, 11.05, "A", pad("d1", 1000), seq=first, window=502)   # RTO retransmission
    lo.send(True, 11.07, "A", window=502)
    lost = lo.seq[False]
    lo.seq[False] = lost + 1000                                          # segment lost before the capture point
    lo.send(False, 11.10, "A", pad("d3", 1000), window=502)
    lo.send(True, 11.11, "A", ack=lost, window=502)
    lo.send(False, 11.12, "A", pad("d4", 1000), window=502)
    lo.send(True, 11.13, "A", ack=lost, window=502)
    lo.send(False, 11.14, "A", pad("d5", 1000), window=502)
    lo.send(True, 11.15, "A", ack=lost, window=502)
    lo.send(True, 11.16, "A", ack=lost, window=502)
    lo.send(False, 11.17, "A", pad("d2", 1000), seq=lost, window=502)    # the missing segment fills the gap
    lo.send(True, 11.19, "A", window=502)
    seen = lo.send(False, 11.20, "A", pad("d6", 1000), window=502)       # lost after the capture point
    lo.send(False, 11.21, "A", pad("d7", 1000), window=502)
    for i in range(3):
        lo.send(True, 11.22 + i * 0.001, "A", ack=seen, window=502)
    lo.send(False, 11.23, "A", pad("d6", 1000), seq=seen, window=502)    # fast retransmit after 3 duplicate ACKs
    lo.send(True, 11.25, "A", window=502)
    # window full: the client's 4000-byte window fills
    w = Tcp(cap, client, 41005, server, 443, 60000, 160000)
    w.handshake(13.0, ws_a=0, ws_b=0, mss_a=1360)
    w.send(True, 13.03, "PA", pad("get", 100), window=4000)
    for i in range(4):
        w.send(False, 13.05 + i * 0.001, "A", pad("fill", 1000), window=8192)
    w.send(True, 13.2, "A", window=4000)
    # reset mid-connection
    x = Tcp(cap, client, 41006, server, 443, 70000, 170000)
    x.handshake(15.0)
    x.send(True, 15.03, "PA", pad("get", 100))
    x.send(False, 15.05, "PA", pad("part", 500), window=502)
    x.send(False, 15.06, "RA", window=0)
    return cap


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def ext(etype, body):
    return struct.pack("!HH", etype, len(body)) + body


def client_hello(sni, suites, versions=None, alpn=None, groups=None, legacy=0x0303, padding=0):
    body = struct.pack("!H", legacy) + pad("random-" + sni, 32) + b"\x20" + pad("sid", 32)
    body += struct.pack("!H", len(suites) * 2) + b"".join(struct.pack("!H", s) for s in suites) + b"\x01\x00"
    exts = b""
    name = sni.encode()
    exts += ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    if groups:
        g = b"".join(struct.pack("!H", x) for x in groups)
        exts += ext(10, struct.pack("!H", len(g)) + g)
        share = struct.pack("!HH", groups[-1], 32) + pad("key", 32)
        exts += ext(51, struct.pack("!H", len(share)) + share)
    if alpn:
        a = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        exts += ext(16, struct.pack("!H", len(a)) + a)
    if versions:
        v = b"".join(struct.pack("!H", x) for x in versions)
        exts += ext(43, bytes([len(v)]) + v)
    if padding:
        exts += ext(21, b"\x00" * padding)
    body += struct.pack("!H", len(exts)) + exts
    return handshake_record(1, body, record_version=0x0301)


def server_hello(suite, version=0x0303, supported=None, alpn=None, group=None):
    body = struct.pack("!H", version) + pad("server-random", 32) + b"\x20" + pad("sid", 32)
    body += struct.pack("!HB", suite, 0)
    exts = b""
    if supported:
        exts += ext(43, struct.pack("!H", supported))
    if group:
        exts += ext(51, struct.pack("!HH", group, 32) + pad("skey", 32))
    if alpn:
        exts += ext(16, struct.pack("!H", len(alpn) + 1) + bytes([len(alpn)]) + alpn.encode())
    body += struct.pack("!H", len(exts)) + exts
    return body


def handshake_record(htype, body, record_version=0x0303):
    message = bytes([htype]) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 22, record_version, len(message)) + message


def expired_certificate() -> bytes:
    """A deterministic Ed25519 self-signed certificate that expired before the capture."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.net")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(4242).not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2025, 6, 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("legacy.example.net")]), critical=False)
            .sign(key, None))
    return cert.public_bytes(serialization.Encoding.DER)


def build_tls():
    cap = Capture()
    client, server = "10.7.7.70", "198.51.100.90"
    # TLS 1.3 with GREASE values, ALPN h2
    a = Tcp(cap, client, 42000, server, 443, 1000, 2000)
    a.handshake(0.0)
    a.send(True, 0.03, "PA", client_hello("app.example.com", [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02F],
                                          versions=[0x1A1A, 0x0304, 0x0303], alpn=["h2", "http/1.1"],
                                          groups=[0x2A2A, 0x001D]))
    sh = handshake_record(2, server_hello(0x1301, supported=0x0304, group=0x001D))
    a.send(False, 0.05, "PA", sh + bytes([20, 3, 3, 0, 1, 1]) + struct.pack("!BHH", 23, 0x0303, 40) + pad("enc", 40),
           window=502)
    # TLS 1.2, ClientHello split across two segments, expired certificate
    b = Tcp(cap, client, 42001, server, 443, 3000, 4000)
    b.handshake(1.0)
    hello = client_hello("legacy.example.net", [0xC02F, 0xC013, 0x009C], alpn=["http/1.1"], groups=[0x0017],
                         padding=1600)
    b.send(True, 1.03, "A", hello[:1400])
    b.send(True, 1.031, "PA", hello[1400:])
    cert = expired_certificate()
    cert_msg = (len(cert) + 3).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert
    flight = handshake_record(2, server_hello(0xC013)) + handshake_record(11, cert_msg) + handshake_record(14, b"")
    b.send(False, 1.05, "PA", flight, window=502)
    # TLS 1.0 client offering RC4 and 3DES, server picks RC4
    c = Tcp(cap, client, 42002, server, 443, 5000, 6000)
    c.handshake(2.0)
    c.send(True, 2.03, "PA", client_hello("old.example.org", [0x0005, 0x000A, 0x002F], legacy=0x0301))
    c.send(False, 2.05, "PA", handshake_record(2, server_hello(0x0005, version=0x0301), record_version=0x0301),
           window=502)
    # ClientHello on a non-standard port answered by a fatal handshake_failure alert
    d = Tcp(cap, client, 42003, server, 9443, 7000, 8000)
    d.handshake(3.0)
    d.send(True, 3.03, "PA", client_hello("strict.example.com", [0xC013], groups=[0x0017]))
    d.send(False, 3.05, "PA", struct.pack("!BHHBB", 21, 0x0303, 2, 2, 40), window=502)
    return cap


# ---------------------------------------------------------------------------
# QoS and RTP
# ---------------------------------------------------------------------------

def rtp(cap, t, src, dst, sport, dport, seq, ts, ssrc, pt=0, tos=0, size=160):
    header = struct.pack("!BBHII", 0x80, pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
    cap.add(t, eth(IP(src=src, dst=dst, id=seq & 0xFFFF, tos=tos) / UDP(sport=sport, dport=dport)
                   / Raw(header + pad("v", size))))


def gre_wrap(inner):
    return struct.pack("!HHI", 0x2000, 0x0800, 100) + bytes(inner)


def build_qos_rtp():
    cap = Capture()
    phone, pbx = "10.8.8.80", "10.9.9.90"
    for i in range(100):
        if i in (40, 41):
            continue
        rtp(cap, i * 0.02 + 0.0005 * (i % 3), phone, pbx, 16384, 20000, 1000 + i, 160 * i, 0x11111111, tos=0xB8)
    for i in range(100):
        jitter = 0.015 if i % 2 else 0.0
        rtp(cap, 0.01 + i * 0.02 + jitter, pbx, phone, 20000, 16384, 5000 + i, 160 * i, 0x22222222, tos=0)
    for i in range(50):
        rtp(cap, 0.005 + i * 0.02, phone, pbx, 16386, 20002, 7000 + i, 960 * i, 0x33333333, pt=111, tos=0xB8, size=80)
    hub, spoke = "192.0.2.1", "198.51.100.2"
    for i in range(5):
        inner = IP(src="10.10.1.1", dst="10.20.1.1", tos=0xB8, id=300 + i) / UDP(sport=30000, dport=30002) / Raw(pad("g", 60))
        cap.add(3.0 + i * 0.01, eth(IP(src=spoke, dst=hub, proto=47, tos=0, id=600 + i) / Raw(gre_wrap(inner))))
        inner = IP(src="10.10.1.2", dst="10.20.1.2", tos=0x88, id=400 + i) / UDP(sport=30004, dport=30006) / Raw(pad("h", 60))
        cap.add(3.05 + i * 0.01, eth(IP(src=hub, dst=spoke, proto=47, tos=0x88, id=700 + i) / Raw(gre_wrap(inner))))
    for i in range(3):
        cap.add(4.0 + i * 0.01, eth(IP(src="10.8.8.81", dst="10.9.9.91", tos=0x03, id=800 + i)
                                    / UDP(sport=40000, dport=40002) / Raw(pad("ce", 100))))
    return cap


# ---------------------------------------------------------------------------
# Multi-capture: NAT router (inside / outside) and asymmetric WANs
# ---------------------------------------------------------------------------

def build_corr_nat():
    inside, outside = Capture(), Capture()
    nat_ip, web, other = "203.0.113.5", "198.51.100.80", "198.51.100.81"

    def both(t, inner_pkt, outer_pkt, delay=0.0005, seen_inside=True, seen_outside=True):
        if seen_inside:
            inside.add(t, eth(inner_pkt))
        if seen_outside:
            outside.add(t + delay, eth(outer_pkt))

    def tcp_pair(src_in, sport_in, src_out, sport_out, dst, dport, flags, seq, ack, ipid, outbound, payload=b"",
                 seen_inside=True, seen_outside=True, tos_in=0, tos_out=0):
        if outbound:
            a = IP(src=src_in, dst=dst, id=ipid, ttl=64, tos=tos_in) / TCP(sport=sport_in, dport=dport, flags=flags, seq=seq, ack=ack, window=64240)
            b = IP(src=src_out, dst=dst, id=ipid, ttl=63, tos=tos_out) / TCP(sport=sport_out, dport=dport, flags=flags, seq=seq, ack=ack, window=64240)
            if payload:
                a, b = a / Raw(payload), b / Raw(payload)
            both(seq_time[0], a, b, seen_inside=seen_inside, seen_outside=seen_outside)
        else:
            b = IP(src=dst, dst=src_out, id=ipid, ttl=60, tos=tos_out) / TCP(sport=dport, dport=sport_out, flags=flags, seq=seq, ack=ack, window=65160)
            a = IP(src=dst, dst=src_in, id=ipid, ttl=59, tos=tos_in) / TCP(sport=dport, dport=sport_in, flags=flags, seq=seq, ack=ack, window=65160)
            if payload:
                a, b = a / Raw(payload), b / Raw(payload)
            if seen_outside:
                outside.add(seq_time[0], eth(b, MAC_B, MAC_A))
            if seen_inside:
                inside.add(seq_time[0] + 0.0005, eth(a, MAC_B, MAC_A))

    seq_time = [0.0]

    def at(t):
        seq_time[0] = t

    # flow 1: a full exchange through source NAT 10.0.0.10:40000 -> 203.0.113.5:61000
    at(0.0); tcp_pair("10.0.0.10", 40000, nat_ip, 61000, web, 443, "S", 1000, 0, 11, True)
    at(0.02); tcp_pair("10.0.0.10", 40000, nat_ip, 61000, web, 443, "SA", 9000, 1001, 21, False)
    at(0.03); tcp_pair("10.0.0.10", 40000, nat_ip, 61000, web, 443, "A", 1001, 9001, 12, True)
    at(0.04); tcp_pair("10.0.0.10", 40000, nat_ip, 61000, web, 443, "PA", 1001, 9001, 13, True, pad("hello", 300),
                       tos_in=0xB8, tos_out=0)
    at(0.06); tcp_pair("10.0.0.10", 40000, nat_ip, 61000, web, 443, "PA", 9001, 1301, 22, False, pad("world", 500))
    # flow 2: SYN crosses, the SYN-ACK is seen outside but never reaches the inside
    for i, t in enumerate((1.0, 2.0, 4.0)):
        at(t); tcp_pair("10.0.0.11", 40001, nat_ip, 61001, other, 443, "S", 2000, 0, 31 + i, True)
        at(t + 0.02); tcp_pair("10.0.0.11", 40001, nat_ip, 61001, other, 443, "SA", 7000, 2001, 41 + i, False,
                               seen_inside=False)
    # flow 3: ICMP from 10.0.0.12 is permitted, its UDP probes are dropped by the router (an ACL)
    req_in = IP(src="10.0.0.12", dst="198.51.100.82", id=50, ttl=64) / ICMP(type=8, id=0x0101, seq=1) / Raw(pad("ok", 56))
    req_out = IP(src=nat_ip, dst="198.51.100.82", id=50, ttl=63) / ICMP(type=8, id=0x8002, seq=1) / Raw(pad("ok", 56))
    both(4.5, req_in, req_out)
    for i in range(3):
        inside.add(5.0 + i, eth(IP(src="10.0.0.12", dst="198.51.100.82", id=51 + i, ttl=64)
                                / UDP(sport=33434 + i, dport=33434 + i) / Raw(pad("probe", 32))))
    # flow 4: ICMP echo through PAT (identifier rewritten), reply returns
    for i in range(3):
        t = 8.0 + i
        req_in = IP(src="10.0.0.13", dst=web, id=61 + i, ttl=64) / ICMP(type=8, id=0x1234, seq=i + 1) / Raw(pad("ping", 56))
        req_out = IP(src=nat_ip, dst=web, id=61 + i, ttl=63) / ICMP(type=8, id=0x8001, seq=i + 1) / Raw(pad("ping", 56))
        both(t, req_in, req_out)
        rep_out = IP(src=web, dst=nat_ip, id=71 + i, ttl=60) / ICMP(type=0, id=0x8001, seq=i + 1) / Raw(pad("ping", 56))
        rep_in = IP(src=web, dst="10.0.0.13", id=71 + i, ttl=59) / ICMP(type=0, id=0x1234, seq=i + 1) / Raw(pad("ping", 56))
        outside.add(t + 0.02, eth(rep_out, MAC_B, MAC_A))
        inside.add(t + 0.0205, eth(rep_in, MAC_B, MAC_A))
    return inside, outside


def build_corr_asymmetric():
    lan, wan1, wan2 = Capture(), Capture(), Capture()
    host, server = "10.0.0.20", "192.0.2.50"
    seqs = {"c": 100, "s": 900}
    for i in range(4):
        t = i * 0.5
        payload = pad(f"req{i}", 100)
        out = IP(src=host, dst=server, id=500 + i, ttl=64) / TCP(sport=50000, dport=22, flags="PA", seq=seqs["c"], ack=seqs["s"]) / Raw(payload)
        lan.add(t, eth(out))
        out.ttl = 63
        wan1.add(t + 0.001, eth(out))
        seqs["c"] += 100
        back = IP(src=server, dst=host, id=600 + i, ttl=58) / TCP(sport=22, dport=50000, flags="PA", seq=seqs["s"], ack=seqs["c"]) / Raw(pad(f"rep{i}", 200))
        wan2.add(t + 0.03, eth(back, MAC_B, MAC_A))
        back.ttl = 57
        lan.add(t + 0.031, eth(back, MAC_B, MAC_A))
        seqs["s"] += 200
    return lan, wan1, wan2


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out_dir, exist_ok=True)
    single = {
        "dp_pmtu_frag_needed.pcap": build_pmtu_frag_needed,
        "dp_pmtu_black_hole.pcap": build_pmtu_black_hole,
        "dp_fragments.pcap": build_fragments,
        "dp_esp_sizes.pcap": build_esp_sizes,
        "dp_tcp_health.pcap": build_tcp_health,
        "dp_tls.pcap": build_tls,
        "dp_qos_rtp.pcap": build_qos_rtp,
    }
    outputs = {name: builder() for name, builder in single.items()}
    outputs["dp_corr_inside.pcap"], outputs["dp_corr_outside.pcap"] = build_corr_nat()
    outputs["dp_corr_lan.pcap"], outputs["dp_corr_wan1.pcap"], outputs["dp_corr_wan2.pcap"] = build_corr_asymmetric()
    for name, cap in outputs.items():
        path = os.path.join(out_dir, name)
        cap.write(path)
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
