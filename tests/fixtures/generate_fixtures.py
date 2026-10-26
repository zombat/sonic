#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Network Detector Test Fixtures

Generates the small, deterministic pcap files the network detector tests read.
Every packet is built byte by byte with scapy and struct, with fixed addresses,
fixed timestamps and no randomness, so running this script twice produces
identical files. Addresses come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and private 10.0.0.0/8.

Usage:
    python3 tests/fixtures/generate_fixtures.py            # writes next to this script
    python3 tests/fixtures/generate_fixtures.py OUT_DIR    # writes into OUT_DIR

Fixtures:
    ipsec_ikev2_esp.pcap        IKEv2 SA_INIT + IKE_AUTH, ESP both ways, a CREATE_CHILD_SA rekey
    ipsec_cleartext_icmp.pcap   the same, plus a cleartext ICMP echo between the same peers
    ikev2_no_proposal.pcap      IKE_SA_INIT answered with NO_PROPOSAL_CHOSEN
    ikev2_no_response.pcap      IKE_SA_INIT retransmitted with no reply at all
    ikev1.pcap                  IKEv1 Main Mode + Quick Mode + ESP; a second peer refused with NO-PROPOSAL-CHOSEN
    ipsec_natt.pcap             NAT-T: IKE floats to UDP 4500, ESP-in-UDP, keepalives, a sequence gap and a replayed packet
    gre_nhrp.pcap               DMVPN: GRE with key, NHRP registrations (one refused), Phase 3 redirect, resolution, error indication
    bgp_session.pcap            iBGP session up, UPDATEs, hold timer expired NOTIFICATION, re-establish; a bad-peer-AS OPEN; a refused TCP 179
    ospf_hello_mismatch.pcap    two OSPF routers on one link with different hello/dead intervals
    ospf_failover.pcap          OSPF adjacency up (2-Way, DBD), one router goes silent past the dead interval and returns
    eigrp_mismatch.pcap         EIGRP K-value mismatch, a goodbye, and a neighbor that goes silent past its hold time
    routing_over_gre.pcap       EIGRP and iBGP inside GRE (a DMVPN tunnel without IPsec), seen on the WAN
    icmp_loss.pcap              ICMP echo with a 3-packet outage, unreachables, TTL exceeded, ARP with and without replies
    sip_minimal.pcap            a tiny SIP INVITE/200/ACK/BYE exchange (proves the SIP path still runs)
"""

import hashlib
import os
import struct
import sys

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

BASE_TIME = 1767225600.0  # 2026-01-01T00:00:00Z

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"
MAC_C = "02:00:00:00:00:0c"
MAC_BCAST = "ff:ff:ff:ff:ff:ff"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def inet_checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071) used by OSPF, EIGRP and NHRP."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip4(addr: str) -> bytes:
    """Dotted-quad string to 4 bytes."""
    return bytes(int(octet) for octet in addr.split("."))


def filler(label: str, length: int) -> bytes:
    """Deterministic pseudo-random bytes (stands in for ciphertext, nonces, keys)."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{label}:{counter}".encode()).digest()
        counter += 1
    return out[:length]


class Capture:
    """Collects packets with explicit timestamps relative to BASE_TIME."""

    def __init__(self):
        self.packets = []

    def add(self, offset: float, pkt):
        pkt.time = BASE_TIME + offset
        self.packets.append(pkt)

    def write(self, path: str):
        wrpcap(path, self.packets)


def eth_ip(src, dst, proto=None, ttl=255, mac_src=MAC_A, mac_dst=MAC_B):
    """Ethernet + IPv4 header."""
    kwargs = {"src": src, "dst": dst, "ttl": ttl}
    if proto is not None:
        kwargs["proto"] = proto
    return Ether(src=mac_src, dst=mac_dst) / IP(**kwargs)


# ---------------------------------------------------------------------------
# IKE / ESP builders
# ---------------------------------------------------------------------------

IKE_SA_INIT = 34
IKE_AUTH = 35
CREATE_CHILD_SA = 36
INFORMATIONAL = 37

FLAG_INITIATOR = 0x08
FLAG_RESPONSE = 0x20


def ike_message(ispi, rspi, exch, flags, msgid, payloads, version=0x20):
    """
    Build an IKE message. payloads is a list of (type, body) or (type, body, inner_next)
    tuples; inner_next overrides the next-payload field (used by the SK payload, whose
    next-payload names the first encrypted payload).
    """
    data = b""
    for index, item in enumerate(payloads):
        body = item[1]
        if len(item) > 2:
            nxt = item[2]
        else:
            nxt = payloads[index + 1][0] if index + 1 < len(payloads) else 0
        data += struct.pack("!BBH", nxt, 0, 4 + len(body)) + body
    first = payloads[0][0] if payloads else 0
    header = ispi + rspi + struct.pack("!BBBBII", first, version, exch, flags, msgid, 28 + len(data))
    return header + data


def ikev2_sa_body():
    """One IKE proposal: AES-CBC-256, PRF-HMAC-SHA256, HMAC-SHA256-128, DH group 14."""
    transforms = [
        (1, 12, struct.pack("!HH", 0x800E, 256)),
        (2, 5, b""),
        (3, 12, b""),
        (4, 14, b""),
    ]
    tbytes = b""
    for index, (ttype, tid, attrs) in enumerate(transforms):
        more = 3 if index + 1 < len(transforms) else 0
        tbytes += struct.pack("!BBHBBH", more, 0, 8 + len(attrs), ttype, 0, tid) + attrs
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(tbytes), 1, 1, 0, len(transforms)) + tbytes
    return proposal


def notify_body(msgtype, data=b"", protoid=0):
    return struct.pack("!BBH", protoid, 0, msgtype) + data


def ike_sa_init_request(ispi, label):
    return ike_message(ispi, bytes(8), IKE_SA_INIT, FLAG_INITIATOR, 0, [
        (33, ikev2_sa_body()),
        (34, struct.pack("!HH", 14, 0) + filler(label + "ke", 64)),
        (40, filler(label + "ni", 32)),
        (41, notify_body(16388, filler(label + "natd-src", 20))),
        (41, notify_body(16389, filler(label + "natd-dst", 20))),
    ])


def ike_sa_init_response(ispi, rspi, label):
    return ike_message(ispi, rspi, IKE_SA_INIT, FLAG_RESPONSE, 0, [
        (33, ikev2_sa_body()),
        (34, struct.pack("!HH", 14, 0) + filler(label + "kr", 64)),
        (40, filler(label + "nr", 32)),
        (41, notify_body(16388, filler(label + "natd-src-r", 20))),
        (41, notify_body(16389, filler(label + "natd-dst-r", 20))),
    ])


def ike_encrypted(ispi, rspi, exch, flags, msgid, inner_first, length, label):
    """An IKEv2 message whose only payload is SK (encrypted and integrity protected)."""
    body = filler(label, length)
    return ike_message(ispi, rspi, exch, flags, msgid, [(46, body, inner_first)])


def esp_packet(spi, seq, label, length=80):
    return struct.pack("!II", spi, seq) + filler(f"{label}:{seq}", length)


# ---------------------------------------------------------------------------
# Fixture: IKEv2 + ESP (encrypted verdict), optionally with cleartext ICMP
# ---------------------------------------------------------------------------

HUB_WAN = "192.0.2.1"
SPOKE_WAN = "198.51.100.2"
SPOKE3_WAN = "203.0.113.3"


def build_ikev2_esp(with_cleartext_icmp=False):
    cap = Capture()
    ispi = bytes.fromhex("1111111111111111")
    rspi = bytes.fromhex("2222222222222222")
    t = 0.0

    def ike(src, dst, payload, offset, sport=500, dport=500):
        mac_src, mac_dst = (MAC_A, MAC_B) if src == SPOKE_WAN else (MAC_B, MAC_A)
        cap.add(offset, eth_ip(src, dst, mac_src=mac_src, mac_dst=mac_dst) / UDP(sport=sport, dport=dport) / Raw(payload))

    ike(SPOKE_WAN, HUB_WAN, ike_sa_init_request(ispi, "a"), t)
    ike(HUB_WAN, SPOKE_WAN, ike_sa_init_response(ispi, rspi, "a"), t + 0.010)
    ike(SPOKE_WAN, HUB_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "auth-i"), t + 0.030)
    ike(HUB_WAN, SPOKE_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_RESPONSE, 1, 36, 272, "auth-r"), t + 0.045)

    spi_out, spi_in = 0xC0FFEE01, 0xC0FFEE02
    t = 1.0
    for seq in range(1, 11):
        cap.add(t, eth_ip(SPOKE_WAN, HUB_WAN, proto=50) / Raw(esp_packet(spi_out, seq, "out")))
        cap.add(t + 0.004, eth_ip(HUB_WAN, SPOKE_WAN, proto=50, mac_src=MAC_B, mac_dst=MAC_A) / Raw(esp_packet(spi_in, seq, "in")))
        t += 0.5

    if with_cleartext_icmp:
        for seq in range(1, 5):
            cap.add(t, eth_ip(SPOKE_WAN, HUB_WAN, ttl=64) / ICMP(type=8, id=0x77, seq=seq) / Raw(b"cleartext ping"))
            cap.add(t + 0.002, eth_ip(HUB_WAN, SPOKE_WAN, ttl=64, mac_src=MAC_B, mac_dst=MAC_A) / ICMP(type=0, id=0x77, seq=seq) / Raw(b"cleartext ping"))
            t += 0.25

    # Rekey: CREATE_CHILD_SA, then a new pair of SPIs carries the traffic.
    ike(SPOKE_WAN, HUB_WAN, ike_encrypted(ispi, rspi, CREATE_CHILD_SA, FLAG_INITIATOR, 2, 33, 240, "rekey-i"), t)
    ike(HUB_WAN, SPOKE_WAN, ike_encrypted(ispi, rspi, CREATE_CHILD_SA, FLAG_RESPONSE, 2, 33, 224, "rekey-r"), t + 0.012)
    t += 0.5
    new_out, new_in = 0xC0FFEE11, 0xC0FFEE12
    for seq in range(1, 6):
        cap.add(t, eth_ip(SPOKE_WAN, HUB_WAN, proto=50) / Raw(esp_packet(new_out, seq, "out2")))
        cap.add(t + 0.004, eth_ip(HUB_WAN, SPOKE_WAN, proto=50, mac_src=MAC_B, mac_dst=MAC_A) / Raw(esp_packet(new_in, seq, "in2")))
        t += 0.5
    return cap


def build_ikev2_no_proposal():
    cap = Capture()
    ispi = bytes.fromhex("3333333333333333")
    for attempt in range(2):
        t = attempt * 2.0
        cap.add(t, eth_ip(SPOKE_WAN, HUB_WAN) / UDP(sport=500, dport=500) / Raw(ike_sa_init_request(ispi, f"np{attempt}")))
        reply = ike_message(ispi, bytes(8), IKE_SA_INIT, FLAG_RESPONSE, 0, [(41, notify_body(14))])
        cap.add(t + 0.008, eth_ip(HUB_WAN, SPOKE_WAN, mac_src=MAC_B, mac_dst=MAC_A) / UDP(sport=500, dport=500) / Raw(reply))
    return cap


def build_ikev2_no_response():
    cap = Capture()
    ispi = bytes.fromhex("4444444444444444")
    request = ike_sa_init_request(ispi, "nr")
    for index, offset in enumerate([0.0, 2.0, 6.0, 14.0]):
        cap.add(offset, eth_ip(SPOKE_WAN, HUB_WAN) / UDP(sport=500, dport=500) / Raw(request))
    return cap


def build_ipsec_natt():
    cap = Capture()
    nat_outside = "203.0.113.50"  # the spoke's address after NAT
    ispi = bytes.fromhex("5555555555555555")
    rspi = bytes.fromhex("6666666666666666")
    marker = b"\x00\x00\x00\x00"
    cap.add(0.0, eth_ip(nat_outside, HUB_WAN) / UDP(sport=500, dport=500) / Raw(ike_sa_init_request(ispi, "n")))
    cap.add(0.010, eth_ip(HUB_WAN, nat_outside, mac_src=MAC_B, mac_dst=MAC_A) / UDP(sport=500, dport=500) / Raw(ike_sa_init_response(ispi, rspi, "n")))
    cap.add(0.030, eth_ip(nat_outside, HUB_WAN) / UDP(sport=4500, dport=4500) / Raw(marker + ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "nauth-i")))
    cap.add(0.045, eth_ip(HUB_WAN, nat_outside, mac_src=MAC_B, mac_dst=MAC_A) / UDP(sport=4500, dport=4500) / Raw(marker + ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_RESPONSE, 1, 36, 272, "nauth-r")))
    spi_out, spi_in = 0xAB000001, 0xAB000002
    t = 1.0
    # Outbound skips sequence 5 (a gap) and repeats sequence 7 (a possible replay).
    out_seqs = [1, 2, 3, 4, 6, 7, 7, 8]
    for index, seq in enumerate(out_seqs):
        cap.add(t, eth_ip(nat_outside, HUB_WAN) / UDP(sport=4500, dport=4500) / Raw(esp_packet(spi_out, seq, "nout")))
        if index < 6:
            cap.add(t + 0.004, eth_ip(HUB_WAN, nat_outside, mac_src=MAC_B, mac_dst=MAC_A) / UDP(sport=4500, dport=4500) / Raw(esp_packet(spi_in, index + 1, "nin")))
        t += 0.5
    cap.add(t, eth_ip(nat_outside, HUB_WAN) / UDP(sport=4500, dport=4500) / Raw(b"\xff"))
    cap.add(t + 20.0, eth_ip(nat_outside, HUB_WAN) / UDP(sport=4500, dport=4500) / Raw(b"\xff"))
    return cap


def ikev1_sa_body():
    """IKEv1 SA payload: DOI IPsec, one proposal with one transform (AES-256, SHA, PSK, group 14)."""
    attrs = b"".join(struct.pack("!HH", 0x8000 | attr, value) for attr, value in
                     [(1, 7), (14, 256), (2, 2), (3, 1), (4, 14), (11, 1), (12, 28800)])
    transform = struct.pack("!BBH", 0, 0, 4 + 4 + len(attrs)) + bytes([1, 1, 0, 0]) + attrs
    proposal_body = bytes([1, 1, 0, 1]) + transform  # proposal 1, ISAKMP, no SPI, 1 transform
    proposal = struct.pack("!BBH", 0, 0, 4 + len(proposal_body)) + proposal_body
    return struct.pack("!II", 1, 1) + proposal


def ikev1_message(ispi, rspi, exch, msgid, payloads, encrypted=False, label=""):
    if encrypted:
        body = filler(label, 80)
        first = payloads[0][0] if payloads else 8
        return ispi + rspi + struct.pack("!BBBBII", first, 0x10, exch, 0x01, msgid, 28 + len(body)) + body
    return ike_message(ispi, rspi, exch, 0, msgid, payloads, version=0x10)


def build_ikev1():
    cap = Capture()
    # SA A: Main Mode (6 messages, the last two encrypted), Quick Mode (3, encrypted), then ESP.
    ispi, rspi = bytes.fromhex("7777777777777777"), bytes.fromhex("8888888888888888")
    i, r = SPOKE_WAN, HUB_WAN

    def send(src, dst, payload, t):
        mac_src, mac_dst = (MAC_A, MAC_B) if src == i else (MAC_B, MAC_A)
        cap.add(t, eth_ip(src, dst, mac_src=mac_src, mac_dst=mac_dst) / UDP(sport=500, dport=500) / Raw(payload))

    send(i, r, ikev1_message(ispi, bytes(8), 2, 0, [(1, ikev1_sa_body())]), 0.00)
    send(r, i, ikev1_message(ispi, rspi, 2, 0, [(1, ikev1_sa_body())]), 0.01)
    send(i, r, ikev1_message(ispi, rspi, 2, 0, [(4, filler("v1ke-i", 64)), (10, filler("v1n-i", 32))]), 0.02)
    send(r, i, ikev1_message(ispi, rspi, 2, 0, [(4, filler("v1ke-r", 64)), (10, filler("v1n-r", 32))]), 0.03)
    send(i, r, ikev1_message(ispi, rspi, 2, 0, [(5, b"")], encrypted=True, label="mm5"), 0.04)
    send(r, i, ikev1_message(ispi, rspi, 2, 0, [(5, b"")], encrypted=True, label="mm6"), 0.05)
    for index, (src, dst) in enumerate([(i, r), (r, i), (i, r)]):
        send(src, dst, ikev1_message(ispi, rspi, 32, 0x0A0B0C0D, [(8, b"")], encrypted=True, label=f"qm{index}"),
             0.06 + index * 0.01)
    t = 1.0
    for seq in range(1, 6):
        cap.add(t, eth_ip(i, r, proto=50) / Raw(esp_packet(0xD0000001, seq, "v1out")))
        cap.add(t + 0.003, eth_ip(r, i, proto=50, mac_src=MAC_B, mac_dst=MAC_A) / Raw(esp_packet(0xD0000002, seq, "v1in")))
        t += 0.5
    # SA B: another spoke's Main Mode is refused in a cleartext Informational NO-PROPOSAL-CHOSEN.
    ispi_b = bytes.fromhex("9999999999999999")
    cap.add(4.0, eth_ip(SPOKE3_WAN, HUB_WAN, mac_src=MAC_C) / UDP(sport=500, dport=500)
            / Raw(ikev1_message(ispi_b, bytes(8), 2, 0, [(1, ikev1_sa_body())])))
    notification = struct.pack("!IBBH", 1, 1, 0, 14)
    cap.add(4.01, eth_ip(HUB_WAN, SPOKE3_WAN, mac_dst=MAC_C) / UDP(sport=500, dport=500)
            / Raw(ikev1_message(ispi_b, bytes(8), 5, 0x11223344, [(11, notification)])))
    return cap


# ---------------------------------------------------------------------------
# Fixture: GRE + NHRP (DMVPN)
# ---------------------------------------------------------------------------

HUB_TUN = "10.0.0.1"
SPOKE2_TUN = "10.0.0.2"
SPOKE3_TUN = "10.0.0.3"
SPOKE4_WAN = "192.0.2.44"
SPOKE4_TUN = "10.0.0.4"
GRE_KEY = 100


def gre(inner_proto: int, inner: bytes, key=GRE_KEY) -> bytes:
    if key is None:
        return struct.pack("!HH", 0x0000, inner_proto) + inner
    return struct.pack("!HHI", 0x2000, inner_proto, key) + inner


def nhrp_packet(op: int, mandatory: bytes) -> bytes:
    """NHRP fixed header (RFC 2332 5.1) + mandatory part, with a correct checksum."""
    total = 20 + len(mandatory)

    def header(checksum):
        return (struct.pack("!HH", 0x0001, 0x0800) + bytes(5)
                + struct.pack("!BHHHBBBB", 255, total, checksum, 0, 1, op, 4, 0))

    checksum = inet_checksum(header(0) + mandatory)
    return header(checksum) + mandatory


def nhrp_cie(code=0, prefix=32, mtu=1400, htime=7200, cli_nbma=None, cli_proto=None):
    nbma = ip4(cli_nbma) if cli_nbma else b""
    proto = ip4(cli_proto) if cli_proto else b""
    return struct.pack("!BBHHHBBBB", code, prefix, 0, mtu, htime, len(nbma), 0, len(proto), 0) + nbma + proto


def nhrp_mandatory(flags, reqid, src_nbma, src_proto, dst_proto, cies=b""):
    return (struct.pack("!BBHI", 4, 4, flags, reqid) + ip4(src_nbma) + ip4(src_proto) + ip4(dst_proto) + cies)


def nhrp_error(code, src_nbma, src_proto, dst_proto, errored=b""):
    return struct.pack("!BBHHH", 4, 4, 0, code, 0) + ip4(src_nbma) + ip4(src_proto) + ip4(dst_proto) + errored


def nhrp_traffic_indication(src_nbma, src_proto, dst_proto, original: bytes):
    """Cisco NHRP Traffic Indication (type 8), the DMVPN Phase 3 redirect."""
    return struct.pack("!BBHI", 4, 4, 0, 0) + ip4(src_nbma) + ip4(src_proto) + ip4(dst_proto) + original


def build_gre_nhrp():
    cap = Capture()

    def send(src, dst, payload, offset, mac_src=MAC_A, mac_dst=MAC_B):
        cap.add(offset, eth_ip(src, dst, proto=47, mac_src=mac_src, mac_dst=mac_dst) / Raw(payload))

    # Spoke 2 and spoke 3 register with the hub (success); spoke 4 is refused (code 4).
    reg = 0x02000000
    send(SPOKE_WAN, HUB_WAN, gre(0x2001, nhrp_packet(3, nhrp_mandatory(0x8000, reg + 1, SPOKE_WAN, SPOKE2_TUN, HUB_TUN, nhrp_cie(prefix=32)))), 0.0)
    send(HUB_WAN, SPOKE_WAN, gre(0x2001, nhrp_packet(4, nhrp_mandatory(0x8000, reg + 1, SPOKE_WAN, SPOKE2_TUN, HUB_TUN, nhrp_cie(code=0, prefix=32)))), 0.005, MAC_B, MAC_A)
    send(SPOKE3_WAN, HUB_WAN, gre(0x2001, nhrp_packet(3, nhrp_mandatory(0x8000, reg + 2, SPOKE3_WAN, SPOKE3_TUN, HUB_TUN, nhrp_cie(prefix=32)))), 0.100, MAC_C, MAC_B)
    send(HUB_WAN, SPOKE3_WAN, gre(0x2001, nhrp_packet(4, nhrp_mandatory(0x8000, reg + 2, SPOKE3_WAN, SPOKE3_TUN, HUB_TUN, nhrp_cie(code=0, prefix=32)))), 0.105, MAC_B, MAC_C)
    send(SPOKE4_WAN, HUB_WAN, gre(0x2001, nhrp_packet(3, nhrp_mandatory(0x8000, reg + 3, SPOKE4_WAN, SPOKE4_TUN, HUB_TUN, nhrp_cie(prefix=32)))), 0.200)
    send(HUB_WAN, SPOKE4_WAN, gre(0x2001, nhrp_packet(4, nhrp_mandatory(0x8000, reg + 3, SPOKE4_WAN, SPOKE4_TUN, HUB_TUN, nhrp_cie(code=4, prefix=32)))), 0.205, MAC_B, MAC_A)

    # Spoke 2 sends data to a host behind spoke 3 through the hub.
    inner = bytes(IP(src="10.1.2.1", dst="10.1.3.1", ttl=63) / ICMP(type=8, id=9, seq=1) / Raw(b"via hub"))
    send(SPOKE_WAN, HUB_WAN, gre(0x0800, inner), 1.0)
    send(HUB_WAN, SPOKE3_WAN, gre(0x0800, inner), 1.001, MAC_B, MAC_C)
    # The hub redirects spoke 2 (Phase 3 shortcut signalling).
    original = inner[:28]
    send(HUB_WAN, SPOKE_WAN, gre(0x2001, nhrp_packet(8, nhrp_traffic_indication(HUB_WAN, HUB_TUN, "10.1.2.1", original))), 1.002, MAC_B, MAC_A)
    # Spoke 2 resolves 10.1.3.1; spoke 3 answers directly with its NBMA address.
    res = 0x03000000
    send(SPOKE_WAN, HUB_WAN, gre(0x2001, nhrp_packet(1, nhrp_mandatory(0x8000, res + 1, SPOKE_WAN, SPOKE2_TUN, "10.1.3.1", nhrp_cie(prefix=32)))), 1.010)
    send(HUB_WAN, SPOKE3_WAN, gre(0x2001, nhrp_packet(1, nhrp_mandatory(0x8000, res + 1, SPOKE_WAN, SPOKE2_TUN, "10.1.3.1", nhrp_cie(prefix=32)))), 1.011, MAC_B, MAC_C)
    send(SPOKE3_WAN, SPOKE_WAN, gre(0x2001, nhrp_packet(2, nhrp_mandatory(0x8000 | 0x4000, res + 1, SPOKE_WAN, SPOKE2_TUN, "10.1.3.1", nhrp_cie(code=0, prefix=24, cli_nbma=SPOKE3_WAN, cli_proto=SPOKE3_TUN)))), 1.020, MAC_C, MAC_A)
    # A resolution request for an address nobody owns: the hub answers with an error indication.
    unresolvable = nhrp_packet(1, nhrp_mandatory(0x8000, res + 2, SPOKE_WAN, SPOKE2_TUN, "10.9.9.9", nhrp_cie(prefix=32)))
    send(SPOKE_WAN, HUB_WAN, gre(0x2001, unresolvable), 2.0)
    send(HUB_WAN, SPOKE_WAN, gre(0x2001, nhrp_packet(7, nhrp_error(6, HUB_WAN, HUB_TUN, SPOKE2_TUN, unresolvable))), 2.005, MAC_B, MAC_A)
    # Spoke-to-spoke data now flows directly.
    inner2 = bytes(IP(src="10.1.2.1", dst="10.1.3.1", ttl=63) / ICMP(type=8, id=9, seq=2) / Raw(b"direct"))
    send(SPOKE_WAN, SPOKE3_WAN, gre(0x0800, inner2), 3.0, MAC_A, MAC_C)
    return cap


# ---------------------------------------------------------------------------
# Fixture: BGP
# ---------------------------------------------------------------------------

BGP_MARKER = b"\xff" * 16


def bgp_msg(mtype, body=b""):
    return BGP_MARKER + struct.pack("!HB", 19 + len(body), mtype) + body


def bgp_open(asn, hold, router_id):
    caps = bytes([1, 4, 0, 1, 0, 1]) + bytes([65, 4]) + struct.pack("!I", asn)
    opt = bytes([2, len(caps)]) + caps
    return bgp_msg(1, struct.pack("!BHH", 4, asn if asn < 65536 else 23456, hold) + ip4(router_id) + bytes([len(opt)]) + opt)


def bgp_keepalive():
    return bgp_msg(4)


def bgp_update(prefixes, next_hop, withdrawn=()):
    def encode(prefix):
        net, plen = prefix.split("/")
        plen = int(plen)
        return bytes([plen]) + ip4(net)[: (plen + 7) // 8]

    wd = b"".join(encode(p) for p in withdrawn)
    attrs = b""
    if prefixes:
        attrs += bytes([0x40, 1, 1, 0])              # ORIGIN IGP
        attrs += bytes([0x40, 2, 0])                 # AS_PATH empty (iBGP)
        attrs += bytes([0x40, 3, 4]) + ip4(next_hop)  # NEXT_HOP
        attrs += bytes([0x40, 5, 4]) + struct.pack("!I", 100)  # LOCAL_PREF
    nlri = b"".join(encode(p) for p in prefixes)
    return bgp_msg(2, struct.pack("!H", len(wd)) + wd + struct.pack("!H", len(attrs)) + attrs + nlri)


def bgp_notification(code, subcode, data=b""):
    return bgp_msg(3, bytes([code, subcode]) + data)


class TcpConversation:
    """Tracks sequence numbers for a TCP conversation between endpoint a and endpoint b."""

    def __init__(self, cap, a, a_port, b, b_port, a_isn, b_isn, mac_a=MAC_A, mac_b=MAC_B, tunnel=None):
        self.cap = cap
        self.ends = {True: (a, a_port, mac_a), False: (b, b_port, mac_b)}
        self.next_seq = {True: a_isn, False: b_isn}
        # tunnel=(outer_a, outer_b) carries the conversation inside GRE between those addresses.
        self.tunnel = tunnel

    def send(self, from_a, offset, flags, payload=b""):
        src, sport, mac_src = self.ends[from_a]
        dst, dport, mac_dst = self.ends[not from_a]
        seq = self.next_seq[from_a]
        ack = self.next_seq[not from_a] if "A" in flags else 0
        segment = IP(src=src, dst=dst, ttl=255) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
                                                      window=16384)
        if payload:
            segment = segment / Raw(payload)
        if self.tunnel:
            outer_src, outer_dst = self.tunnel if from_a else self.tunnel[::-1]
            pkt = eth_ip(outer_src, outer_dst, proto=47, mac_src=mac_src, mac_dst=mac_dst) / Raw(gre(0x0800, bytes(segment)))
        else:
            pkt = Ether(src=mac_src, dst=mac_dst) / segment
        self.cap.add(offset, pkt)
        consumed = len(payload) + (1 if "S" in flags else 0) + (1 if "F" in flags else 0)
        self.next_seq[from_a] = seq + consumed


def build_bgp_session():
    cap = Capture()
    r1, r2 = "10.255.0.1", "10.255.0.2"

    def session(start, isn_a, isn_b, sport, hold_a, hold_b, fail_with_hold_expiry):
        conv = TcpConversation(cap, r1, sport, r2, 179, isn_a, isn_b)
        t = start
        conv.send(True, t, "S")
        conv.send(False, t + 0.001, "SA")
        conv.send(True, t + 0.002, "A")
        conv.send(True, t + 0.010, "PA", bgp_open(65000, hold_a, "1.1.1.1"))
        conv.send(False, t + 0.012, "PA", bgp_open(65000, hold_b, "2.2.2.2"))
        conv.send(True, t + 0.020, "PA", bgp_keepalive())
        conv.send(False, t + 0.022, "PA", bgp_keepalive())
        conv.send(True, t + 0.100, "PA", bgp_update(["10.1.1.0/24", "10.1.2.0/24"], r1))
        conv.send(False, t + 0.102, "PA", bgp_update(["10.2.2.0/24"], r2))
        conv.send(True, t + 0.110, "PA", bgp_update([], r1))   # End-of-RIB
        conv.send(False, t + 0.112, "PA", bgp_update([], r2))  # End-of-RIB
        t += 10.0
        conv.send(True, t, "PA", bgp_keepalive())
        conv.send(False, t + 0.001, "PA", bgp_keepalive())
        if fail_with_hold_expiry:
            # r2 goes quiet; r1 keeps sending keepalives until its 30 s hold timer expires.
            conv.send(True, t + 10.0, "PA", bgp_keepalive())
            conv.send(True, t + 20.0, "PA", bgp_keepalive())
            conv.send(True, t + 30.5, "PA", bgp_notification(4, 0))
            conv.send(True, t + 30.6, "FA")
            conv.send(False, t + 30.7, "RA")
            return t + 30.7
        conv.send(True, t + 0.5, "PA", bgp_update([], r1, withdrawn=["10.1.2.0/24"]))
        return t + 0.5

    end = session(0.0, 1000, 5000, 40001, 30, 90, True)
    session(end + 5.0, 9000, 15000, 40002, 30, 90, False)

    # A third router opens with the wrong AS and is refused (OPEN error, bad peer AS).
    r3 = "10.255.0.3"
    conv = TcpConversation(cap, r3, 40003, r1, 179, 300, 700, MAC_C, MAC_A)
    t = 2.0
    conv.send(True, t, "S")
    conv.send(False, t + 0.001, "SA")
    conv.send(True, t + 0.002, "A")
    conv.send(True, t + 0.010, "PA", bgp_open(65099, 180, "3.3.3.3"))
    conv.send(False, t + 0.011, "PA", bgp_notification(2, 2, struct.pack("!H", 65099)))
    conv.send(False, t + 0.012, "FA")

    # A fourth address refuses TCP 179 outright (no neighbor configured there).
    r4 = "10.255.0.4"
    conv = TcpConversation(cap, r1, 40004, r4, 179, 50, 0, MAC_A, MAC_C)
    conv.send(True, 3.0, "S")
    conv.send(False, 3.001, "RA")
    cap.packets.sort(key=lambda p: p.time)
    return cap


# ---------------------------------------------------------------------------
# Fixture: OSPF
# ---------------------------------------------------------------------------

def ospf_packet(ptype, router_id, area, body, auth_type=0):
    length = 24 + len(body)

    def header(checksum):
        return struct.pack("!BBH", 2, ptype, length) + ip4(router_id) + ip4(area) + struct.pack("!HH", checksum, auth_type)

    # The checksum covers the whole packet except the 64-bit authentication field.
    checksum = inet_checksum(header(0) + body)
    return header(checksum) + bytes(8) + body


def ospf_hello(router_id, area, mask, hello, dead, dr="0.0.0.0", bdr="0.0.0.0", neighbors=(), prio=1, options=0x02):
    body = ip4(mask) + struct.pack("!HBBI", hello, options, prio, dead) + ip4(dr) + ip4(bdr)
    body += b"".join(ip4(n) for n in neighbors)
    return ospf_packet(1, router_id, area, body)


def ospf_dbd(router_id, area, mtu, flags, seq, options=0x02):
    return ospf_packet(2, router_id, area, struct.pack("!HBBI", mtu, options, flags, seq))


def build_ospf_hello_mismatch():
    cap = Capture()
    r1, r2 = "10.0.12.1", "10.0.12.2"
    for index in range(4):
        t = index * 10.0
        cap.add(t, eth_ip(r1, "224.0.0.5", proto=89, ttl=1, mac_dst="01:00:5e:00:00:05") / Raw(ospf_hello("1.1.1.1", "0.0.0.0", "255.255.255.0", 10, 40)))
    for index in range(8):
        t = 1.0 + index * 5.0
        cap.add(t, eth_ip(r2, "224.0.0.5", proto=89, ttl=1, mac_src=MAC_B, mac_dst="01:00:5e:00:00:05") / Raw(ospf_hello("2.2.2.2", "0.0.0.0", "255.255.255.0", 5, 20)))
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_ospf_failover():
    cap = Capture()
    r1, r3 = "10.0.13.1", "10.0.13.3"
    mcast = "224.0.0.5"

    def hello(src, rid, mac, t, neighbors, dr="0.0.0.0", bdr="0.0.0.0"):
        cap.add(t, eth_ip(src, mcast, proto=89, ttl=1, mac_src=mac, mac_dst="01:00:5e:00:00:05")
                / Raw(ospf_hello(rid, "0.0.0.0", "255.255.255.0", 10, 40, dr=dr, bdr=bdr, neighbors=neighbors)))

    # Bring-up: one-way, then 2-Way, then DBD exchange.
    hello(r1, "1.1.1.1", MAC_A, 0.0, [])
    hello(r3, "3.3.3.3", MAC_C, 0.5, ["1.1.1.1"])
    hello(r1, "1.1.1.1", MAC_A, 1.0, ["3.3.3.3"])
    cap.add(1.2, eth_ip(r1, r3, proto=89, ttl=1, mac_src=MAC_A, mac_dst=MAC_C) / Raw(ospf_dbd("1.1.1.1", "0.0.0.0", 1500, 0x07, 1000)))
    cap.add(1.3, eth_ip(r3, r1, proto=89, ttl=1, mac_src=MAC_C, mac_dst=MAC_A) / Raw(ospf_dbd("3.3.3.3", "0.0.0.0", 1500, 0x07, 3000)))
    # Steady state, DR 10.0.13.3, BDR 10.0.13.1.
    for index in range(1, 4):
        t = index * 10.0
        hello(r1, "1.1.1.1", MAC_A, t, ["3.3.3.3"], dr=r3, bdr=r1)
        hello(r3, "3.3.3.3", MAC_C, t + 0.5, ["1.1.1.1"], dr=r3, bdr=r1)
    # r3 fails at about t=30.5: r1 keeps sending hellos and drops it once the
    # 40 s dead interval runs out (t=70.5), becoming DR itself.
    for index in range(4, 9):
        t = index * 10.0
        neighbors = ["3.3.3.3"] if t < 70.5 else []
        hello(r1, "1.1.1.1", MAC_A, t, neighbors, dr=r3 if neighbors else r1, bdr=r1 if neighbors else "0.0.0.0")
    # r3 comes back at t=85.
    hello(r3, "3.3.3.3", MAC_C, 85.0, [])
    hello(r1, "1.1.1.1", MAC_A, 90.0, ["3.3.3.3"], dr=r1)
    hello(r3, "3.3.3.3", MAC_C, 95.0, ["1.1.1.1"], dr=r1)
    cap.packets.sort(key=lambda p: p.time)
    return cap


# ---------------------------------------------------------------------------
# Fixture: EIGRP
# ---------------------------------------------------------------------------

def eigrp_packet(opcode, asn, tlvs=b"", flags=0, seq=0, ack=0):
    def build(checksum):
        return struct.pack("!BBHIIIHH", 2, opcode, checksum, flags, seq, ack, 0, asn) + tlvs

    return build(inet_checksum(build(0)))


def eigrp_param_tlv(k_values, hold):
    return struct.pack("!HH", 0x0001, 12) + bytes(k_values) + struct.pack("!H", hold)


def eigrp_version_tlv():
    return struct.pack("!HHBBBB", 0x0004, 8, 15, 0, 2, 0)


def eigrp_route_tlv(prefix_len, prefix_bytes):
    # A classic IPv4 internal route TLV (0x0102) with a dummy metric.
    body = ip4("0.0.0.0") + struct.pack("!II", 2560, 256000) + (1500).to_bytes(3, "big") + struct.pack("!BBBH", 0, 255, 1, 0)
    body += bytes([prefix_len]) + prefix_bytes
    return struct.pack("!HH", 0x0102, 4 + len(body)) + body


def build_eigrp_mismatch():
    cap = Capture()
    mcast = "224.0.0.10"
    r1, r2, r3 = "10.0.23.1", "10.0.23.2", "10.0.23.3"
    good_k = [1, 0, 1, 0, 0, 0]
    bad_k = [1, 1, 1, 0, 0, 0]

    def hello(src, mac, t, k, hold=15):
        cap.add(t, eth_ip(src, mcast, proto=88, ttl=2, mac_src=mac, mac_dst="01:00:5e:00:00:0a")
                / Raw(eigrp_packet(5, 100, eigrp_param_tlv(k, hold) + eigrp_version_tlv())))

    # r1 and r2 are healthy neighbors; r3 has different K-values.
    for index in range(5):
        t = index * 5.0
        hello(r1, MAC_A, t, good_k)
        hello(r2, MAC_B, t + 0.2, good_k)
        hello(r3, MAC_C, t + 0.4, bad_k)
    # r1 and r2 bring up the adjacency (INIT update) and exchange a route.
    cap.add(0.5, eth_ip(r1, r2, proto=88, ttl=2, mac_src=MAC_A, mac_dst=MAC_B) / Raw(eigrp_packet(1, 100, flags=0x1, seq=1)))
    cap.add(0.6, eth_ip(r2, r1, proto=88, ttl=2, mac_src=MAC_B, mac_dst=MAC_A) / Raw(eigrp_packet(1, 100, flags=0x1, seq=1, ack=1)))
    cap.add(0.7, eth_ip(r1, r2, proto=88, ttl=2, mac_src=MAC_A, mac_dst=MAC_B) / Raw(eigrp_packet(1, 100, eigrp_route_tlv(24, bytes([10, 1, 1])), flags=0x8, seq=2, ack=1)))
    # r2 sends a goodbye at t=25 (all K-values 255), then goes silent; r1 continues.
    hello(r2, MAC_B, 25.0, [255] * 6)
    for index in range(6, 10):
        hello(r1, MAC_A, index * 5.0, good_k)
    # r1 queries for the lost route.
    cap.add(26.0, eth_ip(r1, mcast, proto=88, ttl=2, mac_src=MAC_A, mac_dst="01:00:5e:00:00:0a") / Raw(eigrp_packet(3, 100, eigrp_route_tlv(24, bytes([10, 2, 2])), seq=3)))
    # r3 goes silent after t=20.4 without a goodbye (hold time 15 s expires at about 35.4).
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_routing_over_gre():
    """EIGRP and iBGP running over a DMVPN tunnel (GRE without IPsec), seen on the WAN."""
    cap = Capture()

    def tunneled(t, outer_src, outer_dst, inner_src, inner_dst, proto, payload, mac_src, mac_dst):
        inner = bytes(IP(src=inner_src, dst=inner_dst, ttl=2, proto=proto) / Raw(payload))
        cap.add(t, eth_ip(outer_src, outer_dst, proto=47, mac_src=mac_src, mac_dst=mac_dst) / Raw(gre(0x0800, inner)))

    k = [1, 0, 1, 0, 0, 0]
    hello = eigrp_packet(5, 100, eigrp_param_tlv(k, 15) + eigrp_version_tlv())
    for index in range(4):
        t = index * 5.0
        tunneled(t, HUB_WAN, SPOKE_WAN, HUB_TUN, "224.0.0.10", 88, hello, MAC_B, MAC_A)
        tunneled(t + 0.3, SPOKE_WAN, HUB_WAN, SPOKE2_TUN, "224.0.0.10", 88, hello, MAC_A, MAC_B)
    tunneled(0.5, HUB_WAN, SPOKE_WAN, HUB_TUN, SPOKE2_TUN, 88, eigrp_packet(1, 100, flags=0x1, seq=1), MAC_B, MAC_A)
    tunneled(0.6, SPOKE_WAN, HUB_WAN, SPOKE2_TUN, HUB_TUN, 88, eigrp_packet(1, 100, flags=0x1, seq=1, ack=1), MAC_A, MAC_B)

    conv = TcpConversation(cap, HUB_TUN, 179, SPOKE2_TUN, 41001, 7000, 8000, MAC_B, MAC_A, tunnel=(HUB_WAN, SPOKE_WAN))
    conv.send(False, 1.0, "S")
    conv.send(True, 1.001, "SA")
    conv.send(False, 1.002, "A")
    conv.send(False, 1.010, "PA", bgp_open(65000, 180, "10.0.0.2"))
    conv.send(True, 1.012, "PA", bgp_open(65000, 180, "10.0.0.1"))
    conv.send(False, 1.020, "PA", bgp_keepalive())
    conv.send(True, 1.022, "PA", bgp_keepalive())
    conv.send(True, 1.100, "PA", bgp_update(["10.1.1.0/24"], HUB_TUN))
    cap.packets.sort(key=lambda p: p.time)
    return cap


# ---------------------------------------------------------------------------
# Fixture: ICMP / ARP reachability
# ---------------------------------------------------------------------------

def build_icmp_loss():
    cap = Capture()
    a, b = "10.1.1.1", "10.2.2.2"
    router = "10.1.1.254"
    t = 0.0
    lost = {4, 5, 6}
    for seq in range(1, 11):
        cap.add(t, eth_ip(a, b, ttl=64) / ICMP(type=8, id=0x1234, seq=seq) / Raw(b"abcdefgh" * 4))
        if seq not in lost:
            rtt = 0.010 + seq * 0.001
            cap.add(t + rtt, eth_ip(b, a, ttl=62, mac_src=MAC_B, mac_dst=MAC_A) / ICMP(type=0, id=0x1234, seq=seq) / Raw(b"abcdefgh" * 4))
        t += 1.0
    # A host unreachable from the gateway for a probe towards 10.3.3.3.
    probe = IP(src=a, dst="10.3.3.3", ttl=64) / ICMP(type=8, id=0x55, seq=1) / Raw(b"probe")
    cap.add(11.0, eth_ip(a, "10.3.3.3", ttl=64) / ICMP(type=8, id=0x55, seq=1) / Raw(b"probe"))
    cap.add(11.002, eth_ip(router, a, ttl=255, mac_src=MAC_B, mac_dst=MAC_A) / ICMP(type=3, code=1) / bytes(probe)[:28])
    # A port unreachable for a UDP probe.
    udp_probe = IP(src=a, dst=b, ttl=64) / UDP(sport=33434, dport=33435) / Raw(b"x" * 12)
    cap.add(12.0, eth_ip(a, b, ttl=64) / UDP(sport=33434, dport=33435) / Raw(b"x" * 12))
    cap.add(12.003, eth_ip(b, a, ttl=62, mac_src=MAC_B, mac_dst=MAC_A) / ICMP(type=3, code=3) / bytes(udp_probe)[:28])
    # A TTL exceeded from the gateway (traceroute hop).
    ttl_probe = IP(src=a, dst=b, ttl=1) / UDP(sport=33434, dport=33436) / Raw(b"y" * 12)
    cap.add(13.0, eth_ip(a, b, ttl=1) / UDP(sport=33434, dport=33436) / Raw(b"y" * 12))
    cap.add(13.001, eth_ip(router, a, ttl=255, mac_src=MAC_B, mac_dst=MAC_A) / ICMP(type=11, code=0) / bytes(ttl_probe)[:28])
    # ARP: the gateway answers; 10.1.1.99 never does (three tries).
    cap.add(14.0, Ether(src=MAC_A, dst=MAC_BCAST) / ARP(op=1, hwsrc=MAC_A, psrc=a, pdst=router))
    cap.add(14.001, Ether(src=MAC_B, dst=MAC_A) / ARP(op=2, hwsrc=MAC_B, psrc=router, hwdst=MAC_A, pdst=a))
    for index in range(3):
        cap.add(15.0 + index, Ether(src=MAC_A, dst=MAC_BCAST) / ARP(op=1, hwsrc=MAC_A, psrc=a, pdst="10.1.1.99"))
    return cap


# ---------------------------------------------------------------------------
# Fixture: minimal SIP
# ---------------------------------------------------------------------------

def build_sip_minimal():
    cap = Capture()
    ua, pbx = "10.5.5.10", "10.5.5.1"
    call_id = "fixture-call-1@10.5.5.10"

    def sip(src, dst, text, t):
        cap.add(t, eth_ip(src, dst, ttl=64) / UDP(sport=5060, dport=5060) / Raw(text.replace("\n", "\r\n").encode()))

    sdp = "v=0\no=ua 1 1 IN IP4 10.5.5.10\ns=call\nc=IN IP4 10.5.5.10\nt=0 0\nm=audio 16384 RTP/AVP 0\na=rtpmap:0 PCMU/8000\n"
    headers = (f"Via: SIP/2.0/UDP {ua}:5060;branch=z9hG4bK1\nFrom: <sip:100@{pbx}>;tag=a1\nTo: <sip:200@{pbx}>\n"
               f"Call-ID: {call_id}\nCSeq: 1 INVITE\nContact: <sip:100@{ua}>\nUser-Agent: fixture-ua\n")
    sip(ua, pbx, f"INVITE sip:200@{pbx} SIP/2.0\n{headers}Content-Type: application/sdp\nContent-Length: {len(sdp.replace(chr(10), chr(13) + chr(10)))}\n\n{sdp}", 0.0)
    sip(pbx, ua, f"SIP/2.0 200 OK\n{headers.replace('To: <sip:200@' + pbx + '>', 'To: <sip:200@' + pbx + '>;tag=b2')}Content-Length: 0\n\n", 0.5)
    sip(ua, pbx, f"ACK sip:200@{pbx} SIP/2.0\n{headers.replace('CSeq: 1 INVITE', 'CSeq: 1 ACK')}Content-Length: 0\n\n", 0.6)
    sip(ua, pbx, f"BYE sip:200@{pbx} SIP/2.0\n{headers.replace('CSeq: 1 INVITE', 'CSeq: 2 BYE')}Content-Length: 0\n\n", 5.0)
    sip(pbx, ua, f"SIP/2.0 200 OK\n{headers.replace('CSeq: 1 INVITE', 'CSeq: 2 BYE')}Content-Length: 0\n\n", 5.1)
    return cap


FIXTURES = {
    "ipsec_ikev2_esp.pcap": lambda: build_ikev2_esp(False),
    "ipsec_cleartext_icmp.pcap": lambda: build_ikev2_esp(True),
    "ikev2_no_proposal.pcap": build_ikev2_no_proposal,
    "ikev2_no_response.pcap": build_ikev2_no_response,
    "ipsec_natt.pcap": build_ipsec_natt,
    "ikev1.pcap": build_ikev1,
    "gre_nhrp.pcap": build_gre_nhrp,
    "bgp_session.pcap": build_bgp_session,
    "ospf_hello_mismatch.pcap": build_ospf_hello_mismatch,
    "ospf_failover.pcap": build_ospf_failover,
    "eigrp_mismatch.pcap": build_eigrp_mismatch,
    "routing_over_gre.pcap": build_routing_over_gre,
    "icmp_loss.pcap": build_icmp_loss,
    "sip_minimal.pcap": build_sip_minimal,
}


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out_dir, exist_ok=True)
    for name, builder in FIXTURES.items():
        path = os.path.join(out_dir, name)
        builder().write(path)
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
