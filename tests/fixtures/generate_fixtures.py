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
    ikev2_negotiation.pcap      two proposals offered, INVALID_KE_PAYLOAD retry, AES-GCM chosen, DPD; a weak SA whose DPD goes unanswered
    ikev2_failures.pcap         NAT-T missing, a PSK-style auth failure, IKE_AUTH unanswered, a DH group never retried
    esp_stale_spi.pcap          an old ESP SPI used after a rekey, and an unprotected INVALID_IKE_SPI
    audit_one_leak.pcap         IKE/ESP plus exactly one GRE-carried BGP, ICMP, ARP, loopback and CDP frame
    nhrp_phase3_broken.pcap     Phase 3 flows that stop at each step, resolution thrashing, no-redirect relaying
    phase3_encrypted.pcap       protected DMVPN on the transport: one spoke-to-spoke shortcut forms, one is never answered
    bgp_failover.pcap           BGP to two hubs with MSS options; hold timer expiry, a RST, an inferred hold expiry, ping outage
    convergence_dpd.pcap        a hub dies under IPsec: ESP stops, DPD goes unanswered, traffic shifts to the other hub
    ospf_stuck.pcap             OSPF stuck in EXSTART (MTU mismatch) and in EXCHANGE (DBD never acknowledged)

Every fixture is synthetic: built here, never captured from a real network.
"""

import hashlib
import os
import struct
import sys

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: F401

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


def natd(ispi, rspi, addr, port):
    """RFC 7296 NAT detection hash: SHA-1(SPIi | SPIr | IP | port)."""
    return hashlib.sha1(ispi + rspi + ip4(addr) + struct.pack("!H", port)).digest()


def ike_sa_init_request(ispi, label, src=None, dst=None, sport=500, dport=500, seen_src=None,
                        sa_body=None, ke_group=14):
    """
    IKE_SA_INIT request. With src/dst the NAT detection hashes are real: computed from
    seen_src (the address the sender believes it has, behind a NAT) or src, so a capture
    of the translated packet shows a NAT; without them they are filler.
    """
    rspi = bytes(8)
    if src is not None:
        natd_src = natd(ispi, rspi, seen_src or src, sport)
        natd_dst = natd(ispi, rspi, dst, dport)
    else:
        natd_src, natd_dst = filler(label + "natd-src", 20), filler(label + "natd-dst", 20)
    return ike_message(ispi, rspi, IKE_SA_INIT, FLAG_INITIATOR, 0, [
        (33, sa_body if sa_body is not None else ikev2_sa_body()),
        (34, struct.pack("!HH", ke_group, 0) + filler(label + "ke", 64)),
        (40, filler(label + "ni", 32)),
        (41, notify_body(16388, natd_src)),
        (41, notify_body(16389, natd_dst)),
    ])


def ike_sa_init_response(ispi, rspi, label, src=None, dst=None, sport=500, dport=500, sa_body=None, ke_group=14):
    """IKE_SA_INIT response; with src/dst its NAT detection hashes match those addresses."""
    if src is not None:
        natd_src, natd_dst = natd(ispi, rspi, src, sport), natd(ispi, rspi, dst, dport)
    else:
        natd_src, natd_dst = filler(label + "natd-src-r", 20), filler(label + "natd-dst-r", 20)
    return ike_message(ispi, rspi, IKE_SA_INIT, FLAG_RESPONSE, 0, [
        (33, sa_body if sa_body is not None else ikev2_sa_body()),
        (34, struct.pack("!HH", ke_group, 0) + filler(label + "kr", 64)),
        (40, filler(label + "nr", 32)),
        (41, notify_body(16388, natd_src)),
        (41, notify_body(16389, natd_dst)),
    ])


def ikev2_proposals(proposals):
    """An SA payload body from [[(type, id, key_length or None), ...], ...] (one list per proposal)."""
    out = b""
    for pindex, transforms in enumerate(proposals):
        tbytes = b""
        for index, (ttype, tid, keylen) in enumerate(transforms):
            attrs = struct.pack("!HH", 0x800E, keylen) if keylen else b""
            more = 3 if index + 1 < len(transforms) else 0
            tbytes += struct.pack("!BBHBBH", more, 0, 8 + len(attrs), ttype, 0, tid) + attrs
        last = 2 if pindex + 1 < len(proposals) else 0
        out += struct.pack("!BBHBBBB", last, 0, 8 + len(tbytes), pindex + 1, 1, 0, len(transforms)) + tbytes
    return out


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

    ike(SPOKE_WAN, HUB_WAN, ike_sa_init_request(ispi, "a", SPOKE_WAN, HUB_WAN), t)
    ike(HUB_WAN, SPOKE_WAN, ike_sa_init_response(ispi, rspi, "a", HUB_WAN, SPOKE_WAN), t + 0.010)
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
        cap.add(t, eth_ip(SPOKE_WAN, HUB_WAN) / UDP(sport=500, dport=500) / Raw(ike_sa_init_request(ispi, f"np{attempt}", SPOKE_WAN, HUB_WAN)))
        reply = ike_message(ispi, bytes(8), IKE_SA_INIT, FLAG_RESPONSE, 0, [(41, notify_body(14))])
        cap.add(t + 0.008, eth_ip(HUB_WAN, SPOKE_WAN, mac_src=MAC_B, mac_dst=MAC_A) / UDP(sport=500, dport=500) / Raw(reply))
    return cap


def build_ikev2_no_response():
    cap = Capture()
    ispi = bytes.fromhex("4444444444444444")
    request = ike_sa_init_request(ispi, "nr", SPOKE_WAN, HUB_WAN)
    for index, offset in enumerate([0.0, 2.0, 6.0, 14.0]):
        cap.add(offset, eth_ip(SPOKE_WAN, HUB_WAN) / UDP(sport=500, dport=500) / Raw(request))
    return cap


def build_ipsec_natt():
    cap = Capture()
    nat_outside = "203.0.113.50"  # the spoke's address after NAT
    ispi = bytes.fromhex("5555555555555555")
    rspi = bytes.fromhex("6666666666666666")
    marker = b"\x00\x00\x00\x00"
    cap.add(0.0, eth_ip(nat_outside, HUB_WAN) / UDP(sport=500, dport=500) / Raw(ike_sa_init_request(ispi, "n", nat_outside, HUB_WAN, seen_src="10.0.0.50")))
    cap.add(0.010, eth_ip(HUB_WAN, nat_outside, mac_src=MAC_B, mac_dst=MAC_A) / UDP(sport=500, dport=500) / Raw(ike_sa_init_response(ispi, rspi, "n", HUB_WAN, nat_outside)))
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


# ---------------------------------------------------------------------------
# Control plane, crypto and convergence fixtures (all synthetic)
# ---------------------------------------------------------------------------

AES_GCM_16, AES_CBC, DES3 = 20, 12, 3
PRF_SHA1, PRF_SHA512 = 2, 7
INTEG_SHA1_96 = 2
GROUP2, GROUP19, GROUP20 = 2, 19, 20
STRONG = [(1, AES_GCM_16, 256), (2, PRF_SHA512, None), (4, GROUP19, None), (4, GROUP20, None)]
LEGACY = [(1, AES_CBC, 128), (2, PRF_SHA1, None), (3, INTEG_SHA1_96, None), (4, GROUP2, None)]
WEAK = [(1, DES3, None), (2, PRF_SHA1, None), (3, INTEG_SHA1_96, None), (4, GROUP2, None)]


def ike_udp(cap, t, src, dst, payload, port=500, mac_src=MAC_A, mac_dst=MAC_B):
    """One IKE message on UDP 500, or on 4500 with the non-ESP marker."""
    data = (b"\x00\x00\x00\x00" + payload) if port == 4500 else payload
    cap.add(t, eth_ip(src, dst, mac_src=mac_src, mac_dst=mac_dst) / UDP(sport=port, dport=port) / Raw(data))


def esp_burst(cap, src, dst, spi, start, count, interval, label, first_seq=1, udp=False):
    """count ESP packets src -> dst every interval seconds; returns the next sequence number."""
    seq = first_seq
    for index in range(count):
        payload = esp_packet(spi, seq, label)
        pkt = eth_ip(src, dst, proto=None if udp else 50)
        pkt = pkt / UDP(sport=4500, dport=4500) / Raw(payload) if udp else pkt / Raw(payload)
        cap.add(round(start + index * interval, 6), pkt)
        seq += 1
    return seq


def ike_empty_informational(ispi, rspi, flags, msgid, label):
    """An encrypted INFORMATIONAL with nothing inside SK (57 bytes): what IKEv2 DPD sends."""
    return ike_encrypted(ispi, rspi, INFORMATIONAL, flags, msgid, 0, 25, label)


def build_ikev2_negotiation():
    """SA 1: two proposals offered, INVALID_KE_PAYLOAD retry, AES-GCM chosen, DPD answered.
    SA 2: a weak proposal chosen, then DPD unanswered (peer stops answering)."""
    cap = Capture()
    s1, s2 = "198.51.100.2", "203.0.113.3"
    ispi, rspi = bytes.fromhex("a1a1a1a1a1a1a1a1"), bytes.fromhex("b1b1b1b1b1b1b1b1")
    offer = ikev2_proposals([STRONG, LEGACY])
    ike_udp(cap, 0.000, s1, HUB_WAN, ike_sa_init_request(ispi, "neg1", s1, HUB_WAN, sa_body=offer, ke_group=GROUP20))
    refusal = ike_message(ispi, bytes(8), IKE_SA_INIT, FLAG_RESPONSE, 0, [(41, notify_body(17, struct.pack("!H", GROUP19)))])
    ike_udp(cap, 0.008, HUB_WAN, s1, refusal, mac_src=MAC_B, mac_dst=MAC_A)
    ike_udp(cap, 0.020, s1, HUB_WAN, ike_sa_init_request(ispi, "neg1b", s1, HUB_WAN, sa_body=offer, ke_group=GROUP19))
    chosen = ikev2_proposals([[(1, AES_GCM_16, 256), (2, PRF_SHA512, None), (4, GROUP19, None)]])
    ike_udp(cap, 0.030, HUB_WAN, s1, ike_sa_init_response(ispi, rspi, "neg1", HUB_WAN, s1, sa_body=chosen,
                                                          ke_group=GROUP19), mac_src=MAC_B, mac_dst=MAC_A)
    ike_udp(cap, 0.040, s1, HUB_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "neg1-ai"))
    ike_udp(cap, 0.050, HUB_WAN, s1, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_RESPONSE, 1, 36, 272, "neg1-ar"),
            mac_src=MAC_B, mac_dst=MAC_A)
    esp_burst(cap, s1, HUB_WAN, 0xE1000001, 1.0, 10, 1.0, "neg1-o")
    esp_burst(cap, HUB_WAN, s1, 0xE1000002, 1.004, 10, 1.0, "neg1-i")
    # DPD every 10 s from the spoke, each answered; a DELETE-sized INFORMATIONAL is not a liveness check.
    for index, t in enumerate([5.0, 15.0, 25.0]):
        ike_udp(cap, t, s1, HUB_WAN, ike_empty_informational(ispi, rspi, FLAG_INITIATOR, 2 + index, f"dpd1-{index}"))
        ike_udp(cap, t + 0.004, HUB_WAN, s1, ike_empty_informational(ispi, rspi, FLAG_RESPONSE, 2 + index,
                                                                      f"dpd1r-{index}"), mac_src=MAC_B, mac_dst=MAC_A)
    ike_udp(cap, 26.0, s1, HUB_WAN, ike_encrypted(ispi, rspi, INFORMATIONAL, FLAG_INITIATOR, 5, 42, 37, "del1"))
    ike_udp(cap, 26.004, HUB_WAN, s1, ike_empty_informational(ispi, rspi, FLAG_RESPONSE, 5, "del1r"),
            mac_src=MAC_B, mac_dst=MAC_A)

    ispi2, rspi2 = bytes.fromhex("a2a2a2a2a2a2a2a2"), bytes.fromhex("b2b2b2b2b2b2b2b2")
    weak = ikev2_proposals([WEAK])
    ike_udp(cap, 2.000, s2, HUB_WAN, ike_sa_init_request(ispi2, "neg2", s2, HUB_WAN, sa_body=weak, ke_group=GROUP2),
            mac_src=MAC_C)
    ike_udp(cap, 2.010, HUB_WAN, s2, ike_sa_init_response(ispi2, rspi2, "neg2", HUB_WAN, s2, sa_body=weak,
                                                          ke_group=GROUP2), mac_src=MAC_B, mac_dst=MAC_C)
    ike_udp(cap, 2.020, s2, HUB_WAN, ike_encrypted(ispi2, rspi2, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "neg2-ai"),
            mac_src=MAC_C)
    ike_udp(cap, 2.030, HUB_WAN, s2, ike_encrypted(ispi2, rspi2, IKE_AUTH, FLAG_RESPONSE, 1, 36, 272, "neg2-ar"),
            mac_src=MAC_B, mac_dst=MAC_C)
    esp_burst(cap, s2, HUB_WAN, 0xE2000001, 3.0, 5, 1.0, "neg2-o")
    esp_burst(cap, HUB_WAN, s2, 0xE2000002, 3.004, 5, 1.0, "neg2-i")
    # From t=30 the hub stops answering: one check, three retransmissions, no reply.
    for t in [30.0, 32.0, 34.0, 36.0]:
        ike_udp(cap, t, s2, HUB_WAN, ike_empty_informational(ispi2, rspi2, FLAG_INITIATOR, 2, "dpd2"), mac_src=MAC_C)
    cap.add(40.0, eth_ip(s1, HUB_WAN, proto=50) / Raw(esp_packet(0xE1000001, 11, "neg1-o")))
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_ikev2_failures():
    """Four failed IKEv2 SAs: NAT-T missing, PSK-style auth failure, IKE_AUTH unanswered, DH group refused."""
    cap = Capture()
    nat_peer, auth_peer, silent_peer, dh_peer = "198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"
    # NAT detected (the spoke believes it is 10.0.0.7), yet IKE_AUTH stays on UDP 500 and is never answered.
    ispi, rspi = bytes.fromhex("c1c1c1c1c1c1c1c1"), bytes.fromhex("d1d1d1d1d1d1d1d1")
    ike_udp(cap, 0.0, nat_peer, HUB_WAN, ike_sa_init_request(ispi, "f1", nat_peer, HUB_WAN, seen_src="10.0.0.7"))
    ike_udp(cap, 0.01, HUB_WAN, nat_peer, ike_sa_init_response(ispi, rspi, "f1", HUB_WAN, nat_peer),
            mac_src=MAC_B, mac_dst=MAC_A)
    for t in [0.02, 1.02, 3.02]:
        ike_udp(cap, t, nat_peer, HUB_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "f1-ai"))
    # Auth failure: a small encrypted IKE_AUTH response (one AUTHENTICATION_FAILED notify) and no ESP.
    ispi, rspi = bytes.fromhex("c2c2c2c2c2c2c2c2"), bytes.fromhex("d2d2d2d2d2d2d2d2")
    ike_udp(cap, 5.0, auth_peer, HUB_WAN, ike_sa_init_request(ispi, "f2", auth_peer, HUB_WAN))
    ike_udp(cap, 5.01, HUB_WAN, auth_peer, ike_sa_init_response(ispi, rspi, "f2", HUB_WAN, auth_peer),
            mac_src=MAC_B, mac_dst=MAC_A)
    ike_udp(cap, 5.02, auth_peer, HUB_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "f2-ai"))
    ike_udp(cap, 5.03, HUB_WAN, auth_peer, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_RESPONSE, 1, 41, 48, "f2-ar"),
            mac_src=MAC_B, mac_dst=MAC_A)
    # IKE_AUTH retransmitted with no reply and no NAT (a peer that silently drops a bad PSK).
    ispi, rspi = bytes.fromhex("c3c3c3c3c3c3c3c3"), bytes.fromhex("d3d3d3d3d3d3d3d3")
    ike_udp(cap, 8.0, silent_peer, HUB_WAN, ike_sa_init_request(ispi, "f3", silent_peer, HUB_WAN))
    ike_udp(cap, 8.01, HUB_WAN, silent_peer, ike_sa_init_response(ispi, rspi, "f3", HUB_WAN, silent_peer),
            mac_src=MAC_B, mac_dst=MAC_A)
    for t in [8.02, 9.02, 11.02]:
        ike_udp(cap, t, silent_peer, HUB_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "f3-ai"))
    # DH group refused (INVALID_KE_PAYLOAD asks for 19) and the initiator never retries.
    ispi = bytes.fromhex("c4c4c4c4c4c4c4c4")
    ike_udp(cap, 14.0, dh_peer, HUB_WAN, ike_sa_init_request(ispi, "f4", dh_peer, HUB_WAN, ke_group=14))
    refusal = ike_message(ispi, bytes(8), IKE_SA_INIT, FLAG_RESPONSE, 0, [(41, notify_body(17, struct.pack("!H", GROUP19)))])
    ike_udp(cap, 14.01, HUB_WAN, dh_peer, refusal, mac_src=MAC_B, mac_dst=MAC_A)
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_esp_stale_spi():
    """A rekey moves 198.51.100.2 -> hub to a new SPI; the old SPI comes back 6 s later, and the hub,
    which lost the IKE SA, answers a DPD with an unprotected INVALID_IKE_SPI."""
    cap = Capture()
    ispi, rspi = bytes.fromhex("e5e5e5e5e5e5e5e5"), bytes.fromhex("f5f5f5f5f5f5f5f5")
    ike_udp(cap, 0.0, SPOKE_WAN, HUB_WAN, ike_sa_init_request(ispi, "st", SPOKE_WAN, HUB_WAN))
    ike_udp(cap, 0.01, HUB_WAN, SPOKE_WAN, ike_sa_init_response(ispi, rspi, "st", HUB_WAN, SPOKE_WAN),
            mac_src=MAC_B, mac_dst=MAC_A)
    ike_udp(cap, 0.02, SPOKE_WAN, HUB_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "st-ai"))
    ike_udp(cap, 0.03, HUB_WAN, SPOKE_WAN, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_RESPONSE, 1, 36, 272, "st-ar"),
            mac_src=MAC_B, mac_dst=MAC_A)
    seq = esp_burst(cap, SPOKE_WAN, HUB_WAN, 0xAA000001, 1.0, 4, 0.5, "old-o")
    esp_burst(cap, HUB_WAN, SPOKE_WAN, 0xAA000002, 1.002, 4, 0.5, "old-i")
    ike_udp(cap, 3.0, SPOKE_WAN, HUB_WAN, ike_encrypted(ispi, rspi, CREATE_CHILD_SA, FLAG_INITIATOR, 2, 33, 240, "st-rk"))
    ike_udp(cap, 3.01, HUB_WAN, SPOKE_WAN, ike_encrypted(ispi, rspi, CREATE_CHILD_SA, FLAG_RESPONSE, 2, 33, 224, "st-rr"),
            mac_src=MAC_B, mac_dst=MAC_A)
    esp_burst(cap, SPOKE_WAN, HUB_WAN, 0xBB000001, 3.5, 12, 0.5, "new-o")
    esp_burst(cap, HUB_WAN, SPOKE_WAN, 0xBB000002, 3.502, 12, 0.5, "new-i")
    # The spoke sends on the old outbound SPI again, long after the new one took over.
    esp_burst(cap, SPOKE_WAN, HUB_WAN, 0xAA000001, 9.6, 2, 0.5, "old-o", first_seq=seq)
    # The hub lost its IKE SA: an INFORMATIONAL request is answered with an unprotected INVALID_IKE_SPI.
    ike_udp(cap, 10.0, SPOKE_WAN, HUB_WAN, ike_empty_informational(ispi, rspi, FLAG_INITIATOR, 3, "st-dpd"))
    invalid = ike_message(ispi, rspi, INFORMATIONAL, FLAG_RESPONSE, 3, [(41, notify_body(4))])
    ike_udp(cap, 10.01, HUB_WAN, SPOKE_WAN, invalid, mac_src=MAC_B, mac_dst=MAC_A)
    cap.packets.sort(key=lambda p: p.time)
    return cap


def cdp_frame():
    """802.3 + LLC + SNAP (Cisco OUI, PID 0x2000) carrying a minimal CDPv2 frame."""
    from scapy.all import LLC, SNAP, Dot3
    tlv = struct.pack("!HH", 0x0001, 4 + 4) + b"BR1\x00"
    body = bytes([2, 180]) + struct.pack("!H", 0) + tlv
    pkt = Dot3(src=MAC_A, dst="01:00:0c:cc:cc:cc") / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0x00000C, code=0x2000) / Raw(body)
    return pkt


def build_audit_one_leak():
    """An encrypted transport link with exactly one of each leak: GRE carrying BGP, ICMP to the
    provider, ARP, a Cisco loopback keepalive and a CDP frame."""
    cap = Capture()
    ispi, rspi = bytes.fromhex("1212121212121212"), bytes.fromhex("3434343434343434")
    ike_udp(cap, 0.0, SPOKE_WAN, HUB_WAN, ike_sa_init_request(ispi, "au", SPOKE_WAN, HUB_WAN))
    ike_udp(cap, 0.01, HUB_WAN, SPOKE_WAN, ike_sa_init_response(ispi, rspi, "au", HUB_WAN, SPOKE_WAN),
            mac_src=MAC_B, mac_dst=MAC_A)
    esp_burst(cap, SPOKE_WAN, HUB_WAN, 0xCC000001, 1.0, 10, 0.5, "au-o")
    esp_burst(cap, HUB_WAN, SPOKE_WAN, 0xCC000002, 1.002, 10, 0.5, "au-i")
    leaked = bytes(IP(src=SPOKE2_TUN, dst=HUB_TUN, ttl=1) / TCP(sport=40100, dport=179, flags="PA", seq=1, ack=1)
                   / Raw(bgp_keepalive()))
    cap.add(2.25, eth_ip(SPOKE_WAN, HUB_WAN, proto=47) / Raw(gre(0x0800, leaked)))
    cap.add(3.25, eth_ip(SPOKE_WAN, "203.0.113.1", ttl=64) / ICMP(type=8, id=7, seq=1) / Raw(b"provider"))
    cap.add(3.5, Ether(src=MAC_A, dst=MAC_BCAST) / ARP(op=1, hwsrc=MAC_A, psrc=SPOKE_WAN, pdst="198.51.100.1"))
    cap.add(4.0, Ether(src=MAC_A, dst=MAC_A, type=0x9000) / Raw(b"\x00\x00\x01\x00" + bytes(40)))
    cap.add(4.5, cdp_frame())
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_nhrp_phase3_broken():
    """Phase 3 failures in cleartext GRE: an unanswered (thrashing) resolution, a hub that relays
    without redirecting, a spoke that ignores the redirect, and a resolution with no direct data."""
    cap = Capture()
    spoke4_wan, spoke4_tun = SPOKE4_WAN, SPOKE4_TUN

    def send(src, dst, payload, offset, mac_src=MAC_A, mac_dst=MAC_B):
        cap.add(offset, eth_ip(src, dst, proto=47, mac_src=mac_src, mac_dst=mac_dst) / Raw(payload))

    reg = 0x05000000
    for index, (wan, tun) in enumerate([(SPOKE_WAN, SPOKE2_TUN), (SPOKE3_WAN, SPOKE3_TUN), (spoke4_wan, spoke4_tun)]):
        send(wan, HUB_WAN, gre(0x2001, nhrp_packet(3, nhrp_mandatory(0x8000, reg + index, wan, tun, HUB_TUN, nhrp_cie()))),
             0.01 * index)
        send(HUB_WAN, wan, gre(0x2001, nhrp_packet(4, nhrp_mandatory(0x8000, reg + index, wan, tun, HUB_TUN,
                                                                     nhrp_cie(code=0)))), 0.01 * index + 0.005)

    def data(t, src, dst, outer_src, outer_dst, seq):
        inner = bytes(IP(src=src, dst=dst, ttl=63) / ICMP(type=8, id=21, seq=seq) / Raw(b"phase3"))
        send(outer_src, outer_dst, gre(0x0800, inner), t)
        return inner

    def redirect(t, spoke_wan, inner):
        send(HUB_WAN, spoke_wan, gre(0x2001, nhrp_packet(8, nhrp_traffic_indication(HUB_WAN, HUB_TUN, "10.0.0.250",
                                                                                     inner[:28]))), t)

    # Flow 1: spoke 2 -> 10.1.3.1, redirected, then eight resolution requests that nobody answers.
    inner = data(1.0, "10.1.2.1", "10.1.3.1", SPOKE_WAN, HUB_WAN, 1)
    data(1.001, "10.1.2.1", "10.1.3.1", HUB_WAN, SPOKE3_WAN, 1)
    redirect(1.002, SPOKE_WAN, inner)
    for index in range(8):
        t = 1.01 + index * 0.15
        req = nhrp_packet(1, nhrp_mandatory(0x8000, 0x06000000 + index, SPOKE_WAN, SPOKE2_TUN, "10.1.3.1", nhrp_cie()))
        send(SPOKE_WAN, HUB_WAN, gre(0x2001, req), t)
        send(HUB_WAN, SPOKE3_WAN, gre(0x2001, req), t + 0.001)
    # Flow 2: spoke 4 -> 10.1.3.1 through the hub, twice, with no redirect at all.
    data(4.0, "10.1.4.1", "10.1.3.1", spoke4_wan, HUB_WAN, 1)
    data(4.001, "10.1.4.1", "10.1.3.1", HUB_WAN, SPOKE3_WAN, 1)
    data(5.0, "10.1.4.1", "10.1.3.1", spoke4_wan, HUB_WAN, 2)
    # Flow 3: spoke 3 -> 10.1.2.1 is redirected but spoke 3 never resolves.
    inner = data(6.0, "10.1.3.1", "10.1.2.1", SPOKE3_WAN, HUB_WAN, 1)
    data(6.001, "10.1.3.1", "10.1.2.1", HUB_WAN, SPOKE_WAN, 1)
    redirect(6.002, SPOKE3_WAN, inner)
    # Flow 4: spoke 4 -> 10.1.2.1 is redirected and resolved, but no data ever goes direct.
    inner = data(7.0, "10.1.4.1", "10.1.2.1", spoke4_wan, HUB_WAN, 1)
    data(7.001, "10.1.4.1", "10.1.2.1", HUB_WAN, SPOKE_WAN, 1)
    redirect(7.002, spoke4_wan, inner)
    req = nhrp_packet(1, nhrp_mandatory(0x8000, 0x07000001, spoke4_wan, spoke4_tun, "10.1.2.1", nhrp_cie()))
    send(spoke4_wan, HUB_WAN, gre(0x2001, req), 7.01)
    send(HUB_WAN, SPOKE_WAN, gre(0x2001, req), 7.011)
    reply = nhrp_packet(2, nhrp_mandatory(0x8000 | 0x4000, 0x07000001, spoke4_wan, spoke4_tun, "10.1.2.1",
                                          nhrp_cie(code=0, prefix=24, cli_nbma=SPOKE_WAN, cli_proto=SPOKE2_TUN)))
    send(SPOKE_WAN, spoke4_wan, gre(0x2001, reply), 7.02)
    data(8.0, "10.1.4.1", "10.1.2.1", spoke4_wan, HUB_WAN, 2)
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_phase3_encrypted():
    """Protected DMVPN seen on the transport: spokes keep ESP to two hubs; one spoke-to-spoke
    shortcut forms (IKE then direct ESP), another is never answered."""
    cap = Capture()
    hub1, hub2 = "192.0.2.1", "192.0.2.2"
    a, b, c = "198.51.100.2", "203.0.113.3", "198.51.100.4"
    for index, spoke in enumerate([a, b, c]):
        for hindex, hub in enumerate([hub1, hub2]):
            base = 0xD0000000 + index * 16 + hindex * 4
            esp_burst(cap, spoke, hub, base + 1, 0.1 + index * 0.01 + hindex * 0.002, 12, 1.0, f"p3e{index}{hindex}o")
            esp_burst(cap, hub, spoke, base + 2, 0.104 + index * 0.01 + hindex * 0.002, 12, 1.0, f"p3e{index}{hindex}i")
    ispi, rspi = bytes.fromhex("5a5a5a5a5a5a5a5a"), bytes.fromhex("6b6b6b6b6b6b6b6b")
    ike_udp(cap, 5.0, a, b, ike_sa_init_request(ispi, "sc", a, b))
    ike_udp(cap, 5.006, b, a, ike_sa_init_response(ispi, rspi, "sc", b, a), mac_src=MAC_C, mac_dst=MAC_A)
    ike_udp(cap, 5.012, a, b, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_INITIATOR, 1, 35, 320, "sc-ai"))
    ike_udp(cap, 5.020, b, a, ike_encrypted(ispi, rspi, IKE_AUTH, FLAG_RESPONSE, 1, 36, 272, "sc-ar"),
            mac_src=MAC_C, mac_dst=MAC_A)
    esp_burst(cap, a, b, 0xE0000001, 5.030, 6, 0.5, "sc-o")
    esp_burst(cap, b, a, 0xE0000002, 5.034, 6, 0.5, "sc-i")
    ispi2 = bytes.fromhex("7c7c7c7c7c7c7c7c")
    for t in [8.0, 9.0, 11.0]:
        ike_udp(cap, t, a, c, ike_sa_init_request(ispi2, "sc2", a, c))
    cap.packets.sort(key=lambda p: p.time)
    return cap


def bgp_open_caps(asn, hold, router_id):
    """OPEN with multiprotocol IPv4 unicast, route refresh and 4-byte AS capabilities."""
    caps = bytes([1, 4, 0, 1, 0, 1]) + bytes([2, 0]) + bytes([65, 4]) + struct.pack("!I", asn)
    opt = bytes([2, len(caps)]) + caps
    return bgp_msg(1, struct.pack("!BHH", 4, asn, hold) + ip4(router_id) + bytes([len(opt)]) + opt)


class MssConversation(TcpConversation):
    """A TcpConversation whose SYN and SYN-ACK carry an MSS option."""

    def __init__(self, *args, mss=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.mss = mss or {}

    def send(self, from_a, offset, flags, payload=b""):
        if "S" not in flags or not self.mss.get(from_a):
            return super().send(from_a, offset, flags, payload)
        src, sport, mac_src = self.ends[from_a]
        dst, dport, mac_dst = self.ends[not from_a]
        seq = self.next_seq[from_a]
        ack = self.next_seq[not from_a] if "A" in flags else 0
        segment = IP(src=src, dst=dst, ttl=255) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
                                                      window=16384, options=[("MSS", self.mss[from_a])])
        self.cap.add(offset, Ether(src=mac_src, dst=mac_dst) / segment)
        self.next_seq[from_a] = seq + 1


def build_bgp_failover():
    """Spoke 10.255.0.11 with BGP to two hubs over the overlay (seen in cleartext, inside the tunnel):
    hub 1 goes silent at t=40 and the spoke's hold timer expires at t=70; hub 2 then sends the UPDATE
    that moves traffic; a ping across the overlay shows the outage. Plus a session closed by RST and
    one whose hold expiry is only inferred (RST after the peer went quiet)."""
    cap = Capture()
    spoke, hub1, hub2, r3, r4 = "10.255.0.11", "10.255.0.1", "10.255.0.2", "10.255.0.3", "10.255.0.4"

    def bring_up(conv, t, local_id, remote_id):
        conv.send(True, t, "S")
        conv.send(False, t + 0.001, "SA")
        conv.send(True, t + 0.002, "A")
        conv.send(True, t + 0.010, "PA", bgp_open_caps(65100, 30, local_id))
        conv.send(False, t + 0.012, "PA", bgp_open_caps(65100, 30, remote_id))
        conv.send(True, t + 0.020, "PA", bgp_keepalive())
        conv.send(False, t + 0.022, "PA", bgp_keepalive())

    c1 = MssConversation(cap, spoke, 40011, hub1, 179, 1000, 5000, mss={True: 1360, False: 1360})
    bring_up(c1, 0.0, "10.1.11.1", "10.0.0.1")
    c1.send(False, 0.1, "PA", bgp_update(["10.1.1.0/24", "10.1.2.0/24"], hub1))
    for t in [10.0, 20.0, 30.0, 40.0]:
        c1.send(True, t, "PA", bgp_keepalive())
        c1.send(False, t + 0.002, "PA", bgp_keepalive())
    for t in [50.0, 60.0]:
        c1.send(True, t, "PA", bgp_keepalive())
    c1.send(True, 70.0, "PA", bgp_notification(4, 0))
    c1.send(True, 70.001, "FA")

    c2 = MssConversation(cap, spoke, 40012, hub2, 179, 2000, 6000, mss={True: 1460, False: 1460})
    bring_up(c2, 0.5, "10.1.11.1", "10.0.0.2")
    for t in [10.5, 20.5, 30.5, 40.5, 50.5, 60.5, 70.4, 80.5]:
        c2.send(True, t, "PA", bgp_keepalive())
        c2.send(False, t + 0.002, "PA", bgp_keepalive())
        if t == 70.4:
            # Sequence numbers follow call order, so the UPDATE is sent in time order.
            c2.send(False, 70.5, "PA", bgp_update(["10.1.1.0/24", "10.1.2.0/24"], hub2))

    c3 = TcpConversation(cap, spoke, 40013, r3, 179, 3000, 7000)
    bring_up(c3, 1.0, "10.1.11.1", "10.0.0.3")
    c3.send(True, 11.0, "PA", bgp_keepalive())
    c3.send(False, 11.002, "PA", bgp_keepalive())
    c3.send(False, 15.0, "RA")

    c4 = TcpConversation(cap, spoke, 40014, r4, 179, 4000, 8000)
    bring_up(c4, 1.5, "10.1.11.1", "10.0.0.4")
    for t in [11.5, 21.5]:
        c4.send(True, t, "PA", bgp_keepalive())
    c4.send(True, 33.0, "RA")

    # A ping across the overlay, one per second; replies stop while traffic follows the dead hub.
    for index in range(31, 81):
        t = float(index)
        cap.add(t, eth_ip("10.1.11.1", "10.1.1.1", ttl=64) / ICMP(type=8, id=0x4242, seq=index) / Raw(b"overlay"))
        if not 41 <= index <= 70:
            cap.add(t + 0.020, eth_ip("10.1.1.1", "10.1.11.1", ttl=62, mac_src=MAC_B, mac_dst=MAC_A)
                    / ICMP(type=0, id=0x4242, seq=index) / Raw(b"overlay"))
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_convergence_dpd():
    """Transport capture at spoke 198.51.100.2 with tunnels to two hubs. Hub 1 dies at t=30: its ESP
    stops, the spoke's DPD to it goes unanswered (t=35, retries to 41), the spoke's ESP to hub 1 stops
    after DPD gives up, and the traffic moves to hub 2 at t=41.6."""
    cap = Capture()
    spoke, hub1, hub2 = "198.51.100.2", "192.0.2.1", "192.0.2.2"
    ispi1, rspi1 = bytes.fromhex("9191919191919191"), bytes.fromhex("9292929292929292")
    ispi2, rspi2 = bytes.fromhex("9393939393939393"), bytes.fromhex("9494949494949494")
    esp_burst(cap, spoke, hub1, 0xF1000001, 0.0, 412, 0.1, "cv-o1")        # until about 41.1
    esp_burst(cap, hub1, spoke, 0xF1000002, 0.05, 300, 0.1, "cv-i1")       # until 29.95
    esp_burst(cap, spoke, hub2, 0xF2000001, 0.5, 41, 1.0, "cv-o2")         # 1 pps keepalive level
    esp_burst(cap, hub2, spoke, 0xF2000002, 0.55, 41, 1.0, "cv-i2")
    esp_burst(cap, spoke, hub2, 0xF2000001, 41.6, 184, 0.1, "cv-o2b", first_seq=42)   # the shift
    esp_burst(cap, hub2, spoke, 0xF2000002, 41.65, 184, 0.1, "cv-i2b", first_seq=42)
    for index, t in enumerate([5.0, 15.0, 25.0]):
        for ispi, rspi, hub, label in ((ispi1, rspi1, hub1, "h1"), (ispi2, rspi2, hub2, "h2")):
            ike_udp(cap, t + (0.3 if hub == hub2 else 0.0), spoke, hub,
                    ike_empty_informational(ispi, rspi, FLAG_INITIATOR, 10 + index, f"cv-{label}-{index}"))
            ike_udp(cap, t + (0.3 if hub == hub2 else 0.0) + 0.004, hub, spoke,
                    ike_empty_informational(ispi, rspi, FLAG_RESPONSE, 10 + index, f"cv-{label}r-{index}"),
                    mac_src=MAC_B, mac_dst=MAC_A)
    for t in [35.0, 37.0, 39.0, 41.0]:
        ike_udp(cap, t, spoke, hub1, ike_empty_informational(ispi1, rspi1, FLAG_INITIATOR, 13, "cv-h1-dead"))
    for index, t in enumerate([35.3, 45.3, 55.3]):
        ike_udp(cap, t, spoke, hub2, ike_empty_informational(ispi2, rspi2, FLAG_INITIATOR, 13 + index, f"cv-h2b-{index}"))
        ike_udp(cap, t + 0.004, hub2, spoke, ike_empty_informational(ispi2, rspi2, FLAG_RESPONSE, 13 + index,
                                                                      f"cv-h2br-{index}"), mac_src=MAC_B, mac_dst=MAC_A)
    cap.packets.sort(key=lambda p: p.time)
    return cap


def build_ospf_stuck():
    """Two OSPF links stuck in the database exchange: 10.0.45.0/24 in EXSTART with an MTU mismatch
    (1500 vs 1400), 10.0.67.0/24 in EXCHANGE with equal MTUs and a DBD never acknowledged."""
    cap = Capture()
    mcast = "224.0.0.5"

    def hello(src, rid, mac, t, neighbors):
        cap.add(t, eth_ip(src, mcast, proto=89, ttl=1, mac_src=mac, mac_dst="01:00:5e:00:00:05")
                / Raw(ospf_hello(rid, "0.0.0.0", "255.255.255.0", 10, 40, neighbors=neighbors)))

    def dbd(src, dst, rid, mac_src, mac_dst, t, mtu, flags, seq):
        cap.add(t, eth_ip(src, dst, proto=89, ttl=1, mac_src=mac_src, mac_dst=mac_dst)
                / Raw(ospf_dbd(rid, "0.0.0.0", mtu, flags, seq)))

    r1, r2, r3, r4 = "10.0.45.1", "10.0.45.2", "10.0.67.1", "10.0.67.2"
    for index in range(4):
        t = index * 10.0
        hello(r1, "4.4.4.4", MAC_A, t, ["5.5.5.5"] if index else [])
        hello(r2, "5.5.5.5", MAC_B, t + 0.2, ["4.4.4.4"])
        hello(r3, "6.6.6.6", MAC_A, t + 0.4, ["7.7.7.7"] if index else [])
        hello(r4, "7.7.7.7", MAC_C, t + 0.6, ["6.6.6.6"])
    for index in range(5):
        t = 1.0 + index * 5.0
        dbd(r1, r2, "4.4.4.4", MAC_A, MAC_B, t, 1500, 0x07, 1000)
        dbd(r2, r1, "5.5.5.5", MAC_B, MAC_A, t + 0.1, 1400, 0x07, 2000)
    dbd(r3, r4, "6.6.6.6", MAC_A, MAC_C, 1.0, 1500, 0x07, 5000)
    dbd(r4, r3, "7.7.7.7", MAC_C, MAC_A, 1.05, 1500, 0x07, 7000)
    dbd(r3, r4, "6.6.6.6", MAC_A, MAC_C, 1.1, 1500, 0x02, 7000)
    for index in range(4):
        dbd(r4, r3, "7.7.7.7", MAC_C, MAC_A, 1.2 + index * 5.0, 1500, 0x03, 7001)
    cap.packets.sort(key=lambda p: p.time)
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
    "ikev2_negotiation.pcap": build_ikev2_negotiation,
    "ikev2_failures.pcap": build_ikev2_failures,
    "esp_stale_spi.pcap": build_esp_stale_spi,
    "audit_one_leak.pcap": build_audit_one_leak,
    "nhrp_phase3_broken.pcap": build_nhrp_phase3_broken,
    "phase3_encrypted.pcap": build_phase3_encrypted,
    "bgp_failover.pcap": build_bgp_failover,
    "convergence_dpd.pcap": build_convergence_dpd,
    "ospf_stuck.pcap": build_ospf_stuck,
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
