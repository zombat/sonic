#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. IPsec ESP Test Fixtures (synthetic)

Generates the small, deterministic pcaps the ESP-decryption tests read, built with scapy's
IPsec support (scapy.layers.ipsec.SecurityAssociation) at fixed addresses (RFC 5737 and
RFC 1918 inner), fixed SPIs, fixed timestamps and fixed throwaway keys, so two runs produce
identical files. Names start with esp_. Every key is a synthetic placeholder, defined here.

    esp_tunnel.pcap   a tunnel 198.51.100.1 <-> 198.51.100.2 carrying, inside ESP:
                      SA 0x00001001 (AES-CBC + HMAC-SHA1-96): inner ICMP echo and a TCP SYN
                        from 192.168.50.1 to 192.168.50.2;
                      SA 0x00001002 (AES-GCM, reverse direction): the ICMP reply and TCP SYN-ACK;
                      SA 0x00002001 (AES-CBC + HMAC-SHA256-128): a second inner ICMP echo;
                      SA 0x00003001 (AES-CBC + HMAC-SHA256-128, transport mode): a TCP SYN host to host;
                      SA 0x00004001 (AES-GCM, NAT-T: ESP in UDP 4500): an inner ICMP echo.

The matching SA keys are written by the test into an SA file (S.O.N.I.C.'s format) and into an
`ip xfrm state` style dump; the keys are synthetic placeholders and the tests assert no key
appears in the report.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate_dataplane_fixtures import Capture  # noqa: E402
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw  # noqa: E402
from scapy.layers.ipsec import ESP, SecurityAssociation  # noqa: E402

OUTER_A, OUTER_B = "198.51.100.1", "198.51.100.2"
INNER_A, INNER_B = "192.168.50.1", "192.168.50.2"
MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"

# Throwaway keys (synthetic placeholders, never real).
KEY_AES128 = bytes(range(16))
KEY_SHA1 = bytes(range(20))
KEY_SHA256 = bytes(range(32))
KEY_GCM = bytes(range(16)) + bytes([0xDE, 0xAD, 0xBE, 0xEF])  # 16-byte key + 4-byte salt

SPI_CBC_SHA1 = 0x00001001
SPI_GCM = 0x00001002
SPI_CBC_SHA256 = 0x00002001
SPI_TRANSPORT = 0x00003001
SPI_NATT = 0x00004001

SA_HEX = {
    "cbc_sha1": {"enc": KEY_AES128.hex(), "auth": KEY_SHA1.hex()},
    "gcm": {"enc": KEY_GCM.hex(), "auth": ""},
    "cbc_sha256": {"enc": KEY_AES128.hex(), "auth": KEY_SHA256.hex()},
}


def _sa(spi, src, dst, crypt_algo, crypt_key, auth_algo, auth_key, tunnel=True, nat_t=False):
    kwargs = {"spi": spi, "crypt_algo": crypt_algo, "crypt_key": crypt_key}
    if tunnel:
        kwargs["tunnel_header"] = IP(src=src, dst=dst)
    if nat_t:
        kwargs["nat_t_header"] = UDP(sport=4500, dport=4500)
    if auth_algo:
        kwargs["auth_algo"] = auth_algo
        kwargs["auth_key"] = auth_key
    return SecurityAssociation(ESP, **kwargs)


def build_tunnel():
    cap = Capture()
    sa_fwd = _sa(SPI_CBC_SHA1, OUTER_A, OUTER_B, "AES-CBC", KEY_AES128, "HMAC-SHA1-96", KEY_SHA1)
    sa_rev = _sa(SPI_GCM, OUTER_B, OUTER_A, "AES-GCM", KEY_GCM, "NULL", None)
    sa_fwd2 = _sa(SPI_CBC_SHA256, OUTER_A, OUTER_B, "AES-CBC", KEY_AES128, "SHA2-256-128", KEY_SHA256)
    sa_transport = _sa(SPI_TRANSPORT, OUTER_A, OUTER_B, "AES-CBC", KEY_AES128, "SHA2-256-128", KEY_SHA256,
                       tunnel=False)
    sa_natt = _sa(SPI_NATT, OUTER_A, OUTER_B, "AES-GCM", KEY_GCM, "NULL", None, nat_t=True)

    counter = {"n": 0}

    def add(t, sa, inner, mac_from_a=True):
        # A fixed IV per packet (scapy would pick a random one), so two runs produce identical files.
        counter["n"] += 1
        iv = bytes([counter["n"]]) * sa.crypt_algo.iv_size
        pkt = sa.encrypt(inner, iv=iv)
        src = MAC_A if mac_from_a else MAC_B
        dst = MAC_B if mac_from_a else MAC_A
        frame = Ether(src=src, dst=dst) / pkt
        cap.add(t, frame)

    icmp_req = IP(src=INNER_A, dst=INNER_B) / ICMP(type=8, id=1, seq=1) / Raw(b"esp-inner-ping-payload")
    icmp_rep = IP(src=INNER_B, dst=INNER_A) / ICMP(type=0, id=1, seq=1) / Raw(b"esp-inner-ping-payload")
    syn = IP(src=INNER_A, dst=INNER_B) / TCP(sport=44000, dport=80, flags="S", seq=1000)
    synack = IP(src=INNER_B, dst=INNER_A) / TCP(sport=80, dport=44000, flags="SA", seq=5000, ack=1001)
    icmp_req2 = IP(src=INNER_A, dst=INNER_B) / ICMP(type=8, id=2, seq=1) / Raw(b"second-esp-inner-ping")

    add(0.00, sa_fwd, icmp_req, True)
    add(0.02, sa_rev, icmp_rep, False)
    add(0.10, sa_fwd, syn, True)
    add(0.12, sa_rev, synack, False)
    add(0.20, sa_fwd2, icmp_req2, True)
    # transport mode, host to host: the TCP segment itself is the ESP payload
    add(0.30, sa_transport, IP(src=OUTER_A, dst=OUTER_B) / TCP(sport=45000, dport=22, flags="S", seq=9000), True)
    # NAT-T: ESP in UDP 4500, tunnel mode
    add(0.40, sa_natt, IP(src=INNER_A, dst=INNER_B) / ICMP(type=8, id=3, seq=1) / Raw(b"nat-t-inner-ping"), True)
    return cap


def sa_file_text():
    """S.O.N.I.C.'s SA-file text that decrypts esp_tunnel.pcap (synthetic keys)."""
    return "\n\n".join([
        f"src: {OUTER_A}\ndst: {OUTER_B}\nspi: {SPI_CBC_SHA1:#010x}\nencryption: aes-cbc\n"
        f"encryption_key: 0x{SA_HEX['cbc_sha1']['enc']}\nintegrity: hmac-sha1-96\n"
        f"integrity_key: 0x{SA_HEX['cbc_sha1']['auth']}",
        f"src: {OUTER_B}\ndst: {OUTER_A}\nspi: {SPI_GCM:#010x}\nencryption: aes-gcm\n"
        f"encryption_key: 0x{SA_HEX['gcm']['enc']}",
        f"src: {OUTER_A}\ndst: {OUTER_B}\nspi: {SPI_CBC_SHA256:#010x}\nencryption: aes-cbc\n"
        f"encryption_key: 0x{SA_HEX['cbc_sha256']['enc']}\nintegrity: hmac-sha256-128\n"
        f"integrity_key: 0x{SA_HEX['cbc_sha256']['auth']}",
        f"src: {OUTER_A}\ndst: {OUTER_B}\nspi: {SPI_TRANSPORT:#010x}\nencryption: aes-cbc\n"
        f"encryption_key: 0x{SA_HEX['cbc_sha256']['enc']}\nintegrity: hmac-sha256-128\n"
        f"integrity_key: 0x{SA_HEX['cbc_sha256']['auth']}",
        f"src: {OUTER_A}\ndst: {OUTER_B}\nspi: {SPI_NATT:#010x}\nencryption: aes-gcm\n"
        f"encryption_key: 0x{SA_HEX['gcm']['enc']}",
    ]) + "\n"


def xfrm_state_text():
    """
    An `ip -s xfrm state` style dump (synthetic keys) for two SAs: the forward AES-CBC+SHA1 one
    (enc + auth-trunc) and the reverse AES-GCM one (aead rfc4106, key followed by its 4-byte salt),
    with the anti-replay, lifetime and stats lines `-s` adds.
    """
    return (f"src {OUTER_A} dst {OUTER_B}\n"
            f"\tproto esp spi {SPI_CBC_SHA1:#010x} reqid 1 mode tunnel\n"
            f"\treplay-window 32 flag af-unspec\n"
            f"\tenc cbc(aes) 0x{SA_HEX['cbc_sha1']['enc']}\n"
            f"\tauth-trunc hmac(sha1) 0x{SA_HEX['cbc_sha1']['auth']} 96\n"
            f"\tanti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000\n"
            f"src {OUTER_B} dst {OUTER_A}\n"
            f"\tproto esp spi {SPI_GCM:#010x} reqid 2 mode tunnel\n"
            f"\treplay-window 32 flag af-unspec\n"
            f"\taead rfc4106(gcm(aes)) 0x{SA_HEX['gcm']['enc']} 128\n"
            f"\tlifetime config:\n\t  limit: soft (INF)(bytes), hard (INF)(bytes)\n"
            f"\tstats:\n\t  replay-window 0 replay 0 failed 0\n")


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else HERE
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "esp_tunnel.pcap")
    build_tunnel().write(path)
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
