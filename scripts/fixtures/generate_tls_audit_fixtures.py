#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Encryption Audit Test Fixtures (synthetic)

Generates the small, deterministic pcaps that test the cleartext audit's judgement of
SSH and TLS by their handshake: sessions that look encrypted from their record headers
or packet framing but whose handshake chose no encryption, weak encryption, or is not
in the capture. Every file is synthetic: TLS records and handshake messages and SSH
binary packets are built here with struct, TCP with scapy, at fixed addresses
(10.80.0.0/16), fixed timestamps and no randomness (the "ciphertext" of the sessions
captured mid-stream is a SHA-256 chain), so two runs produce identical files. Names
start with enc_. Credentials in them are synthetic placeholders.

Usage:
    python3 tests/fixtures/generate_tls_audit_fixtures.py            # writes next to this script
    python3 tests/fixtures/generate_tls_audit_fixtures.py OUT_DIR    # writes into OUT_DIR

Fixtures:
    enc_tls12_null.pcap          TLS 1.2 on tcp/443: the ServerHello chooses TLS_RSA_WITH_NULL_SHA256, so the
                                 application data records after ChangeCipherSpec carry a RESTCONF request and
                                 its Basic authorization in plaintext with only a MAC
    enc_tls13_integrity_only.pcap
                                 TLS 1.3 on tcp/57400: the ServerHello chooses TLS_SHA256_SHA256 (RFC 9150), so
                                 every record after it, the handshake's included, is plaintext with an HMAC
    enc_tls10.pcap               TLS 1.0 on tcp/443 with TLS_RSA_WITH_AES_128_CBC_SHA: encrypted, but weak
    enc_ssh_none.pcap            SSH on tcp/22: the client lists "none,aes128-ctr", the server "aes128-ctr,none",
                                 so RFC 4253 picks none (the client's first that the server offers); after NEWKEYS
                                 the userauth request and its password cross in plaintext
    enc_ssh_cbc.pcap             SSH on tcp/22: the client lists "aes128-cbc,aes128-ctr", the server
                                 "aes128-ctr,aes128-cbc", so aes128-cbc is chosen: encrypted, but weak
    enc_midstream.pcap           two sessions that began before the capture: TLS 1.2 on tcp/443 whose first
                                 captured segments are application data records, and SSH on tcp/22 with no banner
                                 and no key exchange, only ciphertext
    enc_port22_text.pcap         a session on tcp/22 with no SSH banner that carries plain text (a CLI login):
                                 not SSH, so it stays cleartext
"""

import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate_dataplane_fixtures import Capture, Tcp, client_hello, handshake_record, pad, server_hello  # noqa: E402

SYNTHETIC_BASIC = b"Basic c3ludGhldGljLXVzZXI6c3ludGhldGljLXBhc3M="  # synthetic-user:synthetic-pass
SYNTHETIC_SSH_PASSWORD = b"synthetic-ssh-pass-not-real"


def record(ctype: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", ctype, version, len(body)) + body


def ccs(version: int = 0x0303) -> bytes:
    return record(20, b"\x01", version)


def stream(label: str, length: int) -> bytes:
    """Deterministic bytes that look like ciphertext: a SHA-256 chain seeded by the label."""
    out, block = b"", label.encode()
    while len(out) < length:
        block = hashlib.sha256(block).digest()
        out += block
    return out[:length]


def ssh_packet(payload: bytes) -> bytes:
    """An SSH binary packet before encryption (RFC 4253 6): length, padding length, payload, padding."""
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    return struct.pack("!IB", len(payload) + pad_len + 1, pad_len) + payload + bytes(pad_len)


def ssh_string(value: bytes) -> bytes:
    return struct.pack("!I", len(value)) + value


def kexinit(label: str, ciphers: bytes, macs: bytes = b"hmac-sha2-256") -> bytes:
    names = [b"curve25519-sha256", b"ssh-ed25519", ciphers, ciphers, macs, macs, b"none", b"none", b"", b""]
    body = bytes([20]) + pad("cookie" + label, 16) + b"".join(ssh_string(n) for n in names)
    return ssh_packet(body + b"\x00" + struct.pack("!I", 0))


def ssh_session(cap, t, client, cport, server, client_ciphers, server_ciphers, after_newkeys):
    """Banners, both KEXINITs, an ECDH exchange, NEWKEYS, then after_newkeys(tcp, t) sends the rest."""
    s = Tcp(cap, client, cport, server, 22, 1000 + cport, 9000 + cport)
    s.handshake(t)
    s.send(True, t + 0.03, "PA", b"SSH-2.0-SyntheticClient_1.0\r\n")
    s.send(False, t + 0.04, "PA", b"SSH-2.0-SyntheticServer_1.0\r\n")
    s.send(False, t + 0.05, "PA", kexinit("server", server_ciphers))
    s.send(True, t + 0.06, "PA", kexinit("client", client_ciphers))
    s.send(True, t + 0.07, "PA", ssh_packet(bytes([30]) + ssh_string(pad("ecdh-c", 32))))
    s.send(False, t + 0.08, "PA", ssh_packet(bytes([31]) + ssh_string(pad("ecdh-s", 64))) + ssh_packet(bytes([21])))
    s.send(True, t + 0.09, "PA", ssh_packet(bytes([21])))
    after_newkeys(s, t + 0.10)
    return s


def tls12_session(cap, t, client, cport, server, sport, suite, version, sni, app_client, app_server):
    """A full TLS 1.2-style handshake choosing suite at version, then one application data record each way."""
    s = Tcp(cap, client, cport, server, sport, 2000 + cport, 7000 + cport)
    s.handshake(t)
    s.send(True, t + 0.03, "PA", client_hello(sni, [suite, 0xC02F], legacy=version))
    s.send(False, t + 0.05, "PA", handshake_record(2, server_hello(suite, version=version), record_version=version)
           + handshake_record(14, b"", record_version=version), window=502)
    s.send(True, t + 0.07, "PA", handshake_record(16, struct.pack("!H", 64) + pad("pms", 64), record_version=version)
           + ccs(version) + record(22, pad("client-finished", 48), version))
    s.send(False, t + 0.09, "PA", ccs(version) + record(22, pad("server-finished", 48), version))
    s.send(True, t + 0.11, "PA", record(23, app_client, version))
    s.send(False, t + 0.13, "PA", record(23, app_server, version))
    s.send(True, t + 0.15, "FA")
    s.send(False, t + 0.16, "FA")
    return s


def build_tls12_null():
    cap = Capture()
    request = (b"GET /restconf/data/Cisco-IOS-XE-native:native/hostname HTTP/1.1\r\nHost: 10.80.0.1\r\n"
               b"Authorization: " + SYNTHETIC_BASIC + b"\r\n\r\n")
    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/yang-data+json\r\n\r\n{\"hostname\": \"edge-1\"}"
    tls12_session(cap, 0.0, "10.80.0.10", 51000, "10.80.0.1", 443, 0x003B, 0x0303, "edge-1.example.net",
                  request + pad("mac", 32), response + pad("mac", 32))
    return cap


def build_tls13_integrity_only():
    cap = Capture()
    s = Tcp(cap, "10.80.0.10", 51100, "10.80.0.2", 57400, 3000, 4000)
    s.handshake(0.0)
    s.send(True, 0.03, "PA", client_hello("srl.example.net", [0xC0B4], versions=[0x0304], alpn=["h2"],
                                          groups=[0x001D]))
    hello = handshake_record(2, server_hello(0xC0B4, supported=0x0304, group=0x001D))
    # After the ServerHello every record is application_data on the wire, here holding plaintext and an HMAC.
    encrypted_extensions = bytes([8]) + (6).to_bytes(3, "big") + b"\x00\x04\x00\x10\x00\x00"
    s.send(False, 0.05, "PA", hello + ccs() + record(23, encrypted_extensions + b"\x16" + pad("hmac", 32)), window=502)
    s.send(True, 0.07, "PA", ccs() + record(23, bytes([20]) + (32).to_bytes(3, "big") + pad("fin", 32) + b"\x16"
                                            + pad("hmac", 32)))
    s.send(True, 0.09, "PA", record(23, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x17" + pad("hmac", 32)))
    s.send(False, 0.11, "PA", record(23, pad("gnmi-capabilities-response", 120) + b"\x17" + pad("hmac", 32)))
    return cap


def build_tls10():
    cap = Capture()
    tls12_session(cap, 0.0, "10.80.0.10", 51200, "10.80.0.3", 443, 0x002F, 0x0301, "legacy.example.net",
                  stream("tls10-c", 96), stream("tls10-s", 160))
    return cap


def build_ssh_none():
    cap = Capture()

    def plaintext(s, t):
        s.send(True, t, "PA", ssh_packet(bytes([5]) + ssh_string(b"ssh-userauth")))
        s.send(False, t + 0.01, "PA", ssh_packet(bytes([6]) + ssh_string(b"ssh-userauth")))
        s.send(True, t + 0.02, "PA", ssh_packet(bytes([50]) + ssh_string(b"admin") + ssh_string(b"ssh-connection")
                                               + ssh_string(b"password") + b"\x00" + ssh_string(SYNTHETIC_SSH_PASSWORD)))
        s.send(False, t + 0.03, "PA", ssh_packet(bytes([52])))

    ssh_session(cap, 0.0, "10.80.0.10", 52000, "10.80.0.4", b"none,aes128-ctr", b"aes128-ctr,none", plaintext)
    return cap


def build_ssh_cbc():
    cap = Capture()

    def ciphertext(s, t):
        for i in range(3):
            s.send(True, t + i * 0.01, "PA", stream(f"cbc-c{i}", 64))
            s.send(False, t + i * 0.01 + 0.005, "PA", stream(f"cbc-s{i}", 96))

    ssh_session(cap, 0.0, "10.80.0.10", 52100, "10.80.0.5", b"aes128-cbc,aes128-ctr", b"aes128-ctr,aes128-cbc",
                ciphertext)
    return cap


def build_midstream():
    cap = Capture()
    # TLS 1.2 on tcp/443, captured after its handshake: no SYN, application data records from the first segment
    t = Tcp(cap, "10.80.0.10", 53000, "10.80.0.6", 443, 50000, 60000)
    for i in range(3):
        t.send(True, 0.1 + i * 0.1, "PA", record(23, stream(f"mid-tls-c{i}", 80 + i * 16)))
        t.send(False, 0.15 + i * 0.1, "PA", record(23, stream(f"mid-tls-s{i}", 300 + i * 40)))
    # SSH on tcp/22, captured after its key exchange: no banner, only ciphertext packets of keystroke size
    s = Tcp(cap, "10.80.0.10", 53100, "10.80.0.7", 22, 70000, 80000)
    for i in range(4):
        s.send(True, 1.0 + i * 0.2, "PA", stream(f"mid-ssh-c{i}", 36))
        s.send(False, 1.05 + i * 0.2, "PA", stream(f"mid-ssh-s{i}", 52))
        s.send(True, 1.06 + i * 0.2, "A")
    return cap


def build_port22_text():
    cap = Capture()
    s = Tcp(cap, "10.80.0.10", 53200, "10.80.0.8", 22, 90000, 91000)
    s.handshake(0.0)
    s.send(False, 0.03, "PA", b"\r\nUser Access Verification\r\n\r\nUsername: ")
    s.send(True, 0.05, "PA", b"admin\r\n")
    s.send(False, 0.06, "PA", b"Password: ")
    s.send(True, 0.08, "PA", b"synthetic-not-real\r\n")
    s.send(False, 0.09, "PA", b"\r\nedge-8#show running-config | include hostname\r\nhostname edge-8\r\nedge-8#")
    return cap


BUILDERS = {
    "enc_tls12_null.pcap": build_tls12_null,
    "enc_tls13_integrity_only.pcap": build_tls13_integrity_only,
    "enc_tls10.pcap": build_tls10,
    "enc_ssh_none.pcap": build_ssh_none,
    "enc_ssh_cbc.pcap": build_ssh_cbc,
    "enc_midstream.pcap": build_midstream,
    "enc_port22_text.pcap": build_port22_text,
}


def main():
    default_out = os.path.join(os.path.dirname(os.path.dirname(HERE)), "testdata", "fixtures")
    out_dir = sys.argv[1] if len(sys.argv) > 1 else default_out
    os.makedirs(out_dir, exist_ok=True)
    for name, builder in BUILDERS.items():
        path = os.path.join(out_dir, name)
        builder().write(path)
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
