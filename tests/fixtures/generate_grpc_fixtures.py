#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. gRPC Test Fixtures (synthetic)

Generates the small, deterministic pcaps the gRPC troubleshooting tests read for
the cases no real capture on hand shows: RST_STREAM, GOAWAY (graceful, too_many_pings,
with unprocessed streams), a flow-control stall, a frame over the peer's max frame
size, a header list over the peer's limit, more streams than the server allows, a
message over the 4 MiB default, a deadline cancel, a TCP reset with an RPC open, a
preface nobody answered, TLS 1.2 with a client alert and a certificate with no IP
SAN, and TLS 1.3 with a HelloRetryRequest. Every file is synthetic: HTTP/2 frames,
HPACK (literal fields, no Huffman, no dynamic table), gRPC framing and gNMI protobuf
are built here with struct, TCP with scapy, at fixed addresses (10.0.0.0/8 and RFC
5737), fixed timestamps and no randomness, so two runs produce identical files.
Names start with grpc_. The credentials in them are synthetic placeholders.

Usage:
    python3 tests/fixtures/generate_grpc_fixtures.py            # writes next to this script
    python3 tests/fixtures/generate_grpc_fixtures.py OUT_DIR    # writes into OUT_DIR

Fixtures:
    grpc_h2_trouble.pcap   plaintext gNMI on tcp/9339: Capabilities (JSON_IETF, PROTO, ASCII), Get with
                           the encoding field absent refused UNIMPLEMENTED, Get with wrong credentials refused
                           UNAUTHENTICATED (username/password metadata), a STREAM Subscribe whose server stalls
                           on the client's stream window for 1.5 s, a Set the client cancels at its 2 s deadline,
                           a gNOI Reboot refused with REFUSED_STREAM over max_concurrent_streams 2, a 20000-byte
                           DATA frame over max_frame_size 16384, a 9000-byte header over max_header_list_size
                           8192, a 5000000-byte message refused RESOURCE_EXHAUSTED, an x-api-key in metadata
    grpc_connection_trouble.pcap
                           GOAWAY ENHANCE_YOUR_CALM too_many_pings after pings every second; a graceful server
                           GOAWAY leaving stream 3 unprocessed; a TCP reset with a Subscribe open; a preface to
                           tcp/57400 the server closed without answering; a connection on tcp/50051 captured
                           mid-way (no SYN, no preface), whose header blocks name HPACK dynamic table entries
                           the capture never saw; an HTTP/1.1 connection from client port 50051 to tcp/8080
    grpc_tls12_alert.pcap  TLS 1.2 on tcp/57400, no SNI, ALPN h2: a self-signed certificate with only a DNS SAN,
                           refused by the client with a fatal unknown_ca alert
    grpc_tls13_hrr.pcap    TLS 1.3 on tcp/9339, no SNI, ALPN h2: HelloRetryRequest and the middlebox-compatibility
                           ChangeCipherSpec, the second ClientHello, the ServerHello
    grpc_mgmt_mix.pcap     management sessions for the cleartext audit: NETCONF over SSH on tcp/830 (banners,
                           KEXINIT, ECDH, NEWKEYS, then encrypted packets), TLS 1.3 on tcp/443, a cleartext login on
                           tcp/23, and gRPC over cleartext HTTP/2 from port 41000 to 50001 (the client's port lower
                           than the server's) with an authorization header

build_tls13_keylog() is not a committed fixture: the tests call it to make a TLS 1.3 gNMI session
with real TLS from Python's ssl module and its key log, in a temporary directory, on every run.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate_dataplane_fixtures import Capture, Tcp, ext, handshake_record, pad, server_hello  # noqa: E402

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SYNTHETIC_USER = b"synthetic-user"
SYNTHETIC_PASSWORD = b"synthetic-pass-not-real"
SYNTHETIC_API_KEY = b"synthetic-api-key-0000"


# ---------------------------------------------------------------------------
# HTTP/2, HPACK, gRPC and protobuf builders
# ---------------------------------------------------------------------------

def hpack_int(value: int, prefix_bits: int, flags: int = 0) -> bytes:
    top = (1 << prefix_bits) - 1
    if value < top:
        return bytes([flags | value])
    out = [flags | top]
    value -= top
    while value >= 128:
        out.append((value % 128) + 128)
        value //= 128
    out.append(value)
    return bytes(out)


def hpack(headers) -> bytes:
    """A header block of literal fields without indexing (new name, no Huffman): no dynamic table state."""
    block = b""
    for name, value in headers:
        name = name.encode() if isinstance(name, str) else name
        value = value.encode() if isinstance(value, str) else value
        block += b"\x00" + hpack_int(len(name), 7) + name + hpack_int(len(value), 7) + value
    return block


def h2(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", sid) + payload


def settings(**values) -> bytes:
    ids = {"header_table_size": 1, "enable_push": 2, "max_concurrent_streams": 3, "initial_window_size": 4,
           "max_frame_size": 5, "max_header_list_size": 6}
    return h2(4, 0, 0, b"".join(struct.pack("!HI", ids[k], v) for k, v in values.items()))


SETTINGS_ACK = h2(4, 1, 0)


def headers_frame(sid, headers, end_stream=False) -> bytes:
    return h2(1, 0x04 | (0x01 if end_stream else 0), sid, hpack(headers))


def data_frame(sid, payload, end_stream=False) -> bytes:
    return h2(0, 0x01 if end_stream else 0, sid, payload)


def window_update(sid, increment) -> bytes:
    return h2(8, 0, sid, struct.pack("!I", increment))


def rst_stream(sid, code) -> bytes:
    return h2(3, 0, sid, struct.pack("!I", code))


def goaway(last_sid, code, debug=b"") -> bytes:
    return h2(7, 0, 0, struct.pack("!II", last_sid, code) + debug)


def ping(opaque: bytes, ack=False) -> bytes:
    return h2(6, 1 if ack else 0, 0, opaque)


def grpc_message(message: bytes) -> bytes:
    return b"\x00" + struct.pack("!I", len(message)) + message


def varint(value: int) -> bytes:
    out = b""
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def pb_varint(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def pb_bytes(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def gnmi_path(*elems: str) -> bytes:
    return b"".join(pb_bytes(3, pb_bytes(1, e.encode())) for e in elems)


def request_headers(method: str, authority: str, extra=(), timeout="15S"):
    return [(":method", "POST"), (":scheme", "http"), (":path", method), (":authority", authority),
            ("content-type", "application/grpc"), ("user-agent", "synthetic-client/1.0 grpc-go/1.70.0"),
            ("te", "trailers"), ("grpc-timeout", timeout), *extra]


def trailers(status: int, message: str = ""):
    out = [("grpc-status", str(status))]
    if message:
        out.append(("grpc-message", message.replace(" ", "%20")))
    return out


RESPONSE_HEADERS = [(":status", "200"), ("content-type", "application/grpc")]


class H2Conn:
    """One HTTP/2 connection over a synthetic TCP connection; times are absolute offsets."""

    def __init__(self, cap, client, cport, server, sport, isn_c, isn_s, t, syn=True):
        self.tcp = Tcp(cap, client, cport, server, sport, isn_c, isn_s)
        if syn:
            self.tcp.handshake(t)

    def client(self, t, *frames):
        self.tcp.send(True, t, "PA", b"".join(frames))

    def server(self, t, *frames):
        self.tcp.send(False, t, "PA", b"".join(frames))


# ---------------------------------------------------------------------------
# grpc_h2_trouble.pcap
# ---------------------------------------------------------------------------

def capabilities_response() -> bytes:
    models = b"".join(pb_bytes(1, pb_bytes(1, name.encode()) + pb_bytes(2, b"Synthetic") + pb_bytes(3, b"1.0.0"))
                      for name in ("openconfig-interfaces", "openconfig-system"))
    return models + pb_bytes(2, varint(4) + varint(2) + varint(3)) + pb_bytes(3, b"0.10.0")


def build_h2_trouble():
    cap = Capture()
    client, server = "10.20.0.10", "10.20.0.1"
    authority = f"{server}:9339"
    creds = [("username", SYNTHETIC_USER), ("password", SYNTHETIC_PASSWORD)]
    c = H2Conn(cap, client, 51000, server, 9339, 1000, 5000, 0.0)
    c.client(0.03, PREFACE, settings(initial_window_size=8192, max_header_list_size=16384))
    c.server(0.031, settings(max_concurrent_streams=2, max_frame_size=16384, max_header_list_size=8192),
             SETTINGS_ACK)
    c.client(0.032, SETTINGS_ACK)
    # stream 1: Capabilities, OK
    c.client(0.10, headers_frame(1, request_headers("/gnmi.gNMI/Capabilities", authority, creds)),
             data_frame(1, grpc_message(b""), end_stream=True))
    body = grpc_message(capabilities_response())
    c.server(0.12, headers_frame(1, RESPONSE_HEADERS), data_frame(1, body), headers_frame(1, trailers(0), True))
    # stream 3: Get with the encoding field absent (JSON), refused UNIMPLEMENTED in a trailers-only response
    get = pb_bytes(2, gnmi_path("system", "state", "hostname"))
    c.client(0.20, headers_frame(3, request_headers("/gnmi.gNMI/Get", authority, creds)),
             data_frame(3, grpc_message(get), end_stream=True))
    c.server(0.21, headers_frame(3, RESPONSE_HEADERS + trailers(12, "unsupported encoding: JSON"), True))
    # stream 5: Get JSON_IETF with wrong credentials, UNAUTHENTICATED
    get = pb_bytes(2, gnmi_path("interfaces")) + pb_varint(5, 4)
    c.client(0.30, headers_frame(5, request_headers("/gnmi.gNMI/Get", authority,
                                                    [("username", SYNTHETIC_USER), ("password", b"wrong-" + SYNTHETIC_PASSWORD)])),
             data_frame(5, grpc_message(get), end_stream=True))
    c.server(0.31, headers_frame(5, RESPONSE_HEADERS + trailers(16, "authentication failed"), True))
    # stream 7: Subscribe STREAM, SAMPLE every 10 s; the server fills the client's 8192-byte stream window
    sub = pb_bytes(1, pb_bytes(2, pb_bytes(1, gnmi_path("interfaces", "interface", "state", "counters"))
                                + pb_varint(2, 2) + pb_varint(3, 10_000_000_000)) + pb_varint(8, 4))
    c.client(0.40, headers_frame(7, request_headers("/gnmi.gNMI/Subscribe", authority, creds, timeout="300S")),
             data_frame(7, grpc_message(sub)))
    note = pb_bytes(1, pb_varint(1, 1767225600_000_000_000) + pb_bytes(4, pb_bytes(1, gnmi_path("in-octets"))))
    first = grpc_message(note) + grpc_message(pb_varint(3, 1))  # a notification, then sync_response
    burst = grpc_message(pb_bytes(1, pb_varint(1, 1767225601_000_000_000) + pad("counters", 12000)))
    room = 8192 - len(first)  # the client's stream window: SETTINGS_INITIAL_WINDOW_SIZE 8192
    c.server(0.42, headers_frame(7, RESPONSE_HEADERS), data_frame(7, first + burst[:room]))
    rest = burst[room:]
    # the window is at 0 from 0.42 to 1.92, while the server still has data waiting
    c.client(1.92, window_update(7, 65535), window_update(0, 65535))
    c.server(1.93, data_frame(7, rest))
    # stream 9: Set, cancelled by the client at its 2 s deadline
    setreq = pb_bytes(4, pb_bytes(1, gnmi_path("system", "config", "hostname")))
    c.client(2.00, headers_frame(9, request_headers("/gnmi.gNMI/Set", authority, creds, timeout="2S")),
             data_frame(9, grpc_message(setreq), end_stream=True))
    # stream 11: gNOI Reboot while 7 and 9 are open: over max_concurrent_streams 2, refused
    c.client(2.10, headers_frame(11, request_headers("/gnoi.system.System/Reboot", authority, creds)),
             data_frame(11, grpc_message(pb_varint(1, 1)), end_stream=True))
    c.server(2.101, rst_stream(11, 7))
    c.client(4.00, rst_stream(9, 8))
    # stream 13: a DATA frame of 20000 bytes, over the server's max_frame_size 16384, and a 9000-byte header
    big_header = [("x-trace-context", pad("trace", 9000))]
    c.client(4.10, headers_frame(13, request_headers("/gnoi.file.File/Put", authority, creds + big_header)),
             data_frame(13, grpc_message(pad("file", 19995))))
    c.server(4.11, rst_stream(13, 6))
    # stream 15: a 5000000-byte message: the server refuses it from the length prefix
    c.client(4.20, headers_frame(15, request_headers("/gnmi.gNMI/Set", authority,
                                                     [("x-api-key", SYNTHETIC_API_KEY)])),
             data_frame(15, b"\x00" + struct.pack("!I", 5_000_000) + pad("blob", 1000)))
    c.server(4.21, headers_frame(15, RESPONSE_HEADERS + trailers(
        8, "grpc: received message larger than max (5000000 vs. 4194304)"), True))
    c.client(4.211, rst_stream(15, 8))
    # stream 7 is still open at the end of the capture (a STREAM subscription)
    return cap


# ---------------------------------------------------------------------------
# grpc_connection_trouble.pcap
# ---------------------------------------------------------------------------

def build_connection_trouble():
    cap = Capture()
    client, server = "10.30.0.10", "10.30.0.1"
    authority = f"{server}:50051"
    # 1: pings every second while idle, the server answers GOAWAY ENHANCE_YOUR_CALM too_many_pings
    a = H2Conn(cap, client, 52000, server, 50051, 100, 900, 0.0)
    a.client(0.03, PREFACE, settings())
    a.server(0.031, settings(max_concurrent_streams=100), SETTINGS_ACK)
    a.client(0.032, SETTINGS_ACK)
    a.client(0.05, headers_frame(1, request_headers("/grpc.health.v1.Health/Check", authority)),
             data_frame(1, grpc_message(b""), end_stream=True))
    a.server(0.06, headers_frame(1, RESPONSE_HEADERS), data_frame(1, grpc_message(pb_varint(1, 1))),
             headers_frame(1, trailers(0), True))
    for i in range(3):
        opaque = struct.pack("!Q", i + 1)
        a.client(1.0 + i, ping(opaque))
        a.server(1.0005 + i, ping(opaque, ack=True))
    a.server(3.001, goaway(1, 11, b"too_many_pings"))
    # 2: a graceful server GOAWAY with last stream 1, after the client had sent stream 3
    b = H2Conn(cap, client, 52001, server, 50051, 2000, 3000, 5.0)
    b.client(5.03, PREFACE, settings())
    b.server(5.031, settings(), SETTINGS_ACK)
    b.client(5.04, headers_frame(1, request_headers("/gnmi.gNMI/Capabilities", authority)),
             data_frame(1, grpc_message(b""), end_stream=True))
    b.server(5.05, headers_frame(1, RESPONSE_HEADERS), data_frame(1, grpc_message(capabilities_response())),
             headers_frame(1, trailers(0), True))
    b.client(5.10, headers_frame(3, request_headers("/gnmi.gNMI/Get", authority)),
             data_frame(3, grpc_message(pb_bytes(2, gnmi_path("system")) + pb_varint(5, 4)), end_stream=True))
    b.server(5.1005, goaway(1, 0, b"server shutting down"))
    # 3: a TCP reset from the server while a Subscribe is open
    r = H2Conn(cap, client, 52002, server, 50051, 4000, 6000, 7.0)
    r.client(7.03, PREFACE, settings())
    r.server(7.031, settings(), SETTINGS_ACK)
    sub = pb_bytes(1, pb_bytes(2, pb_bytes(1, gnmi_path("system"))) + pb_varint(5, 0))
    r.client(7.04, headers_frame(1, request_headers("/gnmi.gNMI/Subscribe", authority, timeout="600S")),
             data_frame(1, grpc_message(sub)))
    r.server(7.05, headers_frame(1, RESPONSE_HEADERS), data_frame(1, grpc_message(pb_varint(3, 1))))
    r.tcp.send(False, 8.0, "RA")
    # 4: the HTTP/2 preface in cleartext to tcp/57400, which expects TLS: the server closes without answering
    p = H2Conn(cap, client, 52003, server, 57400, 8000, 9000, 9.0)
    p.client(9.03, PREFACE, settings())
    p.tcp.send(False, 9.04, "FA")
    p.tcp.send(True, 9.041, "FA")
    p.tcp.send(False, 9.042, "A")
    # 5: captured mid-way: no SYN, no preface, and header blocks that index dynamic table entries 62 and 63
    m = H2Conn(cap, client, 52004, server, 50051, 10000, 11000, 10.0, syn=False)
    m.client(10.1, h2(1, 0x04, 21, bytes([0xBE]) + hpack([(":path", "/gnmi.gNMI/Get")])),
             data_frame(21, grpc_message(pb_bytes(2, gnmi_path("system")) + pb_varint(5, 4)), end_stream=True))
    m.server(10.2, h2(1, 0x05, 21, bytes([0xBF]) + hpack([("grpc-status", "0")])))
    # 6: an unrelated HTTP/1.1 connection whose client port happens to be 50051, decoded as HTTP/2 too
    w = Tcp(cap, "10.30.0.20", 50051, server, 8080, 12000, 13000)
    w.handshake(11.0)
    w.send(True, 11.03, "PA", b"GET / HTTP/1.1\r\nHost: 10.30.0.1:8080\r\n\r\n")
    w.send(False, 11.04, "PA", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    return cap


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def client_hello_no_sni(suites, versions=None, alpn=None, groups=None, label="hello"):
    """A ClientHello with no server_name extension (a client that dialled an IP address)."""
    body = struct.pack("!H", 0x0303) + pad("random-" + label, 32) + b"\x20" + pad("sid", 32)
    body += struct.pack("!H", len(suites) * 2) + b"".join(struct.pack("!H", s) for s in suites) + b"\x01\x00"
    exts = b""
    if groups:
        g = b"".join(struct.pack("!H", x) for x in groups)
        exts += ext(10, struct.pack("!H", len(g)) + g)
        share = struct.pack("!HH", groups[-1], 32) + pad("key" + label, 32)
        exts += ext(51, struct.pack("!H", len(share)) + share)
    if alpn:
        a = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        exts += ext(16, struct.pack("!H", len(a)) + a)
    if versions:
        v = b"".join(struct.pack("!H", x) for x in versions)
        exts += ext(43, bytes([len(v)]) + v)
    body += struct.pack("!H", len(exts)) + exts
    return handshake_record(1, body, record_version=0x0301)


def self_signed_certificate() -> bytes:
    """A deterministic Ed25519 self-signed certificate with a DNS SAN and no IP SAN."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gnmi.example.net")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(5757).not_valid_before(datetime.datetime(2025, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("gnmi.example.net")]), critical=False)
            .sign(key, None))
    return cert.public_bytes(serialization.Encoding.DER)


HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def build_tls12_alert():
    cap = Capture()
    client, server = "10.40.0.10", "192.0.2.57"
    t = Tcp(cap, client, 53000, server, 57400, 1000, 2000)
    t.handshake(0.0)
    t.send(True, 0.03, "PA", client_hello_no_sni([0xC02F, 0xC030, 0xCCA8], alpn=["h2"], groups=[0x001D],
                                                 label="tls12"))
    cert = self_signed_certificate()
    cert_msg = (len(cert) + 3).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert
    flight = (handshake_record(2, server_hello(0xC02F, alpn="h2")) + handshake_record(11, cert_msg)
              + handshake_record(14, b""))
    t.send(False, 0.05, "PA", flight, window=502)
    t.send(True, 0.051, "PA", struct.pack("!BHHBB", 21, 0x0303, 2, 2, 48))  # fatal unknown_ca from the client
    t.send(True, 0.052, "FA")
    t.send(False, 0.053, "FA")
    return cap


def build_tls13_hrr():
    cap = Capture()
    client, server = "10.40.0.11", "192.0.2.93"
    t = Tcp(cap, client, 53100, server, 9339, 3000, 4000)
    t.handshake(0.0)
    t.send(True, 0.03, "PA", client_hello_no_sni([0x1301, 0x1302], versions=[0x0304], alpn=["h2"],
                                                 groups=[0x001D], label="first"))
    hrr = struct.pack("!H", 0x0303) + HRR_RANDOM + b"\x20" + pad("sid", 32) + struct.pack("!HB", 0x1301, 0)
    hrr_exts = ext(43, struct.pack("!H", 0x0304)) + ext(51, struct.pack("!H", 0x0017))
    hrr += struct.pack("!H", len(hrr_exts)) + hrr_exts
    t.send(False, 0.05, "PA", handshake_record(2, hrr) + bytes([20, 3, 3, 0, 1, 1]), window=502)
    t.send(True, 0.07, "PA", bytes([20, 3, 3, 0, 1, 1]) + client_hello_no_sni(
        [0x1301, 0x1302], versions=[0x0304], alpn=["h2"], groups=[0x0017], label="second"))
    sh = handshake_record(2, server_hello(0x1301, supported=0x0304, group=0x0017))
    t.send(False, 0.09, "PA", sh + bytes([20, 3, 3, 0, 1, 1]) + struct.pack("!BHH", 23, 0x0303, 60) + pad("enc", 60),
           window=502)
    t.send(True, 0.11, "PA", struct.pack("!BHH", 23, 0x0303, 80) + pad("cfin", 80))
    return cap


def ssh_packet(payload: bytes) -> bytes:
    """An SSH binary packet before encryption (RFC 4253 6): length, padding length, payload, padding."""
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    return struct.pack("!IB", len(payload) + pad_len + 1, pad_len) + payload + bytes(pad_len)


def ssh_kexinit(label: str) -> bytes:
    names = [b"curve25519-sha256", b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256",
             b"hmac-sha2-256", b"none", b"none", b"", b""]
    body = bytes([20]) + pad("cookie" + label, 16) + b"".join(struct.pack("!I", len(n)) + n for n in names)
    return ssh_packet(body + b"\x00" + struct.pack("!I", 0))


def build_mgmt_mix():
    cap = Capture()
    client, router = "10.70.0.10", "10.70.0.1"
    # NETCONF over SSH on tcp/830
    n = Tcp(cap, client, 56000, router, 830, 1000, 2000)
    n.handshake(0.0)
    n.send(True, 0.03, "PA", b"SSH-2.0-SyntheticClient\r\n")
    n.send(False, 0.04, "PA", b"SSH-2.0-SyntheticServer\r\n")
    n.send(False, 0.05, "PA", ssh_kexinit("server"))
    n.send(True, 0.06, "PA", ssh_kexinit("client"))
    n.send(True, 0.07, "PA", ssh_packet(bytes([30]) + struct.pack("!I", 32) + pad("ecdh-c", 32)))
    n.send(False, 0.08, "PA", ssh_packet(bytes([31]) + struct.pack("!I", 64) + pad("ecdh-s", 64))
           + ssh_packet(bytes([21])))
    n.send(True, 0.09, "PA", ssh_packet(bytes([21])))
    for i in range(4):
        n.send(True, 0.10 + i * 0.01, "PA", pad(f"enc-c{i}", 96))
        n.send(False, 0.105 + i * 0.01, "PA", pad(f"enc-s{i}", 160))
    # TLS 1.3 on tcp/443
    t = Tcp(cap, client, 56001, router, 443, 3000, 4000)
    t.handshake(1.0)
    hello = client_hello_no_sni([0x1301, 0x1302], versions=[0x0304], alpn=["h2", "http/1.1"], groups=[0x001D],
                                label="mix")
    t.send(True, 1.03, "PA", hello)
    sh = handshake_record(2, server_hello(0x1301, supported=0x0304, group=0x001D))
    t.send(False, 1.05, "PA", sh + bytes([20, 3, 3, 0, 1, 1]) + struct.pack("!BHH", 23, 0x0303, 200) + pad("e", 200))
    t.send(True, 1.06, "PA", bytes([20, 3, 3, 0, 1, 1]) + struct.pack("!BHH", 23, 0x0303, 60) + pad("f", 60))
    t.send(True, 1.07, "PA", struct.pack("!BHH", 23, 0x0303, 300) + pad("req", 300))
    t.send(False, 1.08, "PA", struct.pack("!BHH", 23, 0x0303, 500) + pad("resp", 500))
    # a cleartext login on tcp/23
    c = Tcp(cap, client, 56002, router, 23, 5000, 6000)
    c.handshake(2.0)
    c.send(False, 2.03, "PA", b"\r\nUser Access Verification\r\n\r\nUsername: ")
    c.send(True, 2.04, "PA", b"synthetic\r\n")
    # gRPC over cleartext HTTP/2 from port 41000 to 50001: the server's port is the higher one
    g = H2Conn(cap, client, 41000, router, 50001, 7000, 8000, 3.0)
    g.client(3.03, PREFACE, settings())
    g.server(3.031, settings(), SETTINGS_ACK)
    g.client(3.04, headers_frame(1, request_headers("/gnmi.gNMI/Capabilities", f"{router}:50001",
                                                    [("authorization", b"Bearer " + SYNTHETIC_API_KEY)])),
             data_frame(1, grpc_message(b""), end_stream=True))
    g.server(3.05, headers_frame(1, RESPONSE_HEADERS), data_frame(1, grpc_message(capabilities_response())),
             headers_frame(1, trailers(0), True))
    return cap


def build_tls13_keylog(out_dir: str, client_port: int = 55000, start: float = 0.0, cap=None,
                       label: str = "grpc_tls13"):
    """
    A TLS 1.3 gNMI session with its key log, generated at test time (not a committed fixture).

    The TLS is real: Python's ssl module (OpenSSL) runs the client and the server in memory
    (MemoryBIO), the client writes its secrets to a key log as SSLKEYLOGFILE would, and the
    bytes each side sends become TCP segments. Keys and randoms differ on every run, so the
    file is never compared byte for byte and the key log is never committed. Inside: gNMI
    Capabilities answered OK and a Get refused UNAUTHENTICATED, with username and password
    metadata (synthetic values) that only the key log makes visible.

    With cap, the session is added to that Capture (from client_port, at start seconds) and no
    pcap is written, so a test can put several sessions, each with its own key log, in one file.

    Returns (pcap path, or None with cap; key log path).
    """
    import datetime
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gnmi-tls.example.net")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(datetime.datetime(2025, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("gnmi-tls.example.net")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(out_dir, f"{label}.server.crt"), os.path.join(out_dir, f"{label}.server.key")
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    keylog = os.path.join(out_dir, f"{label}.keylog")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    server_ctx.set_alpn_protocols(["h2"])
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.set_alpn_protocols(["h2"])
    client_ctx.keylog_filename = keylog
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(c_in, c_out, server_side=False)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    flights = []

    def pump():
        moved = True
        while moved:
            moved = False
            data = c_out.read()
            if data:
                flights.append((True, data))
                s_in.write(data)
                moved = True
            data = s_out.read()
            if data:
                flights.append((False, data))
                c_in.write(data)
                moved = True

    done = {"client": False, "server": False}
    for _ in range(20):
        for side, obj in (("client", client), ("server", server)):
            if not done[side]:
                try:
                    obj.do_handshake()
                    done[side] = True
                except ssl.SSLWantReadError:
                    pass
            pump()
        if all(done.values()):
            break

    def drain(obj):
        out = b""
        while True:
            try:
                out += obj.read(65536)
            except ssl.SSLWantReadError:
                return out

    authority = "198.51.100.57:57400"
    creds = [("username", SYNTHETIC_USER), ("password", SYNTHETIC_PASSWORD)]
    client.write(PREFACE + settings() + headers_frame(1, request_headers("/gnmi.gNMI/Capabilities", authority,
                                                                         creds))
                 + data_frame(1, grpc_message(b""), end_stream=True))
    pump()
    drain(server)
    server.write(settings(max_concurrent_streams=100) + SETTINGS_ACK + headers_frame(1, RESPONSE_HEADERS)
                 + data_frame(1, grpc_message(capabilities_response())) + headers_frame(1, trailers(0), True))
    pump()
    drain(client)
    client.write(SETTINGS_ACK + headers_frame(3, request_headers("/gnmi.gNMI/Get", authority, creds))
                 + data_frame(3, grpc_message(pb_bytes(2, gnmi_path("system")) + pb_varint(5, 4)), end_stream=True))
    pump()
    drain(server)
    server.write(headers_frame(3, RESPONSE_HEADERS + trailers(16, "authentication failed"), True))
    pump()
    drain(client)

    write = cap is None
    cap = Capture() if write else cap
    tcp = Tcp(cap, "10.60.0.10", client_port, "198.51.100.57", 57400, 7000, 8000)
    tcp.handshake(start)
    t = start + 0.05
    for from_client, data in flights:
        tcp.send(from_client, t, "PA", data, window=502)
        t += 0.01
    if not write:
        return None, keylog
    pcap = os.path.join(out_dir, f"{label}_keylog.pcap")
    cap.write(pcap)
    return pcap, keylog


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else HERE
    os.makedirs(out_dir, exist_ok=True)
    builders = {
        "grpc_h2_trouble.pcap": build_h2_trouble,
        "grpc_connection_trouble.pcap": build_connection_trouble,
        "grpc_tls12_alert.pcap": build_tls12_alert,
        "grpc_tls13_hrr.pcap": build_tls13_hrr,
        "grpc_mgmt_mix.pcap": build_mgmt_mix,
    }
    for name, builder in builders.items():
        path = os.path.join(out_dir, name)
        builder().write(path)
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
