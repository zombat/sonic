#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. RESTCONF and REST Test Fixtures (synthetic)

Generates the small, deterministic pcaps the RESTCONF/REST troubleshooting tests read
for the cases a real capture on hand does not show, built with scapy at fixed addresses
(RFC 5737) and fixed timestamps so two runs produce identical files. Names start with
restconf_. The credentials in them are synthetic placeholders.

Cleartext fixtures (the http dissector pairs request and response by TCP stream):
    restconf_cleartext.pcap   HTTP/1.1 RESTCONF on tcp/8080 and REST on tcp/80:
                              a GET 200 (application/yang-data+json), a POST 201 with a Location,
                              a PUT 204, a DELETE 404 whose body is an ietf-restconf:errors XML
                              document, a GET 400 whose body is an ietf-restconf:errors JSON
                              document, a GET carrying Authorization Basic (a cleartext credential),
                              a plain REST GET /api/v1/status 200 (application/json), and an h2c
                              RESTCONF GET 200 on tcp/8081 with an X-Auth-Token header

build_restconf_tls13_keylog() is not a committed fixture: the tests call it to make RESTCONF
over TLS 1.3 (HTTP/1.1 and HTTP/2) with real TLS from Python's ssl module and its key log, in a
temporary directory, on every run. S.O.N.I.C. commits only synthetic fixtures; a real
RESTCONF-over-TLS capture with a key log is listed as not done in the tests when none is present.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate_dataplane_fixtures import Capture, Tcp  # noqa: E402
import generate_grpc_fixtures as g  # noqa: E402

SYNTHETIC_USER = b"restconf-user"
SYNTHETIC_PASSWORD = b"restconf-pass-not-real"
SYNTHETIC_BASIC = b"cmVzdGNvbmYtdXNlcjpyZXN0Y29uZi1wYXNzLW5vdC1yZWFs"  # base64("restconf-user:restconf-pass-not-real")
SYNTHETIC_TOKEN = b"restconf-token-0000-not-real"

ERRORS_JSON = (b'{"ietf-restconf:errors":{"error":[{"error-type":"application","error-tag":"invalid-value",'
               b'"error-path":"/ietf-interfaces:interfaces/interface=eth9","error-message":"uri keypath not found"'
               b'}]}}')
ERRORS_XML = (b'<errors xmlns="urn:ietf:params:xml:ns:yang:ietf-restconf"><error>'
              b'<error-type>protocol</error-type><error-tag>data-missing</error-tag>'
              b'<error-path>/ietf-interfaces:interfaces/interface=eth9</error-path>'
              b'<error-message>object not found</error-message></error></errors>')
IFACE_JSON = b'{"ietf-interfaces:interfaces":{"interface":[{"name":"GigabitEthernet1","enabled":true}]}}'
STATUS_JSON = b'{"status":"ok","uptime":12345}'


def http1_request(method, uri, host, headers=(), body=b"", version="1.1"):
    lines = [f"{method} {uri} HTTP/{version}", f"Host: {host}"]
    for name, value in headers:
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http1_response(code, phrase, headers=(), body=b"", version="1.1"):
    lines = [f"HTTP/{version} {code} {phrase}"]
    for name, value in headers:
        lines.append(f"{name}: {value}")
    # A real server frames every response: Content-Length (0 when empty) so a keep-alive
    # connection's next response is not read as this one's body (RFC 7230 section 3.3.3).
    if code != 204:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: keep-alive")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def exchange(tcp, t, request, response, rtt=0.01):
    tcp.send(True, t, "PA", request, window=502)
    tcp.send(False, t + rtt, "PA", response, window=502)
    tcp.send(True, t + rtt * 2, "A", window=502)


def build_restconf_cleartext():
    cap = Capture()
    client, srv = "10.80.0.10", "198.51.100.90"
    yang = "application/yang-data+json"

    # tcp/8080: RESTCONF over HTTP/1.1
    c1 = Tcp(cap, client, 45001, srv, 8080, 1000, 2000)
    c1.handshake(0.0)
    exchange(c1, 0.05,
             http1_request("GET", "/restconf/data/ietf-interfaces:interfaces", "nc.example.net",
                           [("Accept", yang)]),
             http1_response(200, "OK", [("Content-Type", yang)], IFACE_JSON))
    exchange(c1, 0.20,
             http1_request("POST", "/restconf/data/ietf-interfaces:interfaces", "nc.example.net",
                           [("Content-Type", yang)], IFACE_JSON),
             http1_response(201, "Created",
                            [("Location", "https://nc.example.net/restconf/data/ietf-interfaces:interfaces/"
                                          "interface=GigabitEthernet1"), ("Content-Type", yang)]))
    exchange(c1, 0.35,
             http1_request("PUT", "/restconf/data/ietf-interfaces:interfaces/interface=GigabitEthernet1",
                           "nc.example.net", [("Content-Type", yang)], IFACE_JSON),
             http1_response(204, "No Content"))
    exchange(c1, 0.50,
             http1_request("DELETE", "/restconf/data/ietf-interfaces:interfaces/interface=eth9", "nc.example.net"),
             http1_response(404, "Not Found", [("Content-Type", "application/yang-data+xml")], ERRORS_XML))
    exchange(c1, 0.65,
             http1_request("GET", "/restconf/data/ietf-interfaces:interfaces/interface=eth9", "nc.example.net",
                           [("Accept", yang)]),
             http1_response(400, "Bad Request", [("Content-Type", yang)], ERRORS_JSON))
    exchange(c1, 0.80,
             http1_request("GET", "/restconf/data/ietf-system:system", "nc.example.net",
                           [("Accept", yang), ("Authorization", "Basic " + SYNTHETIC_BASIC.decode())]),
             http1_response(200, "OK", [("Content-Type", yang)], b'{"ietf-system:system":{}}'))

    # tcp/80: a plain REST JSON API, not RESTCONF
    c2 = Tcp(cap, client, 45002, srv, 80, 3000, 4000)
    c2.handshake(1.0)
    exchange(c2, 1.05,
             http1_request("GET", "/api/v1/status", "api.example.net", [("Accept", "application/json")]),
             http1_response(200, "OK", [("Content-Type", "application/json")], STATUS_JSON))

    # tcp/8081: RESTCONF over cleartext HTTP/2 (h2c), with a token header
    h2 = g.H2Conn(cap, client, 45003, srv, 8081, 5000, 6000, 2.0)
    req = [(":method", "GET"), (":scheme", "http"),
           (":path", "/restconf/data/ietf-interfaces:interfaces"), (":authority", "nc.example.net:8081"),
           ("accept", yang), ("x-auth-token", SYNTHETIC_TOKEN.decode())]
    h2.client(2.05, g.PREFACE, g.settings(), g.headers_frame(1, req, end_stream=True))
    h2.server(2.10, g.settings(max_concurrent_streams=100), g.SETTINGS_ACK,
              g.headers_frame(1, [(":status", "200"), ("content-type", yang)]),
              g.data_frame(1, IFACE_JSON, end_stream=True))
    return cap


def build_restconf_tls13_keylog(out_dir, client_port=46000, start=0.0, cap=None, label="restconf_tls13",
                                http2=True):
    """
    RESTCONF over TLS 1.3 (HTTP/1.1 or HTTP/2) with its key log, generated at test time.

    The TLS is real (Python's ssl module, MemoryBIO), the client writes its secrets to a key
    log as SSLKEYLOGFILE would, and each side's bytes become TCP segments. Inside: a RESTCONF
    GET answered 200 and a DELETE answered 404 with an ietf-restconf:errors body, carrying an
    Authorization header (synthetic) that only the key log makes visible. Returns (pcap or None
    with cap; key log path).
    """
    import datetime
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "restconf-tls.example.net")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(11).not_valid_before(datetime.datetime(2025, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("restconf-tls.example.net")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(out_dir, f"{label}.server.crt")
    key_path = os.path.join(out_dir, f"{label}.server.key")
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    keylog = os.path.join(out_dir, f"{label}.keylog")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.keylog_filename = keylog
    if http2:
        server_ctx.set_alpn_protocols(["h2"])
        client_ctx.set_alpn_protocols(["h2"])
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

    authority = "198.51.100.91:443"
    yang = "application/yang-data+json"
    if http2:
        creds = [("authorization", "Bearer " + SYNTHETIC_TOKEN.decode()), ("accept", yang)]
        client.write(g.PREFACE + g.settings()
                     + g.headers_frame(1, [(":method", "GET"), (":scheme", "https"),
                                           (":path", "/restconf/data/ietf-interfaces:interfaces"),
                                           (":authority", authority)] + creds, end_stream=True))
        pump()
        drain(server)
        server.write(g.settings(max_concurrent_streams=100) + g.SETTINGS_ACK
                     + g.headers_frame(1, [(":status", "200"), ("content-type", yang)])
                     + g.data_frame(1, IFACE_JSON, end_stream=True))
        pump()
        drain(client)
        client.write(g.SETTINGS_ACK
                     + g.headers_frame(3, [(":method", "DELETE"), (":scheme", "https"),
                                           (":path", "/restconf/data/ietf-interfaces:interfaces/interface=eth9"),
                                           (":authority", authority)] + creds, end_stream=True))
        pump()
        drain(server)
        server.write(g.headers_frame(3, [(":status", "404"), ("content-type", yang)])
                     + g.data_frame(3, ERRORS_JSON, end_stream=True))
        pump()
        drain(client)
    else:
        get = http1_request("GET", "/restconf/data/ietf-interfaces:interfaces", "restconf-tls.example.net",
                            [("Accept", yang), ("Authorization", "Basic " + SYNTHETIC_BASIC.decode())])
        client.write(get)
        pump()
        drain(server)
        server.write(http1_response(200, "OK", [("Content-Type", yang)], IFACE_JSON))
        pump()
        drain(client)
        delete = http1_request(
            "DELETE", "/restconf/data/ietf-interfaces:interfaces/interface=eth9", "restconf-tls.example.net",
            [("Authorization", "Basic " + SYNTHETIC_BASIC.decode())])
        client.write(delete)
        pump()
        drain(server)
        server.write(http1_response(404, "Not Found", [("Content-Type", yang)], ERRORS_JSON))
        pump()
        drain(client)

    write = cap is None
    cap = Capture() if write else cap
    tcp = Tcp(cap, "10.80.0.20", client_port, "198.51.100.91", 443, 7000, 8000)
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
    builders = {"restconf_cleartext.pcap": build_restconf_cleartext}
    for name, builder in builders.items():
        path = os.path.join(out_dir, name)
        builder().write(path)
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
