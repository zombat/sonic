#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. TACACS+ and RADIUS Test Fixtures (synthetic)

Generates the small, deterministic pcaps the AAA troubleshooting tests read, built with
scapy (its RADIUS layer and the contrib TACACS+ layer) at fixed addresses (RFC 5737),
fixed timestamps, fixed ids and throwaway keys, so two runs produce identical files. Names
start with aaa_. Every credential and key in them is a synthetic placeholder, defined here.

    aaa_radius.pcap   RADIUS to udp/1812-1813: an Access-Request (User-Password, NAS-IP,
                      Calling-Station, a valid Message-Authenticator) answered by an Access-Accept
                      with a valid Message-Authenticator; a second Access-Request answered by an
                      Access-Reject without one; a third whose Message-Authenticator was altered,
                      left unanswered; an Accounting Start and Stop answered Accounting-Response.
                      The User-Password is encrypted with the shared secret and the request
                      authenticator (RFC 2865); each
                      response carries a valid Response Authenticator.
    aaa_tacacs.pcap   TACACS+ to tcp/49: an authentication login (START, REPLY GETPASS,
                      CONTINUE with the password, REPLY PASS), an authorization (REQUEST,
                      REPLY PASS_ADD) and accounting (REQUEST, REPLY SUCCESS) for one session;
                      a second session whose authentication REPLY is FAIL; and a third session
                      sent with the unencrypted flag set (its body in cleartext). Obfuscated
                      bodies are built by scapy with the shared key (contrib tacacs SECRET).

The keys and passwords are never real. The tests pass the key to tshark through a key file
written at test time, and assert no key, password or recovered secret appears in the report.
"""

import hashlib
import hmac
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate_dataplane_fixtures import Capture  # noqa: E402
from scapy.all import IP, TCP, UDP, Ether, Raw  # noqa: E402
from scapy.layers.radius import Radius, RadiusAttribute  # noqa: E402
import scapy.contrib.tacacs as tac  # noqa: E402

RADIUS_SECRET = "radius-shared-secret-not-real"
TACACS_KEY = "tacacs-shared-key-not-real"
SYNTHETIC_PASSWORD = "user-password-not-real"
SYNTHETIC_TACACS_PASSWORD = "enable-password-not-real"

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


def _eth(ip_layer, from_client):
    src, dst = (MAC_A, MAC_B) if from_client else (MAC_B, MAC_A)
    return Ether(src=src, dst=dst) / ip_layer


def radius_encrypt(password, secret, authenticator):
    """RFC 2865 User-Password encryption."""
    pw = password.encode()
    pw += b"\x00" * ((16 - len(pw) % 16) % 16)
    out = b""
    last = authenticator
    for i in range(0, len(pw), 16):
        pad = hashlib.md5(secret.encode() + last).digest()
        chunk = bytes(x ^ y for x, y in zip(pw[i:i + 16], pad))
        out += chunk
        last = chunk
    return out


def _attr_offset(packet_bytes, attr_type):
    """The offset of an attribute's value in a RADIUS message (walking the attributes, not searching)."""
    pos = 20
    while pos + 2 <= len(packet_bytes):
        if packet_bytes[pos] == attr_type:
            return pos + 2
        pos += packet_bytes[pos + 1]
    raise ValueError(f"no attribute {attr_type}")


def _with_message_authenticator(packet_bytes, secret):
    """
    Patch a valid Message-Authenticator (RFC 3579 3.2): HMAC-MD5 keyed with the secret over the message
    with the attribute zeroed; for a response the authenticator field must hold the request's when called.
    """
    pos = _attr_offset(packet_bytes, 80)
    data = bytearray(packet_bytes)
    data[pos:pos + 16] = b"\x00" * 16
    data[pos:pos + 16] = hmac.new(secret.encode(), bytes(data), hashlib.md5).digest()
    return bytes(data)


def _response_authenticator(resp_bytes, request_authenticator, secret):
    """RFC 2865 Response Authenticator = MD5(code+id+len+ReqAuth+attrs+secret)."""
    data = bytearray(resp_bytes)
    data[4:20] = request_authenticator
    ra = hashlib.md5(bytes(data) + secret.encode()).digest()
    data[4:20] = ra
    return bytes(data)


def build_radius():
    cap = Capture()
    client, server = "10.90.0.10", "198.51.100.20"
    # --- Access-Request / Accept (user alice) with a Message-Authenticator ---
    req_auth = bytes(range(16))
    attrs = [
        RadiusAttribute(type=1, value=b"alice"),
        RadiusAttribute(type=2, value=radius_encrypt(SYNTHETIC_PASSWORD, RADIUS_SECRET, req_auth)),
        RadiusAttribute(type=4, value=bytes([203, 0, 113, 9])),  # NAS-IP-Address
        RadiusAttribute(type=31, value=b"00-11-22-33-44-55"),    # Calling-Station-Id
        RadiusAttribute(type=80, value=b"\x00" * 16),            # Message-Authenticator (patched below)
    ]
    req = bytes(Radius(code=1, id=10, authenticator=req_auth, attributes=attrs))
    req = _with_message_authenticator(req, RADIUS_SECRET)
    cap.add(0.0, _eth(IP(src=client, dst=server) / UDP(sport=50010, dport=1812) / Raw(req), True))
    # The Accept carries a Message-Authenticator too, computed over the request's authenticator, and
    # then its Response Authenticator over the message as sent (RFC 3579 3.2, RFC 2865 3).
    accept = bytes(Radius(code=2, id=10, authenticator=req_auth,
                          attributes=[RadiusAttribute(type=80, value=b"\x00" * 16),
                                      RadiusAttribute(type=18, value=b"Welcome")]))
    accept = _response_authenticator(_with_message_authenticator(accept, RADIUS_SECRET), req_auth, RADIUS_SECRET)
    cap.add(0.02, _eth(IP(src=server, dst=client) / UDP(sport=1812, dport=50010) / Raw(accept), False))

    # --- Access-Request / Reject (user mallory) ---
    req_auth2 = bytes(range(16, 32))
    attrs2 = [RadiusAttribute(type=1, value=b"mallory"),
              RadiusAttribute(type=2, value=radius_encrypt("wrong-password-not-real", RADIUS_SECRET, req_auth2)),
              RadiusAttribute(type=4, value=bytes([203, 0, 113, 9]))]
    req2 = bytes(Radius(code=1, id=11, authenticator=req_auth2, attributes=attrs2))
    cap.add(0.10, _eth(IP(src=client, dst=server) / UDP(sport=50010, dport=1812) / Raw(req2), True))
    reject = bytes(Radius(code=3, id=11, authenticator=b"\x00" * 16,
                          attributes=[RadiusAttribute(type=18, value=b"Access denied")]))
    reject = _response_authenticator(reject, req_auth2, RADIUS_SECRET)  # no Message-Authenticator
    cap.add(0.12, _eth(IP(src=server, dst=client) / UDP(sport=1812, dport=50010) / Raw(reject), False))

    # --- Access-Request (user eve) whose Message-Authenticator was altered; the server drops it ---
    req_auth3 = bytes(range(32, 48))
    attrs3 = [RadiusAttribute(type=1, value=b"eve"),
              RadiusAttribute(type=2, value=radius_encrypt(SYNTHETIC_PASSWORD, RADIUS_SECRET, req_auth3)),
              RadiusAttribute(type=80, value=b"\x00" * 16)]
    eve = bytes(Radius(code=1, id=12, authenticator=req_auth3, attributes=attrs3))
    req3 = bytearray(_with_message_authenticator(eve, RADIUS_SECRET))
    req3[_attr_offset(bytes(req3), 80)] ^= 0xFF
    cap.add(0.15, _eth(IP(src=client, dst=server) / UDP(sport=50010, dport=1812) / Raw(bytes(req3)), True))

    # --- Accounting Start / Response, then Stop / Response ---
    for seq, (status, start_t, rid) in enumerate([(1, 0.20, 20), (2, 0.40, 21)]):
        acct_attrs = [RadiusAttribute(type=1, value=b"alice"), RadiusAttribute(type=40, value=bytes([0, 0, 0, status])),
                      RadiusAttribute(type=44, value=b"sess-0001"), RadiusAttribute(type=4, value=bytes([203, 0, 113, 9]))]
        # Accounting-Request authenticator = MD5(code+id+len+16 zeros+attrs+secret)
        acct = bytearray(Radius(code=4, id=rid, authenticator=b"\x00" * 16, attributes=acct_attrs).__bytes__())
        ra = hashlib.md5(bytes(acct) + RADIUS_SECRET.encode()).digest()
        acct[4:20] = ra
        cap.add(start_t, _eth(IP(src=client, dst=server) / UDP(sport=50010, dport=1813) / Raw(bytes(acct)), True))
        resp = bytes(Radius(code=5, id=rid, authenticator=b"\x00" * 16))
        resp = _response_authenticator(resp, bytes(ra), RADIUS_SECRET)
        cap.add(start_t + 0.02, _eth(IP(src=server, dst=client) / UDP(sport=1813, dport=50010) / Raw(resp), False))
    return cap


def _tac(session_id, seq, ptype, body, flags=0):
    return bytes(tac.TacacsHeader(version=0xc0, type=ptype, seq=seq, flags=flags, session_id=session_id) / body)


class _TacConn:
    """One TCP connection for one TACACS+ session, with a SYN handshake and ordered segments."""

    def __init__(self, cap, client, server, cport, t):
        self.cap, self.client, self.server, self.cport = cap, client, server, cport
        self.seq = {True: 1000, False: 5000}
        # three-way handshake, so each session is a distinct, clean TCP stream for tshark
        self._seg(t, True, "S")
        self._seg(t + 0.001, False, "SA")
        self._seg(t + 0.002, True, "A")

    def _seg(self, t, from_client, flags, payload=b""):
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sport, dport = (self.cport, 49) if from_client else (49, self.cport)
        seq, ack = self.seq[from_client], self.seq[not from_client]
        self.cap.add(t, _eth(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
                             / (Raw(payload) if payload else b""), from_client))
        self.seq[from_client] += len(payload) + (1 if "S" in flags else 0)

    def send(self, t, from_client, payload):
        self._seg(t, from_client, "PA", payload)


def build_tacacs():
    cap = Capture()
    client, server = "10.90.0.11", "198.51.100.21"
    tac.SECRET = TACACS_KEY  # scapy obfuscates each body with this key when the unencrypted flag is clear

    # --- Session A: authentication login (PASS) ---
    sid = 0x0A0A0A0A
    a = _TacConn(cap, client, server, 40001, 0.0)
    a.send(0.01, True, _tac(sid, 1, 1, tac.TacacsAuthenticationStart(
        action=1, priv_lvl=15, authen_type=1, authen_service=1, user=b"admin", port=b"tty1",
        rem_addr=b"10.90.0.11", data=b"")))
    a.send(0.02, False, _tac(sid, 2, 1, tac.TacacsAuthenticationReply(status=5, flags=0, server_msg=b"Password: ",
                                                                      data=b"")))
    a.send(0.03, True, _tac(sid, 3, 1, tac.TacacsAuthenticationContinue(
        flags=0, user_msg=SYNTHETIC_TACACS_PASSWORD.encode(), data=b"")))
    a.send(0.04, False, _tac(sid, 4, 1, tac.TacacsAuthenticationReply(status=1, flags=0, server_msg=b"", data=b"")))

    # --- Session B: authorization (PASS_ADD) ---
    sid2 = 0x0B0B0B0B
    b = _TacConn(cap, client, server, 40002, 0.20)
    b.send(0.21, True, _tac(sid2, 1, 2, tac.TacacsAuthorizationRequest(
        authen_method=6, priv_lvl=15, authen_type=1, authen_service=1, user=b"admin", port=b"tty1",
        rem_addr=b"10.90.0.11")))
    b.send(0.22, False, _tac(sid2, 2, 2, tac.TacacsAuthorizationReply(status=1, server_msg=b"", data=b"")))

    # --- Session C: accounting (SUCCESS) ---
    sid3 = 0x0C0C0C0C
    c = _TacConn(cap, client, server, 40003, 0.40)
    c.send(0.41, True, _tac(sid3, 1, 3, tac.TacacsAccountingRequest(
        flags=2, authen_method=6, priv_lvl=15, authen_type=1, authen_service=1, user=b"admin", port=b"tty1",
        rem_addr=b"10.90.0.11")))
    c.send(0.42, False, _tac(sid3, 2, 3, tac.TacacsAccountingReply(status=1, server_msg=b"", data=b"")))

    # --- Session D: authentication FAIL ---
    sidf = 0x0D0D0D0D
    d = _TacConn(cap, client, server, 40004, 0.60)
    d.send(0.61, True, _tac(sidf, 1, 1, tac.TacacsAuthenticationStart(
        action=1, priv_lvl=1, authen_type=1, authen_service=1, user=b"baduser", port=b"tty2",
        rem_addr=b"10.90.0.11", data=b"")))
    d.send(0.62, False, _tac(sidf, 2, 1, tac.TacacsAuthenticationReply(status=2, flags=0,
                                                                       server_msg=b"Login incorrect", data=b"")))

    # --- Session E: the unencrypted flag set (cleartext body, no obfuscation) ---
    tac.SECRET = None  # scapy leaves the body plaintext; the unencrypted flag marks it so
    side = 0x0E0E0E0E
    e = _TacConn(cap, client, server, 40005, 0.80)
    e.send(0.81, True, _tac(side, 1, 1, tac.TacacsAuthenticationStart(
        action=1, priv_lvl=1, authen_type=1, authen_service=1, user=b"plainuser", port=b"tty3",
        rem_addr=b"10.90.0.11", data=b""), flags=0x01))
    tac.SECRET = TACACS_KEY
    return cap


def main():
    default_out = os.path.join(os.path.dirname(os.path.dirname(HERE)), "testdata", "fixtures")
    out_dir = sys.argv[1] if len(sys.argv) > 1 else default_out
    os.makedirs(out_dir, exist_ok=True)
    for name, builder in {"aaa_radius.pcap": build_radius, "aaa_tacacs.pcap": build_tacacs}.items():
        path = os.path.join(out_dir, name)
        builder().write(path)
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
