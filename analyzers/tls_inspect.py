#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. TLS Handshake Detector

TlsDetector (deterministic): reassembles the first bytes of each TCP direction
(in order, at most MAX_STREAM_BYTES) from the raw payloads both extraction
backends provide, finds TLS by content on any port, and parses the cleartext
part of the handshake:
    - ClientHello: SNI, offered versions (supported_versions, else the legacy
      version), cipher suites, ALPN, supported groups, key share groups, and
      whether Encrypted Client Hello was offered (GREASE values dropped)
    - ServerHello: the chosen version, cipher suite, ALPN, key share group, and
      HelloRetryRequest
    - TLS 1.2 and older: the server certificate chain is cleartext; the leaf
      subject, issuer, validity (checked against the capture time) and DNS names
      are read when the cryptography package is installed. In TLS 1.3 the
      certificate is encrypted and the report says so.
    - cleartext alerts (handshake_failure, protocol_version, unknown_ca, ...)
    - a check against a baseline passed as a parameter:
        {"min_version": "TLS1.2", "versions": ["TLS1.3"], "cipher_suites": [names or "0x1301"],
         "require_sni": true, "alpn": ["h2", "http/1.1"], "require_forward_secrecy": true,
         "forbid_weak_offers": true}
      Without one, a chosen version below TLS 1.2 or a weak chosen suite is still flagged.

QUIC (TLS inside UDP), STARTTLS upgrades and DTLS are not decoded.

Author: Raymond A Rizzo | Zombat
"""

import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from analyzers.dataplane_common import endpoint, seq_delta, transport
from analyzers.network_common import Context, cap, make_event, make_issue, sort_issues, status_from_issues

MAX_STREAM_BYTES = 16384
MAX_STREAMS = 4000
MAX_PENDING_SEGMENTS = 32

VERSIONS = {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
VERSION_RANK = {"SSL3.0": 0, "TLS1.0": 1, "TLS1.1": 2, "TLS1.2": 3, "TLS1.3": 4}

CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256", 0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA", 0x003B: "TLS_RSA_WITH_NULL_SHA256", 0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x5600: "TLS_FALLBACK_SCSV",
}
WEAK_MARKERS = ("RC4", "3DES", "_DES_", "DES40", "NULL", "EXPORT", "anon", "_MD5")
SIGNALING = {0x00FF, 0x5600}

GROUPS = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448",
          0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096", 0x11EC: "X25519MLKEM768",
          0x11EB: "SecP256r1MLKEM768", 0x6399: "X25519Kyber768Draft00", 0x0201: "MLKEM768", 0x0202: "MLKEM1024"}

ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
          40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
          45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
          49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
          71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
          109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
          116: "certificate_required", 120: "no_application_protocol"}

HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

LIMITS = [
    "Only the cleartext handshake is read. In TLS 1.3 everything after the ServerHello is encrypted: the "
    "certificate, the server's extensions and any later alert cannot be seen. In TLS 1.2 and older the "
    "certificate is visible and is read here.",
    "Certificate trust (chain to a trusted root, revocation) is not judged; only what the certificate says.",
    "In TLS 1.3 the server's ALPN choice travels in the encrypted EncryptedExtensions message, so server_chose.alpn "
    "is null and an ALPN baseline is checked only for TLS 1.2 and older.",
    "With Encrypted Client Hello the visible SNI is the outer, public name, not the real server name.",
    "A handshake split across segments is reassembled from the first bytes of each direction; one that starts "
    "before the capture, or whose segments were lost before the capture point, cannot be read.",
    "QUIC, DTLS and STARTTLS are not decoded.",
]


def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def suite_name(code: int) -> str:
    return CIPHER_SUITES.get(code, f"0x{code:04x}")


def suite_is_weak(name: str) -> bool:
    return any(marker in name for marker in WEAK_MARKERS)


def suite_has_forward_secrecy(name: str) -> bool:
    return name.startswith("TLS_ECDHE_") or name.startswith("TLS_DHE_") or (name.startswith("TLS_") and "_WITH_" not in name)


def normalize_version(value: Any) -> Optional[str]:
    """'TLS1.3', 'TLSv1.3', 'TLS 1.3', '1.3', 0x0304 -> 'TLS1.3'."""
    if isinstance(value, int):
        return VERSIONS.get(value)
    text = str(value).strip().upper().replace(" ", "").replace("V1", "1")
    if text.startswith("1."):
        text = "TLS" + text
    if text in ("SSL3", "SSL3.0", "SSLV3"):
        return "SSL3.0"
    return text if text in VERSION_RANK else None


def normalize_suite(value: Any) -> str:
    if isinstance(value, int):
        return suite_name(value)
    text = str(value).strip()
    if text.lower().startswith("0x"):
        try:
            return suite_name(int(text, 16))
        except ValueError:
            return text
    return text.upper() if text.upper() in {v.upper() for v in CIPHER_SUITES.values()} else text


def _u16(data: bytes, pos: int) -> int:
    return struct.unpack("!H", data[pos:pos + 2])[0]


def _parse_extensions(data: bytes) -> Dict[int, bytes]:
    out = {}
    pos = 0
    while pos + 4 <= len(data):
        etype, elen = struct.unpack("!HH", data[pos:pos + 4])
        out.setdefault(etype, data[pos + 4:pos + 4 + elen])
        pos += 4 + elen
    return out


def _alpn_list(body: bytes) -> List[str]:
    out = []
    if len(body) < 2:
        return out
    pos, end = 2, 2 + _u16(body, 0)
    while pos < min(end, len(body)):
        length = body[pos]
        out.append(body[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return out


def parse_client_hello(body: bytes) -> Optional[Dict[str, Any]]:
    try:
        legacy = _u16(body, 0)
        pos = 34
        pos += 1 + body[pos]
        cs_len = _u16(body, pos)
        suites = [_u16(body, pos + 2 + i) for i in range(0, cs_len, 2)]
        pos += 2 + cs_len
        pos += 1 + body[pos]
        exts = _parse_extensions(body[pos + 2:pos + 2 + _u16(body, pos)]) if pos + 2 <= len(body) else {}
    except (IndexError, struct.error):
        return None
    sni = None
    if 0 in exts and len(exts[0]) >= 5 and exts[0][2] == 0:
        sni = exts[0][5:5 + _u16(exts[0], 3)].decode("ascii", "replace")
    versions = []
    if 43 in exts and exts[43]:
        raw = exts[43][1:1 + exts[43][0]]
        versions = [_u16(raw, i) for i in range(0, len(raw) - 1, 2)]
    versions = [v for v in versions if not is_grease(v)] or [legacy]
    groups = []
    if 10 in exts and len(exts[10]) >= 2:
        groups = [_u16(exts[10], 2 + i) for i in range(0, _u16(exts[10], 0), 2) if 2 + i + 2 <= len(exts[10])]
    shares = []
    if 51 in exts and len(exts[51]) >= 2:
        data, pos = exts[51], 2
        while pos + 4 <= len(data):
            group, klen = struct.unpack("!HH", data[pos:pos + 4])
            shares.append(group)
            pos += 4 + klen
    return {
        "sni": sni,
        "legacy_version": VERSIONS.get(legacy, f"0x{legacy:04x}"),
        "versions": [VERSIONS.get(v, f"0x{v:04x}") for v in versions],
        "cipher_suites": [suite_name(s) for s in suites if not is_grease(s)],
        "alpn": _alpn_list(exts[16]) if 16 in exts else [],
        "groups": [GROUPS.get(g, f"0x{g:04x}") for g in groups if not is_grease(g)],
        "key_share_groups": [GROUPS.get(g, f"0x{g:04x}") for g in shares if not is_grease(g)],
        "ech_offered": 0xFE0D in exts,
        "extensions": len(exts),
    }


def parse_server_hello(body: bytes) -> Optional[Dict[str, Any]]:
    try:
        legacy = _u16(body, 0)
        random = body[2:34]
        pos = 34
        pos += 1 + body[pos]
        suite = _u16(body, pos)
        pos += 3
        exts = _parse_extensions(body[pos + 2:pos + 2 + _u16(body, pos)]) if pos + 2 <= len(body) else {}
    except (IndexError, struct.error):
        return None
    version = _u16(exts[43], 0) if 43 in exts and len(exts[43]) >= 2 else legacy
    alpn = _alpn_list(exts[16]) if 16 in exts else []
    group = _u16(exts[51], 0) if 51 in exts and len(exts[51]) >= 2 else None
    return {"version": VERSIONS.get(version, f"0x{version:04x}"), "cipher_suite": suite_name(suite),
            "alpn": alpn[0] if alpn else None, "key_share_group": GROUPS.get(group, f"0x{group:04x}") if group else None,
            "hello_retry_request": random == HRR_RANDOM}


def parse_certificate(body: bytes, capture_time: float) -> Dict[str, Any]:
    """The leaf certificate of a TLS <= 1.2 Certificate message."""
    out: Dict[str, Any] = {"visible": True, "chain_length": 0}
    try:
        total = int.from_bytes(body[0:3], "big")
        pos, certs = 3, []
        while pos + 3 <= min(len(body), 3 + total):
            length = int.from_bytes(body[pos:pos + 3], "big")
            certs.append(body[pos + 3:pos + 3 + length])
            pos += 3 + length
    except IndexError:
        return out
    out["chain_length"] = len(certs)
    if not certs:
        return out
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        out["parsed"] = False
        out["note"] = "install the cryptography package to read subject, issuer and validity"
        return out
    try:
        cert = x509.load_der_x509_certificate(certs[0])
    except Exception as exc:  # truncated or malformed DER
        out["parsed"] = False
        out["note"] = f"leaf certificate not parsed: {type(exc).__name__}"
        return out

    def cn(name):
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()

    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.fromtimestamp(capture_time, tz=timezone.utc)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    out.update({"parsed": True, "subject": cn(cert.subject), "issuer": cn(cert.issuer),
                "self_signed": cert.subject == cert.issuer,
                "not_before": not_before.isoformat().replace("+00:00", "Z"),
                "not_after": not_after.isoformat().replace("+00:00", "Z"),
                "valid_at_capture_time": not_before <= now <= not_after, "dns_names": list(san)[:20]})
    return out


class _Stream:
    """In-order reassembly of the first bytes of one TCP direction, parsed as TLS records."""

    def __init__(self, base: int):
        self.base = base
        self.buf = bytearray()
        self.pending: Dict[int, bytes] = {}
        self.pos = 0
        self.hs = bytearray()
        self.encrypted = False
        self.done = False
        self.full = False

    def add(self, seq: int, payload: bytes, truncated: bool):
        rel = seq_delta(seq, self.base)
        if rel > len(self.buf):
            if len(self.pending) < MAX_PENDING_SEGMENTS:
                self.pending[rel] = payload
            return
        if rel + len(payload) > len(self.buf):
            self.buf += payload[len(self.buf) - rel:]
        while len(self.buf) in self.pending:
            part = self.pending.pop(len(self.buf))
            self.buf += part
        if truncated or len(self.buf) >= MAX_STREAM_BYTES:
            self.full = True  # parse what is here, then stop


class TlsDetector:
    """TLS handshake inspection with an optional baseline check."""

    name = "tls"

    def __init__(self, baseline: Optional[Dict[str, Any]] = None):
        self.baseline = dict(baseline or {})
        self.streams: Dict[tuple, _Stream] = {}
        self.sessions: Dict[tuple, Dict[str, Any]] = {}
        self.ignored = set()
        self.dropped = 0

    def feed(self, rec: Dict[str, Any]):
        view = transport(rec)
        if view is None or not view["tcp"] or not view["dtcp"]:
            return
        dp = rec["dp"]
        payload = dp.get("pl")
        if not payload:
            return
        tcp = view["tcp"]
        src, dst = (view["src"], tcp["sport"]), (view["dst"], tcp["dport"])
        key = (src, dst)
        if key in self.ignored:
            return
        stream = self.streams.get(key)
        if stream is None:
            if not (payload[0] in (0x15, 0x16) and len(payload) >= 3 and payload[1] == 3 and payload[2] <= 4):
                self.ignored.add(key)
                return
            if len(self.streams) >= MAX_STREAMS:
                self.dropped += 1
                return
            stream = _Stream(view["dtcp"]["seq"])
            self.streams[key] = stream
        if stream.done:
            return
        stream.add(view["dtcp"]["seq"], payload, truncated=tcp["len"] > len(payload))
        self._parse(stream, src, dst, rec)
        if stream.full and not stream.done:
            stream.done = True
            stream.buf = bytearray()
            stream.pending.clear()

    def _session(self, src, dst, rec, client_side: bool):
        client, server = (src, dst) if client_side else (dst, src)
        key = (client, server)
        session = self.sessions.get(key)
        if session is None:
            session = {"client": client, "server": server, "client_hello": None, "server_hello": None,
                       "certificate": None, "alerts": [], "frames": {}, "first_t": rec["t"],
                       "server_spoke_tls": False}
            self.sessions[key] = session
        return session

    def _parse(self, stream: _Stream, src, dst, rec):
        buf = stream.buf
        while not stream.done and stream.pos + 5 <= len(buf):
            ctype, _ver, length = buf[stream.pos], _u16(buf, stream.pos + 1), _u16(buf, stream.pos + 3)
            if ctype not in (20, 21, 22, 23) or length > 18432:
                stream.done = True
                break
            if stream.pos + 5 + length > len(buf):
                break
            body = bytes(buf[stream.pos + 5:stream.pos + 5 + length])
            stream.pos += 5 + length
            if ctype == 20:
                stream.encrypted = True
            elif ctype == 23:
                stream.done = True
            elif ctype == 21:
                session = self._find_session(src, dst, rec)
                if not stream.encrypted and len(body) == 2:
                    session["alerts"].append({"from": endpoint(*src), "level": "fatal" if body[0] == 2 else "warning",
                                              "description": ALERTS.get(body[1], f"alert {body[1]}"),
                                              "frame": rec["n"], "t": rec["t"]})
                else:
                    session["alerts"].append({"from": endpoint(*src), "level": "encrypted",
                                              "description": "encrypted alert (content not visible)",
                                              "frame": rec["n"], "t": rec["t"]})
            elif ctype == 22 and not stream.encrypted:
                stream.hs += body
                self._handshake(stream, src, dst, rec)
            elif ctype == 22:
                pass  # encrypted handshake (TLS 1.2 Finished after CCS)
        if stream.done:
            stream.buf = bytearray()
            stream.pending.clear()

    def _find_session(self, src, dst, rec):
        if (src, dst) in self.sessions:
            return self.sessions[(src, dst)]
        if (dst, src) in self.sessions:
            return self.sessions[(dst, src)]
        return self._session(src, dst, rec, client_side=True)

    def _handshake(self, stream: _Stream, src, dst, rec):
        hs = stream.hs
        while len(hs) >= 4:
            htype = hs[0]
            hlen = int.from_bytes(hs[1:4], "big")
            if len(hs) < 4 + hlen:
                break
            body = bytes(hs[4:4 + hlen])
            del hs[:4 + hlen]
            if htype == 1:
                session = self._session(src, dst, rec, client_side=True)
                session["client_hello"] = parse_client_hello(body)
                session["frames"]["client_hello"] = rec["n"]
                session["first_t"] = min(session["first_t"], rec["t"])
            elif htype == 2:
                session = self._session(src, dst, rec, client_side=False)
                parsed = parse_server_hello(body)
                session["server_spoke_tls"] = True
                if parsed and parsed["hello_retry_request"]:
                    session["hello_retry_request"] = True
                    session["frames"]["hello_retry_request"] = rec["n"]
                    continue
                session["server_hello"] = parsed
                session["frames"]["server_hello"] = rec["n"]
                session["server_hello_t"] = rec["t"]
                if parsed and parsed["version"] == "TLS1.3":
                    stream.encrypted = True
                    stream.done = True
                    return
            elif htype == 11:
                session = self._session(src, dst, rec, client_side=False)
                session["certificate"] = parse_certificate(body, rec["t"])
                session["frames"]["certificate"] = rec["n"]
            elif htype == 14:  # ServerHelloDone: nothing cleartext follows that we read
                stream.done = True
                return

    # -- report -------------------------------------------------------------------

    def present(self) -> bool:
        return bool(self.sessions)

    def _check(self, session) -> List[Dict[str, Any]]:
        violations = []
        base = self.baseline
        ch, sh = session["client_hello"] or {}, session["server_hello"] or {}
        chosen_version = sh.get("version")
        chosen_suite = sh.get("cipher_suite")
        allowed_versions = [normalize_version(v) for v in base.get("versions", [])]
        allowed_versions = [v for v in allowed_versions if v]
        min_version = normalize_version(base["min_version"]) if base.get("min_version") else None
        if chosen_version and chosen_version in VERSION_RANK:
            if allowed_versions and chosen_version not in allowed_versions:
                violations.append(make_issue("error", "TLS_BASELINE_VERSION",
                                             f"negotiated {chosen_version}, baseline allows {', '.join(allowed_versions)}"))
            elif min_version and VERSION_RANK[chosen_version] < VERSION_RANK[min_version]:
                violations.append(make_issue("error", "TLS_BASELINE_VERSION",
                                             f"negotiated {chosen_version}, below the baseline minimum {min_version}"))
            elif not allowed_versions and not min_version and VERSION_RANK[chosen_version] < VERSION_RANK["TLS1.2"]:
                violations.append(make_issue("warning", "TLS_OLD_VERSION",
                                             f"negotiated {chosen_version} (deprecated by RFC 8996)"))
        if chosen_suite:
            allowed = [normalize_suite(s).upper() for s in base.get("cipher_suites", [])]
            if allowed and chosen_suite.upper() not in allowed:
                violations.append(make_issue("error", "TLS_BASELINE_CIPHER",
                                             f"chose {chosen_suite}, not in the baseline list"))
            if suite_is_weak(chosen_suite):
                violations.append(make_issue("error", "TLS_WEAK_CIPHER_CHOSEN",
                                             f"chose a weak cipher suite {chosen_suite}"))
            if base.get("require_forward_secrecy") and not suite_has_forward_secrecy(chosen_suite):
                violations.append(make_issue("error", "TLS_NO_FORWARD_SECRECY",
                                             f"chose {chosen_suite}: static RSA key exchange, no forward secrecy"))
        if base.get("require_sni") and ch and not ch.get("sni"):
            violations.append(make_issue("warning", "TLS_BASELINE_SNI", "ClientHello carries no SNI"))
        if base.get("alpn") and sh and chosen_version != "TLS1.3":  # TLS 1.3 sends the choice encrypted
            allowed_alpn = list(base["alpn"])
            if sh.get("alpn") not in allowed_alpn:
                violations.append(make_issue("warning", "TLS_BASELINE_ALPN",
                                             f"ALPN {sh.get('alpn')!r} not in {allowed_alpn}"))
        if ch:
            weak = [s for s in ch.get("cipher_suites", []) if suite_is_weak(s)]
            old = [v for v in ch.get("versions", []) if v in VERSION_RANK and VERSION_RANK[v] < VERSION_RANK["TLS1.2"]]
            if weak or old:
                severity = "warning" if base.get("forbid_weak_offers") else "info"
                text = "client offered"
                if weak:
                    text += f" weak suites {', '.join(weak[:5])}"
                if old:
                    text += f"{' and' if weak else ''} versions {', '.join(old)}"
                violations.append(make_issue(severity, "TLS_WEAK_OFFERED", text))
        cert = session.get("certificate")
        if cert and cert.get("parsed") and not cert.get("valid_at_capture_time"):
            violations.append(make_issue("error", "TLS_CERT_NOT_VALID", f"server certificate valid {cert['not_before']} to {cert['not_after']}, "
                                          "not at capture time"))
        return violations

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        sessions = []
        for session in sorted(self.sessions.values(), key=lambda s: s["first_t"]):
            sh = session["server_hello"]
            version = sh["version"] if sh else None
            if sh is None:
                certificate = {"visible": False, "reason": "no ServerHello seen"}
            elif version == "TLS1.3":
                certificate = {"visible": False, "reason": "TLS 1.3 encrypts the certificate; not visible"}
            else:
                certificate = session["certificate"] or {"visible": False,
                                                         "reason": "Certificate message not captured (resumed "
                                                                   "session, or segments missing)"}
            violations = self._check(session)
            label = f"{endpoint(*session['client'])} -> {endpoint(*session['server'])}"
            sni = (session["client_hello"] or {}).get("sni")
            frames = sorted(set(session["frames"].values()))
            for alert in session["alerts"]:
                if alert["level"] == "fatal" or alert["description"] not in ("close_notify",):
                    if alert["level"] == "encrypted":
                        continue
                    text = f"TLS {label}: {alert['level']} alert {alert['description']} from {alert['from']}"
                    issues.append(make_issue("error" if alert["level"] == "fatal" else "warning", "TLS_ALERT", text,
                                             [alert["frame"]]))
                    events.append(make_event(ctx, alert["t"], "tls", "alert", text, alert["frame"]))
            if session["client_hello"] and not sh and not session["alerts"]:
                text = f"TLS {label}: ClientHello (SNI {sni}) with no ServerHello seen"
                issues.append(make_issue("warning", "TLS_NO_SERVER_HELLO", text, frames))
                events.append(make_event(ctx, session["first_t"], "tls", "no_server_hello", text, frames[0] if frames else None))
            for v in violations:
                issues.append(dict(v, message=f"TLS {label} (SNI {sni}): {v['message']}", frames=frames))
            if sh:
                events.append(make_event(ctx, session.get("server_hello_t", session["first_t"]), "tls", "handshake",
                                         f"TLS {label} SNI {sni}: {version} {sh['cipher_suite']}",
                                         session["frames"].get("server_hello")))
            sessions.append({
                "client": endpoint(*session["client"]), "server": endpoint(*session["server"]), "sni": sni,
                "client_offered": session["client_hello"], "server_chose": sh,
                "hello_retry_request": bool(session.get("hello_retry_request")),
                "certificate": certificate,
                "alerts": [{k: v for k, v in a.items() if k != "t"} for a in session["alerts"]],
                "baseline_pass": not any(v["severity"] == "error" for v in violations) if self.baseline else None,
                "findings": violations, "frames": session["frames"], "first_t": ctx.rel(session["first_t"]),
            })
        present = self.present()
        status = status_from_issues(issues, present)
        if not present:
            verdict = "No TLS handshake in this capture."
        else:
            versions: Dict[str, int] = {}
            for s in sessions:
                if s["server_chose"]:
                    versions[s["server_chose"]["version"]] = versions.get(s["server_chose"]["version"], 0) + 1
            failing = [s for s in sessions if s["baseline_pass"] is False]
            verdict = f"{len(sessions)} TLS handshake(s)"
            if versions:
                verdict += ": " + ", ".join(f"{n} {v}" for v, n in sorted(versions.items()))
            unanswered = sum(1 for s in sessions if s["client_offered"] and not s["server_chose"])
            if unanswered:
                verdict += f"; {unanswered} without ServerHello"
            if self.baseline:
                verdict += (f"; {len(failing)} fail the baseline" if failing else "; all meet the baseline")
            verdict += "."
        listed, omitted = cap(sessions, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "baseline": self.baseline or None,
            "summary": {"handshakes": len(sessions), "streams_dropped_at_cap": self.dropped,
                        "baseline_failures": sum(1 for s in sessions if s["baseline_pass"] is False)},
            "sessions": listed,
            "sessions_omitted": omitted,
            "limits": LIMITS,
            "issues": sort_issues(issues),
            "events": events,
        }
