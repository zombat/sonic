#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. HTTP/1.1 and HTTP/2 message extraction (for RESTCONF and REST over TLS)

Reads HTTP request/response exchanges from a capture with Wireshark's own HTTP,
HTTP/2, HPACK and TLS dissectors, through tshark, decrypting TLS with the same key
log (or the Decryption Secrets Block a pcapng carries) that analyzers/grpc_inspect.py
uses. Wireshark does the hard parts: TCP reassembly, TLS decryption from a key log,
HTTP/1.1 request/response pairing, and HTTP/2 framing with HPACK.

HTTP/1.1 is read in one streamed `-T fields` pass over the `http` dissector (request
method and URI, response code and phrase, Content-Type, Location, the time since the
request, the request frame a response pairs to, and the reassembled body). HTTP/2 is
read with the shared extractors/http2.py pass (iter_http2_packets) and assembled into
request/response messages per stream here.

Header values that carry a credential are masked at the source, before anything else
sees them: an Authorization scheme (Basic, Bearer, ...) is kept but its credential is
not, and Cookie, Set-Cookie and token headers are flagged by name with the value
dropped. The masked values are kept only in memory (secret_values) so the analyzer can
scrub any echo of one from its report; they are never written into a record. The key
log is handed to tshark by path only (never read or copied here); extractors/tls_secrets.py
reads which sessions the secrets cover (labels and client randoms only).

Author: Raymond A Rizzo | Zombat
"""

import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

from extractors.http2 import (
    CREDENTIAL_NAME, GRPC_PORTS, TcpConnection, _int, iter_http2_packets,
)

# Ports where HTTP or HTTPS (and so RESTCONF or REST) commonly listen. A TLS connection
# on one of these, or offering ALPN http/1.1 or h2, is decoded as TLS then HTTP.
FIELD_SEP = "\x1f"  # tshark -E aggregator: joins repeated field occurrences within one layer

HTTP_PORTS = {
    80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt", 8008: "http-alt", 8888: "http-alt",
    4443: "https-alt",
}

# RESTCONF media types (RFC 8040) and NETCONF-style notification feeds; a request on a
# /restconf or /.well-known/host-meta path is RESTCONF whatever the type.
RESTCONF_TYPES = (
    "application/yang-data+json", "application/yang-data+xml", "application/yang.data+json",
    "application/yang.data+xml", "application/yang-patch+json", "application/yang-patch+xml",
    "application/yang.patch+json", "application/yang.patch+xml", "application/yang.api+json",
    "application/yang.api+xml", "application/yang-errors+json", "application/yang-errors+xml",
)
MAX_BODY_KEEP = 1 << 16  # bytes of a response body read for RESTCONF error parsing

HTTP1_FIELDS = [
    "frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport",
    "http.request.method", "http.request.uri", "http.request.version", "http.host",
    "http.response.code", "http.response.phrase", "http.response.version",
    "http.content_type", "http.location", "http.time", "http.request_in", "http.response_in",
    "http.authorization", "http.proxy_authorization", "http.www_authenticate", "http.cookie", "http.set_cookie",
    "http.request.line", "http.response.line", "http.content_length_header", "http.file_data",
]


def is_restconf(path: Optional[str], content_types: Tuple[Optional[str], ...]) -> bool:
    """Whether a request looks like RESTCONF, from its path or any of its content types."""
    if path and ("/restconf" in path or "/.well-known/host-meta" in path):
        return True
    for content in content_types:
        if content and any(content.lower().startswith(t) for t in RESTCONF_TYPES):
            return True
    return False


def _auth_scheme(value: str) -> str:
    """The scheme word of an Authorization header value (Basic, Bearer, Digest, ...), lower-cased label kept."""
    token = value.split(None, 1)[0] if value else ""
    return token or "credentials"


def _mask_credential(secrets: Set[str], value: Optional[str]) -> None:
    """Record a credential value so the analyzer can scrub any echo of it (never emitted as data)."""
    if value and len(value) >= 4:
        secrets.add(value)
        # Authorization values are "<scheme> <credential>": the credential alone may be quoted elsewhere.
        if " " in value:
            secrets.add(value.split(None, 1)[1])


def _header_lines(raw: str) -> List[Tuple[str, str]]:
    """(name, value) pairs from aggregated http.request.line / http.response.line output."""
    out: List[Tuple[str, str]] = []
    for line in (raw.split(FIELD_SEP) if FIELD_SEP in raw else re.split(r"\\r\\n,?", raw)):
        line = line.rstrip("\r\n").rstrip("\\r\\n")
        if ":" in line:
            name, _, value = line.partition(":")
            out.append((name.strip(), value.strip()))
    return out


def _credentials_from_lines(lines: List[Tuple[str, str]], secrets: Set[str]) -> List[Dict[str, str]]:
    """Credential-bearing headers (token headers, API keys) from raw header lines, values masked."""
    found: List[Dict[str, str]] = []
    for name, value in lines:
        low = name.lower()
        if low in ("authorization", "proxy-authorization", "cookie", "set-cookie", "host", "content-type",
                   "accept", "content-length", "user-agent", "location", "www-authenticate"):
            continue  # handled by their own dedicated fields
        if CREDENTIAL_NAME.search(low):
            _mask_credential(secrets, value)
            found.append({"header": name, "kind": "token", "value": "masked"})
    return found


def plan_http_decode_as(conns: Dict[int, TcpConnection], extra_ports: Optional[List[int]] = None
                        ) -> Tuple[List[str], Dict[int, str]]:
    """
    tshark decode-as for the HTTP passes, and why each port is decoded.

    A TLS connection on an HTTP(S) or gRPC port, or offering ALPN h2 or http/1.1, is
    decoded as TLS (HTTP or HTTP/2 inside follows ALPN, the port association, or the
    heuristic). A plaintext HTTP(S) port is decoded as http.
    """
    reasons: Dict[int, str] = {}
    want = set(HTTP_PORTS) | set(GRPC_PORTS) | set(extra_ports or [])
    plain_http = set(HTTP_PORTS) | set(extra_ports or [])
    for conn in sorted(conns.values(), key=lambda c: c.first_frame):
        port = conn.service_port()
        alpn = set(conn.alpn)
        if conn.is_tls() and (port in want or alpn & {"h2", "http/1.1"}):
            reasons.setdefault(port, "tls_http")
        elif not conn.is_tls() and conn.preface_frame is not None:
            reasons.setdefault(port, "h2c")  # cleartext HTTP/2 by its preface, on any port
        elif not conn.is_tls() and port in plain_http:
            reasons.setdefault(port, "http_port")
    decode = {"tls_http": "tls", "h2c": "http2", "http_port": "http"}
    options: List[str] = []
    for port, reason in sorted(reasons.items()):
        options += ["-d", f"tcp.port=={port},{decode[reason]}"]
    return options, reasons


def http1_messages(file_path: str, decode_as: List[str], keylog_file: Optional[str] = None,
                   display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                   out_of_order: bool = True) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """
    HTTP/1.x request and response messages from the capture, paired, through the `http` dissector.

    Returns (messages, secret_values). A message:
    {"http_version", "tcp_stream", "src", "sport", "dst", "dport", "frame", "t", "is_request",
     "method", "uri", "host", "status", "phrase", "content_type", "location", "time_since_request",
     "request_frame", "body_len", "body" (bytes, response only, capped), "credentials": [...],
     "has_auth", "auth_scheme", "has_cookie"}.
    """
    flt = "http"
    if display_filter:
        flt = f"({display_filter}) && http"
    command = ["tshark", "-n", "-r", file_path, *decode_as]
    if out_of_order:
        command += ["-o", "tcp.reassemble_out_of_order:TRUE"]
    if keylog_file:
        command += ["-o", f"tls.keylog_file:{keylog_file}"]
    command += ["-Y", flt, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", f"aggregator={FIELD_SEP}",
                "-E", "quote=n"]
    for name in HTTP1_FIELDS:
        command += ["-e", name]
    if max_packets:
        command += ["-c", str(int(max_packets))]
    secrets: Set[str] = set()
    messages: List[Dict[str, Any]] = []
    with tempfile.TemporaryFile(mode="w+") as err:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True, bufsize=1 << 16)
        produced = 0
        try:
            for line in proc.stdout:
                produced += 1
                parts = line.rstrip("\n").split("\t")
                parts += [""] * (len(HTTP1_FIELDS) - len(parts))
                row = dict(zip(HTTP1_FIELDS, parts))
                msg = _http1_row(row, secrets)
                if msg:
                    messages.append(msg)
        finally:
            if proc.poll() is None:
                proc.stdout.close()
                proc.terminate()
            proc.wait()
            err.seek(0)
            stderr_text = err.read()[-2000:].strip()
        if proc.returncode not in (0, None) and produced == 0:
            raise RuntimeError(f"tshark failed (exit {proc.returncode}): {stderr_text}")
    return messages, secrets


def _http1_row(row: Dict[str, str], secrets: Set[str]) -> Optional[Dict[str, Any]]:
    index = _int(row["tcp.stream"].split(FIELD_SEP)[0])
    if index is None:
        return None
    method = (row["http.request.method"].split(FIELD_SEP)[0] or None)
    code = _int(row["http.response.code"].split(FIELD_SEP)[0])
    if method is None and code is None:
        return None  # a continuation frame of a reassembled body, not a message boundary
    src = (row["ip.src"] or row["ipv6.src"]).split(FIELD_SEP)[0]
    dst = (row["ip.dst"] or row["ipv6.dst"]).split(FIELD_SEP)[0]
    sport, dport = _int(row["tcp.srcport"].split(FIELD_SEP)[0]), _int(row["tcp.dstport"].split(FIELD_SEP)[0])
    lines = _header_lines(row["http.request.line"] or row["http.response.line"])
    credentials = _credentials_from_lines(lines, secrets)
    auth = (row["http.authorization"] or row["http.proxy_authorization"]).split(FIELD_SEP)[0]
    cookie = bool(row["http.cookie"] or row["http.set_cookie"])
    if auth:
        _mask_credential(secrets, auth)
    for raw_cookie in (row["http.cookie"], row["http.set_cookie"]):
        for value in raw_cookie.split(FIELD_SEP):
            _mask_credential(secrets, value)
    body = _decode_file_data(row["http.file_data"].split(FIELD_SEP)[0])[:MAX_BODY_KEEP]
    version = (row["http.request.version"] or row["http.response.version"]).split(FIELD_SEP)[0] or None
    return {
        "http_version": (version or "HTTP/1.1").replace("HTTP/", ""),
        "tcp_stream": index, "src": src, "dst": dst, "sport": sport, "dport": dport,
        "frame": _int(row["frame.number"]) or 0, "t": float(row["frame.time_epoch"] or 0.0),
        "is_request": method is not None,
        "method": method, "uri": row["http.request.uri"].split(FIELD_SEP)[0] or None,
        "host": row["http.host"].split(FIELD_SEP)[0] or None,
        "status": code, "phrase": row["http.response.phrase"].split(FIELD_SEP)[0] or None,
        "content_type": row["http.content_type"].split(FIELD_SEP)[0] or None,
        "location": row["http.location"].split(FIELD_SEP)[0] or None,
        "time_since_request": _float(row["http.time"].split(FIELD_SEP)[0]),
        "request_frame": _int(row["http.request_in"].split(FIELD_SEP)[0]),
        "body_len": len(body), "body": body if method is None else b"",
        "credentials": credentials,
        "has_auth": bool(auth), "auth_scheme": _auth_scheme(auth) if auth else None, "has_cookie": cookie,
    }


def _decode_file_data(value: str) -> bytes:
    """tshark renders http.file_data as text for a text body, as colon-hex for a binary one."""
    if not value:
        return b""
    compact = value.replace(":", "")
    if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try:
            return bytes.fromhex(compact)
        except ValueError:
            pass
    return value.encode("utf-8", "replace")


def _float(value: Optional[str]) -> Optional[float]:
    try:
        return float(value) if value else None
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# HTTP/2 message assembly (request/response per stream)
# ---------------------------------------------------------------------------

def http2_messages(file_path: str, decode_as: List[str], wanted: Set[int], keylog_file: Optional[str] = None,
                   display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                   out_of_order: bool = True) -> Tuple[List[Dict[str, Any]], Set[str], int, Dict[str, Any]]:
    """
    HTTP/2 request and response messages per stream, from the shared HTTP/2 pass.

    Returns (messages, secret_values, packets_read, status). A message mirrors an HTTP/1.1
    one, with the stream id and the authority. DATA bytes become the body (response only,
    capped) for RESTCONF error parsing; header values are already masked by the extractor.
    """
    extraction = iter_http2_packets(file_path, decode_as, keylog_file=keylog_file, display_filter=display_filter,
                                    max_packets=max_packets, out_of_order=out_of_order)
    streams: Dict[Tuple[int, int], Dict[str, Any]] = {}
    order: List[Tuple[int, int]] = []
    packets = 0
    for packet in extraction.packets:
        index = packet["tcp_stream"]
        if index not in wanted:
            continue
        packets += 1
        server = _server_side(packet)
        for frame in packet["frames"]:
            if frame.get("type") not in ("HEADERS", "CONTINUATION", "DATA"):
                continue
            key = (index, frame.get("stream_id", 0))
            msg = streams.get(key)
            if msg is None:
                msg = _new_h2_message(packet, index, frame.get("stream_id", 0))
                streams[key] = msg
                order.append(key)
            if frame["type"] in ("HEADERS", "CONTINUATION"):
                _apply_h2_headers(msg, frame, server, packet)
            elif frame["type"] == "DATA":
                _apply_h2_data(msg, frame, server, packet)
    messages: List[Dict[str, Any]] = []
    for key in order:
        messages.extend(_split_h2_message(streams[key]))
    return messages, set(extraction.secret_values), packets, extraction.status


def _server_side(packet: Dict[str, Any]) -> Optional[bool]:
    """True when this packet is from the server, inferred later by the analyzer; kept None here."""
    return None


def _new_h2_message(packet: Dict[str, Any], index: int, stream_id: int) -> Dict[str, Any]:
    return {"http_version": "2", "tcp_stream": index, "stream_id": stream_id,
            "src": packet["src"], "dst": packet["dst"], "sport": packet["sport"], "dport": packet["dport"],
            "request": {"frame": None, "t": None, "headers": {}, "credentials": [], "has_auth": False,
                        "auth_scheme": None, "has_cookie": False, "body_len": 0},
            "response": {"frame": None, "t": None, "headers": {}, "body": b"", "body_len": 0}}


def _apply_h2_headers(msg: Dict[str, Any], frame: Dict[str, Any], server: Optional[bool],
                      packet: Dict[str, Any]) -> None:
    headers = {h["name"]: h for h in frame.get("headers", [])}
    is_response = ":status" in headers or (not headers.get(":method") and msg["request"]["headers"])
    side = msg["response"] if is_response else msg["request"]
    for name, meta in headers.items():
        if meta.get("value") is not None:
            side["headers"].setdefault(name, meta["value"])
        if meta.get("credential"):
            low = name.lower()
            if low in ("authorization", "proxy-authorization"):
                side.setdefault("auth_scheme", "credentials")
                side["has_auth"] = True
                if meta.get("value"):
                    side["auth_scheme"] = meta["value"].split(None, 1)[0]
            elif low in ("cookie", "set-cookie"):
                side["has_cookie"] = True
            else:
                side.setdefault("credentials", []).append({"header": name, "kind": "token", "value": "masked"})
    if side["frame"] is None:
        side["frame"], side["t"] = packet["n"], packet["t"]


def _apply_h2_data(msg: Dict[str, Any], frame: Dict[str, Any], server: Optional[bool],
                   packet: Dict[str, Any]) -> None:
    # A DATA frame belongs to the response if the request headers are already in; else the request.
    side = msg["response"] if msg["request"]["headers"] else msg["request"]
    data = frame.get("data") or b""
    side["body_len"] = side.get("body_len", 0) + (frame.get("data_len") or len(data))
    if side is msg["response"] and len(side["body"]) < MAX_BODY_KEEP:
        side["body"] = (side["body"] + data)[:MAX_BODY_KEEP]
    if side["frame"] is None:
        side["frame"], side["t"] = packet["n"], packet["t"]


def _split_h2_message(stream: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One assembled stream into a request record and (when present) a response record."""
    req, resp = stream["request"], stream["response"]
    base = {"http_version": "2", "tcp_stream": stream["tcp_stream"], "stream_id": stream["stream_id"],
            "src": stream["src"], "dst": stream["dst"], "sport": stream["sport"], "dport": stream["dport"]}
    out: List[Dict[str, Any]] = []
    if req["headers"] or req["frame"] is not None:
        out.append({**base, "is_request": True, "frame": req["frame"], "t": req["t"],
                    "method": req["headers"].get(":method"), "uri": req["headers"].get(":path"),
                    "host": req["headers"].get(":authority"),
                    "content_type": req["headers"].get("content-type"), "status": None, "phrase": None,
                    "location": None, "time_since_request": None, "request_frame": None,
                    "body_len": req.get("body_len", 0), "body": b"",
                    "credentials": req.get("credentials", []),
                    "has_auth": req.get("has_auth", False), "auth_scheme": req.get("auth_scheme"),
                    "has_cookie": req.get("has_cookie", False)})
    if resp["headers"] or resp["frame"] is not None:
        status = resp["headers"].get(":status")
        timing = None
        if resp["t"] is not None and req["t"] is not None:
            timing = resp["t"] - req["t"]
        out.append({**base, "is_request": False, "frame": resp["frame"], "t": resp["t"],
                    "method": None, "uri": None, "host": None,
                    "content_type": resp["headers"].get("content-type"),
                    "status": _int(status) if status else None, "phrase": None,
                    "location": resp["headers"].get("location"),
                    "time_since_request": timing, "request_frame": req["frame"],
                    "body_len": resp.get("body_len", 0), "body": resp.get("body", b""),
                    "credentials": [], "has_auth": False, "auth_scheme": None, "has_cookie": False})
    return out
