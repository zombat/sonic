#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. RESTCONF and REST troubleshooting (HTTP/1.1 and HTTP/2, decrypted with a key log)

Reads RESTCONF (RFC 8040) and any REST-over-HTTP exchange from a capture with
Wireshark's HTTP, HTTP/2, HPACK and TLS dissectors through tshark, and answers the
questions an engineer asks of a RESTCONF client and server. It decrypts TLS with the
same key log (or the Decryption Secrets Block a pcapng carries) that the gRPC
troubleshooter uses; without one, a TLS session shows only its handshake.

Per request (a request paired to its response):
    the method and path, the HTTP status and phrase, the time from request to response,
    the request and response Content-Type, the response body size, a Location on a 201
    Created, and, for a RESTCONF error, the ietf-restconf:errors fields (error-type,
    error-tag, error-path, error-message, error-app-tag) parsed from the body (JSON or XML).

Credentials present, never shown:
    an Authorization header (Basic, Bearer, ...): the scheme is kept, the credential is
    masked; Cookie, Set-Cookie and token headers (X-Auth-Token, X-API-Key, CSRF tokens,
    ...) are flagged by name with the value dropped. Over cleartext HTTP each is a finding
    (CLEARTEXT_CREDENTIAL); over TLS it is reported as present (CREDENTIAL_IN_REQUEST),
    seen only because the key log decrypted it. No value reaches a record: the extractor
    masks them at the source and any echo is scrubbed from the report by value.

Message bodies are never decoded except RESTCONF error documents: a GET that returns
configuration shows its Content-Type and size, never its contents.

Author: Raymond A Rizzo | Zombat
"""

import json
import os
import struct
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from analyzers.network_common import (
    Context, cap, iso_time, make_issue, sort_issues, status_from_issues,
)
from extractors.http2 import GRPC_PORTS, discover, tshark_available, tshark_version
from extractors.http_messages import (
    HTTP_PORTS, http1_messages, http2_messages, is_restconf, plan_http_decode_as,
)
from extractors.tls_secrets import key_log_labels, missing_labels, pcapng_secrets

REPORT_SCHEMA = "sonic.http_report/1"

HTTP_STATUS_HINTS = {
    400: "the server rejected the request as malformed (bad JSON/XML, a bad path or value)",
    401: "the server refused the credentials: check the Authorization header or the account",
    403: "the credentials were accepted but this user may not touch this resource (RESTCONF NACM, or an ACL)",
    404: "the target has no such resource (a wrong path, or a data node that is not configured)",
    405: "the method is not allowed on this resource (RESTCONF allows GET/POST/PUT/PATCH/DELETE per node)",
    409: "a conflict: the resource already exists (POST) or was changed by someone else",
    412: "a precondition failed (an If-Match/If-Unmodified-Since on a RESTCONF datastore)",
    415: "the server does not accept this Content-Type (RESTCONF wants application/yang-data+json or +xml)",
    429: "the server is rate limiting",
    500: "the server hit an internal error; read the error body and the device logs",
    501: "the server does not implement this (a RESTCONF capability or method it does not support)",
    503: "the server is unavailable or overloaded (transient); retry with backoff",
}

LIMITS = [
    "TLS-wrapped RESTCONF/REST without a key log (or TLS secrets embedded in a pcapng) shows only the "
    "handshake: no method, path, status or body. In TLS 1.3 the certificate is encrypted too.",
    "A session's secret is matched by its ClientHello random: a session whose ClientHello is not in the "
    "capture cannot be decrypted, whatever the key log holds.",
    "A capture that begins mid-connection may leave an HTTP/2 request without its method or path (HPACK state "
    "missing) or an HTTP/1.1 body unreassembled.",
    "Only RESTCONF error documents are parsed from a body; a successful GET's configuration is never decoded "
    "(its Content-Type and size are reported).",
    "Credential values are never shown: an Authorization scheme is kept, the credential is masked, and Cookie, "
    "token and CSRF headers are flagged by name only.",
    "RESTCONF event-stream notifications (text/event-stream) are reported as a long-lived GET; their contents "
    "are not decoded.",
]


def _endpoint(ip: Optional[str], port: Optional[int]) -> Optional[str]:
    if ip is None or port is None:
        return None
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# RESTCONF error documents (RFC 8040 errors, JSON and XML)
# ---------------------------------------------------------------------------

_ERROR_FIELDS = ("error-type", "error-tag", "error-app-tag", "error-path", "error-message")


def parse_restconf_errors(body: bytes, content_type: Optional[str]) -> List[Dict[str, Any]]:
    """
    The ietf-restconf:errors of a RESTCONF error body (RFC 8040 section 3.9), JSON or XML.

    Returns a list of {error-type, error-tag, error-app-tag, error-path, error-message}, only
    the keys present. An empty list when the body is not a RESTCONF errors document.
    """
    if not body:
        return []
    text = body.decode("utf-8", "replace").strip()
    looks_json = text.startswith("{") or (content_type and "json" in content_type.lower())
    looks_xml = text.startswith("<") or (content_type and "xml" in content_type.lower())
    if looks_json:
        errors = _restconf_errors_json(text)
        if errors:
            return errors
    if looks_xml:
        return _restconf_errors_xml(text)
    # Fall back to trying JSON then XML when the content type did not say.
    return _restconf_errors_json(text) or _restconf_errors_xml(text)


def _restconf_errors_json(text: str) -> List[Dict[str, Any]]:
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(doc, dict):
        return []
    container = None
    for key in ("ietf-restconf:errors", "errors"):
        if isinstance(doc.get(key), dict):
            container = doc[key]
            break
    if container is None:
        return []
    raw = container.get("error")
    entries = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    out = []
    for entry in entries:
        if isinstance(entry, dict):
            out.append({k: str(entry[k]) for k in _ERROR_FIELDS if k in entry and entry[k] is not None})
    return [e for e in out if e]


def _restconf_errors_xml(text: str) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out = []
    # Elements are namespaced (urn:ietf:params:xml:ns:yang:ietf-restconf); match by local name.
    for error in root.iter():
        if _local(error.tag) != "error":
            continue
        entry = {}
        for child in error:
            name = _local(child.tag)
            if name in _ERROR_FIELDS and child.text:
                entry[name] = child.text.strip()
        if entry:
            out.append(entry)
    return out


def _local(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


# ---------------------------------------------------------------------------
# TLS secrets and decryption coverage (shared shape with the gRPC report)
# ---------------------------------------------------------------------------

def _secrets_view(file_path: str, keylog_file: Optional[str]) -> Dict[str, Any]:
    """Which TLS sessions the secrets cover (labels and client randoms only; no secret kept)."""
    key_log: Dict[str, set] = {}
    if keylog_file:
        try:
            key_log = key_log_labels(keylog_file)
        except OSError:
            key_log = {}
    try:
        embedded = pcapng_secrets(file_path) or {"blocks": 0, "labels": {}}
    except (OSError, ValueError, struct.error):
        embedded = {"blocks": 0, "labels": {}}
    by_random: Dict[str, Dict[str, set]] = {}
    for source, table in (("key log", key_log), ("pcapng", embedded["labels"])):
        for random, labels in table.items():
            entry = by_random.setdefault(random, {"labels": set(), "sources": set()})
            entry["labels"] |= labels
            entry["sources"].add(source)
    names = (["the key log"] if keylog_file else []) + (["the secrets in the pcapng"] if embedded["blocks"] else [])
    return {"key_log_file": bool(keylog_file), "pcapng_blocks": embedded["blocks"], "by_random": by_random,
            "source": " and ".join(names) or None, "sessions_in_key_log": len(key_log),
            "sessions_in_pcapng": len(embedded["labels"])}


def _scrub(value: Any, secrets: List[str]) -> Any:
    """Replace any echo of a masked credential value inside report text."""
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            if secret and secret in value:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value


# ---------------------------------------------------------------------------
# The analysis
# ---------------------------------------------------------------------------

def analyze_http_capture(file_path: str, keylog_file: Optional[str] = None, ports: Optional[List[int]] = None,
                         display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                         max_items: int = 25) -> Dict[str, Any]:
    """
    Troubleshoot RESTCONF and REST over HTTP/1.1 and HTTP/2 in one capture, decrypting TLS
    with a key log (keylog_file) or the secrets a pcapng carries.

    Returns the report (status "success") or {"status": "error", "error": ...}.
    """
    if not file_path or not os.path.exists(file_path):
        return _error(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        return _error(f"File not readable: {file_path}")
    if not tshark_available():
        return _error("RESTCONF/REST analysis needs tshark (Wireshark's HTTP, HTTP/2 and TLS dissectors); install it")
    if keylog_file and (not os.path.isfile(keylog_file) or not os.access(keylog_file, os.R_OK)):
        return _error("keylog_file is not a readable file")
    if max_packets is not None and int(max_packets) <= 0:
        return _error("max_packets must be a positive number")
    extra_ports: List[int] = []
    for port in ports or []:
        try:
            value = int(port)
        except (TypeError, ValueError):
            return _error(f"Not a TCP port: {port!r}")
        if not 1 <= value <= 65535:
            return _error(f"Not a TCP port: {port!r}")
        extra_ports.append(value)
    max_items = max(1, int(max_items or 25))

    status: Dict[str, Any] = {}
    try:
        disc = discover(file_path, display_filter=display_filter, max_packets=max_packets, status=status,
                        extra_ports=extra_ports)
    except RuntimeError as exc:
        return _error(str(exc))
    secrets = _secrets_view(file_path, keylog_file)
    secrets_given = bool(secrets["source"])
    decode_as, reasons = plan_http_decode_as(disc, extra_ports)
    wanted = {index for index, conn in disc.items() if _carries_http(conn, extra_ports)}

    secret_values: set = set()
    messages: List[Dict[str, Any]] = []
    try:
        http1, http1_secrets = http1_messages(file_path, decode_as, keylog_file, display_filter, max_packets)
        secret_values |= http1_secrets
        messages += [m for m in http1 if m["tcp_stream"] in wanted]
    except RuntimeError as exc:
        return _error(str(exc))
    http2_packets = 0
    try:
        http2, http2_secrets, http2_packets, h2_status = http2_messages(
            file_path, decode_as, wanted, keylog_file, display_filter, max_packets)
        secret_values |= http2_secrets
        messages += http2
        if h2_status.get("parse_error"):
            status["http2_parse_error"] = h2_status["parse_error"]
    except RuntimeError as exc:
        status["http2_error"] = str(exc)

    start = min((m["t"] for m in messages if m.get("t")), default=None)
    for conn in disc.values():
        start = conn.first_t if start is None else min(start, conn.first_t)
    end = max((m["t"] for m in messages if m.get("t")), default=None)
    for conn in disc.values():
        end = conn.last_t if end is None else max(end, conn.last_t)
    ctx = Context(start, end, max_items=max_items)

    coverage = _decryption_coverage(disc, file_path, decode_as, keylog_file, secrets, display_filter,
                                    max_packets, max_items) if any(c.is_tls() for c in disc.values()) else None

    requests, conn_rows, issues = _build(disc, messages, reasons, secrets_given, coverage, ctx)
    # A TLS connection on an HTTP(S) port that produced no message (not decrypted) is still
    # reported, so the no-key-log case says "give a key log" rather than "nothing found".
    seen = {row["flow"] for row in conn_rows}
    for index in sorted(wanted):
        conn = disc.get(index)
        if conn is None or not conn.is_tls():
            continue
        flow = (f"{_endpoint(conn.client[0], conn.client[1]) if conn.client else _endpoint(conn.a[0], conn.a[1])}"
                f" -> {_endpoint(conn.server[0], conn.server[1]) if conn.server else _endpoint(conn.b[0], conn.b[1])}")
        if flow in seen:
            continue
        conn_rows.append({"flow": flow, "service": f"tcp/{conn.service_port()}",
                          "service_name": HTTP_PORTS.get(conn.service_port()),
                          "transport": _transport(conn, False, secrets_given), "http_versions": [],
                          "requests": 0, "restconf": None, "sni": conn.sni, "alpn_offered": conn.alpn,
                          "decrypted": False})
        if not secrets_given:
            issues.append(make_issue("info", "HTTP_TLS_NOT_DECRYPTED",
                                     f"{flow} (tcp/{conn.service_port()}): TLS with no key log, so the requests are "
                                     "encrypted; have the client write a key log (SSLKEYLOGFILE) and pass it to read "
                                     "them", [conn.tls_client_hello] if conn.tls_client_hello else []))
    conn_rows.sort(key=lambda c: c["flow"])
    credentials = _credentials_summary(requests)

    verdict = _verdict(conn_rows, requests, credentials, coverage, secrets_given)
    if coverage and secrets_given:
        for row in coverage["sessions"]:
            if not row["decrypted"]:
                issues.append(make_issue("warning", "TLS_SESSION_NOT_DECRYPTED",
                                         f"{row['flow']} ({row['service']}): not decrypted: {row['reason']}",
                                         [row["client_hello_frame"]] if row["client_hello_frame"] else []))
    if secrets["pcapng_blocks"]:
        issues.append(make_issue("info", "TLS_SECRETS_IN_CAPTURE",
                                 f"the capture carries TLS secrets in {secrets['pcapng_blocks']} Decryption Secrets "
                                 f"Block(s) ({secrets['sessions_in_pcapng']} session(s)): anyone with this file can "
                                 "read the sessions they cover"))

    listed_requests, requests_omitted = cap(requests, max_items * 4)
    present = bool(conn_rows)
    report = {
        "status": "success",
        "schema": REPORT_SCHEMA,
        "file": file_path,
        "overall_status": status_from_issues(issues, present),
        "verdict": verdict,
        "capture": {
            "start": iso_time(start), "end": iso_time(end),
            "http_messages": len(messages), "http2_packets": http2_packets,
            "tshark": tshark_version(),
            "decode_as": [opt for opt in decode_as if opt != "-d"],
            "decode_as_reasons": {f"tcp/{p}": r for p, r in sorted(reasons.items())},
            "keylog_file_given": bool(keylog_file),
            "tls_secrets": {"source": secrets["source"], "key_log_file": secrets["key_log_file"],
                            "pcapng_decryption_secrets_blocks": secrets["pcapng_blocks"],
                            "sessions_in_key_log": secrets["sessions_in_key_log"],
                            "sessions_in_pcapng": secrets["sessions_in_pcapng"]},
            "display_filter": display_filter, "max_packets": max_packets,
            "warnings": [w for w in (status.get("http2_error"), status.get("http2_parse_error")) if w],
        },
        "summary": {
            "connections": len(conn_rows), "requests": len(requests),
            "restconf_requests": sum(1 for r in requests if r["restconf"]),
            "status_counts": _status_counts(requests),
            "restconf_errors": sum(1 for r in requests if r["restconf_errors"]),
            "cleartext_credentials": sum(1 for c in credentials if c["cleartext"]),
        },
        "connections": conn_rows,
        "requests": listed_requests,
        "requests_omitted": requests_omitted,
        "credentials": credentials,
        "tls_decryption": coverage,
        "issues": sort_issues(issues),
        "limits": LIMITS,
    }
    scrub_list = sorted({v for v in secret_values if len(v) >= 4}, key=len, reverse=True)
    return _scrub(report, scrub_list)


def _carries_http(conn, extra_ports) -> bool:
    port = conn.service_port()
    if port in HTTP_PORTS or port in extra_ports:
        return True
    if conn.is_tls() and (port in GRPC_PORTS or set(conn.alpn) & {"h2", "http/1.1"}):
        return True
    return conn.preface_frame is not None or port in GRPC_PORTS


def _transport(conn, decrypted: bool, secrets_given: bool) -> str:
    if not conn.is_tls():
        return "cleartext"
    if decrypted:
        return "tls (decrypted)"
    return "tls (not decrypted)" if secrets_given else "tls (no key log)"


def _build(disc, messages, reasons, secrets_given, coverage, ctx
           ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Pair requests with responses, build per-request records, per-connection rows and issues."""
    cov_by_stream = {row["tcp_stream"]: row for row in (coverage or {}).get("sessions", [])}
    by_stream: Dict[int, List[Dict[str, Any]]] = {}
    for msg in messages:
        by_stream.setdefault(msg["tcp_stream"], []).append(msg)

    requests: List[Dict[str, Any]] = []
    conn_rows: List[Dict[str, Any]] = []
    issues: List[Dict[str, Any]] = []
    for index in sorted(by_stream):
        conn = disc.get(index)
        if conn is None:
            continue
        cov = cov_by_stream.get(index) or {}
        decrypted = bool(cov.get("decrypted")) or not conn.is_tls()
        transport = _transport(conn, decrypted, secrets_given)
        flow = f"{_endpoint(conn.client[0], conn.client[1]) if conn.client else _endpoint(conn.a[0], conn.a[1])}" \
               f" -> {_endpoint(conn.server[0], conn.server[1]) if conn.server else _endpoint(conn.b[0], conn.b[1])}"
        service = f"tcp/{conn.service_port()}"
        paired = _pair(by_stream[index])
        versions = sorted({r["http_version"] for r in paired})
        restconf_here = any(r["restconf"] for r in paired)
        for rec in paired:
            rec["flow"], rec["service"], rec["transport"] = flow, service, transport
            requests.append(rec)
            label = f"{flow} ({service})"
            _request_issues(rec, label, issues)
        conn_rows.append({
            "flow": flow, "service": service, "service_name": HTTP_PORTS.get(conn.service_port()),
            "transport": transport, "http_versions": versions, "requests": len(paired),
            "restconf": restconf_here, "sni": conn.sni, "alpn_offered": conn.alpn,
            "decrypted": decrypted if conn.is_tls() else None,
        })
    return requests, conn_rows, issues


def _pair(stream_messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build request records from a stream's messages, pairing each response to its request."""
    requests = [m for m in stream_messages if m["is_request"]]
    responses = [m for m in stream_messages if not m["is_request"]]
    # HTTP/1.1 pairs by request_frame; HTTP/2 by stream id (one request, one response per stream).
    by_frame: Dict[int, Dict[str, Any]] = {}
    by_stream_id: Dict[int, Dict[str, Any]] = {}
    for req in requests:
        if req["frame"]:
            by_frame[req["frame"]] = req
        if req.get("stream_id") is not None:
            by_stream_id[req["stream_id"]] = req
    used = set()
    records: List[Dict[str, Any]] = []

    def record(req, resp):
        method = (req or {}).get("method")
        path = (req or {}).get("uri")
        req_ct = (req or {}).get("content_type")
        resp_ct = (resp or {}).get("content_type")
        body = (resp or {}).get("body") or b""
        errors = parse_restconf_errors(body, resp_ct) if resp and (resp.get("status") or 0) >= 400 else []
        restconf = is_restconf(path, (req_ct, resp_ct)) or bool(errors)
        creds = list((req or {}).get("credentials") or [])
        if (req or {}).get("has_auth"):
            creds.append({"header": "Authorization", "kind": "authorization",
                          "scheme": req.get("auth_scheme"), "value": "masked"})
        if (req or {}).get("has_cookie"):
            creds.append({"header": "Cookie", "kind": "cookie", "value": "masked"})
        timing = (resp or {}).get("time_since_request")
        return {
            "http_version": (req or resp or {}).get("http_version"),
            "stream_id": (req or resp or {}).get("stream_id"),
            "method": method, "path": path, "host": (req or {}).get("host"),
            "status": (resp or {}).get("status"), "phrase": (resp or {}).get("phrase"),
            "request_content_type": req_ct, "response_content_type": resp_ct,
            "request_body_bytes": (req or {}).get("body_len", 0),
            "response_body_bytes": (resp or {}).get("body_len", 0),
            "timing_ms": round(timing * 1000, 3) if timing is not None else None,
            "location": (resp or {}).get("location"),
            "restconf": restconf, "restconf_errors": errors,
            "credentials": creds,
            "frames": {"request": (req or {}).get("frame"), "response": (resp or {}).get("frame")},
            "t": (req or resp or {}).get("t"),
            "outcome": _outcome(resp),
        }

    for resp in responses:
        req = None
        if resp.get("stream_id") is not None:
            req = by_stream_id.get(resp["stream_id"])
        if req is None and resp.get("request_frame"):
            req = by_frame.get(resp["request_frame"])
        if req is not None:
            used.add(id(req))
        records.append(record(req, resp))
    for req in requests:
        if id(req) not in used:
            records.append(record(req, None))
    records.sort(key=lambda r: (r["frames"]["request"] or r["frames"]["response"] or 0))
    return records


def _outcome(resp: Optional[Dict[str, Any]]) -> str:
    if resp is None:
        return "no_response"
    code = resp.get("status") or 0
    if code >= 500:
        return "server_error"
    if code >= 400:
        return "client_error"
    if code >= 200:
        return "ok"
    return "other"


def _request_issues(rec: Dict[str, Any], label: str, issues: List[Dict[str, Any]]) -> None:
    frames = [f for f in (rec["frames"].get("response"), rec["frames"].get("request")) if f]
    code = rec["status"] or 0
    desc = f"{rec['method'] or '?'} {rec['path'] or '?'}"
    if rec["restconf_errors"]:
        for err in rec["restconf_errors"]:
            tag = err.get("error-tag", "error")
            parts = ", ".join(f"{k}={v}" for k, v in err.items() if k != "error-tag")
            issues.append(make_issue("error" if code >= 500 or code == 0 else "warning", "RESTCONF_ERROR",
                                     f"{label}: {desc} -> {code} {tag}" + (f" ({parts})" if parts else ""),
                                     frames, status=code, error_tag=tag))
    elif code >= 500:
        issues.append(make_issue("error", "HTTP_SERVER_ERROR",
                                 f"{label}: {desc} -> {code} {rec['phrase'] or ''}: "
                                 f"{HTTP_STATUS_HINTS.get(code, 'a server error')}", frames, status=code))
    elif code >= 400:
        issues.append(make_issue("warning", "HTTP_CLIENT_ERROR",
                                 f"{label}: {desc} -> {code} {rec['phrase'] or ''}: "
                                 f"{HTTP_STATUS_HINTS.get(code, 'a client error')}", frames, status=code))
    elif rec["outcome"] == "no_response" and rec["method"]:
        issues.append(make_issue("warning", "HTTP_NO_RESPONSE",
                                 f"{label}: {desc} got no response before the capture ended", frames))
    for cred in rec["credentials"]:
        cleartext = rec["transport"] == "cleartext"
        name = cred["header"] + (f" ({cred['scheme']})" if cred.get("scheme") else "")
        if cleartext:
            issues.append(make_issue("error", "CLEARTEXT_CREDENTIAL",
                                     f"{label}: {name} sent in cleartext on {desc} (value masked): anyone on the "
                                     "path can read it; use TLS", frames, header=cred["header"]))
        else:
            issues.append(make_issue("info", "CREDENTIAL_IN_REQUEST",
                                     f"{label}: {name} on {desc}, protected by TLS on the wire (seen because the "
                                     "secrets decrypted it; value masked)", frames, header=cred["header"]))


def _credentials_summary(requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One row per (flow, header): how many requests carried it, cleartext or not, value masked."""
    summary: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for rec in requests:
        for cred in rec["credentials"]:
            key = (rec["flow"], cred["header"])
            entry = summary.setdefault(key, {"flow": rec["flow"], "service": rec["service"],
                                             "header": cred["header"], "kind": cred["kind"],
                                             "scheme": cred.get("scheme"),
                                             "cleartext": rec["transport"] == "cleartext",
                                             "requests": 0, "frames": [], "value": "masked"})
            entry["requests"] += 1
            if rec["frames"].get("request"):
                entry["frames"].append(rec["frames"]["request"])
    return sorted(summary.values(), key=lambda e: (e["flow"], e["header"]))


def _status_counts(requests: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for rec in requests:
        key = str(rec["status"]) if rec["status"] else rec["outcome"]
        counts[key] = counts.get(key, 0) + 1
    return counts


def _verdict(conn_rows, requests, credentials, coverage, secrets_given) -> str:
    if not conn_rows:
        return "No HTTP, RESTCONF or REST found: nothing on an HTTP(S) port, no HTTP/2 and no HTTP/1 request."
    restconf = sum(1 for r in requests if r["restconf"])
    tls = [c for c in conn_rows if c["transport"].startswith("tls")]
    parts = [f"{len(conn_rows)} HTTP connection(s)"]
    if tls:
        decrypted = sum(1 for c in tls if c.get("decrypted"))
        parts.append(f"{len(tls)} over TLS, {decrypted} decrypted"
                     + ("" if secrets_given or not tls else " (no key log: give one to read the requests)"))
    if requests:
        errs = sum(1 for r in requests if r["status"] and r["status"] >= 400)
        parts.append(f"{len(requests)} request(s)" + (f", {restconf} RESTCONF" if restconf else "")
                     + (f", {errs} with a 4xx/5xx status" if errs else ""))
    else:
        parts.append("no request decoded"
                     + ("" if secrets_given else " (TLS without a key log shows only the handshake)"))
    clear = sorted({c["header"] for c in credentials if c["cleartext"]})
    if clear:
        parts.append(f"credentials in cleartext: {', '.join(clear)} (values masked)")
    return ". ".join(parts) + "."


def _decryption_coverage(disc, file_path, decode_as, keylog_file, secrets, display_filter, max_packets, max_items
                         ) -> Dict[str, Any]:
    """Per TLS session: whether the secrets decrypted it and, when not, why; and the totals."""
    from extractors.http2 import tls_decryption
    tls_state: Dict[int, Dict[str, Any]] = {}
    if secrets["source"]:
        try:
            tls_state = tls_decryption(file_path, decode_as, keylog_file, display_filter, max_packets)
            reached = {i for i, st in tls_state.items() if st and (st["handshake"] or st["application_data"])}
            retry = [i for i, c in disc.items() if c.is_tls() and i not in reached]
            if retry:
                flt = "tcp.stream in {" + " ".join(str(i) for i in sorted(retry)) + "}"
                if display_filter:
                    flt = f"({display_filter}) && {flt}"
                second = tls_decryption(file_path, decode_as, keylog_file, flt, max_packets, out_of_order=False)
                for index in retry:
                    first, other = tls_state.get(index), second.get(index)
                    if first and other:
                        first["handshake"] = first["handshake"] or other["handshake"]
                        first["application_data"] = sorted(set(first["application_data"])
                                                           | set(other["application_data"]))
                        first["client_random"] = first["client_random"] or other["client_random"]
                    elif other:
                        tls_state[index] = other
        except Exception:  # noqa: BLE001 - the coverage view is an addition
            tls_state = {}
    rows = []
    for index, dconn in sorted(disc.items(), key=lambda kv: kv[1].first_frame):
        if not dconn.is_tls():
            continue
        client, server = dconn.client or dconn.a, dconn.server or dconn.b
        state = tls_state.get(index) or {}
        inside = list(state.get("application_data") or [])
        decrypted = bool(state.get("handshake") or inside)
        random = state.get("client_random")
        found = secrets["by_random"].get(random) if random else None
        missing = missing_labels(found["labels"], None) if found else []
        if not secrets["source"]:
            reason = "no key log given, and the capture carries no TLS secrets"
        elif decrypted:
            reason = None
        elif random is None and dconn.tls_client_hello is None:
            reason = "no ClientHello in the capture (the session began before it), so no secret can be matched to it"
        elif random is None:
            reason = "its ClientHello could not be reassembled from the capture, so no secret can be matched to it"
        elif not found:
            reason = (f"{secrets['source']} hold no secret for this session (no line with its ClientHello random): "
                      "the key log is from another session or client")
        else:
            reason = ("the secrets name this session's ClientHello random"
                      + (f" but lack {', '.join(missing)}" if missing else "") + ", and tshark did not decrypt it")
        rows.append({"flow": f"{_endpoint(client[0], client[1])} -> {_endpoint(server[0], server[1])}",
                     "service": f"tcp/{dconn.service_port()}", "tcp_stream": index,
                     "client_hello_frame": state.get("client_hello_frame") or dconn.tls_client_hello,
                     "decrypted": decrypted, "application_data": inside,
                     "secret_in": sorted(found["sources"]) if found else [],
                     "labels": sorted(found["labels"]) if found else [], "reason": reason})
    done = sum(1 for r in rows if r["decrypted"])
    if not rows:
        verdict = "No TLS session in this capture."
    elif not secrets["source"]:
        verdict = f"0 of {len(rows)} TLS session(s) decrypted: no key log given, and the capture carries no secrets."
    else:
        verdict = f"{done} of {len(rows)} TLS session(s) decrypted with {secrets['source']}."
        if done < len(rows):
            verdict = verdict[:-1] + f"; not decrypted: {', '.join(r['flow'] for r in rows if not r['decrypted'])}."
    listed, omitted = cap(rows, max_items)
    return {"verdict": verdict, "decrypted": done, "total": len(rows), "secrets_source": secrets["source"],
            "sessions": listed, "sessions_omitted": omitted}
