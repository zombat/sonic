#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. TACACS+ and RADIUS troubleshooting (de-obfuscated with a shared key)

Reads the AAA exchange from a capture with Wireshark's TACACS+ and RADIUS dissectors
through tshark. Given the shared key an operator supplies (read by path, never echoed),
it de-obfuscates TACACS+ bodies (an MD5 pad of the key) and decrypts the RADIUS
User-Password (the shared secret and the request authenticator), and reports:

    - who asked (the user name and the NAS), accept or reject, and the authorization and
      accounting records;
    - for RADIUS, the Access-Request / Accept / Reject / Challenge and Accounting flow per
      transaction id, whether the shared secret validated the response authenticator (a wrong
      secret shows as an invalid authenticator), and whether a Message-Authenticator was
      present;
    - for TACACS+, each session (by session id): the authentication result (PASS, FAIL,
      GETPASS, ...), the authorization status and the accounting status;
    - a TACACS+ session sent with the unencrypted flag set (its body in cleartext) as a
      cleartext finding.

Any recovered password or secret is masked: the extractor reads it only to note that it was
recovered and so the analyzer can scrub any echo of it; no credential value, and never the
shared key, reaches a record. A user name (who asked) is shown, as RESTCONF and gRPC show it.

Author: Raymond A Rizzo | Zombat
"""

import hashlib
import hmac
import os
from typing import Any, Dict, List, Optional, Tuple

from analyzers.network_common import (
    cap, iso_time, make_issue, sort_issues, status_from_issues,
)
from extractors.aaa import extract_aaa, tshark_available, tshark_version
from extractors.aaa import SEP

REPORT_SCHEMA = "sonic.aaa_report/1"

RADIUS_CODES = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request",
                5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server", 13: "Status-Client",
                40: "Disconnect-Request", 41: "Disconnect-ACK", 42: "Disconnect-NAK",
                43: "CoA-Request", 44: "CoA-ACK", 45: "CoA-NAK"}
RADIUS_ACCT_STATUS = {1: "Start", 2: "Stop", 3: "Interim-Update", 7: "Accounting-On", 8: "Accounting-Off"}

TACACS_TYPES = {1: "Authentication", 2: "Authorization", 3: "Accounting"}
TACACS_AUTHEN_STATUS = {1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER", 5: "GETPASS", 6: "RESTART",
                        7: "ERROR", 0x21: "FOLLOW"}
TACACS_AUTHOR_STATUS = {1: "PASS_ADD", 2: "PASS_REPL", 0x10: "FAIL", 0x11: "ERROR", 0x21: "FOLLOW"}
TACACS_ACCT_STATUS = {1: "SUCCESS", 2: "ERROR", 0x21: "FOLLOW"}
TACACS_ACTIONS = {1: "login", 2: "chpass", 3: "sendpass", 4: "sendauth"}
TACACS_SERVICES = {0: "none", 1: "login", 2: "enable", 3: "ppp", 4: "arap", 5: "pt", 6: "rcmd", 7: "x25",
                   8: "nasi", 9: "fwproxy"}
TACACS_UNENCRYPTED_FLAG = 0x01

LIMITS = [
    "Only what crossed the capture point is read; a key that is wrong for a session shows as a TACACS+ body that "
    "will not de-obfuscate or a RADIUS response whose authenticator does not validate.",
    "TACACS+ runs over TCP: a session whose start is not in the capture may be missing its user name or action.",
    "A RADIUS User-Password is decrypted only in the request that carries it; CHAP, EAP and MS-CHAP credentials are "
    "noted as present (an EAP exchange is not decrypted).",
    "The shared key and every recovered password are secrets: they are read by path, masked at the source, and "
    "never written to a record, a log or a report.",
    "Per-server keys are not distinguished: tshark takes one tacplus.key and one radius.shared_secret, so a capture "
    "mixing servers with different keys decrypts only the sessions that key fits.",
]


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# The operator's shared-key file (read by path, never echoed)
# ---------------------------------------------------------------------------

_TACACS_KEYS = ("tacacs_key", "tacacs-key", "tacplus.key", "tacplus_key", "tacacs")
_RADIUS_KEYS = ("radius_secret", "radius-secret", "radius.shared_secret", "radius_shared_secret", "radius")


def read_keys_file(path: str) -> Tuple[Optional[str], Optional[str]]:
    """
    (tacacs_key, radius_secret) from an operator's key file. A `name: value` file names each
    (tacacs_key / radius_secret); a single bare line is used for both. Values are never echoed.

    Raises:
        OSError: the file cannot be read
        ValueError: the file has no recognisable key
    """
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    tacacs = radius = None
    bare: Optional[str] = None
    recognised = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line or "=" in line:
            sep = ":" if (":" in line and (("=" not in line) or line.index(":") < line.index("="))) else "="
            name, _, value = line.partition(sep)
            name, value = name.strip().lower(), value.strip().strip('"').strip("'")
            if not value:
                continue
            if name in _TACACS_KEYS:
                tacacs, recognised = value, True
            elif name in _RADIUS_KEYS:
                radius, recognised = value, True
        elif bare is None:
            bare = line
    if not recognised:
        if bare is not None:
            return bare, bare  # a single bare key: use it for both protocols
        raise ValueError("no tacacs_key or radius_secret found in the key file")
    return tacacs, radius


# ---------------------------------------------------------------------------
# Field access
# ---------------------------------------------------------------------------

def _val(row: Dict[str, str], name: str) -> str:
    return row.get(name, "").split(SEP)[0]


def _int_val(row: Dict[str, str], name: str) -> Optional[int]:
    value = _val(row, name)
    if value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _endpoint(row: Dict[str, str], which: str, port_field: str) -> str:
    ip = _val(row, f"ip.{which}") or _val(row, f"ipv6.{which}")
    port = _val(row, port_field)
    return f"{ip}:{port}" if port else ip


def _hex_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value.replace(":", "")) if value else b""
    except ValueError:
        return b""


def message_authenticator(raw: bytes, secret: Optional[str], request_authenticator: Optional[bytes] = None) -> str:
    """
    The state of one RADIUS message's Message-Authenticator (RFC 3579 3.2): "absent", "valid",
    "invalid", or "unchecked" without a secret. It is the HMAC-MD5, keyed with the shared secret,
    of the whole message with the attribute's value zeroed (and, in a response, the Request
    Authenticator of the request in the authenticator field). Only the verdict leaves this function.
    """
    if len(raw) < 20:
        return "unchecked"
    raw = raw[:int.from_bytes(raw[2:4], "big")]
    pos, offset = 20, None
    while pos + 2 <= len(raw):
        atype, alen = raw[pos], raw[pos + 1]
        if alen < 2:
            break
        if atype == 80 and alen == 18:
            offset = pos + 2
            break
        pos += alen
    if offset is None:
        return "absent"
    if not secret:
        return "unchecked"
    data = bytearray(raw)
    value = bytes(data[offset:offset + 16])
    data[offset:offset + 16] = b"\x00" * 16
    if request_authenticator is not None:
        data[4:20] = request_authenticator
    mac = hmac.new(secret.encode(), bytes(data), hashlib.md5).digest()
    return "valid" if hmac.compare_digest(mac, value) else "invalid"


# ---------------------------------------------------------------------------
# RADIUS
# ---------------------------------------------------------------------------

def _radius_exchanges(rows: List[Dict[str, Any]], recovered: set, secret: Optional[str] = None) -> List[Dict[str, Any]]:
    """Group RADIUS packets into transactions by (client, server, id, auth-vs-acct)."""
    transactions: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}
    order: List[Tuple[str, str, int, str]] = []
    for row in rows:
        code = _int_val(row, "radius.code")
        if code is None:
            continue
        rid = _int_val(row, "radius.id")
        is_acct = code in (4, 5)
        is_request = code in (1, 4)
        client_port = "udp.srcport" if is_request else "udp.dstport"
        server_port = "udp.dstport" if is_request else "udp.srcport"
        client = _endpoint(row, "src" if is_request else "dst", client_port)
        server = _endpoint(row, "dst" if is_request else "src", server_port)
        key = (client, server, rid if rid is not None else -1, "acct" if is_acct else "auth")
        tx = transactions.get(key)
        if tx is None:
            tx = {"client": client, "server": server, "id": rid, "kind": "accounting" if is_acct else "auth",
                  "request_code": None, "response_code": None, "username": None, "nas": None,
                  "calling_station": None, "acct_status": None, "authenticator_valid": None,
                  "message_authenticator": {"request": None, "response": None}, "credential_recovered": False,
                  "frames": [], "t": None, "_raw": {}}
            transactions[key] = tx
            order.append(key)
        frame = _int_val(row, "frame.number")
        if frame:
            tx["frames"].append(frame)
        if tx["t"] is None:
            tx["t"] = float(_val(row, "frame.time_epoch") or 0.0)
        name = _val(row, "radius.User_Name")
        if name and not tx["username"]:
            tx["username"] = name
        nas = _val(row, "radius.NAS_IP_Address") or _val(row, "radius.NAS_Identifier")
        if nas and not tx["nas"]:
            tx["nas"] = nas
        calling = _val(row, "radius.Calling_Station_Id")
        if calling and not tx["calling_station"]:
            tx["calling_station"] = calling
        acct = _int_val(row, "radius.Acct_Status_Type")
        if acct is not None:
            tx["acct_status"] = RADIUS_ACCT_STATUS.get(acct, str(acct))
        raw = _hex_bytes(_val(row, "udp.payload"))
        if raw:
            tx["_raw"].setdefault("request" if is_request else "response", (code, raw))
        if _val(row, "radius.authenticator.valid") in ("1", "True"):
            tx["authenticator_valid"] = True
        if _val(row, "radius.authenticator.invalid") in ("1", "True"):
            tx["authenticator_valid"] = False
        if _val(row, "radius.User_Password") or _val(row, "radius.CHAP_Password"):
            tx["credential_recovered"] = True
        if is_request:
            tx["request_code"] = RADIUS_CODES.get(code, str(code))
        else:
            tx["response_code"] = RADIUS_CODES.get(code, str(code))
    out = []
    for key in order:
        tx = transactions[key]
        tx["result"] = _radius_result(tx)
        request = tx["_raw"].get("request")
        for side, (code, raw) in tx["_raw"].items():
            if code in (1, 12):  # Access-Request, Status-Server: over the packet's own authenticator
                tx["message_authenticator"][side] = message_authenticator(raw, secret)
            elif code in (2, 3, 11) and request:  # responses: over the request's authenticator (RFC 3579 3.2)
                tx["message_authenticator"][side] = message_authenticator(raw, secret, request[1][4:20])
            else:
                state = message_authenticator(raw, None)
                tx["message_authenticator"][side] = "absent" if state == "absent" else "unchecked"
        del tx["_raw"]  # the raw messages carry the encrypted User-Password: never into a record
        out.append(tx)
    return out


def _radius_result(tx: Dict[str, Any]) -> str:
    resp = tx["response_code"]
    if resp == "Access-Accept":
        return "accept"
    if resp == "Access-Reject":
        return "reject"
    if resp == "Access-Challenge":
        return "challenge"
    if tx["kind"] == "accounting":
        return "accounted" if tx["response_code"] else "no_response"
    return "no_response" if tx["request_code"] else "orphan_response"


# ---------------------------------------------------------------------------
# TACACS+
# ---------------------------------------------------------------------------

def _tacacs_sessions(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group TACACS+ packets by session id into one session record each."""
    sessions: Dict[int, Dict[str, Any]] = {}
    order: List[int] = []
    for row in rows:
        sid = _int_val(row, "tacplus.session_id")
        if sid is None:
            continue
        session = sessions.get(sid)
        if session is None:
            session = {"session_id": sid, "client": None, "server": None, "user": None, "action": None,
                       "service": None, "priv_lvl": None, "cleartext": False, "types": set(),
                       "authentication": None, "authorization": None, "accounting": None,
                       "credential_recovered": False, "frames": [], "t": None}
            sessions[sid] = session
            order.append(sid)
        frame = _int_val(row, "frame.number")
        if frame:
            session["frames"].append(frame)
        if session["t"] is None:
            session["t"] = float(_val(row, "frame.time_epoch") or 0.0)
        ptype = _int_val(row, "tacplus.type")
        if ptype is not None:
            session["types"].add(TACACS_TYPES.get(ptype, str(ptype)))
        # The client is the side with the ephemeral port; the server listens on 49.
        sport, dport = _int_val(row, "tcp.srcport"), _int_val(row, "tcp.dstport")
        if dport == 49 and session["client"] is None:
            session["client"] = _endpoint(row, "src", "tcp.srcport")
            session["server"] = _endpoint(row, "dst", "tcp.dstport")
        elif sport == 49 and session["server"] is None:
            session["server"] = _endpoint(row, "src", "tcp.srcport")
            session["client"] = _endpoint(row, "dst", "tcp.dstport")
        flags = _int_val(row, "tacplus.flags")
        if flags is not None and flags & TACACS_UNENCRYPTED_FLAG:
            session["cleartext"] = True
        user = _val(row, "tacplus.user")
        if user and not session["user"]:
            session["user"] = user
        action = _int_val(row, "tacplus.authen_action")
        if action is not None and session["action"] is None:
            session["action"] = TACACS_ACTIONS.get(action, str(action))
        service = _int_val(row, "tacplus.service")
        if service is not None and session["service"] is None:
            session["service"] = TACACS_SERVICES.get(service, str(service))
        priv = _int_val(row, "tacplus.privilege_level")
        if priv is not None and session["priv_lvl"] is None:
            session["priv_lvl"] = priv
        authen = _int_val(row, "tacplus.body_authen_rep.status")
        if authen is not None:
            session["authentication"] = TACACS_AUTHEN_STATUS.get(authen, hex(authen))
        author = _int_val(row, "tacplus.body_author_rep.auth_status")
        if author is not None:
            session["authorization"] = TACACS_AUTHOR_STATUS.get(author, hex(author))
        acct = _int_val(row, "tacplus.body_acct.status")
        if acct is not None:
            session["accounting"] = TACACS_ACCT_STATUS.get(acct, hex(acct))
        if _val(row, "tacplus.auth_password") or _val(row, "tacplus.body_authen_req_cont.user"):
            session["credential_recovered"] = True
    out = []
    for sid in order:
        session = sessions[sid]
        session["types"] = sorted(session["types"])
        out.append(session)
    return out


# ---------------------------------------------------------------------------
# The analysis
# ---------------------------------------------------------------------------

def analyze_aaa_capture(file_path: str, keys_file: Optional[str] = None,
                        display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                        max_items: int = 25) -> Dict[str, Any]:
    """
    Troubleshoot TACACS+ and RADIUS in one capture, de-obfuscated with the operator's shared key.

    Returns the report (status "success") or {"status": "error", "error": ...}.
    """
    if not file_path or not os.path.exists(file_path):
        return _error(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        return _error(f"File not readable: {file_path}")
    if not tshark_available():
        return _error("AAA analysis needs tshark (Wireshark's TACACS+ and RADIUS dissectors); install it")
    if max_packets is not None and int(max_packets) <= 0:
        return _error("max_packets must be a positive number")
    tacacs_key = radius_secret = None
    if keys_file:
        if not os.path.isfile(keys_file) or not os.access(keys_file, os.R_OK):
            return _error("keys_file is not a readable file")
        try:
            tacacs_key, radius_secret = read_keys_file(keys_file)
        except (OSError, ValueError) as exc:
            return _error(f"cannot read the key file: {exc}")
    max_items = max(1, int(max_items or 25))

    try:
        radius_rows, tacacs_rows, recovered = extract_aaa(file_path, tacacs_key, radius_secret,
                                                          display_filter, max_packets)
    except RuntimeError as exc:
        return _error(str(exc))

    radius = _radius_exchanges(radius_rows, recovered, radius_secret)
    tacacs = _tacacs_sessions(tacacs_rows)

    start = min([e["t"] for e in radius + tacacs if e.get("t")], default=None)
    end = max([e["t"] for e in radius + tacacs if e.get("t")], default=None)

    issues: List[Dict[str, Any]] = []
    credentials: List[Dict[str, Any]] = []
    _radius_issues(radius, radius_secret is not None, issues, credentials)
    _tacacs_issues(tacacs, tacacs_key is not None, issues, credentials)

    verdict = _verdict(radius, tacacs, tacacs_key is not None, radius_secret is not None, credentials)
    listed_radius, radius_omitted = cap(radius, max_items)
    listed_tacacs, tacacs_omitted = cap(tacacs, max_items)
    present = bool(radius or tacacs)
    report = {
        "status": "success",
        "schema": REPORT_SCHEMA,
        "file": file_path,
        "overall_status": status_from_issues(issues, present),
        "verdict": verdict,
        "capture": {
            "start": iso_time(start), "end": iso_time(end),
            "tshark": tshark_version(),
            "tacacs_key_given": tacacs_key is not None,
            "radius_secret_given": radius_secret is not None,
            "display_filter": display_filter, "max_packets": max_packets,
        },
        "summary": {
            "radius_transactions": len(radius), "tacacs_sessions": len(tacacs),
            "accepts": sum(1 for e in radius if e["result"] == "accept")
            + sum(1 for s in tacacs if s["authentication"] == "PASS"),
            "rejects": sum(1 for e in radius if e["result"] == "reject")
            + sum(1 for s in tacacs if s["authentication"] == "FAIL"),
            "cleartext_tacacs_sessions": sum(1 for s in tacacs if s["cleartext"]),
            "credentials_recovered": sum(1 for e in radius if e["credential_recovered"])
            + sum(1 for s in tacacs if s["credential_recovered"]),
        },
        "radius": [_radius_view(e) for e in listed_radius],
        "radius_omitted": radius_omitted,
        "tacacs": [_tacacs_view(s) for s in listed_tacacs],
        "tacacs_omitted": tacacs_omitted,
        "credentials": credentials,
        "issues": sort_issues(issues),
        "limits": LIMITS,
    }
    # The shared keys never reach the report; they are scrubbed too, as for every recovered credential.
    secrets = sorted({v for v in set(recovered) | {tacacs_key or "", radius_secret or ""} if len(v) >= 3},
                     key=len, reverse=True)
    return _scrub(report, secrets)


def _radius_view(e: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in e.items() if k != "t"} | {
        "credential": "masked" if e["credential_recovered"] else None}


def _tacacs_view(s: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in s.items() if k != "t"} | {
        "credential": "masked" if s["credential_recovered"] else None}


def _radius_issues(radius, secret_given, issues, credentials) -> None:
    for e in radius:
        label = f"{e['client']} -> {e['server']} id {e['id']}"
        frames = e["frames"][:1]
        if e["result"] == "reject":
            issues.append(make_issue("warning", "AAA_ACCESS_REJECT",
                                     f"{label}: {e['username'] or 'a user'} was rejected (Access-Reject)",
                                     frames, username=e["username"]))
        elif e["result"] == "no_response" and e["kind"] == "auth":
            issues.append(make_issue("warning", "AAA_NO_RESPONSE",
                                     f"{label}: Access-Request for {e['username'] or 'a user'} got no response",
                                     frames))
        if secret_given and e["response_code"] and e["authenticator_valid"] is False:
            issues.append(make_issue("error", "RADIUS_BAD_AUTHENTICATOR",
                                     f"{label}: the {e['response_code']} response authenticator did not validate "
                                     "against the shared secret: the key is wrong, or the packet was altered",
                                     frames))
        mauth = e["message_authenticator"]
        for side, name in (("request", e["request_code"]), ("response", e["response_code"])):
            if mauth.get(side) == "invalid":
                issues.append(make_issue("error", "RADIUS_BAD_MESSAGE_AUTHENTICATOR",
                                         f"{label}: the {name} Message-Authenticator did not verify against the shared "
                                         "secret: the key is wrong, or the packet was altered", frames))
        if e["kind"] == "auth" and e["response_code"] in ("Access-Accept", "Access-Reject", "Access-Challenge") \
                and mauth.get("response") == "absent":
            issues.append(make_issue("warning", "RADIUS_NO_MESSAGE_AUTHENTICATOR",
                                     f"{label}: the {e['response_code']} carried no Message-Authenticator: such a "
                                     "response can be forged by Blast-RADIUS (CVE-2024-3596); have the server send "
                                     "it on every response and the client require it", frames))
        if e["credential_recovered"]:
            credentials.append({"protocol": "radius", "flow": f"{e['client']} -> {e['server']}",
                                "username": e["username"], "kind": "User-Password", "value": "masked"})
            issues.append(make_issue("info", "AAA_CREDENTIAL_RECOVERED",
                                     f"{label}: the User-Password for {e['username'] or 'a user'} was decrypted with "
                                     "the shared secret (value masked): anyone with the secret and the capture can "
                                     "read it", frames, username=e["username"]))


def _tacacs_issues(tacacs, key_given, issues, credentials) -> None:
    for s in tacacs:
        label = f"session {s['session_id']:#010x} {s['client']} -> {s['server']}"
        frames = s["frames"][:1]
        if s["cleartext"]:
            issues.append(make_issue("error", "AAA_CLEARTEXT_TACACS",
                                     f"{label}: the TACACS+ body is sent unobfuscated (the unencrypted flag is set): "
                                     "the user name, password and authorization cross the network readable",
                                     frames, user=s["user"]))
        if s["authentication"] == "FAIL":
            issues.append(make_issue("warning", "AAA_AUTH_FAIL",
                                     f"{label}: authentication FAILed for {s['user'] or 'a user'}", frames,
                                     user=s["user"]))
        if s["authorization"] in ("FAIL", "ERROR"):
            issues.append(make_issue("warning", "AAA_AUTHORIZATION_FAIL",
                                     f"{label}: authorization {s['authorization']} for {s['user'] or 'a user'}",
                                     frames, user=s["user"]))
        if s["credential_recovered"] and not s["cleartext"]:
            credentials.append({"protocol": "tacacs+", "flow": f"{s['client']} -> {s['server']}",
                                "username": s["user"], "kind": "password", "value": "masked"})
            issues.append(make_issue("info", "AAA_CREDENTIAL_RECOVERED",
                                     f"{label}: the password for {s['user'] or 'a user'} was de-obfuscated with the "
                                     "shared key (value masked): anyone with the key and the capture can read it",
                                     frames, user=s["user"]))


def _verdict(radius, tacacs, tacacs_key, radius_secret, credentials) -> str:
    if not radius and not tacacs:
        return "No TACACS+ or RADIUS found in this capture."
    parts = []
    if radius:
        accepts = sum(1 for e in radius if e["result"] == "accept")
        rejects = sum(1 for e in radius if e["result"] == "reject")
        tail = "" if radius_secret else " (no shared secret given: User-Password stays encrypted)"
        parts.append(f"{len(radius)} RADIUS transaction(s), {accepts} accept, {rejects} reject{tail}")
    if tacacs:
        clear = sum(1 for s in tacacs if s["cleartext"])
        tail = "" if tacacs_key else " (no key given: the bodies stay obfuscated)"
        parts.append(f"{len(tacacs)} TACACS+ session(s)"
                     + (f", {clear} sent unobfuscated" if clear else "") + tail)
    if credentials:
        parts.append(f"{len(credentials)} credential(s) recovered (masked)")
    return ". ".join(parts) + "."


def _scrub(value: Any, secrets: List[str]) -> Any:
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
