#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. SNMP troubleshooting (v1, v2c and v3, with SNMPv3 USM decryption)

Reads SNMP from a capture with Wireshark's SNMP dissector through tshark, names every
message's version and, for v3, its security level, and - given a USM users file the operator
supplies - decrypts the authPriv scoped PDUs.

    - every message is named v1, v2c or v3; a v3 message also by its security level
      (noAuthNoPriv, authNoPriv, authPriv), and engine discovery (the empty-user probe and the
      agent's report) is named as such;
    - a v1 or v2c community string is flagged as a cleartext credential (value masked);
    - each v3 authenticated message says whether it authenticated and each authPriv message
      whether it decrypted, and when not, why: an unknown user, a user given for another engine,
      a wrong auth passphrase, a wrong privacy passphrase, or (AES-192/256 over an SHA1 or MD5
      user) a key-extension mismatch tshark 3.6.2 cannot bridge. Nothing is skipped silently;
    - an SNMPv3 Report from the agent is named by the usmStats counter it returns
      (usmStatsUnknownUserNames, usmStatsWrongDigests, usmStatsDecryptionErrors, ...), which is the
      agent's own verdict on the request before it.

The USM passphrases are secrets (read by path, kept off the tshark command line, never written
out); a decrypted scoped PDU's contents are never emitted, only its PDU type and that it
decrypted. A community string is masked at the source. The engine id and user name are shown
(they identify, they do not authenticate).

Author: Raymond A Rizzo | Zombat
"""

import os
from typing import Any, Dict, List, Optional

from analyzers.network_common import cap, iso_time, make_issue, sort_issues, status_from_issues
from extractors.snmp import (
    AUTH_HASH_BYTES, PRIV_KEY_BYTES, SEP, SnmpUsersError, extract_snmp, needs_key_extension, parse_users_file,
    tshark_available, tshark_version,
)

REPORT_SCHEMA = "sonic.snmp_report/1"

VERSION_NAMES = {0: "v1", 1: "v2c", 3: "v3"}
PDU_NAMES = {0: "get-request", 1: "get-next-request", 2: "response", 3: "set-request", 4: "trap",
             5: "get-bulk-request", 6: "inform-request", 7: "snmpV2-trap", 8: "report"}
USM_STATS = {
    "1.3.6.1.6.3.15.1.1.1.0": ("usmStatsUnsupportedSecLevels", "the agent does not support the security level asked"),
    "1.3.6.1.6.3.15.1.1.2.0": ("usmStatsNotInTimeWindows", "the request fell outside the agent's time window "
                               "(engine boots/time out of sync)"),
    "1.3.6.1.6.3.15.1.1.3.0": ("usmStatsUnknownUserNames", "the agent has no such user"),
    "1.3.6.1.6.3.15.1.1.4.0": ("usmStatsUnknownEngineIDs", "the request named another engine id (normal in engine "
                               "discovery)"),
    "1.3.6.1.6.3.15.1.1.5.0": ("usmStatsWrongDigests", "the request failed authentication at the agent: wrong auth "
                               "passphrase or protocol"),
    "1.3.6.1.6.3.15.1.1.6.0": ("usmStatsDecryptionErrors", "the agent could not decrypt the request: wrong privacy "
                               "passphrase or protocol"),
}

LIMITS = [
    "Only what crossed the capture point is read. A v3 message whose user is not in the users file, or is given for "
    "another engine id, is reported as not decrypted with that reason, never skipped silently.",
    "SNMPv3 decryption needs the right USM passphrases; a wrong auth passphrase fails authentication and a wrong "
    "privacy passphrase leaves the scoped PDU unreadable.",
    "TShark 3.6.2 offers auth MD5, SHA1, SHA2-224/256/384/512 and priv DES, AES-128, AES-192, AES-256. For AES-192/256 "
    "over an SHA1 or MD5 user it extends the key the Reeder (Cisco) way; an agent that extends it the Blumenthal-draft "
    "way, net-snmp among them, cannot be decrypted then (with SHA2-256 or SHA2-512 no extension is needed and it can).",
    "A v1 or v2c community string is a cleartext credential: anyone on the path reads it. It is flagged and masked.",
    "The USM passphrases are secrets: read by path, kept off the tshark command line (a temporary snmp_users table), "
    "and never written to a record, a log or a report. A decrypted PDU's contents are never emitted.",
]


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


def _all(row: Dict[str, str], name: str) -> List[str]:
    return [v for v in row.get(name, "").split(SEP) if v]


def _val(row: Dict[str, str], name: str) -> str:
    values = _all(row, name)
    return values[0] if values else ""


def _int(value: str) -> Optional[int]:
    try:
        return int(value, 0) if value != "" else None
    except ValueError:
        return None


def _flag(row: Dict[str, str], name: str) -> bool:
    return _val(row, name) in ("1", "True", "true")


def _endpoint(row: Dict[str, str], which: str) -> str:
    ip = _val(row, f"ip.{which}") or _val(row, f"ipv6.{which}")
    port = _val(row, f"udp.{'srcport' if which == 'src' else 'dstport'}")
    return f"{ip}:{port}" if port else ip


def analyze_snmp_capture(file_path: str, users_file: Optional[str] = None,
                         display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                         max_items: int = 25) -> Dict[str, Any]:
    """
    Troubleshoot SNMP in one capture: name every version, and decrypt SNMPv3 with the users file.

    Returns the report (status "success") or {"status": "error", "error": ...}.
    """
    if not file_path or not os.path.exists(file_path):
        return _error(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        return _error(f"File not readable: {file_path}")
    if not tshark_available():
        return _error("SNMP analysis needs tshark (Wireshark's SNMP dissector); install it")
    if max_packets is not None and int(max_packets) <= 0:
        return _error("max_packets must be a positive number")
    users: Optional[List[Dict[str, str]]] = None
    if users_file:
        if not os.path.isfile(users_file) or not os.access(users_file, os.R_OK):
            return _error("users_file is not a readable file")
        try:
            with open(users_file, "r", encoding="utf-8") as handle:
                users = parse_users_file(handle.read())
        except SnmpUsersError as exc:
            return _error(f"cannot read the users file: {exc}")
        except (OSError, UnicodeDecodeError) as exc:
            return _error(f"cannot read the users file: {getattr(exc, 'strerror', None) or type(exc).__name__}")
    max_items = max(1, int(max_items or 25))

    try:
        rows, communities, table_warnings = extract_snmp(file_path, users, display_filter=display_filter,
                                                         max_packets=max_packets)
    except RuntimeError as exc:
        return _error(str(exc))

    by_user = {u["user"]: u for u in (users or [])}
    messages: List[Dict[str, Any]] = []
    version_counts: Dict[str, int] = {}
    level_counts: Dict[str, int] = {}
    outcome_counts: Dict[str, int] = {}
    per_user: Dict[str, Dict[str, Any]] = {}
    issues: List[Dict[str, Any]] = []
    credentials: List[Dict[str, Any]] = []
    community_flows = set()
    start = end = None

    for row in rows:
        version = _int(_val(row, "snmp.msgVersion"))
        if version is None:
            version = _int(_val(row, "snmp.version"))
        if version is None:
            continue
        vname = VERSION_NAMES.get(version, f"v{version}")
        version_counts[vname] = version_counts.get(vname, 0) + 1
        frame = _int(_val(row, "frame.number"))
        frames = [frame] if frame else []
        try:
            t = float(_val(row, "frame.time_epoch") or "nan")
        except ValueError:
            t = None
        if t is not None and t == t:
            start = t if start is None else min(start, t)
            end = t if end is None else max(end, t)
        src, dst = _endpoint(row, "src"), _endpoint(row, "dst")
        pdu = _int(_val(row, "snmp.data"))
        msg: Dict[str, Any] = {"frame": frame, "version": vname, "src": src, "dst": dst,
                               "pdu": PDU_NAMES.get(pdu) if pdu is not None else None}

        if version in (0, 1):
            msg["security_level"] = "community"
            if _val(row, "snmp.community"):
                msg["credential"] = "masked"
                flow = tuple(sorted((src.rsplit(":", 1)[0], dst.rsplit(":", 1)[0])))  # one finding per link
                if (vname, flow) not in community_flows:
                    community_flows.add((vname, flow))
                    credentials.append({"protocol": vname, "flow": f"{flow[0]} -> {flow[1]}",
                                        "kind": "community string", "value": "masked"})
                    issues.append(make_issue("error", "SNMP_CLEARTEXT_COMMUNITY",
                                             f"{src} -> {dst}: an SNMP {vname} community string crosses the network "
                                             "in cleartext (value masked): anyone on the path can read it and use it; "
                                             "move to SNMPv3 authPriv", frames, version=vname))
            messages.append(msg)
            continue

        auth, crypt = _flag(row, "snmp.v3.flags.auth"), _flag(row, "snmp.v3.flags.crypt")
        level = "authPriv" if crypt else "authNoPriv" if auth else "noAuthNoPriv"
        level_counts[level] = level_counts.get(level, 0) + 1
        user_name = _val(row, "snmp.msgUserName")
        engine = _val(row, "snmp.msgAuthoritativeEngineID").replace(":", "").lower()
        msg.update({"security_level": level, "user": user_name or None, "engine_id": engine or None})
        if msg["pdu"] == "report":
            stat = _report_counter(row)
            if stat:
                msg["report"] = stat[0]
                msg["report_meaning"] = stat[1]
                if stat[0] != "usmStatsUnknownEngineIDs":
                    issues.append(make_issue("warning", "SNMP_AGENT_REPORT",
                                             f"{src} -> {dst}: the agent answered with a Report {stat[0]}"
                                             f"{' for user ' + repr(user_name) if user_name else ''}: {stat[1]}",
                                             frames, counter=stat[0]))
        if not user_name and level == "noAuthNoPriv":
            msg["role"] = "engine discovery"
        if auth:
            outcome, reason = _v3_outcome(row, crypt, user_name, engine, by_user, users is not None)
            msg["outcome"], msg["reason"] = outcome, reason
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
            tally = per_user.setdefault(user_name or "?", {"user": user_name or None, "messages": 0, "outcomes": {}})
            tally["messages"] += 1
            tally["outcomes"][outcome] = tally["outcomes"].get(outcome, 0) + 1
            _v3_issue(msg, outcome, reason, src, dst, frames, issues)
        messages.append(msg)

    if table_warnings:
        for line in table_warnings:
            issues.append(make_issue("error", "SNMP_USERS_TABLE_REFUSED",
                                     f"tshark refused a line of the users table: {line}"))
    for name, user in by_user.items():
        if name not in per_user and user.get("auth"):
            issues.append(make_issue("info", "SNMP_USER_NOT_SEEN",
                                     f"user {name!r} from the users file sent no authenticated message in this capture"))

    verdict = _verdict(version_counts, level_counts, outcome_counts, credentials, users is not None)
    listed, omitted = cap(messages, max_items * 4)
    report = {
        "status": "success",
        "schema": REPORT_SCHEMA,
        "file": file_path,
        "overall_status": status_from_issues(issues, bool(messages)),
        "verdict": verdict,
        "capture": {
            "start": iso_time(start), "end": iso_time(end),
            "tshark": tshark_version(),
            "users_file_given": users is not None,
            "users_count": len(users) if users else 0,
            "display_filter": display_filter, "max_packets": max_packets,
            "warnings": table_warnings,
        },
        "summary": {
            "messages": len(messages), "versions": version_counts, "v3_security_levels": level_counts,
            "v3_outcomes": outcome_counts,
            "authpriv_decrypted": outcome_counts.get("decrypted", 0),
            "authpriv_not_decrypted": sum(n for k, n in outcome_counts.items()
                                          if k in ("decrypt_failed", "auth_failed", "unknown_user", "unknown_engine",
                                                   "no_keys", "not_attempted")),
            "cleartext_communities": len(credentials),
        },
        "v3_users": sorted(per_user.values(), key=lambda u: u["user"] or ""),
        "messages": listed,
        "messages_omitted": omitted,
        "credentials": credentials,
        "issues": sort_issues(issues),
        "limits": LIMITS,
    }
    secrets = {c for c in communities}
    for user in users or []:
        secrets.update(v for v in (user.get("auth_pass"), user.get("priv_pass")) if v)
    return _scrub(report, sorted((s for s in secrets if len(s) >= 3), key=len, reverse=True))


def _report_counter(row: Dict[str, str]):
    for oid in _all(row, "snmp.name"):
        if oid in USM_STATS:
            return USM_STATS[oid]
    return None


def _v3_outcome(row, crypt, user_name, engine, by_user, users_given):
    """
    The outcome of one authenticated v3 message, from what tshark did with it:
    authenticated / decrypted / auth_failed / decrypt_failed / unknown_user / unknown_engine /
    no_keys / not_attempted, and a reason sentence.
    """
    attempted = bool(_val(row, "snmp.authentication_ok") or _val(row, "snmp.authentication_error")
                     or _val(row, "snmp.decrypted_pdu") or _val(row, "_ws.malformed")
                     or _val(row, "snmp.decrypted_data_bad_formatted") or _val(row, "snmp.failed_decrypted_data_pdu"))
    dissected = _val(row, "snmp.data") != ""
    user = by_user.get(user_name)
    if _val(row, "snmp.authentication_error") or _val(row, "snmp.verify_authentication_error"):
        tail = " (the privacy key still decrypted it)" if crypt and dissected else ""
        return "auth_failed", ("authentication failed: the auth passphrase or protocol in the users file does not "
                               f"match the one this message was sent with{tail}")
    if crypt and dissected:
        return "decrypted", None
    if not crypt and _val(row, "snmp.authentication_ok"):
        return "authenticated", None
    if attempted and crypt:
        if user and needs_key_extension(user):
            return "decrypt_failed", (
                f"decryption failed. This user's {user['priv']} key ({PRIV_KEY_BYTES[user['priv']] * 8} bits) is longer "
                f"than its {user['auth']} hash ({AUTH_HASH_BYTES[user['auth']] * 8} bits), so tshark 3.6.2 extends it "
                "the Reeder (Cisco) way: an agent that extends it the Blumenthal-draft way (net-snmp, among others) "
                "cannot be decrypted with tshark 3.6.2; a wrong privacy passphrase looks the same")
        return "decrypt_failed", ("decryption failed: authentication passed, so the user and engine match, and the "
                                  "privacy passphrase or protocol is wrong" if _val(row, "snmp.authentication_ok")
                                  else "decryption failed: the privacy passphrase or protocol is wrong")
    if not users_given:
        return "no_keys", "no users file was given, so the message's keys are unknown"
    if user is None:
        return "unknown_user", f"unknown user: the users file has no entry for user {user_name!r}"
    if user.get("engine_id") and engine and user["engine_id"] != engine:
        return "unknown_engine", (f"unknown engine: the users file gives user {user_name!r} only for engine "
                                  f"{user['engine_id']}, and this message is from engine {engine}")
    if not user.get("auth"):
        return "not_attempted", f"the users file gives user {user_name!r} no auth protocol"
    return "not_attempted", "tshark did not apply this user's keys to the message (check the protocols)"


def _v3_issue(msg, outcome, reason, src, dst, frames, issues) -> None:
    codes = {"auth_failed": ("warning", "SNMP_AUTH_FAILED"), "decrypt_failed": ("warning", "SNMP_DECRYPT_FAILED"),
             "unknown_user": ("warning", "SNMP_UNKNOWN_USER"), "unknown_engine": ("warning", "SNMP_UNKNOWN_ENGINE"),
             "no_keys": ("info", "SNMP_NOT_DECRYPTED"), "not_attempted": ("warning", "SNMP_NOT_DECRYPTED")}
    if outcome not in codes:
        return
    severity, code = codes[outcome]
    issues.append(make_issue(severity, code, f"{src} -> {dst}: SNMPv3 {msg['security_level']} message from user "
                                             f"{msg.get('user') or '?'!r}: {reason}", frames, user=msg.get("user")))


def _verdict(version_counts, level_counts, outcome_counts, credentials, users_given) -> str:
    if not version_counts:
        return "No SNMP found in this capture."
    parts = [", ".join(f"{n} {v}" for v, n in sorted(version_counts.items())) + " message(s)"]
    if level_counts:
        parts.append("v3 security levels: " + ", ".join(f"{n} {lvl}" for lvl, n in sorted(level_counts.items())))
    if level_counts.get("authPriv"):
        total = level_counts["authPriv"]
        if users_given:
            done = outcome_counts.get("decrypted", 0)
            others = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in sorted(outcome_counts.items())
                               if k not in ("decrypted", "authenticated"))
            parts.append(f"{done} of {total} authPriv message(s) decrypted" + (f" ({others})" if others else ""))
        else:
            parts.append(f"{total} authPriv message(s) left encrypted: no users file given")
    if credentials:
        parts.append(f"{len(credentials)} cleartext community credential flow(s) (values masked)")
    return ". ".join(parts) + "."


def _scrub(value: Any, secrets: List[str]) -> Any:
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            if secret in value:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value
