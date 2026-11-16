#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. SNMP extraction (v1, v2c and v3, with SNMPv3 USM decryption)

Reads SNMP from a capture with Wireshark's own SNMP dissector through tshark. For SNMPv3
authPriv messages the dissector decrypts the scoped PDU when it has the user's USM keys;
S.O.N.I.C. supplies them through tshark's snmp_users UAT, written into a temporary
WIRESHARK_CONFIG_DIR (extractors/wsconfig.py), so the passphrases are never on the tshark
command line (not visible in the process argv).

The USM passphrases are secrets, read by path (an operator's users file) and handed here as
data; they are never logged, returned or written to a report. A v1/v2c community string is a
cleartext credential: it is read only to flag it, and the analyzer scrubs any echo of it.

What TShark 3.6.2 does, measured against net-snmp 5.9.4 (tests/fixtures/generate_snmp_fixtures.py):
    - the snmp_users UAT takes its two enum columns as labels: auth MD5, SHA1, SHA2-224, SHA2-256,
      SHA2-384, SHA2-512; priv DES, AES (AES-128), AES192, AES256. Nothing else is accepted (no 3DES,
      no separate "Cisco" entry): an unknown label is a table error on stderr and that user is dropped.
    - for AES192 and AES256 it extends a key that is shorter than the cipher needs the Reeder way
      (draft-reeder-snmpv3-usm-3desede, what Cisco implements). net-snmp extends it the
      draft-blumenthal-aes-usm-04 way, so net-snmp's AES-192/256 decrypts only when the auth hash is
      at least the key length (SHA2-256 or SHA2-512): with SHA1 or MD5 it cannot be decrypted.
    - SNMPv3 carries its version in snmp.msgVersion (snmp.version is v1/v2c only).
    - snmp.decrypted_pdu holds whatever a key produced, right or wrong; a message really decrypted
      when its scoped PDU dissected (snmp.data). A wrong key shows as a malformed packet or a
      "not formatted as expected" expert item, and a wrong auth passphrase as snmp.authentication_error.

Author: Raymond A Rizzo | Zombat
"""

import subprocess
import tempfile
from typing import Dict, List, Optional, Set, Tuple

from extractors.http2 import tshark_available, tshark_version  # noqa: F401 (re-exported for the analyzer)
from extractors.wsconfig import tshark_env, wireshark_config

SEP = "\x1f"

# Operator spellings -> the exact snmp_users UAT label tshark 3.6.2 accepts (checked one by one).
AUTH_LABELS = {
    "md5": "MD5", "hmac-md5": "MD5", "hmac-md5-96": "MD5",
    "sha": "SHA1", "sha1": "SHA1", "sha-1": "SHA1", "hmac-sha": "SHA1", "hmac-sha-96": "SHA1",
    "sha224": "SHA2-224", "sha-224": "SHA2-224", "sha2-224": "SHA2-224",
    "sha256": "SHA2-256", "sha-256": "SHA2-256", "sha2-256": "SHA2-256",
    "sha384": "SHA2-384", "sha-384": "SHA2-384", "sha2-384": "SHA2-384",
    "sha512": "SHA2-512", "sha-512": "SHA2-512", "sha2-512": "SHA2-512",
}
PRIV_LABELS = {
    "des": "DES", "cbc-des": "DES",
    "aes": "AES", "aes128": "AES", "aes-128": "AES", "cfb128-aes-128": "AES",
    "aes192": "AES192", "aes-192": "AES192",
    "aes256": "AES256", "aes-256": "AES256",
}
AUTH_HASH_BYTES = {"MD5": 16, "SHA1": 20, "SHA2-224": 28, "SHA2-256": 32, "SHA2-384": 48, "SHA2-512": 64}
PRIV_KEY_BYTES = {"DES": 16, "AES": 16, "AES192": 24, "AES256": 32}

SNMP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.srcport", "udp.dstport", "snmp.version", "snmp.msgVersion", "snmp.community",
    "snmp.msgUserName", "snmp.msgAuthoritativeEngineID", "snmp.v3.flags.auth", "snmp.v3.flags.crypt",
    "snmp.data", "snmp.decrypted_pdu", "_ws.malformed", "snmp.decrypted_data_bad_formatted",
    "snmp.failed_decrypted_data_pdu", "snmp.authentication_ok", "snmp.authentication_error",
    "snmp.verify_authentication_error", "snmp.name",  # an OID only; read for a Report's usmStats counter
]


class SnmpUsersError(ValueError):
    """A USM users file that cannot be parsed into usable users (the message never holds a passphrase)."""


_USER_ALIASES = {
    "user": "user", "username": "user", "name": "user", "securityname": "user",
    "engine_id": "engine_id", "engineid": "engine_id", "engine": "engine_id",
    "auth": "auth", "auth_proto": "auth", "auth_protocol": "auth", "authentication": "auth",
    "auth_pass": "auth_pass", "auth_passphrase": "auth_pass", "authpass": "auth_pass", "auth_password": "auth_pass",
    "priv": "priv", "priv_proto": "priv", "priv_protocol": "priv", "privacy": "priv",
    "priv_pass": "priv_pass", "priv_passphrase": "priv_pass", "privpass": "priv_pass", "priv_password": "priv_pass",
}
_CSV_ORDER = ["user", "auth", "auth_pass", "priv", "priv_pass", "engine_id"]


def parse_users_file(text: str) -> List[Dict[str, str]]:
    """
    USM users from an operator's users file, each normalised to tshark's labels. Two formats:

    - block (YAML-like): records separated by a blank line, a `---` or a `- user:` line, each a set
      of `name: value` lines (user, engine_id (optional), auth, auth_pass, priv, priv_pass);
    - CSV: one user per line, `user,auth,auth_pass,priv,priv_pass[,engine_id]` (a header row whose
      first column is `user` is skipped).

    auth and priv take net-snmp's spellings (MD5, SHA, SHA-224 ... SHA-512; DES, AES, AES-192,
    AES-256) or tshark's labels. A user without auth is noAuthNoPriv and needs no entry.

    Raises:
        SnmpUsersError: no user with a name, an algorithm tshark 3.6.2 does not offer, or a
            passphrase holding a double quote or backslash (the UAT format cannot carry them)
    """
    lines = text.splitlines()
    looks_csv = any("," in ln and ":" not in ln for ln in lines if ln.strip() and not ln.strip().startswith("#"))
    users = _parse_csv(lines) if looks_csv else _parse_blocks(lines)
    users = [u for u in users if u.get("user")]
    if not users:
        raise SnmpUsersError("no SNMPv3 user with a name found in the users file")
    for user in users:
        _normalise(user)
    return users


def _normalise(user: Dict[str, str]) -> None:
    auth = user.get("auth", "").strip()
    priv = user.get("priv", "").strip()
    if auth:
        label = AUTH_LABELS.get(auth.lower()) or (auth if auth in AUTH_HASH_BYTES else None)
        if label is None:
            raise SnmpUsersError(f"user {user['user']}: auth protocol {auth!r} is not one tshark 3.6.2 offers "
                                 f"({', '.join(AUTH_HASH_BYTES)})")
        user["auth"] = label
    if priv:
        label = PRIV_LABELS.get(priv.lower()) or (priv if priv in PRIV_KEY_BYTES else None)
        if label is None:
            raise SnmpUsersError(f"user {user['user']}: privacy protocol {priv!r} is not one tshark 3.6.2 offers "
                                 f"({', '.join(PRIV_KEY_BYTES)})")
        user["priv"] = label
    for key in ("auth_pass", "priv_pass"):
        if any(ch in user.get(key, "") for ch in '"\\'):
            raise SnmpUsersError(f"user {user['user']}: a {key} holding a double quote or a backslash cannot be "
                                 "written to tshark's users table")
    engine = (user.get("engine_id") or "").strip().lower()
    if engine.startswith("0x"):
        engine = engine[2:]
    user["engine_id"] = engine.replace(":", "").replace(" ", "")


def needs_key_extension(user: Dict[str, str]) -> bool:
    """Whether this user's privacy key is longer than its auth hash (AES-192/256 over SHA1 or MD5)."""
    auth, priv = user.get("auth"), user.get("priv")
    return bool(auth and priv in ("AES192", "AES256") and AUTH_HASH_BYTES[auth] < PRIV_KEY_BYTES[priv])


def _parse_csv(lines: List[str]) -> List[Dict[str, str]]:
    users = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if parts and parts[0].lower() in ("user", "username", "name"):
            continue  # header row
        user = {_CSV_ORDER[i]: value for i, value in enumerate(parts[:len(_CSV_ORDER)]) if value}
        if user.get("user"):
            users.append(user)
    return users


def _parse_blocks(lines: List[str]) -> List[Dict[str, str]]:
    users: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped in ("---", "[user]"):
            if current:
                users.append(current)
                current = {}
            continue
        line = stripped[1:].strip() if stripped.startswith("- ") else stripped
        sep = ":" if (":" in line and ("=" not in line or line.index(":") < line.index("="))) else "="
        if sep not in line:
            continue
        name, _, value = line.partition(sep)
        canon = _USER_ALIASES.get(name.strip().lower())
        value = value.strip().strip('"').strip("'")
        if canon and value:
            if canon == "user" and current.get("user"):
                users.append(current)
                current = {}
            current[canon] = value
    if current:
        users.append(current)
    return users


def user_uat_row(user: Dict[str, str]) -> str:
    """One snmp_users UAT record (engine id, user, auth label, auth pass, priv label, priv pass)."""
    fields = [user.get("engine_id", ""), user["user"], user.get("auth") or "MD5", user.get("auth_pass", ""),
              user.get("priv") or "DES", user.get("priv_pass", "")]
    return ",".join('"' + f + '"' for f in fields)


def extract_snmp(file_path: str, users: Optional[List[Dict[str, str]]] = None,
                 display_filter: Optional[str] = None, max_packets: Optional[int] = None
                 ) -> Tuple[List[Dict[str, str]], Set[str], List[str]]:
    """
    (snmp rows, community values, warnings) from the capture, decrypting SNMPv3 with the users' keys.

    The users with an auth protocol are written to the snmp_users UAT in a temporary
    WIRESHARK_CONFIG_DIR, never on the command line. Each row is the tshark fields for one SNMP
    message. The community strings are kept in memory only, so the analyzer can scrub any echo.
    warnings carries tshark's own complaints about the users table (an entry it refused).
    """
    uat_rows = [user_uat_row(u) for u in (users or []) if u.get("auth")]
    uats = {"snmp_users": uat_rows} if uat_rows else None
    rows: List[Dict[str, str]] = []
    warnings: List[str] = []
    stderr_text = ""
    with wireshark_config(uats=uats) as config_dir:
        env = tshark_env(config_dir)
        flt = "snmp"
        if display_filter:
            flt = f"({display_filter}) && snmp"
        command = ["tshark", "-n", "-r", file_path, "-Y", flt, "-T", "fields", "-E", "separator=\t",
                   "-E", "occurrence=a", "-E", f"aggregator={SEP}", "-E", "quote=n"]
        for name in SNMP_FIELDS:
            command += ["-e", name]
        if max_packets:
            command += ["-c", str(int(max_packets))]
        with tempfile.TemporaryFile(mode="w+") as err:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True, env=env, bufsize=1 << 16)
            produced = 0
            try:
                for line in proc.stdout:
                    produced += 1
                    parts = line.rstrip("\n").split("\t")
                    parts += [""] * (len(SNMP_FIELDS) - len(parts))
                    rows.append(dict(zip(SNMP_FIELDS, parts)))
            finally:
                if proc.poll() is None:
                    proc.stdout.close()
                    proc.terminate()
                proc.wait()
                err.seek(0)
                stderr_text = err.read()[-4000:].strip()
            if proc.returncode not in (0, None) and produced == 0:
                raise RuntimeError(f"tshark failed (exit {proc.returncode}): {stderr_text}")
    for line in stderr_text.splitlines():
        if "snmp_users" in line or "SNMP Users" in line:
            warnings.append(line.strip()[:300])  # names a table line and an enum column, never a passphrase
    communities: Set[str] = set()
    for row in rows:
        for value in row.get("snmp.community", "").split(SEP):
            if value:
                communities.add(value)
    return rows, communities, warnings
