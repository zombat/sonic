#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. TACACS+ and RADIUS extraction (de-obfuscated with a shared key)

Reads TACACS+ and RADIUS from a capture with Wireshark's own dissectors through tshark.
TACACS+ bodies are obfuscated with an MD5 pad of the shared key, and the RADIUS
User-Password is encrypted with the shared secret and the request authenticator;
tshark's tacplus.key and radius.shared_secret preferences undo both. S.O.N.I.C. passes
the key material to tshark through a temporary WIRESHARK_CONFIG_DIR (extractors/wsconfig.py),
never on the command line, so the secret is not visible in the tshark process's argv.

Any recovered credential (a de-obfuscated password, a decrypted User-Password) is read only
to note that it was recovered and to let the analyzer scrub any echo of it; it is never
returned in a record. The shared key is never read, logged or returned here.

Author: Raymond A Rizzo | Zombat
"""

import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

from extractors.http2 import tshark_available, tshark_version  # noqa: F401 (re-exported for the analyzer)
from extractors.wsconfig import tshark_env, wireshark_config

SEP = "\x1f"

RADIUS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.srcport", "udp.dstport", "radius.code", "radius.id",
    "radius.User_Name", "radius.User_Password", "radius.CHAP_Password", "radius.State",
    "radius.NAS_IP_Address", "radius.NAS_Identifier", "radius.Calling_Station_Id", "radius.Called_Station_Id",
    "radius.Acct_Status_Type", "radius.Acct_Session_Id", "radius.Reply_Message",
    "radius.authenticator.valid", "radius.authenticator.invalid", "radius.Message_Authenticator",
    # The raw RADIUS message, kept in memory only, so the analyzer can check a Message-Authenticator
    # (tshark 3.6.2 validates the Response Authenticator but not the Message-Authenticator).
    "udp.payload",
]

TACACS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tacplus.session_id", "tacplus.type", "tacplus.seqno", "tacplus.flags",
    "tacplus.authen_action", "tacplus.privilege_level", "tacplus.authentication_type", "tacplus.service",
    "tacplus.user", "tacplus.auth_password", "tacplus.body_authen_rep.status", "tacplus.body_authen_rep.server_msg",
    "tacplus.body_authen_req_cont.user", "tacplus.body_author_rep.auth_status", "tacplus.body_acct.status",
    "tacplus.acct.flags",
]

# Fields whose value is or may be a recovered credential: read only to note recovery and to scrub.
RADIUS_SECRET_FIELDS = ("radius.User_Password", "radius.CHAP_Password")
TACACS_SECRET_FIELDS = ("tacplus.auth_password", "tacplus.body_authen_req_cont.user")


def _run_fields(file_path: str, display: str, fields: List[str], env: Dict[str, str],
                display_filter: Optional[str], max_packets: Optional[int]) -> List[Dict[str, str]]:
    flt = display
    if display_filter:
        flt = f"({display_filter}) && ({display})"
    command = ["tshark", "-n", "-r", file_path, "-Y", flt, "-T", "fields", "-E", "separator=\t",
               "-E", "occurrence=a", "-E", f"aggregator={SEP}", "-E", "quote=n"]
    for name in fields:
        command += ["-e", name]
    if max_packets:
        command += ["-c", str(int(max_packets))]
    rows: List[Dict[str, str]] = []
    with tempfile.TemporaryFile(mode="w+") as err:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True, env=env, bufsize=1 << 16)
        produced = 0
        try:
            for line in proc.stdout:
                produced += 1
                parts = line.rstrip("\n").split("\t")
                parts += [""] * (len(fields) - len(parts))
                rows.append(dict(zip(fields, parts)))
        finally:
            if proc.poll() is None:
                proc.stdout.close()
                proc.terminate()
            proc.wait()
            err.seek(0)
            stderr_text = err.read()[-2000:].strip()
        if proc.returncode not in (0, None) and produced == 0:
            raise RuntimeError(f"tshark failed (exit {proc.returncode}): {stderr_text}")
    return rows


def _first(row: Dict[str, str], name: str) -> str:
    return row.get(name, "").split(SEP)[0]


def extract_aaa(file_path: str, tacacs_key: Optional[str], radius_secret: Optional[str],
                display_filter: Optional[str] = None, max_packets: Optional[int] = None
                ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Set[str]]:
    """
    (radius rows, tacacs rows, recovered-credential values) from the capture.

    The keys are written to a temporary WIRESHARK_CONFIG_DIR (never on the command line);
    a None key means that protocol is read without a key (versions and metadata only). Each
    row is the tshark fields for one packet, lists joined on SEP. The third return holds the
    recovered credential values, in memory only, so the analyzer can scrub any echo of one.
    """
    preferences: Dict[str, str] = {}
    if tacacs_key:
        preferences["tacplus.key"] = tacacs_key
    if radius_secret:
        preferences["radius.shared_secret"] = radius_secret
        preferences["radius.validate_authenticator"] = "TRUE"
    with wireshark_config(preferences=preferences) as config_dir:
        env = tshark_env(config_dir)
        radius_rows = _run_fields(file_path, "radius", RADIUS_FIELDS, env, display_filter, max_packets)
        tacacs_rows = _run_fields(file_path, "tacplus", TACACS_FIELDS, env, display_filter, max_packets)
    secrets: Set[str] = set()
    for row in radius_rows:
        for name in RADIUS_SECRET_FIELDS:
            for value in row.get(name, "").split(SEP):
                if value and len(value) >= 3:
                    secrets.add(value)
    for row in tacacs_rows:
        for name in TACACS_SECRET_FIELDS:
            for value in row.get(name, "").split(SEP):
                if value and len(value) >= 3:
                    secrets.add(value)
    return radius_rows, tacacs_rows, secrets
