#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. temporary Wireshark configuration (keys and UATs off the command line)

Some tshark decryptions take their key material from a preference (tacplus.key,
radius.shared_secret) or a UAT file (esp_sa, snmp_users), not from a key-log-style
file path. Passing a secret with `-o pref:VALUE` would put it in the tshark process's
argv, where any user on the box could read it from `ps` or /proc. To avoid that,
S.O.N.I.C. writes the preferences and UAT files into a private temporary directory
(0700, each file 0600) and points tshark at it with WIRESHARK_CONFIG_DIR, so the
secret never appears on a command line. The directory is removed when the context
exits, whatever happened.

No secret is ever logged, returned or written anywhere else. The caller reads the key
material by path (an operator-supplied file) and hands it here as data.

Author: Raymond A Rizzo | Zombat
"""

import contextlib
import os
import shutil
import tempfile
from typing import Dict, Iterator, List, Optional


@contextlib.contextmanager
def wireshark_config(preferences: Optional[Dict[str, str]] = None,
                     uats: Optional[Dict[str, List[str]]] = None) -> Iterator[str]:
    """
    A temporary WIRESHARK_CONFIG_DIR holding the given preferences and UAT files.

    Args:
        preferences: {pref name: value}, written to a `preferences` file (one `name: value`
            per line). Used for tacplus.key and radius.shared_secret, whose values are secrets.
        uats: {uat name: [record line, ...]}, each written to a file of that name (esp_sa,
            snmp_users). Each record line is a full UAT row as Wireshark stores it.

    Yields:
        the directory path, to pass as the WIRESHARK_CONFIG_DIR environment variable.
    """
    path = tempfile.mkdtemp(prefix="sonic-ws-")
    try:
        os.chmod(path, 0o700)
        if preferences:
            pref_path = os.path.join(path, "preferences")
            with open(os.open(pref_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w",
                      encoding="utf-8") as handle:
                for name, value in preferences.items():
                    handle.write(f"{name}: {value}\n")
        for name, rows in (uats or {}).items():
            uat_path = os.path.join(path, name)
            with open(os.open(uat_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w",
                      encoding="utf-8") as handle:
                for row in rows:
                    handle.write(row.rstrip("\n") + "\n")
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def tshark_env(config_dir: str) -> Dict[str, str]:
    """A copy of os.environ with WIRESHARK_CONFIG_DIR set to config_dir, for a tshark subprocess."""
    env = dict(os.environ)
    env["WIRESHARK_CONFIG_DIR"] = config_dir
    return env
