#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. TLS Secrets: what a key log covers, without keeping a secret

A TLS key log (NSS/SSLKEYLOGFILE format: "LABEL <client random> <secret>" per line) and
the Decryption Secrets Block a pcapng can carry (editcap --inject-secrets tls,KEYLOG)
hold the secrets tshark decrypts with. To say which TLS sessions in a capture they
cover, S.O.N.I.C. needs only the first two columns: which labels exist for which
client random. This module reads exactly that. Each line is split, the label and the
client random are kept, and the secret column is dropped before the next line is
read; no secret is stored, returned, logged or written anywhere. The key log itself is
still handed to tshark by path only (extractors/http2.py).

A client random is public: it is the 32-byte random of the session's ClientHello, sent
in the clear. It is used here to match sessions and is not put in a report.

Author: Raymond A Rizzo | Zombat
"""

import os
import struct
from typing import Dict, Iterable, Optional, Set

PCAPNG_SECTION = 0x0A0D0D0A
PCAPNG_DSB = 0x0000000A
DSB_TLS = 0x544C534B  # "TLSK": a TLS key log (NSS format)
BYTE_ORDER_MAGIC = 0x1A2B3C4D
MAX_SECRETS_BLOCK = 64 * 1024 * 1024

# Labels a TLS 1.2 or TLS 1.3 key log carries (NSS key log format).
TLS13_LABELS = ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0",
                "SERVER_TRAFFIC_SECRET_0")
KNOWN_LABELS = {"CLIENT_RANDOM", "CLIENT_EARLY_TRAFFIC_SECRET", "EARLY_EXPORTER_SECRET", "EXPORTER_SECRET",
                *TLS13_LABELS}


def labels_by_random(lines: Iterable[str]) -> Dict[str, Set[str]]:
    """{client random (lower-case hex): labels} from key log lines; the secret column is never kept."""
    out: Dict[str, Set[str]] = {}
    for line in lines:
        parts = line.split(None, 2)
        if len(parts) < 3 or parts[0] not in KNOWN_LABELS:
            continue  # a comment, an RSA line (keyed by encrypted pre-master secret) or not a key log line
        label, random = parts[0], parts[1].lower()
        del parts
        if len(random) == 64:
            out.setdefault(random, set()).add(label)
    return out


def key_log_labels(path: str) -> Dict[str, Set[str]]:
    """What a key log file covers, by client random (read line by line; secrets dropped)."""
    with open(path, "r", encoding="ascii", errors="replace") as handle:
        return labels_by_random(handle)


def pcapng_secrets(path: str) -> Optional[Dict[str, object]]:
    """
    The TLS secrets a pcapng carries in Decryption Secrets Blocks: {"blocks": n,
    "labels": {client random: labels}}, or None for a file that is not pcapng. Every other
    block is skipped by its length, without being read.
    """
    blocks = 0
    labels: Dict[str, Set[str]] = {}
    with open(path, "rb") as handle:
        head = handle.read(12)
        if len(head) < 12 or struct.unpack("<I", head[:4])[0] != PCAPNG_SECTION:
            return None
        order = "<" if struct.unpack("<I", head[8:12])[0] == BYTE_ORDER_MAGIC else ">"
        handle.seek(0)
        size = os.fstat(handle.fileno()).st_size
        pos = 0
        while pos + 12 <= size:
            handle.seek(pos)
            header = handle.read(8)
            if len(header) < 8:
                break
            btype = struct.unpack("<I", header[:4])[0]
            if btype == PCAPNG_SECTION:  # each section states its own byte order
                magic = handle.read(4)
                order = "<" if struct.unpack("<I", magic)[0] == BYTE_ORDER_MAGIC else ">"
            else:
                btype = struct.unpack(order + "I", header[:4])[0]
            length = struct.unpack(order + "I", header[4:8])[0]
            if length < 12 or length % 4 or pos + length > size:
                break  # a damaged block: stop rather than guess
            if btype == PCAPNG_DSB and length - 12 <= MAX_SECRETS_BLOCK:
                body = handle.read(length - 12)
                stype, slen = struct.unpack(order + "II", body[:8])
                if stype == DSB_TLS:
                    blocks += 1
                    for random, names in labels_by_random(body[8:8 + slen].decode("ascii", "replace")
                                                          .splitlines()).items():
                        labels.setdefault(random, set()).update(names)
                del body
            pos += length
    return {"blocks": blocks, "labels": labels}


def missing_labels(labels: Set[str], version: Optional[str]) -> list:
    """The labels a session of this version needs to be decrypted in full, and that are absent."""
    if version == "TLS1.3":
        return [label for label in TLS13_LABELS if label not in labels]
    if version in ("TLS1.2", "TLS1.1", "TLS1.0", "SSL3.0"):
        return [] if "CLIENT_RANDOM" in labels else ["CLIENT_RANDOM"]
    return []
