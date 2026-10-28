#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Data Plane Helpers

Small shared pieces for the data plane detectors (path_mtu, esp_overhead, tcp,
tls, qos) and the multi-capture tools: the transport view of a record (outer, or
the inner packet when GRE carries IPv4), DSCP names, and 32-bit sequence
arithmetic.

Author: Raymond A Rizzo | Zombat
"""

from typing import Any, Dict, Optional

DSCP_NAMES = {0: "CS0/BE", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13", 16: "CS2", 18: "AF21", 20: "AF22",
              22: "AF23", 24: "CS3", 26: "AF31", 28: "AF32", 30: "AF33", 32: "CS4", 34: "AF41", 36: "AF42",
              38: "AF43", 40: "CS5", 44: "VOICE-ADMIT", 46: "EF", 48: "CS6", 56: "CS7"}


def dscp_name(value: Optional[int]) -> str:
    if value is None:
        return "unknown"
    return DSCP_NAMES.get(value, f"DSCP {value}")


def transport(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    The addresses, L4 header and data plane fields of the packet a frame carries.

    For GRE carrying IPv4 this is the inner packet (marked tunneled, with the outer
    endpoints under "outer"); otherwise the outer packet. None for non-IP frames.
    """
    ip = rec.get("ip")
    dp = rec.get("dp")
    if not ip or dp is None:
        return None
    inner = rec.get("inner")
    if inner and dp.get("inner"):
        hdr = dp["inner"]
        return {"src": inner["src"], "dst": inner["dst"], "proto": inner["proto"], "tcp": inner.get("tcp"),
                "udp": inner.get("udp"), "dtcp": dp.get("tcp"), "tunneled": True, "dscp": hdr["dscp"],
                "ecn": hdr["ecn"], "id": hdr["id"], "tl": hdr["tl"], "df": hdr["df"],
                "outer": (ip["src"], ip["dst"]), "v6": False}
    return {"src": ip["src"], "dst": ip["dst"], "proto": ip["proto"], "tcp": rec.get("tcp"), "udp": rec.get("udp"),
            "dtcp": dp.get("tcp"), "tunneled": False, "dscp": dp["dscp"], "ecn": dp["ecn"], "id": dp["id"],
            "tl": dp["tl"], "df": dp["df"], "outer": None, "v6": ip["v"] == 6}


def is_fragment(rec: Dict[str, Any]) -> bool:
    dp = rec.get("dp") or {}
    return bool(dp.get("mf")) or (dp.get("off") or 0) > 0


def seq_delta(a: int, b: int) -> int:
    """a - b in 32-bit sequence space, as a signed number."""
    d = (a - b) & 0xFFFFFFFF
    return d - 0x100000000 if d >= 0x80000000 else d


def endpoint(addr: str, port: Optional[int]) -> str:
    if port is None:
        return addr
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def percentile(values, fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]
