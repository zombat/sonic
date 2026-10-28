#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Data Plane Record Fields

Adds the header detail the data plane detectors need to each normalized record
from extractors/network.py, under one key, rec["dp"], so the existing record
keys keep their meaning. Both backends fill it: the tshark backend from extra
field columns (DATAPLANE_TSHARK_FIELDS, appended to the network extractor's
field list, so the capture is still read once), the scapy backend by parsing the
raw IP bytes here. The two must agree field for field; the backend parity test
in test_network_detectors.py holds them to it on every fixture.

rec["dp"] (present on every IP frame):
    hl      outer IP header length in bytes (IPv6: 40)
    tl      outer IP total length (IPv6: 40 + payload length)
    id      IPv4 identification (None for IPv6)
    df, mf  IPv4 Don't Fragment / More Fragments bits as 0/1 (None for IPv6)
    off     IPv4 fragment offset in bytes (0 for IPv6)
    dscp    DSCP of the outer header; ecn: its ECN bits
    inner   for GRE carrying IPv4: {"tl", "id", "df", "dscp", "ecn"} of the inner header
    tcp     when the frame carries TCP (outer, or inside GRE):
            {"seq", "ack", "win", "hl", "mss", "ws", "sack", "ts"}
            seq/ack are the raw 32-bit numbers, win the unscaled window field,
            mss/ws the MSS and window-scale shift options when present (else None),
            sack/ts whether SACK-permitted / timestamps options are present
    pl      the first PAYLOAD_HEAD bytes of the TCP or UDP payload (unfragmented
            packets with a payload only)
    ph      a short hash of the whole TCP or UDP payload (same condition as pl),
            used to match one packet across captures
    icmp    for an ICMP error: {"mtu", "orig_id", "orig_len", "orig_df"}: the next-hop
            MTU a Fragmentation Needed / Packet Too Big states, and the identification,
            total length and DF bit of the packet the error refers to

IPv6 extension headers (including the fragment header) are not walked: an IPv6
packet's fragment fields read as unfragmented.

Author: Raymond A Rizzo | Zombat
"""

import hashlib
import struct
from typing import Any, Dict, Optional

PAYLOAD_HEAD = 2048

# (record field key, candidate tshark field names), appended to TSHARK_FIELDS.
DATAPLANE_TSHARK_FIELDS = [
    ("dp.ip.hl", ["ip.hdr_len"]),
    ("dp.ip.len", ["ip.len"]),
    ("dp.ip.id", ["ip.id"]),
    ("dp.ip.df", ["ip.flags.df"]),
    ("dp.ip.mf", ["ip.flags.mf"]),
    ("dp.ip.dscp", ["ip.dsfield.dscp"]),
    ("dp.ip.ecn", ["ip.dsfield.ecn"]),
    ("dp.ip6.plen", ["ipv6.plen"]),
    ("dp.ip6.dscp", ["ipv6.tclass.dscp"]),
    ("dp.ip6.ecn", ["ipv6.tclass.ecn"]),
    ("dp.tcp.seq", ["tcp.seq_raw"]),
    ("dp.tcp.ack", ["tcp.ack_raw"]),
    ("dp.tcp.win", ["tcp.window_size_value"]),
    ("dp.tcp.hl", ["tcp.hdr_len"]),
    ("dp.tcp.mss", ["tcp.options.mss_val"]),
    ("dp.tcp.ws", ["tcp.options.wscale.shift"]),
    ("dp.tcp.kinds", ["tcp.option_kind"]),
    ("dp.tcp.payload", ["tcp.payload"]),
    ("dp.udp.payload", ["udp.payload"]),
    ("dp.icmp.mtu", ["icmp.mtu"]),
    ("dp.icmpv6.mtu", ["icmpv6.mtu"]),
]

# tshark options the data plane fields depend on: fragments stay per frame (no
# reassembly onto the last fragment), as the scapy backend sees them.
TSHARK_OPTIONS = ["-o", "ip.defragment:FALSE"]


def payload_hash(payload: bytes) -> str:
    """A short, stable digest of a payload (8 bytes of BLAKE2b, hex)."""
    return hashlib.blake2b(payload, digest_size=8).hexdigest()


def _bytes_from_hex(value: Optional[str]) -> bytes:
    if not value:
        return b""
    try:
        return bytes.fromhex(value.replace(":", ""))
    except ValueError:
        return b""


def _set_payload(dp: Dict[str, Any], payload: bytes):
    if payload:
        dp["pl"] = payload[:PAYLOAD_HEAD]
        dp["ph"] = payload_hash(payload)


# ---------------------------------------------------------------------------
# tshark backend
# ---------------------------------------------------------------------------

def fill_from_tshark(rec: Dict[str, Any], row) -> None:
    """Add rec["dp"] from a tshark field row (row is extractors.network._Row)."""
    ip = rec.get("ip")
    if not ip:
        return
    v6 = ip["v"] == 6
    if v6:
        plen = row.int("dp.ip6.plen") or 0
        dp: Dict[str, Any] = {"hl": 40, "tl": 40 + plen, "id": None, "df": None, "mf": None, "off": 0,
                              "dscp": row.int("dp.ip6.dscp") or 0, "ecn": row.int("dp.ip6.ecn") or 0}
    else:
        dp = {"hl": row.int("dp.ip.hl") or 20, "tl": row.int("dp.ip.len") or 0, "id": row.int("dp.ip.id"),
              "df": row.int("dp.ip.df") or 0, "mf": row.int("dp.ip.mf") or 0,
              "off": row.int("ip.frag_offset") or 0,
              "dscp": row.int("dp.ip.dscp") or 0, "ecn": row.int("dp.ip.ecn") or 0}
    rec["dp"] = dp
    fragment = bool(dp["mf"]) or dp["off"] > 0
    tunneled = "inner" in rec
    if tunneled:
        dp["inner"] = {"tl": row.int("dp.ip.len", 1) or 0, "id": row.int("dp.ip.id", 1),
                       "df": row.int("dp.ip.df", 1) or 0, "dscp": row.int("dp.ip.dscp", 1) or 0,
                       "ecn": row.int("dp.ip.ecn", 1) or 0}
    target = rec["inner"] if tunneled else rec
    if "tcp" in target:
        kinds = row.ints("dp.tcp.kinds")
        dp["tcp"] = {"seq": row.int("dp.tcp.seq") or 0, "ack": row.int("dp.tcp.ack") or 0,
                     "win": row.int("dp.tcp.win") or 0, "hl": row.int("dp.tcp.hl") or 20,
                     "mss": row.int("dp.tcp.mss"), "ws": row.int("dp.tcp.ws"),
                     "sack": 4 in kinds, "ts": 8 in kinds}
        if not fragment:
            _set_payload(dp, _bytes_from_hex(row.first("dp.tcp.payload")))
    elif "udp" in target and not fragment:
        _set_payload(dp, _bytes_from_hex(row.first("dp.udp.payload")))
    icmp = rec.get("icmp")
    if icmp and icmp.get("orig") is not None:
        layer = 2 if icmp.get("tunneled") else 1
        if icmp["v6"]:
            plen = row.int("dp.ip6.plen", layer)
            dp["icmp"] = {"mtu": row.int("dp.icmpv6.mtu") if icmp["type"] == 2 else None,
                          "orig_id": None, "orig_len": 40 + plen if plen is not None else None, "orig_df": None}
        else:
            dp["icmp"] = {"mtu": row.int("dp.icmp.mtu") if (icmp["type"], icmp["code"]) == (3, 4) else None,
                          "orig_id": row.int("dp.ip.id", layer), "orig_len": row.int("dp.ip.len", layer),
                          "orig_df": row.int("dp.ip.df", layer)}


# ---------------------------------------------------------------------------
# scapy backend (raw bytes)
# ---------------------------------------------------------------------------

def _ip4_header(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    tos = data[1]
    flags_frag = struct.unpack("!H", data[6:8])[0]
    return {"hl": (data[0] & 0x0F) * 4, "tl": struct.unpack("!H", data[2:4])[0],
            "id": struct.unpack("!H", data[4:6])[0], "df": (flags_frag >> 14) & 1, "mf": (flags_frag >> 13) & 1,
            "off": (flags_frag & 0x1FFF) * 8, "dscp": tos >> 2, "ecn": tos & 0x03}


def _tcp_header(seg: bytes) -> Optional[Dict[str, Any]]:
    if len(seg) < 20:
        return None
    seq, ack = struct.unpack("!II", seg[4:12])
    hl = (seg[12] >> 4) * 4
    win = struct.unpack("!H", seg[14:16])[0]
    out = {"seq": seq, "ack": ack, "win": win, "hl": hl, "mss": None, "ws": None, "sack": False, "ts": False}
    pos, end = 20, min(hl, len(seg))
    while pos < end:
        kind = seg[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 1 >= end:
            break
        length = seg[pos + 1]
        if length < 2:
            break
        body = seg[pos + 2:pos + length]
        if kind == 2 and len(body) == 2:
            out["mss"] = struct.unpack("!H", body)[0]
        elif kind == 3 and len(body) == 1:
            out["ws"] = body[0]
        elif kind == 4:
            out["sack"] = True
        elif kind == 8:
            out["ts"] = True
        pos += length
    return out


def _gre_payload(payload: bytes) -> Optional[bytes]:
    if len(payload) < 4:
        return None
    flags_ver = struct.unpack("!H", payload[0:2])[0]
    pos = 4
    for bit in (0x8000, 0x2000, 0x1000):
        if flags_ver & bit:
            pos += 4
    return payload[pos:]


def fill_from_bytes(rec: Dict[str, Any], raw: bytes) -> None:
    """Add rec["dp"] by parsing the raw IP packet bytes (IPv4 or IPv6)."""
    ip = rec.get("ip")
    if not ip or not raw:
        return
    if ip["v"] == 6:
        if len(raw) < 40:
            return
        plen = struct.unpack("!H", raw[4:6])[0]
        tclass = ((raw[0] & 0x0F) << 4) | (raw[1] >> 4)
        dp: Dict[str, Any] = {"hl": 40, "tl": 40 + plen, "id": None, "df": None, "mf": None, "off": 0,
                              "dscp": tclass >> 2, "ecn": tclass & 0x03}
        payload = raw[40:40 + plen] if plen else raw[40:]
    else:
        header = _ip4_header(raw)
        if header is None:
            return
        dp = header
        payload = raw[header["hl"]:header["tl"] or len(raw)]
    rec["dp"] = dp
    fragment = bool(dp["mf"]) or dp["off"] > 0
    l4 = payload
    target = rec
    if "inner" in rec:
        inner_raw = _gre_payload(payload) or b""
        inner = _ip4_header(inner_raw)
        if inner:
            dp["inner"] = {"tl": inner["tl"], "id": inner["id"], "df": inner["df"], "dscp": inner["dscp"],
                           "ecn": inner["ecn"]}
            l4 = inner_raw[inner["hl"]:inner["tl"] or len(inner_raw)]
        target = rec["inner"]
    if "tcp" in target:
        tcp = _tcp_header(l4)
        if tcp:
            dp["tcp"] = tcp
            if not fragment:
                _set_payload(dp, l4[tcp["hl"]:])
    elif "udp" in target and not fragment and len(l4) >= 8:
        length = struct.unpack("!H", l4[4:6])[0]
        _set_payload(dp, l4[8:length] if length >= 8 else l4[8:])
    icmp = rec.get("icmp")
    if icmp and icmp.get("orig") is not None:
        message = l4
        if icmp["v6"]:
            orig_plen = struct.unpack("!H", message[12:14])[0] if len(message) >= 14 else None
            mtu = struct.unpack("!I", message[4:8])[0] if icmp["type"] == 2 and len(message) >= 8 else None
            dp["icmp"] = {"mtu": mtu, "orig_id": None,
                          "orig_len": 40 + orig_plen if orig_plen is not None else None, "orig_df": None}
        else:
            orig = _ip4_header(message[8:])
            mtu = (struct.unpack("!H", message[6:8])[0] if (icmp["type"], icmp["code"]) == (3, 4)
                   and len(message) >= 8 else None)
            dp["icmp"] = {"mtu": mtu, "orig_id": orig["id"] if orig else None,
                          "orig_len": orig["tl"] if orig else None, "orig_df": orig["df"] if orig else None}
