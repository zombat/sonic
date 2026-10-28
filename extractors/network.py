#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Network Packet Extraction Module

Extracts the fields the non-SIP network detectors need (IPsec/IKE, ESP, GRE,
NHRP, BGP, OSPF, EIGRP, ICMP, ARP and generic L3/L4 framing) from a pcap or
pcapng file, using the same strategy as the SIP extractor in extractors/tshark.py:
tshark first, scapy as the fallback.

Both backends produce the same normalized packet record, one dict per frame, so
every detector works the same way whichever backend ran. Records are yielded one
at a time (a generator), so a large capture is never held in memory at once.

Record keys (a key is present only when the frame carries that protocol):
    n            frame number (1-based, as Wireshark numbers frames)
    t            capture timestamp, epoch seconds (float)
    len          frame length in bytes
    eth_type     EtherType of a non-IP frame (ARP is 0x0806)
    llc          "cdp" | "stp" | "llc" for an 802.3/LLC frame (no EtherType)
    ip           outer IP header: {"v": 4|6, "src", "dst", "proto", "ttl"}
    tcp          {"sport", "dport", "flags", "len"}       (outer TCP; a SYN also
                  carries "mss" when the MSS option is present)
    udp          {"sport", "dport", "len"}                (outer UDP, len = payload bytes)
    inner        IPv4 header carried inside GRE: {"src", "dst", "proto"}
    ike          {"version", "ispi", "rspi", "exch", "flags", "msgid", "length",
                  "notify": [types], "encrypted": bool, "natt": bool,
                  "payloads": [cleartext payload types, in order],
                  "proposals": [{"num", "protocol", "spi", "transforms": [{"type", "id", "key_length"}]}],
                  "ke_group": int|None, "natd_src": [hex], "natd_dst": [hex],
                  "invalid_ke_group": int|None, "invalid_spis": [hex]}
                 Both backends parse the IKE bytes with parse_ike (tshark hands over
                 udp.payload), so the decoded fields are identical by construction.
    esp          {"spi", "seq", "udp": bool}
    nat_keepalive True for a NAT-T keepalive (a one-byte 0xFF on UDP 4500)
    gre          {"key": int|None, "ptype": int}
    nhrp         {"op", "src_nbma", "src_proto", "dst_proto", "reqid", "code",
                  "err_code", "client_nbma", "client_proto", "prefix",
                  "orig_src", "orig_dst"}
    bgp          [{"type", "len", "myas", "hold", "bgp_id", "as4", "major", "minor",
                   "caps": [capability codes] (OPEN only, else None)}, ...]
    bgp_nlri     IPv4 prefixes announced in this frame's UPDATEs
    bgp_withdrawn IPv4 prefixes withdrawn in this frame's UPDATEs
    ospf         {"type", "rid", "area", "auth", "mask", "hello", "dead", "prio",
                  "dr", "bdr", "neighbors": [...], "options", "mtu",
                  "dbd_flags", "dd_seq"}                   (mtu/dbd_flags/dd_seq: DB Description only)
    eigrp        {"opcode", "as", "flags", "seq", "ack", "tlvs": [...], "k": [6]|None,
                  "hold": int|None}
    icmp         {"v6": bool, "type", "code", "id", "seq", "src", "dst",
                  "tunneled": bool, "orig": {"src", "dst", "proto", "dport"}|None}
    arp          {"op", "spa", "tpa", "sha"}
    sip          True when the frame is SIP (the SIP path in analyzers/ handles it)

Author: Raymond A Rizzo | Zombat
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import ipaddress
from typing import Any, Dict, Iterator, List, Optional

# ---------------------------------------------------------------------------
# tshark backend
# ---------------------------------------------------------------------------

# (record field key, candidate tshark field names). The first candidate this
# tshark knows is used; a key with no known candidate is reported as missing,
# so a renamed field in another Wireshark release degrades visibly, not silently.
TSHARK_FIELDS = [
    ("frame.number", ["frame.number"]),
    ("frame.time_epoch", ["frame.time_epoch"]),
    ("frame.len", ["frame.len"]),
    ("frame.protocols", ["frame.protocols"]),
    ("eth.type", ["eth.type"]),
    ("ip.src", ["ip.src"]),
    ("ip.dst", ["ip.dst"]),
    ("ip.proto", ["ip.proto"]),
    ("ip.ttl", ["ip.ttl"]),
    ("ip.frag_offset", ["ip.frag_offset"]),
    ("ipv6.src", ["ipv6.src"]),
    ("ipv6.dst", ["ipv6.dst"]),
    ("ipv6.nxt", ["ipv6.nxt"]),
    ("ipv6.hlim", ["ipv6.hlim"]),
    ("tcp.srcport", ["tcp.srcport"]),
    ("tcp.dstport", ["tcp.dstport"]),
    ("tcp.flags", ["tcp.flags"]),
    ("tcp.len", ["tcp.len"]),
    ("tcp.mss", ["tcp.options.mss_val"]),
    ("udp.srcport", ["udp.srcport"]),
    ("udp.dstport", ["udp.dstport"]),
    ("udp.length", ["udp.length"]),
    ("udp.payload", ["udp.payload"]),
    ("udpencap.non_esp_marker", ["udpencap.non_esp_marker"]),
    ("udpencap.nat_keepalive", ["udpencap.nat_keepalive"]),
    ("isakmp.ispi", ["isakmp.ispi"]),
    ("isakmp.rspi", ["isakmp.rspi"]),
    ("isakmp.version", ["isakmp.version"]),
    ("isakmp.exchtype", ["isakmp.exchangetype", "isakmp.exchtype"]),
    ("isakmp.flags", ["isakmp.flags"]),
    ("isakmp.messageid", ["isakmp.messageid"]),
    ("isakmp.length", ["isakmp.length"]),
    ("isakmp.notify.msgtype", ["isakmp.notify.msgtype"]),
    ("isakmp.typepayload", ["isakmp.typepayload"]),
    ("esp.spi", ["esp.spi"]),
    ("esp.sequence", ["esp.sequence"]),
    ("gre.key", ["gre.key"]),
    ("gre.proto", ["gre.proto"]),
    ("nhrp.op", ["nhrp.hdr.op.type"]),
    ("nhrp.src_nbma", ["nhrp.src.nbma.addr"]),
    ("nhrp.src_proto", ["nhrp.src.prot.addr"]),
    ("nhrp.dst_proto", ["nhrp.dst.prot.addr"]),
    ("nhrp.reqid", ["nhrp.reqid"]),
    ("nhrp.code", ["nhrp.code"]),
    ("nhrp.err_code", ["nhrp.err.code"]),
    ("nhrp.client_nbma", ["nhrp.client.nbma.addr"]),
    ("nhrp.client_proto", ["nhrp.client.prot.addr"]),
    ("nhrp.prefix", ["nhrp.prefix"]),
    ("bgp.type", ["bgp.type"]),
    ("bgp.length", ["bgp.length"]),
    ("bgp.myas", ["bgp.open.myas"]),
    ("bgp.hold", ["bgp.open.holdtime"]),
    ("bgp.id", ["bgp.open.identifier"]),
    ("bgp.as4", ["bgp.cap.4as"]),
    ("bgp.caps", ["bgp.cap.type"]),
    ("bgp.major", ["bgp.notify.major_error"]),
    ("bgp.minor", ["bgp.notify.minor_error"]),
    ("bgp.minor_open", ["bgp.notify.minor_error_open"]),
    ("bgp.minor_update", ["bgp.notify.minor_error_update"]),
    ("bgp.minor_expired", ["bgp.notify.minor_error_expired"]),
    ("bgp.minor_state", ["bgp.notify.minor_error_state"]),
    ("bgp.minor_cease", ["bgp.notify.minor_error_cease"]),
    ("bgp.minor_capability", ["bgp.notify.minor_error_capability"]),
    ("bgp.nlri", ["bgp.nlri_prefix"]),
    ("bgp.withdrawn", ["bgp.withdrawn_prefix"]),
    ("ospf.msg", ["ospf.msg"]),
    ("ospf.rid", ["ospf.srcrouter"]),
    ("ospf.area", ["ospf.area_id"]),
    ("ospf.auth", ["ospf.auth.type"]),
    ("ospf.mask", ["ospf.hello.network_mask"]),
    ("ospf.hello", ["ospf.hello.hello_interval"]),
    ("ospf.dead", ["ospf.hello.router_dead_interval"]),
    ("ospf.prio", ["ospf.hello.router_priority"]),
    ("ospf.dr", ["ospf.hello.designated_router"]),
    ("ospf.bdr", ["ospf.hello.backup_designated_router"]),
    ("ospf.neighbors", ["ospf.hello.active_neighbor"]),
    ("ospf.options", ["ospf.v2.options"]),
    ("ospf.mtu", ["ospf.db.interface_mtu"]),
    ("ospf.dbd", ["ospf.dbd"]),
    ("ospf.dd_seq", ["ospf.db.dd_sequence"]),
    ("eigrp.opcode", ["eigrp.opcode"]),
    ("eigrp.as", ["eigrp.as"]),
    ("eigrp.flags", ["eigrp.flags"]),
    ("eigrp.seq", ["eigrp.seq"]),
    ("eigrp.ack", ["eigrp.ack"]),
    ("eigrp.tlv", ["eigrp.tlv_type"]),
    ("eigrp.k1", ["eigrp.par.k1"]),
    ("eigrp.k2", ["eigrp.par.k2"]),
    ("eigrp.k3", ["eigrp.par.k3"]),
    ("eigrp.k4", ["eigrp.par.k4"]),
    ("eigrp.k5", ["eigrp.par.k5"]),
    ("eigrp.k6", ["eigrp.par.k6"]),
    ("eigrp.hold", ["eigrp.par.holdtime"]),
    ("icmp.type", ["icmp.type"]),
    ("icmp.code", ["icmp.code"]),
    ("icmp.ident", ["icmp.ident"]),
    ("icmp.seq", ["icmp.seq"]),
    ("icmpv6.type", ["icmpv6.type"]),
    ("icmpv6.code", ["icmpv6.code"]),
    ("icmpv6.ident", ["icmpv6.echo.identifier"]),
    ("icmpv6.seq", ["icmpv6.echo.sequence_number"]),
    ("arp.opcode", ["arp.opcode"]),
    ("arp.spa", ["arp.src.proto_ipv4"]),
    ("arp.tpa", ["arp.dst.proto_ipv4"]),
    ("arp.sha", ["arp.src.hw_mac"]),
]

# Field keys whose absence matters to a detector (used to report degraded coverage).
_ESSENTIAL_PREFIXES = ("frame.", "ip.", "tcp.", "udp.")

_FIELD_CACHE: Optional[Dict[str, str]] = None

ICMP_ERROR_TYPES = {3, 4, 5, 11, 12}
ICMPV6_ERROR_TYPES = {1, 2, 3, 4}


def _resolve_tshark_fields() -> Dict[str, str]:
    """
    Map each record field key to the tshark field name this tshark supports.

    Runs `tshark -G fields` once per process and caches the answer. A key whose
    candidates are all unknown is left out; callers report it as missing.
    """
    global _FIELD_CACHE
    if _FIELD_CACHE is not None:
        return _FIELD_CACHE
    wanted = {name for _, names in TSHARK_FIELDS for name in names}
    known = set()
    try:
        proc = subprocess.Popen(["tshark", "-G", "fields"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            parts = line.split("\t", 3)
            if len(parts) > 2 and parts[0] == "F" and parts[2] in wanted:
                known.add(parts[2])
        proc.wait()
    except (OSError, subprocess.SubprocessError):
        known = set()
    resolved = {}
    for key, names in TSHARK_FIELDS:
        for name in names:
            if name in known:
                resolved[key] = name
                break
    _FIELD_CACHE = resolved
    return resolved


def _to_int(value: Optional[str]) -> Optional[int]:
    """Parse a tshark value ("12", "0x0c", "True") into an int, or None."""
    if value is None or value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        if value in ("True", "true"):
            return 1
        if value in ("False", "false"):
            return 0
        try:
            return int(float(value))
        except ValueError:
            return None


def _hex_bytes(value: Optional[str]) -> Optional[str]:
    """Normalize a tshark FT_BYTES value to lowercase hex with no separators."""
    if not value:
        return None
    return value.replace(":", "").lower()


class _Row:
    """Accessor over one tshark output row (field key -> list of values)."""

    __slots__ = ("values",)

    def __init__(self, values: Dict[str, List[str]]):
        self.values = values

    def all(self, key: str) -> List[str]:
        return self.values.get(key, [])

    def first(self, key: str) -> Optional[str]:
        vals = self.values.get(key)
        return vals[0] if vals else None

    def at(self, key: str, index: int) -> Optional[str]:
        vals = self.values.get(key)
        return vals[index] if vals and len(vals) > index else None

    def int(self, key: str, index: int = 0) -> Optional[int]:
        return _to_int(self.at(key, index))

    def ints(self, key: str) -> List[int]:
        return [v for v in (_to_int(x) for x in self.all(key)) if v is not None]

    def has(self, key: str) -> bool:
        return bool(self.values.get(key))


def _record_from_tshark(row: _Row) -> Dict[str, Any]:
    """Build one normalized record from a tshark field row."""
    rec: Dict[str, Any] = {
        "n": row.int("frame.number") or 0,
        "t": float(row.first("frame.time_epoch") or 0.0),
        "len": row.int("frame.len") or 0,
    }
    protocols = row.first("frame.protocols") or ""
    ip_srcs = row.all("ip.src")
    if ip_srcs:
        rec["ip"] = {"v": 4, "src": ip_srcs[0], "dst": row.first("ip.dst"),
                     "proto": row.int("ip.proto"), "ttl": row.int("ip.ttl")}
    elif row.has("ipv6.src"):
        rec["ip"] = {"v": 6, "src": row.first("ipv6.src"), "dst": row.first("ipv6.dst"),
                     "proto": row.int("ipv6.nxt"), "ttl": row.int("ipv6.hlim")}
    elif row.has("eth.type"):
        rec["eth_type"] = row.int("eth.type")
    elif ":llc" in protocols:
        rec["llc"] = "cdp" if ":cdp" in protocols else ("stp" if ":stp" in protocols else "llc")

    # GRE carrying IPv4: the transport and routing fields belong to the inner
    # packet, so they go under rec["inner"] with the inner addresses.
    tunneled = False
    if row.has("gre.proto"):
        rec["gre"] = {"key": row.int("gre.key"), "ptype": row.int("gre.proto")}
        if rec["gre"]["ptype"] == 0x0800 and len(ip_srcs) > 1:
            tunneled = True
            rec["inner"] = {"src": ip_srcs[1], "dst": row.at("ip.dst", 1), "proto": row.int("ip.proto", 1)}
    target = rec["inner"] if tunneled else rec

    # A TCP/UDP header copied inside an ICMP error is not this frame's transport header.
    l4_proto = rec["inner"]["proto"] if tunneled else (rec["ip"]["proto"] if "ip" in rec else None)
    if row.has("tcp.srcport") and l4_proto == 6:
        target["tcp"] = {"sport": row.int("tcp.srcport"), "dport": row.int("tcp.dstport"),
                         "flags": row.int("tcp.flags") or 0, "len": row.int("tcp.len") or 0}
        if target["tcp"]["flags"] & 0x02 and row.has("tcp.mss"):
            target["tcp"]["mss"] = row.int("tcp.mss")
    if row.has("udp.srcport") and l4_proto == 17:
        length = row.int("udp.length")
        target["udp"] = {"sport": row.int("udp.srcport"), "dport": row.int("udp.dstport"),
                         "len": max((length or 8) - 8, 0)}

    ike_from_bytes = None
    if row.has("isakmp.exchtype") and row.has("udp.payload") and "udp" in target:
        raw = bytes.fromhex(_hex_bytes(row.first("udp.payload")) or "")
        ports = (target["udp"]["sport"], target["udp"]["dport"])
        if 4500 in ports and raw[:4] == b"\x00\x00\x00\x00":
            ike_from_bytes = parse_ike(raw[4:], natt=True)
        elif 500 in ports or 4500 in ports:
            ike_from_bytes = parse_ike(raw, natt=False)
    if ike_from_bytes:
        target["ike"] = ike_from_bytes
    elif row.has("isakmp.exchtype"):
        version_raw = row.int("isakmp.version") or 0
        version = 2 if (version_raw >> 4) == 2 else 1
        flags = row.int("isakmp.flags") or 0
        types = row.ints("isakmp.typepayload")
        target["ike"] = {
            "version": version,
            "ispi": _hex_bytes(row.first("isakmp.ispi")),
            "rspi": _hex_bytes(row.first("isakmp.rspi")),
            "exch": row.int("isakmp.exchtype"),
            "flags": flags,
            "msgid": row.int("isakmp.messageid") or 0,
            "length": row.int("isakmp.length") or 0,
            "notify": row.ints("isakmp.notify.msgtype"),
            "encrypted": (46 in types) if version == 2 else bool(flags & 0x01),
            "natt": row.has("udpencap.non_esp_marker"),
        }
        target["ike"].update(_ike_defaults())
    if row.has("esp.spi"):
        target["esp"] = {"spi": row.int("esp.spi"), "seq": row.int("esp.sequence"),
                         "udp": "udp" in target}
    if row.has("udpencap.nat_keepalive"):
        target["nat_keepalive"] = True

    if row.has("nhrp.op"):
        op = row.int("nhrp.op")
        nhrp = {
            "op": op,
            "src_nbma": row.first("nhrp.src_nbma"),
            "src_proto": row.first("nhrp.src_proto"),
            "dst_proto": row.first("nhrp.dst_proto"),
            "reqid": row.int("nhrp.reqid"),
            "code": row.int("nhrp.code") if op in (2, 4, 6) else None,
            "err_code": row.int("nhrp.err_code") if op == 7 else None,
            "client_nbma": row.first("nhrp.client_nbma") if op == 2 else None,
            "client_proto": row.first("nhrp.client_proto") if op == 2 else None,
            "prefix": row.int("nhrp.prefix") if op == 2 else None,
            "orig_src": None,
            "orig_dst": None,
        }
        if op == 8 and len(ip_srcs) > 1:
            nhrp["orig_src"] = ip_srcs[1]
            nhrp["orig_dst"] = row.at("ip.dst", 1)
        rec["nhrp"] = nhrp

    if row.has("bgp.type"):
        types = row.ints("bgp.type")
        lengths = row.ints("bgp.length")
        myas, holds, ids, as4s = row.ints("bgp.myas"), row.ints("bgp.hold"), row.all("bgp.id"), row.ints("bgp.as4")
        majors = row.ints("bgp.major")
        minors: List[int] = []
        for key in ("bgp.minor", "bgp.minor_open", "bgp.minor_update", "bgp.minor_expired",
                    "bgp.minor_state", "bgp.minor_cease", "bgp.minor_capability"):
            minors.extend(row.ints(key))
        messages = []
        open_index = notify_index = 0
        caps = row.ints("bgp.caps")
        for index, mtype in enumerate(types):
            msg = {"type": mtype, "len": lengths[index] if index < len(lengths) else None,
                   "myas": None, "hold": None, "bgp_id": None, "as4": None, "major": None, "minor": None,
                   "caps": None}
            if mtype == 1:
                msg["myas"] = myas[open_index] if open_index < len(myas) else None
                msg["hold"] = holds[open_index] if open_index < len(holds) else None
                msg["bgp_id"] = ids[open_index] if open_index < len(ids) else None
                msg["as4"] = as4s[open_index] if open_index < len(as4s) else None
                # tshark flattens capability codes per frame; one OPEN per frame is the norm.
                msg["caps"] = caps if open_index == 0 else []
                open_index += 1
            elif mtype == 3:
                msg["major"] = majors[notify_index] if notify_index < len(majors) else None
                msg["minor"] = minors[notify_index] if notify_index < len(minors) else None
                notify_index += 1
            messages.append(msg)
        target["bgp"] = messages
        target["bgp_nlri"] = len(row.all("bgp.nlri"))
        target["bgp_withdrawn"] = len(row.all("bgp.withdrawn"))

    if row.has("ospf.msg"):
        target["ospf"] = {
            "type": row.int("ospf.msg"),
            "rid": row.first("ospf.rid"),
            "area": row.first("ospf.area"),
            "auth": row.int("ospf.auth"),
            "mask": row.first("ospf.mask"),
            "hello": row.int("ospf.hello"),
            "dead": row.int("ospf.dead"),
            "prio": row.int("ospf.prio"),
            "dr": row.first("ospf.dr"),
            "bdr": row.first("ospf.bdr"),
            "neighbors": row.all("ospf.neighbors"),
            "options": row.int("ospf.options"),
            "mtu": row.int("ospf.mtu"),
            "dbd_flags": row.int("ospf.dbd"),
            "dd_seq": row.int("ospf.dd_seq"),
        }

    if row.has("eigrp.opcode"):
        k_values = [row.int(f"eigrp.k{i}") for i in range(1, 7)]
        target["eigrp"] = {
            "opcode": row.int("eigrp.opcode"),
            "as": row.int("eigrp.as"),
            "flags": row.int("eigrp.flags") or 0,
            "seq": row.int("eigrp.seq") or 0,
            "ack": row.int("eigrp.ack") or 0,
            "tlvs": row.ints("eigrp.tlv"),
            "k": k_values if all(k is not None for k in k_values) else None,
            "hold": row.int("eigrp.hold"),
        }

    carries_other = "gre" in rec and "inner" not in rec  # NHRP etc. may embed a copied IP header
    if carries_other:
        pass
    elif row.has("icmp.type") and "ip" in rec:
        _icmp_from_tshark(rec, row, ip_srcs, v6=False)
    elif row.has("icmpv6.type") and "ip" in rec:
        _icmp_from_tshark(rec, row, row.all("ipv6.src"), v6=True)

    if row.has("arp.opcode"):
        rec["arp"] = {"op": row.int("arp.opcode"), "spa": row.first("arp.spa"),
                      "tpa": row.first("arp.tpa"), "sha": row.first("arp.sha")}

    if ":sip" in protocols:
        rec["sip"] = True
    return rec


def _icmp_from_tshark(rec, row: _Row, srcs: List[str], v6: bool):
    """Fill rec['icmp'] from a tshark row, following GRE tunneling and ICMP error nesting."""
    prefix = "icmpv6" if v6 else "icmp"
    dst_key = "ipv6.dst" if v6 else "ip.dst"
    proto_key = "ipv6.nxt" if v6 else "ip.proto"
    icmp_type = row.int(f"{prefix}.type")
    errors = ICMPV6_ERROR_TYPES if v6 else ICMP_ERROR_TYPES
    tunneled = "inner" in rec and not v6
    layer = 1 if tunneled else 0
    if len(srcs) <= layer:
        return
    icmp = {"v6": v6, "type": icmp_type, "code": row.int(f"{prefix}.code"), "id": None, "seq": None,
            "src": srcs[layer], "dst": row.at(dst_key, layer), "tunneled": tunneled, "orig": None}
    if icmp_type in errors:
        if len(srcs) > layer + 1:
            proto = row.int(proto_key, layer + 1)
            dport = None
            if proto == 17:
                dport = row.int("udp.dstport")
            elif proto == 6:
                dport = row.int("tcp.dstport")
            icmp["orig"] = {"src": srcs[layer + 1], "dst": row.at(dst_key, layer + 1),
                            "proto": proto, "dport": dport}
    else:
        icmp["id"] = row.int(f"{prefix}.ident")
        icmp["seq"] = row.int(f"{prefix}.seq")
    rec["icmp"] = icmp


def iter_records_tshark(file_path: str, display_filter: Optional[str] = None,
                        max_packets: Optional[int] = None,
                        status: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
    """
    Stream normalized records from tshark (-T fields, one row per frame).

    Uses field output rather than -T json so the capture is processed as a stream:
    memory stays flat however many packets the capture holds.

    Args:
        file_path: pcap/pcapng path
        display_filter: optional Wireshark display filter (-Y)
        max_packets: optional cap on frames read (-c)
        status: optional dict that receives "missing_fields", "returncode" and "stderr"

    Raises:
        RuntimeError: when tshark exits with an error before producing any frame
    """
    resolved = _resolve_tshark_fields()
    keys = [key for key, _ in TSHARK_FIELDS if key in resolved]
    missing = [key for key, _ in TSHARK_FIELDS if key not in resolved]
    if status is not None:
        status["missing_fields"] = missing
    command = ["tshark", "-n", "-r", file_path, "-T", "fields",
               "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=n"]
    for key in keys:
        command += ["-e", resolved[key]]
    if display_filter:
        command += ["-Y", display_filter]
    if max_packets:
        command += ["-c", str(int(max_packets))]

    with tempfile.TemporaryFile(mode="w+") as err:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True, bufsize=1 << 16)
        produced = 0
        try:
            for line in proc.stdout:
                parts = line.rstrip("\n").split("\t")
                values = {}
                for index, key in enumerate(keys):
                    if index < len(parts) and parts[index]:
                        values[key] = parts[index].split("|")
                produced += 1
                yield _record_from_tshark(_Row(values))
        finally:
            if proc.poll() is None:
                proc.stdout.close()
                proc.terminate()
            proc.wait()
            err.seek(0)
            stderr_text = err.read()[-2000:]
            if status is not None:
                status["returncode"] = proc.returncode
                status["stderr"] = stderr_text.strip()
        if proc.returncode not in (0, None) and produced == 0:
            raise RuntimeError(f"tshark failed (exit {proc.returncode}): {stderr_text.strip()}")


# ---------------------------------------------------------------------------
# Byte-level parsers shared by the scapy backend
# ---------------------------------------------------------------------------

def _ip4(data: bytes) -> str:
    return ".".join(str(b) for b in data[:4])


def _ike_defaults() -> Dict[str, Any]:
    """The decoded IKE fields a header-only parse cannot fill."""
    return {"payloads": [], "proposals": [], "ke_group": None, "natd_src": [], "natd_dst": [],
            "invalid_ke_group": None, "invalid_spis": []}


def parse_ikev2_sa(body: bytes) -> List[Dict[str, Any]]:
    """
    Decode an IKEv2 SA payload body (RFC 7296 3.3) into its proposals.

    Each proposal: {"num", "protocol" (1 IKE, 2 AH, 3 ESP), "spi" (hex or None),
    "transforms": [{"type", "id", "key_length"}]}.
    """
    proposals = []
    pos = 0
    while pos + 8 <= len(body) and len(proposals) < 32:
        last, _, plen, num, proto, spi_size, count = struct.unpack("!BBHBBBB", body[pos:pos + 8])
        if plen < 8 or pos + plen > len(body):
            break
        spi = body[pos + 8:pos + 8 + spi_size].hex() if spi_size else None
        transforms = []
        tpos = pos + 8 + spi_size
        end = pos + plen
        while tpos + 8 <= end and len(transforms) < max(count, 1) * 2 and len(transforms) < 64:
            _, _, tlen, ttype, _, tid = struct.unpack("!BBHBBH", body[tpos:tpos + 8])
            if tlen < 8:
                break
            key_length = None
            apos = tpos + 8
            while apos + 4 <= tpos + tlen:
                atype, avalue = struct.unpack("!HH", body[apos:apos + 4])
                if atype & 0x8000:
                    if atype & 0x7FFF == 14:
                        key_length = avalue
                    apos += 4
                else:
                    apos += 4 + avalue
            transforms.append({"type": ttype, "id": tid, "key_length": key_length})
            tpos += tlen
        proposals.append({"num": num, "protocol": proto, "spi": spi, "transforms": transforms})
        pos += plen
        if last == 0:
            break
    return proposals


def parse_ike(data: bytes, natt: bool) -> Optional[Dict[str, Any]]:
    """
    Parse an IKEv1/IKEv2 header and its cleartext payload chain.

    For IKEv2 it also decodes what is readable before the SK payload: SA
    proposals and transforms, the KE payload's DH group, NAT detection hashes,
    the group an INVALID_KE_PAYLOAD asks for, and the SPI an INVALID_SPI names.
    """
    if len(data) < 28:
        return None
    ispi, rspi = data[0:8].hex(), data[8:16].hex()
    first, version_raw, exch, flags, msgid, length = struct.unpack("!BBBBII", data[16:28])
    version = 2 if (version_raw >> 4) == 2 else 1
    if (version_raw >> 4) not in (1, 2):
        return None
    out = {"version": version, "ispi": ispi, "rspi": rspi, "exch": exch, "flags": flags,
           "msgid": msgid, "length": length, "notify": [], "encrypted": False, "natt": natt}
    out.update(_ike_defaults())
    notifies: List[int] = out["notify"]
    encrypted = (version == 1 and bool(flags & 0x01))
    nxt, offset = first, 28
    end = min(len(data), length) if length else len(data)
    steps = 0
    while nxt and not encrypted and offset + 4 <= end and steps < 64:
        steps += 1
        if version == 2 and nxt in (46, 53):
            break
        next_payload, _, plen = struct.unpack("!BBH", data[offset:offset + 4])
        if plen < 4:
            break
        out["payloads"].append(nxt)
        body = data[offset + 4:offset + plen]
        if version == 2 and nxt == 41 and len(body) >= 4:
            spi_size, ntype = body[1], struct.unpack("!H", body[2:4])[0]
            notifies.append(ntype)
            ndata = body[4 + spi_size:]
            if ntype == 16388:
                out["natd_src"].append(ndata.hex())
            elif ntype == 16389:
                out["natd_dst"].append(ndata.hex())
            elif ntype == 17 and len(ndata) >= 2:
                out["invalid_ke_group"] = struct.unpack("!H", ndata[0:2])[0]
            elif ntype == 11:
                out["invalid_spis"].append((ndata[:4] or body[4:4 + spi_size]).hex())
        elif version == 2 and nxt == 33:
            out["proposals"] = parse_ikev2_sa(body)
        elif version == 2 and nxt == 34 and len(body) >= 2:
            out["ke_group"] = struct.unpack("!H", body[0:2])[0]
        elif version == 1 and nxt == 11 and len(body) >= 8:
            notifies.append(struct.unpack("!H", body[6:8])[0])
        nxt, offset = next_payload, offset + plen
    if version == 2 and nxt in (46, 53):
        encrypted = True
        out["payloads"].append(nxt)
    out["encrypted"] = encrypted
    return out


def parse_nhrp(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse an NHRP packet (RFC 2332, plus Cisco's type 8 Traffic Indication)."""
    if len(data) < 20:
        return None
    op = data[17]
    shtl, sstl = data[18] & 0x3F, data[19] & 0x3F
    out = {"op": op, "src_nbma": None, "src_proto": None, "dst_proto": None, "reqid": None,
           "code": None, "err_code": None, "client_nbma": None, "client_proto": None,
           "prefix": None, "orig_src": None, "orig_dst": None}
    m = data[20:]
    if len(m) < 8:
        return out
    spl, dpl = m[0], m[1]
    if op == 7:
        out["err_code"] = struct.unpack("!H", m[4:6])[0]
        # The errored packet follows the addresses; its request ID ties the error to a request.
        nested = parse_nhrp(m[8 + shtl + sstl + spl + dpl:])
        if nested:
            out["reqid"] = nested["reqid"]
    elif op != 8:
        out["reqid"] = struct.unpack("!I", m[4:8])[0]
    pos = 8
    if shtl == 4:
        out["src_nbma"] = _ip4(m[pos:pos + 4])
    pos += shtl + sstl
    if spl == 4:
        out["src_proto"] = _ip4(m[pos:pos + 4])
    pos += spl
    if dpl == 4:
        out["dst_proto"] = _ip4(m[pos:pos + 4])
    pos += dpl
    if op in (1, 2, 3, 4, 5, 6) and len(m) >= pos + 12:
        cie = m[pos:]
        code, prefix = cie[0], cie[1]
        cli_tl, cli_stl, cli_pl = cie[8] & 0x3F, cie[9] & 0x3F, cie[10]
        if op in (2, 4, 6):
            out["code"] = code
        if op == 2:
            out["prefix"] = prefix
            cpos = 12
            if cli_tl == 4:
                out["client_nbma"] = _ip4(cie[cpos:cpos + 4])
            cpos += cli_tl + cli_stl
            if cli_pl == 4:
                out["client_proto"] = _ip4(cie[cpos:cpos + 4])
    elif op == 8 and len(m) >= pos + 20 and (m[pos] >> 4) == 4:
        out["orig_src"] = _ip4(m[pos + 12:pos + 16])
        out["orig_dst"] = _ip4(m[pos + 16:pos + 20])
    return out


def parse_bgp_messages(data: bytes) -> (List[Dict[str, Any]], int, int, int):
    """
    Parse every complete BGP message at the start of data.

    Returns (messages, bytes consumed, IPv4 NLRI count, IPv4 withdrawn count).
    """
    messages = []
    nlri = withdrawn = 0
    pos = 0
    while len(data) - pos >= 19:
        if data[pos:pos + 16] != b"\xff" * 16:
            break
        length, mtype = struct.unpack("!HB", data[pos + 16:pos + 19])
        if length < 19 or length > 4096 or len(data) - pos < length:
            break
        body = data[pos + 19:pos + length]
        msg = {"type": mtype, "len": length, "myas": None, "hold": None, "bgp_id": None,
               "as4": None, "major": None, "minor": None, "caps": None}
        if mtype == 1 and len(body) >= 10:
            _, myas, hold = struct.unpack("!BHH", body[0:5])
            msg.update(myas=myas, hold=hold, bgp_id=_ip4(body[5:9]))
            msg["as4"] = _bgp_as4(body[10:10 + body[9]])
            msg["caps"] = _bgp_caps(body[10:10 + body[9]])
        elif mtype == 3 and len(body) >= 2:
            msg.update(major=body[0], minor=body[1])
        elif mtype == 2 and len(body) >= 4:
            wlen = struct.unpack("!H", body[0:2])[0]
            withdrawn += _count_prefixes(body[2:2 + wlen])
            alen = struct.unpack("!H", body[2 + wlen:4 + wlen])[0] if len(body) >= 4 + wlen else 0
            nlri += _count_prefixes(body[4 + wlen + alen:])
        messages.append(msg)
        pos += length
    return messages, pos, nlri, withdrawn


def _bgp_as4(params: bytes) -> Optional[int]:
    pos = 0
    while pos + 2 <= len(params):
        ptype, plen = params[pos], params[pos + 1]
        value = params[pos + 2:pos + 2 + plen]
        if ptype == 2:
            cpos = 0
            while cpos + 2 <= len(value):
                code, clen = value[cpos], value[cpos + 1]
                if code == 65 and clen == 4:
                    return struct.unpack("!I", value[cpos + 2:cpos + 6])[0]
                cpos += 2 + clen
        pos += 2 + plen
    return None


def _bgp_caps(params: bytes) -> List[int]:
    """Capability codes from an OPEN's optional parameters, in wire order."""
    codes: List[int] = []
    pos = 0
    while pos + 2 <= len(params):
        ptype, plen = params[pos], params[pos + 1]
        value = params[pos + 2:pos + 2 + plen]
        if ptype == 2:
            cpos = 0
            while cpos + 2 <= len(value):
                codes.append(value[cpos])
                cpos += 2 + value[cpos + 1]
        pos += 2 + plen
    return codes


def _count_prefixes(data: bytes) -> int:
    count = pos = 0
    while pos < len(data):
        plen = data[pos]
        if plen > 32:
            break
        pos += 1 + (plen + 7) // 8
        count += 1
    return count


def parse_ospf(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse an OSPFv2 header plus the Hello or DB Description body."""
    if len(data) < 24 or data[0] != 2:
        return None
    ptype = data[1]
    out = {"type": ptype, "rid": _ip4(data[4:8]), "area": _ip4(data[8:12]),
           "auth": struct.unpack("!H", data[14:16])[0], "mask": None, "hello": None,
           "dead": None, "prio": None, "dr": None, "bdr": None, "neighbors": [],
           "options": None, "mtu": None, "dbd_flags": None, "dd_seq": None}
    body = data[24:struct.unpack("!H", data[2:4])[0]]
    if ptype == 1 and len(body) >= 20:
        out["mask"] = _ip4(body[0:4])
        out["hello"], out["options"], out["prio"], out["dead"] = struct.unpack("!HBBI", body[4:12])
        out["dr"], out["bdr"] = _ip4(body[12:16]), _ip4(body[16:20])
        out["neighbors"] = [_ip4(body[i:i + 4]) for i in range(20, len(body) - 3, 4)]
    elif ptype == 2 and len(body) >= 8:
        out["mtu"], out["options"], out["dbd_flags"], out["dd_seq"] = struct.unpack("!HBBI", body[0:8])
    return out


def parse_eigrp(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse an EIGRP header and its TLV list (parameter TLV decoded)."""
    if len(data) < 20:
        return None
    _, opcode, _, flags, seq, ack, _, asn = struct.unpack("!BBHIIIHH", data[:20])
    out = {"opcode": opcode, "as": asn, "flags": flags, "seq": seq, "ack": ack,
           "tlvs": [], "k": None, "hold": None}
    pos = 20
    while pos + 4 <= len(data):
        ttype, tlen = struct.unpack("!HH", data[pos:pos + 4])
        if tlen < 4:
            break
        out["tlvs"].append(ttype)
        if ttype == 0x0001 and tlen >= 12:
            out["k"] = list(data[pos + 4:pos + 10])
            out["hold"] = struct.unpack("!H", data[pos + 10:pos + 12])[0]
        pos += tlen
    return out


def parse_icmp(data: bytes, src: str, dst: str, v6: bool, tunneled: bool) -> Optional[Dict[str, Any]]:
    """Parse an ICMP/ICMPv6 message; for errors, the embedded original header."""
    if len(data) < 8:
        return None
    icmp_type, code = data[0], data[1]
    out = {"v6": v6, "type": icmp_type, "code": code, "id": None, "seq": None,
           "src": src, "dst": dst, "tunneled": tunneled, "orig": None}
    errors = ICMPV6_ERROR_TYPES if v6 else ICMP_ERROR_TYPES
    if icmp_type in errors:
        inner = data[8:]
        if not v6 and len(inner) >= 20 and (inner[0] >> 4) == 4:
            ihl = (inner[0] & 0x0F) * 4
            proto = inner[9]
            dport = None
            if proto in (6, 17) and len(inner) >= ihl + 4:
                dport = struct.unpack("!H", inner[ihl + 2:ihl + 4])[0]
            out["orig"] = {"src": _ip4(inner[12:16]), "dst": _ip4(inner[16:20]), "proto": proto, "dport": dport}
        elif v6 and len(inner) >= 40 and (inner[0] >> 4) == 6:
            proto = inner[6]
            dport = None
            if proto in (6, 17) and len(inner) >= 44:
                dport = struct.unpack("!H", inner[42:44])[0]
            out["orig"] = {"src": str(ipaddress.IPv6Address(inner[8:24])),
                           "dst": str(ipaddress.IPv6Address(inner[24:40])), "proto": proto, "dport": dport}
    else:
        out["id"], out["seq"] = struct.unpack("!HH", data[4:8])
    return out


_SIP_STARTS = (b"INVITE ", b"ACK ", b"BYE ", b"CANCEL ", b"REGISTER ", b"OPTIONS ", b"NOTIFY ",
               b"SUBSCRIBE ", b"PRACK ", b"UPDATE ", b"REFER ", b"INFO ", b"MESSAGE ", b"SIP/2.0 ")


class _BgpReassembler:
    """Minimal in-order TCP reassembly for BGP on port 179 (scapy backend only)."""

    def __init__(self):
        self.flows: Dict[tuple, list] = {}

    def feed(self, key: tuple, seq: int, payload: bytes, flags: int):
        state = self.flows.get(key)
        if flags & 0x02:  # SYN starts a fresh stream
            self.flows[key] = [seq + 1, b""]
            return [], 0, 0
        if not payload:
            return [], 0, 0
        if state is None or seq != state[0]:
            if state is not None and seq < state[0]:
                return [], 0, 0  # retransmission of data already seen
            state = [seq, b""]  # gap or mid-stream start: resynchronise here
        buf = state[1] + payload
        state[0] = seq + len(payload)
        messages, used, nlri, withdrawn = parse_bgp_messages(buf)
        rest = buf[used:]
        if rest and rest[:16] != b"\xff" * min(16, len(rest)):
            rest = b""  # not the start of another BGP message: drop it and resynchronise
        state[1] = rest[-65536:]
        self.flows[key] = state
        return messages, nlri, withdrawn


def iter_records_scapy(file_path: str, max_packets: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """
    Stream normalized records using scapy (fallback when tshark is unavailable).

    scapy decodes the link layer and the IP/IPv6/ARP headers; everything above is
    parsed from bytes by the parsers in this module, so the result matches the
    tshark backend field for field.
    """
    try:
        from scapy.all import PcapReader, IP, IPv6, ARP, LLC, SNAP
    except ImportError:
        print("Scapy is not installed. Please run 'pip install scapy'.", file=sys.stderr)
        raise

    bgp = _BgpReassembler()
    number = 0
    with PcapReader(file_path) as reader:
        for pkt in reader:
            number += 1
            if max_packets and number > max_packets:
                break
            rec: Dict[str, Any] = {"n": number, "t": float(pkt.time), "len": len(pkt)}
            if ARP in pkt:
                arp = pkt[ARP]
                rec["eth_type"] = 0x0806
                rec["arp"] = {"op": int(arp.op), "spa": arp.psrc, "tpa": arp.pdst, "sha": arp.hwsrc}
                yield rec
                continue
            payload = None
            if IP in pkt:
                ip = pkt[IP]
                raw = bytes(ip)
                ihl = ip.ihl * 4 if ip.ihl else 20
                total = ip.len if ip.len else len(raw)
                payload = raw[ihl:total]
                rec["ip"] = {"v": 4, "src": ip.src, "dst": ip.dst, "proto": int(ip.proto), "ttl": int(ip.ttl)}
                if ip.frag:
                    yield rec
                    continue
            elif IPv6 in pkt:
                ip6 = pkt[IPv6]
                raw = bytes(ip6)
                payload = raw[40:40 + ip6.plen] if ip6.plen else raw[40:]
                rec["ip"] = {"v": 6, "src": ip6.src, "dst": ip6.dst, "proto": int(ip6.nh), "ttl": int(ip6.hlim)}
            else:
                eth_type = None if LLC in pkt else getattr(pkt, "type", None)
                if isinstance(eth_type, int):
                    rec["eth_type"] = eth_type
                elif LLC in pkt:
                    # 802.3 + LLC: CDP rides SNAP with Cisco's PID 0x2000, STP uses DSAP 0x42.
                    if SNAP in pkt and int(pkt[SNAP].code) == 0x2000:
                        rec["llc"] = "cdp"
                    elif int(pkt[LLC].dsap) == 0x42:
                        rec["llc"] = "stp"
                    else:
                        rec["llc"] = "llc"
                yield rec
                continue
            _fill_l4(rec, rec["ip"], payload, bgp)
            yield rec


def _tcp_mss(options: bytes) -> Optional[int]:
    """The MSS value from a TCP options block, or None when absent."""
    pos = 0
    while pos < len(options):
        kind = options[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 1 >= len(options) or options[pos + 1] < 2:
            break
        olen = options[pos + 1]
        if kind == 2 and olen == 4 and pos + 4 <= len(options):
            return struct.unpack("!H", options[pos + 2:pos + 4])[0]
        pos += olen
    return None


def _fill_l4(rec: Dict[str, Any], ip: Dict[str, Any], payload: bytes, bgp: _BgpReassembler):
    """Decode everything above IP for the scapy backend."""
    proto, v6 = ip["proto"], ip["v"] == 6
    if proto == 6 and len(payload) >= 20:
        sport, dport, seq = struct.unpack("!HHI", payload[0:8])
        offset = (payload[12] >> 4) * 4
        flags = payload[13] | ((payload[12] & 0x01) << 8)
        data = payload[offset:]
        rec["tcp"] = {"sport": sport, "dport": dport, "flags": flags, "len": len(data)}
        if flags & 0x02:
            mss = _tcp_mss(payload[20:offset])
            if mss is not None:
                rec["tcp"]["mss"] = mss
        if 179 in (sport, dport):
            key = (ip["src"], sport, ip["dst"], dport)
            messages, nlri, withdrawn = bgp.feed(key, seq, data, flags)
            if messages:
                rec["bgp"] = messages
                rec["bgp_nlri"] = nlri
                rec["bgp_withdrawn"] = withdrawn
        if (sport in (5060, 5061) or dport in (5060, 5061)) and data.startswith(_SIP_STARTS):
            rec["sip"] = True
    elif proto == 17 and len(payload) >= 8:
        sport, dport, length = struct.unpack("!HHH", payload[0:6])
        data = payload[8:length] if length >= 8 else payload[8:]
        rec["udp"] = {"sport": sport, "dport": dport, "len": len(data)}
        if 4500 in (sport, dport):
            if data == b"\xff":
                rec["nat_keepalive"] = True
            elif data[:4] == b"\x00\x00\x00\x00":
                ike = parse_ike(data[4:], natt=True)
                if ike:
                    rec["ike"] = ike
            elif len(data) >= 8:
                spi, seq = struct.unpack("!II", data[0:8])
                rec["esp"] = {"spi": spi, "seq": seq, "udp": True}
        elif 500 in (sport, dport):
            ike = parse_ike(data, natt=False)
            if ike:
                rec["ike"] = ike
        if data.startswith(_SIP_STARTS):
            rec["sip"] = True
    elif proto == 50 and len(payload) >= 8:
        spi, seq = struct.unpack("!II", payload[0:8])
        rec["esp"] = {"spi": spi, "seq": seq, "udp": False}
    elif proto == 47 and len(payload) >= 4:
        flags_ver, ptype = struct.unpack("!HH", payload[0:4])
        pos = 4
        if flags_ver & 0x8000:
            pos += 4  # checksum + reserved
        key = None
        if flags_ver & 0x2000 and len(payload) >= pos + 4:
            key = struct.unpack("!I", payload[pos:pos + 4])[0]
            pos += 4
        if flags_ver & 0x1000:
            pos += 4  # sequence number
        rec["gre"] = {"key": key, "ptype": ptype}
        inner = payload[pos:]
        if ptype == 0x2001:
            nhrp = parse_nhrp(inner)
            if nhrp:
                rec["nhrp"] = nhrp
        elif ptype == 0x0800 and len(inner) >= 20 and (inner[0] >> 4) == 4:
            ihl = (inner[0] & 0x0F) * 4
            total = struct.unpack("!H", inner[2:4])[0] or len(inner)
            src, dst, iproto = _ip4(inner[12:16]), _ip4(inner[16:20]), inner[9]
            inner_rec: Dict[str, Any] = {"src": src, "dst": dst, "proto": iproto}
            rec["inner"] = inner_rec
            frag = struct.unpack("!H", inner[6:8])[0] & 0x1FFF
            if not frag:
                _fill_l4(inner_rec, {"v": 4, "src": src, "dst": dst, "proto": iproto}, inner[ihl:total], bgp)
            # ICMP and the SIP flag sit at the top level, as tshark reports them.
            if "icmp" in inner_rec:
                rec["icmp"] = inner_rec.pop("icmp")
                rec["icmp"]["tunneled"] = True
            if inner_rec.pop("sip", None):
                rec["sip"] = True
    elif proto == 89:
        ospf = parse_ospf(payload)
        if ospf:
            rec["ospf"] = ospf
    elif proto == 88:
        eigrp = parse_eigrp(payload)
        if eigrp:
            rec["eigrp"] = eigrp
    elif (proto == 1 and not v6) or (proto == 58 and v6):
        icmp = parse_icmp(payload, ip["src"], ip["dst"], v6=v6, tunneled=False)
        if icmp:
            rec["icmp"] = icmp


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

class NetworkExtraction:
    """
    A started extraction: which backend runs, and the record stream it yields.

    Attributes:
        backend: "tshark" or "scapy"
        records: iterator of normalized packet records
        info: dict describing the extraction (backend, filters, missing fields, warnings);
              complete only after records has been consumed
    """

    def __init__(self, backend: str, records: Iterator[Dict[str, Any]], info: Dict[str, Any]):
        self.backend = backend
        self.records = records
        self.info = info


def open_network_records(file_path: str, display_filter: Optional[str] = None,
                         max_packets: Optional[int] = None, backend: str = "auto") -> NetworkExtraction:
    """
    Start extracting network records, trying tshark first and falling back to scapy.

    Args:
        file_path: Path to the pcap/pcapng file
        display_filter: Wireshark display filter applied before detection (tshark only;
                        refused rather than ignored when only scapy is available)
        max_packets: read at most this many frames
        backend: "auto" (tshark, else scapy), "tshark" or "scapy"

    Returns:
        NetworkExtraction

    Raises:
        FileNotFoundError: the file does not exist
        RuntimeError: the requested backend is unavailable, or a display filter was
                      given and tshark cannot run
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    info: Dict[str, Any] = {"display_filter": display_filter, "max_packets": max_packets, "warnings": []}
    use_tshark = backend in ("auto", "tshark") and shutil.which("tshark") is not None
    if backend == "tshark" and not use_tshark:
        raise RuntimeError("tshark backend requested but tshark is not installed")
    if use_tshark:
        status: Dict[str, Any] = {}
        stream = iter_records_tshark(file_path, display_filter, max_packets, status)
        try:
            first = next(stream)
        except StopIteration:
            first = None
        except RuntimeError as exc:
            if display_filter or backend == "tshark":
                raise
            info["warnings"].append(f"{exc}; fell back to scapy")
            first = None
            stream = None
        if stream is not None:
            info["backend"] = "tshark"
            info["missing_fields"] = status.get("missing_fields", [])

            def chained():
                if first is not None:
                    yield first
                yield from stream

            return NetworkExtraction("tshark", chained(), info)
    if display_filter:
        raise RuntimeError("display_filter needs tshark, which is not available; "
                           "remove the filter to analyze the whole capture with scapy")
    info["backend"] = "scapy"
    info["missing_fields"] = []
    return NetworkExtraction("scapy", iter_records_scapy(file_path, max_packets), info)
