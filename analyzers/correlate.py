#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Multi-Capture Correlation

correlate_captures() reads two or more captures of the same traffic taken at
different points (inside and outside of a NAT router, WAN1 and WAN2, before and
after a firewall) and follows each packet across them. Deterministic, no LLM.

How a packet is recognised in another capture (fields NAT leaves alone):
    ESP            SPI and sequence number
    IKE            initiator and responder SPI, message ID, flags, length
    TCP            raw sequence and acknowledgement numbers, flags, payload length, payload hash
    UDP            payload length and payload hash (IP identification when there is no payload)
    ICMP echo      type, sequence number, IP total length and identification (the identifier
                   changes under PAT and is treated as the port)
    other IP       protocol, identification and total length
GRE carrying IPv4 is matched on the inner packet, so a cleartext inside capture
matches the tunnel on the WAN.

The captures are merged by timestamp (after any clock offset) and streamed: a
packet is held for matching for window_s seconds, and at most max_packets_held
packets are held at once (the oldest leave early when the cap is reached, and
the report counts them). Memory therefore depends on the window, not on the
capture size.

What it reports:
    transit         per capture pair: packets matched, the time between sightings
                    (one-way delay plus any clock offset), the TTL decrement (routed hops)
    nat             per capture pair, each address/port translation (inside local to
                    outside global and back), with packet counts and frames
    connections     each end-to-end conversation, linked across captures through NAT:
                    where each direction was seen, and a verdict:
                      ok            both directions crossed every capture point they reached
                      asymmetric    out through one capture point, back through another
                      reply_lost    the reply was seen at fewer points than the request:
                                    it was last seen at X and never reached Y
                      partial_loss  some packets of a direction vanished between two points
                      seen_only_at  a direction seen at one capture point only although other
                                    traffic between the same two addresses crossed another
                                    point (a probe stopped by the device after it: an ACL,
                                    a route or a drop)
                      not_on_other_paths  seen at one point, and no other point ever saw these
                                    two addresses talk: the flow does not cross them
    dscp_changes    the DSCP of the same packet differing between two capture points

Author: Raymond A Rizzo | Zombat
"""

import heapq
import ipaddress
import os
from collections import Counter, OrderedDict, deque
from typing import Any, Dict, Iterator, List, Optional, Tuple

from analyzers.dataplane_common import dscp_name, endpoint, transport
from analyzers.network_common import iso_time, median
from extractors.network import open_network_records

SCHEMA = "sonic.correlation_report/1"
DEFAULT_WINDOW_S = 2.0
DEFAULT_MAX_HELD = 200000
MAX_NODES = 200000
MAX_DELTA_SAMPLES = 20000

LIMITS = [
    "Only packets that reached at least one capture point are known; a packet dropped before the first "
    "capture point is invisible.",
    "Matching relies on fields NAT normally keeps (TCP sequence numbers, ESP SPI/sequence, payload hashes, IP "
    "identification). A device that randomizes TCP sequence numbers or rewrites payloads (an ALG) breaks "
    "matching for those flows.",
    "Times between capture points include the difference between the capturing clocks; captures written by "
    "one host (for example the CML controller) share a clock.",
    "A packet is held for matching for window_s seconds and at most max_packets_held packets are held; a "
    "packet that reaches the next capture point later than that, or after an early eviction, counts as "
    "unmatched.",
    "seen_only_at is an observation, not a verdict on intent: a flow that never needed to cross the other "
    "capture points looks the same as one that was dropped.",
]


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


def _multicast(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_multicast or addr == "255.255.255.255" or (ip.version == 4 and addr.endswith(".255"))


def packet_identity(rec: Dict[str, Any]) -> Optional[Tuple[tuple, tuple]]:
    """
    (match key, directional tuple) for one record, or None when it cannot be matched.

    The directional tuple is (protocol, src, sport, dst, dport) of the packet as seen
    at this capture point (the inner packet for GRE).
    """
    view = transport(rec)
    if view is None:
        return None
    dp = rec["dp"]
    esp = rec.get("esp")
    ike = rec.get("ike")
    icmp = rec.get("icmp")
    tcp, udp = view["tcp"], view["udp"]
    if tcp:
        tup = (6, view["src"], tcp["sport"], view["dst"], tcp["dport"])
    elif udp:
        tup = (17, view["src"], udp["sport"], view["dst"], udp["dport"])
    elif icmp and icmp.get("id") is not None:
        tup = (view["proto"], view["src"], icmp["id"], view["dst"], icmp["id"])
    else:
        tup = (view["proto"], view["src"], None, view["dst"], None)
    if esp is not None:
        return ("esp", esp["spi"], esp["seq"]), tup
    if ike is not None:
        return ("ike", ike["ispi"], ike["rspi"], ike["msgid"], ike["flags"], ike["length"]), tup
    if tcp and view["dtcp"]:
        d = view["dtcp"]
        return ("tcp", d["seq"], d["ack"], tcp["flags"] & 0x17, tcp["len"], dp.get("ph")), tup
    if udp:
        if dp.get("ph"):
            return ("udp", udp["len"], dp["ph"]), tup
        return ("udp", udp["len"], view["id"]), tup
    if icmp and icmp.get("seq") is not None:
        return ("icmp", icmp["type"], icmp["seq"], view["tl"], view["id"]), tup
    if view["id"] is None:
        return None
    return ("ip", view["proto"], view["id"], view["tl"]), tup


def _reverse(tup: tuple) -> tuple:
    proto, src, sport, dst, dport = tup
    return (proto, dst, dport, src, sport)


def _tuple_text(tup: tuple) -> str:
    proto, src, sport, dst, dport = tup
    name = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 50: "esp", 47: "gre"}.get(proto, f"ip-proto-{proto}")
    if proto in (1, 58) and sport is not None:
        return f"{name} {src} -> {dst} id {sport}"
    return f"{name} {endpoint(src, sport)} -> {endpoint(dst, dport)}"


class _UnionFind:
    def __init__(self):
        self.parent: List[int] = []

    def add(self) -> int:
        self.parent.append(len(self.parent))
        return len(self.parent) - 1

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


class Correlator:
    """Streaming cross-capture matcher; feed sightings in timestamp order."""

    def __init__(self, labels: List[str], window_s: float, max_held: int,
                 infos: Optional[List[Dict[str, Any]]] = None):
        self.labels = labels
        self.infos = infos if infos is not None else [{} for _ in labels]
        self.addr_pairs = [set() for _ in labels]
        self.window = window_s
        self.max_held = max_held
        self.open: Dict[tuple, List[Dict[str, Any]]] = {}
        self.queue: deque = deque()
        self.held = 0
        self.evicted_early = 0
        self.nodes: Dict[tuple, int] = {}
        self.node_info: List[Dict[str, Any]] = []
        self.nodes_dropped = 0
        self.uf = _UnionFind()
        self.pairs: Dict[tuple, Dict[str, Any]] = {}
        self.nat: Dict[tuple, Dict[str, Any]] = {}
        self.dscp: Dict[tuple, Dict[str, Any]] = {}
        self.patterns: Dict[int, Dict[tuple, Dict[str, Any]]] = {}
        self.unmatched = Counter()
        self.packets = Counter()
        self.groups_matched = 0

    def _node(self, cap: int, tup: tuple, t: float, n: int) -> Optional[int]:
        key = (cap, tup)
        node = self.nodes.get(key)
        if node is None:
            if len(self.nodes) >= MAX_NODES:
                self.nodes_dropped += 1
                return None
            node = self.uf.add()
            self.nodes[key] = node
            self.node_info.append({"cap": cap, "tuple": tup, "packets": 0, "first_t": t, "first_n": n,
                                   "last_t": t, "last_n": n})
        info = self.node_info[node]
        info["packets"] += 1
        info["last_t"], info["last_n"] = t, n
        return node

    def feed(self, cap: int, t: float, rec: Dict[str, Any]):
        self.packets[cap] += 1
        self._expire(t)
        ident = packet_identity(rec)
        if ident is None:
            return
        key, tup = ident
        if len(self.addr_pairs[cap]) < MAX_NODES:
            self.addr_pairs[cap].add((tup[1], tup[3]))
        sighting = {"cap": cap, "t": t, "n": rec["n"], "tuple": tup, "dscp": (transport(rec) or {}).get("dscp"),
                    "ttl": rec["ip"].get("ttl"), "flags": (rec.get("tcp") or (rec.get("inner") or {}).get("tcp") or {}).get("flags")}
        for group in self.open.get(key, []):
            if cap not in group["s"] and t - group["t0"] <= self.window:
                group["s"][cap] = sighting
                self.held += 1
                break
        else:
            group = {"key": key, "t0": t, "s": {cap: sighting}, "done": False}
            self.open.setdefault(key, []).append(group)
            self.queue.append(group)
            self.held += 1
        while self.held > self.max_held and self.queue:
            self.evicted_early += 1
            self._finish(self.queue.popleft())

    def _expire(self, now: float):
        while self.queue and now - self.queue[0]["t0"] > self.window:
            self._finish(self.queue.popleft())

    def flush(self):
        while self.queue:
            self._finish(self.queue.popleft())

    def active(self, t: float) -> frozenset:
        """Captures that were recording at time t (started, and not yet ended)."""
        out = []
        for cap, info in enumerate(self.infos):
            start, end = info.get("start"), info.get("end")
            if start is None or start > t + self.window:
                continue
            if info.get("done") and end is not None and end < t - self.window:
                continue
            out.append(cap)
        return frozenset(out)

    def _finish(self, group):
        if group["done"]:
            return
        group["done"] = True
        siblings = self.open.get(group["key"])
        if siblings is not None:
            siblings.remove(group)
            if not siblings:
                del self.open[group["key"]]
        sightings = sorted(group["s"].values(), key=lambda s: s["t"])
        self.held -= len(sightings)
        nodes = []
        for s in sightings:
            node = self._node(s["cap"], s["tuple"], s["t"], s["n"])
            nodes.append(node)
        if len(sightings) == 1:
            self.unmatched[sightings[0]["cap"]] += 1
        else:
            self.groups_matched += 1
        for node in nodes[1:]:
            if node is not None and nodes[0] is not None:
                self.uf.union(nodes[0], node)
        for i, a in enumerate(sightings):
            for b in sightings[i + 1:]:
                self._pair(a, b)
        if nodes[0] is not None:
            order = (tuple(s["cap"] for s in sightings), self.active(group["t0"]))
            bucket = self.patterns.setdefault(nodes[0], {})
            entry = bucket.get(order)
            if entry is None:
                entry = {"count": 0, "frames": {self.labels[s["cap"]]: s["n"] for s in sightings},
                         "first_t": sightings[0]["t"], "syn": False, "synack": False}
                bucket[order] = entry
            entry["count"] += 1
            flags = sightings[0]["flags"] or 0
            if flags & 0x02:
                entry["synack" if flags & 0x10 else "syn"] = True

    def _pair(self, a, b):
        key = (a["cap"], b["cap"]) if a["cap"] < b["cap"] else (b["cap"], a["cap"])
        first, second = (a, b) if a["cap"] == key[0] else (b, a)
        stats = self.pairs.setdefault(key, {"matched": 0, "deltas": [], "ttl": Counter()})
        stats["matched"] += 1
        if len(stats["deltas"]) < MAX_DELTA_SAMPLES:
            stats["deltas"].append(second["t"] - first["t"])
        if a["ttl"] is not None and b["ttl"] is not None:
            stats["ttl"][a["ttl"] - b["ttl"]] += 1  # a is earlier in time: hops from a to b
        if a["tuple"] != b["tuple"]:
            nat = self.nat.setdefault((a["cap"], b["cap"], a["tuple"], b["tuple"]),
                                      {"packets": 0, "frames": {}})
            nat["packets"] += 1
            nat["frames"].setdefault(self.labels[a["cap"]], a["n"])
            nat["frames"].setdefault(self.labels[b["cap"]], b["n"])
        if a["dscp"] is not None and b["dscp"] is not None and a["dscp"] != b["dscp"]:
            change = self.dscp.setdefault((a["cap"], b["cap"], a["dscp"], b["dscp"], a["tuple"]),
                                          {"packets": 0, "frames": {}})
            change["packets"] += 1
            change["frames"].setdefault(self.labels[a["cap"]], a["n"])
            change["frames"].setdefault(self.labels[b["cap"]], b["n"])


def _stream(index: int, path: str, offset: float, backend: str, max_packets: Optional[int],
            info: Dict[str, Any]) -> Iterator[tuple]:
    extraction = open_network_records(path, max_packets=max_packets, backend=backend)
    info["backend"] = extraction.backend
    first = last = None
    for rec in extraction.records:
        t = rec["t"] + offset
        first = t if first is None else min(first, t)
        last = t if last is None else max(last, t)
        info["start"], info["end"] = first, last
        yield (t, index, rec["n"], rec)
    info["done"] = True
    info["warnings"] = extraction.info.get("warnings", [])


def correlate_captures(captures: List[Dict[str, Any]], window_s: float = DEFAULT_WINDOW_S,
                       max_packets_held: int = DEFAULT_MAX_HELD, clock_offsets_s: Optional[Dict[str, float]] = None,
                       max_packets: Optional[int] = None, max_items: int = 25,
                       backend: str = "auto") -> Dict[str, Any]:
    """
    Follow packets across two or more captures; see the module docstring for the report.

    Args:
        captures: [{"path": "/abs/inside.pcap", "label": "inside"}, ...], two or more, labels unique.
                  List them in path order when they lie on one path (the report then names the
                  segment where a packet stopped).
        window_s: how long a packet waits for its copy in another capture (default 2 s)
        max_packets_held: cap on packets held for matching at once (default 200000)
        clock_offsets_s: {label: seconds added to that capture's timestamps}
        max_packets: read at most this many frames from each capture
        max_items: cap on list lengths
        backend: "auto", "tshark" or "scapy"
    """
    if not isinstance(captures, list) or len(captures) < 2:
        return _error("captures needs two or more entries, each {\"path\": ..., \"label\": ...}")
    labels, paths = [], []
    for entry in captures:
        if not isinstance(entry, dict) or not entry.get("path"):
            return _error("each capture needs a \"path\" (and a \"label\")")
        label = str(entry.get("label") or os.path.basename(entry["path"]))
        if label in labels:
            return _error(f"duplicate capture label {label!r}")
        if not os.path.exists(entry["path"]):
            return _error(f"File not found: {entry['path']}")
        labels.append(label)
        paths.append(entry["path"])
    offsets = dict(clock_offsets_s or {})
    unknown = [k for k in offsets if k not in labels]
    if unknown:
        return _error(f"clock_offsets_s names unknown label(s): {unknown}", labels=labels)
    window_s = float(window_s if window_s is not None else DEFAULT_WINDOW_S)
    if window_s <= 0 or window_s > 60:
        return _error("window_s must be between 0 and 60 seconds")
    max_packets_held = int(max_packets_held or DEFAULT_MAX_HELD)
    if max_packets_held < 100:
        return _error("max_packets_held must be at least 100")
    max_items = max(1, int(max_items or 25))

    infos = [{"label": label, "path": path, "clock_offset_s": float(offsets.get(label, 0.0))}
             for label, path in zip(labels, paths)]
    try:
        streams = [_stream(i, path, infos[i]["clock_offset_s"], backend, max_packets, infos[i])
                   for i, path in enumerate(paths)]
        corr = Correlator(labels, window_s, max_packets_held, infos)
        for t, index, _n, rec in heapq.merge(*streams, key=lambda item: (item[0], item[1], item[2])):
            if rec.get("ip"):
                corr.feed(index, t, rec)
            else:
                corr.packets[index] += 1
        corr.flush()
    except (FileNotFoundError, RuntimeError) as exc:
        return _error(str(exc))
    return _report(corr, labels, infos, window_s, max_packets_held, max_items)


def _report(corr: Correlator, labels, infos, window_s, max_held, max_items) -> Dict[str, Any]:
    start = min((i["start"] for i in infos if i.get("start") is not None), default=None)

    def rel(t):
        return round(t - start, 6) if t is not None and start is not None else None

    captures = []
    for i, info in enumerate(infos):
        captures.append({"label": info["label"], "path": info["path"], "backend": info.get("backend"),
                         "packets": corr.packets[i], "unmatched_packets": corr.unmatched[i],
                         "start": iso_time(info.get("start")), "end": iso_time(info.get("end")),
                         "clock_offset_s": info["clock_offset_s"], "warnings": info.get("warnings", [])})

    transit = []
    for (a, b), stats in sorted(corr.pairs.items()):
        deltas = stats["deltas"]
        hops = stats["ttl"].most_common(1)[0][0] if stats["ttl"] else None
        transit.append({"from": labels[a], "to": labels[b], "packets_matched": stats["matched"],
                        "delta_ms": {"min": round(min(deltas) * 1000, 3), "median": round(median(deltas) * 1000, 3),
                                     "max": round(max(deltas) * 1000, 3)} if deltas else None,
                        "ttl_decrement": hops,
                        "note": (f"{labels[b]} sees packets {abs(round(median(deltas) * 1000, 3))} ms "
                                 f"{'after' if median(deltas) >= 0 else 'before'} {labels[a]} (median, both "
                                 "directions; includes any clock offset)") if deltas else None})

    merged: Dict[tuple, Dict[str, Any]] = {}
    for (ca, cb, ta, tb), entry in corr.nat.items():
        (lo, x), (hi, y) = sorted(((ca, ta), (cb, tb)))
        changed = []
        if x[0] in (1, 58):  # ICMP: the identifier belongs to whichever address was translated
            if x[1] != y[1]:
                changed.append(("source", (x[1], x[2]), (y[1], y[2]), (x[3], None)))
            if x[3] != y[3]:
                changed.append(("destination", (x[3], x[4]), (y[3], y[4]), (x[1], None)))
        else:
            if x[1:3] != y[1:3]:
                changed.append(("source", (x[1], x[2]), (y[1], y[2]), (x[3], x[4])))
            if x[3:5] != y[3:5]:
                changed.append(("destination", (x[3], x[4]), (y[3], y[4]), (x[1], x[2])))
        for kind, before, after, remote in changed:
            # the reply of a source NAT is a destination rewrite of the same mapping
            key = (lo, hi, x[0], frozenset((before, after)))
            item = merged.get(key)
            if item is None:
                item = {"protocol": _tuple_text(x).split(" ")[0], "between": [labels[lo], labels[hi]],
                        f"at_{labels[lo]}": endpoint(*before), f"at_{labels[hi]}": endpoint(*after),
                        "remote": endpoint(*remote), "kind": f"{kind} NAT" + (" with port/id translation"
                                                                             if before[1] != after[1] else ""),
                        "packets": 0, "frames": {}}
                merged[key] = item
            item["packets"] += entry["packets"]
            for label, n in entry["frames"].items():
                item["frames"].setdefault(label, n)
    nat = sorted(merged.values(), key=lambda m: -m["packets"])

    dscp_changes = []
    for (ca, cb, da, db, tup), entry in sorted(corr.dscp.items(), key=lambda kv: -kv[1]["packets"]):
        dscp_changes.append({"from": labels[ca], "to": labels[cb], "flow": _tuple_text(tup),
                             "dscp_before": dscp_name(da), "dscp_after": dscp_name(db), "packets": entry["packets"],
                             "frames": entry["frames"]})

    connections = _connections(corr, labels, rel)
    order = {"reply_lost": 0, "partial_loss": 1, "asymmetric": 2, "seen_only_at": 3, "ok": 4, "not_on_other_paths": 5}
    connections.sort(key=lambda c: (order.get(c["verdict"], 9), c["first_t"] or 0))
    counts = Counter(c["verdict"] for c in connections)
    issues = []
    for conn in connections:
        severity = {"reply_lost": "error", "partial_loss": "warning", "asymmetric": "warning",
                    "seen_only_at": "warning"}.get(conn["verdict"])
        if severity:
            issues.append({"severity": severity, "code": f"CORRELATE_{conn['verdict'].upper()}",
                           "message": conn["detail"], "frames": conn["frames"]})
    for change in dscp_changes:
        issues.append({"severity": "warning", "code": "CORRELATE_DSCP_REWRITTEN",
                       "message": f"{change['flow']}: DSCP {change['dscp_before']} at {change['from']} became "
                                  f"{change['dscp_after']} at {change['to']} ({change['packets']} packet(s))",
                       "frames": change["frames"]})
    matched = corr.groups_matched
    if not matched:
        verdict = ("No packet was seen in more than one capture. If the captures overlap in time and carry the "
                   "same traffic, their clocks may differ by more than window_s: pass clock_offsets_s.")
    else:
        bits = [f"{matched} packet(s) matched across {len(labels)} captures"]
        if nat:
            bits.append(f"{len(nat)} NAT translation(s)")
        for name in ("reply_lost", "partial_loss", "asymmetric", "seen_only_at"):
            if counts.get(name):
                bits.append(f"{counts[name]} {name.replace('_', ' ')}")
        if dscp_changes:
            bits.append(f"DSCP rewritten on {sum(c['packets'] for c in dscp_changes)} packet(s)")
        verdict = "; ".join(bits) + "."
    conn_list = connections[:max_items]
    return {
        "status": "success",
        "schema": SCHEMA,
        "verdict": verdict,
        "captures": captures,
        "matching": {"window_s": window_s, "max_packets_held": max_held, "evicted_early": corr.evicted_early,
                     "flows_dropped_at_cap": corr.nodes_dropped, "packets_matched": matched},
        "summary": {"connections": len(connections), "by_verdict": dict(counts), "nat_translations": len(nat),
                    "dscp_changes": len(dscp_changes)},
        "issues": issues[:max_items * 4],
        "transit": transit,
        "nat": nat[:max_items],
        "nat_omitted": max(len(nat) - max_items, 0),
        "connections": conn_list,
        "connections_omitted": max(len(connections) - max_items, 0),
        "dscp_changes": dscp_changes[:max_items],
        "limits": LIMITS,
    }


def _connections(corr: Correlator, labels, rel) -> List[Dict[str, Any]]:
    comps: Dict[int, List[int]] = {}
    for node in range(len(corr.node_info)):
        comps.setdefault(corr.uf.find(node), []).append(node)
    partner: Dict[int, Counter] = {}
    for (cap, tup), node in corr.nodes.items():
        other = corr.nodes.get((cap, _reverse(tup)))
        if other is not None:
            a, b = corr.uf.find(node), corr.uf.find(other)
            if a != b:
                partner.setdefault(a, Counter())[b] += corr.node_info[other]["packets"]
    done = set()
    out = []
    for root in sorted(comps, key=lambda r: min(corr.node_info[n]["first_t"] for n in comps[r])):
        if root in done:
            continue
        done.add(root)
        rev_root = partner[root].most_common(1)[0][0] if root in partner else None
        if rev_root is not None:
            done.add(rev_root)
        fwd = _direction(corr, labels, comps[root])
        rev = _direction(corr, labels, comps[rev_root]) if rev_root is not None else None
        if fwd["first_t"] is not None and rev and rev["first_t"] is not None and rev["first_t"] < fwd["first_t"]:
            fwd, rev = rev, fwd
        out.append(_judge(fwd, rev, labels, rel, corr))
    return out


def _direction(corr: Correlator, labels, nodes: List[int]) -> Dict[str, Any]:
    seen = Counter()
    tuples = {}
    first_t = None
    patterns = Counter()
    examples = {}
    flags = {"syn": False, "synack": False}
    for node in nodes:
        info = corr.node_info[node]
        seen[info["cap"]] += info["packets"]
        tuples.setdefault(labels[info["cap"]], _tuple_text(info["tuple"]))
        first_t = info["first_t"] if first_t is None else min(first_t, info["first_t"])
        for order, entry in corr.patterns.get(node, {}).items():
            patterns[order] += entry["count"]
            examples.setdefault(order, entry["frames"])
            flags["syn"] |= entry["syn"]
            flags["synack"] |= entry["synack"]
    caps = sorted(seen)
    origin = min(nodes, key=lambda n: corr.node_info[n]["first_t"])
    dst = corr.node_info[origin]["tuple"][3]
    return {"caps": caps, "seen": {labels[c]: seen[c] for c in caps}, "tuples": tuples, "first_t": first_t,
            "patterns": patterns, "examples": examples, "flags": flags, "multicast": _multicast(dst),
            "origin": (corr.node_info[origin]["cap"], corr.node_info[origin]["tuple"])}


def _on_path_elsewhere(corr: Correlator, fwd, others: List[int]) -> List[int]:
    """Captures among `others` that saw other traffic between this flow's two addresses (NAT applied)."""
    cap, tup = fwd["origin"]
    addr_map: Dict[tuple, str] = {}
    for (ca, cb, ta, tb) in corr.nat:
        addr_map.setdefault((ca, cb, ta[1]), tb[1])
        addr_map.setdefault((ca, cb, ta[3]), tb[3])
    found = []
    for other in others:
        src = addr_map.get((cap, other, tup[1]), tup[1])
        dst = addr_map.get((cap, other, tup[3]), tup[3])
        if (src, dst) in corr.addr_pairs[other] or (dst, src) in corr.addr_pairs[other]:
            found.append(other)
    return found


def _judge(fwd, rev, labels, rel, corr) -> Dict[str, Any]:
    fwd_set = set(fwd["caps"])
    rev_set = set(rev["caps"]) if rev else set()
    frames: Dict[str, set] = {}

    def keep(example):
        for label, n in example.items():
            frames.setdefault(label, set()).add(n)

    for order, ex in list(fwd["examples"].items())[:2]:
        keep(ex)
    what = next(iter(fwd["tuples"].values()))
    partial = []
    for direction, name in ((fwd, "request"), (rev, "reply")):
        if not direction or len(direction["caps"]) < 2:
            continue
        span = set(direction["caps"])
        for (order, active), count in direction["patterns"].items():
            missing = (span & set(active)) - set(order)
            if missing:
                last = labels[order[-1]]
                partial.append({"direction": name, "packets": count, "seen_at": [labels[c] for c in order],
                                "last_seen_at": last, "missing_at": [labels[c] for c in sorted(missing)],
                                "frames": direction["examples"].get((order, active), {})})
    detail = ""
    if rev and fwd_set and rev_set and fwd_set != rev_set and (fwd_set - rev_set) and (rev_set - fwd_set):
        verdict = "asymmetric"
        detail = (f"{what}: requests seen at {', '.join(labels[c] for c in sorted(fwd_set))}, replies at "
                  f"{', '.join(labels[c] for c in sorted(rev_set))}: out through "
                  f"{', '.join(labels[c] for c in sorted(fwd_set - rev_set))}, back through "
                  f"{', '.join(labels[c] for c in sorted(rev_set - fwd_set))}")
    elif rev and rev_set < fwd_set:
        verdict = "reply_lost"
        missing = sorted(fwd_set - rev_set)
        last = (labels[max(rev["patterns"], key=rev["patterns"].get)[0][-1]] if rev["patterns"]
                else labels[min(rev_set)])
        kind = "SYN-ACK" if rev["flags"]["synack"] else "reply"
        detail = (f"{what}: the {kind} was last seen at {last} and never reached "
                  f"{', '.join(labels[c] for c in missing)} (the request crossed "
                  f"{', '.join(labels[c] for c in sorted(fwd_set))}): dropped between {last} and "
                  f"{', '.join(labels[c] for c in missing)}")
        for order, ex in list(rev["examples"].items())[:2]:
            keep(ex)
    elif partial:
        verdict = "partial_loss"
        p = max(partial, key=lambda x: x["packets"])
        detail = (f"{what}: {sum(x['packets'] for x in partial)} packet(s) did not cross every capture point, e.g. "
                  f"{p['packets']} {p['direction']} packet(s) last seen at {p['last_seen_at']}, missing at "
                  f"{', '.join(p['missing_at'])}")
        for x in partial[:2]:
            keep(x["frames"])
    elif len(fwd_set) == 1 and (not rev or len(rev_set) <= 1):
        where = labels[next(iter(fwd_set))]
        recording = corr.active(fwd["first_t"]) if fwd["first_t"] is not None else frozenset(range(len(labels)))
        others = [i for i in sorted(recording) if i not in fwd_set | rev_set]
        on_path = [] if fwd["multicast"] else _on_path_elsewhere(corr, fwd, others)
        if on_path:
            verdict = "seen_only_at"
            names = ", ".join(labels[i] for i in on_path)
            detail = (f"{what}: seen only at {where}" + (" (with replies)" if rev else ", no reply") +
                      f"; never at {names}, although other traffic between the same addresses crossed {names}: "
                      f"it stopped after {where} (an ACL, a route or a drop)")
        else:
            verdict = "not_on_other_paths"
            detail = (f"{what}: seen only at {where}"
                      + (f"; {', '.join(labels[i] for i in others)} never saw these two addresses talk, so this flow "
                         "does not cross them" if others else ""))
    else:
        verdict = "ok"
        crossed = ", ".join(labels[c] for c in sorted(fwd_set | rev_set))
        detail = (f"{what}: both directions crossed {crossed}" if rev else
                  f"{what}: crossed {crossed} (no reply seen at any capture point)")
    return {
        "flow": what,
        "verdict": verdict,
        "detail": detail,
        "endpoints_by_capture": fwd["tuples"],
        "request": {"seen_at": fwd["seen"]},
        "reply": {"seen_at": rev["seen"]} if rev else None,
        "incomplete": partial[:5],
        "link_local_or_multicast": fwd["multicast"],
        "first_t": rel(fwd["first_t"]),
        "frames": {label: sorted(ns)[:10] for label, ns in frames.items()},
    }
