#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Path MTU and Fragmentation Detector

PathMtuDetector (deterministic, streaming):
    - ICMP Fragmentation Needed (type 3 code 4) and ICMPv6 Packet Too Big: which
      router sent it, the next-hop MTU it advertises, and the packet it refers to,
      matched back to the probe frame by the identification (IPv4) or the length
      (IPv6) copied into the error.
    - DF-set probes: ICMP echo requests with DF (every IPv6 echo counts) per
      source and destination: the largest answered, the smallest that vanished.
      Large probes that vanished with no ICMP while smaller ones were answered are
      a PMTUD black hole, and the path MTU lies between the two sizes.
    - TCP: DF segments retransmitted and never acknowledged while smaller
      segments of the same connection were, with no ICMP for that destination: a
      TCP black hole (MSS too large for the path, ICMP filtered).
    - IP fragments per datagram (source, destination, protocol, identification):
      complete, incomplete (first, middle or last piece missing at this capture
      point), overlapping, the size of the first fragment (the MTU of the link
      where the datagram was split), and ICMP reassembly-time-exceeded.

Memory is bounded: probes, TCP segments and fragment groups are held up to fixed
caps (MAX_PROBES, MAX_TCP_SEGMENTS_PER_FLOW, MAX_FRAGMENT_GROUPS), oldest first out.

Author: Raymond A Rizzo | Zombat
"""

from collections import OrderedDict
from typing import Any, Dict, List

from analyzers.dataplane_common import seq_delta, transport
from analyzers.network_common import (
    Context, add_frame, cap, make_event, make_issue, sort_issues, status_from_issues,
)

MIN_PROBE_BYTES = 576          # every IPv4 path carries 576; DF packets above it can probe the path
MAX_PROBES = 50000
MAX_TCP_FLOWS = 20000
MAX_TCP_SEGMENTS_PER_FLOW = 256
MAX_FRAGMENT_GROUPS = 20000
PENDING_WINDOW_S = 2.0

LIMITS = [
    "Only what crossed this capture point is visible: a Fragmentation Needed sent towards a host on "
    "another segment, or dropped by an ACL before this point, is invisible here, so a black hole verdict "
    "means 'no ICMP seen here', not proof that no router sent one.",
    "A vanished probe can be loss rather than MTU; the black hole verdict needs smaller probes to the same "
    "destination answered and larger ones never answered.",
    "Fragments captured on one side of the reassembling host show whether pieces arrived here; whether "
    "the host reassembled them is not visible.",
    "IPv6 extension headers (including fragment headers) are not decoded.",
]


class PathMtuDetector:
    """Streaming path MTU, PMTUD black hole and fragmentation detector."""

    name = "path_mtu"

    def __init__(self):
        self.probes: "OrderedDict[tuple, Dict[str, Any]]" = OrderedDict()
        self.echo_index: Dict[tuple, tuple] = {}
        self.ptb: Dict[tuple, Dict[str, Any]] = {}
        self.ptb_targets = set()
        self.tcp_flows: "OrderedDict[tuple, Dict[str, Any]]" = OrderedDict()
        self.frag_groups: "OrderedDict[tuple, Dict[str, Any]]" = OrderedDict()
        self.frag_groups_dropped = 0
        self.reassembly_timeouts: List[Dict[str, Any]] = []
        self.df_large = 0
        self.largest_df = 0
        self.last_t = None

    # -- feed -----------------------------------------------------------------

    def feed(self, rec: Dict[str, Any]):
        dp = rec.get("dp")
        ip = rec.get("ip")
        if not dp or not ip:
            return
        self.last_t = rec["t"]
        if dp["mf"] or dp["off"]:
            self._feed_fragment(rec, ip, dp)
        icmp = rec.get("icmp")
        if icmp:
            self._feed_icmp(rec, icmp)
        view = transport(rec)
        if view is None:
            return
        df = True if view["v6"] else bool(view["df"])
        size = view["tl"] or 0
        if df and size > MIN_PROBE_BYTES:
            self.df_large += 1
            self.largest_df = max(self.largest_df, size)
            self._remember_probe(rec, view, icmp)
        if view["tcp"] and view["dtcp"]:
            self._feed_tcp(rec, view, df, size)

    def _remember_probe(self, rec, view, icmp):
        key = (view["src"], view["dst"], view["id"] if not view["v6"] else ("len", view["tl"]))
        echo = None
        if icmp and icmp["type"] == (128 if icmp["v6"] else 8):
            echo = (icmp["src"], icmp["dst"], icmp["id"], icmp["seq"])
        probe = self.probes.get(key)
        if probe is None:
            if len(self.probes) >= MAX_PROBES:
                self.probes.popitem(last=False)
            probe = {"t": rec["t"], "n": rec["n"], "src": view["src"], "dst": view["dst"], "len": view["tl"],
                     "echo": echo, "answered": False, "ptb": False, "tunneled": view["tunneled"]}
            self.probes[key] = probe
            if echo:
                self.echo_index[echo] = key

    def _feed_icmp(self, rec, icmp):
        v6, itype, code = icmp["v6"], icmp["type"], icmp["code"]
        if itype == (129 if v6 else 0):
            key = self.echo_index.get((icmp["dst"], icmp["src"], icmp["id"], icmp["seq"]))
            if key and key in self.probes:
                self.probes[key]["answered"] = True
            return
        orig = icmp.get("orig") or {}
        detail = (rec.get("dp") or {}).get("icmp") or {}
        if (not v6 and itype == 11 and code == 1) or (v6 and itype == 3 and code == 1):
            self.reassembly_timeouts.append({"from": icmp["src"], "to": icmp["dst"], "t": rec["t"], "n": rec["n"],
                                             "original_dst": orig.get("dst")})
            return
        if not ((not v6 and itype == 3 and code == 4) or (v6 and itype == 2)):
            return
        mtu = detail.get("mtu")
        key = (icmp["src"], icmp["dst"], orig.get("src"), orig.get("dst"), mtu)
        entry = self.ptb.get(key)
        if entry is None:
            entry = {"router": icmp["src"], "to": icmp["dst"], "original_src": orig.get("src"),
                     "original_dst": orig.get("dst"), "original_protocol": orig.get("proto"),
                     "original_dport": orig.get("dport"), "mtu": mtu, "original_len": detail.get("orig_len"),
                     "count": 0, "first_t": rec["t"], "frames": [], "probe_frames": [], "tunneled": icmp["tunneled"]}
            self.ptb[key] = entry
        entry["count"] += 1
        add_frame(entry["frames"], rec["n"])
        self.ptb_targets.add((orig.get("src"), orig.get("dst")))
        probe_key = (orig.get("src"), orig.get("dst"),
                     detail.get("orig_id") if not v6 else ("len", detail.get("orig_len")))
        probe = self.probes.get(probe_key)
        if probe is not None:
            probe["ptb"] = True
            add_frame(entry["probe_frames"], probe["n"])

    def _feed_tcp(self, rec, view, df, size):
        tcp, dtcp = view["tcp"], view["dtcp"]
        fwd = (view["src"], tcp["sport"], view["dst"], tcp["dport"])
        rev = (view["dst"], tcp["dport"], view["src"], tcp["sport"])
        flags = tcp["flags"]
        if flags & 0x10:  # ACK: retire what the other side's data it covers
            flow = self.tcp_flows.get(rev)
            if flow is not None:
                ack = dtcp["ack"]
                done = [seq for seq, seg in flow["segments"].items() if seq_delta(ack, seq + seg["plen"]) >= 0]
                for seq in done:
                    seg = flow["segments"].pop(seq)
                    flow["max_acked_size"] = max(flow["max_acked_size"], seg["len"])
        plen = tcp["len"]
        if plen <= 0 or not df:
            return
        flow = self.tcp_flows.get(fwd)
        if flow is None:
            if len(self.tcp_flows) >= MAX_TCP_FLOWS:
                self.tcp_flows.popitem(last=False)
            flow = {"segments": {}, "max_acked_size": 0, "src": view["src"], "dst": view["dst"],
                    "sport": tcp["sport"], "dport": tcp["dport"]}
            self.tcp_flows[fwd] = flow
        seg = flow["segments"].get(dtcp["seq"])
        if seg is None:
            if len(flow["segments"]) >= MAX_TCP_SEGMENTS_PER_FLOW:
                return
            flow["segments"][dtcp["seq"]] = {"len": size, "plen": plen, "sent": 1, "t": rec["t"], "n": rec["n"],
                                             "frames": [rec["n"]]}
        else:
            seg["sent"] += 1
            add_frame(seg["frames"], rec["n"])

    def _feed_fragment(self, rec, ip, dp):
        key = (ip["src"], ip["dst"], ip["proto"], dp["id"])
        group = self.frag_groups.get(key)
        if group is None:
            if len(self.frag_groups) >= MAX_FRAGMENT_GROUPS:
                self.frag_groups.popitem(last=False)
                self.frag_groups_dropped += 1
            group = {"src": ip["src"], "dst": ip["dst"], "proto": ip["proto"], "id": dp["id"], "pieces": [],
                     "first_t": rec["t"], "last_t": rec["t"], "frames": [], "first_fragment_len": None}
            self.frag_groups[key] = group
        group["last_t"] = rec["t"]
        add_frame(group["frames"], rec["n"])
        if len(group["pieces"]) < 128:
            group["pieces"].append((dp["off"], max(dp["tl"] - dp["hl"], 0), dp["mf"], rec["n"]))
        if dp["off"] == 0:
            group["first_fragment_len"] = dp["tl"]

    # -- report ---------------------------------------------------------------

    def present(self) -> bool:
        return bool(self.df_large or self.ptb or self.frag_groups or self.reassembly_timeouts)

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        frag_needed = self._report_ptb(ctx, issues, events)
        black_holes = self._echo_black_holes(ctx, issues, events) + self._tcp_black_holes(ctx, issues, events)
        fragments = self._report_fragments(ctx, issues, events)
        for timeout in self.reassembly_timeouts:
            message = (f"{timeout['from']} gave up reassembling fragments towards it from {timeout['to']} "
                       "(ICMP fragment reassembly time exceeded): a fragment was lost on the way")
            issues.append(make_issue("error", "FRAGMENT_REASSEMBLY_TIMEOUT", message, [timeout["n"]]))
            events.append(make_event(ctx, timeout["t"], "ip", "reassembly_timeout", message, timeout["n"]))
        present = self.present()
        status = status_from_issues(issues, present)
        verdict = self._verdict(present, frag_needed, black_holes, fragments)
        ptb_list, ptb_omitted = cap(frag_needed, ctx.max_items)
        holes_list, holes_omitted = cap(black_holes, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "summary": {
                "df_packets_over_576": self.df_large,
                "largest_df_packet": self.largest_df or None,
                "frag_needed_messages": sum(p["count"] for p in frag_needed),
                "smallest_mtu_advertised": min((p["mtu"] for p in frag_needed if p["mtu"]), default=None),
                "black_holes": len(black_holes),
                "fragmented_datagrams": fragments["datagrams"],
                "incomplete_datagrams": fragments["incomplete_count"],
                "reassembly_timeouts": len(self.reassembly_timeouts),
            },
            "frag_needed": ptb_list,
            "frag_needed_omitted": ptb_omitted,
            "black_holes": holes_list,
            "black_holes_omitted": holes_omitted,
            "fragments": fragments,
            "limits": LIMITS,
            "issues": sort_issues(issues),
            "events": events,
        }

    def _report_ptb(self, ctx, issues, events):
        out = []
        for entry in sorted(self.ptb.values(), key=lambda e: e["first_t"]):
            what = "Packet Too Big" if ":" in (entry["router"] or "") else "Fragmentation Needed"
            mtu = entry["mtu"]
            text = (f"{entry['router']} sent {what} to {entry['to']} for packets {entry['original_src']} -> "
                    f"{entry['original_dst']}")
            text += f" ({entry['original_len']} bytes)" if entry["original_len"] else ""
            if mtu:
                text += f": next-hop MTU {mtu}"
                severity = "warning"
                if entry["original_len"] and mtu >= entry["original_len"]:
                    text += " (not smaller than the packet it refers to: a bogus or stale MTU)"
            else:
                text += ": no next-hop MTU stated (pre-RFC 1191 router; the sender must guess)"
                severity = "warning"
            text += f" ({entry['count']}x)"
            if entry["probe_frames"]:
                text += f"; refers to frame(s) {', '.join(map(str, entry['probe_frames'][:3]))}"
            issues.append(make_issue(severity, "PMTU_FRAG_NEEDED", text, entry["frames"], mtu=mtu,
                                     router=entry["router"]))
            events.append(make_event(ctx, entry["first_t"], "icmp", "frag_needed", text, entry["frames"][0]))
            item = dict(entry)
            item["first_t"] = ctx.rel(entry["first_t"])
            out.append(item)
        return out

    def _echo_black_holes(self, ctx, issues, events):
        by_pair: Dict[tuple, List[Dict[str, Any]]] = {}
        for probe in self.probes.values():
            if probe["echo"]:
                by_pair.setdefault((probe["src"], probe["dst"]), []).append(probe)
        pending_cut = ctx.end - PENDING_WINDOW_S if ctx.end is not None else None
        out = []
        for (src, dst), probes in by_pair.items():
            answered = [p for p in probes if p["answered"]]
            vanished = [p for p in probes if not p["answered"] and not p["ptb"]
                        and not (pending_cut is not None and p["t"] > pending_cut)]
            if not vanished or (src, dst) in self.ptb_targets:
                continue
            largest_ok = max((p["len"] for p in answered), default=None)
            smallest_lost = min(p["len"] for p in vanished)
            if largest_ok is None or largest_ok >= smallest_lost:
                continue  # nothing answered, or same-size probes answered: loss, not MTU
            frames = [p["n"] for p in sorted(vanished, key=lambda p: p["t"])][:10]
            hole = {"kind": "icmp_echo", "src": src, "dst": dst, "largest_answered": largest_ok,
                    "smallest_vanished": smallest_lost, "vanished_probes": len(vanished),
                    "path_mtu_between": [largest_ok, smallest_lost - 1], "frames": frames}
            text = (f"PMTUD black hole {src} -> {dst}: DF probes up to {largest_ok} bytes answered, "
                    f"{len(vanished)} probe(s) of {smallest_lost} bytes or more vanished with no ICMP "
                    f"Fragmentation Needed seen; path MTU is between {largest_ok} and {smallest_lost - 1}")
            issues.append(make_issue("error", "PMTU_BLACK_HOLE", text, frames))
            first = min(vanished, key=lambda p: p["t"])
            events.append(make_event(ctx, first["t"], "icmp", "pmtu_black_hole", text, first["n"]))
            out.append(hole)
        return out

    def _tcp_black_holes(self, ctx, issues, events):
        out = []
        for flow in self.tcp_flows.values():
            stuck = [s for s in flow["segments"].values() if s["sent"] >= 2]
            if not stuck or (flow["src"], flow["dst"]) in self.ptb_targets:
                continue
            smallest = min(s["len"] for s in stuck)
            if flow["max_acked_size"] == 0 or flow["max_acked_size"] >= smallest:
                continue
            frames = []
            for seg in sorted(stuck, key=lambda s: s["t"]):
                frames.extend(seg["frames"])
            first = min(stuck, key=lambda s: s["t"])
            text = (f"TCP black hole {flow['src']}:{flow['sport']} -> {flow['dst']}:{flow['dport']}: "
                    f"{len(stuck)} DF segment(s) of {smallest}+ bytes retransmitted and never acknowledged while "
                    f"segments up to {flow['max_acked_size']} bytes were; no ICMP seen: lower the MSS "
                    "(ip tcp adjust-mss) or let ICMP type 3 code 4 through")
            issues.append(make_issue("error", "TCP_PMTU_BLACK_HOLE", text, frames[:10]))
            events.append(make_event(ctx, first["t"], "tcp", "pmtu_black_hole", text, first["n"]))
            out.append({"kind": "tcp", "src": flow["src"], "dst": flow["dst"], "sport": flow["sport"],
                        "dport": flow["dport"], "largest_answered": flow["max_acked_size"],
                        "smallest_vanished": smallest, "vanished_probes": len(stuck),
                        "path_mtu_between": [flow["max_acked_size"], smallest - 1], "frames": frames[:10]})
        return out

    def _report_fragments(self, ctx, issues, events):
        complete = 0
        incomplete = []
        overlapping = []
        by_pair: Dict[tuple, Dict[str, Any]] = {}
        for group in self.frag_groups.values():
            pieces = sorted(group["pieces"])
            pair = by_pair.setdefault((group["src"], group["dst"], group["proto"]), {
                "src": group["src"], "dst": group["dst"], "protocol": group["proto"], "datagrams": 0,
                "first_fragment_sizes": set(), "incomplete": 0})
            pair["datagrams"] += 1
            if group["first_fragment_len"]:
                pair["first_fragment_sizes"].add(group["first_fragment_len"])
            covered = 0
            gap = overlap = False
            seen = set()
            for off, length, _mf, _n in pieces:
                if (off, length) in seen:
                    continue
                seen.add((off, length))
                if off > covered:
                    gap = True
                elif off < covered:
                    overlap = True
                covered = max(covered, off + length)
            has_first = any(off == 0 for off, *_ in pieces)
            has_last = any(not mf for _off, _len, mf, _n in pieces)
            missing = []
            if not has_first:
                missing.append("first")
            if gap:
                missing.append("middle")
            if not has_last:
                missing.append("last")
            if overlap:
                overlapping.append({"src": group["src"], "dst": group["dst"], "protocol": group["proto"],
                                    "id": group["id"], "frames": group["frames"]})
            if missing:
                pair["incomplete"] += 1
                incomplete.append({"src": group["src"], "dst": group["dst"], "protocol": group["proto"],
                                   "id": group["id"], "missing": missing, "pieces_seen": len(seen),
                                   "first_t": ctx.rel(group["first_t"]), "frames": group["frames"]})
            else:
                complete += 1
        if incomplete:
            first = incomplete[0]
            text = (f"{len(incomplete)} fragmented datagram(s) incomplete at this capture point (e.g. "
                    f"{first['src']} -> {first['dst']} id {first['id']}: {', '.join(first['missing'])} "
                    "fragment missing); the receiver cannot reassemble them")
            issues.append(make_issue("warning", "FRAGMENT_INCOMPLETE", text, first["frames"]))
            events.append(make_event(ctx, ctx.start + first["first_t"] if ctx.start is not None else 0,
                                     "ip", "fragment_incomplete", text, first["frames"][0]))
        if overlapping:
            text = (f"{len(overlapping)} datagram(s) with overlapping fragments (a broken fragmenter or an "
                    "evasion attempt; many hosts drop them)")
            issues.append(make_issue("error", "FRAGMENT_OVERLAP", text, overlapping[0]["frames"]))
        pairs = []
        for pair in sorted(by_pair.values(), key=lambda p: -p["datagrams"]):
            sizes = sorted(pair.pop("first_fragment_sizes"))
            pair["first_fragment_sizes"] = sizes
            pair["split_at_mtu"] = max(sizes) if sizes else None
            pairs.append(pair)
        if pairs and not incomplete:
            top = pairs[0]
            text = (f"{sum(p['datagrams'] for p in pairs)} datagram(s) fragmented; e.g. {top['src']} -> {top['dst']} "
                    f"split at {top['split_at_mtu']} bytes")
            issues.append(make_issue("info", "IP_FRAGMENTATION", text, []))
        incomplete_list, incomplete_omitted = cap(incomplete, ctx.max_items)
        pairs_list, pairs_omitted = cap(pairs, ctx.max_items)
        return {"datagrams": len(self.frag_groups), "complete": complete, "incomplete_count": len(incomplete),
                "incomplete": incomplete_list, "incomplete_omitted": incomplete_omitted,
                "overlapping": overlapping[:ctx.max_items], "by_pair": pairs_list, "by_pair_omitted": pairs_omitted,
                "groups_dropped_at_cap": self.frag_groups_dropped}

    def _verdict(self, present, frag_needed, black_holes, fragments) -> str:
        if not present:
            return "No large DF packets, no Fragmentation Needed and no fragments in this capture."
        parts = []
        if frag_needed:
            mtus = sorted({p["mtu"] for p in frag_needed if p["mtu"]})
            parts.append(f"{sum(p['count'] for p in frag_needed)} Fragmentation Needed / Packet Too Big"
                         + (f" advertising MTU {', '.join(map(str, mtus))}" if mtus else " without an MTU"))
        if black_holes:
            hole = black_holes[0]
            parts.append(f"PMTUD black hole {hole['src']} -> {hole['dst']} (path MTU between "
                         f"{hole['path_mtu_between'][0]} and {hole['path_mtu_between'][1]})")
        if fragments["datagrams"]:
            text = f"{fragments['datagrams']} fragmented datagram(s)"
            if fragments["incomplete_count"]:
                text += f", {fragments['incomplete_count']} incomplete"
            parts.append(text)
        if not parts:
            return (f"{self.df_large} DF packet(s) over 576 bytes, largest {self.largest_df}; no Fragmentation "
                    "Needed, no fragments, no black hole.")
        return "; ".join(parts) + "."
