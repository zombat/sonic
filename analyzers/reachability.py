#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Reachability and Conversation Detectors

ReachabilityDetector (deterministic, per address pair):
    ICMP/ICMPv6 echo request/reply matching by (source, destination, identifier,
    sequence): sent, answered, lost, loss percent, RTT min/avg/max, and outage
    windows (runs of consecutive unanswered requests with their start, end and
    duration, the shape of a failover). Echo through a GRE tunnel is matched on
    the inner addresses and marked tunneled. ICMP errors (destination
    unreachable, time exceeded, redirect, fragmentation needed) with their codes
    decoded and the original destination they refer to. ARP requests that never
    got a reply, gratuitous ARP, and one IP answered by two MAC addresses.

ConversationDetector:
    Totals, protocols by packet and byte count, top conversations (address
    pairs) and top talkers. Always applicable when a capture has packets.

Author: Raymond A Rizzo | Zombat
"""

from collections import Counter
from typing import Any, Dict, List

from analyzers.network_common import (
    Context, add_frame, cap, icmp_describe, ip_sort_key, label_service, make_event, make_issue, pair_key,
    protocol_label, sort_issues, status_from_issues,
)

ECHO_REQUEST = {False: 8, True: 128}
ECHO_REPLY = {False: 0, True: 129}
PENDING_WINDOW_S = 2.0  # an unanswered request this close to the end may still be in flight
MAX_REQUESTS_PER_PAIR = 200000


class ReachabilityDetector:
    """Streaming ICMP/ARP reachability detector."""

    name = "reachability"

    def __init__(self):
        self.requests: Dict[tuple, Dict[str, Any]] = {}
        self.pairs: Dict[tuple, Dict[str, Any]] = {}
        self.unmatched_replies = Counter()
        self.icmp_errors: Dict[tuple, Dict[str, Any]] = {}
        self.arp_requests: Dict[str, Dict[str, Any]] = {}
        self.arp_replies: Dict[str, Dict[str, Any]] = {}
        self.gratuitous = 0
        self.icmp_seen = False
        self.arp_seen = False

    def feed(self, rec: Dict[str, Any]):
        icmp = rec.get("icmp")
        if icmp:
            self.icmp_seen = True
            self._feed_icmp(rec, icmp)
        arp = rec.get("arp")
        if arp:
            self.arp_seen = True
            self._feed_arp(rec, arp)

    def _feed_icmp(self, rec, icmp):
        v6, itype = icmp["v6"], icmp["type"]
        src, dst, t, n = icmp["src"], icmp["dst"], rec["t"], rec["n"]
        if itype == ECHO_REQUEST[v6]:
            key = (src, dst, icmp["id"], icmp["seq"], v6)
            req = self.requests.get(key)
            pair = self.pairs.get((src, dst))
            if pair is None:
                pair = {"src": src, "dst": dst, "v6": v6, "tunneled": icmp["tunneled"], "keys": [],
                        "duplicates": 0, "first_t": t, "frames": []}
                self.pairs[(src, dst)] = pair
            if req is not None:
                pair["duplicates"] += 1
                return
            if len(pair["keys"]) >= MAX_REQUESTS_PER_PAIR:
                return
            self.requests[key] = {"t": t, "n": n, "reply_t": None, "reply_n": None}
            pair["keys"].append(key)
            add_frame(pair["frames"], n)
        elif itype == ECHO_REPLY[v6]:
            key = (dst, src, icmp["id"], icmp["seq"], v6)
            req = self.requests.get(key)
            if req is None:
                self.unmatched_replies[(src, dst)] += 1
            elif req["reply_t"] is None:
                req["reply_t"], req["reply_n"] = t, n
        else:
            type_name, code_text = icmp_describe(v6, itype, icmp["code"])
            orig = icmp.get("orig") or {}
            key = (src, dst, v6, itype, icmp["code"], orig.get("dst"), orig.get("proto"), orig.get("dport"))
            err = self.icmp_errors.get(key)
            if err is None:
                err = {"from": src, "to": dst, "v6": v6, "type": itype, "code": icmp["code"], "type_name": type_name,
                       "code_text": code_text, "original_src": orig.get("src"), "original_dst": orig.get("dst"),
                       "original_protocol": orig.get("proto"), "original_dport": orig.get("dport"),
                       "count": 0, "first_t": t, "frames": []}
                self.icmp_errors[key] = err
            err["count"] += 1
            add_frame(err["frames"], n)

    def _feed_arp(self, rec, arp):
        spa, tpa, t, n = arp["spa"], arp["tpa"], rec["t"], rec["n"]
        if arp["op"] == 1:
            if spa == tpa:
                self.gratuitous += 1
                return
            req = self.arp_requests.get(tpa)
            if req is None:
                req = {"target": tpa, "askers": set(), "count": 0, "first_t": t, "frames": []}
                self.arp_requests[tpa] = req
            req["askers"].add(spa)
            req["count"] += 1
            add_frame(req["frames"], n)
        elif arp["op"] == 2:
            if spa == tpa:
                self.gratuitous += 1
            rep = self.arp_replies.get(spa)
            if rep is None:
                rep = {"ip": spa, "macs": Counter(), "first_t": t, "frames": []}
                self.arp_replies[spa] = rep
            rep["macs"][arp["sha"]] += 1
            add_frame(rep["frames"], n)

    def present(self) -> bool:
        return self.icmp_seen or self.arp_seen

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        echo_pairs = []
        for (src, dst), pair in sorted(self.pairs.items(), key=lambda kv: kv[1]["first_t"]):
            echo_pairs.append(self._echo_pair(ctx, pair, issues, events))

        errors = []
        for err in sorted(self.icmp_errors.values(), key=lambda e: e["first_t"]):
            target = err["original_dst"]
            proto = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}.get(err["original_protocol"], err["original_protocol"])
            what = f"{proto}/{err['original_dport']}" if err["original_dport"] else f"{proto}"
            message = (f"{err['from']} sent {err['type_name']} ({err['code_text']}) to {err['to']} "
                       f"for {what} towards {target} ({err['count']}x)")
            severity = "warning"
            if err["type"] == 11 or (err["v6"] and err["type"] == 3):
                severity = "info"
            if not err["v6"] and err["type"] == 3 and err["code"] == 4 or (err["v6"] and err["type"] == 2):
                message += "; a packet too big for the path with DF set: check tunnel MTU / TCP MSS adjust"
            issues.append(make_issue(severity, f"ICMP_{err['type_name'].upper()}", message, err["frames"],
                                     icmp_type=err["type"], icmp_code=err["code"]))
            events.append(make_event(ctx, err["first_t"], "icmp", err["type_name"], message, err["frames"][0]))
            out = dict(err)
            out["first_t"] = ctx.rel(err["first_t"])
            errors.append(out)

        arp_unanswered = []
        arp_answered = []
        for target, req in sorted(self.arp_requests.items(), key=lambda kv: ip_sort_key(kv[0])):
            if target in self.arp_replies:
                arp_answered.append(target)
                continue
            arp_unanswered.append({"target": target, "requested_by": sorted(req["askers"], key=ip_sort_key),
                                   "requests": req["count"], "first_t": ctx.rel(req["first_t"]), "frames": req["frames"]})
            issues.append(make_issue("warning", "ARP_NO_REPLY",
                                     f"ARP for {target} asked {req['count']} time(s) by "
                                     f"{', '.join(sorted(req['askers'], key=ip_sort_key))}, never answered "
                                     "(host down, wrong subnet, or not on this segment)", req["frames"]))
        duplicates = []
        for ip, rep in self.arp_replies.items():
            if len(rep["macs"]) > 1:
                duplicates.append({"ip": ip, "macs": dict(rep["macs"]), "frames": rep["frames"]})
                issues.append(make_issue("error", "ARP_DUPLICATE_IP",
                                         f"{ip} is claimed by several MAC addresses: {', '.join(rep['macs'])}",
                                         rep["frames"]))

        present = self.present()
        status = status_from_issues(issues, present)
        verdict = self._verdict(present, echo_pairs, errors, arp_unanswered)
        pairs_list, pairs_omitted = cap(echo_pairs, ctx.max_items)
        errors_list, errors_omitted = cap(errors, ctx.max_items)
        unanswered_list, unanswered_omitted = cap(arp_unanswered, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "summary": {
                "echo_pairs": len(echo_pairs),
                "echo_requests": sum(p["sent"] for p in echo_pairs),
                "echo_replies_matched": sum(p["answered"] for p in echo_pairs),
                "echo_lost": sum(p["lost"] for p in echo_pairs),
                "unmatched_replies": sum(self.unmatched_replies.values()),
                "icmp_errors": sum(e["count"] for e in errors),
                "arp_targets_unanswered": len(arp_unanswered),
                "arp_targets_answered": len(arp_answered),
                "gratuitous_arp": self.gratuitous,
            },
            "echo": pairs_list,
            "echo_omitted": pairs_omitted,
            "icmp_errors": errors_list,
            "icmp_errors_omitted": errors_omitted,
            "arp_unanswered": unanswered_list,
            "arp_unanswered_omitted": unanswered_omitted,
            "arp_duplicate_ips": duplicates,
            "issues": sort_issues(issues),
            "events": events,
        }

    def _echo_pair(self, ctx, pair, issues, events):
        src, dst = pair["src"], pair["dst"]
        requests = [self.requests[key] for key in pair["keys"]]
        requests.sort(key=lambda r: r["t"])
        rtts = []
        lost = pending = 0
        outages = []
        run = []

        def close_run():
            if run:
                start, end = run[0], run[-1]
                next_ok = None
                outages.append({"start_t": ctx.rel(start["t"]), "end_t": ctx.rel(end["t"]),
                                "lost_requests": len(run), "first_frame": start["n"], "last_frame": end["n"],
                                "start_time_s": start["t"], "next_reply_frame": next_ok})
                run.clear()

        answered_times = [r["t"] for r in requests if r["reply_t"] is not None]
        last_answered_t = max(answered_times) if answered_times else None
        pending_cut = ctx.end - PENDING_WINDOW_S if ctx.end is not None else None
        for req in requests:
            if req["reply_t"] is not None:
                rtts.append((req["reply_t"] - req["t"]) * 1000.0)
                if run:
                    close_run()
                    outages[-1]["next_reply_frame"] = req["reply_n"]
                    outages[-1]["recovered_t"] = ctx.rel(req["reply_t"])
            elif (pending_cut is not None and req["t"] > pending_cut
                  and (last_answered_t is None or req["t"] > last_answered_t)):
                pending += 1  # sent just before the capture ended; the reply may still be in flight
            else:
                lost += 1
                run.append(req)
        close_run()
        for outage in outages:
            outage.pop("start_time_s", None)
            outage.setdefault("recovered_t", None)
            outage["duration_s"] = (round(outage["recovered_t"] - outage["start_t"], 3)
                                    if outage["recovered_t"] is not None else None)
        sent = len(requests)
        counted = sent - pending
        answered = len(rtts)
        loss_pct = round(100.0 * lost / counted, 1) if counted else 0.0
        label = f"{src} -> {dst}" + (" (inside GRE)" if pair["tunneled"] else "")
        if counted and answered == 0:
            verdict = "no_reply"
            issues.append(make_issue("error", "ICMP_NO_REPLY",
                                     f"ping {label}: {counted} request(s), no reply seen at this capture point "
                                     "(destination down, path broken, or replies take another path)", pair["frames"]))
        elif lost:
            verdict = "loss"
            issues.append(make_issue("warning", "ICMP_LOSS",
                                     f"ping {label}: {lost} of {counted} lost ({loss_pct}%), "
                                     f"{len(outages)} outage window(s)", [o["first_frame"] for o in outages]))
        else:
            verdict = "ok"
        for outage in outages:
            text = f"ping {label}: {outage['lost_requests']} consecutive request(s) unanswered"
            text += (f", recovered after {outage['duration_s']} s" if outage["duration_s"] is not None
                     else ", not recovered by capture end")
            events.append(make_event(ctx, ctx.start + outage["start_t"] if ctx.start is not None else 0,
                                     "icmp", "outage", text, outage["first_frame"]))
        return {
            "src": src, "dst": dst, "ipv6": pair["v6"], "tunneled": pair["tunneled"], "verdict": verdict,
            "sent": sent, "answered": answered, "lost": lost, "pending_at_capture_end": pending,
            "loss_percent": loss_pct, "duplicate_requests_seen": pair["duplicates"],
            "rtt_ms": ({"min": round(min(rtts), 3), "avg": round(sum(rtts) / len(rtts), 3), "max": round(max(rtts), 3)}
                       if rtts else None),
            "outages": outages[:ctx.max_items],
            "first_t": ctx.rel(pair["first_t"]),
            "frames": pair["frames"],
        }

    @staticmethod
    def _verdict(present, echo_pairs, errors, arp_unanswered) -> str:
        if not present:
            return "No ICMP or ARP in this capture."
        parts = []
        if echo_pairs:
            bad = [p for p in echo_pairs if p["verdict"] != "ok"]
            if bad:
                parts.append("ping loss: " + "; ".join(
                    f"{p['src']}->{p['dst']} {p['lost']}/{p['sent'] - p['pending_at_capture_end']} lost"
                    for p in bad[:5]))
            else:
                parts.append(f"all {len(echo_pairs)} ping pair(s) answered, no loss")
        if errors:
            parts.append(f"{sum(e['count'] for e in errors)} ICMP error(s): " + "; ".join(
                f"{e['type_name']} ({e['code_text']}) from {e['from']}" for e in errors[:3]))
        if arp_unanswered:
            parts.append("ARP unanswered for " + ", ".join(a["target"] for a in arp_unanswered[:5]))
        return "; ".join(parts) if parts else "ARP seen, all requests answered."


class ConversationDetector:
    """Totals, protocol mix, top conversations and top talkers."""

    name = "conversations"

    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.protocols: Dict[str, List[int]] = {}
        self.conversations: Dict[tuple, Dict[str, Any]] = {}
        self.talkers: Dict[str, List[int]] = {}

    def feed(self, rec: Dict[str, Any]):
        self.packets += 1
        length = rec.get("len", 0)
        self.bytes += length
        label = protocol_label(rec)
        stats = self.protocols.get(label)
        if stats is None:
            stats = [0, 0]
            self.protocols[label] = stats
        stats[0] += 1
        stats[1] += length
        ip = rec.get("ip")
        if not ip:
            return
        src, dst = ip["src"], ip["dst"]
        key = pair_key(src, dst)
        conv = self.conversations.get(key)
        if conv is None:
            conv = {"packets": 0, "bytes": 0, "a_to_b": [0, 0], "b_to_a": [0, 0], "protocols": Counter()}
            self.conversations[key] = conv
        conv["packets"] += 1
        conv["bytes"] += length
        direction = conv["a_to_b"] if src == key[0] else conv["b_to_a"]
        direction[0] += 1
        direction[1] += length
        conv["protocols"][label] += 1
        talker = self.talkers.get(src)
        if talker is None:
            talker = [0, 0]
            self.talkers[src] = talker
        talker[0] += 1
        talker[1] += length

    def present(self) -> bool:
        return self.packets > 0

    def report(self, ctx: Context) -> Dict[str, Any]:
        protocols = [{"protocol": label, "service": label_service(label), "packets": p, "bytes": b}
                     for label, (p, b) in sorted(self.protocols.items(), key=lambda kv: (-kv[1][1], kv[0]))]
        convs = []
        for (a, b), conv in sorted(self.conversations.items(), key=lambda kv: -kv[1]["bytes"]):
            convs.append({"a": a, "b": b, "packets": conv["packets"], "bytes": conv["bytes"],
                          "a_to_b": {"packets": conv["a_to_b"][0], "bytes": conv["a_to_b"][1]},
                          "b_to_a": {"packets": conv["b_to_a"][0], "bytes": conv["b_to_a"][1]},
                          "protocols": dict(conv["protocols"].most_common(5))})
        talkers = [{"address": addr, "packets_sent": p, "bytes_sent": b}
                   for addr, (p, b) in sorted(self.talkers.items(), key=lambda kv: -kv[1][1])]
        duration = round(ctx.end - ctx.start, 3) if ctx.start is not None and ctx.end is not None else None
        top = protocols[0]["protocol"] if protocols else None
        verdict = (f"{self.packets} packets, {self.bytes} bytes over {duration} s; {len(self.conversations)} "
                   f"address pair(s); most bytes: {top}") if self.packets else "Empty capture."
        convs_list, convs_omitted = cap(convs, ctx.max_items)
        talkers_list, talkers_omitted = cap(talkers, ctx.max_items)
        protocols_list, protocols_omitted = cap(protocols, ctx.max_items * 2)
        return {
            "detector": self.name,
            "status": "ok" if self.packets else "not_present",
            "verdict": verdict,
            "totals": {"packets": self.packets, "bytes": self.bytes, "duration_s": duration,
                       "address_pairs": len(self.conversations), "hosts_sending": len(self.talkers)},
            "protocols": protocols_list,
            "protocols_omitted": protocols_omitted,
            "top_conversations": convs_list,
            "top_conversations_omitted": convs_omitted,
            "top_talkers": talkers_list,
            "top_talkers_omitted": talkers_omitted,
            "issues": [],
            "events": [],
        }
