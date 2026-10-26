#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Routing Protocol Health Detector

Deterministic checks of BGP, OSPFv2 and EIGRP from captured packets, with a
timeline of adjacency changes so a failover (a router dies, neighbors notice,
routing reconverges) can be read off in order.

BGP (TCP 179), per peer pair:
    TCP connection attempts (unanswered SYN, refused with RST), OPEN details
    (AS, hold time, router ID), established/down transitions, UPDATE counts and
    IPv4 prefixes announced/withdrawn, End-of-RIB, NOTIFICATION code/subcode
    decoded with a plain hint, keepalive gaps beyond the negotiated hold time,
    a speaker still silent at capture end, session resets and flaps.

OSPF (IP 89), per link (routers whose hello subnets overlap):
    hello/dead intervals, network mask, area, authentication type and E-bit
    (stub) compared between speakers, DB Description MTU, DR/BDR claims and
    changes, neighbor state hints (one-way, 2-Way or better, DBD/LSA exchange
    seen), duplicate router IDs, hello gaps beyond the dead interval, neighbors
    dropped from and re-added to hello lists.

EIGRP (IP 88), per link (unicast exchange or the same /24):
    K-values and AS compared between speakers, hold time, goodbye messages
    (all K-values 255), INIT updates (adjacency starts and restarts), Queries
    and SIA-Queries, gaps beyond the hold time, a speaker silent at capture end.

Author: Raymond A Rizzo | Zombat
"""

import ipaddress
from collections import Counter
from typing import Any, Dict, List, Optional

from analyzers.network_common import (
    BGP_TYPES, EIGRP_OPCODES, Context, add_frame, bgp_error_hint, bgp_error_name, cap, make_event,
    make_issue, median, pair_key, sort_issues, status_from_issues, worst_status,
)


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------

class _BgpConnection:
    def __init__(self, key, t):
        self.key = key
        self.first_t = t
        self.syn_from = None
        self.syn_count = 0
        self.synack = False
        self.rst_from = None
        self.fin_from = set()
        self.closed = False
        self.opens: Dict[str, Dict[str, Any]] = {}
        self.ka_after_open = set()
        self.established_t = None
        self.down_t = None
        self.down_reason = None
        self.last_msg_t: Dict[str, float] = {}
        self.max_gap: Dict[str, float] = {}
        self.over_hold: List[Dict[str, Any]] = []
        self.frames: List[int] = []

    def hold_time(self) -> Optional[int]:
        holds = [o["hold"] for o in self.opens.values() if o.get("hold") is not None]
        return min(holds) if len(holds) == 2 else None


class BgpAnalyzer:
    """Streaming BGP session analysis."""

    def __init__(self):
        self.connections: Dict[tuple, List[_BgpConnection]] = {}
        self.sessions: Dict[tuple, Dict[str, Any]] = {}
        self.messages = 0

    def _session(self, a, b):
        key = pair_key(a, b)
        sess = self.sessions.get(key)
        if sess is None:
            sess = {"speakers": {}, "notifications": [], "events": [], "established": 0, "downs": 0,
                    "connections": [], "first_t": None, "last_t": None, "over_gre": False}
            self.sessions[key] = sess
        return sess

    def _speaker(self, sess, ip):
        sp = sess["speakers"].get(ip)
        if sp is None:
            sp = {"as": None, "router_id": None, "hold_time": None, "messages": Counter(), "prefixes_announced": 0,
                  "prefixes_withdrawn": 0, "end_of_rib_t": None, "keepalive_gaps": [], "last_keepalive_t": None}
            sess["speakers"][ip] = sp
        return sp

    def feed(self, rec):
        tcp = rec.get("tcp")
        if not tcp or 179 not in (tcp["sport"], tcp["dport"]):
            return
        src, dst = rec["ip"]["src"], rec["ip"]["dst"]
        t, n, flags = rec["t"], rec["n"], tcp["flags"]
        sess = self._session(src, dst)
        sess["over_gre"] = sess["over_gre"] or bool(rec.get("tunneled"))
        if sess["first_t"] is None:
            sess["first_t"] = t
        sess["last_t"] = t
        ckey = tuple(sorted([(src, tcp["sport"]), (dst, tcp["dport"])]))
        conns = self.connections.setdefault(ckey, [])
        syn_only = flags & 0x02 and not flags & 0x10
        if not conns or (syn_only and (conns[-1].closed or conns[-1].established_t is not None)):
            conn = _BgpConnection(ckey, t)
            conns.append(conn)
            sess["connections"].append(conn)
        conn = conns[-1]
        add_frame(conn.frames, n)
        if syn_only:
            conn.syn_from = conn.syn_from or src
            conn.syn_count += 1
        elif flags & 0x02 and flags & 0x10:
            conn.synack = True
        if flags & 0x04:
            conn.rst_from = src
            self._close(sess, conn, t, n, f"TCP RST from {src}")
        if flags & 0x01:
            conn.fin_from.add(src)
            self._close(sess, conn, t, n, f"TCP FIN from {src}")
        messages = rec.get("bgp", [])
        for msg in messages:
            self.messages += 1
            self._feed_message(rec, sess, conn, src, dst, msg)
        if any(msg["type"] == 2 for msg in messages):
            # Prefix counts are per frame (tshark reports them that way), so add them once.
            sp = self._speaker(sess, src)
            sp["prefixes_announced"] += rec.get("bgp_nlri", 0)
            sp["prefixes_withdrawn"] += rec.get("bgp_withdrawn", 0)
            if rec.get("bgp_withdrawn"):
                sess["events"].append(("withdraw", t, n, f"{src} withdrew {rec['bgp_withdrawn']} prefix(es)"))

    def _close(self, sess, conn, t, n, reason):
        if conn.closed:
            return
        conn.closed = True
        if conn.established_t is not None and conn.down_t is None:
            conn.down_t = t
            conn.down_reason = conn.down_reason or reason
            sess["downs"] += 1
            sess["events"].append(("down", t, n, f"session down ({conn.down_reason})"))

    def _feed_message(self, rec, sess, conn, src, dst, msg):
        t, n = rec["t"], rec["n"]
        sp = self._speaker(sess, src)
        mtype = msg["type"]
        sp["messages"][BGP_TYPES.get(mtype, f"type_{mtype}")] += 1
        last = conn.last_msg_t.get(src)
        if last is not None:
            gap = t - last
            conn.max_gap[src] = max(conn.max_gap.get(src, 0.0), gap)
            hold = conn.hold_time()
            if conn.established_t is not None and hold and gap > hold:
                conn.over_hold.append({"speaker": src, "gap_s": round(gap, 3), "hold_time": hold, "frame": n, "t": t})
        conn.last_msg_t[src] = t
        if mtype == 1:
            asn = msg.get("as4") or msg.get("myas")
            conn.opens[src] = {"as": asn, "hold": msg.get("hold"), "router_id": msg.get("bgp_id")}
            sp["as"], sp["hold_time"], sp["router_id"] = asn, msg.get("hold"), msg.get("bgp_id")
            sess["events"].append(("open", t, n, f"OPEN from {src}: AS {asn}, hold {msg.get('hold')} s, "
                                                 f"router ID {msg.get('bgp_id')}"))
        elif mtype == 4:
            if sp["last_keepalive_t"] is not None:
                sp["keepalive_gaps"].append(t - sp["last_keepalive_t"])
            sp["last_keepalive_t"] = t
            if src in conn.opens:
                conn.ka_after_open.add(src)
            if (conn.established_t is None and len(conn.opens) == 2 and len(conn.ka_after_open) == 2
                    and not conn.closed):
                conn.established_t = t
                sess["established"] += 1
                hold = conn.hold_time()
                sess["events"].append(("established", t, n, f"session established (hold time {hold} s)"))
        elif mtype == 2:
            if msg.get("len") == 23:
                sp["end_of_rib_count"] = sp.get("end_of_rib_count", 0) + 1
                if sp["end_of_rib_t"] is None or conn.established_t and sp["end_of_rib_t"] < conn.established_t:
                    sp["end_of_rib_t"] = t
                sess["events"].append(("end_of_rib", t, n, f"End-of-RIB from {src} (initial routing table sent)"))
        elif mtype == 3:
            name = bgp_error_name(msg.get("major"), msg.get("minor"))
            note = {"from": src, "to": dst, "code": msg.get("major"), "subcode": msg.get("minor"), "name": name,
                    "hint": bgp_error_hint(msg.get("major"), msg.get("minor")), "frame": n, "t": t,
                    "while_established": conn.established_t is not None}
            sess["notifications"].append(note)
            conn.down_reason = f"NOTIFICATION from {src}: {name}"
            sess["events"].append(("notification", t, n, f"NOTIFICATION {src}->{dst}: {name}"))
            if conn.established_t is not None and conn.down_t is None:
                conn.down_t = t
                sess["downs"] += 1
                sess["events"].append(("down", t, n, f"session down ({conn.down_reason})"))

    def present(self) -> bool:
        return bool(self.sessions)

    def report(self, ctx: Context, issues, events) -> Dict[str, Any]:
        sessions_out = []
        for key, sess in sorted(self.sessions.items(), key=lambda kv: kv[1]["first_t"] or 0):
            label = f"{key[0]} <-> {key[1]}"
            conns = sess["connections"]
            last = conns[-1] if conns else None
            if sess["established"] and last and last.established_t is not None and last.down_t is None:
                state = "established"
            elif sess["established"]:
                state = "down"
            elif any(c.rst_from and not c.synack for c in conns):
                state = "tcp_refused"
            elif conns and all(c.syn_count and not c.synack and not c.rst_from for c in conns):
                state = "tcp_no_answer"
            elif sess["notifications"]:
                state = "open_rejected"
            else:
                state = "not_established"
            hold = next((c.hold_time() for c in reversed(conns) if c.hold_time() is not None), None)
            speakers = {}
            for ip, sp in sess["speakers"].items():
                speakers[ip] = {"as": sp["as"], "router_id": sp["router_id"], "hold_time_offered": sp["hold_time"],
                                "messages": dict(sp["messages"]), "prefixes_announced": sp["prefixes_announced"],
                                "prefixes_withdrawn": sp["prefixes_withdrawn"],
                                "end_of_rib_t": ctx.rel(sp["end_of_rib_t"]),
                                "keepalive_interval_s": round(median(sp["keepalive_gaps"]), 3) if sp["keepalive_gaps"] else None}
            ases = {sp["as"] for sp in sess["speakers"].values() if sp["as"] is not None}
            ibgp = len(ases) == 1 and len(sess["speakers"]) == 2

            for note in sess["notifications"]:
                major, minor = note["code"], note["subcode"]
                severity = "error"
                if (major, minor) == (6, 7):
                    severity = "info"
                elif major == 6 and minor in (2, 3, 4, 6):
                    severity = "warning"
                issues.append(make_issue(severity, "BGP_NOTIFICATION",
                                         f"{note['from']} sent NOTIFICATION to {note['to']}: {note['name']}"
                                         + (f" ({note['hint']})" if note["hint"] else ""), [note["frame"]],
                                         bgp_code=major, bgp_subcode=minor, name=note["name"]))
            for conn in conns:
                for gap in conn.over_hold:
                    issues.append(make_issue("warning", "BGP_HOLD_TIME_EXCEEDED",
                                             f"{gap['speaker']} sent nothing for {gap['gap_s']} s on {label}, longer than "
                                             f"the negotiated hold time of {gap['hold_time']} s", [gap["frame"]]))
            if state == "established" and ctx.end is not None and hold:
                for ip, t_last in last.last_msg_t.items():
                    silence = ctx.end - t_last
                    if silence > hold:
                        issues.append(make_issue("error", "BGP_PEER_SILENT",
                                                 f"{ip} has sent nothing for {round(silence, 1)} s on {label} "
                                                 f"(hold time {hold} s): the session will drop or already has",
                                                 last.frames[-3:]))
            if state == "tcp_refused":
                frames = [f for c in conns if c.rst_from for f in c.frames[:2]]
                issues.append(make_issue("error", "BGP_TCP_REFUSED",
                                         f"TCP 179 connection on {label} refused with RST: the peer has no neighbor "
                                         "configured for this source address, or BGP is not running there", frames))
                sess["events"].append(("refused", conns[0].first_t, conns[0].frames[0], "TCP 179 refused (RST)"))
            elif state == "tcp_no_answer":
                issues.append(make_issue("warning", "BGP_TCP_NO_ANSWER",
                                         f"TCP SYN to port 179 on {label} never answered: peer down, no route to it, "
                                         "or TCP 179 filtered", conns[0].frames[:3]))
            elif state == "down":
                issues.append(make_issue("error", "BGP_SESSION_DOWN",
                                         f"BGP session {label} was established and is down at the end of the capture "
                                         f"({last.down_reason if last else 'unknown reason'})",
                                         last.frames[-3:] if last else []))
            if sess["downs"] and sess["established"] > 1:
                issues.append(make_issue("warning", "BGP_SESSION_FLAP",
                                         f"BGP session {label} went down {sess['downs']} time(s) and was established "
                                         f"{sess['established']} time(s)", []))

            for kind, t, n, detail in sess["events"]:
                events.append(make_event(ctx, t, "bgp", kind, f"{label}: {detail}", n))

            sessions_out.append({
                "peers": list(key), "state": state, "ibgp": ibgp, "over_gre": sess["over_gre"],
                "negotiated_hold_time": hold,
                "speakers": speakers, "tcp_connections": len(conns), "times_established": sess["established"],
                "times_down": sess["downs"],
                "notifications": [{k: (ctx.rel(v) if k == "t" else v) for k, v in note.items()}
                                  for note in sess["notifications"]],
                "first_t": ctx.rel(sess["first_t"]), "last_t": ctx.rel(sess["last_t"]),
                "frames": conns[0].frames[:5] if conns else [],
            })
        listed, omitted = cap(sessions_out, ctx.max_items)
        return {"sessions": listed, "sessions_omitted": omitted, "messages": self.messages,
                "established_sessions": sum(1 for s in sessions_out if s["state"] == "established")}


# ---------------------------------------------------------------------------
# OSPF
# ---------------------------------------------------------------------------

class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


class OspfAnalyzer:
    """Streaming OSPFv2 analysis."""

    def __init__(self):
        self.routers: Dict[tuple, Dict[str, Any]] = {}
        self.exchange: Dict[tuple, Counter] = {}
        self.events: List[tuple] = []
        self.packets = 0

    def feed(self, rec):
        ospf = rec.get("ospf")
        if not ospf or "ip" not in rec:
            return
        self.packets += 1
        src, dst = rec["ip"]["src"], rec["ip"]["dst"]
        t, n = rec["t"], rec["n"]
        key = (ospf["rid"], src)
        router = self.routers.get(key)
        if router is None:
            router = {"rid": ospf["rid"], "address": src, "area": ospf["area"], "auth": ospf["auth"],
                      "mask": None, "hello": None, "dead": None, "prio": None, "options": None,
                      "dr": None, "bdr": None, "neighbors": None, "hellos": 0, "first_t": t, "last_t": t,
                      "last_hello_t": None, "max_hello_gap": 0.0, "gaps_over_dead": [], "mtu": None,
                      "types": Counter(), "frames": [], "ever_listed": set(), "over_gre": False}
            self.routers[key] = router
        router["over_gre"] = router["over_gre"] or bool(rec.get("tunneled"))
        router["types"][ospf["type"]] += 1
        router["last_t"] = t
        router["area"], router["auth"] = ospf["area"], ospf["auth"]
        add_frame(router["frames"], n)
        if ospf["type"] == 1:
            self._hello(router, ospf, t, n)
        else:
            if ospf["type"] == 2 and ospf.get("mtu") is not None:
                router["mtu"] = ospf["mtu"]
            self.exchange.setdefault((src, dst), Counter())[ospf["type"]] += 1

    def _hello(self, router, ospf, t, n):
        label = f"{router['rid']} ({router['address']})"
        if router["last_hello_t"] is not None:
            gap = t - router["last_hello_t"]
            router["max_hello_gap"] = max(router["max_hello_gap"], gap)
            dead = ospf.get("dead") or router["dead"]
            if dead and gap > dead:
                router["gaps_over_dead"].append({"from_t": router["last_hello_t"], "to_t": t, "gap_s": round(gap, 3),
                                                 "dead_interval": dead, "frame": n})
                self.events.append(("hello_gap", router["last_hello_t"], n,
                                    f"{label} sent no hello for {round(gap, 1)} s (dead interval {dead} s), "
                                    "neighbors drop it after the dead interval"))
                self.events.append(("hellos_resumed", t, n, f"{label} hellos resumed"))
        router["last_hello_t"] = t
        router["hellos"] += 1
        if router["dr"] is not None and (ospf["dr"], ospf["bdr"]) != (router["dr"], router["bdr"]):
            self.events.append(("dr_change", t, n, f"{label} now reports DR {ospf['dr']}, BDR {ospf['bdr']} "
                                                   f"(was DR {router['dr']}, BDR {router['bdr']})"))
        new_neighbors = set(ospf["neighbors"])
        if router["neighbors"] is not None:
            for nbr in sorted(new_neighbors - router["neighbors"]):
                self.events.append(("neighbor_up", t, n, f"{label} now lists neighbor {nbr}"))
            for nbr in sorted(router["neighbors"] - new_neighbors):
                self.events.append(("neighbor_down", t, n, f"{label} dropped neighbor {nbr} from its hellos"))
        elif new_neighbors:
            self.events.append(("neighbor_up", t, n, f"{label} lists neighbor(s) {', '.join(sorted(new_neighbors))}"))
        router["ever_listed"] |= new_neighbors
        for field in ("mask", "hello", "dead", "prio", "options", "dr", "bdr"):
            router[field] = ospf[field]
        router["neighbors"] = new_neighbors

    def present(self) -> bool:
        return bool(self.routers)

    def _links(self) -> List[List[tuple]]:
        uf = _UnionFind()
        nets = {}
        for key, router in self.routers.items():
            uf.find(key)
            if router["mask"]:
                try:
                    nets[key] = ipaddress.ip_network(f"{router['address']}/{router['mask']}", strict=False)
                except ValueError:
                    pass
        keys = list(self.routers)
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                addr_a = ipaddress.ip_address(self.routers[a]["address"])
                addr_b = ipaddress.ip_address(self.routers[b]["address"])
                if (a in nets and addr_b in nets[a]) or (b in nets and addr_a in nets[b]):
                    uf.union(a, b)
                elif (self.routers[a]["address"], self.routers[b]["address"]) in self.exchange or \
                        (self.routers[b]["address"], self.routers[a]["address"]) in self.exchange:
                    uf.union(a, b)
        groups: Dict[Any, List[tuple]] = {}
        for key in keys:
            groups.setdefault(uf.find(key), []).append(key)
        return list(groups.values())

    def report(self, ctx: Context, issues, events) -> Dict[str, Any]:
        links_out = []
        rid_addresses: Dict[str, set] = {}
        for router in self.routers.values():
            rid_addresses.setdefault(router["rid"], set()).add(router["address"])
        for rid, addresses in rid_addresses.items():
            if len(addresses) > 1:
                issues.append(make_issue("error", "OSPF_DUPLICATE_ROUTER_ID",
                                         f"router ID {rid} is used by {', '.join(sorted(addresses))}", []))

        for group in self._links():
            routers = [self.routers[k] for k in sorted(group, key=lambda k: k[1])]
            network = None
            for r in routers:
                if r["mask"]:
                    network = str(ipaddress.ip_network(f"{r['address']}/{r['mask']}", strict=False))
                    break
            mismatches = []
            checks = [("area", "area", "OSPF_AREA_MISMATCH", "area"),
                      ("hello", "hello_interval", "OSPF_HELLO_INTERVAL_MISMATCH", "hello interval"),
                      ("dead", "dead_interval", "OSPF_DEAD_INTERVAL_MISMATCH", "dead interval"),
                      ("mask", "network_mask", "OSPF_NETWORK_MASK_MISMATCH", "network mask"),
                      ("auth", "auth_type", "OSPF_AUTH_TYPE_MISMATCH", "authentication type")]
            for field, name, code, words in checks:
                values = {r["rid"]: r[field] for r in routers if r[field] is not None}
                if len(set(values.values())) > 1:
                    mismatches.append({"parameter": name, "values": values})
                    detail = ", ".join(f"{rid}={value}" for rid, value in values.items())
                    issues.append(make_issue("error", code, f"OSPF {words} mismatch on {network or 'link'}: {detail}; "
                                                            "these routers will not become neighbors",
                                             [f for r in routers for f in r["frames"][:2]], values=values))
            ebits = {r["rid"]: bool(r["options"] & 0x02) for r in routers if r["options"] is not None and r["hellos"]}
            if len(set(ebits.values())) > 1:
                mismatches.append({"parameter": "stub_area_flag", "values": {k: not v for k, v in ebits.items()}})
                issues.append(make_issue("error", "OSPF_STUB_FLAG_MISMATCH",
                                         f"OSPF E-bit (stub area flag) differs on {network or 'link'}: "
                                         + ", ".join(f"{rid} stub={not v}" for rid, v in ebits.items()), []))
            mtus = {r["rid"]: r["mtu"] for r in routers if r["mtu"] is not None}
            if len(set(mtus.values())) > 1:
                mismatches.append({"parameter": "interface_mtu", "values": mtus})
                issues.append(make_issue("error", "OSPF_MTU_MISMATCH",
                                         f"OSPF DB Description MTU differs on {network or 'link'}: "
                                         + ", ".join(f"{rid}={m}" for rid, m in mtus.items())
                                         + "; the adjacency sticks in EXSTART/EXCHANGE", []))

            adjacencies = []
            for i, a in enumerate(routers):
                for b in routers[i + 1:]:
                    a_lists_b = b["rid"] in a["ever_listed"]
                    b_lists_a = a["rid"] in b["ever_listed"]
                    exch = Counter()
                    exch.update(self.exchange.get((a["address"], b["address"]), Counter()))
                    exch.update(self.exchange.get((b["address"], a["address"]), Counter()))
                    if a_lists_b and b_lists_a:
                        state = "2-way_or_better"
                    elif a_lists_b or b_lists_a:
                        state = "one-way"
                        hearer, silent = (a, b) if a_lists_b else (b, a)
                        issues.append(make_issue(
                            "warning", "OSPF_ONE_WAY",
                            f"{hearer['rid']} hears {silent['rid']}, but {silent['rid']} never lists {hearer['rid']}: "
                            "stuck in INIT (one-way link, multicast filtered, or a parameter mismatch)", []))
                    else:
                        state = "none"
                        if not mismatches and a["hellos"] and b["hellos"]:
                            issues.append(make_issue(
                                "warning", "OSPF_NO_ADJACENCY",
                                f"{a['rid']} and {b['rid']} send hellos on the same link but never list each other", []))
                    adjacencies.append({"routers": [a["rid"], b["rid"]], "state_hint": state,
                                        "dbd_exchanged": exch[2] > 0, "lsa_exchange_seen": (exch[3] + exch[4] + exch[5]) > 0})

            routers_out = []
            for r in routers:
                label = f"{r['rid']} ({r['address']})"
                for gap in r["gaps_over_dead"]:
                    issues.append(make_issue("warning", "OSPF_HELLO_GAP",
                                             f"{label} sent no hello for {gap['gap_s']} s (dead interval "
                                             f"{gap['dead_interval']} s): its neighbors declared it down, then it returned",
                                             [gap["frame"]]))
                if ctx.end is not None and r["last_hello_t"] is not None and r["dead"]:
                    silence = ctx.end - r["last_hello_t"]
                    if silence > r["dead"]:
                        issues.append(make_issue("error", "OSPF_ROUTER_SILENT",
                                                 f"{label} sent its last hello {round(silence, 1)} s before the capture "
                                                 f"ended (dead interval {r['dead']} s): it is down or unreachable",
                                                 r["frames"][-2:]))
                        self.events.append(("router_silent", r["last_hello_t"], r["frames"][-1],
                                            f"{label} last hello; silent until capture end"))
                routers_out.append({
                    "router_id": r["rid"], "address": r["address"], "over_gre": r["over_gre"],
                    "area": r["area"], "network_mask": r["mask"],
                    "hello_interval": r["hello"], "dead_interval": r["dead"], "priority": r["prio"],
                    "auth_type": r["auth"], "dr": r["dr"], "bdr": r["bdr"],
                    "neighbors_listed": sorted(r["neighbors"] or []), "hellos": r["hellos"],
                    "max_hello_gap_s": round(r["max_hello_gap"], 3), "dbd_mtu": r["mtu"],
                    "packets_by_type": {str(k): v for k, v in r["types"].items()},
                    "first_t": ctx.rel(r["first_t"]), "last_hello_t": ctx.rel(r["last_hello_t"]),
                })
            drs = Counter(r["dr"] for r in routers if r["dr"] and r["dr"] != "0.0.0.0")
            links_out.append({"network": network, "routers": routers_out, "mismatches": mismatches,
                              "adjacencies": adjacencies, "dr": drs.most_common(1)[0][0] if drs else None})
        for kind, t, n, detail in self.events:
            events.append(make_event(ctx, t, "ospf", kind, detail, n))
        listed, omitted = cap(links_out, ctx.max_items)
        return {"links": listed, "links_omitted": omitted, "packets": self.packets, "routers": len(self.routers)}


# ---------------------------------------------------------------------------
# EIGRP
# ---------------------------------------------------------------------------

class EigrpAnalyzer:
    """Streaming EIGRP analysis."""

    def __init__(self):
        self.speakers: Dict[str, Dict[str, Any]] = {}
        self.unicast = set()
        self.events: List[tuple] = []
        self.packets = 0

    def feed(self, rec):
        eigrp = rec.get("eigrp")
        if not eigrp or "ip" not in rec:
            return
        self.packets += 1
        src, dst = rec["ip"]["src"], rec["ip"]["dst"]
        t, n = rec["t"], rec["n"]
        sp = self.speakers.get(src)
        if sp is None:
            sp = {"address": src, "as": eigrp["as"], "k": None, "hold": None, "hellos": 0, "first_t": t,
                  "last_t": None, "max_gap": 0.0, "gaps_over_hold": [], "goodbyes": [], "init_to": Counter(),
                  "opcodes": Counter(), "route_tlvs": 0, "frames": [], "over_gre": False}
            self.speakers[src] = sp
        sp["over_gre"] = sp["over_gre"] or bool(rec.get("tunneled"))
        label = src
        if sp["last_t"] is not None:
            gap = t - sp["last_t"]
            sp["max_gap"] = max(sp["max_gap"], gap)
            if sp["hold"] and gap > sp["hold"]:
                sp["gaps_over_hold"].append({"gap_s": round(gap, 3), "hold": sp["hold"], "frame": n, "t": t})
                self.events.append(("hold_expired", sp["last_t"] + sp["hold"], n,
                                    f"{label} silent for {round(gap, 1)} s (hold {sp['hold']} s): neighbors drop it"))
        sp["last_t"] = t
        sp["as"] = eigrp["as"]
        add_frame(sp["frames"], n)
        opcode = eigrp["opcode"]
        is_ack = opcode == 5 and eigrp["ack"] and not eigrp["tlvs"]
        sp["opcodes"]["Ack" if is_ack else EIGRP_OPCODES.get(opcode, f"opcode_{opcode}")] += 1
        if not dst.startswith("224.") and not dst.lower().startswith("ff0"):
            self.unicast.add(pair_key(src, dst))
        if eigrp["k"] is not None:
            if eigrp["k"] == [255] * 6:
                sp["goodbyes"].append({"t": t, "frame": n})
                self.events.append(("goodbye", t, n, f"{label} sent an EIGRP goodbye (neighbor shut down or removed)"))
            else:
                sp["k"] = eigrp["k"]
                sp["hold"] = eigrp["hold"]
        if 0x0007 in eigrp["tlvs"]:
            sp["goodbyes"].append({"t": t, "frame": n})
            self.events.append(("goodbye", t, n, f"{label} sent a peer termination TLV"))
        if opcode == 5 and not is_ack:
            sp["hellos"] += 1
        if opcode == 1 and eigrp["flags"] & 0x01:
            sp["init_to"][dst] += 1
            self.events.append(("adjacency_init", t, n, f"{label} sent INIT update to {dst} (adjacency starting)"))
        sp["route_tlvs"] += sum(1 for tlv in eigrp["tlvs"] if tlv in (0x0102, 0x0103, 0x0402, 0x0403, 0x0602, 0x0603))
        if opcode == 3:
            self.events.append(("query", t, n, f"{label} sent a Query (a route was lost and is being recomputed)"))
        elif opcode == 10:
            self.events.append(("sia_query", t, n, f"{label} sent an SIA-Query (route stuck in active)"))

    def present(self) -> bool:
        return bool(self.speakers)

    def _links(self) -> List[List[str]]:
        uf = _UnionFind()
        addresses = list(self.speakers)
        for addr in addresses:
            uf.find(addr)
        for a, b in self.unicast:
            if a in self.speakers and b in self.speakers:
                uf.union(a, b)
        for i, a in enumerate(addresses):
            for b in addresses[i + 1:]:
                try:
                    if ipaddress.ip_address(b) in ipaddress.ip_network(f"{a}/24", strict=False):
                        uf.union(a, b)
                except ValueError:
                    continue
        groups: Dict[str, List[str]] = {}
        for addr in addresses:
            groups.setdefault(uf.find(addr), []).append(addr)
        return list(groups.values())

    def report(self, ctx: Context, issues, events) -> Dict[str, Any]:
        links_out = []
        for group in self._links():
            speakers = [self.speakers[a] for a in sorted(group, key=lambda x: ipaddress.ip_address(x))]
            mismatches = []
            ases = {sp["address"]: sp["as"] for sp in speakers}
            if len(set(ases.values())) > 1:
                mismatches.append({"parameter": "as", "values": ases})
                issues.append(make_issue("error", "EIGRP_AS_MISMATCH",
                                         "EIGRP AS differs between speakers on one link: "
                                         + ", ".join(f"{a}=AS{v}" for a, v in ases.items())
                                         + "; they will not become neighbors", []))
            for asn in sorted(set(ases.values())):
                ks = {sp["address"]: sp["k"] for sp in speakers if sp["as"] == asn and sp["k"] is not None}
                distinct = {tuple(k) for k in ks.values()}
                if len(distinct) > 1:
                    common = Counter(tuple(k) for k in ks.values()).most_common(1)[0][0]
                    odd = [a for a, k in ks.items() if tuple(k) != common]
                    mismatches.append({"parameter": "k_values", "values": {a: k for a, k in ks.items()}})
                    issues.append(make_issue("error", "EIGRP_K_VALUE_MISMATCH",
                                             f"EIGRP K-values differ in AS {asn}: "
                                             + ", ".join(f"{a}={k}" for a, k in ks.items())
                                             + f"; {', '.join(odd)} cannot form adjacencies with the others", []))
            adjacencies = []
            for i, a in enumerate(speakers):
                for b in speakers[i + 1:]:
                    init_ab = a["init_to"].get(b["address"], 0)
                    init_ba = b["init_to"].get(a["address"], 0)
                    unicast = pair_key(a["address"], b["address"]) in self.unicast
                    adjacencies.append({"speakers": [a["address"], b["address"]],
                                        "init_exchanged": bool(init_ab and init_ba), "unicast_seen": unicast,
                                        "restarts": max(init_ab, init_ba) - 1 if (init_ab or init_ba) else 0})
                    if max(init_ab, init_ba) > 1:
                        issues.append(make_issue("warning", "EIGRP_ADJACENCY_RESTART",
                                                 f"EIGRP adjacency {a['address']} <-> {b['address']} restarted "
                                                 f"{max(init_ab, init_ba) - 1} time(s) (repeated INIT updates)", []))
            speakers_out = []
            for sp in speakers:
                for gb in sp["goodbyes"]:
                    issues.append(make_issue("warning", "EIGRP_GOODBYE",
                                             f"{sp['address']} sent an EIGRP goodbye: the neighbor was shut down, "
                                             "its configuration removed, or its interface is going down", [gb["frame"]]))
                for gap in sp["gaps_over_hold"]:
                    issues.append(make_issue("warning", "EIGRP_HOLD_TIME_EXPIRED",
                                             f"{sp['address']} sent nothing for {gap['gap_s']} s (hold time {gap['hold']} s): "
                                             "neighbors declared it down, then it returned", [gap["frame"]]))
                if ctx.end is not None and sp["hold"] and sp["last_t"] is not None:
                    silence = ctx.end - sp["last_t"]
                    if silence > sp["hold"]:
                        after_goodbye = bool(sp["goodbyes"]) and sp["goodbyes"][-1]["t"] >= sp["last_t"] - 0.001
                        if not after_goodbye:
                            issues.append(make_issue("error", "EIGRP_NEIGHBOR_SILENT",
                                                     f"{sp['address']} went silent {round(silence, 1)} s before the capture "
                                                     f"ended without a goodbye (hold time {sp['hold']} s): it failed or "
                                                     "became unreachable", sp["frames"][-2:]))
                            self.events.append(("neighbor_silent", sp["last_t"] + sp["hold"], sp["frames"][-1],
                                                f"{sp['address']} hold time expired (last packet at "
                                                f"{ctx.rel(sp['last_t'])} s); silent until capture end"))
                if sp["opcodes"].get("SIA-Query"):
                    issues.append(make_issue("warning", "EIGRP_STUCK_IN_ACTIVE",
                                             f"{sp['address']} sent {sp['opcodes']['SIA-Query']} SIA-Query message(s)", []))
                if sp["opcodes"].get("Query"):
                    issues.append(make_issue("info", "EIGRP_QUERIES",
                                             f"{sp['address']} sent {sp['opcodes']['Query']} Query message(s): "
                                             "routes were lost and recomputed", []))
                speakers_out.append({
                    "address": sp["address"], "over_gre": sp["over_gre"], "as": sp["as"], "k_values": sp["k"],
                    "hold_time": sp["hold"],
                    "hellos": sp["hellos"], "max_gap_s": round(sp["max_gap"], 3),
                    "goodbyes": len(sp["goodbyes"]), "messages": dict(sp["opcodes"]),
                    "init_updates_to": dict(sp["init_to"]), "route_tlvs": sp["route_tlvs"],
                    "first_t": ctx.rel(sp["first_t"]), "last_t": ctx.rel(sp["last_t"]),
                })
            links_out.append({"speakers": speakers_out, "mismatches": mismatches, "adjacencies": adjacencies})
        for kind, t, n, detail in self.events:
            events.append(make_event(ctx, t, "eigrp", kind, detail, n))
        listed, omitted = cap(links_out, ctx.max_items)
        return {"links": listed, "links_omitted": omitted, "packets": self.packets, "speakers": len(self.speakers)}


# ---------------------------------------------------------------------------
# Combined routing detector
# ---------------------------------------------------------------------------

class RoutingDetector:
    """BGP + OSPF + EIGRP, reported together with one failover timeline."""

    name = "routing"

    def __init__(self):
        self.bgp = BgpAnalyzer()
        self.ospf = OspfAnalyzer()
        self.eigrp = EigrpAnalyzer()

    def feed(self, rec):
        inner = rec.get("inner")
        if inner and ("tcp" in inner or "ospf" in inner or "eigrp" in inner):
            # A routing protocol carried inside GRE (for example EIGRP or BGP over a
            # DMVPN tunnel): analyze it on the tunnel (inner) addresses.
            view = dict(inner)
            view.update(n=rec["n"], t=rec["t"], len=rec["len"], tunneled=True,
                        ip={"v": 4, "src": inner["src"], "dst": inner["dst"], "proto": inner["proto"], "ttl": None})
            rec = view
        if "tcp" in rec:
            self.bgp.feed(rec)
        elif "ospf" in rec:
            self.ospf.feed(rec)
        elif "eigrp" in rec:
            self.eigrp.feed(rec)

    def present(self) -> bool:
        return self.bgp.present() or self.ospf.present() or self.eigrp.present()

    def report(self, ctx: Context) -> Dict[str, Any]:
        out: Dict[str, Any] = {"detector": self.name}
        all_issues: List[Dict[str, Any]] = []
        all_events: List[Dict[str, Any]] = []
        statuses = []
        verdicts = []
        for name, analyzer in (("bgp", self.bgp), ("ospf", self.ospf), ("eigrp", self.eigrp)):
            if not analyzer.present():
                out[name] = {"present": False}
                continue
            issues: List[Dict[str, Any]] = []
            events: List[Dict[str, Any]] = []
            section = analyzer.report(ctx, issues, events)
            status = status_from_issues(issues, True)
            section.update({"present": True, "status": status, "verdict": self._verdict(name, section, issues),
                            "issues": sort_issues(issues)})
            out[name] = section
            statuses.append(status)
            verdicts.append(section["verdict"])
            for issue in issues:
                issue = dict(issue)
                issue["protocol"] = name
                all_issues.append(issue)
            all_events.extend(events)
        all_events.sort(key=lambda e: (e["t"] if e["t"] is not None else 0))
        out["status"] = worst_status(statuses) if statuses else "not_present"
        out["verdict"] = " ".join(verdicts) if verdicts else "No BGP, OSPF or EIGRP in this capture."
        out["issues"] = sort_issues(all_issues)
        out["events"] = all_events
        out["failover_timeline"] = [e for e in all_events if e["event"] in FAILOVER_EVENTS][:ctx.max_items * 4]
        return out

    @staticmethod
    def _verdict(name: str, section: Dict[str, Any], issues) -> str:
        errors = [i for i in issues if i["severity"] == "error"]
        if name == "bgp":
            sessions = section["sessions"]
            up = sum(1 for s in sessions if s["state"] == "established")
            flaps = sum(s["times_down"] for s in sessions)
            text = f"BGP: {up} of {len(sessions)} session(s) established at capture end"
            if flaps:
                text += f", {flaps} session reset(s)"
        elif name == "ospf":
            adj = [a for link in section["links"] for a in link["adjacencies"]]
            two_way = sum(1 for a in adj if a["state_hint"] == "2-way_or_better")
            text = f"OSPF: {section['routers']} router(s), {two_way} of {len(adj)} adjacency pair(s) reached 2-Way or better"
        else:
            adj = [a for link in section["links"] for a in link["adjacencies"]]
            formed = sum(1 for a in adj if a["init_exchanged"])
            text = f"EIGRP: {section['speakers']} speaker(s), {formed} adjacency(ies) formed in the capture"
        if errors:
            codes = sorted({i["code"] for i in errors})
            text += f"; problems: {', '.join(codes)}"
        return text + "."


FAILOVER_EVENTS = {"established", "down", "notification", "refused", "end_of_rib", "withdraw",
                   "hello_gap", "hellos_resumed", "neighbor_up", "neighbor_down", "dr_change", "router_silent",
                   "goodbye", "hold_expired", "adjacency_init", "query", "sia_query", "neighbor_silent"}
