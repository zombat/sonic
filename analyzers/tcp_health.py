#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. TCP Health Detector

TcpHealthDetector (deterministic, per connection, from raw sequence numbers so
both extraction backends give the same answer):
    - handshake: SYN without SYN-ACK (and any ICMP error naming the connection),
      SYN answered by RST, SYN retransmissions, the MSS, window scale, SACK and
      timestamp options each side offered, and the handshake round trips seen
      from the capture point
    - retransmissions: a segment whose start was already seen. Fast (after two or
      more duplicate ACKs for it) or after a timeout, with the observed timeout
    - gaps: data that skipped ahead of what this capture point saw (lost before
      the capture point), and out-of-order arrivals filling a gap
    - duplicate ACK runs, zero-window periods (with duration), window-full events
      (bytes in flight reached the peer's advertised window), resets with who sent
      them and when
    - RTT samples (data to the ACK that covers it, retransmitted data excluded)
      and the RFC 6298 retransmission timeout those samples imply
    - one verdict per connection: no_answer, refused, receiver_buffer_exhausted,
      loss_on_path, receive_window_limited, reset, healthy, each backed by counts
      and frame numbers

Memory is bounded: MAX_CONNECTIONS connections, and per direction at most
MAX_SEEN_SEGMENTS remembered segment starts and MAX_RTT_PENDING unacknowledged
segments.

Author: Raymond A Rizzo | Zombat
"""

from collections import OrderedDict
from typing import Any, Dict, List, Optional

from analyzers.dataplane_common import endpoint, percentile, seq_delta, transport
from analyzers.network_common import (
    Context, add_frame, cap, icmp_describe, make_event, make_issue, median, sort_issues, status_from_issues,
)

MAX_CONNECTIONS = 20000
MAX_SEEN_SEGMENTS = 4096
MAX_RTT_PENDING = 1024
MAX_RTT_SAMPLES = 2000
SYN, RST, FIN, ACK = 0x02, 0x04, 0x01, 0x10

VERDICT_ORDER = ["no_answer", "refused", "receiver_buffer_exhausted", "loss_on_path", "receive_window_limited",
                 "reset", "healthy"]

LIMITS = [
    "Retransmissions, gaps and RTT are what this capture point saw: a segment lost after the capture point "
    "shows as a retransmission here, one lost before it shows as a gap. RTT is from the capture point to the "
    "receiver and back, not end to end unless the capture was taken on the sender.",
    "A connection whose handshake was not captured has no window scale, so window-full checks and options "
    "are skipped for it.",
    "Payload contents are not judged here (see the tls detector for TLS handshakes).",
]


def _direction(base: Optional[int]) -> Dict[str, Any]:
    return {"base": base, "max_end": 0, "acked": None, "mss": None, "ws": None, "sack": False, "ts": False,
            "segments": 0, "bytes": 0, "retrans": 0, "fast_retrans": 0, "timeout_retrans": 0, "rto_observed": [],
            "out_of_order": 0, "gaps": 0, "gap_bytes": 0, "seen": OrderedDict(), "pending": OrderedDict(),
            "rtt": [], "last_ack": None, "last_win": None, "dup_run": 0, "dupacks": 0, "dupack_runs": 0,
            "dupacks_for": {}, "win_scaled": None, "zero_window": 0, "zw_start": None, "zw_total": 0.0,
            "window_full": 0, "frames_retrans": [], "frames_zero": [], "frames_full": [], "frames_gap": [],
            "frames_dup": []}


class TcpHealthDetector:
    """Streaming per-connection TCP health."""

    name = "tcp"

    def __init__(self):
        self.conns: "OrderedDict[tuple, Dict[str, Any]]" = OrderedDict()
        self.dropped = 0
        self.icmp_refs: Dict[tuple, Dict[str, Any]] = {}

    @staticmethod
    def _key(a, b, tunneled):
        return (tunneled,) + tuple(sorted((a, b)))

    def feed(self, rec: Dict[str, Any]):
        icmp = rec.get("icmp")
        if icmp and icmp.get("orig") and icmp["orig"].get("proto") == 6:
            orig = icmp["orig"]
            ref = self.icmp_refs.setdefault((orig["src"], orig["dst"], orig.get("dport")), {
                "from": icmp["src"], "type": icmp["type"], "code": icmp["code"], "v6": icmp["v6"], "frames": []})
            add_frame(ref["frames"], rec["n"])
            return
        view = transport(rec)
        if view is None or not view["tcp"] or not view["dtcp"]:
            return
        tcp, dtcp = view["tcp"], view["dtcp"]
        src, dst = (view["src"], tcp["sport"]), (view["dst"], tcp["dport"])
        key = self._key(src, dst, view["tunneled"])
        conn = self.conns.get(key)
        if conn is None:
            if len(self.conns) >= MAX_CONNECTIONS:
                self.dropped += 1
                return
            conn = {"a": src, "b": dst, "tunneled": view["tunneled"], "client": None, "server": None,
                    "syn": None, "synack": None, "hs_ack_t": None, "dirs": {}, "rst": [], "fin": {},
                    "first_t": rec["t"], "last_t": rec["t"], "first_n": rec["n"], "packets": 0, "events": 0,
                    "spoke": set()}
            self.conns[key] = conn
        conn["packets"] += 1
        conn["last_t"] = rec["t"]
        self._segment(conn, rec, src, dst, tcp, dtcp)

    # -- per segment -------------------------------------------------------------

    def _segment(self, conn, rec, src, dst, tcp, dtcp):
        t, n, flags = rec["t"], rec["n"], tcp["flags"]
        seq, plen = dtcp["seq"], tcp["len"]
        out = conn["dirs"].get(src)
        if flags & SYN:
            if out is None or out["base"] is None or out["segments"] == 0:
                out = _direction(seq)
                conn["dirs"][src] = out
            out["mss"], out["ws"], out["sack"], out["ts"] = dtcp["mss"], dtcp["ws"], dtcp["sack"], dtcp["ts"]
            if not flags & ACK:
                conn["client"], conn["server"] = conn["client"] or src, conn["server"] or dst
                syn = conn["syn"]
                if syn is None:
                    conn["syn"] = {"count": 1, "first_t": t, "last_t": t, "frames": [n]}
                else:
                    syn["count"] += 1
                    syn["last_t"] = t
                    add_frame(syn["frames"], n)
            elif conn["synack"] is None:
                conn["synack"] = {"t": t, "n": n, "count": 1}
                conn["server"], conn["client"] = conn["server"] or src, conn["client"] or dst
            else:
                conn["synack"]["count"] += 1
        if out is None:
            out = _direction(seq - 1)  # mid-stream: treat the first byte seen as the start
            conn["dirs"][src] = out
        peer = conn["dirs"].get(dst)
        if not flags & RST:
            conn["spoke"].add(src)
        if flags & RST:
            conn["rst"].append({"from": src, "t": t, "n": n, "after_bytes": out["bytes"]})
        if flags & FIN and src not in conn["fin"]:
            conn["fin"][src] = t
        if flags & ACK and peer is not None:
            if conn["synack"] and conn["hs_ack_t"] is None and src == conn["client"] and not flags & SYN:
                conn["hs_ack_t"] = t
            self._ack(conn, rec, out, peer, dtcp, flags, plen)
        if not flags & (SYN | RST):
            self._window(conn, rec, out, peer, dtcp)
        if plen > 0:
            self._data(conn, rec, out, peer, seq, plen)
        elif flags & FIN:
            rel = seq_delta(seq, out["base"])
            out["max_end"] = max(out["max_end"], rel + 1)

    def _data(self, conn, rec, out, peer, seq, plen):
        t, n = rec["t"], rec["n"]
        rel = seq_delta(seq, out["base"])
        out["segments"] += 1
        out["bytes"] += plen
        if rel in out["seen"]:
            out["retrans"] += 1
            add_frame(out["frames_retrans"], n)
            last_t = out["seen"][rel]
            if out["dupacks_for"].get(rel, 0) >= 2:
                out["fast_retrans"] += 1
            else:
                out["timeout_retrans"] += 1
                if len(out["rto_observed"]) < 1000:
                    out["rto_observed"].append((t - last_t) * 1000.0)
            out["seen"][rel] = t
            out["pending"].pop(rel + plen, None)  # Karn: no RTT sample from retransmitted data
            if conn["events"] < 6 and out["retrans"] == 1:
                conn["events"] += 1
                conn.setdefault("event_list", []).append(("retransmission", t, n))
            return
        if rel < out["max_end"]:
            out["out_of_order"] += 1
        elif rel > out["max_end"] and out["segments"] > 1:
            out["gaps"] += 1
            out["gap_bytes"] += rel - out["max_end"]
            add_frame(out["frames_gap"], n)
        out["seen"][rel] = t
        if len(out["seen"]) > MAX_SEEN_SEGMENTS:
            out["seen"].popitem(last=False)
        out["pending"][rel + plen] = t
        if len(out["pending"]) > MAX_RTT_PENDING:
            out["pending"].popitem(last=False)
        out["max_end"] = max(out["max_end"], rel + plen)
        if peer is not None and peer["win_scaled"] is not None and out["acked"] is not None:
            in_flight = out["max_end"] - out["acked"]
            if peer["win_scaled"] > 0 and in_flight >= peer["win_scaled"]:
                out["window_full"] += 1
                add_frame(out["frames_full"], n)

    def _ack(self, conn, rec, out, peer, dtcp, flags, plen):
        if peer["base"] is None:
            return
        ack_rel = seq_delta(dtcp["ack"], peer["base"])
        sent_t = peer["pending"].get(ack_rel)
        if sent_t is not None and len(peer["rtt"]) < MAX_RTT_SAMPLES:
            peer["rtt"].append((rec["t"] - sent_t) * 1000.0)
        while peer["pending"]:
            first = next(iter(peer["pending"]))
            if first <= ack_rel:
                peer["pending"].popitem(last=False)
            else:
                break
        pure = plen == 0 and not flags & (SYN | FIN | RST)
        outstanding = ack_rel < peer["max_end"]
        if pure and outstanding and out["last_ack"] == dtcp["ack"] and out["last_win"] == dtcp["win"]:
            out["dupacks"] += 1
            out["dup_run"] += 1
            add_frame(out["frames_dup"], rec["n"])
            peer["dupacks_for"][ack_rel] = peer["dupacks_for"].get(ack_rel, 0) + 1
            if len(peer["dupacks_for"]) > MAX_RTT_PENDING:
                peer["dupacks_for"].pop(next(iter(peer["dupacks_for"])))
            if out["dup_run"] == 3:
                out["dupack_runs"] += 1
        else:
            out["dup_run"] = 0
        out["last_ack"], out["last_win"] = dtcp["ack"], dtcp["win"]
        if peer["acked"] is None or ack_rel > peer["acked"]:
            peer["acked"] = ack_rel

    def _window(self, conn, rec, out, peer, dtcp):
        win = dtcp["win"]
        scaled = None
        if peer is not None and out["ws"] is not None and peer["ws"] is not None:
            scaled = win << out["ws"]
        elif conn["syn"] is not None and conn["synack"] is not None:
            scaled = win  # both SYNs seen, no scaling negotiated
        out["win_scaled"] = scaled
        if win == 0:
            if out["zw_start"] is None:
                out["zw_start"] = rec["t"]
                out["zero_window"] += 1
                add_frame(out["frames_zero"], rec["n"])
                if conn["events"] < 6:
                    conn["events"] += 1
                    conn.setdefault("event_list", []).append(("zero_window", rec["t"], rec["n"]))
        elif out["zw_start"] is not None:
            out["zw_total"] += rec["t"] - out["zw_start"]
            out["zw_start"] = None

    # -- report ----------------------------------------------------------------------

    def present(self) -> bool:
        return bool(self.conns)

    def _rto(self, samples: List[float]) -> Dict[str, Any]:
        if not samples:
            return {"rtt_ms": None, "rfc6298_rto_ms": None}
        srtt, rttvar = samples[0], samples[0] / 2
        for r in samples[1:]:
            rttvar = 0.75 * rttvar + 0.25 * abs(srtt - r)
            srtt = 0.875 * srtt + 0.125 * r
        return {"rtt_ms": {"min": round(min(samples), 3), "median": round(median(samples), 3),
                           "p95": round(percentile(samples, 0.95), 3), "max": round(max(samples), 3),
                           "samples": len(samples)},
                "srtt_ms": round(srtt, 3),
                "rfc6298_rto_ms": round(max(1000.0, srtt + 4 * rttvar), 1),
                "linux_rto_ms": round(max(200.0, srtt + 4 * rttvar), 1)}

    def _summarize(self, ctx, conn, end_t):
        client, server = conn["client"] or conn["a"], conn["server"] or conn["b"]
        dirs = {}
        frames: List[int] = []
        conditions = []
        for ep in (client, server):
            d = conn["dirs"].get(ep)
            if d is None:
                continue
            zw_total = d["zw_total"] + ((end_t - d["zw_start"]) if d["zw_start"] is not None else 0.0)
            rto = self._rto(d["rtt"])
            dirs["client_to_server" if ep == client else "server_to_client"] = {
                "from": endpoint(*ep), "segments_with_data": d["segments"], "bytes": d["bytes"],
                "mss": d["mss"], "window_scale": d["ws"], "sack_permitted": d["sack"], "timestamps": d["ts"],
                "retransmissions": d["retrans"], "fast_retransmissions": d["fast_retrans"],
                "timeout_retransmissions": d["timeout_retrans"],
                "observed_retransmission_timeout_ms": ({"min": round(min(d["rto_observed"]), 1),
                                                        "median": round(median(d["rto_observed"]), 1),
                                                        "max": round(max(d["rto_observed"]), 1)}
                                                       if d["rto_observed"] else None),
                "gaps_before_capture_point": d["gaps"], "gap_bytes": d["gap_bytes"],
                "out_of_order": d["out_of_order"], "duplicate_acks_sent": d["dupacks"],
                "duplicate_ack_runs_of_3": d["dupack_runs"], "zero_window_advertisements": d["zero_window"],
                "zero_window_seconds": round(zw_total, 3), "zero_window_open_at_end": d["zw_start"] is not None,
                "window_full_events": d["window_full"], **rto,
                "frames": {"retransmissions": d["frames_retrans"], "gaps": d["frames_gap"],
                           "duplicate_acks": d["frames_dup"], "zero_window": d["frames_zero"],
                           "window_full": d["frames_full"]},
            }
        syn, synack = conn["syn"], conn["synack"]
        server_rst = [r for r in conn["rst"] if r["from"] == server]
        detail = ""
        if syn and not synack and server not in conn["spoke"]:
            if server_rst:
                verdict = "refused"
                detail = (f"{endpoint(*server)} answered the SYN with RST: nothing listening, or a firewall "
                          "rejecting the connection")
                frames = [syn["frames"][0], server_rst[0]["n"]]
            else:
                verdict = "no_answer"
                detail = (f"{syn['count']} SYN(s) from {endpoint(*client)}, no SYN-ACK seen at this capture point: "
                          "the server is down, a filter drops it silently, or the reply returns by another path")
                frames = syn["frames"]
                ref = self.icmp_refs.get((client[0], server[0], server[1]))
                if ref:
                    name, code_text = icmp_describe(ref["v6"], ref["type"], ref["code"])
                    detail += f"; {ref['from']} answered with ICMP {name} ({code_text})"
                    frames = frames + ref["frames"]
        else:
            zero = [(ep, d) for ep, d in conn["dirs"].items() if d["zero_window"]]
            loss = sum(d["retrans"] + d["gaps"] + d["dupack_runs"] for d in conn["dirs"].values())
            full = sum(d["window_full"] for d in conn["dirs"].values())
            if zero:
                ep, d = max(zero, key=lambda item: item[1]["zw_total"])
                verdict = "receiver_buffer_exhausted"
                total = d["zw_total"] + ((end_t - d["zw_start"]) if d["zw_start"] is not None else 0.0)
                detail = (f"the endpoint's receive buffer is exhausted: {endpoint(*ep)} advertised a zero window "
                          f"{d['zero_window']} time(s), {round(total, 3)} s in total"
                          + (", still closed at capture end" if d["zw_start"] is not None else "")
                          + "; the application is not reading fast enough, the network is not the bottleneck")
                frames = d["frames_zero"]
            elif loss:
                verdict = "loss_on_path"
                parts = []
                for name, d in dirs.items():
                    bits = []
                    if d["retransmissions"]:
                        text = (f"{d['retransmissions']} retransmission(s) ({d['fast_retransmissions']} fast, "
                                f"{d['timeout_retransmissions']} after timeout")
                        if d["observed_retransmission_timeout_ms"]:
                            text += f", timeout ~{d['observed_retransmission_timeout_ms']['median']} ms"
                        bits.append(text + ")")
                    if d["gaps_before_capture_point"]:
                        bits.append(f"{d['gaps_before_capture_point']} gap(s) lost before this capture point")
                    if bits:
                        parts.append(f"{d['from']} sent " + ", ".join(bits))
                        frames += d["frames"]["retransmissions"] + d["frames"]["gaps"]
                dup = sum(d["dupack_runs"] for d in conn["dirs"].values())
                detail = "loss on the path: " + "; ".join(parts)
                if dup:
                    detail += f"; {dup} run(s) of 3+ duplicate ACKs"
            elif full:
                verdict = "receive_window_limited"
                detail = (f"bytes in flight reached the receiver's advertised window {full} time(s): throughput is "
                          "capped by the receive window (raise the buffer or window scaling), not by loss")
                for d in conn["dirs"].values():
                    frames += d["frames_full"]
            elif conn["rst"]:
                verdict = "reset"
                rst = conn["rst"][0]
                detail = f"reset by {endpoint(*rst['from'])} after {rst['after_bytes']} byte(s) from it"
                frames = [rst["n"]]
            else:
                verdict = "healthy"
                detail = "no retransmissions, gaps, zero windows or resets seen"
            if syn and syn["count"] > 1:
                conditions.append(f"{syn['count'] - 1} SYN retransmission(s)")
            if syn and not synack:
                conditions.append("SYN-ACK not seen at this capture point although the server answered later "
                                  "(it took another path, or the capture missed it)")
        if conn["rst"] and verdict not in ("refused", "reset"):
            conditions.append(f"reset by {endpoint(*conn['rst'][0]['from'])}")
        handshake = None
        if syn:
            handshake = {"syn_frames": syn["frames"], "syn_count": syn["count"],
                         "synack_frame": synack["n"] if synack else None,
                         "capture_point_to_server_ms": round((synack["t"] - syn["last_t"]) * 1000, 3) if synack else None,
                         "capture_point_to_client_ms": (round((conn["hs_ack_t"] - synack["t"]) * 1000, 3)
                                                        if synack and conn["hs_ack_t"] else None)}
        return {
            "client": endpoint(*client), "server": endpoint(*server), "handshake_seen": bool(syn),
            "over_gre": conn["tunneled"], "verdict": verdict, "detail": detail, "other_conditions": conditions,
            "packets": conn["packets"], "first_t": ctx.rel(conn["first_t"]), "last_t": ctx.rel(conn["last_t"]),
            "handshake": handshake, "directions": dirs, "frames": sorted(set(frames))[:10],
        }

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        end_t = ctx.end if ctx.end is not None else 0.0
        conns = []
        for conn in self.conns.values():
            summary = self._summarize(ctx, conn, end_t)
            conns.append(summary)
            label = f"{summary['client']} -> {summary['server']}"
            if summary["verdict"] in ("no_answer", "refused") and conn["syn"]:
                events.append(make_event(ctx, conn["syn"]["first_t"], "tcp", summary["verdict"],
                                         f"{label}: {summary['detail']}", conn["syn"]["frames"][0]))
            for kind, t, n in conn.get("event_list", []):
                events.append(make_event(ctx, t, "tcp", kind, f"{label}: first {kind.replace('_', ' ')}", n))
            for rst in conn["rst"][:2]:
                events.append(make_event(ctx, rst["t"], "tcp", "rst", f"{label}: RST from {endpoint(*rst['from'])}",
                                         rst["n"]))
        conns.sort(key=lambda c: (VERDICT_ORDER.index(c["verdict"]), c["first_t"] or 0))
        counts = {v: sum(1 for c in conns if c["verdict"] == v) for v in VERDICT_ORDER}
        specs = {
            "no_answer": ("error", "TCP_NO_ANSWER", "SYN without SYN-ACK"),
            "refused": ("warning", "TCP_REFUSED", "SYN answered by RST"),
            "receiver_buffer_exhausted": ("warning", "TCP_ZERO_WINDOW", "receive buffer exhausted (zero window)"),
            "loss_on_path": ("warning", "TCP_LOSS", "loss on the path"),
            "receive_window_limited": ("info", "TCP_WINDOW_FULL", "limited by the receive window"),
            "reset": ("info", "TCP_RESET", "reset mid-connection"),
        }
        for verdict, (severity, code, title) in specs.items():
            hit = [c for c in conns if c["verdict"] == verdict]
            if not hit:
                continue
            sample = "; ".join(f"{c['client']} -> {c['server']}: {c['detail']}" for c in hit[:3])
            frames = [f for c in hit[:3] for f in c["frames"]]
            issues.append(make_issue(severity, code, f"{len(hit)} connection(s) {title}. {sample}", frames,
                                     connections=len(hit)))
        mss_values = sorted({d["mss"] for c in conns for d in c["directions"].values() if d["mss"]})
        clamped = [m for m in mss_values if m < 1460]
        if clamped:
            issues.append(make_issue("info", "TCP_MSS_BELOW_1460",
                                     f"MSS offered below 1460: {', '.join(map(str, clamped))} (a lower interface MTU, "
                                     "or ip tcp adjust-mss clamping for a tunnel)", []))
        present = self.present()
        status = status_from_issues(issues, present)
        if not present:
            verdict = "No TCP in this capture."
        else:
            bad = {v: n for v, n in counts.items() if n and v != "healthy"}
            verdict = (f"{len(conns)} TCP connection(s): " +
                       (", ".join(f"{n} {v.replace('_', ' ')}" for v, n in bad.items()) if bad else "all healthy")
                       + (f"; MSS offered {', '.join(map(str, mss_values))}" if mss_values else "") + ".")
        listed, omitted = cap(conns, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "summary": {"connections": len(conns), "by_verdict": counts, "mss_offered": mss_values,
                        "connections_dropped_at_cap": self.dropped},
            "connections": listed,
            "connections_omitted": omitted,
            "limits": LIMITS,
            "issues": sort_issues(issues),
            "events": events,
        }
