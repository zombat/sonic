#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. QoS Detector

QosDetector (deterministic, streaming):
    - DSCP per flow (source, destination, service) on the outer header, with ECN
      congestion-experienced marks counted
    - GRE: the inner (customer) DSCP against the outer (delivery) DSCP per tunnel,
      packet by packet: copied, rewritten, or lost (inner marked, outer 0)
    - ESP: the outer DSCP per SA. The inner header is encrypted, so one capture
      shows only whether the SA carries several markings (the router copies DSCP
      per packet) or one; correlate_captures with an inside capture compares the
      two sides packet by packet
    - RTP streams (found by content on any UDP port): packets, loss, duplicates,
      reordering, RFC 3550 interarrival jitter, the DSCP they carry, and a MOS from
      the existing E-model in analyzers/rtp_mos_analysis.py (latency left out: one
      capture point cannot measure one-way delay)

Author: Raymond A Rizzo | Zombat
"""

from collections import Counter
from typing import Any, Dict, List, Optional

from analyzers.dataplane_common import dscp_name, endpoint, transport
from analyzers.network_common import (
    SERVICE_NAMES, Context, add_frame, cap, make_event, make_issue, protocol_label, sort_issues, status_from_issues,
)

MAX_FLOWS = 5000
MAX_RTP_STREAMS = 2000
MIN_RTP_PACKETS = 10
STATIC_CLOCK = {0: 8000, 3: 8000, 4: 8000, 8: 8000, 9: 8000, 13: 8000, 18: 8000}
CLOCK_CHOICES = [8000, 16000, 32000, 44100, 48000, 90000]
AUDIO_PT = {0, 3, 4, 8, 9, 13, 18}

LIMITS = [
    "ESP hides the inner header: from one capture the inner DSCP of encrypted traffic is unknown, so 'copied' "
    "is inferred from several markings on one SA. Compare an inside and an outside capture with "
    "correlate_captures to see the rewrite directly.",
    "RTP latency is not measurable from one capture point; jitter and loss are what arrived here. RTP is found "
    "by its header shape, so a non-RTP UDP flow that looks like RTP for 10+ packets can be counted.",
    "Clock rate is 8000 Hz for static audio payload types and estimated from timestamps for dynamic ones.",
]


class _RtpStream:
    __slots__ = ("key", "ssrc", "pt", "first_t", "last_t", "packets", "first_seq", "max_ext", "cycles",
                 "last_seq", "recent", "dups", "ooo", "ones", "deltas", "warmup", "clock", "clock_source",
                 "jitter", "max_jitter", "jitter_sum", "jitter_n", "prev", "dscp", "frames", "tunneled", "bytes")

    def __init__(self, key, ssrc, pt, t, n, tunneled):
        self.key, self.ssrc, self.pt, self.tunneled = key, ssrc, pt, tunneled
        self.first_t = self.last_t = t
        self.packets = 0
        self.bytes = 0
        self.first_seq = self.last_seq = None
        self.max_ext = None
        self.cycles = 0
        self.recent = set()
        self.dups = self.ooo = self.ones = self.deltas = 0
        self.warmup: List[tuple] = []
        self.clock = STATIC_CLOCK.get(pt)
        self.clock_source = "static" if self.clock else None
        self.jitter = 0.0
        self.max_jitter = 0.0
        self.jitter_sum = 0.0
        self.jitter_n = 0
        self.prev = None
        self.dscp = Counter()
        self.frames: List[int] = []

    def add(self, t, n, seq, ts, dscp, size):
        self.packets += 1
        self.bytes += size
        self.last_t = t
        self.dscp[dscp] += 1
        add_frame(self.frames, n)
        if self.first_seq is None:
            self.first_seq = self.last_seq = seq
            self.max_ext = seq
        else:
            delta = (seq - self.last_seq) & 0xFFFF
            self.deltas += 1
            if delta == 1:
                self.ones += 1
            ext = self.cycles + seq
            if seq < (self.max_ext & 0xFFFF) and (self.max_ext & 0xFFFF) - seq > 0x8000:
                self.cycles += 0x10000
                ext = self.cycles + seq
            if ext in self.recent:
                self.dups += 1
                self.last_seq = seq
                return
            if ext < self.max_ext:
                self.ooo += 1
            self.max_ext = max(self.max_ext, ext)
            self.last_seq = seq
        self.recent.add(self.cycles + seq)
        if len(self.recent) > 1024:
            self.recent = {s for s in self.recent if s > self.max_ext - 512}
        if self.clock is None:
            self.warmup.append((t, ts))
            if len(self.warmup) >= 20:
                (t0, ts0), (t1, ts1) = self.warmup[0], self.warmup[-1]
                rate = ((ts1 - ts0) & 0xFFFFFFFF) / (t1 - t0) if t1 > t0 else 8000
                self.clock = min(CLOCK_CHOICES, key=lambda c: abs(c - rate))
                self.clock_source = "estimated"
                pending, self.warmup = self.warmup, []
                for wt, wts in pending:
                    self._jitter(wt, wts)
            return
        self._jitter(t, ts)

    def _jitter(self, t, ts):
        if self.prev is not None:
            pt, pts = self.prev
            d = (t - pt) - (((ts - pts + 0x80000000) & 0xFFFFFFFF) - 0x80000000) / self.clock
            self.jitter += (abs(d) - self.jitter) / 16.0
            self.max_jitter = max(self.max_jitter, self.jitter)
            self.jitter_sum += self.jitter
            self.jitter_n += 1
        self.prev = (t, ts)

    def finish(self):
        if self.clock is None and self.warmup:
            self.clock, self.clock_source = 8000, "assumed"
            pending, self.warmup = self.warmup, []
            for wt, wts in pending:
                self._jitter(wt, wts)


class QosDetector:
    """DSCP per flow, tunnel copy behaviour, RTP stream quality with DSCP."""

    name = "qos"

    def __init__(self):
        self.flows: Dict[tuple, Dict[str, Any]] = {}
        self.flows_dropped = 0
        self.gre: Dict[tuple, Dict[str, Any]] = {}
        self.esp: Dict[tuple, Dict[str, Any]] = {}
        self.rtp: Dict[tuple, _RtpStream] = {}
        self.not_rtp = set()
        self.ce = Counter()
        self.ce_frames: List[int] = []
        self.marked = False

    def feed(self, rec: Dict[str, Any]):
        ip = rec.get("ip")
        dp = rec.get("dp")
        if not ip or not dp:
            return
        dscp = dp["dscp"]
        if dscp:
            self.marked = True
        if dp["ecn"] == 3:
            self.ce[(ip["src"], ip["dst"])] += 1
            add_frame(self.ce_frames, rec["n"])
        label = protocol_label(rec)
        esp = rec.get("esp")
        key = (ip["src"], ip["dst"], label, esp["spi"] if esp else None)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= MAX_FLOWS:
                self.flows_dropped += 1
            else:
                flow = {"src": ip["src"], "dst": ip["dst"], "protocol": label, "dscp": Counter(), "packets": 0,
                        "frames": []}
                self.flows[key] = flow
        if flow is not None:
            flow["packets"] += 1
            flow["dscp"][dscp] += 1
            if dscp:
                add_frame(flow["frames"], rec["n"])
        if esp:
            sa = self.esp.setdefault((ip["src"], ip["dst"], esp["spi"]), {"dscp": Counter(), "frames": []})
            sa["dscp"][dscp] += 1
            if dscp:
                add_frame(sa["frames"], rec["n"])
        inner = dp.get("inner")
        if inner is not None:
            tunnel = self.gre.setdefault((ip["src"], ip["dst"]), {"pairs": Counter(), "frames": [], "lost_frames": []})
            tunnel["pairs"][(inner["dscp"], dscp)] += 1
            if inner["dscp"]:
                self.marked = True
            if inner["dscp"] != dscp:
                add_frame(tunnel["lost_frames"], rec["n"])
        view = transport(rec)
        if view and view["udp"] and dp.get("pl"):
            self._feed_rtp(rec, view, dp)

    def _feed_rtp(self, rec, view, dp):
        udp, payload = view["udp"], dp["pl"]
        sport, dport = udp["sport"], udp["dport"]
        if len(payload) < 12 or (payload[0] >> 6) != 2 or sport < 1024 or dport < 1024:
            return
        if sport in SERVICE_NAMES or dport in SERVICE_NAMES:
            return
        pt = payload[1] & 0x7F
        if 72 <= pt <= 76:
            return  # RTCP
        seq = int.from_bytes(payload[2:4], "big")
        ts = int.from_bytes(payload[4:8], "big")
        ssrc = int.from_bytes(payload[8:12], "big")
        key = (view["src"], sport, view["dst"], dport, ssrc)
        stream = self.rtp.get(key)
        if stream is None:
            if key in self.not_rtp or len(self.rtp) >= MAX_RTP_STREAMS:
                return
            stream = _RtpStream(key, ssrc, pt, rec["t"], rec["n"], view["tunneled"])
            self.rtp[key] = stream
        stream.add(rec["t"], rec["n"], seq, ts, view["dscp"], view["tl"] or 0)

    def present(self) -> bool:
        return bool(self.marked or self.esp or self.gre or self._rtp_streams() or self.ce)

    def _rtp_streams(self) -> List[_RtpStream]:
        return [s for s in self.rtp.values()
                if s.packets >= MIN_RTP_PACKETS and s.deltas and s.ones / s.deltas >= 0.5]

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        flows = []
        for flow in sorted(self.flows.values(), key=lambda f: -f["packets"]):
            if len(flow["dscp"]) == 1 and 0 in flow["dscp"]:
                continue
            flows.append({"src": flow["src"], "dst": flow["dst"], "protocol": flow["protocol"],
                          "packets": flow["packets"],
                          "dscp": {dscp_name(d): c for d, c in sorted(flow["dscp"].items())}, "frames": flow["frames"]})
        unmarked = sum(1 for f in self.flows.values() if set(f["dscp"]) == {0})

        tunnels = []
        for (src, dst), tunnel in self.gre.items():
            total = sum(tunnel["pairs"].values())
            copied = sum(c for (i, o), c in tunnel["pairs"].items() if i == o)
            lost = sum(c for (i, o), c in tunnel["pairs"].items() if i and not o)
            rewritten = total - copied - lost
            item = {"outer_src": src, "outer_dst": dst, "packets_with_inner_ipv4": total, "copied": copied,
                    "inner_marked_outer_zero": lost, "rewritten": rewritten,
                    "pairs": [{"inner": dscp_name(i), "outer": dscp_name(o), "packets": c}
                              for (i, o), c in tunnel["pairs"].most_common(10)],
                    "frames": tunnel["lost_frames"]}
            tunnels.append(item)
            if lost:
                issues.append(make_issue("warning", "QOS_GRE_DSCP_NOT_COPIED",
                                         f"GRE {src} -> {dst}: {lost} packet(s) marked inside but DSCP 0 on the "
                                         "delivery header: WAN QoS cannot see the class (check tunnel tos / "
                                         "qos pre-classify)", tunnel["lost_frames"]))
            elif rewritten:
                issues.append(make_issue("info", "QOS_GRE_DSCP_REWRITTEN",
                                         f"GRE {src} -> {dst}: {rewritten} packet(s) carry a different DSCP outside "
                                         "than inside", tunnel["lost_frames"]))

        sas = []
        for (src, dst, spi), sa in self.esp.items():
            values = sorted(sa["dscp"])
            if len(values) > 1:
                reading = "several markings on one SA: DSCP is copied from the inner header per packet"
            elif values == [0]:
                reading = ("every packet DSCP 0: either the inner traffic was unmarked or the router does not copy "
                           "DSCP into ESP; an inside capture tells which")
            else:
                reading = (f"every packet {dscp_name(values[0])}: one class inside, or a fixed outer marking "
                           "(cannot tell from one capture)")
            sas.append({"src": src, "dst": dst, "spi": f"0x{spi:08x}" if isinstance(spi, int) else spi,
                        "dscp": {dscp_name(d): c for d, c in sorted(sa["dscp"].items())}, "reading": reading,
                        "frames": sa["frames"]})

        streams = []
        try:
            from analyzers.rtp_mos_analysis import AdvancedRTPMOSAnalyzer, RTPStreamMetrics
            scorer = AdvancedRTPMOSAnalyzer()
        except Exception:  # pragma: no cover - the module ships with S.O.N.I.C.
            scorer = None
        for stream in sorted(self._rtp_streams(), key=lambda s: s.first_t):
            stream.finish()
            expected = stream.max_ext - stream.first_seq + 1 if stream.max_ext is not None else 0
            received = stream.packets - stream.dups
            lost = max(expected - received, 0)
            loss_pct = round(100.0 * lost / expected, 2) if expected else 0.0
            jitter_ms = round(stream.jitter * 1000, 3)
            mean_jitter_ms = round(stream.jitter_sum / stream.jitter_n * 1000, 3) if stream.jitter_n else 0.0
            codec = scorer._map_payload_to_codec(stream.pt) if scorer else "Unknown"
            mos = None
            if scorer:
                metrics = RTPStreamMetrics(ssrc=f"0x{stream.ssrc:08x}", packets_sent=expected,
                                           packets_received=received, packets_lost=lost, packet_loss_rate=loss_pct,
                                           avg_jitter=mean_jitter_ms, max_jitter=round(stream.max_jitter * 1000, 3),
                                           codec=codec, payload_type=str(stream.pt))
                mos = round(scorer._calculate_emodel_mos(metrics), 2)
            src, sport, dst, dport, _ = stream.key
            dscps = sorted(stream.dscp)
            item = {"src": endpoint(src, sport), "dst": endpoint(dst, dport), "ssrc": f"0x{stream.ssrc:08x}",
                    "payload_type": stream.pt, "codec": codec, "clock_rate": stream.clock,
                    "clock_rate_source": stream.clock_source, "packets": stream.packets, "expected": expected,
                    "lost": lost, "loss_percent": loss_pct, "duplicates": stream.dups, "out_of_order": stream.ooo,
                    "jitter_ms": {"final": jitter_ms, "mean": mean_jitter_ms,
                                  "max": round(stream.max_jitter * 1000, 3)},
                    "duration_s": round(stream.last_t - stream.first_t, 3),
                    "dscp": {dscp_name(d): c for d, c in sorted(stream.dscp.items())},
                    "mos_estimate": mos, "latency": "not measurable from one capture point",
                    "over_gre": stream.tunneled, "first_t": ctx.rel(stream.first_t), "frames": stream.frames}
            streams.append(item)
            label = f"RTP {item['src']} -> {item['dst']} SSRC {item['ssrc']}"
            if dscps != [46] and stream.pt in AUDIO_PT:
                issues.append(make_issue("warning", "QOS_RTP_NOT_EF",
                                         f"{label} ({codec}) carries {', '.join(dscp_name(d) for d in dscps)}, "
                                         "not EF (46): voice will queue with best effort", stream.frames))
            elif 46 not in dscps and not dscps == [34]:
                issues.append(make_issue("info", "QOS_RTP_UNMARKED",
                                         f"{label} (PT {stream.pt}) carries {', '.join(dscp_name(d) for d in dscps)}",
                                         stream.frames))
            if loss_pct > 1.0:
                issues.append(make_issue("error" if loss_pct > 5 else "warning", "QOS_RTP_LOSS",
                                         f"{label}: {lost} of {expected} packets lost ({loss_pct}%)", stream.frames))
                events.append(make_event(ctx, stream.first_t, "rtp", "loss",
                                         f"{label}: {loss_pct}% loss", stream.frames[0]))
            if mean_jitter_ms > 30:
                issues.append(make_issue("warning", "QOS_RTP_JITTER",
                                         f"{label}: mean jitter {mean_jitter_ms} ms (max {item['jitter_ms']['max']})",
                                         stream.frames))
        if self.ce:
            total = sum(self.ce.values())
            issues.append(make_issue("info", "QOS_ECN_CE",
                                     f"{total} packet(s) marked ECN Congestion Experienced: a queue on the path was "
                                     "congested", self.ce_frames))
        present = self.present()
        status = status_from_issues(issues, present)
        if not present:
            verdict = "No DSCP marking, tunnel, ESP or RTP to judge."
        else:
            parts = []
            if flows:
                parts.append(f"{len(flows)} marked flow(s), {unmarked} unmarked")
            if tunnels:
                lost = sum(t["inner_marked_outer_zero"] for t in tunnels)
                parts.append(f"GRE: {lost} packet(s) lose their marking" if lost else "GRE copies DSCP to the outer header")
            if sas:
                copied = sum(1 for s in sas if "copied" in s["reading"])
                parts.append(f"ESP: {copied} of {len(sas)} SA(s) show DSCP copied per packet")
            if streams:
                worst = min((s["mos_estimate"] for s in streams if s["mos_estimate"] is not None), default=None)
                parts.append(f"{len(streams)} RTP stream(s)" + (f", worst MOS estimate {worst}" if worst else ""))
            verdict = "; ".join(parts) + "."
        flows_list, flows_omitted = cap(flows, ctx.max_items)
        sas_list, sas_omitted = cap(sas, ctx.max_items)
        streams_list, streams_omitted = cap(streams, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "summary": {"marked_flows": len(flows), "unmarked_flows": unmarked, "gre_tunnels": len(tunnels),
                        "esp_sas": len(sas), "rtp_streams": len(streams), "ecn_ce_packets": sum(self.ce.values()),
                        "flows_dropped_at_cap": self.flows_dropped},
            "marked_flows": flows_list,
            "marked_flows_omitted": flows_omitted,
            "gre_tunnels": tunnels[:ctx.max_items],
            "esp_sas": sas_list,
            "esp_sas_omitted": sas_omitted,
            "rtp_streams": streams_list,
            "rtp_streams_omitted": streams_omitted,
            "limits": LIMITS,
            "issues": sort_issues(issues),
            "events": events,
        }
