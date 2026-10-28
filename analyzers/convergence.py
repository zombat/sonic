#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Convergence Timeline Detector

Measures a failover from one capture: from an event (a time passed in, for
example when a runbook stopped a link) or, without one, from the first sign of
failure, to when routing reacted and traffic resumed, and says what drove it.

Signals, all from packets:
    failure   the last protected packet (ESP, IKE, NAT-T keepalive) from a peer before
              it went quiet for longer than twice its usual longest gap (or silence_s);
              the last BGP message from a speaker whose session then dropped; an IKEv2 liveness
              check (DPD) left unanswered; a BGP NOTIFICATION, RST or FIN; an
              ICMP echo outage starting
    detection DPD giving up (the last unanswered liveness transmission), a BGP
              Hold Timer Expired NOTIFICATION, or a hold expiry inferred from a
              peer's silence before the session closed; BFD Down
    reaction  the first BGP UPDATE or withdrawal on a session that does not
              involve the failed peer (the surviving path)
    resumed   an ICMP outage recovering; ESP on the surviving tunnels rising to
              carry the failed tunnel's rate (a heuristic on packet rates); or
              ESP from the failed peer returning

The driver is "bfd", "bgp_hold_timer", "dpd", "explicit_close" or
"undetermined", with the reason. On a transport-link capture of a protected
DMVPN, BGP travels inside ESP: only DPD, ESP rates and IKE are visible there,
and the driver is then inferred from timing against the hold time given.

Author: Raymond A Rizzo | Zombat
"""

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from analyzers.ipsec_vpn import IPsecDetector
from analyzers.network_common import Context, iso_time, make_event, make_issue, pair_key
from analyzers.reachability import ReachabilityDetector
from analyzers.routing_health import RoutingDetector

GAP_RECORD_S = 0.5           # gaps at least this long are kept per ESP direction
DEFAULT_SILENCE_S = 3.0      # floor for a stop; by default twice the direction's 95th percentile gap
SHIFT_WINDOW_S = 10          # seconds before the failure used as the rate baseline
SHIFT_FRACTION = 0.5         # surviving tunnels must add this share of the lost rate
RELATIVE_LIMIT = 1e9         # an event time below this is seconds from the first frame

CANNOT_SHOW = [
    "On a transport-link capture of a protected tunnel, BGP, NHRP and the user traffic travel inside ESP: "
    "routing reaction and traffic resumption are then inferred from ESP packet rates, not read from BGP.",
    "A liveness check (DPD) is recognised by size because its payload is encrypted.",
    "An event time from the runbook host and the capture's timestamps come from different clocks; "
    "a skew between them shifts every delta measured from the event.",
    "Only this capture point is seen: a failure elsewhere shows only through its effect on these links.",
]


def parse_event_time(value: Union[None, int, float, str], start: Optional[float]) -> Optional[float]:
    """
    Accept epoch seconds, seconds from the first frame (a number below 1e9 or "+12.5"),
    or an ISO-8601 timestamp, and return epoch seconds. Raises ValueError otherwise.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip()
        try:
            number = float(text)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(f"event_time {value!r} is not epoch seconds, seconds from the first frame, "
                                 "or an ISO-8601 time")
            if parsed.tzinfo is None:
                raise ValueError(f"event_time {value!r} has no time zone; add Z or an offset")
            return parsed.timestamp()
        if text.startswith("+"):
            return (start or 0.0) + number
    if number < RELATIVE_LIMIT:
        return (start or 0.0) + number
    return number


class _EspDirection:
    __slots__ = ("first_t", "first_n", "last_t", "last_n", "gaps", "buckets", "count", "sample")

    def __init__(self, t, n):
        self.first_t, self.first_n, self.last_t, self.last_n = t, n, t, n
        self.gaps: List[tuple] = []
        self.buckets = Counter()
        self.count = 0
        self.sample: List[float] = []

    def feed(self, t, n):
        gap = t - self.last_t
        if gap >= GAP_RECORD_S and len(self.gaps) < 20000:
            self.gaps.append((self.last_t, self.last_n, t, n))
        if self.count and len(self.sample) < 2000:
            self.sample.append(gap)
        self.last_t, self.last_n = t, n
        self.buckets[int(t)] += 1
        self.count += 1


class ConvergenceDetector:
    """Failover timeline across IPsec, BGP and ICMP. Feed records, then call report()."""

    name = "convergence"

    def __init__(self, event_time=None, failed_peer: Optional[str] = None, hold_time: Optional[float] = None,
                 silence_s: Optional[float] = None):
        self.event_time_raw = event_time
        self.failed_peer = failed_peer
        self.hold_time = hold_time
        self.silence_given = silence_s is not None
        self.silence_s = float(silence_s) if silence_s else DEFAULT_SILENCE_S
        self.ipsec = IPsecDetector()
        self.routing = RoutingDetector()
        self.reach = ReachabilityDetector()
        self.esp: Dict[tuple, _EspDirection] = {}
        self.start = None
        self.end = None

    def feed(self, rec: Dict[str, Any]):
        t = rec.get("t")
        if t:
            self.start = t if self.start is None or t < self.start else self.start
            self.end = t if self.end is None or t > self.end else self.end
        self.ipsec.feed(rec)
        self.routing.feed(rec)
        self.reach.feed(rec)
        if ("esp" in rec or "ike" in rec or rec.get("nat_keepalive")) and "ip" in rec:
            # Any protected traffic from a peer (ESP, IKE including DPD, NAT-T keepalives) shows it alive.
            key = (rec["ip"]["src"], rec["ip"]["dst"])
            direction = self.esp.get(key)
            if direction is None:
                direction = _EspDirection(t, rec["n"])
                direction.buckets[int(t)] += 1
                direction.count = 1
                self.esp[key] = direction
            else:
                direction.feed(t, rec["n"])

    def present(self) -> bool:
        return bool(self.esp) or self.routing.present() or self.reach.present() or bool(self.ipsec.sas)

    # -- helpers -----------------------------------------------------------

    def _threshold(self, direction: _EspDirection, liveness_interval: Optional[float]) -> float:
        """
        Silence that counts as a stop: silence_s when given; otherwise twice the direction's
        95th percentile gap, and at least 1.5 liveness (DPD) intervals when the pair runs
        periodic DPD, because a live but idle peer still answers DPD that often.
        """
        if self.silence_given:
            return self.silence_s
        limit = self.silence_s
        if len(direction.sample) >= 5:
            ordered = sorted(direction.sample)
            limit = max(limit, 2 * ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))])
        if liveness_interval:
            limit = max(limit, 1.5 * liveness_interval)
        return limit

    def _stops(self, liveness: Dict[tuple, float]) -> List[Dict[str, Any]]:
        """Every protected-traffic direction that went quiet: a long gap, or silence until the capture ended."""
        out = []
        for (src, dst), d in self.esp.items():
            limit = self._threshold(d, liveness.get(pair_key(src, dst)))
            for t_prev, n_prev, t_next, n_next in d.gaps:
                if t_next - t_prev >= limit:
                    out.append({"src": src, "dst": dst, "last_t": t_prev, "last_frame": n_prev,
                                "resumed_t": t_next, "resumed_frame": n_next, "silence_s": round(t_next - t_prev, 3)})
            if self.end is not None and self.end - d.last_t >= limit:
                out.append({"src": src, "dst": dst, "last_t": d.last_t, "last_frame": d.last_n, "resumed_t": None,
                            "resumed_frame": None, "silence_s": round(self.end - d.last_t, 3)})
        return sorted(out, key=lambda s: s["last_t"])

    def _one_sided(self, stop: Dict[str, Any]) -> bool:
        """
        True when the reverse direction kept sending through this direction's silence:
        it was not itself quiet from one second after the stop until the silence ended.
        """
        reverse = self.esp.get((stop["dst"], stop["src"]))
        if reverse is None:
            return False
        window_start = stop["last_t"] + 1.0
        window_end = (stop["resumed_t"] if stop["resumed_t"] is not None else (self.end or stop["last_t"])) - 0.5
        if window_end <= window_start:
            return False
        if reverse.last_t <= window_start or reverse.first_t >= window_end:
            return False
        for t_prev, _, t_next, _ in reverse.gaps:
            if t_prev <= window_start and t_next >= window_end:
                return False
        return True

    def _rate(self, pairs: List[tuple], start: int, end: int) -> float:
        if end <= start:
            return 0.0
        total = 0
        for key in pairs:
            d = self.esp.get(key)
            if d:
                total += sum(d.buckets.get(sec, 0) for sec in range(start, end))
        return total / (end - start)

    # -- reporting ---------------------------------------------------------

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        wide = Context(ctx.start, ctx.end, max_items=10 ** 6)
        ipsec = self.ipsec.report(wide)
        routing = self.routing.report(wide)
        reach = self.reach.report(wide)
        event_t = parse_event_time(self.event_time_raw, ctx.start)
        liveness: Dict[tuple, float] = {}
        for sa in ipsec.get("ike_sas", []):
            intervals = ((sa.get("negotiation") or {}).get("liveness") or {}).get("interval_s_by_sender") or {}
            values = [v for v in intervals.values() if v]
            if values and sa["initiator"] and sa["responder"]:
                key = pair_key(sa["initiator"], sa["responder"])
                liveness[key] = max(liveness.get(key, 0.0), max(values))
        stops = self._stops(liveness)
        for stop in stops:
            stop["one_sided"] = self._one_sided(stop)
        if event_t is None:
            # Without an event, a quiet period counts only when the other side kept sending into it:
            # an idle tunnel goes quiet both ways, a dead peer leaves the live side talking to nobody.
            stops = [stop for stop in stops if stop["one_sided"]]
        bgp_sessions = routing.get("bgp", {}).get("sessions", []) if routing.get("bgp", {}).get("present") else []

        # 1. Which peer failed.
        failed = self.failed_peer
        failed_source = "given" if failed else None
        after = [s for s in stops if event_t is None or s["last_t"] >= event_t - 1.0]
        if not failed and after:
            # The peer whose own ESP stopped first (at or after the event).
            failed = after[0]["src"]
            failed_source = "inferred: the first peer whose ESP stopped" + (" after the event" if event_t else "")
        if not failed:
            downs = [down for sess in bgp_sessions for down in sess["downs"]
                     if down.get("quietest_speaker") and
                     (event_t is None or (ctx.start or 0) + down["t"] >= event_t - 1.0)]
            # A hold-timer or BFD drop names the dead peer; a RST or FIN alone does not.
            dead = [d for d in downs if d["cause"] in ("hold_timer_expired", "hold_timer_expired_inferred", "bfd_down")]
            pick = min(dead or downs, key=lambda d: d["t"]) if (dead or downs) else None
            if pick:
                failed = pick["quietest_speaker"]
                failed_source = "inferred: the BGP speaker that went quiet before its session dropped"

        # 2. Signals.
        signals: List[Dict[str, Any]] = []

        def add(kind, t, frame, detail, phase, peer=None, **extra):
            if t is None:
                return
            signals.append(dict({"kind": kind, "t_abs": t, "frame": frame, "detail": detail, "phase": phase,
                                 "peer": peer}, **extra))

        for s in stops:
            if failed and failed not in (s["src"], s["dst"]):
                continue
            if s["src"] == failed or not failed:
                add("esp_stopped", s["last_t"], s["last_frame"],
                    f"last ESP {s['src']} -> {s['dst']} before {s['silence_s']} s of silence"
                    + ("" if s["resumed_t"] else " (until capture end)"), "failure", s["src"])
                if s["resumed_t"]:
                    add("esp_resumed", s["resumed_t"], s["resumed_frame"],
                        f"ESP {s['src']} -> {s['dst']} resumes", "recovery", s["src"])
            else:
                add("esp_towards_failed_stopped", s["last_t"], s["last_frame"],
                    f"{s['src']} stops sending ESP to {s['dst']} (its SA torn down, or no traffic routed there)",
                    "teardown", s["dst"])
        dpd_dead = None
        for sa in ipsec.get("ike_sas", []):
            neg = sa.get("negotiation") or {}
            for check in (neg.get("liveness") or {}).get("unanswered_checks", []):
                if failed and check["to"] != failed:
                    continue
                first_abs, last_abs = (ctx.start or 0) + check["first_t"], (ctx.start or 0) + check["last_t"]
                add("dpd_unanswered", first_abs, check["frame"],
                    f"liveness check (DPD) {check['from']} -> {check['to']} unanswered, "
                    f"{check['transmissions']} transmission(s)", "failure", check["to"])
                if check["transmissions"] >= 2:
                    add("dpd_gave_up", last_abs, check["frame"],
                        f"last DPD retransmission to {check['to']}; the SA is deleted after it", "detection",
                        check["to"])
                    if dpd_dead is None or last_abs < dpd_dead:
                        dpd_dead = last_abs
            for ex in sa.get("exchanges", []):
                if ex["exchange"] == "IKE_SA_INIT" and ex["t"] is not None:
                    peer = sa["responder"] if sa["initiator"] != failed else sa["initiator"]
                    add("ike_negotiation", (ctx.start or 0) + ex["t"], (ex["request_frames"] or [None])[0],
                        f"IKE_SA_INIT {sa['initiator']} -> {sa['responder']} ({sa['outcome']})", "reaction", peer)
        hold_seen = []
        bfd = []
        for sess in bgp_sessions:
            involves_failed = failed in sess["peers"] if failed else False
            for note in sess["notifications"]:
                t_abs = (ctx.start or 0) + note["t"]
                if note["code"] == 4:
                    add("bgp_hold_expired", t_abs, note["frame"],
                        f"NOTIFICATION Hold Timer Expired {note['from']} -> {note['to']}", "detection", note["to"])
                    hold_seen.append(t_abs)
                elif (note["code"], note["subcode"]) == (6, 10):
                    add("bfd_down", t_abs, note["frame"], f"NOTIFICATION Cease/BFD Down {note['from']}",
                        "detection", note["to"])
                    bfd.append(t_abs)
                else:
                    add("bgp_notification", t_abs, note["frame"],
                        f"NOTIFICATION {note['name']} {note['from']} -> {note['to']}", "failure", note["from"])
            for down in sess["downs"]:
                t_abs = (ctx.start or 0) + down["t"]
                if down.get("quietest_last_message_t") is not None and down["cause"] != "tcp_rst" \
                        and down["cause"] != "tcp_fin":
                    add("bgp_last_message", (ctx.start or 0) + down["quietest_last_message_t"],
                        down["quietest_last_message_frame"],
                        f"last BGP message from {down['quietest_speaker']} before its session dropped",
                        "failure", down["quietest_speaker"])
                add("bgp_down", t_abs, down["frame"], f"BGP {' <-> '.join(sess['peers'])} down: {down['explanation']}",
                    "detection", down.get("quietest_speaker"), cause=down["cause"])
                if down["cause"] == "hold_timer_expired_inferred":
                    hold_seen.append(t_abs)
            if involves_failed:
                continue
            internal = self.routing.bgp.sessions.get(tuple(sess["peers"]), {})
            for ip, sp in internal.get("speakers", {}).items():
                for up in sp.get("updates", []):
                    add("bgp_update", up["t"], up["frame"],
                        f"BGP UPDATE {ip} on {' <-> '.join(sess['peers'])}: {up['announced']} announced, "
                        f"{up['withdrawn']} withdrawn", "reaction", ip)
        for pair in reach.get("echo", []):
            for outage in pair.get("outages", []):
                add("icmp_outage", (ctx.start or 0) + outage["start_t"], outage["first_frame"],
                    f"ping {pair['src']} -> {pair['dst']}: {outage['lost_requests']} request(s) unanswered",
                    "failure", None)
                if outage.get("recovered_t") is not None:
                    add("icmp_recovered", (ctx.start or 0) + outage["recovered_t"], outage["next_reply_frame"],
                        f"ping {pair['src']} -> {pair['dst']} answered again", "recovery", None)

        failure_signals = sorted((s for s in signals if s["phase"] == "failure"
                                  and (event_t is None or s["t_abs"] >= event_t - 1.0)
                                  and (not failed or s["peer"] in (None, failed))), key=lambda s: s["t_abs"])
        first_sign = failure_signals[0] if failure_signals else None
        origin = event_t if event_t is not None else (first_sign["t_abs"] if first_sign else None)

        # 3. Traffic shift onto the surviving tunnels (ESP rates).
        shift = self._traffic_shift(failed, origin, ctx)
        if shift and shift.get("t_abs"):
            add("traffic_shift", shift["t_abs"], shift.get("frame"), shift["detail"], "recovery", None)

        def first_after(kinds, t0, about_failed=False):
            cands = [s for s in signals if s["kind"] in kinds and t0 is not None and s["t_abs"] >= t0
                     and (not about_failed or not failed or s["peer"] in (None, failed))]
            return min(cands, key=lambda s: s["t_abs"]) if cands else None

        detection = first_after({"dpd_gave_up", "bgp_hold_expired", "bfd_down", "bgp_down"}, origin, True)
        update = first_after({"bgp_update"}, origin)
        resumed = first_after({"icmp_recovered", "traffic_shift", "esp_resumed"}, origin, True)
        reaction_candidates = [s for s in (update, resumed) if s]
        reaction_t = min(s["t_abs"] for s in reaction_candidates) if reaction_candidates else None

        driver = self._driver(origin, reaction_t, dpd_dead, hold_seen, bfd, signals, bgp_sessions, failed)

        def delta(t):
            return round(t - origin, 3) if t is not None and origin is not None else None

        timeline = []
        for s in sorted(signals, key=lambda s: s["t_abs"]):
            if origin is not None and s["t_abs"] < origin - SHIFT_WINDOW_S:
                continue
            timeline.append({"t": ctx.rel(s["t_abs"]), "time": iso_time(s["t_abs"]), "delta_s": delta(s["t_abs"]),
                             "phase": s["phase"], "signal": s["kind"], "peer": s["peer"], "detail": s["detail"],
                             "frame": s["frame"]})
        if event_t is not None:
            timeline.append({"t": ctx.rel(event_t), "time": iso_time(event_t), "delta_s": 0.0, "phase": "event",
                             "signal": "event", "peer": failed, "detail": "event time given by the caller",
                             "frame": None})
        timeline.sort(key=lambda e: (e["t"] if e["t"] is not None else 0, e["phase"] != "event"))

        measurements = {
            "origin": "event_time" if event_t is not None else ("first_failure_sign" if first_sign else None),
            "origin_t": ctx.rel(origin),
            "first_failure_sign": self._brief(first_sign, ctx, delta),
            "detection": self._brief(detection, ctx, delta),
            "first_update_on_surviving_path": self._brief(update, ctx, delta),
            "traffic_resumed": self._brief(resumed, ctx, delta),
            "event_to_first_failure_sign_s": delta(first_sign["t_abs"]) if first_sign else None,
            "event_to_detection_s": delta(detection["t_abs"]) if detection else None,
            "event_to_first_update_s": delta(update["t_abs"]) if update else None,
            "event_to_traffic_resumed_s": delta(resumed["t_abs"]) if resumed else None,
        }
        present = self.present()
        if not present:
            verdict = "No ESP, IKE, BGP or ICMP in this capture: nothing to measure convergence from."
            status = "not_present"
        elif origin is None:
            verdict = ("No failure seen: no ESP direction went quiet, no DPD went unanswered, no BGP session "
                       "dropped and no ping outage" + (" after the event time" if event_t else ""))
            status = "ok"
        else:
            parts = [f"failed peer {failed or 'unknown'}"]
            if measurements["event_to_detection_s"] is not None:
                parts.append(f"detected after {measurements['event_to_detection_s']} s ({detection['kind']})")
            if measurements["event_to_first_update_s"] is not None:
                parts.append(f"first UPDATE on the surviving path after {measurements['event_to_first_update_s']} s")
            if measurements["event_to_traffic_resumed_s"] is not None:
                parts.append(f"traffic resumed after {measurements['event_to_traffic_resumed_s']} s "
                             f"({resumed['kind']})")
            else:
                parts.append("traffic not seen resuming before the capture ended")
            parts.append(f"driver: {driver['mechanism']}")
            verdict = ("Convergence from " + ("the event" if event_t is not None else "the first failure sign")
                       + ": " + "; ".join(parts))
            status = "ok" if resumed else "warning"
            if not resumed:
                issues.append(make_issue("warning", "CONVERGENCE_NOT_SEEN",
                                         "traffic was not seen resuming after the failure before the capture ended",
                                         [first_sign["frame"]] if first_sign and first_sign["frame"] else []))
        for entry in timeline:
            if entry["phase"] != "event":
                events.append(make_event(ctx, (ctx.start or 0) + entry["t"], "convergence", entry["signal"],
                                         entry["detail"], entry["frame"]))
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "event_time": iso_time(event_t),
            "event_t": ctx.rel(event_t),
            "failed_peer": failed,
            "failed_peer_source": failed_source,
            "driver": driver,
            "measurements": measurements,
            "traffic_shift": shift,
            "timeline": timeline[:ctx.max_items * 4],
            "timeline_omitted": max(len(timeline) - ctx.max_items * 4, 0),
            "cannot_show": CANNOT_SHOW,
            "issues": issues,
            "events": events,
        }

    @staticmethod
    def _brief(signal, ctx, delta):
        if not signal:
            return None
        return {"signal": signal["kind"], "t": ctx.rel(signal["t_abs"]), "delta_s": delta(signal["t_abs"]),
                "frame": signal["frame"], "detail": signal["detail"]}

    def _traffic_shift(self, failed, origin, ctx) -> Optional[Dict[str, Any]]:
        """Seconds after the failure until the surviving tunnels carry the failed tunnel's rate."""
        if not failed or origin is None:
            return None
        failed_pairs = [k for k in self.esp if failed in k]
        locals_ = {a if b == failed else b for a, b in failed_pairs}
        surviving = [k for k in self.esp if failed not in k and (k[0] in locals_ or k[1] in locals_)]
        if not failed_pairs or not surviving:
            return {"t_abs": None, "detail": "no surviving ESP tunnel from the same local router to compare",
                    "surviving_pairs": [list(k) for k in surviving]}
        start = int(origin)
        lost = self._rate(failed_pairs, start - SHIFT_WINDOW_S, start)
        base = self._rate(surviving, start - SHIFT_WINDOW_S, start)
        out = {"lost_rate_pps": round(lost, 2), "surviving_baseline_pps": round(base, 2),
               "surviving_pairs": [list(k) for k in surviving], "t_abs": None,
               "method": (f"first second after the failure in which the surviving tunnels carry their "
                          f"{SHIFT_WINDOW_S} s baseline plus {int(SHIFT_FRACTION * 100)}% of the failed tunnel's "
                          "rate, for two seconds running (heuristic on ESP packet rates)")}
        if lost < 1.0:
            out["detail"] = (f"the failed tunnel carried {round(lost, 2)} packets/s before the failure: too little "
                             "to measure a traffic shift from rates")
            return out
        need = base + SHIFT_FRACTION * lost
        last = int(self.end or start)
        for sec in range(start, last + 1):
            if self._rate(surviving, sec, sec + 1) >= need and self._rate(surviving, sec + 1, sec + 2) >= need:
                out["t_abs"] = float(sec)
                out["detail"] = (f"surviving tunnels {', '.join(' <-> '.join(k) for k in surviving)} reach "
                                 f"{round(self._rate(surviving, sec, sec + 1), 1)} packets/s (baseline {round(base, 1)}, "
                                 f"lost {round(lost, 1)}): traffic moved to the surviving path")
                out["frame"] = None
                return out
        out["detail"] = "the surviving tunnels never picked up the failed tunnel's rate before the capture ended"
        return out

    def _driver(self, origin, reaction_t, dpd_dead, hold_seen, bfd, signals, sessions, failed) -> Dict[str, Any]:
        if origin is None:
            return {"mechanism": "undetermined", "reason": "no failure seen"}
        before = (reaction_t if reaction_t is not None else float("inf")) + 1.0
        if any(origin - 1.0 <= t <= before for t in bfd):
            return {"mechanism": "bfd", "reason": "a BGP NOTIFICATION Cease/BFD Down preceded the reaction"}
        hold = [t for t in hold_seen if origin - 1.0 <= t <= before]
        dpd_ok = dpd_dead is not None and origin - 1.0 <= dpd_dead <= before
        if hold and (not dpd_ok or min(hold) <= dpd_dead):
            return {"mechanism": "bgp_hold_timer",
                    "reason": f"the BGP hold timer expired {round(min(hold) - origin, 3)} s after the start, before "
                              "any DPD gave up" if dpd_ok else
                              f"the BGP hold timer expired {round(min(hold) - origin, 3)} s after the start"}
        if dpd_ok:
            return {"mechanism": "dpd",
                    "reason": f"DPD gave up on the failed peer {round(dpd_dead - origin, 3)} s after the start, "
                              "before the routing reaction; no BGP hold expiry was seen first"}
        explicit = [s for s in signals if s["kind"] in ("bgp_notification", "bgp_down")
                    and s.get("cause") in (None, "notification", "tcp_rst", "tcp_fin") and s["t_abs"] >= origin - 1.0]
        if explicit:
            return {"mechanism": "explicit_close",
                    "reason": f"the session was closed explicitly ({explicit[0]['detail']})"}
        hold_time = self.hold_time or next((s["negotiated_hold_time"] for s in sessions
                                            if s.get("negotiated_hold_time")), None)
        if reaction_t is not None and hold_time:
            took = reaction_t - origin
            if 0.8 * hold_time <= took <= 1.25 * hold_time:
                return {"mechanism": "bgp_hold_timer",
                        "reason": f"inferred from timing: the reaction came {round(took, 3)} s after the start, "
                                  f"matching the {hold_time} s hold time, and no DPD gave up first"}
            return {"mechanism": "undetermined",
                    "reason": f"the reaction came {round(took, 3)} s after the start, which matches neither DPD "
                              f"(none seen giving up) nor the {hold_time} s hold time"}
        return {"mechanism": "undetermined",
                "reason": "no DPD, BFD or BGP hold expiry seen; pass hold_time to infer the hold timer from timing"}
