#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Merged Event Timeline

merge_timelines() runs every network detector over each of several captures
(analyze_network_capture, one read per capture), merges their notable events by
absolute timestamp into one timeline, and measures the time between chosen
events: for a chaos or failover run, how long from a link going down to routing
reconverging, and whether that is within the design threshold. The result can be
written to a JSON file so a run keeps it beside its captures.

A measurement names two events by selector:
    {"name": "bgp failover",
     "from": {"capture": "wan1", "detector": "routing", "event": "down"},
     "to":   {"event": "established", "contains": "10.255.0.2"},
     "max_s": 30}
Selector keys (all optional, all must match): capture (label), detector, protocol,
event, contains (substring of the detail), occurrence ("first", "last" or a
1-based number; default first). The "to" event is searched only after the "from"
event. Verdicts: within, exceeded, below_min, not_found.

Without measurements, automatic ones are reported: every ping outage window (its
duration), and each routing down-type event paired with the next up-type event.

Author: Raymond A Rizzo | Zombat
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from analyzers.network_common import iso_time
from analyzers.network_orchestrator import DETECTOR_NAMES, analyze_network_capture

SCHEMA = "sonic.merged_timeline/1"
DOWN_EVENTS = {"down", "neighbor_down", "notification", "hold_expired", "goodbye", "router_silent", "hello_gap",
               "outage", "no_answer", "rst", "pmtu_black_hole"}
UP_EVENTS = {"established", "neighbor_up", "adjacency_init", "eor"}
SELECTOR_KEYS = {"capture", "detector", "protocol", "event", "contains", "occurrence"}

LIMITS = [
    "Event times are packet timestamps at each capture point, to the millisecond; captures from different "
    "hosts are only as comparable as their clocks (use clock_offsets_s).",
    "Each capture's timeline is capped by the detectors (max_items x 8 events per capture); a very busy "
    "capture can lose late events, reported as timeline_omitted per capture.",
    "A measurement is the time between two packets as captured; protocol timers that run inside a router "
    "between packets are invisible.",
]


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


def _epoch(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _matches(event: Dict[str, Any], selector: Dict[str, Any]) -> bool:
    for key in ("capture", "detector", "protocol", "event"):
        if selector.get(key) is not None and event.get(key) != selector[key]:
            return False
    contains = selector.get("contains")
    if contains and str(contains).lower() not in (event.get("detail") or "").lower():
        return False
    return True


def _pick(events: List[Dict[str, Any]], selector: Dict[str, Any], after: Optional[float]) -> Optional[Dict[str, Any]]:
    hits = [e for e in events if _matches(e, selector) and (after is None or e["epoch"] >= after)]
    if not hits:
        return None
    occurrence = selector.get("occurrence", "first")
    if occurrence == "last":
        return hits[-1]
    if occurrence == "first" or occurrence is None:
        return hits[0]
    index = int(occurrence) - 1
    return hits[index] if 0 <= index < len(hits) else None


def _public(event: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if event is None:
        return None
    return {k: v for k, v in event.items() if k != "epoch"}


def _measure(events, spec) -> Dict[str, Any]:
    name = spec.get("name") or "measurement"
    start = _pick(events, spec.get("from") or {}, None)
    end = _pick(events, spec.get("to") or {}, start["epoch"] if start else None) if start else None
    out = {"name": name, "from": _public(start), "to": _public(end), "max_s": spec.get("max_s"),
           "min_s": spec.get("min_s"), "delta_s": None}
    if start is None or end is None:
        out["verdict"] = "not_found"
        out["detail"] = f"{name}: " + ("no event matches 'from'" if start is None else
                                       "no event matching 'to' after the 'from' event")
        return out
    delta = round(end["epoch"] - start["epoch"], 3)
    out["delta_s"] = delta
    if spec.get("max_s") is not None and delta > float(spec["max_s"]):
        out["verdict"] = "exceeded"
    elif spec.get("min_s") is not None and delta < float(spec["min_s"]):
        out["verdict"] = "below_min"
    else:
        out["verdict"] = "within"
    bound = f" (threshold {spec['max_s']} s)" if spec.get("max_s") is not None else ""
    out["detail"] = (f"{name}: {delta} s from {start['capture']} {start['event']} at t={start['t']} to "
                     f"{end['capture']} {end['event']} at t={end['t']}{bound}: {out['verdict']}")
    return out


def _auto(events, reports, labels, failover_max_s) -> List[Dict[str, Any]]:
    out = []
    for label, report in zip(labels, reports):
        for pair in (report.get("reachability") or {}).get("echo", []):
            for outage in pair.get("outages", []):
                item = {"name": f"ping outage {pair['src']} -> {pair['dst']} at {label}", "kind": "ping_outage",
                        "capture": label, "start_t_in_capture": outage["start_t"],
                        "delta_s": outage.get("duration_s"), "lost_requests": outage["lost_requests"],
                        "max_s": failover_max_s}
                if outage.get("duration_s") is None:
                    item["verdict"] = "not_recovered"
                elif failover_max_s is not None:
                    item["verdict"] = "exceeded" if outage["duration_s"] > failover_max_s else "within"
                else:
                    item["verdict"] = "measured"
                out.append(item)
    routing = [e for e in events if e["detector"] == "routing"]
    for i, down in enumerate(routing):
        if down["event"] not in DOWN_EVENTS:
            continue
        up = next((e for e in routing[i + 1:] if e["event"] in UP_EVENTS and e["protocol"] == down["protocol"]), None)
        item = {"name": f"{down['protocol']} {down['event']} at {down['capture']} to next {down['protocol']} up",
                "kind": "routing_convergence", "from": _public(down), "to": _public(up), "max_s": failover_max_s,
                "delta_s": round(up["epoch"] - down["epoch"], 3) if up else None}
        if up is None:
            item["verdict"] = "not_recovered"
        elif failover_max_s is not None:
            item["verdict"] = "exceeded" if item["delta_s"] > failover_max_s else "within"
        else:
            item["verdict"] = "measured"
        out.append(item)
    return out


def merge_timelines(captures: List[Dict[str, Any]], measurements: Optional[List[Dict[str, Any]]] = None,
                    detectors: Optional[List[str]] = None, failover_max_s: Optional[float] = None,
                    clock_offsets_s: Optional[Dict[str, float]] = None, max_events: int = 500,
                    output_path: Optional[str] = None, overwrite: bool = False, backend: str = "auto",
                    options: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Merge the detector timelines of several captures and measure between events (see module docstring)."""
    if not isinstance(captures, list) or not captures:
        return _error("captures needs one or more entries, each {\"path\": ..., \"label\": ...}")
    labels, paths = [], []
    for entry in captures:
        if not isinstance(entry, dict) or not entry.get("path"):
            return _error("each capture needs a \"path\" (and a \"label\")")
        label = str(entry.get("label") or os.path.basename(entry["path"]))
        if label in labels:
            return _error(f"duplicate capture label {label!r}")
        labels.append(label)
        paths.append(entry["path"])
    offsets = dict(clock_offsets_s or {})
    unknown = [k for k in offsets if k not in labels]
    if unknown:
        return _error(f"clock_offsets_s names unknown label(s): {unknown}", labels=labels)
    for spec in measurements or []:
        if not isinstance(spec, dict) or not isinstance(spec.get("from"), dict) or not isinstance(spec.get("to"), dict):
            return _error("each measurement needs \"from\" and \"to\" selectors (objects)")
        for side in ("from", "to"):
            bad = set(spec[side]) - SELECTOR_KEYS
            if bad:
                return _error(f"unknown selector key(s) {sorted(bad)} in measurement {spec.get('name')!r}",
                              valid_keys=sorted(SELECTOR_KEYS))
            if spec[side].get("capture") is not None and spec[side]["capture"] not in labels:
                return _error(f"measurement {spec.get('name')!r} names unknown capture {spec[side]['capture']!r}",
                              labels=labels)
    if output_path:
        if not output_path.endswith(".json"):
            return _error("output_path must end in .json")
        if os.path.exists(output_path) and not overwrite:
            return _error(f"output_path exists: {output_path} (pass overwrite=true to replace it)")
        parent = os.path.dirname(os.path.abspath(output_path))
        if not os.path.isdir(parent):
            return _error(f"output_path directory does not exist: {parent}")
    max_events = max(1, int(max_events or 500))

    reports, events, per_capture = [], [], []
    for label, path in zip(labels, paths):
        report = analyze_network_capture(path, detectors=detectors, include_sip=False, max_items=1000,
                                         backend=backend, options=options)
        if report.get("status") != "success":
            return _error(f"{label}: {report.get('error')}", capture=label)
        reports.append(report)
        offset = float(offsets.get(label, 0.0))
        for event in report["timeline"]:
            epoch = _epoch(event.get("time"))
            if epoch is None:
                continue
            events.append({"epoch": epoch + offset, "capture": label, "detector": event.get("detector"),
                           "protocol": event.get("protocol"), "event": event.get("event"),
                           "detail": event.get("detail"), "frame": event.get("frame")})
        per_capture.append({"label": label, "path": path, "packets": report["capture"]["packets"],
                            "start": report["capture"]["start"], "end": report["capture"]["end"],
                            "clock_offset_s": offset, "overall_status": report["overall_status"],
                            "events": sum(1 for e in events if e["capture"] == label),
                            "timeline_omitted": report.get("timeline_omitted", 0),
                            "verdicts": report.get("verdicts", {})})
    events.sort(key=lambda e: (e["epoch"], labels.index(e["capture"]), e.get("frame") or 0))
    starts = [_epoch(c["start"]) + c["clock_offset_s"] for c in per_capture if c["start"]]
    origin = min(starts) if starts else (events[0]["epoch"] if events else None)
    for event in events:
        event["t"] = round(event["epoch"] - origin, 3)
        event["time"] = iso_time(event["epoch"])

    measured = [_measure(events, spec) for spec in (measurements or [])]
    auto = _auto(events, reports, labels, failover_max_s) if not measurements else []
    failing = [m for m in measured + auto if m.get("verdict") in ("exceeded", "below_min", "not_found",
                                                                    "not_recovered")]
    if measured or auto:
        verdict = (f"{len(events)} event(s) from {len(labels)} capture(s); "
                   f"{len(measured) + len(auto)} measurement(s), "
                   + (f"{len(failing)} outside the threshold or not found" if failing else "all within threshold")
                   + ".")
    else:
        verdict = f"{len(events)} event(s) from {len(labels)} capture(s); nothing to measure."
    result = {
        "status": "success",
        "schema": SCHEMA,
        "verdict": verdict,
        "origin": iso_time(origin),
        "captures": per_capture,
        "measurements": measured,
        "auto_measurements": auto,
        "timeline": [_public(e) for e in events[:max_events]],
        "timeline_omitted": max(len(events) - max_events, 0),
        "detectors": list(detectors) if detectors else list(DETECTOR_NAMES),
        "limits": LIMITS,
    }
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=False)
            handle.write("\n")
        result["written_to"] = os.path.abspath(output_path)
    return result
