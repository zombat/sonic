#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Network Analysis Orchestrator

One entry point for the non-SIP detectors. It reads the capture once (tshark
first, scapy fallback, see extractors/network.py), feeds every frame to each
selected detector, and returns one combined, JSON-serializable report. Detectors
that found nothing to look at are listed as not present rather than failing, so
the same call works on any capture: the report says which protocols were there.

Detectors (run by default):
    ipsec          IKEv1/IKEv2 (proposals, DH groups, NAT detection, DPD, a diagnosis
                   per SA), ESP (sequence, stale SPIs), NAT-T, and the encrypted/cleartext verdict
    gre_nhrp       GRE tunnels and NHRP (DMVPN registration, resolution, redirect)
    dmvpn_phase3   the Phase 3 shortcut sequence per flow, thrashing, encrypted shortcuts
    routing        BGP (OPEN, MSS, down cause), OSPF (incl. stuck EXSTART/EXCHANGE)
                   and EIGRP health with a failover timeline
    reachability   ICMP echo loss/RTT/outages, ICMP errors, ARP without replies
    conversations  protocols, top conversations and top talkers
Detectors run only when named:
    cleartext_audit  zero-cleartext assertion against an allowlist (pass/fail)
    convergence      failover timeline from an event or the first failure sign

When SIP is present the existing SIP quality path (CallQualityScorer and the
RTP MOS analyzer, the same functions quick_quality_check uses) runs unchanged and
its result is attached under "sip".

No LLM is involved: every finding comes from the packets.

Author: Raymond A Rizzo | Zombat
"""

import contextlib
import dataclasses
import enum
import ipaddress
import os
import sys
from typing import Any, Dict, List, Optional

from analyzers.cleartext_audit import CleartextAuditDetector
from analyzers.convergence import ConvergenceDetector
from analyzers.dmvpn_phase3 import DmvpnPhase3Detector
from analyzers.gre_nhrp import GreNhrpDetector
from analyzers.ipsec_vpn import IPsecDetector
from analyzers.network_common import Context, SEVERITY_ORDER, iso_time, worst_status
from analyzers.reachability import ConversationDetector, ReachabilityDetector
from analyzers.routing_health import RoutingDetector
from extractors.network import open_network_records

REPORT_SCHEMA = "sonic.network_report/1"
# Run by default: each one reports not_present when its protocols are absent.
DETECTOR_NAMES = ["ipsec", "gre_nhrp", "dmvpn_phase3", "routing", "reachability", "conversations"]
# Run only when asked for: an assertion and a measurement that need the caller's intent.
OPTIONAL_DETECTORS = ["cleartext_audit", "convergence"]
ALL_DETECTORS = DETECTOR_NAMES + OPTIONAL_DETECTORS
VPN_DETECTORS = ["ipsec", "gre_nhrp", "dmvpn_phase3"]
ROUTING_DETECTORS = ["routing", "reachability"]
OPTION_NAMES = {"allow", "hubs", "expected_mss", "event_time", "failed_peer", "hold_time", "silence_s"}


def _family(rec: Dict[str, Any], families: set):
    """Record which protocol families a frame carries (for protocols_present)."""
    inner = rec.get("inner")
    if inner:
        _family(inner, families)  # protocols carried inside GRE count too
    for key, name in (("ike", "ike"), ("esp", "esp"), ("gre", "gre"), ("nhrp", "nhrp"), ("bgp", "bgp"),
                      ("ospf", "ospf"), ("eigrp", "eigrp"), ("arp", "arp"), ("sip", "sip")):
        if key in rec:
            families.add(name)
    if rec.get("nat_keepalive") or ("esp" in rec and rec["esp"].get("udp")) or ("ike" in rec and rec["ike"].get("natt")):
        families.add("nat-t")
    if "icmp" in rec:
        families.add("icmpv6" if rec["icmp"]["v6"] else "icmp")
    if "tcp" in rec:
        families.add("tcp")
    if "udp" in rec:
        families.add("udp")
    ip = rec.get("ip")
    if ip and ip.get("v") == 6:
        families.add("ipv6")


def to_jsonable(value: Any) -> Any:
    """Convert dataclasses, enums, sets and objects into plain JSON types."""
    if isinstance(value, enum.Enum):
        return to_jsonable(value.value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, set):
        return sorted(to_jsonable(v) for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "__dict__"):
        return {k: to_jsonable(v) for k, v in vars(value).items() if not k.startswith("_")}
    return str(value)


def _sip_quality(file_path: str) -> Dict[str, Any]:
    """
    Run the existing SIP quality path (as quick_quality_check does) and return it as JSON.

    The SIP modules print progress to stdout; that is redirected to stderr here so an
    MCP stdio transport, which owns stdout, is never corrupted.
    """
    result: Dict[str, Any] = {"present": True}
    with contextlib.redirect_stdout(sys.stderr):
        try:
            from extractors.tshark import extract_sip_data
            from extractors.auth_info import extract_auth_and_registration_info
            from analyzers.call_quality_scoring import CallQualityScorer
            from analyzers.rtp_mos_analysis import AdvancedRTPMOSAnalyzer
        except Exception as exc:  # pragma: no cover - import failure is environment-specific
            result["error"] = f"SIP modules unavailable: {exc}"
            return result
        sip_data = extract_sip_data(file_path)
        if not sip_data:
            result["error"] = "SIP frames were detected but the SIP extractor returned no data"
            return result
        try:
            auth_data = extract_auth_and_registration_info(file_path)
            quality = CallQualityScorer().score_call_quality(sip_data, [], None, file_path, auth_data=auth_data)
            result["quality_analysis"] = to_jsonable(quality)
        except Exception as exc:
            result["quality_error"] = str(exc)
        try:
            mos = AdvancedRTPMOSAnalyzer().analyze_rtp_streams(sip_data, file_path)
            result["mos_analysis"] = to_jsonable(mos)
        except Exception as exc:
            result["mos_error"] = str(exc)
    result["note"] = ("SIP/RTP quality from the existing S.O.N.I.C. SIP path; use analyze_pcap for the full "
                      "LLM-assisted SIP call analysis")
    return result


def _build_detectors(names: List[str], peers: Optional[List[str]], options: Dict[str, Any]):
    builders = {
        "ipsec": lambda: IPsecDetector(peers=peers),
        "gre_nhrp": GreNhrpDetector,
        "dmvpn_phase3": lambda: DmvpnPhase3Detector(hubs=options.get("hubs")),
        "routing": lambda: RoutingDetector(expected_mss=options.get("expected_mss")),
        "reachability": ReachabilityDetector,
        "conversations": ConversationDetector,
        "cleartext_audit": lambda: CleartextAuditDetector(allow=options.get("allow")),
        "convergence": lambda: ConvergenceDetector(event_time=options.get("event_time"),
                                                   failed_peer=options.get("failed_peer"),
                                                   hold_time=options.get("hold_time"),
                                                   silence_s=options.get("silence_s")),
    }
    return [builders[name]() for name in names]


def _check_options(options: Dict[str, Any]) -> Optional[str]:
    """Validate detector options; returns an error message or None."""
    unknown = sorted(set(options) - OPTION_NAMES)
    if unknown:
        return f"Unknown option(s): {', '.join(unknown)} (valid: {', '.join(sorted(OPTION_NAMES))})"
    for key in ("hubs",):
        for value in options.get(key) or []:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return f"Not an IP address in {key}: {value!r}"
    if options.get("failed_peer"):
        try:
            ipaddress.ip_address(options["failed_peer"])
        except ValueError:
            return f"failed_peer is not an IP address: {options['failed_peer']!r}"
    for key in ("expected_mss", "hold_time", "silence_s"):
        value = options.get(key)
        if value is not None:
            try:
                if float(value) <= 0:
                    return f"{key} must be a positive number"
            except (TypeError, ValueError):
                return f"{key} must be a number, got {value!r}"
    if options.get("allow") is not None:
        from analyzers.cleartext_audit import parse_allowlist
        try:
            parse_allowlist(options["allow"])
        except ValueError as exc:
            return str(exc)
    if options.get("event_time") is not None:
        from analyzers.convergence import parse_event_time
        try:
            parse_event_time(options["event_time"], 0.0)
        except ValueError as exc:
            return str(exc)
    return None


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


def analyze_network_capture(
    file_path: str,
    detectors: Optional[List[str]] = None,
    peers: Optional[List[str]] = None,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    include_sip: bool = True,
    max_items: int = 25,
    backend: str = "auto",
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run the network detectors over one capture and return one combined report.

    Args:
        file_path: path to a pcap or pcapng file
        detectors: subset of ALL_DETECTORS to run (default: DETECTOR_NAMES; the
                   optional cleartext_audit and convergence run only when named)
        peers: IP addresses whose mutual traffic the encryption verdict judges
               (default: every pair that exchanged IKE/ESP, plus GRE tunnel endpoints)
        display_filter: Wireshark display filter applied before detection (tshark only)
        max_packets: read at most this many frames
        include_sip: run the existing SIP quality path when SIP is present
        max_items: cap on list lengths in the report (sessions, flows, pairs, ...)
        backend: "auto", "tshark" or "scapy"
        options: detector settings: allow (cleartext_audit allowlist tokens), hubs
                 (hub NBMA addresses for dmvpn_phase3), expected_mss (routing),
                 event_time, failed_peer, hold_time, silence_s (convergence)

    Returns:
        dict: the report (status "success"), or {"status": "error", "error": ...}
    """
    if not file_path or not os.path.exists(file_path):
        return _error(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        return _error(f"File not readable: {file_path}")
    names = list(detectors) if detectors else list(DETECTOR_NAMES)
    unknown = [name for name in names if name not in ALL_DETECTORS]
    if unknown:
        return _error(f"Unknown detector(s): {', '.join(unknown)}", valid_detectors=ALL_DETECTORS)
    options = {k: v for k, v in (options or {}).items() if v is not None}
    problem = _check_options(options)
    if problem:
        return _error(problem)
    if options.get("expected_mss") is not None:
        options["expected_mss"] = int(options["expected_mss"])
    peer_list = list(peers or [])
    for peer in peer_list:
        try:
            ipaddress.ip_address(peer)
        except ValueError:
            return _error(f"Not an IP address in peers: {peer!r}")
    if max_packets is not None and int(max_packets) <= 0:
        return _error("max_packets must be a positive number")
    max_items = max(1, int(max_items or 25))

    try:
        extraction = open_network_records(file_path, display_filter=display_filter,
                                          max_packets=max_packets, backend=backend)
    except (FileNotFoundError, RuntimeError) as exc:
        return _error(str(exc))

    active = _build_detectors(names, peer_list, options)
    families: set = set()
    packets = 0
    total_bytes = 0
    start = end = None
    sip_seen = False
    try:
        for rec in extraction.records:
            packets += 1
            total_bytes += rec.get("len", 0)
            t = rec.get("t")
            if t:
                start = t if start is None or t < start else start
                end = t if end is None or t > end else end
            _family(rec, families)
            if rec.get("sip"):
                sip_seen = True
            for detector in active:
                detector.feed(rec)
    except Exception as exc:
        return _error(f"Extraction failed: {exc}", type=type(exc).__name__)

    ctx = Context(start, end, max_items=max_items)
    report: Dict[str, Any] = {
        "status": "success",
        "schema": REPORT_SCHEMA,
        "file": file_path,
        "capture": {
            "backend": extraction.backend,
            "packets": packets,
            "bytes": total_bytes,
            "start": iso_time(start),
            "end": iso_time(end),
            "duration_s": round(end - start, 3) if start is not None and end is not None else None,
            "display_filter": display_filter,
            "max_packets": max_packets,
            "missing_tshark_fields": extraction.info.get("missing_fields", []),
            "warnings": extraction.info.get("warnings", []),
        },
        "protocols_present": sorted(families),
        "detectors_requested": names,
    }
    sections: Dict[str, Dict[str, Any]] = {}
    for detector in active:
        sections[detector.name] = detector.report(ctx)

    run = [name for name, sec in sections.items() if sec.get("status") != "not_present"]
    report["detectors_run"] = run
    report["detectors_not_present"] = [name for name in sections if name not in run]

    timeline: List[Dict[str, Any]] = []
    issues: List[Dict[str, Any]] = []
    for name, section in sections.items():
        for event in section.pop("events", []):
            event = dict(event)
            event["detector"] = name
            timeline.append(event)
        for issue in section.get("issues", []):
            if issue["severity"] in ("error", "warning"):
                issue = dict(issue)
                issue["detector"] = name
                issues.append(issue)
    timeline.sort(key=lambda e: (e["t"] if e["t"] is not None else 0, e.get("frame") or 0))
    issues.sort(key=lambda i: SEVERITY_ORDER.get(i["severity"], 9))
    limit = max_items * 8
    report["overall_status"] = worst_status(sec.get("status", "not_present") for sec in sections.values()
                                            if sec.get("detector") != "conversations")
    report["verdicts"] = {name: sec.get("verdict") for name, sec in sections.items()}
    report["issues"] = issues[:limit]
    report["issues_omitted"] = max(len(issues) - limit, 0)
    report["timeline"] = timeline[:limit]
    report["timeline_omitted"] = max(len(timeline) - limit, 0)
    report.update(sections)

    if sip_seen and include_sip:
        report["sip"] = _sip_quality(file_path)
    else:
        report["sip"] = {"present": sip_seen,
                         "note": "SIP present; set include_sip to run the SIP quality path" if sip_seen
                         else "no SIP in this capture"}
    return report


def analyze_vpn_capture(file_path: str, peers: Optional[List[str]] = None, display_filter: Optional[str] = None,
                        max_packets: Optional[int] = None, max_items: int = 25, backend: str = "auto",
                        hubs: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    IPsec + GRE/NHRP + the Phase 3 sequence, with the encrypted/cleartext verdict lifted to the top level.

    Returns the analyze_network_capture report plus:
        encryption_verdict  "encrypted" | "cleartext_seen" | "no_esp" | "not_present"
        verdict             the one-sentence encryption verdict
        ike_diagnoses       one diagnosis per IKE SA
        phase3_verdict      the DMVPN Phase 3 sequence verdict
    """
    report = analyze_network_capture(file_path, detectors=VPN_DETECTORS, peers=peers,
                                     display_filter=display_filter, max_packets=max_packets,
                                     include_sip=False, max_items=max_items, backend=backend,
                                     options={"hubs": hubs})
    if report.get("status") != "success":
        return report
    ipsec = report.get("ipsec", {})
    gre = report.get("gre_nhrp", {})
    overlay = gre.get("verdict")
    if gre.get("status") == "not_present" and ipsec.get("summary", {}).get("esp_packets"):
        overlay = ("No GRE or NHRP visible: with tunnel protection, GRE and NHRP travel inside ESP. "
                   "Capture on the tunnel interface to see the DMVPN overlay.")
    ordered = {
        "status": report["status"],
        "encryption_verdict": ipsec.get("encryption_verdict"),
        "verdict": ipsec.get("verdict"),
        "negotiation_verdict": ipsec.get("negotiation_verdict"),
        "overlay_verdict": overlay,
        "phase3_verdict": report.get("dmvpn_phase3", {}).get("verdict"),
        "ike_diagnoses": [{"initiator": sa["initiator"], "responder": sa["responder"],
                           "initiator_spi": sa["initiator_spi"], "outcome": sa["outcome"],
                           "diagnosis": sa.get("diagnosis")} for sa in ipsec.get("ike_sas", [])],
    }
    ordered.update(report)
    return ordered


def analyze_routing_capture(file_path: str, display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                            max_items: int = 25, backend: str = "auto",
                            expected_mss: Optional[int] = None) -> Dict[str, Any]:
    """
    Routing (BGP/OSPF/EIGRP) plus reachability, with the failover timeline lifted to the top.
    """
    report = analyze_network_capture(file_path, detectors=ROUTING_DETECTORS, display_filter=display_filter,
                                     max_packets=max_packets, include_sip=False, max_items=max_items,
                                     backend=backend, options={"expected_mss": expected_mss})
    if report.get("status") != "success":
        return report
    routing = report.get("routing", {})
    reach = report.get("reachability", {})
    outages = []
    for pair in reach.get("echo", []):
        for outage in pair.get("outages", []):
            outages.append(dict(outage, src=pair["src"], dst=pair["dst"]))
    ordered = {
        "status": report["status"],
        "verdict": routing.get("verdict"),
        "reachability_verdict": reach.get("verdict"),
        "failover_timeline": routing.get("failover_timeline", []),
        "ping_outages": outages,
    }
    ordered.update(report)
    return ordered


def audit_cleartext_capture(file_path: str, allow: Optional[List[str]] = None, display_filter: Optional[str] = None,
                            max_packets: Optional[int] = None, max_items: int = 25,
                            backend: str = "auto") -> Dict[str, Any]:
    """
    The zero-cleartext assertion: every frame against the allowlist, pass or fail.

    Returns {"status": "success", "passed": bool, "result": "pass"|"fail", "verdict",
    "allowlist", "frames_audited", "frames_outside_allowlist", "by_protocol",
    "violations", "first_violation_frame", "cannot_show", "capture"} or an error.
    """
    report = analyze_network_capture(file_path, detectors=["cleartext_audit"], display_filter=display_filter,
                                     max_packets=max_packets, include_sip=False, max_items=max_items,
                                     backend=backend, options={"allow": allow})
    if report.get("status") != "success":
        return report
    audit = report["cleartext_audit"]
    out = {"status": "success", "passed": audit["passed"], "result": audit["result"], "verdict": audit["verdict"]}
    for key in ("allowlist", "frames_audited", "frames_allowed", "frames_outside_allowlist", "first_violation_frame",
                "by_protocol", "violations", "violations_omitted", "allowed_by_rule", "cannot_show", "issues"):
        out[key] = audit[key]
    out["file"] = report["file"]
    out["capture"] = report["capture"]
    out["protocols_present"] = report["protocols_present"]
    return out


def analyze_convergence_capture(file_path: str, event_time=None, failed_peer: Optional[str] = None,
                                hold_time: Optional[float] = None, silence_s: Optional[float] = None,
                                display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                                max_items: int = 25, backend: str = "auto") -> Dict[str, Any]:
    """
    The failover timeline: failure sign, detection, routing reaction and traffic resumption.

    Returns {"status": "success", "verdict", "driver", "failed_peer", "measurements",
    "timeline", "traffic_shift", "cannot_show", "capture"} or an error.
    """
    report = analyze_network_capture(file_path, detectors=["convergence"], display_filter=display_filter,
                                     max_packets=max_packets, include_sip=False, max_items=max_items,
                                     backend=backend,
                                     options={"event_time": event_time, "failed_peer": failed_peer,
                                              "hold_time": hold_time, "silence_s": silence_s})
    if report.get("status") != "success":
        return report
    conv = report["convergence"]
    out = {"status": "success", "verdict": conv["verdict"], "driver": conv["driver"],
           "failed_peer": conv["failed_peer"], "failed_peer_source": conv["failed_peer_source"],
           "event_time": conv["event_time"], "event_t": conv["event_t"], "measurements": conv["measurements"],
           "timeline": conv["timeline"], "timeline_omitted": conv["timeline_omitted"],
           "traffic_shift": conv["traffic_shift"], "issues": conv["issues"], "cannot_show": conv["cannot_show"],
           "file": report["file"], "capture": report["capture"], "protocols_present": report["protocols_present"]}
    return out
