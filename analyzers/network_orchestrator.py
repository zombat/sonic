#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Network Analysis Orchestrator

One entry point for the non-SIP detectors. It reads the capture once (tshark
first, scapy fallback, see extractors/network.py), feeds every frame to each
selected detector, and returns one combined, JSON-serializable report. Detectors
that found nothing to look at are listed as not present rather than failing, so
the same call works on any capture: the report says which protocols were there.

Detectors:
    ipsec          IKEv1/IKEv2, ESP, NAT-T, and the encrypted/cleartext verdict
    gre_nhrp       GRE tunnels and NHRP (DMVPN registration, resolution, redirect)
    routing        BGP, OSPF and EIGRP health with a failover timeline
    reachability   ICMP echo loss/RTT/outages, ICMP errors, ARP without replies
    path_mtu       Fragmentation Needed / Packet Too Big, PMTUD black holes, IP fragments
    esp_overhead   ESP sizes against cipher families, overhead, post-encryption fragmentation
    tcp            per-connection TCP health with a verdict (no answer, loss, zero window, ...)
    tls            TLS ClientHello/ServerHello, certificate (TLS 1.2), baseline check
    qos            DSCP per flow, GRE/ESP marking copy, RTP jitter/loss/MOS with DSCP
    conversations  protocols, top conversations and top talkers

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

from analyzers.gre_nhrp import GreNhrpDetector
from analyzers.ipsec_vpn import IPsecDetector
from analyzers.network_common import Context, SEVERITY_ORDER, iso_time, worst_status
from analyzers.reachability import ConversationDetector, ReachabilityDetector
from analyzers.routing_health import RoutingDetector
from analyzers.esp_overhead import EspOverheadDetector
from analyzers.path_mtu import PathMtuDetector
from analyzers.qos import QosDetector
from analyzers.tcp_health import TcpHealthDetector
from analyzers.tls_inspect import TlsDetector
from extractors.network import open_network_records

REPORT_SCHEMA = "sonic.network_report/1"
DETECTOR_NAMES = ["ipsec", "gre_nhrp", "routing", "reachability", "path_mtu", "esp_overhead", "tcp", "tls", "qos",
                  "conversations"]
VPN_DETECTORS = ["ipsec", "gre_nhrp"]
ROUTING_DETECTORS = ["routing", "reachability"]
DATA_PLANE_DETECTORS = ["path_mtu", "esp_overhead", "tcp", "tls", "qos"]
OPTION_KEYS = {"esp_overhead": {"transport_mtu", "tunnel_mtu", "gre_header_bytes"}, "tls": {"baseline"}}


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


def _build_detectors(names: List[str], peers: Optional[List[str]], options: Optional[Dict[str, Dict[str, Any]]] = None):
    options = options or {}
    builders = {
        "ipsec": lambda: IPsecDetector(peers=peers),
        "gre_nhrp": GreNhrpDetector,
        "routing": RoutingDetector,
        "reachability": ReachabilityDetector,
        "path_mtu": PathMtuDetector,
        "esp_overhead": lambda: EspOverheadDetector(**options.get("esp_overhead", {})),
        "tcp": TcpHealthDetector,
        "tls": lambda: TlsDetector(**options.get("tls", {})),
        "qos": QosDetector,
        "conversations": ConversationDetector,
    }
    return [builders[name]() for name in names]


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
    options: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Run the network detectors over one capture and return one combined report.

    Args:
        file_path: path to a pcap or pcapng file
        detectors: subset of DETECTOR_NAMES to run (default: all)
        peers: IP addresses whose mutual traffic the encryption verdict judges
               (default: every pair that exchanged IKE/ESP, plus GRE tunnel endpoints)
        display_filter: Wireshark display filter applied before detection (tshark only)
        max_packets: read at most this many frames
        include_sip: run the existing SIP quality path when SIP is present
        max_items: cap on list lengths in the report (sessions, flows, pairs, ...)
        backend: "auto", "tshark" or "scapy"
        options: per-detector settings, {"esp_overhead": {"transport_mtu", "tunnel_mtu",
                 "gre_header_bytes"}, "tls": {"baseline": {...}}}

    Returns:
        dict: the report (status "success"), or {"status": "error", "error": ...}
    """
    if not file_path or not os.path.exists(file_path):
        return _error(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        return _error(f"File not readable: {file_path}")
    names = list(detectors) if detectors else list(DETECTOR_NAMES)
    unknown = [name for name in names if name not in DETECTOR_NAMES]
    if unknown:
        return _error(f"Unknown detector(s): {', '.join(unknown)}", valid_detectors=DETECTOR_NAMES)
    peer_list = list(peers or [])
    for peer in peer_list:
        try:
            ipaddress.ip_address(peer)
        except ValueError:
            return _error(f"Not an IP address in peers: {peer!r}")
    if max_packets is not None and int(max_packets) <= 0:
        return _error("max_packets must be a positive number")
    max_items = max(1, int(max_items or 25))
    options = dict(options or {})
    for name, settings in options.items():
        if name not in OPTION_KEYS:
            return _error(f"No options for detector {name!r}", detectors_with_options=sorted(OPTION_KEYS))
        if not isinstance(settings, dict) or set(settings) - OPTION_KEYS[name]:
            return _error(f"Unknown option(s) for {name}: {sorted(set(settings or {}) - OPTION_KEYS[name])}",
                          valid_options=sorted(OPTION_KEYS[name]))

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
                        max_packets: Optional[int] = None, max_items: int = 25, backend: str = "auto") -> Dict[str, Any]:
    """
    IPsec + GRE/NHRP only, with the encrypted/cleartext verdict lifted to the top level.

    Returns the analyze_network_capture report plus:
        encryption_verdict  "encrypted" | "cleartext_seen" | "no_esp" | "not_present"
        verdict             the one-sentence encryption verdict
    """
    report = analyze_network_capture(file_path, detectors=VPN_DETECTORS, peers=peers,
                                     display_filter=display_filter, max_packets=max_packets,
                                     include_sip=False, max_items=max_items, backend=backend)
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
    }
    ordered.update(report)
    return ordered


def analyze_routing_capture(file_path: str, display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                            max_items: int = 25, backend: str = "auto") -> Dict[str, Any]:
    """
    Routing (BGP/OSPF/EIGRP) plus reachability, with the failover timeline lifted to the top.
    """
    report = analyze_network_capture(file_path, detectors=ROUTING_DETECTORS, display_filter=display_filter,
                                     max_packets=max_packets, include_sip=False, max_items=max_items,
                                     backend=backend)
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


def analyze_data_plane_capture(file_path: str, tls_baseline: Optional[Dict[str, Any]] = None,
                               transport_mtu: int = 1500, tunnel_mtu: Optional[int] = None,
                               gre_header_bytes: int = 8, display_filter: Optional[str] = None,
                               max_packets: Optional[int] = None, max_items: int = 25,
                               backend: str = "auto") -> Dict[str, Any]:
    """
    The data plane detectors (path_mtu, esp_overhead, tcp, tls, qos), with each verdict lifted to the top.
    """
    options = {"esp_overhead": {"transport_mtu": transport_mtu, "tunnel_mtu": tunnel_mtu,
                                "gre_header_bytes": gre_header_bytes}}
    if tls_baseline:
        options["tls"] = {"baseline": tls_baseline}
    report = analyze_network_capture(file_path, detectors=DATA_PLANE_DETECTORS, display_filter=display_filter,
                                     max_packets=max_packets, include_sip=False, max_items=max_items,
                                     backend=backend, options=options)
    if report.get("status") != "success":
        return report
    ordered = {"status": report["status"], "overall_status": report["overall_status"]}
    for name in DATA_PLANE_DETECTORS:
        ordered[f"{name}_verdict"] = report.get(name, {}).get("verdict")
    ordered.update(report)
    return ordered
