#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Network Report Formatting

Console summary and markdown/JSON report files for the network detector report
produced by analyzers/network_orchestrator.py.

Author: Raymond A Rizzo | Zombat
"""

import json
from typing import Any, Dict, List

STATUS_MARK = {"ok": "OK", "warning": "WARNING", "problem": "PROBLEM", "not_present": "not present"}
SECTION_TITLES = [("cleartext_audit", "Zero-cleartext audit"), ("ipsec", "IPsec / VPN"),
                  ("gre_nhrp", "GRE / NHRP (DMVPN)"), ("dmvpn_phase3", "DMVPN Phase 3 sequence"),
                  ("routing", "Routing protocols"), ("reachability", "Reachability (ICMP / ARP)"),
                  ("convergence", "Convergence"), ("conversations", "Conversations")]


def print_network_summary(report: Dict[str, Any]) -> None:
    """Print a short human summary of a network report to stdout."""
    if report.get("status") != "success":
        print(f"Network analysis failed: {report.get('error')}")
        return
    cap = report["capture"]
    print("=" * 80)
    print("S.O.N.I.C. network analysis (deterministic, no LLM)")
    print("=" * 80)
    print(f"File: {report['file']}")
    print(f"Backend: {cap['backend']} | packets: {cap['packets']} | duration: {cap['duration_s']} s")
    print(f"Protocols present: {', '.join(report['protocols_present']) or 'none'}")
    print(f"Overall: {STATUS_MARK.get(report['overall_status'], report['overall_status'])}")
    print()
    for key, title in SECTION_TITLES:
        section = report.get(key)
        if not section:
            continue
        print(f"[{STATUS_MARK.get(section.get('status'), section.get('status'))}] {title}: {section.get('verdict')}")
    issues = report.get("issues", [])
    if issues:
        print()
        print("Issues:")
        for issue in issues[:30]:
            print(f"  - {issue['severity'].upper()} {issue['code']}: {issue['message']}")
        if len(issues) > 30:
            print(f"  ... and {len(issues) - 30} more")
    timeline = report.get("timeline", [])
    if timeline:
        print()
        print("Timeline (seconds from first frame):")
        for event in timeline[:40]:
            print(f"  {event['t']:>10} {event['protocol']:<6} {event['event']:<22} {event['detail']}")
        if len(timeline) > 40:
            print(f"  ... and {len(timeline) - 40} more")
    sip = report.get("sip", {})
    if sip.get("present"):
        grade = (sip.get("quality_analysis") or {}).get("grade")
        print()
        print(f"SIP present: quality grade {grade} (see the sip section of the report)")


def _md_table(rows: List[Dict[str, Any]], columns: List[str]) -> str:
    if not rows:
        return "_none_\n"
    out = "| " + " | ".join(columns) + " |\n"
    out += "|" + "---|" * len(columns) + "\n"
    for row in rows:
        out += "| " + " | ".join(str(row.get(c, "")) for c in columns) + " |\n"
    return out


def build_network_markdown(report: Dict[str, Any]) -> str:
    """Render a network report as markdown."""
    if report.get("status") != "success":
        return f"# S.O.N.I.C. network analysis\n\nAnalysis failed: {report.get('error')}\n"
    cap = report["capture"]
    md = ["# S.O.N.I.C. network analysis", ""]
    md.append(f"- File: `{report['file']}`")
    md.append(f"- Backend: {cap['backend']}, {cap['packets']} packets, {cap['bytes']} bytes, {cap['duration_s']} s")
    md.append(f"- Capture window: {cap['start']} to {cap['end']}")
    if cap.get("display_filter"):
        md.append(f"- Display filter: `{cap['display_filter']}`")
    md.append(f"- Protocols present: {', '.join(report['protocols_present']) or 'none'}")
    md.append(f"- Overall status: **{report['overall_status']}**")
    md.append("")
    md.append("## Verdicts")
    md.append("")
    for key, title in SECTION_TITLES:
        section = report.get(key)
        if section:
            md.append(f"- **{title}** ({section.get('status')}): {section.get('verdict')}")
    md.append("")
    issues = report.get("issues", [])
    md.append("## Issues")
    md.append("")
    md.append(_md_table([{"severity": i["severity"], "detector": i.get("detector"), "code": i["code"],
                          "message": i["message"].replace("|", "/"),
                          "frames": ", ".join(map(str, i.get("frames", [])))} for i in issues],
                        ["severity", "detector", "code", "message", "frames"]))
    ipsec = report.get("ipsec")
    if ipsec and ipsec.get("status") != "not_present":
        md.append("## IPsec / VPN")
        md.append("")
        md.append(f"Encryption verdict: **{ipsec['encryption_verdict']}**. {ipsec['negotiation_verdict']}.")
        md.append("")
        md.append(_md_table([{"endpoints": " <-> ".join(p["endpoints"]), "verdict": p["verdict"],
                              "protected": json.dumps(p["protected_packets"]), "cleartext": p["cleartext_packets"]}
                             for p in ipsec["peer_pairs"]], ["endpoints", "verdict", "protected", "cleartext"]))
        md.append(_md_table([{"version": s["ike_version"], "initiator": s["initiator"], "responder": s["responder"],
                              "outcome": s["outcome"], "detail": s["detail"], "retransmissions": s["retransmissions"],
                              "rekeys": s["rekeys"]} for s in ipsec["ike_sas"]],
                            ["version", "initiator", "responder", "outcome", "detail", "retransmissions", "rekeys"]))
        md.append(_md_table([{k: f[k] for k in ("src", "dst", "spi", "udp_encapsulated", "packets",
                                                 "missing_sequence_numbers", "duplicate_sequence_numbers")}
                             for f in ipsec["esp_flows"]],
                            ["src", "dst", "spi", "udp_encapsulated", "packets", "missing_sequence_numbers",
                             "duplicate_sequence_numbers"]))
        md.append(f"NAT traversal: {ipsec['nat_traversal']['verdict']}")
        md.append("")
    gre = report.get("gre_nhrp")
    if gre and gre.get("status") != "not_present":
        md.append("## GRE / NHRP (DMVPN)")
        md.append("")
        md.append(f"DMVPN phase hint: {gre['dmvpn_phase_hint']}")
        md.append("")
        md.append(_md_table([{k: r[k] for k in ("spoke_nbma", "spoke_tunnel_ip", "hub_nbma", "hub_tunnel_ip", "result")}
                             for r in gre["registrations"]],
                            ["spoke_nbma", "spoke_tunnel_ip", "hub_nbma", "hub_tunnel_ip", "result"]))
        md.append(_md_table([{"src": t["src"], "dst": t["dst"], "packets": t["packets"], "keys": t["gre_keys"],
                              "inner": json.dumps(t["inner_protocols"])} for t in gre["tunnels"]],
                            ["src", "dst", "packets", "keys", "inner"]))
    routing = report.get("routing")
    if routing and routing.get("status") != "not_present":
        md.append("## Routing protocols")
        md.append("")
        bgp = routing.get("bgp", {})
        if bgp.get("present"):
            md.append("### BGP")
            md.append("")
            md.append(_md_table([{"peers": " <-> ".join(s["peers"]), "state": s["state"], "ibgp": s["ibgp"],
                                  "hold": s["negotiated_hold_time"], "established": s["times_established"],
                                  "down": s["times_down"]} for s in bgp["sessions"]],
                                ["peers", "state", "ibgp", "hold", "established", "down"]))
        ospf = routing.get("ospf", {})
        if ospf.get("present"):
            md.append("### OSPF")
            md.append("")
            for link in ospf["links"]:
                md.append(f"Link {link['network']} (DR {link['dr']})")
                md.append("")
                md.append(_md_table([{k: r[k] for k in ("router_id", "address", "area", "hello_interval",
                                                         "dead_interval", "network_mask", "neighbors_listed")}
                                     for r in link["routers"]],
                                    ["router_id", "address", "area", "hello_interval", "dead_interval",
                                     "network_mask", "neighbors_listed"]))
        eigrp = routing.get("eigrp", {})
        if eigrp.get("present"):
            md.append("### EIGRP")
            md.append("")
            for link in eigrp["links"]:
                md.append(_md_table([{k: s[k] for k in ("address", "as", "k_values", "hold_time", "hellos", "goodbyes")}
                                     for s in link["speakers"]],
                                    ["address", "as", "k_values", "hold_time", "hellos", "goodbyes"]))
    reach = report.get("reachability")
    if reach and reach.get("status") != "not_present":
        md.append("## Reachability")
        md.append("")
        md.append(_md_table([{"src": p["src"], "dst": p["dst"], "sent": p["sent"], "answered": p["answered"],
                              "loss_percent": p["loss_percent"],
                              "rtt_avg_ms": (p["rtt_ms"] or {}).get("avg"), "outages": len(p["outages"])}
                             for p in reach["echo"]],
                            ["src", "dst", "sent", "answered", "loss_percent", "rtt_avg_ms", "outages"]))
    timeline = report.get("timeline", [])
    if timeline:
        md.append("## Timeline")
        md.append("")
        md.append(_md_table([{"t (s)": e["t"], "protocol": e["protocol"], "event": e["event"],
                              "detail": e["detail"].replace("|", "/"), "frame": e.get("frame")} for e in timeline],
                            ["t (s)", "protocol", "event", "detail", "frame"]))
    conv = report.get("conversations")
    if conv and conv.get("status") != "not_present":
        md.append("## Conversations")
        md.append("")
        md.append(_md_table(conv["protocols"], ["protocol", "service", "packets", "bytes"]))
        md.append(_md_table([{"a": c["a"], "b": c["b"], "packets": c["packets"], "bytes": c["bytes"]}
                             for c in conv["top_conversations"]], ["a", "b", "packets", "bytes"]))
    md.append("_Generated by S.O.N.I.C. network detectors. Frame numbers match Wireshark's._")
    return "\n".join(md) + "\n"


def save_network_report(report: Dict[str, Any], path: str) -> None:
    """Write the report as JSON (path ending in .json) or markdown (anything else)."""
    with open(path, "w", encoding="utf-8") as handle:
        if path.lower().endswith(".json"):
            json.dump(report, handle, indent=2)
            handle.write("\n")
        else:
            handle.write(build_network_markdown(report))
