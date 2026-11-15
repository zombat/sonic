#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. gRPC Report Formatting

Console summary and markdown/JSON report files for the gRPC troubleshooting report
produced by analyzers/grpc_inspect.py. The report carries no credential value (the
extractor masks them at the source), and files are written through the same
redacting writer as every other S.O.N.I.C. report.

Author: Raymond A Rizzo | Zombat
"""

import json
from typing import Any, Dict, List

from utils.network_reporting import STATUS_MARK, _md_table


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "/").replace("\n", " ")


def print_grpc_summary(report: Dict[str, Any]) -> None:
    """Print a short human summary of a gRPC report to stdout."""
    if report.get("status") != "success":
        print(f"gRPC analysis failed: {report.get('error')}")
        return
    cap = report["capture"]
    print("=" * 80)
    print("S.O.N.I.C. gRPC troubleshooting (Wireshark dissectors through tshark, no LLM)")
    print("=" * 80)
    print(f"File: {report['file']}")
    print(f"tshark: {cap.get('tshark')} | HTTP/2 packets: {cap.get('http2_packets')} | "
          f"decode-as: {', '.join(cap.get('decode_as') or []) or 'none'}")
    print(f"Overall: {STATUS_MARK.get(report['overall_status'], report['overall_status'])}")
    print(f"Verdict: {report['verdict']}")
    for conn in report.get("connections", []):
        print()
        print(f"[{conn['transport']}] {conn['flow']} {conn['service']} ({conn['protocol']})"
              + (f" services: {', '.join(conn['services'])}" if conn.get("services") else ""))
        tls = conn.get("tls")
        if tls:
            cert = tls.get("certificate") or {}
            print(f"  TLS {tls.get('version')} SNI {tls.get('sni')} ALPN offered {tls.get('alpn_offered')}"
                  + (f" certificate {cert.get('subject')} (IP SANs {cert.get('ip_addresses')})"
                     if cert.get("parsed") else ""))
    rpcs = report.get("rpcs", [])
    if rpcs:
        print()
        print("RPCs:")
        for rpc in rpcs[:40]:
            status = rpc.get("grpc_status_name") or rpc.get("outcome")
            print(f"  stream {rpc['stream_id']:>4} {rpc.get('method') or '?':<48} {status:<18} "
                  f"{rpc.get('diagnosis')}")
        if len(rpcs) > 40:
            print(f"  ... and {len(rpcs) - 40} more")
    creds = report.get("credentials", [])
    if creds:
        print()
        print("Credentials in metadata (values masked):")
        for cred in creds:
            print(f"  {cred['key']:<16} {cred['flow']} {'CLEARTEXT' if cred['cleartext'] else cred['transport']} "
                  f"in {cred['requests']} request(s), frames {cred['frames']}")
    issues = [i for i in report.get("issues", []) if i["severity"] in ("error", "warning")]
    if issues:
        print()
        print("Issues:")
        for issue in issues[:30]:
            print(f"  - {issue['severity'].upper()} {issue['code']}: {issue['message']}")
        if len(issues) > 30:
            print(f"  ... and {len(issues) - 30} more")


def build_grpc_markdown(report: Dict[str, Any]) -> str:
    """Render a gRPC report as markdown."""
    if report.get("status") != "success":
        return f"# S.O.N.I.C. gRPC troubleshooting\n\nAnalysis failed: {report.get('error')}\n"
    cap = report["capture"]
    md: List[str] = ["# S.O.N.I.C. gRPC troubleshooting", ""]
    md.append(f"- File: `{report['file']}`")
    md.append(f"- tshark: {cap.get('tshark')}; HTTP/2 packets: {cap.get('http2_packets')}")
    md.append(f"- Decode-as: {', '.join(f'`{d}`' for d in cap.get('decode_as') or []) or 'none'}")
    md.append(f"- Key log given: {'yes' if cap.get('keylog_file_given') else 'no'}; .proto paths: "
              f"{', '.join(cap.get('proto_paths') or []) or 'none'}")
    md.append(f"- Overall status: **{report['overall_status']}**")
    md.append("")
    md.append(f"**Verdict:** {report['verdict']}")
    md.append("")
    md.append("## Connections")
    md.append("")
    md.append(_md_table([{"flow": c["flow"], "service": c["service"], "transport": c["transport"],
                          "protocol": c["protocol"], "services": ", ".join(c.get("services") or []),
                          "rpcs": c["rpcs"], "status": json.dumps(c.get("rpc_status"))}
                         for c in report.get("connections", [])],
                        ["flow", "service", "transport", "protocol", "services", "rpcs", "status"]))
    for conn in report.get("connections", []):
        tls = conn.get("tls")
        if not tls:
            continue
        cert = tls.get("certificate") or {}
        md.append(f"### TLS {conn['flow']}")
        md.append("")
        md.append(f"- Version {tls.get('version')}, suite {tls.get('cipher_suite')}, SNI {tls.get('sni')}, "
                  f"ALPN offered {tls.get('alpn_offered')}, decrypted: {tls.get('decrypted')}")
        if cert.get("parsed"):
            md.append(f"- Certificate: subject {cert.get('subject')}, issuer {cert.get('issuer')}, valid "
                      f"{cert.get('not_before')} to {cert.get('not_after')}, DNS SANs {cert.get('dns_names')}, "
                      f"IP SANs {cert.get('ip_addresses')}")
        else:
            md.append(f"- Certificate: {cert.get('reason', 'not visible')}")
        for alert in tls.get("alerts", []):
            md.append(f"- Alert {alert.get('level')} {alert.get('description')} from {alert.get('from')}: "
                      f"{alert.get('hint', '')}")
        for hint in tls.get("hints", []):
            md.append(f"- {hint['text']}")
        md.append("")
    md.append("## RPCs")
    md.append("")
    md.append(_md_table([{"stream": r["stream_id"], "method": _cell(r.get("method")),
                          "status": _cell(r.get("grpc_status_name") or r.get("outcome")),
                          "message": _cell(r.get("grpc_message")),
                          "req msgs": r["request"]["messages"], "resp msgs": r["response"]["messages"],
                          "first response ms": r["timing"].get("to_first_response_ms"),
                          "end ms": r["timing"].get("to_end_ms"), "diagnosis": _cell(r.get("diagnosis"))}
                         for r in report.get("rpcs", [])],
                        ["stream", "method", "status", "message", "req msgs", "resp msgs", "first response ms",
                         "end ms", "diagnosis"]))
    creds = report.get("credentials", [])
    md.append("## Credentials in metadata")
    md.append("")
    md.append("Reported by key only; no value is read into this report.")
    md.append("")
    md.append(_md_table([{"key": c["key"], "flow": c["flow"], "cleartext": c["cleartext"],
                          "requests": c["requests"], "frames": ", ".join(map(str, c["frames"]))} for c in creds],
                        ["key", "flow", "cleartext", "requests", "frames"]))
    md.append("## Issues")
    md.append("")
    md.append(_md_table([{"severity": i["severity"], "code": i["code"], "message": _cell(i["message"]),
                          "frames": ", ".join(map(str, i.get("frames", [])))} for i in report.get("issues", [])],
                        ["severity", "code", "message", "frames"]))
    md.append("## Limits")
    md.append("")
    md.extend(f"- {line}" for line in report.get("limits", []))
    md.append("")
    md.append("_Generated by S.O.N.I.C. gRPC troubleshooting. Frame numbers match Wireshark's._")
    return "\n".join(md) + "\n"


def save_grpc_report(report: Dict[str, Any], path: str) -> None:
    """Write the report as JSON (path ending in .json) or markdown (anything else), keys redacted."""
    from utils.credentials import redact, write_redacted
    if path.lower().endswith(".json"):
        write_redacted(path, json.dumps(redact(report), indent=2) + "\n")
    else:
        write_redacted(path, build_grpc_markdown(report))
