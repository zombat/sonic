#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. RESTCONF/REST Report Formatting

Console summary and markdown/JSON report files for the RESTCONF and REST troubleshooting
report produced by analyzers/http_inspect.py. The report carries no credential value (the
extractor masks them at the source), and files are written through the same redacting writer
as every other S.O.N.I.C. report.

Author: Raymond A Rizzo | Zombat
"""

import json
from typing import Any, Dict

from utils.network_reporting import STATUS_MARK, _md_table


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "/").replace("\n", " ")


def print_http_summary(report: Dict[str, Any]) -> None:
    """Print a short human summary of a RESTCONF/REST report to stdout."""
    if report.get("status") != "success":
        print(f"RESTCONF/REST analysis failed: {report.get('error')}")
        return
    cap = report["capture"]
    print("=" * 80)
    print("S.O.N.I.C. RESTCONF and REST troubleshooting (Wireshark dissectors through tshark, no LLM)")
    print("=" * 80)
    print(f"File: {report['file']}")
    print(f"tshark: {cap.get('tshark')} | HTTP messages: {cap.get('http_messages')} | "
          f"decode-as: {', '.join(cap.get('decode_as') or []) or 'none'}")
    print(f"Overall: {STATUS_MARK.get(report['overall_status'], report['overall_status'])}")
    print(f"Verdict: {report['verdict']}")
    coverage = report.get("tls_decryption") or {}
    if coverage.get("total"):
        print(f"🔓 TLS decryption: {coverage['verdict']}")
        for row in coverage.get("sessions", []):
            if not row["decrypted"] and coverage.get("secrets_source"):
                print(f"  not decrypted: {row['flow']}: {row['reason']}")
    for conn in report.get("connections", []):
        print()
        print(f"[{conn['transport']}] {conn['flow']} {conn['service']} "
              f"(HTTP/{', '.join(conn['http_versions']) or '?'}"
              + (", RESTCONF" if conn.get("restconf") else "") + ")")
    reqs = report.get("requests", [])
    if reqs:
        print()
        print("Requests:")
        for req in reqs[:40]:
            ms = f"{req['timing_ms']} ms" if req.get("timing_ms") is not None else "-"
            print(f"  {(req.get('method') or '?'):<7} {_cell(req.get('path'))[:52]:<52} "
                  f"-> {_cell(req.get('status')):<4} {ms:<9} {_cell(req.get('response_content_type'))}")
            for err in req.get("restconf_errors", []):
                print(f"        ! {err.get('error-tag')} {err.get('error-path', '')} {err.get('error-message', '')}")
    creds = report.get("credentials", [])
    if creds:
        print()
        print("🔑 Credentials present (values masked):")
        for cred in creds:
            where = "CLEARTEXT" if cred["cleartext"] else "over TLS"
            scheme = f" {cred['scheme']}" if cred.get("scheme") else ""
            print(f"  [{where}] {cred['header']}{scheme} on {cred['flow']} in {cred['requests']} request(s)")
    issues = report.get("issues", [])
    if issues:
        print()
        print(f"Issues ({len(issues)}):")
        for issue in issues[:30]:
            print(f"  [{issue['severity']}] {issue['code']}: {issue['message']}")


def build_http_markdown(report: Dict[str, Any]) -> str:
    """A markdown report for a RESTCONF/REST analysis."""
    if report.get("status") != "success":
        return f"# S.O.N.I.C. RESTCONF/REST report\n\nAnalysis failed: {report.get('error')}\n"
    cap = report["capture"]
    md = ["# S.O.N.I.C. RESTCONF and REST troubleshooting", "",
          f"**File:** `{report['file']}`  ", f"**tshark:** {cap.get('tshark')}  ",
          f"**Overall:** {STATUS_MARK.get(report['overall_status'], report['overall_status'])}  ",
          f"**Verdict:** {report['verdict']}", ""]
    secrets = cap.get("tls_secrets") or {}
    if secrets.get("source"):
        md.append(f"TLS secrets: {secrets['source']} "
                  f"(key log: {secrets.get('sessions_in_key_log')}, pcapng: {secrets.get('sessions_in_pcapng')}).")
        md.append("")
    coverage = report.get("tls_decryption") or {}
    if coverage.get("total"):
        md += ["## TLS decryption", "", coverage["verdict"], ""]
        md.append(_md_table([{"flow": s["flow"], "service": s["service"],
                              "decrypted": "yes" if s["decrypted"] else "no",
                              "secret_in": ", ".join(s["secret_in"]) or "-", "reason": s["reason"] or "-"}
                             for s in coverage.get("sessions", [])],
                            ["flow", "service", "decrypted", "secret_in", "reason"]))
        md.append("")
    md += ["## Connections", "",
           _md_table([{"flow": c["flow"], "service": c["service"], "transport": c["transport"],
                       "http": ", ".join(c["http_versions"]), "restconf": "yes" if c["restconf"] else "no",
                       "requests": c["requests"]}
                      for c in report.get("connections", [])],
                     ["flow", "service", "transport", "http", "restconf", "requests"]), ""]
    reqs = report.get("requests", [])
    if reqs:
        md += ["## Requests", "",
               _md_table([{"method": r.get("method"), "path": r.get("path"), "status": r.get("status"),
                           "ms": r.get("timing_ms"), "content_type": r.get("response_content_type"),
                           "restconf": "yes" if r.get("restconf") else "",
                           "errors": "; ".join(f"{e.get('error-tag')}" for e in r.get("restconf_errors", [])) or "",
                           "location": r.get("location") or ""}
                          for r in reqs],
                         ["method", "path", "status", "ms", "content_type", "restconf", "errors", "location"]), ""]
    creds = report.get("credentials", [])
    if creds:
        md += ["## Credentials present (values masked)", "",
               _md_table([{"flow": c["flow"], "header": c["header"], "scheme": c.get("scheme") or "",
                           "cleartext": "yes" if c["cleartext"] else "no (TLS)", "requests": c["requests"]}
                          for c in creds],
                         ["flow", "header", "scheme", "cleartext", "requests"]), ""]
    issues = report.get("issues", [])
    if issues:
        md += ["## Issues", ""]
        for issue in issues:
            frames = f" (frames {issue['frames']})" if issue.get("frames") else ""
            md.append(f"- **[{issue['severity']}] {issue['code']}**: {issue['message']}{frames}")
        md.append("")
    md += ["## Limits", ""]
    md.extend(f"- {line}" for line in report.get("limits", []))
    md += ["", "_Generated by S.O.N.I.C. RESTCONF/REST troubleshooting. Frame numbers match Wireshark's._"]
    return "\n".join(md) + "\n"


def save_http_report(report: Dict[str, Any], path: str) -> None:
    """Write the report as JSON (path ending in .json) or markdown (anything else), keys redacted."""
    from utils.credentials import redact, write_redacted
    if path.lower().endswith(".json"):
        write_redacted(path, json.dumps(redact(report), indent=2) + "\n")
    else:
        write_redacted(path, build_http_markdown(report))
