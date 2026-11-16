#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. SNMP Report Formatting

Console summary and markdown/JSON report files for the SNMP troubleshooting report produced
by analyzers/snmp_inspect.py. The report carries no USM passphrase and no community value (both
are masked at the source), and files are written through the same redacting writer as every
other S.O.N.I.C. report.

Author: Raymond A Rizzo | Zombat
"""

import json
from typing import Any, Dict

from utils.network_reporting import STATUS_MARK, _md_table


def print_snmp_summary(report: Dict[str, Any]) -> None:
    """Print a short human summary of an SNMP report to stdout."""
    if report.get("status") != "success":
        print(f"SNMP analysis failed: {report.get('error')}")
        return
    cap = report["capture"]
    print("=" * 80)
    print("S.O.N.I.C. SNMP troubleshooting (Wireshark dissector through tshark, no LLM)")
    print("=" * 80)
    print(f"File: {report['file']}")
    print(f"tshark: {cap.get('tshark')} | users file: "
          f"{'yes (' + str(cap.get('users_count')) + ' user(s))' if cap.get('users_file_given') else 'no'}")
    print(f"Overall: {STATUS_MARK.get(report['overall_status'], report['overall_status'])}")
    print(f"Verdict: {report['verdict']}")
    summary = report["summary"]
    print(f"Versions: {summary['versions']} | v3 security levels: {summary['v3_security_levels']}")
    users = report.get("v3_users", [])
    if users:
        print()
        print("🔓 SNMPv3 users (outcome per authenticated message):")
        for u in users:
            outcomes = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in sorted(u["outcomes"].items()))
            print(f"  {str(u['user'] or '?'):<20} {outcomes}")
    messages = report.get("messages", [])
    if messages:
        print()
        print("Messages:")
        for m in messages[:40]:
            extra = ""
            if m["version"] == "v3":
                extra = (f" user={m.get('user') or '-'}" + (f" [{m['role']}]" if m.get("role") else "")
                         + (f" {m['outcome']}" if m.get("outcome") else "")
                         + (f" report {m['report']}" if m.get("report") else ""))
            print(f"  {m['version']:<4} {m['security_level']:<13} {(m.get('pdu') or ''):<17} "
                  f"{m['src']} -> {m['dst']}{extra}")
    creds = report.get("credentials", [])
    if creds:
        print()
        print("🔑 Cleartext community credentials (values masked):")
        for c in creds:
            print(f"  [{c['protocol']}] {c['kind']} on {c['flow']}")
    issues = report.get("issues", [])
    if issues:
        print()
        print(f"Issues ({len(issues)}):")
        for issue in issues[:30]:
            print(f"  [{issue['severity']}] {issue['code']}: {issue['message']}")


def build_snmp_markdown(report: Dict[str, Any]) -> str:
    """A markdown report for an SNMP analysis."""
    if report.get("status") != "success":
        return f"# S.O.N.I.C. SNMP report\n\nAnalysis failed: {report.get('error')}\n"
    cap = report["capture"]
    summary = report["summary"]
    md = ["# S.O.N.I.C. SNMP troubleshooting", "",
          f"**File:** `{report['file']}`  ", f"**tshark:** {cap.get('tshark')}  ",
          f"**Overall:** {STATUS_MARK.get(report['overall_status'], report['overall_status'])}  ",
          f"**Verdict:** {report['verdict']}", "",
          f"Versions: {summary['versions']}. v3 security levels: {summary['v3_security_levels']}. "
          f"authPriv decrypted: {summary['authpriv_decrypted']}/"
          f"{summary['authpriv_decrypted'] + summary['authpriv_not_decrypted']}.", "",
          "## Messages", "",
          _md_table([{"frame": m.get("frame"), "version": m["version"], "security_level": m["security_level"],
                      "pdu": m.get("pdu") or "", "src": m["src"], "dst": m["dst"], "user": m.get("user") or "",
                      "outcome": m.get("outcome") or m.get("role") or "", "report": m.get("report") or "",
                      "reason": m.get("reason") or "", "credential": m.get("credential") or ""}
                     for m in report.get("messages", [])],
                    ["frame", "version", "security_level", "pdu", "src", "dst", "user", "outcome", "report",
                     "reason", "credential"]), ""]
    if report.get("v3_users"):
        md += ["## SNMPv3 users", "",
               _md_table([{"user": u["user"], "messages": u["messages"],
                           "outcomes": ", ".join(f"{n} {k}" for k, n in sorted(u["outcomes"].items()))}
                          for u in report["v3_users"]], ["user", "messages", "outcomes"]), ""]
    creds = report.get("credentials", [])
    if creds:
        md += ["## Cleartext community credentials (values masked)", "",
               _md_table([{"protocol": c["protocol"], "flow": c["flow"], "kind": c["kind"], "value": c["value"]}
                          for c in creds], ["protocol", "flow", "kind", "value"]), ""]
    issues = report.get("issues", [])
    if issues:
        md += ["## Issues", ""]
        for issue in issues:
            frames = f" (frames {issue['frames']})" if issue.get("frames") else ""
            md.append(f"- **[{issue['severity']}] {issue['code']}**: {issue['message']}{frames}")
        md.append("")
    md += ["## Limits", ""]
    md.extend(f"- {line}" for line in report.get("limits", []))
    md += ["", "_Generated by S.O.N.I.C. SNMP troubleshooting. Frame numbers match Wireshark's._"]
    return "\n".join(md) + "\n"


def save_snmp_report(report: Dict[str, Any], path: str) -> None:
    """Write the report as JSON (path ending in .json) or markdown (anything else), keys redacted."""
    from utils.credentials import redact, write_redacted
    if path.lower().endswith(".json"):
        write_redacted(path, json.dumps(redact(report), indent=2) + "\n")
    else:
        write_redacted(path, build_snmp_markdown(report))
