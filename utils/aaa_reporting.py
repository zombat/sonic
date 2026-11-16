#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. AAA (TACACS+ / RADIUS) Report Formatting

Console summary and markdown/JSON report files for the AAA troubleshooting report produced
by analyzers/aaa_inspect.py. The report carries no credential value and never the shared key
(the extractor masks recovered credentials at the source), and files are written through the
same redacting writer as every other S.O.N.I.C. report.

Author: Raymond A Rizzo | Zombat
"""

import json
from typing import Any, Dict

from utils.network_reporting import STATUS_MARK, _md_table


def print_aaa_summary(report: Dict[str, Any]) -> None:
    """Print a short human summary of an AAA report to stdout."""
    if report.get("status") != "success":
        print(f"AAA analysis failed: {report.get('error')}")
        return
    cap = report["capture"]
    print("=" * 80)
    print("S.O.N.I.C. TACACS+ and RADIUS troubleshooting (Wireshark dissectors through tshark, no LLM)")
    print("=" * 80)
    print(f"File: {report['file']}")
    keys = []
    if cap.get("tacacs_key_given"):
        keys.append("tacacs key")
    if cap.get("radius_secret_given"):
        keys.append("radius secret")
    print(f"tshark: {cap.get('tshark')} | keys given: {', '.join(keys) or 'none'}")
    print(f"Overall: {STATUS_MARK.get(report['overall_status'], report['overall_status'])}")
    print(f"Verdict: {report['verdict']}")
    radius = report.get("radius", [])
    if radius:
        print()
        print("RADIUS:")
        for e in radius:
            print(f"  {e['kind']:<10} id {str(e['id']):<4} {str(e['username'] or '?'):<14} "
                  f"{str(e['request_code'] or '')} -> {str(e['response_code'] or '-'):<18} [{e['result']}]"
                  + (f" acct {e['acct_status']}" if e.get("acct_status") else "")
                  + ("" if e["authenticator_valid"] is not False else "  BAD AUTHENTICATOR")
                  + (f"  Message-Authenticator {e['message_authenticator'].get('request') or '-'}/"
                     f"{e['message_authenticator'].get('response') or '-'}"))
    tacacs = report.get("tacacs", [])
    if tacacs:
        print()
        print("TACACS+:")
        for s in tacacs:
            flags = " CLEARTEXT" if s["cleartext"] else ""
            results = "/".join(x for x in (s["authentication"], s["authorization"], s["accounting"]) if x) or "-"
            print(f"  session {s['session_id']:#010x} {str(s['user'] or '?'):<12} "
                  f"{','.join(s['types']):<28} {results}{flags}")
    creds = report.get("credentials", [])
    if creds:
        print()
        print("🔑 Credentials recovered (values masked):")
        for c in creds:
            print(f"  [{c['protocol']}] {c['kind']} for {c.get('username') or '?'} on {c['flow']}")
    issues = report.get("issues", [])
    if issues:
        print()
        print(f"Issues ({len(issues)}):")
        for issue in issues[:30]:
            print(f"  [{issue['severity']}] {issue['code']}: {issue['message']}")


def build_aaa_markdown(report: Dict[str, Any]) -> str:
    """A markdown report for an AAA analysis."""
    if report.get("status") != "success":
        return f"# S.O.N.I.C. AAA report\n\nAnalysis failed: {report.get('error')}\n"
    cap = report["capture"]
    md = ["# S.O.N.I.C. TACACS+ and RADIUS troubleshooting", "",
          f"**File:** `{report['file']}`  ", f"**tshark:** {cap.get('tshark')}  ",
          f"**Overall:** {STATUS_MARK.get(report['overall_status'], report['overall_status'])}  ",
          f"**Verdict:** {report['verdict']}", ""]
    radius = report.get("radius", [])
    if radius:
        md += ["## RADIUS", "",
               _md_table([{"kind": e["kind"], "id": e["id"], "user": e["username"],
                           "request": e["request_code"], "response": e["response_code"], "result": e["result"],
                           "acct": e.get("acct_status") or "", "nas": e.get("nas") or "",
                           "authenticator": "valid" if e["authenticator_valid"] else
                           ("invalid" if e["authenticator_valid"] is False else "-"),
                           "msg_auth": "/".join(str(e["message_authenticator"].get(k) or "-")
                                                for k in ("request", "response")),
                           "credential": e.get("credential") or ""}
                          for e in radius],
                         ["kind", "id", "user", "request", "response", "result", "acct", "nas",
                          "authenticator", "msg_auth", "credential"]), ""]
    tacacs = report.get("tacacs", [])
    if tacacs:
        md += ["## TACACS+", "",
               _md_table([{"session": f"{s['session_id']:#010x}", "user": s["user"], "types": ", ".join(s["types"]),
                           "action": s["action"] or "", "service": s["service"] or "",
                           "authentication": s["authentication"] or "", "authorization": s["authorization"] or "",
                           "accounting": s["accounting"] or "", "cleartext": "yes" if s["cleartext"] else "",
                           "credential": s.get("credential") or ""}
                          for s in tacacs],
                         ["session", "user", "types", "action", "service", "authentication", "authorization",
                          "accounting", "cleartext", "credential"]), ""]
    creds = report.get("credentials", [])
    if creds:
        md += ["## Credentials recovered (values masked)", "",
               _md_table([{"protocol": c["protocol"], "flow": c["flow"], "user": c.get("username") or "",
                           "kind": c["kind"], "value": c["value"]} for c in creds],
                         ["protocol", "flow", "user", "kind", "value"]), ""]
    issues = report.get("issues", [])
    if issues:
        md += ["## Issues", ""]
        for issue in issues:
            frames = f" (frames {issue['frames']})" if issue.get("frames") else ""
            md.append(f"- **[{issue['severity']}] {issue['code']}**: {issue['message']}{frames}")
        md.append("")
    md += ["## Limits", ""]
    md.extend(f"- {line}" for line in report.get("limits", []))
    md += ["", "_Generated by S.O.N.I.C. AAA troubleshooting. Frame numbers match Wireshark's._"]
    return "\n".join(md) + "\n"


def save_aaa_report(report: Dict[str, Any], path: str) -> None:
    """Write the report as JSON (path ending in .json) or markdown (anything else), keys redacted."""
    from utils.credentials import redact, write_redacted
    if path.lower().endswith(".json"):
        write_redacted(path, json.dumps(redact(report), indent=2) + "\n")
    else:
        write_redacted(path, build_aaa_markdown(report))
