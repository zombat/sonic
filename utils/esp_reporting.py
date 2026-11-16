#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. ESP Decryption Report Formatting

Console summary and markdown/JSON report files for the ESP-decryption report produced by
analyzers/esp_decrypt.py. The report carries no SA key (the keys are read by path and kept
off every output), and files are written through the same redacting writer as every other
S.O.N.I.C. report.

Author: Raymond A Rizzo | Zombat
"""

import json
from typing import Any, Dict

from utils.network_reporting import STATUS_MARK, _md_table


def print_esp_summary(report: Dict[str, Any]) -> None:
    """Print a short human summary of an ESP-decryption report to stdout."""
    if report.get("status") != "success":
        print(f"ESP decryption failed: {report.get('error')}")
        return
    cap = report["capture"]
    print("=" * 80)
    print("S.O.N.I.C. IPsec ESP decryption and inner-traffic analysis (tshark, no LLM)")
    print("=" * 80)
    print(f"File: {report['file']}")
    print(f"tshark: {cap.get('tshark')} | SAs: {cap.get('sa_count')} | "
          f"ESP decrypted: {cap.get('esp_decrypted')}/{cap.get('esp_packets')}")
    print(f"Overall: {STATUS_MARK.get(report['overall_status'], report['overall_status'])}")
    print(f"Verdict: {report['verdict']}")
    print()
    print("Security Associations:")
    for s in report.get("security_associations", []):
        mode = ", ".join(f"{s[m]} {m}" for m in ("tunnel", "transport") if s.get(m))
        print(f"  {s['src']} -> {s['dst']} SPI {s['spi']} {s['encryption']}"
              + (f"/{s['integrity']}" if s.get("integrity") else "")
              + f": {s['decrypted']}/{s['packets']} decrypted" + (f" ({mode})" if mode else "")
              + f", ICV good {s.get('icv_good', 0)} bad {s.get('icv_bad', 0)}")
        if s.get("reason"):
            print(f"      {s['reason']}")
    inner = report.get("inner_analysis")
    if inner and inner.get("status") == "success":
        print()
        print(f"Inner traffic ({', '.join(inner.get('protocols_present') or []) or 'none'}):")
        for detector, verdict in (inner.get("verdicts") or {}).items():
            print(f"  {detector}: {verdict}")
        for issue in inner.get("issues", [])[:20]:
            print(f"  [{issue.get('severity')}] {issue.get('detector')}/{issue.get('code')}: {issue.get('message')}")
    issues = report.get("issues", [])
    if issues:
        print()
        print(f"Issues ({len(issues)}):")
        for issue in issues[:30]:
            print(f"  [{issue['severity']}] {issue['code']}: {issue['message']}")


def build_esp_markdown(report: Dict[str, Any]) -> str:
    """A markdown report for an ESP-decryption analysis."""
    if report.get("status") != "success":
        return f"# S.O.N.I.C. ESP decryption report\n\nAnalysis failed: {report.get('error')}\n"
    cap = report["capture"]
    md = ["# S.O.N.I.C. IPsec ESP decryption and inner-traffic analysis", "",
          f"**File:** `{report['file']}`  ", f"**tshark:** {cap.get('tshark')}  ",
          f"**Overall:** {STATUS_MARK.get(report['overall_status'], report['overall_status'])}  ",
          f"**Verdict:** {report['verdict']}", "",
          "## Security Associations", "",
          _md_table([{"src": s["src"], "dst": s["dst"], "spi": s["spi"], "encryption": s["encryption"],
                      "integrity": s.get("integrity") or "", "packets": s["packets"], "decrypted": s["decrypted"],
                      "tunnel": s.get("tunnel", 0), "transport": s.get("transport", 0),
                      "icv_good": s.get("icv_good", 0), "icv_bad": s.get("icv_bad", 0), "reason": s.get("reason") or ""}
                     for s in report.get("security_associations", [])],
                    ["src", "dst", "spi", "encryption", "integrity", "packets", "decrypted", "tunnel", "transport",
                     "icv_good", "icv_bad", "reason"]), ""]
    inner = report.get("inner_analysis")
    if inner and inner.get("status") == "success":
        md += ["## Inner traffic (decrypted)", "",
               f"Protocols present: {', '.join(inner.get('protocols_present') or []) or 'none'}.", ""]
        verdicts = inner.get("verdicts") or {}
        if verdicts:
            md.append(_md_table([{"detector": k, "verdict": v} for k, v in verdicts.items()], ["detector", "verdict"]))
            md.append("")
        if inner.get("issues"):
            md.append("Inner issues:")
            md.append("")
            for issue in inner["issues"]:
                md.append(f"- **[{issue.get('severity')}] {issue.get('detector')}/{issue.get('code')}**: "
                          f"{issue.get('message')}")
            md.append("")
    issues = report.get("issues", [])
    if issues:
        md += ["## Issues", ""]
        for issue in issues:
            frames = f" (frames {issue['frames']})" if issue.get("frames") else ""
            md.append(f"- **[{issue['severity']}] {issue['code']}**: {issue['message']}{frames}")
        md.append("")
    md += ["## Limits", ""]
    md.extend(f"- {line}" for line in report.get("limits", []))
    md += ["", "_Generated by S.O.N.I.C. ESP decryption. Frame numbers are of the reconstructed inner capture._"]
    return "\n".join(md) + "\n"


def save_esp_report(report: Dict[str, Any], path: str) -> None:
    """Write the report as JSON (path ending in .json) or markdown (anything else), keys redacted."""
    from utils.credentials import redact, write_redacted
    if path.lower().endswith(".json"):
        write_redacted(path, json.dumps(redact(report), indent=2) + "\n")
    else:
        write_redacted(path, build_esp_markdown(report))
