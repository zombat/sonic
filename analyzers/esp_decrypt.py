#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. IPsec ESP decryption and inner-traffic analysis (from SA keys)

Given a Security Association file an operator supplies (an SA file in S.O.N.I.C.'s format,
or the output of `ip -s xfrm state`), S.O.N.I.C. decrypts ESP with Wireshark's own ESP
decryption through tshark, reconstructs each decrypted inner IP packet into a new capture,
and runs the existing network detectors over that inner traffic. It reports, per SA, how
many ESP packets it saw and how many it decrypted, and then the inner traffic the keys
revealed.

The SA keys are secrets: they are read by path, written to tshark's esp_sa UAT inside a
private temporary directory (never on the command line), and never logged, returned or
written to a report. The reconstructed inner capture is a temporary file, removed when the
analysis ends.

Cisco IOS (and IOS XE) does not expose ESP session keys, so a capture of a Cisco IOS tunnel
cannot be decrypted this way: this feature is for SAs whose keys an operator can read, such as
a Linux/strongSwan endpoint's `ip xfrm state`.

Author: Raymond A Rizzo | Zombat
"""

import os
import tempfile
from typing import Any, Dict, List, Optional

from analyzers.network_common import cap, make_issue, sort_issues, status_from_issues
from extractors.esp import SaError, decrypt_esp, parse_sa_file, tshark_available, tshark_version

REPORT_SCHEMA = "sonic.esp_decrypt_report/1"

LIMITS = [
    "Only ESP packets whose (src, dst, SPI) matches an SA, and whose keys and algorithms are correct, decrypt; a "
    "wrong key, a missing SA or NULL-but-undeclared encryption leaves the packet encrypted.",
    "Cisco IOS and IOS XE do not expose ESP session keys, so a capture of a Cisco IOS tunnel cannot be decrypted "
    "this way. This feature is for SAs whose keys an operator can read (a Linux/strongSwan endpoint's ip xfrm "
    "state, a lab).",
    "A packet counts as decrypted only when its decrypted ESP trailer is real: the RFC 4303 default padding "
    "(1, 2, 3, ...), a real next header, and in tunnel mode an inner IP packet whose own length is the payload's. "
    "tshark fills its decrypted-data field under a wrong key too, so its presence proves nothing.",
    "Tunnel-mode inner packets are analysed as sent; a transport-mode payload is given back its outer IP "
    "header (the SA's addresses), so ports and payload are the sender's but the IP header is rebuilt.",
    "The inner analysis sees only what the ESP packets carried; a one-way capture shows one direction of the "
    "inner conversation.",
    "SA keys are secrets: read by path, kept off the tshark command line, and never written to a record, a log "
    "or a report.",
]


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


def _write_inner_pcap(inner: List[Dict[str, Any]], path: str) -> int:
    """Reconstruct the decrypted inner IP packets into a pcap; returns the number written."""
    from scapy.all import Ether, IP, IPv6, wrpcap
    packets = []
    for pkt in sorted(inner, key=lambda p: p["t"]):
        raw = pkt["bytes"]
        try:
            layer = IPv6(raw) if (raw[0] >> 4) == 6 else IP(raw)
        except Exception:  # noqa: BLE001 - a malformed inner packet is skipped, not fatal
            continue
        frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layer
        frame.time = pkt["t"]
        packets.append(frame)
    if packets:
        wrpcap(path, packets)
    return len(packets)


def analyze_esp_capture(file_path: str, sa_file: Optional[str] = None, detectors: Optional[List[str]] = None,
                        display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                        max_items: int = 25) -> Dict[str, Any]:
    """
    Decrypt ESP with the SA keys and analyze the inner traffic.

    Returns the report (status "success") or {"status": "error", "error": ...}.
    """
    if not file_path or not os.path.exists(file_path):
        return _error(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        return _error(f"File not readable: {file_path}")
    if not tshark_available():
        return _error("ESP decryption needs tshark (Wireshark's ESP decryption); install it")
    if not sa_file:
        return _error("ESP decryption needs an SA file (sa_file): S.O.N.I.C.'s SA format or `ip xfrm state` output")
    if not os.path.isfile(sa_file) or not os.access(sa_file, os.R_OK):
        return _error("sa_file is not a readable file")
    if max_packets is not None and int(max_packets) <= 0:
        return _error("max_packets must be a positive number")
    max_items = max(1, int(max_items or 25))
    try:
        with open(sa_file, "r", encoding="utf-8") as handle:
            sas = parse_sa_file(handle.read())
    except SaError as exc:
        return _error(f"cannot read the SA file: {exc}")
    except OSError as exc:
        return _error(f"cannot read the SA file: {exc.strerror or type(exc).__name__}")

    try:
        inner, stats, table_warnings = decrypt_esp(file_path, sas, display_filter=display_filter,
                                                   max_packets=max_packets)
    except (RuntimeError, SaError) as exc:
        return _error(str(exc))

    inner_analysis = None
    inner_pcap_written = 0
    tmp_dir = tempfile.mkdtemp(prefix="sonic-esp-")
    try:
        inner_pcap = os.path.join(tmp_dir, "inner.pcap")
        inner_pcap_written = _write_inner_pcap(inner, inner_pcap)
        if inner_pcap_written:
            from analyzers.network_orchestrator import analyze_network_capture
            inner_analysis = analyze_network_capture(inner_pcap, detectors=detectors, include_sip=True,
                                                     max_items=max_items, backend="tshark")
    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

    sa_rows = sorted(({k: v for k, v in s.items() if not k.startswith("_")} for s in stats.values()),
                     key=lambda s: (s["src"], s["dst"], s["spi"]))
    issues: List[Dict[str, Any]] = []
    for sa in sa_rows:
        sa["reason"] = _sa_reason(sa)
        label = f"SA {sa['src']} -> {sa['dst']} SPI {sa['spi']}"
        if sa["packets"] == 0:
            issues.append(make_issue("warning", "ESP_SA_NO_PACKETS", f"{label}: {sa['reason']}"))
        elif sa["decrypted"] == 0:
            issues.append(make_issue("error", "ESP_SA_NOT_DECRYPTED", f"{label}: {sa['reason']}"))
        elif sa["decrypted"] < sa["packets"]:
            issues.append(make_issue("warning", "ESP_SA_PARTIAL", f"{label}: {sa['reason']}"))

    for line in table_warnings:
        issues.append(make_issue("error", "ESP_SA_TABLE_REFUSED", f"tshark refused a row of the SA table: {line}"))

    total_pkts = sum(s["packets"] for s in sa_rows)
    total_dec = sum(s["decrypted"] for s in sa_rows)
    present = total_pkts > 0 or bool(sas)
    verdict = _verdict(sa_rows, total_pkts, total_dec, inner_pcap_written, inner_analysis)

    listed_sas, sas_omitted = cap(sa_rows, max_items)
    report = {
        "status": "success",
        "schema": REPORT_SCHEMA,
        "file": file_path,
        "overall_status": status_from_issues(issues, present),
        "verdict": verdict,
        "capture": {
            "tshark": tshark_version(),
            "sa_count": len(sas),
            "esp_packets": total_pkts, "esp_decrypted": total_dec,
            "inner_packets_reconstructed": inner_pcap_written,
            "warnings": table_warnings,
            "display_filter": display_filter, "max_packets": max_packets,
        },
        "summary": {
            "security_associations": len(sa_rows),
            "esp_packets": total_pkts, "esp_decrypted": total_dec,
            "sas_decrypting": sum(1 for s in sa_rows if s["decrypted"] > 0),
        },
        "security_associations": listed_sas,
        "security_associations_omitted": sas_omitted,
        "inner_analysis": _inner_summary(inner_analysis) if inner_analysis else None,
        "issues": sort_issues(issues),
        "limits": LIMITS,
    }
    return report


def _sa_reason(sa: Dict[str, Any]) -> Optional[str]:
    """Why an SA decrypted nothing (or not everything), from tshark's ICV check and the trailers."""
    if sa["packets"] == 0:
        return ("no ESP packet in the capture matched this SA: wrong addresses or SPI, the other direction's SA, "
                "or the traffic is not in this capture")
    if sa["decrypted"] == sa["packets"]:
        return None
    failed = sa["packets"] - sa["decrypted"]
    aead = "gcm" in str(sa.get("encryption") or "").lower()
    if sa["icv_bad"]:
        what = "the key (for AES-GCM the key and its 4-byte salt)" if aead else "the integrity key or algorithm"
        return (f"{sa['icv_bad']} of {sa['packets']} packet(s) failed the integrity check: {what} is wrong, or the "
                "packets were altered")
    if sa["icv_good"] >= failed and not aead:
        return (f"{failed} of {sa['packets']} packet(s) did not decrypt although their integrity check passed: the "
                "integrity key is right, so the encryption key or algorithm is wrong")
    return (f"{failed} of {sa['packets']} packet(s) did not decrypt: the key or algorithm is wrong (or the sender "
            "pads with something other than the RFC 4303 default, which S.O.N.I.C. uses to prove a decryption)")


def _inner_summary(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """A compact view of the inner-traffic analysis (the full network report is large)."""
    if analysis.get("status") != "success":
        return {"status": analysis.get("status"), "error": analysis.get("error")}
    out = {"status": "success", "protocols_present": analysis.get("protocols_present"),
           "overall_status": analysis.get("overall_status"), "verdicts": {}, "issues": []}
    for key, value in analysis.items():
        if isinstance(value, dict) and "verdict" in value:
            out["verdicts"][key] = value["verdict"]
    for key, value in analysis.items():
        if isinstance(value, dict):
            for issue in value.get("issues", [])[:10]:
                out["issues"].append({"detector": key, **{k: issue[k] for k in ("severity", "code", "message")
                                                          if k in issue}})
    out["issues"] = out["issues"][:40]
    return out


def _verdict(sa_rows, total_pkts, total_dec, inner_written, inner_analysis) -> str:
    if not sa_rows:
        return "No Security Association given."
    decrypting = sum(1 for s in sa_rows if s["decrypted"] > 0)
    parts = [f"{len(sa_rows)} SA(s), {decrypting} decrypting",
             f"{total_dec} of {total_pkts} ESP packet(s) decrypted"]
    if inner_written:
        protos = (inner_analysis or {}).get("protocols_present") or []
        parts.append(f"{inner_written} inner packet(s) reconstructed"
                     + (f"; inner traffic: {', '.join(protos)}" if protos else ""))
    elif total_dec:
        parts.append("no inner packet could be reconstructed")
    return ". ".join(parts) + "."
