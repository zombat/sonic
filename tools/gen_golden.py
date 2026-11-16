#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Golden JSON oracle generator for the S.O.N.I.C. Go migration.

Runs the Python extractor and deterministic analyzers over synthetic fixtures in
tests/fixtures/ and writes normalized, sorted JSON outputs into testdata/golden/.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.esp_overhead import EspOverheadDetector  # noqa: E402
from analyzers.network_common import Context  # noqa: E402
from analyzers.network_orchestrator import audit_cleartext_capture  # noqa: E402
from analyzers.path_mtu import PathMtuDetector  # noqa: E402
from analyzers.qos import QosDetector  # noqa: E402
from analyzers.reachability import ConversationDetector, ReachabilityDetector  # noqa: E402
from analyzers.tcp_health import TcpHealthDetector  # noqa: E402
from analyzers.tls_inspect import TlsDetector  # noqa: E402
from extractors.network import open_network_records  # noqa: E402

RECORD_FIXTURES = [
    "audit_one_leak.pcap",
    "ipsec_cleartext_icmp.pcap",
    "ipsec_ikev2_esp.pcap",
    "ipsec_natt.pcap",
    "ikev2_negotiation.pcap",
    "gre_nhrp.pcap",
    "bgp_session.pcap",
    "ospf_hello_mismatch.pcap",
    "eigrp_mismatch.pcap",
    "icmp_loss.pcap",
    "dp_fragments.pcap",
    "dp_tcp_health.pcap",
    "dp_tls.pcap",
    "dp_esp_sizes.pcap",
    "dp_pmtu_black_hole.pcap",
    "dp_pmtu_frag_needed.pcap",
    "dp_qos_rtp.pcap",
    "grpc_tls12_alert.pcap",
    "grpc_tls13_hrr.pcap",
    "enc_midstream.pcap",
    "enc_port22_text.pcap",
    "enc_ssh_cbc.pcap",
    "enc_ssh_none.pcap",
    "enc_tls10.pcap",
    "enc_tls12_null.pcap",
    "enc_tls13_integrity_only.pcap",
]

AUDIT_FIXTURES = [
    "audit_one_leak.pcap",
    "ipsec_cleartext_icmp.pcap",
    "ipsec_ikev2_esp.pcap",
    "ipsec_natt.pcap",
    "enc_midstream.pcap",
    "enc_port22_text.pcap",
    "enc_ssh_cbc.pcap",
    "enc_ssh_none.pcap",
    "enc_tls10.pcap",
    "enc_tls12_null.pcap",
    "enc_tls13_integrity_only.pcap",
]


def _normalize(value: Any) -> Any:
    """Recursively convert bytes values (such as dp['pl']) to lowercase hex strings."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(_normalize(data), indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")


def run_detector(file_path: str, detector: Any) -> Any:
    """Open records via tshark, compute start/end context, feed detector, and return report."""
    extraction = open_network_records(file_path, backend="tshark")
    start = end = None
    for rec in extraction.records:
        t = rec.get("t")
        if t:
            start = t if start is None or t < start else start
            end = t if end is None or t > end else end
        detector.feed(rec)
    return detector.report(Context(start, end, max_items=25))


def generate_records() -> None:
    """Generate testdata/golden/records/*.json using tshark."""
    out_dir = ROOT / "testdata" / "golden" / "records"
    for name in RECORD_FIXTURES:
        rel_fixture = os.path.join("tests", "fixtures", name)
        extraction = open_network_records(rel_fixture, backend="tshark")
        records = list(extraction.records)
        payload = {
            "backend": extraction.backend,
            "missing_fields": extraction.info.get("missing_fields", []),
            "warnings": extraction.info.get("warnings", []),
            "records": records,
        }
        stem = Path(name).stem
        _write_json(out_dir / f"{stem}.json", payload)


def generate_cleartext_audit() -> None:
    """Generate testdata/golden/cleartext_audit/*.json using tshark."""
    out_dir = ROOT / "testdata" / "golden" / "cleartext_audit"
    for name in AUDIT_FIXTURES:
        rel_fixture = os.path.join("tests", "fixtures", name)
        report = audit_cleartext_capture(rel_fixture, backend="tshark")
        stem = Path(name).stem
        _write_json(out_dir / f"{stem}.json", report)

    for name, out_name in (
        ("audit_one_leak.pcap", "audit_one_leak_allow_crypto.json"),
        ("enc_tls10.pcap", "enc_tls10_allow_crypto.json"),
    ):
        rel_fixture = os.path.join("tests", "fixtures", name)
        report = audit_cleartext_capture(rel_fixture, allow=["crypto"], backend="tshark")
        _write_json(out_dir / out_name, report)


def generate_leaf_detectors() -> int:
    """Generate golden baselines for Phase 2 leaf detectors and return total file count."""
    count = 0
    suites = [
        ("reachability", [
            ("icmp_loss.pcap", "icmp_loss.json", lambda: ReachabilityDetector()),
            ("audit_one_leak.pcap", "audit_one_leak.json", lambda: ReachabilityDetector()),
            ("ipsec_cleartext_icmp.pcap", "ipsec_cleartext_icmp.json", lambda: ReachabilityDetector()),
            ("dp_pmtu_frag_needed.pcap", "dp_pmtu_frag_needed.json", lambda: ReachabilityDetector()),
        ]),
        ("conversations", [
            ("ipsec_ikev2_esp.pcap", "ipsec_ikev2_esp.json", lambda: ConversationDetector()),
            ("audit_one_leak.pcap", "audit_one_leak.json", lambda: ConversationDetector()),
            ("icmp_loss.pcap", "icmp_loss.json", lambda: ConversationDetector()),
            ("dp_tcp_health.pcap", "dp_tcp_health.json", lambda: ConversationDetector()),
        ]),
        ("qos", [
            ("dp_qos_rtp.pcap", "dp_qos_rtp.json", lambda: QosDetector()),
            ("dp_esp_sizes.pcap", "dp_esp_sizes.json", lambda: QosDetector()),
            ("ipsec_ikev2_esp.pcap", "ipsec_ikev2_esp.json", lambda: QosDetector()),
        ]),
        ("path_mtu", [
            ("dp_pmtu_frag_needed.pcap", "dp_pmtu_frag_needed.json", lambda: PathMtuDetector()),
            ("dp_pmtu_black_hole.pcap", "dp_pmtu_black_hole.json", lambda: PathMtuDetector()),
            ("dp_fragments.pcap", "dp_fragments.json", lambda: PathMtuDetector()),
            ("icmp_loss.pcap", "icmp_loss.json", lambda: PathMtuDetector()),
        ]),
        ("esp_overhead", [
            ("dp_esp_sizes.pcap", "dp_esp_sizes.json", lambda: EspOverheadDetector()),
            ("dp_esp_sizes.pcap", "dp_esp_sizes_mtu1400.json", lambda: EspOverheadDetector(tunnel_mtu=1400)),
            ("dp_esp_sizes.pcap", "dp_esp_sizes_mtu1476.json", lambda: EspOverheadDetector(tunnel_mtu=1476)),
            ("ipsec_ikev2_esp.pcap", "ipsec_ikev2_esp.json", lambda: EspOverheadDetector()),
            ("dp_fragments.pcap", "dp_fragments.json", lambda: EspOverheadDetector()),
        ]),
        ("tcp", [
            ("dp_tcp_health.pcap", "dp_tcp_health.json", lambda: TcpHealthDetector()),
            ("dp_tls.pcap", "dp_tls.json", lambda: TcpHealthDetector()),
            ("bgp_session.pcap", "bgp_session.json", lambda: TcpHealthDetector()),
            ("enc_ssh_cbc.pcap", "enc_ssh_cbc.json", lambda: TcpHealthDetector()),
        ]),
        ("tls", [
            ("dp_tls.pcap", "dp_tls.json", lambda: TlsDetector()),
            ("dp_tls.pcap", "dp_tls_baseline_tls13.json", lambda: TlsDetector(baseline={"versions": ["TLS1.3"]})),
            ("enc_tls10.pcap", "enc_tls10.json", lambda: TlsDetector()),
            ("enc_tls12_null.pcap", "enc_tls12_null.json", lambda: TlsDetector()),
            ("enc_tls13_integrity_only.pcap", "enc_tls13_integrity_only.json", lambda: TlsDetector()),
            ("grpc_tls12_alert.pcap", "grpc_tls12_alert.json", lambda: TlsDetector()),
            ("grpc_tls13_hrr.pcap", "grpc_tls13_hrr.json", lambda: TlsDetector()),
        ]),
    ]
    for folder, cases in suites:
        out_dir = ROOT / "testdata" / "golden" / folder
        for pcap_name, out_name, make_det in cases:
            rel_fixture = os.path.join("tests", "fixtures", pcap_name)
            report = run_detector(rel_fixture, make_det())
            _write_json(out_dir / out_name, report)
            count += 1
    return count


def main() -> int:
    os.chdir(ROOT)
    generate_records()
    generate_cleartext_audit()
    leaf_count = generate_leaf_detectors()
    print(
        f"Generated {len(RECORD_FIXTURES)} record golden files, "
        f"{len(AUDIT_FIXTURES) + 2} audit golden files, and {leaf_count} leaf detector golden files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
