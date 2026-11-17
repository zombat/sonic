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
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.aaa_inspect import analyze_aaa_capture  # noqa: E402
from analyzers.convergence import ConvergenceDetector  # noqa: E402
from analyzers.dmvpn_phase3 import DmvpnPhase3Detector  # noqa: E402
from analyzers.esp_decrypt import analyze_esp_capture  # noqa: E402
from analyzers.esp_overhead import EspOverheadDetector  # noqa: E402
from analyzers.gre_nhrp import GreNhrpDetector  # noqa: E402
import analyzers.grpc_inspect as grpc_inspect  # noqa: E402
from analyzers.http_inspect import analyze_http_capture  # noqa: E402
from analyzers.ipsec_vpn import IPsecDetector  # noqa: E402
from analyzers.network_common import Context  # noqa: E402
from analyzers.network_orchestrator import (  # noqa: E402
    analyze_convergence_capture,
    analyze_data_plane_capture,
    analyze_network_capture,
    analyze_routing_capture,
    analyze_vpn_capture,
    audit_cleartext_capture,
)
from analyzers.path_mtu import PathMtuDetector  # noqa: E402
from analyzers.qos import QosDetector  # noqa: E402
from analyzers.reachability import ConversationDetector, ReachabilityDetector  # noqa: E402
from analyzers.routing_health import RoutingDetector  # noqa: E402
from analyzers.snmp_inspect import analyze_snmp_capture  # noqa: E402
from analyzers.tcp_health import TcpHealthDetector  # noqa: E402
from analyzers.tls_inspect import TlsDetector  # noqa: E402
from extractors.network import open_network_records  # noqa: E402
from tests.fixtures.generate_aaa_fixtures import RADIUS_SECRET, TACACS_KEY  # noqa: E402
from tests.fixtures.generate_esp_fixtures import sa_file_text, xfrm_state_text  # noqa: E402

RECORD_FIXTURES = [
    "audit_one_leak.pcap",
    "ipsec_cleartext_icmp.pcap",
    "ipsec_ikev2_esp.pcap",
    "ipsec_natt.pcap",
    "ikev1.pcap",
    "ikev2_failures.pcap",
    "ikev2_negotiation.pcap",
    "ikev2_no_proposal.pcap",
    "ikev2_no_response.pcap",
    "esp_stale_spi.pcap",
    "gre_nhrp.pcap",
    "nhrp_phase3_broken.pcap",
    "phase3_encrypted.pcap",
    "bgp_session.pcap",
    "bgp_failover.pcap",
    "ospf_hello_mismatch.pcap",
    "ospf_failover.pcap",
    "ospf_stuck.pcap",
    "eigrp_mismatch.pcap",
    "routing_over_gre.pcap",
    "convergence_dpd.pcap",
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
        ("gre_nhrp", [
            ("gre_nhrp.pcap", "gre_nhrp.json", lambda: GreNhrpDetector()),
            ("nhrp_phase3_broken.pcap", "nhrp_phase3_broken.json", lambda: GreNhrpDetector()),
            ("routing_over_gre.pcap", "routing_over_gre.json", lambda: GreNhrpDetector()),
            ("audit_one_leak.pcap", "audit_one_leak.json", lambda: GreNhrpDetector()),
        ]),
        ("dmvpn_phase3", [
            ("gre_nhrp.pcap", "gre_nhrp.json", lambda: DmvpnPhase3Detector()),
            ("nhrp_phase3_broken.pcap", "nhrp_phase3_broken.json", lambda: DmvpnPhase3Detector()),
            ("phase3_encrypted.pcap", "phase3_encrypted_no_hubs.json", lambda: DmvpnPhase3Detector()),
            ("phase3_encrypted.pcap", "phase3_encrypted_with_hubs.json", lambda: DmvpnPhase3Detector(hubs=["192.0.2.1", "192.0.2.2"])),
        ]),
        ("ipsec", [
            ("ipsec_ikev2_esp.pcap", "ipsec_ikev2_esp.json", lambda: IPsecDetector()),
            ("ipsec_cleartext_icmp.pcap", "ipsec_cleartext_icmp.json", lambda: IPsecDetector()),
            ("ipsec_natt.pcap", "ipsec_natt.json", lambda: IPsecDetector()),
            ("ikev1.pcap", "ikev1.json", lambda: IPsecDetector()),
            ("ikev2_failures.pcap", "ikev2_failures.json", lambda: IPsecDetector()),
            ("ikev2_negotiation.pcap", "ikev2_negotiation.json", lambda: IPsecDetector()),
            ("ikev2_no_proposal.pcap", "ikev2_no_proposal.json", lambda: IPsecDetector()),
            ("ikev2_no_response.pcap", "ikev2_no_response.json", lambda: IPsecDetector()),
            ("esp_stale_spi.pcap", "esp_stale_spi.json", lambda: IPsecDetector()),
            ("phase3_encrypted.pcap", "phase3_encrypted.json", lambda: IPsecDetector()),
            ("convergence_dpd.pcap", "convergence_dpd.json", lambda: IPsecDetector()),
        ]),
        ("routing", [
            ("bgp_session.pcap", "bgp_session.json", lambda: RoutingDetector()),
            ("bgp_failover.pcap", "bgp_failover.json", lambda: RoutingDetector()),
            ("bgp_failover.pcap", "bgp_failover_mss1360.json", lambda: RoutingDetector(expected_mss=1360)),
            ("ospf_hello_mismatch.pcap", "ospf_hello_mismatch.json", lambda: RoutingDetector()),
            ("ospf_failover.pcap", "ospf_failover.json", lambda: RoutingDetector()),
            ("ospf_stuck.pcap", "ospf_stuck.json", lambda: RoutingDetector()),
            ("eigrp_mismatch.pcap", "eigrp_mismatch.json", lambda: RoutingDetector()),
            ("routing_over_gre.pcap", "routing_over_gre.json", lambda: RoutingDetector()),
        ]),
        ("convergence", [
            ("convergence_dpd.pcap", "convergence_dpd.json", lambda: ConvergenceDetector()),
            ("convergence_dpd.pcap", "convergence_dpd_event30.json", lambda: ConvergenceDetector(event_time="+30.0", hold_time=30.0)),
            ("bgp_failover.pcap", "bgp_failover.json", lambda: ConvergenceDetector()),
            ("ospf_failover.pcap", "ospf_failover.json", lambda: ConvergenceDetector()),
            ("icmp_loss.pcap", "icmp_loss.json", lambda: ConvergenceDetector()),
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


def generate_stage3b1() -> int:
    """Generate golden baselines for SNMP, AAA, and HTTP/RESTCONF inspectors."""
    count = 0
    _write_json(
        ROOT / "testdata" / "golden" / "snmp" / "snmp_v1v2c.json",
        analyze_snmp_capture(os.path.join("tests", "fixtures", "snmp_v1v2c.pcap")),
    )
    count += 1

    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(f"tacacs_key: {TACACS_KEY}\nradius_secret: {RADIUS_SECRET}\n")
        handle.flush()
        aaa_cases = [
            ("aaa_radius.pcap", "aaa_radius_no_key.json", None),
            ("aaa_radius.pcap", "aaa_radius_with_key.json", handle.name),
            ("aaa_tacacs.pcap", "aaa_tacacs_no_key.json", None),
            ("aaa_tacacs.pcap", "aaa_tacacs_with_key.json", handle.name),
        ]
        for pcap_name, out_name, keys_path in aaa_cases:
            rep = analyze_aaa_capture(os.path.join("tests", "fixtures", pcap_name), keys_file=keys_path)
            _write_json(ROOT / "testdata" / "golden" / "aaa" / out_name, rep)
            count += 1

    for pcap_name, out_name in (
        ("restconf_cleartext.pcap", "restconf_cleartext.json"),
        ("dp_tls.pcap", "dp_tls.json"),
        ("grpc_mgmt_mix.pcap", "grpc_mgmt_mix.json"),
    ):
        rep = analyze_http_capture(os.path.join("tests", "fixtures", pcap_name))
        _write_json(ROOT / "testdata" / "golden" / "http_inspect" / out_name, rep)
        count += 1
    return count


def generate_stage3b2() -> int:
    """Generate golden baselines for gRPC, ESP decryption, and network orchestrator."""
    count = 0
    orig_resolve = grpc_inspect.resolve_proto_paths
    grpc_inspect.resolve_proto_paths = lambda p=None: list(p) if p else []
    try:
        grpc_cases = [
            "grpc_connection_trouble.pcap",
            "grpc_h2_trouble.pcap",
            "grpc_mgmt_mix.pcap",
            "grpc_tls12_alert.pcap",
            "grpc_tls13_hrr.pcap",
        ]
        for pcap_name in grpc_cases:
            stem = Path(pcap_name).stem
            rep = grpc_inspect.analyze_grpc_capture(os.path.join("tests", "fixtures", pcap_name), proto_paths=[])
            _write_json(ROOT / "testdata" / "golden" / "grpc" / f"{stem}.json", rep)
            count += 1

        net_cases = [
            ("net_ipsec_ikev2_esp.json", lambda: analyze_network_capture("tests/fixtures/ipsec_ikev2_esp.pcap", backend="tshark")),
            ("net_dp_qos_rtp.json", lambda: analyze_network_capture("tests/fixtures/dp_qos_rtp.pcap", backend="tshark")),
            ("vpn_ipsec_ikev2_esp.json", lambda: analyze_vpn_capture("tests/fixtures/ipsec_ikev2_esp.pcap", backend="tshark")),
            ("routing_bgp_failover.json", lambda: analyze_routing_capture("tests/fixtures/bgp_failover.pcap", backend="tshark", expected_mss=1360)),
            ("audit_grpc_mgmt_mix.json", lambda: audit_cleartext_capture("tests/fixtures/grpc_mgmt_mix.pcap", backend="tshark")),
            ("conv_dpd.json", lambda: analyze_convergence_capture("tests/fixtures/convergence_dpd.pcap", backend="tshark")),
            ("dataplane_tcp_health.json", lambda: analyze_data_plane_capture("tests/fixtures/dp_tcp_health.pcap", backend="tshark")),
        ]
        for out_name, fn in net_cases:
            _write_json(ROOT / "testdata" / "golden" / "network_orchestrator" / out_name, fn())
            count += 1
    finally:
        grpc_inspect.resolve_proto_paths = orig_resolve

    for out_name, text in (
        ("esp_tunnel_sa_file.json", sa_file_text()),
        ("esp_tunnel_xfrm.json", xfrm_state_text()),
    ):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            rep = analyze_esp_capture("tests/fixtures/esp_tunnel.pcap", sa_file=handle.name)
            _write_json(ROOT / "testdata" / "golden" / "esp_decrypt" / out_name, rep)
            count += 1
    return count


def main() -> int:
    os.chdir(ROOT)
    generate_records()
    generate_cleartext_audit()
    leaf_count = generate_leaf_detectors()
    stage3b1_count = generate_stage3b1()
    stage3b2_count = generate_stage3b2()
    print(
        f"Generated {len(RECORD_FIXTURES)} record golden files, "
        f"{len(AUDIT_FIXTURES) + 2} audit golden files, "
        f"{leaf_count} leaf detector golden files, "
        f"{stage3b1_count} stage 3b1 golden files, and "
        f"{stage3b2_count} stage 3b2 golden files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
