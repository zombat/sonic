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

from analyzers.network_orchestrator import audit_cleartext_capture  # noqa: E402
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


def main() -> int:
    os.chdir(ROOT)
    generate_records()
    generate_cleartext_audit()
    print(f"Generated {len(RECORD_FIXTURES)} record golden files and {len(AUDIT_FIXTURES) + 2} audit golden files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
