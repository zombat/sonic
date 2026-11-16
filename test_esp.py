#!/usr/bin/env python3
"""
Tests for IPsec ESP decryption from SA keys (analyzers/esp_decrypt.py, extractors/esp.py).

The synthetic fixture (esp_tunnel.pcap, built by tests/fixtures/generate_esp_fixtures.py with
scapy's IPsec support; the test names say synthetic) carries AES-CBC with HMAC-SHA1-96 and with
HMAC-SHA256-128, AES-GCM, a transport-mode SA and a NAT-T SA (ESP in UDP 4500). Every SA key is a
synthetic placeholder defined in the generator. The keys are written to an SA file and to an
`ip -s xfrm state` dump at test time and reach tshark only through its esp_sa table inside a
temporary WIRESHARK_CONFIG_DIR (never a command line); every assertion about them is that no key
appears in the report, the CLI output or the saved file.

Run with:  python3 -m unittest -q test_esp
"""

import filecmp
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from analyzers.esp_decrypt import analyze_esp_capture
from extractors.esp import SaError, _spi, esp_trailer, parse_sa_file, parse_xfrm_state, sa_uat_row

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
sys.path.insert(0, FIXTURES)
import generate_esp_fixtures as gen  # noqa: E402

HAVE_TSHARK = shutil.which("tshark") is not None
PCAP = os.path.join(FIXTURES, "esp_tunnel.pcap")
KEYS = sorted({gen.SA_HEX["cbc_sha1"]["enc"], gen.SA_HEX["cbc_sha1"]["auth"], gen.SA_HEX["gcm"]["enc"],
               gen.SA_HEX["cbc_sha256"]["auth"]})


def codes(report):
    return [issue["code"] for issue in report["issues"]]


def by_spi(report):
    return {s["spi"]: s for s in report["security_associations"]}


def sa_text(spi, encryption, enc_key, integrity="", int_key=""):
    text = f"src: {gen.OUTER_A}\ndst: {gen.OUTER_B}\nspi: {spi:#010x}\nencryption: {encryption}\nencryption_key: 0x{enc_key}\n"
    if integrity:
        text += f"integrity: {integrity}\nintegrity_key: 0x{int_key}\n"
    return text


class TestSaParsing(unittest.TestCase):
    """The SA-file and `ip xfrm state` parsers, the esp_sa table row and the trailer check."""

    def test_sa_file_records(self):
        sas = parse_sa_file(gen.sa_file_text())
        self.assertEqual([sa["encryption"] for sa in sas], ["aes-cbc", "aes-gcm", "aes-cbc", "aes-cbc", "aes-gcm"])

    def test_xfrm_import_enc_auth_and_aead(self):
        sas = parse_xfrm_state(gen.xfrm_state_text())
        self.assertEqual([(sa["src"], _spi(sa["spi"]), sa["encryption"], sa["integrity"]) for sa in sas],
                         [(gen.OUTER_A, f"{gen.SPI_CBC_SHA1:#010x}", "aes-cbc", "hmac-sha1-96"),
                          (gen.OUTER_B, f"{gen.SPI_GCM:#010x}", "aes-gcm-16", "none")])
        self.assertEqual(parse_sa_file(gen.xfrm_state_text()), sas)  # the SA file reader detects a dump

    def test_uat_row_maps_to_wireshark_labels(self):
        sas = parse_sa_file(gen.sa_file_text())
        self.assertIn('"AES-CBC [RFC3602]"', sa_uat_row(sas[0]))
        self.assertIn('"HMAC-SHA-1-96 [RFC2404]"', sa_uat_row(sas[0]))
        self.assertTrue(sa_uat_row(sas[1]).endswith('"AES-GCM with 16 octet ICV [RFC4106]",'
                                                    f'"0x{gen.SA_HEX["gcm"]["enc"]}","NULL",""'))

    def test_spi_has_one_canonical_form(self):
        self.assertEqual(_spi("0x100"), "0x00000100")
        self.assertEqual(_spi("256"), "0x00000100")
        self.assertEqual(_spi("0x00001001"), "0x00001001")
        with self.assertRaises(SaError):
            _spi("0x1ffffffff")

    def test_refusals_never_echo_a_key(self):
        for sa in ({"src": "a", "dst": "b", "spi": "0x1", "encryption": "rot13"},
                   {"src": "a", "dst": "b", "spi": "0x1", "encryption": "aes-cbc", "encryption_key": "0xsecretkey99"}):
            with self.assertRaises(SaError) as caught:
                sa_uat_row(sa)
            self.assertNotIn("secret", str(caught.exception))

    def test_trailer_proves_a_decryption(self):
        payload = b"\x45" + bytes(19)
        self.assertEqual(esp_trailer(payload + bytes([1, 2, 3]) + bytes([3, 4])), (payload, 4))
        self.assertEqual(esp_trailer(payload + bytes([0, 6])), (payload, 6))
        self.assertIsNone(esp_trailer(payload + bytes([9, 9, 9]) + bytes([3, 4])))  # padding not 1, 2, 3
        self.assertIsNone(esp_trailer(payload + bytes([0, 0x6A])))  # no such next header


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSyntheticEspDecryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.sa_file = os.path.join(cls.tmp, "sa.txt")
        with open(cls.sa_file, "w") as handle:
            handle.write(gen.sa_file_text())
        cls.report = analyze_esp_capture(PCAP, sa_file=cls.sa_file)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def analyze(self, text):
        path = os.path.join(self.tmp, "variant.txt")
        with open(path, "w") as handle:
            handle.write(text)
        return analyze_esp_capture(PCAP, sa_file=path)

    def test_synthetic_every_sa_decrypts(self):
        self.assertEqual(self.report["status"], "success")
        summary = self.report["summary"]
        self.assertEqual((summary["security_associations"], summary["esp_packets"], summary["esp_decrypted"]),
                         (5, 7, 7))
        self.assertEqual(codes(self.report), [])

    def test_synthetic_per_sa_what_decrypted(self):
        sas = by_spi(self.report)
        expect = {gen.SPI_CBC_SHA1: (2, 2, 0), gen.SPI_GCM: (2, 2, 0), gen.SPI_CBC_SHA256: (1, 1, 0),
                  gen.SPI_TRANSPORT: (1, 0, 1), gen.SPI_NATT: (1, 1, 0)}
        for spi, (decrypted, tunnel, transport) in expect.items():
            with self.subTest(spi=hex(spi)):
                sa = sas[f"{spi:#010x}"]
                self.assertEqual((sa["decrypted"], sa["tunnel"], sa["transport"]), (decrypted, tunnel, transport))
                self.assertEqual(sa["icv_bad"], 0)
                self.assertIsNone(sa["reason"])

    def test_synthetic_existing_detectors_run_over_the_inner_traffic(self):
        inner = self.report["inner_analysis"]
        self.assertEqual(inner["status"], "success")
        self.assertEqual(set(inner["protocols_present"]) & {"icmp", "tcp"}, {"icmp", "tcp"})
        self.assertIn("answered", inner["verdicts"]["reachability"])
        self.assertIn("tcp", inner["verdicts"])
        self.assertEqual(self.report["capture"]["inner_packets_reconstructed"], 7)

    def test_synthetic_wrong_encryption_key_with_the_right_integrity_key(self):
        report = self.analyze(sa_text(gen.SPI_CBC_SHA1, "aes-cbc", "ff" * 16, "hmac-sha1-96",
                                      gen.SA_HEX["cbc_sha1"]["auth"]))
        sa = by_spi(report)[f"{gen.SPI_CBC_SHA1:#010x}"]
        self.assertEqual((sa["decrypted"], sa["icv_good"], sa["icv_bad"]), (0, 2, 0))
        self.assertIn("the integrity key is right, so the encryption key or algorithm is wrong", sa["reason"])
        self.assertIn("ESP_SA_NOT_DECRYPTED", codes(report))

    def test_synthetic_wrong_integrity_key(self):
        report = self.analyze(sa_text(gen.SPI_CBC_SHA1, "aes-cbc", gen.SA_HEX["cbc_sha1"]["enc"], "hmac-sha1-96",
                                      "ee" * 20))
        sa = by_spi(report)[f"{gen.SPI_CBC_SHA1:#010x}"]
        self.assertEqual((sa["decrypted"], sa["icv_bad"]), (0, 2))
        self.assertIn("failed the integrity check", sa["reason"])

    def test_synthetic_wrong_gcm_key_fails_its_tag(self):
        report = self.analyze(sa_text(gen.SPI_NATT, "aes-gcm", "dd" * 20))
        sa = by_spi(report)[f"{gen.SPI_NATT:#010x}"]
        self.assertEqual((sa["decrypted"], sa["icv_bad"]), (0, 1))
        self.assertIn("4-byte salt", sa["reason"])

    def test_synthetic_null_encryption(self):
        """ESP with NULL encryption (RFC 2410): readable with its SA, and the table takes the ESP NULL label."""
        from scapy.all import ICMP, IP, Ether, Raw
        from scapy.layers.ipsec import ESP, SecurityAssociation
        from generate_dataplane_fixtures import Capture
        sa = SecurityAssociation(ESP, spi=0x5001, crypt_algo="NULL", crypt_key=None, auth_algo="HMAC-SHA1-96",
                                 auth_key=gen.KEY_SHA1, tunnel_header=IP(src=gen.OUTER_A, dst=gen.OUTER_B))
        cap = Capture()
        cap.add(0.0, Ether() / sa.encrypt(IP(src=gen.INNER_A, dst=gen.INNER_B) / ICMP() / Raw(b"null-esp")))
        pcap = os.path.join(self.tmp, "null.pcap")
        cap.write(pcap)
        sa_file = os.path.join(self.tmp, "null.txt")
        with open(sa_file, "w") as handle:
            handle.write(sa_text(0x5001, "null", "", "hmac-sha1-96", gen.SA_HEX["cbc_sha1"]["auth"]))
        report = analyze_esp_capture(pcap, sa_file=sa_file)
        self.assertEqual(report["capture"]["warnings"], [])
        self.assertEqual(report["summary"]["esp_decrypted"], 1)

    def test_synthetic_sa_with_no_packets(self):
        report = self.analyze(sa_text(0x0000BEEF, "aes-cbc", "00" * 16, "hmac-sha1-96", "00" * 20))
        self.assertIn("ESP_SA_NO_PACKETS", codes(report))
        self.assertIsNone(report["inner_analysis"])

    def test_synthetic_xfrm_dump_decrypts(self):
        report = self.analyze(gen.xfrm_state_text())
        self.assertEqual((report["summary"]["security_associations"], report["summary"]["esp_decrypted"]), (2, 4))

    def test_synthetic_no_key_in_report(self):
        blob = json.dumps(self.report)
        self.assertNotIn(self.sa_file, blob)
        for key in KEYS:
            self.assertNotIn(key, blob)

    def test_missing_or_unreadable_sa_file_is_an_error(self):
        self.assertEqual(analyze_esp_capture(PCAP)["status"], "error")
        self.assertEqual(analyze_esp_capture(PCAP, sa_file="/nonexistent")["status"], "error")
        self.assertEqual(self.analyze("# no SA here\n")["status"], "error")


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestEspInterfaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.sa_file = os.path.join(cls.tmp, "sa.txt")
        with open(cls.sa_file, "w") as handle:
            handle.write(gen.sa_file_text())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_mcp_tool_function(self):
        import mcp_server
        tool = mcp_server.analyze_esp_pcap
        fn = getattr(tool, "fn", tool)
        report = fn(file_path=PCAP, sa_file=self.sa_file)
        self.assertEqual(report["summary"]["esp_decrypted"], 7)
        self.assertEqual(fn(file_path="/nonexistent.pcap", sa_file=self.sa_file)["status"], "error")

    def test_cli_json_and_markdown_hold_no_key(self):
        md = os.path.join(self.tmp, "r.md")
        out = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", PCAP, "--esp-decrypt",
                              "--esp-sa", self.sa_file, "--json", "--save_file", md],
                             capture_output=True, text=True, cwd=HERE)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["summary"]["esp_decrypted"], 7)
        with open(md) as handle:
            texts = [out.stdout, out.stderr, handle.read()]
        for text in texts:
            for key in KEYS:
                self.assertNotIn(key, text)


class TestEspFixtures(unittest.TestCase):
    def test_synthetic_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_esp_fixtures.py"), out],
                           check=True, capture_output=True)
            self.assertEqual(sorted(os.listdir(out)), ["esp_tunnel.pcap"])
            self.assertTrue(filecmp.cmp(os.path.join(out, "esp_tunnel.pcap"), PCAP, shallow=False),
                            "esp_tunnel.pcap differs from a fresh generation; rerun generate_esp_fixtures.py")


if __name__ == "__main__":
    unittest.main()
