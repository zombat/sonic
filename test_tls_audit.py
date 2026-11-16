#!/usr/bin/env python3
"""
Tests for the cleartext audit's judgement of SSH and TLS by their handshake
(analyzers/cleartext_audit.py, with analyzers/tls_inspect.py's suite table): the default
allowlist (encrypted) passes an SSH or TLS session only when its handshake shows real
encryption, a NULL, anonymous, export or integrity-only TLS suite and the SSH cipher none
count as cleartext, weak ones pass with a warning, a session whose handshake is not in the
capture passes only as encrypted, unverified, and crypto keeps meaning IPsec only.

Synthetic fixtures (names start with enc_) are built by
tests/fixtures/generate_tls_audit_fixtures.py; the test names say so. TestRealCaptures
runs on two real captures when they are on this machine (SONIC_GRPC_CAPTURES names their
directory) and skips otherwise: S.O.N.I.C. commits only synthetic fixtures. The ciphers
expected there are derived from what tshark's own SSH and TLS dissectors read, not
written in this file.

Run with:  python3 -m unittest -q test_tls_audit
"""

import filecmp
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from analyzers.cleartext_audit import _parse_kexinit, _ssh_choose, _ssh_cipher
from analyzers.network_orchestrator import analyze_network_capture, audit_cleartext_capture
from analyzers.tls_inspect import CIPHER_SUITES, suite_encryption, suite_name, version_is_weak

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
sys.path.insert(0, FIXTURES)
import generate_tls_audit_fixtures as gen  # noqa: E402

HAVE_TSHARK = shutil.which("tshark") is not None
CAPTURES = os.environ.get("SONIC_GRPC_CAPTURES", "/home/noot/auto-roboto/.IGNORE/cml-capture/proj/captures")
PLAINTEXT = os.path.join(CAPTURES, "gnmi-plaintext.pcap")
ENCRYPTED = os.path.join(CAPTURES, "netconf-restconf-ssh.pcap")


def fixture(name):
    return os.path.join(FIXTURES, name)


def codes(report):
    return [issue["code"] for issue in report["issues"]]


class TestHandshakeKnowledge(unittest.TestCase):
    """The suite table and the SSH algorithm choice, without a capture."""

    def test_suites_that_do_not_encrypt(self):
        for code in (0x0000, 0x0002, 0x003B, 0xC010, 0x002C, 0xC0B4, 0xC0B5, 0x0034, 0xC018, 0x00A6, 0x0003,
                     0x0014, 0x0062):
            with self.subTest(suite=suite_name(code)):
                self.assertEqual(suite_encryption(code)[0], "cleartext")
        self.assertIn("integrity-only", suite_encryption(0xC0B4)[1])
        self.assertIn("anonymous", suite_encryption(0xC018)[1])
        self.assertIn("export", suite_encryption(0x0003)[1])

    def test_weak_strong_and_unknown_suites(self):
        for code in (0x0005, 0x000A, 0xC012, 0x0009):
            self.assertEqual(suite_encryption(code)[0], "weak", suite_name(code))
        for code in (0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA8, 0x009C, 0xC0AC, 0x002F):
            self.assertEqual(suite_encryption(code), ("encrypted", None), suite_name(code))
        self.assertEqual(suite_encryption(0x1234)[0], "unverified")
        self.assertTrue(version_is_weak("TLS1.1") and version_is_weak("TLS1.0") and version_is_weak("SSL3.0"))
        self.assertFalse(version_is_weak("TLS1.2") or version_is_weak("TLS1.3"))

    def test_ssh_choice_follows_the_client_order(self):
        # RFC 4253 7.1: the first algorithm on the client's list that the server also offers.
        self.assertEqual(_ssh_choose(["none", "aes128-ctr"], ["aes128-ctr", "none"]), "none")
        self.assertEqual(_ssh_choose(["aes128-ctr", "none"], ["none", "aes128-ctr"]), "aes128-ctr")
        self.assertIsNone(_ssh_choose(["aes128-gcm@openssh.com"], ["aes128-ctr"]))
        self.assertEqual(_ssh_cipher("none")[0], "cleartext")
        for name in ("arcfour", "arcfour256", "aes128-cbc", "3des-cbc", "rijndael-cbc@lysator.liu.se",
                     "blowfish-ctr"):
            self.assertEqual(_ssh_cipher(name)[0], "weak", name)
        for name in ("aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com",
                     "aes128-gcm"):
            self.assertEqual(_ssh_cipher(name), ("encrypted", None), name)
        self.assertEqual(_ssh_cipher("serpent256-ctr")[0], "unverified")

    def test_kexinit_name_lists(self):
        packet = gen.kexinit("x", b"aes128-cbc,aes128-ctr", b"hmac-sha2-256,none")
        parsed = _parse_kexinit(packet[5:5 + int.from_bytes(packet[:4], "big") - 1 - packet[4]])
        self.assertEqual(parsed["cipher_client_to_server"], ["aes128-cbc", "aes128-ctr"])
        self.assertEqual(parsed["mac_server_to_client"], ["hmac-sha2-256", "none"])
        self.assertIsNone(_parse_kexinit(b"\x14" + bytes(16) + b"\x00\x00\x00\xff"))

    @unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
    def test_suite_names_match_wireshark(self):
        out = subprocess.run(["tshark", "-G", "values"], capture_output=True, text=True, check=True).stdout
        wireshark = {}
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4 and parts[1] == "tls.handshake.ciphersuite":
                wireshark[int(parts[2])] = parts[3]
        self.assertGreater(len(wireshark), 300)
        mismatched = {f"0x{c:04x}": (n, wireshark.get(c)) for c, n in CIPHER_SUITES.items() if wireshark.get(c) != n}
        self.assertEqual(mismatched, {})


class EncryptionAssertions:
    """The audit on the enc_ fixtures; mixed into one TestCase per backend."""

    backend = None

    def audit(self, name, **kwargs):
        report = audit_cleartext_capture(fixture(name), backend=self.backend, **kwargs)
        self.assertEqual(report["status"], "success", report.get("error"))
        self.assertEqual(report["capture"]["backend"], self.backend)
        json.dumps(report)
        return report

    def test_synthetic_tls12_null_suite_counts_as_cleartext(self):
        report = self.audit("enc_tls12_null.pcap")
        self.assertFalse(report["passed"])
        session = report["tcp_sessions"][0]
        self.assertEqual((session["protocol"], session["category"]),
                         ("tls (tcp/443 https) without encryption", "unencrypted_session"))
        enc = session["encryption"]
        self.assertEqual((enc["state"], enc["version"], enc["cipher_suite"], enc["server_hello_frame"]),
                         ("cleartext", "TLS1.2", "TLS_RSA_WITH_NULL_SHA256", 5))
        self.assertEqual(session["protection"], {"key_exchange": 7, "cleartext": 4})
        self.assertEqual(report["cleartext_frames"], 4)
        self.assertEqual(report["encryption"]["cleartext"], 1)
        self.assertIn("NULL cipher", report["verdict"])
        self.assertEqual(report["violations"][0]["reasons"], [enc["reason"]])
        self.assertIn("CLEARTEXT_OUTSIDE_ALLOWLIST", codes(report))
        self.assertFalse(self.audit("enc_tls12_null.pcap", allow=["tls"])["passed"])
        by_port = self.audit("enc_tls12_null.pcap", allow=["tcp:443"])  # a port token still accepts it
        self.assertTrue(by_port["passed"])
        self.assertEqual(by_port["cleartext_frames"], 4)

    def test_synthetic_tls13_integrity_only_suite_counts_as_cleartext(self):
        report = self.audit("enc_tls13_integrity_only.pcap")
        self.assertFalse(report["passed"])
        enc = report["tcp_sessions"][0]["encryption"]
        self.assertEqual((enc["state"], enc["version"], enc["cipher_suite"]), ("cleartext", "TLS1.3", "TLS_SHA256_SHA256"))
        self.assertEqual(report["tcp_sessions"][0]["protocol"], "tls (tcp/57400) without encryption")
        self.assertEqual(report["protection"]["cleartext"], 4)
        self.assertIn("RFC 9150", report["verdict"])

    def test_synthetic_tls10_passes_with_a_weak_warning(self):
        report = self.audit("enc_tls10.pcap")
        self.assertTrue(report["passed"])
        self.assertFalse(report["clean"])
        self.assertTrue(report["verdict"].startswith("PASS with warnings"), report["verdict"])
        enc = report["tcp_sessions"][0]["encryption"]
        self.assertEqual((enc["state"], enc["version"], enc["cipher_suite"]),
                         ("weak", "TLS1.0", "TLS_RSA_WITH_AES_128_CBC_SHA"))
        self.assertIn("RFC 8996", enc["reason"])
        self.assertIn("WEAK_ENCRYPTION", codes(report))
        self.assertEqual(report["encryption"]["weak"], 1)
        tunnel = self.audit("enc_tls10.pcap", allow=["crypto"])
        self.assertFalse(tunnel["passed"])
        self.assertIn("ENCRYPTED_OUTSIDE_ALLOWLIST", codes(tunnel))

    def test_synthetic_ssh_none_chosen_by_the_client_order(self):
        report = self.audit("enc_ssh_none.pcap")
        self.assertFalse(report["passed"])
        session = report["tcp_sessions"][0]
        enc = session["encryption"]
        self.assertEqual((enc["state"], enc["cipher_client_to_server"], enc["cipher_server_to_client"]),
                         ("cleartext", "none", "none"))
        self.assertEqual(enc["kexinit_frames"], {"client": 7, "server": 6})
        self.assertEqual(session["protocol"], "ssh (tcp/22) without encryption")
        self.assertEqual(session["protection"], {"key_exchange": 10, "cleartext": 4})  # the userauth after NEWKEYS
        self.assertIn("the cipher none", report["verdict"])

    def test_synthetic_ssh_cbc_passes_with_a_weak_warning(self):
        report = self.audit("enc_ssh_cbc.pcap")
        self.assertTrue(report["passed"])
        self.assertFalse(report["clean"])
        enc = report["tcp_sessions"][0]["encryption"]
        self.assertEqual((enc["state"], enc["cipher_client_to_server"], enc["mac_client_to_server"]),
                         ("weak", "aes128-cbc", "hmac-sha2-256"))  # the client's first choice, not the server's
        self.assertIn("CBC", enc["reason"])
        self.assertEqual(codes(report).count("WEAK_ENCRYPTION"), 1)

    def test_synthetic_midstream_sessions_pass_unverified_never_clean(self):
        report = self.audit("enc_midstream.pcap")
        self.assertTrue(report["passed"], report["verdict"])
        self.assertFalse(report["clean"])
        self.assertTrue(report["verdict"].startswith("PASS with warnings"))
        sessions = {s["service"]: s for s in report["tcp_sessions"]}
        for service in ("tcp/443", "tcp/22"):
            enc = sessions[service]["encryption"]
            self.assertEqual((enc["state"], enc["handshake_captured"]), ("unverified", False))
            self.assertNotIn("key_exchange", sessions[service]["protection"])
        self.assertIn("NULL cipher cannot be told", sessions["tcp/443"]["encryption"]["reason"])
        self.assertIn("looks like ciphertext", sessions["tcp/22"]["encryption"]["reason"])
        self.assertEqual(codes(report).count("ENCRYPTION_UNVERIFIED"), 2)
        self.assertEqual(report["encryption"]["unverified"], 2)

    def test_synthetic_text_on_port_22_without_a_banner_stays_cleartext(self):
        report = self.audit("enc_port22_text.pcap")
        self.assertFalse(report["passed"])
        self.assertEqual(report["tcp_sessions"][0]["protocol"], "tcp/22")
        self.assertNotIn("encryption", report["tcp_sessions"][0])
        self.assertEqual(report["cleartext_frames"], 8)

    def test_synthetic_strong_sessions_pass_clean_and_are_named_outside_the_tunnel(self):
        report = self.audit("grpc_mgmt_mix.pcap", allow=["encrypted", "tcp:23", "http2"])
        self.assertTrue(report["passed"] and report["clean"], report["verdict"])
        sessions = {s["service"]: s["encryption"] for s in report["tcp_sessions"] if s.get("encryption")}
        self.assertEqual(sessions["tcp/830"]["cipher_client_to_server"], "aes128-ctr")
        self.assertEqual(sessions["tcp/443"]["cipher_suite"], "TLS_AES_128_GCM_SHA256")
        tunnel = [i for i in report["issues"] if i["code"] == "ENCRYPTED_OUTSIDE_TUNNEL"]
        self.assertEqual([i["severity"] for i in tunnel], ["info"])
        self.assertIn("not by IPsec", report["verdict"])


class TestEncryptionTshark(EncryptionAssertions, unittest.TestCase):
    backend = "tshark"

    def setUp(self):
        if not HAVE_TSHARK:
            self.skipTest("tshark is not installed")


class TestEncryptionScapy(EncryptionAssertions, unittest.TestCase):
    backend = "scapy"


class TestOtherViews(unittest.TestCase):
    @unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
    def test_synthetic_null_session_is_readable_to_wireshark_too(self):
        # Independent of S.O.N.I.C.: Wireshark dissects the NULL suite's application data as plain HTTP.
        out = subprocess.run(["tshark", "-n", "-r", fixture("enc_tls12_null.pcap"), "-Y", "http.request",
                              "-T", "fields", "-e", "http.request.uri"], capture_output=True, text=True).stdout
        self.assertIn("/restconf/data/", out)

    def test_synthetic_detector_status_is_warning_for_a_pass_that_is_not_clean(self):
        def status(name, allow=None):
            report = analyze_network_capture(fixture(name), detectors=["cleartext_audit"], include_sip=False,
                                             backend="scapy", options={"cleartext_audit": {"allow": allow}})
            return report["cleartext_audit"]["status"], report["overall_status"]
        self.assertEqual(status("enc_tls10.pcap"), ("warning", "warning"))
        self.assertEqual(status("enc_midstream.pcap"), ("warning", "warning"))
        self.assertEqual(status("enc_ssh_none.pcap"), ("problem", "problem"))
        self.assertEqual(status("grpc_mgmt_mix.pcap", ["encrypted", "tcp:23", "http2"])[0], "ok")

    def test_synthetic_tls_detector_says_a_null_suite_does_not_encrypt(self):
        tls = analyze_network_capture(fixture("enc_tls12_null.pcap"), detectors=["tls"], backend="scapy")["tls"]
        chosen = [i for i in tls["issues"] if i["code"] == "TLS_WEAK_CIPHER_CHOSEN"]
        self.assertEqual(len(chosen), 1)
        self.assertIn("does not encrypt", chosen[0]["message"])

    @unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
    def test_mcp_tool_uses_the_new_default(self):
        import mcp_server
        tool = mcp_server.audit_cleartext_pcap
        fn = getattr(tool, "fn", tool)
        weak = fn(file_path=fixture("enc_tls10.pcap"))
        self.assertEqual((weak["status"], weak["passed"], weak["clean"]), ("success", True, False))
        self.assertEqual(weak["allowlist"], ["encrypted"])
        self.assertFalse(fn(file_path=fixture("enc_ssh_none.pcap"))["passed"])
        self.assertFalse(fn(file_path=fixture("enc_tls10.pcap"), allow=["crypto"])["passed"])


def tshark_rows(path, display_filter, fields, decode_as=()):
    command = ["tshark", "-n", "-r", path, *decode_as, "-Y", display_filter, "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        command += ["-e", field]
    out = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    return [dict(zip(fields, line.split("\t"))) for line in out.splitlines()]


@unittest.skipUnless(HAVE_TSHARK and os.path.exists(PLAINTEXT) and os.path.exists(ENCRYPTED),
                     "the real gNMI and NETCONF/RESTCONF/SSH captures are not on this machine")
class TestRealCaptures(unittest.TestCase):
    """
    NETCONF over SSH, RESTCONF over TLS 1.3 and SSH to a Catalyst 8000V, and plaintext gNMI to
    Stratum with throwaway metadata credentials.
    """

    def test_real_encrypted_capture_passes_by_default_with_the_ciphers_wireshark_reads(self):
        kexinits = tshark_rows(ENCRYPTED, "ssh.message_code==20",
                               ["tcp.stream", "tcp.srcport", "tcp.dstport", "ssh.encryption_algorithms_client_to_server",
                                "ssh.encryption_algorithms_server_to_client"], ["-d", "tcp.port==830,ssh"])
        expected = {}
        for stream in {row["tcp.stream"] for row in kexinits}:
            rows = [row for row in kexinits if row["tcp.stream"] == stream]
            client = next(r for r in rows if r["tcp.dstport"] in ("22", "830"))
            server = next(r for r in rows if r["tcp.srcport"] in ("22", "830"))
            expected[client["tcp.srcport"]] = _ssh_choose(
                client["ssh.encryption_algorithms_client_to_server"].split(","),
                server["ssh.encryption_algorithms_client_to_server"].split(","))
        hellos = tshark_rows(ENCRYPTED, "tls.handshake.type==2", ["tcp.dstport", "tls.handshake.ciphersuite"])
        suites = {row["tcp.dstport"]: suite_name(int(row["tls.handshake.ciphersuite"], 16)) for row in hellos}
        self.assertEqual(len(expected), 2)
        self.assertEqual(len(suites), 3)
        for backend in ("tshark", "scapy"):
            with self.subTest(backend=backend):
                audit = audit_cleartext_capture(ENCRYPTED, backend=backend)
                self.assertEqual(audit["allowlist"], ["encrypted"])
                self.assertTrue(audit["passed"] and audit["clean"], audit["verdict"])
                self.assertTrue(audit["verdict"].startswith("PASS: all 1030 frames"))
                self.assertEqual(audit["encryption"], {"sessions": 5, "encrypted": 5, "weak": 0, "unverified": 0,
                                                       "cleartext": 0, "not_started": 0})
                self.assertIn("ENCRYPTED_OUTSIDE_TUNNEL", codes(audit))
                for session in audit["tcp_sessions"]:
                    port = session["client"].rsplit(":", 1)[1]
                    enc = session["encryption"]
                    if session["service"] == "tcp/443":
                        self.assertEqual((enc["version"], enc["cipher_suite"]), ("TLS1.3", suites[port]))
                    else:
                        self.assertEqual(enc["cipher_client_to_server"], expected[port])
                tunnel = audit_cleartext_capture(ENCRYPTED, backend=backend, allow=["crypto"])
                self.assertFalse(tunnel["passed"])
                self.assertEqual(tunnel["cleartext_frames"], 0)

    def test_real_plaintext_gnmi_still_fails_with_its_credentials(self):
        audit = audit_cleartext_capture(PLAINTEXT)
        self.assertFalse(audit["passed"])
        self.assertEqual(audit["cleartext_frames"], 57)
        self.assertEqual(sorted(c["key"] for c in audit["credentials"]), ["password", "username"])
        self.assertTrue(all(c["value"] == "masked" for c in audit["credentials"]))
        self.assertIn("credentials in cleartext gRPC metadata", audit["verdict"])


class TestTlsAuditFixtures(unittest.TestCase):
    def test_synthetic_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_tls_audit_fixtures.py"), out],
                           check=True, capture_output=True)
            names = sorted(os.listdir(out))
            self.assertEqual(names, sorted(os.path.basename(p) for p in glob.glob(fixture("enc_*.pcap"))))
            self.assertEqual(len(names), 7)
            for name in names:
                with self.subTest(fixture=name):
                    self.assertTrue(filecmp.cmp(os.path.join(out, name), fixture(name), shallow=False),
                                    f"{name} differs from a fresh generation; rerun generate_tls_audit_fixtures.py")


if __name__ == "__main__":
    unittest.main()
