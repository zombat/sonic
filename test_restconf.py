#!/usr/bin/env python3
"""
Tests for RESTCONF and REST troubleshooting (analyzers/http_inspect.py,
extractors/http_messages.py), decrypted with a key log.

Synthetic fixtures (names start with restconf_) are built by
tests/fixtures/generate_restconf_fixtures.py; the test names say so. RESTCONF over
TLS 1.3 (HTTP/1.1 and HTTP/2) with its key log is generated at test time with Python's
ssl module (real TLS, never committed), and the same session with its key log embedded
in a pcapng by editcap. No credential value or secret is written in this file: they are
synthetic placeholders defined in the generator, and every assertion is that they do not
appear in the report, the CLI output or the saved files.

A real RESTCONF-over-TLS capture with a key log is not on this machine (the one RESTCONF
capture, netconf-restconf-ssh.pcap, is TLS 1.3 with no key log): TestRealRestconfCapture
runs on it when present and asserts it shows only the handshake, which is the honest
"not decrypted" state, and the rest is proven on the synthetic TLS sessions above.

Run with:  python3 -m unittest -q test_restconf
"""

import filecmp
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from analyzers.http_inspect import (
    analyze_http_capture, is_restconf, parse_restconf_errors,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
sys.path.insert(0, FIXTURES)
import generate_restconf_fixtures as gen  # noqa: E402

HAVE_TSHARK = shutil.which("tshark") is not None
HAVE_EDITCAP = shutil.which("editcap") is not None
CAPTURES = os.environ.get("SONIC_GRPC_CAPTURES", "/home/noot/auto-roboto/.IGNORE/cml-capture/proj/captures")
REAL_RESTCONF = os.path.join(CAPTURES, "netconf-restconf-ssh.pcap")

SYNTHETIC_SECRETS = [gen.SYNTHETIC_BASIC.decode(), gen.SYNTHETIC_PASSWORD.decode(), gen.SYNTHETIC_TOKEN.decode(),
                     gen.SYNTHETIC_USER.decode() + ":" + gen.SYNTHETIC_PASSWORD.decode()]


def fixture(name):
    return os.path.join(FIXTURES, name)


def codes(report):
    return [issue["code"] for issue in report["issues"]]


def by_path(report):
    return {(r["method"], r["path"]): r for r in report["requests"]}


def key_log_secrets(path):
    """The secret column of a key log, to assert it never appears (never printed)."""
    with open(path) as handle:
        return [line.split()[-1] for line in handle if len(line.split()) == 3]


def inject_secrets(keylog, pcap, out_dir):
    embedded = os.path.join(out_dir, "embedded.pcapng")
    subprocess.run(["editcap", "--inject-secrets", f"tls,{keylog}", pcap, embedded], check=True, capture_output=True)
    os.chmod(embedded, 0o600)
    return embedded


class TestRestconfErrorParsing(unittest.TestCase):
    """The ietf-restconf:errors parser, on bytes built here."""

    def test_json_errors(self):
        body = (b'{"ietf-restconf:errors":{"error":[{"error-type":"application","error-tag":"invalid-value",'
                b'"error-path":"/x","error-message":"bad"}]}}')
        errs = parse_restconf_errors(body, "application/yang-data+json")
        self.assertEqual(len(errs), 1)
        self.assertEqual(errs[0]["error-tag"], "invalid-value")
        self.assertEqual(errs[0]["error-path"], "/x")

    def test_xml_errors(self):
        body = (b'<errors xmlns="urn:ietf:params:xml:ns:yang:ietf-restconf"><error>'
                b'<error-type>protocol</error-type><error-tag>data-missing</error-tag>'
                b'<error-message>gone</error-message></error></errors>')
        errs = parse_restconf_errors(body, "application/yang-data+xml")
        self.assertEqual(errs[0]["error-tag"], "data-missing")
        self.assertEqual(errs[0]["error-type"], "protocol")

    def test_not_an_errors_document(self):
        self.assertEqual(parse_restconf_errors(b'{"ietf-interfaces:interfaces":{}}', "application/yang-data+json"), [])
        self.assertEqual(parse_restconf_errors(b"", None), [])

    def test_is_restconf_by_path_and_type(self):
        self.assertTrue(is_restconf("/restconf/data/x", (None,)))
        self.assertTrue(is_restconf("/api", ("application/yang-data+json",)))
        self.assertFalse(is_restconf("/api/v1/status", ("application/json",)))


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSyntheticCleartext(unittest.TestCase):
    """The synthetic cleartext RESTCONF/REST fixture (HTTP/1.1, h2c, REST)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        gen.build_restconf_cleartext().write(os.path.join(cls.tmp, "restconf_cleartext.pcap"))
        cls.report = analyze_http_capture(os.path.join(cls.tmp, "restconf_cleartext.pcap"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_synthetic_methods_statuses_and_timing(self):
        self.assertEqual(self.report["status"], "success")
        reqs = by_path(self.report)
        self.assertEqual(reqs[("GET", "/restconf/data/ietf-interfaces:interfaces")]["status"], 200)
        self.assertEqual(reqs[("POST", "/restconf/data/ietf-interfaces:interfaces")]["status"], 201)
        self.assertTrue(reqs[("POST", "/restconf/data/ietf-interfaces:interfaces")]["location"])
        put = reqs[("PUT", "/restconf/data/ietf-interfaces:interfaces/interface=GigabitEthernet1")]
        self.assertEqual(put["status"], 204)
        self.assertIsNotNone(put["timing_ms"])

    def test_synthetic_restconf_errors_json_and_xml(self):
        reqs = by_path(self.report)
        delete = reqs[("DELETE", "/restconf/data/ietf-interfaces:interfaces/interface=eth9")]
        self.assertEqual(delete["status"], 404)
        self.assertEqual(delete["restconf_errors"][0]["error-tag"], "data-missing")  # XML body
        get400 = reqs[("GET", "/restconf/data/ietf-interfaces:interfaces/interface=eth9")]
        self.assertEqual(get400["restconf_errors"][0]["error-tag"], "invalid-value")  # JSON body
        self.assertEqual(codes(self.report).count("RESTCONF_ERROR"), 2)

    def test_synthetic_rest_is_not_restconf(self):
        reqs = by_path(self.report)
        self.assertFalse(reqs[("GET", "/api/v1/status")]["restconf"])
        self.assertTrue(reqs[("GET", "/restconf/data/ietf-interfaces:interfaces")]["restconf"])

    def test_synthetic_h2c_restconf_and_cleartext_credentials(self):
        h2 = [r for r in self.report["requests"] if r["http_version"] == "2"]
        self.assertEqual(len(h2), 1)
        self.assertEqual(h2[0]["method"], "GET")
        clear = {c["header"] for c in self.report["credentials"] if c["cleartext"]}
        self.assertEqual(clear, {"Authorization", "x-auth-token"})
        self.assertEqual(codes(self.report).count("CLEARTEXT_CREDENTIAL"), 2)

    def test_synthetic_no_credential_value_anywhere(self):
        blob = json.dumps(self.report)
        for secret in SYNTHETIC_SECRETS:
            self.assertNotIn(secret, blob)


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSyntheticTlsKeylog(unittest.TestCase):
    """RESTCONF over TLS 1.3 decrypted with the client's key log, HTTP/1.1 and HTTP/2."""

    def _run(self, http2):
        with tempfile.TemporaryDirectory() as out:
            pcap, keylog = gen.build_restconf_tls13_keylog(out, http2=http2)
            secrets = key_log_secrets(keylog)
            closed = analyze_http_capture(pcap)
            self.assertEqual(closed["summary"]["requests"], 0)  # encrypted without the key log
            self.assertEqual(closed["tls_decryption"]["decrypted"], 0)
            report = analyze_http_capture(pcap, keylog_file=keylog)
            self.assertEqual(report["status"], "success")
            self.assertTrue(report["capture"]["keylog_file_given"])
            self.assertEqual((report["tls_decryption"]["decrypted"], report["tls_decryption"]["total"]), (1, 1))
            reqs = by_path(report)
            self.assertEqual(reqs[("GET", "/restconf/data/ietf-interfaces:interfaces")]["status"], 200)
            delete = reqs[("DELETE", "/restconf/data/ietf-interfaces:interfaces/interface=eth9")]
            self.assertEqual(delete["status"], 404)
            self.assertEqual(delete["restconf_errors"][0]["error-tag"], "invalid-value")
            self.assertTrue(report["credentials"])
            self.assertFalse(any(c["cleartext"] for c in report["credentials"]))  # over TLS
            self.assertIn("CREDENTIAL_IN_REQUEST", codes(report))
            blob = json.dumps(report)
            self.assertNotIn(keylog, blob)
            for secret in secrets + SYNTHETIC_SECRETS:
                self.assertNotIn(secret, blob)

    def test_synthetic_tls13_http1_key_log_decrypts(self):
        self._run(http2=False)

    def test_synthetic_tls13_http2_key_log_decrypts(self):
        self._run(http2=True)

    @unittest.skipUnless(HAVE_EDITCAP, "editcap is not installed")
    def test_synthetic_tls13_secrets_embedded_in_pcapng_need_no_key_log(self):
        with tempfile.TemporaryDirectory() as out:
            pcap, keylog = gen.build_restconf_tls13_keylog(out, http2=True)
            secrets = key_log_secrets(keylog)
            embedded = inject_secrets(keylog, pcap, out)
            report = analyze_http_capture(embedded)
            self.assertFalse(report["capture"]["keylog_file_given"])
            self.assertEqual(report["capture"]["tls_secrets"]["pcapng_decryption_secrets_blocks"], 1)
            self.assertEqual(report["tls_decryption"]["decrypted"], 1)
            self.assertIn("TLS_SECRETS_IN_CAPTURE", codes(report))
            self.assertTrue(report["requests"])
            blob = json.dumps(report)
            for secret in secrets + SYNTHETIC_SECRETS:
                self.assertNotIn(secret, blob)


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestRestconfInterfaces(unittest.TestCase):
    """The CLI and MCP entry points on the synthetic cleartext fixture."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmp, "restconf_cleartext.pcap")
        gen.build_restconf_cleartext().write(cls.pcap)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_mcp_tool_function(self):
        import mcp_server
        tool = mcp_server.analyze_restconf_pcap
        fn = getattr(tool, "fn", tool)
        report = fn(file_path=self.pcap)
        self.assertEqual(report["status"], "success")
        self.assertTrue(report["requests"])
        self.assertEqual(fn(file_path="/nonexistent.pcap")["status"], "error")

    def test_cli_json_mode_and_report_hold_no_secret(self):
        out = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", self.pcap,
                              "--restconf", "--json"], capture_output=True, text=True, cwd=HERE)
        self.assertEqual(out.returncode, 0, out.stderr)
        report = json.loads(out.stdout)
        self.assertEqual(report["summary"]["connections"], 3)
        for secret in SYNTHETIC_SECRETS:
            self.assertNotIn(secret, out.stdout)
        md_path = self.pcap + ".restconf.md"
        subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", self.pcap, "--restconf"],
                       capture_output=True, text=True, cwd=HERE)
        with open(md_path) as handle:
            md = handle.read()
        for secret in SYNTHETIC_SECRETS:
            self.assertNotIn(secret, md)


class TestRestconfFixtures(unittest.TestCase):
    def test_synthetic_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_restconf_fixtures.py"), out],
                           check=True, capture_output=True)
            names = sorted(os.listdir(out))
            self.assertEqual(names, ["restconf_cleartext.pcap"])
            for name in names:
                with self.subTest(fixture=name):
                    self.assertTrue(filecmp.cmp(os.path.join(out, name), fixture(name), shallow=False),
                                    f"{name} differs from a fresh generation; rerun generate_restconf_fixtures.py")
                    self.assertLess(os.path.getsize(fixture(name)), 200 * 1024)

    @unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
    def test_committed_fixture_reads_as_the_generator_says(self):
        report = analyze_http_capture(fixture("restconf_cleartext.pcap"))
        self.assertEqual((report["summary"]["connections"], report["summary"]["requests"]), (3, 8))


@unittest.skipUnless(HAVE_TSHARK and os.path.exists(REAL_RESTCONF), "needs the real RESTCONF capture")
class TestRealRestconfCapture(unittest.TestCase):
    """
    The real RESTCONF-over-TLS capture on this machine is TLS 1.3 with no key log, so it is
    honestly not decryptable: this asserts it shows only the handshake (the "not done" state).
    """

    def test_real_restconf_tls_without_a_key_log_shows_only_the_handshake(self):
        report = analyze_http_capture(REAL_RESTCONF)
        self.assertEqual(report["status"], "success")
        # No request is decoded without a key log; any TLS session is reported undecrypted.
        self.assertEqual(report["summary"]["requests"], 0)
        if report["tls_decryption"]["total"]:
            self.assertEqual(report["tls_decryption"]["decrypted"], 0)


if __name__ == "__main__":
    unittest.main()
