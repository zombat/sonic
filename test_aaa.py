#!/usr/bin/env python3
"""
Tests for TACACS+ and RADIUS troubleshooting (analyzers/aaa_inspect.py, extractors/aaa.py,
extractors/wsconfig.py), de-obfuscated with a shared key.

Synthetic fixtures (names start with aaa_) are built by tests/fixtures/generate_aaa_fixtures.py
with scapy (its RADIUS layer and the contrib TACACS+ layer); the test names say so. Every key
and password is a synthetic placeholder defined in the generator. The shared key is written to
a key file at test time and passed to tshark through a temporary WIRESHARK_CONFIG_DIR (never on
the command line); every assertion is that no key, password or recovered credential appears in
the report, the CLI output or the saved files.

Run with:  python3 -m unittest -q test_aaa
"""

import filecmp
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from analyzers.aaa_inspect import analyze_aaa_capture, read_keys_file
from extractors import wsconfig
from extractors.wsconfig import wireshark_config

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
sys.path.insert(0, FIXTURES)
import generate_aaa_fixtures as gen  # noqa: E402

HAVE_TSHARK = shutil.which("tshark") is not None
SECRETS = [gen.RADIUS_SECRET, gen.TACACS_KEY, gen.SYNTHETIC_PASSWORD, gen.SYNTHETIC_TACACS_PASSWORD,
           "wrong-password-not-real"]


def codes(report):
    return [issue["code"] for issue in report["issues"]]


def write_keys(tmp):
    path = os.path.join(tmp, "keys.txt")
    with open(path, "w") as handle:
        handle.write(f"tacacs_key: {gen.TACACS_KEY}\nradius_secret: {gen.RADIUS_SECRET}\n")
    return path


class TestKeysFile(unittest.TestCase):
    """The operator's key file parser (never echoes a value)."""

    def test_named_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k")
            with open(path, "w") as h:
                h.write("# keys\ntacacs_key: abc\nradius_secret = def\n")
            self.assertEqual(read_keys_file(path), ("abc", "def"))

    def test_single_bare_key_is_used_for_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k")
            with open(path, "w") as h:
                h.write("onekey123\n")
            self.assertEqual(read_keys_file(path), ("onekey123", "onekey123"))

    def test_empty_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k")
            with open(path, "w") as h:
                h.write("# just a comment\n")
            with self.assertRaises(ValueError):
                read_keys_file(path)


class TestWsConfig(unittest.TestCase):
    """The temporary Wireshark config keeps secrets off the command line and cleans up."""

    def test_preferences_file_written_private_and_removed(self):
        seen = {}
        with wireshark_config(preferences={"tacplus.key": "sekret"}) as d:
            seen["dir"] = d
            pref = os.path.join(d, "preferences")
            self.assertTrue(os.path.exists(pref))
            self.assertEqual(os.stat(pref).st_mode & 0o777, 0o600)
            with open(pref) as h:
                self.assertIn("tacplus.key: sekret", h.read())
        self.assertFalse(os.path.exists(seen["dir"]))  # cleaned up

    @unittest.skipUnless(wsconfig.secret_dir_root(), "no writable tmpfs at /dev/shm on this machine")
    def test_secrets_are_kept_on_tmpfs_where_there_is_one(self):
        with wireshark_config(preferences={"tacplus.key": "sekret"}) as d:
            self.assertEqual(os.path.dirname(d), "/dev/shm")
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)

    def test_without_tmpfs_it_falls_back_to_the_temp_dir_and_warns_once(self):
        with mock.patch.object(wsconfig, "SHM_DIR", "/nonexistent-sonic-shm"), \
                mock.patch.object(wsconfig, "_warned_on_disk", False), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            with wireshark_config(preferences={"tacplus.key": "sekret"}) as d:
                self.assertEqual(os.path.dirname(d), tempfile.gettempdir())
            with wireshark_config(preferences={"tacplus.key": "sekret"}):
                pass
        self.assertEqual(err.getvalue().count("no tmpfs at /nonexistent-sonic-shm"), 1)
        self.assertNotIn("sekret", err.getvalue())

    def _child_holding_a_config(self):
        """A python process that makes a config dir, prints its path and waits to be signalled."""
        code = ("import time\n"
                "from extractors.wsconfig import wireshark_config\n"
                "with wireshark_config(preferences={'tacplus.key': 'sekret'}) as d:\n"
                "    print(d, flush=True)\n"
                "    time.sleep(60)\n")
        child = subprocess.Popen([sys.executable, "-c", code], cwd=HERE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(child.stdout.close)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        path = child.stdout.readline().strip()
        self.assertTrue(os.path.isdir(path), path)
        return child, path

    def test_sigterm_removes_the_config_dir(self):
        child, path = self._child_holding_a_config()
        child.send_signal(signal.SIGTERM)
        self.assertEqual(child.wait(timeout=20), -signal.SIGTERM)  # still ends as SIGTERM would
        self.assertFalse(os.path.exists(path))

    def test_sigint_removes_the_config_dir(self):
        child, path = self._child_holding_a_config()
        child.send_signal(signal.SIGINT)
        self.assertNotEqual(child.wait(timeout=20), 0)
        self.assertFalse(os.path.exists(path))

    def test_a_dir_left_by_sigkill_is_removed_by_the_next_run(self):
        child, path = self._child_holding_a_config()
        child.kill()  # SIGKILL cannot be caught: the directory is left behind
        child.wait(timeout=20)
        self.assertTrue(os.path.exists(path))
        with mock.patch.object(wsconfig, "_warned_on_disk", True):
            with wireshark_config():
                pass
        self.assertFalse(os.path.exists(path))


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSyntheticRadius(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmp, "aaa_radius.pcap")
        gen.build_radius().write(cls.pcap)
        cls.keys = write_keys(cls.tmp)
        cls.report = analyze_aaa_capture(cls.pcap, keys_file=cls.keys)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_radius_versions_and_results(self):
        self.assertEqual(self.report["status"], "success")
        results = {(e["username"], e["kind"]): e for e in self.report["radius"]}
        self.assertEqual(results[("alice", "auth")]["result"], "accept")
        self.assertEqual(results[("mallory", "auth")]["result"], "reject")
        self.assertEqual(results[("eve", "auth")]["result"], "no_response")
        acct = [e for e in self.report["radius"] if e["kind"] == "accounting"]
        self.assertEqual({e["acct_status"] for e in acct}, {"Start", "Stop"})

    def test_synthetic_message_authenticator_checked(self):
        state = {e["username"]: e["message_authenticator"] for e in self.report["radius"] if e["kind"] == "auth"}
        self.assertEqual(state["alice"], {"request": "valid", "response": "valid"})
        self.assertEqual(state["mallory"], {"request": "absent", "response": "absent"})
        self.assertEqual(state["eve"]["request"], "invalid")
        self.assertIn("RADIUS_BAD_MESSAGE_AUTHENTICATOR", codes(self.report))
        self.assertEqual(codes(self.report).count("RADIUS_NO_MESSAGE_AUTHENTICATOR"), 1)  # the Reject
        closed = analyze_aaa_capture(self.pcap)
        self.assertEqual(closed["radius"][0]["message_authenticator"], {"request": "unchecked", "response": "unchecked"})

    def test_synthetic_message_authenticator_agrees_with_scapy(self):
        """scapy's own RFC 3579 implementation is the independent check on S.O.N.I.C.'s."""
        from scapy.all import UDP, rdpcap
        from scapy.layers.radius import Radius, RadiusAttr_Message_Authenticator
        from analyzers.aaa_inspect import message_authenticator
        packets = [bytes(p[UDP].payload) for p in rdpcap(self.pcap)]
        request, accept, eve = packets[0], packets[1], packets[4]
        secret = gen.RADIUS_SECRET.encode()

        def value(raw):
            pos = 20
            while raw[pos] != 80:
                pos += raw[pos + 1]
            return raw[pos + 2:pos + 18]
        for raw, req_auth in ((request, request[4:20]), (accept, request[4:20]), (eve, eve[4:20])):
            expected = RadiusAttr_Message_Authenticator.compute_message_authenticator(Radius(raw), req_auth, secret)
            scapy_ok = expected == value(raw)
            ours = message_authenticator(raw, gen.RADIUS_SECRET, None if raw[0] == 1 else req_auth)
            self.assertEqual(ours, "valid" if scapy_ok else "invalid")

    def test_radius_authenticator_validates_with_the_secret(self):
        for e in self.report["radius"]:
            if e["response_code"]:
                self.assertIs(e["authenticator_valid"], True)

    def test_radius_password_recovered_but_masked(self):
        alice = next(e for e in self.report["radius"] if e["username"] == "alice" and e["kind"] == "auth")
        self.assertTrue(alice["credential_recovered"])
        self.assertEqual(alice["credential"], "masked")
        self.assertIn("AAA_CREDENTIAL_RECOVERED", codes(self.report))
        self.assertIn("AAA_ACCESS_REJECT", codes(self.report))

    def test_radius_no_secret_leaves_password_encrypted(self):
        closed = analyze_aaa_capture(self.pcap)  # no key file
        alice = next(e for e in closed["radius"] if e["username"] == "alice" and e["kind"] == "auth")
        self.assertFalse(alice["credential_recovered"])

    def test_radius_wrong_secret_is_an_invalid_authenticator(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k")
            with open(path, "w") as h:
                h.write("radius_secret: this-is-the-wrong-secret\n")
            report = analyze_aaa_capture(self.pcap, keys_file=path)
            self.assertTrue(any(e["authenticator_valid"] is False for e in report["radius"]))
            self.assertIn("RADIUS_BAD_AUTHENTICATOR", codes(report))

    def test_radius_no_secret_or_password_in_report(self):
        blob = json.dumps(self.report)
        for secret in SECRETS:
            self.assertNotIn(secret, blob)


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSyntheticTacacs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmp, "aaa_tacacs.pcap")
        gen.build_tacacs().write(cls.pcap)
        cls.keys = write_keys(cls.tmp)
        cls.report = analyze_aaa_capture(cls.pcap, keys_file=cls.keys)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_tacacs_sessions_authentication_authorization_accounting(self):
        self.assertEqual(self.report["status"], "success")
        sessions = {s["session_id"]: s for s in self.report["tacacs"]}
        self.assertEqual(len(sessions), 5)
        self.assertEqual(sessions[0x0A0A0A0A]["authentication"], "PASS")
        self.assertEqual(sessions[0x0B0B0B0B]["authorization"], "PASS_ADD")
        self.assertEqual(sessions[0x0C0C0C0C]["accounting"], "SUCCESS")
        self.assertEqual(sessions[0x0D0D0D0D]["authentication"], "FAIL")

    def test_tacacs_credential_recovered_but_masked(self):
        login = next(s for s in self.report["tacacs"] if s["session_id"] == 0x0A0A0A0A)
        self.assertTrue(login["credential_recovered"])
        self.assertEqual(login["credential"], "masked")
        self.assertEqual(login["user"], "admin")
        self.assertIn("AAA_CREDENTIAL_RECOVERED", codes(self.report))

    def test_tacacs_unencrypted_flag_is_cleartext(self):
        clear = next(s for s in self.report["tacacs"] if s["session_id"] == 0x0E0E0E0E)
        self.assertTrue(clear["cleartext"])
        self.assertEqual(clear["user"], "plainuser")
        self.assertIn("AAA_CLEARTEXT_TACACS", codes(self.report))

    def test_tacacs_fail_is_reported(self):
        self.assertIn("AAA_AUTH_FAIL", codes(self.report))

    def test_tacacs_no_key_or_password_in_report(self):
        blob = json.dumps(self.report)
        for secret in SECRETS:
            self.assertNotIn(secret, blob)


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestAaaInterfaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmp, "aaa_tacacs.pcap")
        gen.build_tacacs().write(cls.pcap)
        cls.keys = write_keys(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_mcp_tool_function(self):
        import mcp_server
        tool = mcp_server.analyze_aaa_pcap
        fn = getattr(tool, "fn", tool)
        report = fn(file_path=self.pcap, keys_file=self.keys)
        self.assertEqual(report["status"], "success")
        self.assertTrue(report["tacacs"])
        self.assertEqual(fn(file_path="/nonexistent.pcap")["status"], "error")

    def test_cli_json_mode_holds_no_secret(self):
        out = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", self.pcap,
                              "--aaa", "--aaa-secrets", self.keys, "--json"], capture_output=True, text=True, cwd=HERE)
        self.assertEqual(out.returncode, 0, out.stderr)
        report = json.loads(out.stdout)
        self.assertEqual(report["summary"]["tacacs_sessions"], 5)
        for secret in SECRETS:
            self.assertNotIn(secret, out.stdout)


class TestAaaFixtures(unittest.TestCase):
    def test_synthetic_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_aaa_fixtures.py"), out],
                           check=True, capture_output=True)
            names = sorted(os.listdir(out))
            self.assertEqual(names, ["aaa_radius.pcap", "aaa_tacacs.pcap"])
            for name in names:
                with self.subTest(fixture=name):
                    self.assertTrue(filecmp.cmp(os.path.join(out, name), os.path.join(FIXTURES, name), shallow=False),
                                    f"{name} differs from a fresh generation; rerun generate_aaa_fixtures.py")


if __name__ == "__main__":
    unittest.main()
