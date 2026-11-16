#!/usr/bin/env python3
"""
Tests for SNMP troubleshooting (analyzers/snmp_inspect.py, extractors/snmp.py): every version
named, v1/v2c communities flagged, and SNMPv3 decrypted with a USM users file.

v1 and v2c are proven on a committed synthetic fixture (snmp_v1v2c.pcap, built by
tests/fixtures/generate_snmp_fixtures.py; test names say synthetic). SNMPv3 cannot be built by
hand, so it is proven on real traffic from net-snmp 5.9.4 that the same script captures in a
container (`--v3`, written to ~/.cache/sonic/snmp-captures or SONIC_SNMP_CAPTURES, never
committed): every auth and privacy algorithm net-snmp offers, a wrong privacy passphrase, a wrong
auth passphrase and an unknown user. TestRealV3Matrix skips when that capture is absent.
TestLabCaptures also reads any snmp-*.pcap another writer left in the lab captures directory.

No credential is written in this file: the throwaway passphrases and communities are defined in
the generator, and every assertion about them is that they do not appear in the report, the CLI
output or the markdown file.

Run with:  python3 -m unittest -q test_snmp
           python3 tests/fixtures/generate_snmp_fixtures.py --v3   # first, for the v3 tests (Docker)
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

from analyzers.snmp_inspect import analyze_snmp_capture
from extractors.snmp import SnmpUsersError, needs_key_extension, parse_users_file, user_uat_row

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
sys.path.insert(0, FIXTURES)
import generate_snmp_fixtures as gen  # noqa: E402

HAVE_TSHARK = shutil.which("tshark") is not None
V3_DIR = os.environ.get("SONIC_SNMP_CAPTURES", gen.DEFAULT_V3_DIR)
V3_PCAP = os.path.join(V3_DIR, "snmp-v3-matrix.pcap")
V3_USERS = os.path.join(V3_DIR, "snmp-users.txt")
LAB_DIR = os.environ.get("SONIC_GRPC_CAPTURES", "/home/noot/auto-roboto/.IGNORE/cml-capture/proj/captures")
COMMUNITIES = [gen.COMMUNITY_V1, gen.COMMUNITY_V2C]


def fixture(name):
    return os.path.join(FIXTURES, name)


def codes(report):
    return [issue["code"] for issue in report["issues"]]


class TestUsersFile(unittest.TestCase):
    """The users file parser: both formats, net-snmp spellings to tshark's labels, refusals."""

    def test_block_format_and_label_mapping(self):
        users = parse_users_file("user: a\nauth: SHA-256\nauth_pass: xxxxxxxx\npriv: AES-192\npriv_pass: yyyyyyyy\n\n"
                                 "user: b\nauth: SHA\nauth_pass: xxxxxxxx\n")
        self.assertEqual([(u["user"], u.get("auth"), u.get("priv")) for u in users],
                         [("a", "SHA2-256", "AES192"), ("b", "SHA1", None)])

    def test_csv_format_with_engine(self):
        users = parse_users_file("user,auth,auth_pass,priv,priv_pass,engine_id\nc,MD5,xxxxxxxx,DES,yyyyyyyy,0x8000AB\n")
        self.assertEqual((users[0]["auth"], users[0]["priv"], users[0]["engine_id"]), ("MD5", "DES", "8000ab"))

    def test_uat_row_uses_labels(self):
        row = user_uat_row(parse_users_file("user: u\nauth: SHA-512\nauth_pass: p\npriv: AES-256\npriv_pass: q\n")[0])
        self.assertEqual(row, '"","u","SHA2-512","p","AES256","q"')

    def test_key_extension_is_needed_only_when_the_hash_is_shorter_than_the_key(self):
        def user(auth, priv):
            return parse_users_file(f"user: u\nauth: {auth}\nauth_pass: p\npriv: {priv}\npriv_pass: q\n")[0]
        self.assertTrue(needs_key_extension(user("SHA", "AES-192")))
        self.assertTrue(needs_key_extension(user("MD5", "AES-256")))
        self.assertFalse(needs_key_extension(user("SHA-256", "AES-256")))
        self.assertFalse(needs_key_extension(user("SHA", "AES")))

    def test_refusals_never_echo_a_passphrase(self):
        for text in ("# nothing\n", "user: u\nauth: SHA3\nauth_pass: secret-1\n",
                     "user: u\nauth: SHA\nauth_pass: secret-1\npriv: 3DES\npriv_pass: secret-2\n",
                     'user: u\nauth: SHA\nauth_pass: has"quote-secret\n'):
            with self.assertRaises(SnmpUsersError) as caught:
                parse_users_file(text)
            self.assertNotIn("secret", str(caught.exception))


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSyntheticV1V2c(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_snmp_capture(fixture("snmp_v1v2c.pcap"))

    def test_synthetic_versions_named(self):
        self.assertEqual(self.report["status"], "success")
        self.assertEqual(self.report["summary"]["versions"], {"v1": 2, "v2c": 3})

    def test_synthetic_community_flagged_as_cleartext_and_masked(self):
        self.assertEqual(codes(self.report).count("SNMP_CLEARTEXT_COMMUNITY"), 2)
        self.assertTrue(all(c["value"] == "masked" for c in self.report["credentials"]))
        self.assertEqual({m.get("credential") for m in self.report["messages"]}, {"masked"})

    def test_synthetic_no_community_value_anywhere(self):
        blob = json.dumps(self.report)
        for community in COMMUNITIES:
            self.assertNotIn(community, blob)


@unittest.skipUnless(HAVE_TSHARK and os.path.exists(V3_PCAP) and os.path.exists(V3_USERS),
                     "needs the net-snmp capture: python3 tests/fixtures/generate_snmp_fixtures.py --v3")
class TestRealV3Matrix(unittest.TestCase):
    """Real SNMP from net-snmp 5.9.4, decrypted through tshark 3.6.2's snmp_users table."""

    @classmethod
    def setUpClass(cls):
        cls.report = analyze_snmp_capture(V3_PCAP, users_file=V3_USERS)
        cls.users = {u["user"]: u["outcomes"] for u in cls.report["v3_users"]}

    def test_real_every_version_and_security_level_named(self):
        summary = self.report["summary"]
        self.assertEqual((summary["versions"]["v1"], summary["versions"]["v2c"]), (1 + 1, 1 + 1))  # get + response
        levels = summary["v3_security_levels"]
        self.assertGreater(levels["noAuthNoPriv"], 0)
        self.assertEqual(levels["authNoPriv"], 2)
        self.assertGreater(levels["authPriv"], 0)
        self.assertIn("engine discovery", {m.get("role") for m in self.report["messages"]})
        self.assertEqual(self.users["u_authnopriv"], {"authenticated": 2})

    def test_real_what_tshark_3_6_decrypts(self):
        for user, auth, priv in gen.V3_AUTHPRIV:
            extended = priv in ("AES-192", "AES-256") and auth in ("SHA", "MD5")
            with self.subTest(user=user, auth=auth, priv=priv):
                if user == "u_sha_aes":
                    self.assertEqual(self.users[user].get("decrypted"), 2)  # plus the two failures below
                elif extended:
                    self.assertEqual(self.users[user], {"decrypt_failed": 2})
                else:
                    self.assertEqual(self.users[user], {"decrypted": 2})

    def test_real_key_extension_mismatch_is_explained(self):
        failed = [i for i in self.report["issues"] if i["code"] == "SNMP_DECRYPT_FAILED" and
                  i.get("user") in ("u_sha_aes192", "u_sha_aes256", "u_md5_aes256")]
        self.assertEqual(len(failed), 6)
        self.assertTrue(all("Reeder" in i["message"] and "Blumenthal" in i["message"] for i in failed))

    def test_real_wrong_passphrases_and_unknown_user_never_silent(self):
        self.assertEqual(self.users["u_sha_aes"], {"decrypted": 2, "decrypt_failed": 1, "auth_failed": 1})
        self.assertEqual(self.users["u_nobody"], {"unknown_user": 1})
        reports = {m.get("report") for m in self.report["messages"]}
        self.assertTrue({"usmStatsWrongDigests", "usmStatsUnknownUserNames", "usmStatsUnknownEngineIDs"} <= reports)
        for m in self.report["messages"]:
            if m["version"] == "v3" and m["security_level"] == "authPriv":
                self.assertIn(m["outcome"], ("decrypted", "auth_failed", "decrypt_failed", "unknown_user"))
                self.assertEqual(m["reason"] is None, m["outcome"] == "decrypted")

    def test_real_unknown_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            users = os.path.join(tmp, "users.txt")
            with open(users, "w") as handle:
                handle.write(f"user: u_sha_aes\nengine_id: 0x80001f8880aaaaaaaa\nauth: SHA\n"
                             f"auth_pass: {gen.auth_pass('u_sha_aes')}\npriv: AES\npriv_pass: {gen.priv_pass('u_sha_aes')}\n")
            report = analyze_snmp_capture(V3_PCAP, users_file=users)
            outcomes = {u["user"]: u["outcomes"] for u in report["v3_users"]}
            self.assertEqual(outcomes["u_sha_aes"].get("unknown_engine"), 4)
            self.assertIn("SNMP_UNKNOWN_ENGINE", codes(report))
            self.assertNotIn(gen.priv_pass("u_sha_aes"), json.dumps(report))

    def test_real_without_a_users_file_nothing_decrypts(self):
        closed = analyze_snmp_capture(V3_PCAP)
        self.assertEqual(closed["summary"]["authpriv_decrypted"], 0)
        self.assertEqual(set(closed["summary"]["v3_outcomes"]), {"no_keys"})

    def test_real_no_passphrase_or_community_in_report_cli_or_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            md = os.path.join(tmp, "r.md")
            done = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", V3_PCAP, "--snmp",
                                   "--snmp-users", V3_USERS, "--save_file", md], capture_output=True, text=True, cwd=HERE)
            self.assertEqual(done.returncode, 0, done.stderr)
            with open(md) as handle:
                texts = [json.dumps(self.report), done.stdout, done.stderr, handle.read()]
        for text in texts:
            self.assertNotIn(V3_USERS, text)
            for secret in gen.v3_secrets():
                self.assertNotIn(secret, text)


@unittest.skipUnless(HAVE_TSHARK and glob.glob(os.path.join(LAB_DIR, "snmp-*.pcap")),
                     "no snmp-*.pcap in the lab captures directory")
class TestLabCaptures(unittest.TestCase):
    """Any SNMP capture another writer left in the lab directory: every message is named."""

    def test_lab_captures_name_every_message(self):
        for pcap in sorted(glob.glob(os.path.join(LAB_DIR, "snmp-*.pcap"))):
            with self.subTest(capture=os.path.basename(pcap)):
                report = analyze_snmp_capture(pcap)
                self.assertEqual(report["status"], "success")
                self.assertTrue(all(m["version"] in ("v1", "v2c", "v3") for m in report["messages"]))


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSnmpInterfaces(unittest.TestCase):
    def test_mcp_tool_function(self):
        import mcp_server
        tool = mcp_server.analyze_snmp_pcap
        fn = getattr(tool, "fn", tool)
        report = fn(file_path=fixture("snmp_v1v2c.pcap"))
        self.assertEqual(report["status"], "success")
        self.assertIn("SNMP_CLEARTEXT_COMMUNITY", codes(report))
        self.assertEqual(fn(file_path="/nonexistent.pcap")["status"], "error")
        self.assertEqual(fn(file_path=fixture("snmp_v1v2c.pcap"), users_file="/nonexistent")["status"], "error")

    def test_cli_json_mode_holds_no_community(self):
        out = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", fixture("snmp_v1v2c.pcap"),
                              "--snmp", "--json", "--save_file", os.devnull], capture_output=True, text=True, cwd=HERE)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["summary"]["messages"], 5)
        for community in COMMUNITIES:
            self.assertNotIn(community, out.stdout)


class TestSnmpFixtures(unittest.TestCase):
    def test_synthetic_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_snmp_fixtures.py"), out],
                           check=True, capture_output=True)
            self.assertEqual(sorted(os.listdir(out)), ["snmp_v1v2c.pcap"])
            self.assertTrue(filecmp.cmp(os.path.join(out, "snmp_v1v2c.pcap"), fixture("snmp_v1v2c.pcap"),
                                        shallow=False), "rerun generate_snmp_fixtures.py")


if __name__ == "__main__":
    unittest.main()
