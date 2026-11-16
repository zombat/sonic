#!/usr/bin/env python3
"""
Tests that SIP credentials never reach the LLM or a report (extractors/tshark.py).

A synthetic capture, built here with scapy, holds a REGISTER answered by a 401 Digest
challenge, the REGISTER again with an Authorization Digest response, and an INVITE with
a Proxy-Authorization Basic credential. Every value is a placeholder made up for this
test. The capture goes through the real extraction (tshark, and the scapy fallback), the
prompt S.O.N.I.C. hands the LLM client, and the quality-only CLI report; the digest
response, the Basic credential and the password inside it must appear in none of them,
while the username, realm, nonce and algorithm stay visible for troubleshooting.
An INVITE's SDP carries an SRTP master key (a=crypto inline:), a MIKEY payload (a=key-mgmt)
and a k= key; none may appear either, while the crypto suite stays.

Run with:  python3 -m pytest -q test_sip_credentials.py
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scapy.all import IP, UDP, Raw, wrpcap

from extractors.tshark import (SIP_CREDENTIAL_MASK, extract_sip_data, mask_sip_credentials,
                               read_pcap_with_scapy)

HERE = os.path.dirname(os.path.abspath(__file__))
HAVE_TSHARK = shutil.which("tshark") is not None

# Placeholders only: a made-up digest response and a made-up Basic user:password.
DIGEST_RESPONSE = "6629fae49393a05397450978507c4ef1"
NONCE = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
BASIC_PASSWORD = "not-a-real-password"
BASIC_CREDENTIAL = base64.b64encode(f"bob:{BASIC_PASSWORD}".encode()).decode()
# Made-up SDP media keys: an SDES SRTP master key||salt, a MIKEY payload and a k= key.
SRTP_KEY = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
MIKEY_PAYLOAD = "AQAFgM0XflABAAAAAAAAAAAAAAsAyOOh4RqXbQ"
SDP_K_KEY = "not-a-real-sdp-key"
SECRETS = (DIGEST_RESPONSE, BASIC_CREDENTIAL, BASIC_PASSWORD, SRTP_KEY, MIKEY_PAYLOAD, SDP_K_KEY)

CLIENT, SERVER = "192.0.2.10", "192.0.2.20"


def _sip(lines):
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _common(method, cseq, call_id="reg-1@192.0.2.10"):
    return [f"Via: SIP/2.0/UDP {CLIENT}:5060;branch=z9hG4bK-{cseq}",
            "From: <sip:alice@example.com>;tag=1928301774", "To: <sip:alice@example.com>",
            f"Call-ID: {call_id}", f"CSeq: {cseq} {method}", "Max-Forwards: 70", "Content-Length: 0"]


def _sdp():
    return ("v=0\r\no=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\ns=call\r\n"
            "c=IN IP4 192.0.2.10\r\nt=0 0\r\n"
            f"k=clear:{SDP_K_KEY}\r\n"
            "m=audio 49170 RTP/SAVP 0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{SRTP_KEY}|2^20|1:4\r\n"
            f"a=key-mgmt:mikey {MIKEY_PAYLOAD}\r\n")


def _invite_with_sdp():
    body = _sdp()
    head = ["INVITE sip:dave@example.com SIP/2.0"] + _common("INVITE", 1, "inv-2@192.0.2.10")[:-1] + [
        "Content-Type: application/sdp", f"Content-Length: {len(body)}"]
    return ("\r\n".join(head) + "\r\n\r\n" + body).encode()


def build_capture(path):
    messages = [
        (CLIENT, SERVER, _sip(["REGISTER sip:example.com SIP/2.0"] + _common("REGISTER", 1))),
        (SERVER, CLIENT, _sip(["SIP/2.0 401 Unauthorized"] + _common("REGISTER", 1) + [
            f'WWW-Authenticate: Digest realm="example.com", nonce="{NONCE}", algorithm=MD5, qop="auth"'])),
        (CLIENT, SERVER, _sip(["REGISTER sip:example.com SIP/2.0"] + _common("REGISTER", 2) + [
            f'Authorization: Digest username="alice", realm="example.com", nonce="{NONCE}", '
            f'uri="sip:example.com", response="{DIGEST_RESPONSE}", algorithm=MD5, qop=auth, '
            'nc=00000001, cnonce="0a4f113b"'])),
        (SERVER, CLIENT, _sip(["SIP/2.0 200 OK"] + _common("REGISTER", 2) + ["Expires: 3600"])),
        (CLIENT, SERVER, _sip(["INVITE sip:carol@example.com SIP/2.0"] + _common("INVITE", 1, "inv-1@192.0.2.10") + [
            f"Proxy-Authorization: Basic {BASIC_CREDENTIAL}"])),
        (CLIENT, SERVER, _invite_with_sdp()),
    ]
    packets = [IP(src=s, dst=d) / UDP(sport=5060, dport=5060) / Raw(load=m) for s, d, m in messages]
    for index, packet in enumerate(packets):
        packet.time = 1700000000 + index
    wrpcap(path, packets)


class SipCaptureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmp, "sip_auth.pcap")
        build_capture(cls.pcap)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assertNoCredential(self, text):
        for secret in SECRETS:
            self.assertNotIn(secret, text)


class TestMasking(unittest.TestCase):
    def test_digest_keeps_what_troubleshooting_needs(self):
        header = (f'Digest username="alice", realm="example.com", nonce="{NONCE}", uri="sip:example.com", '
                  f'response="{DIGEST_RESPONSE}", algorithm=MD5, qop=auth, nc=00000001, cnonce="0a4f113b"')
        masked = mask_sip_credentials(header)
        self.assertNotIn(DIGEST_RESPONSE, masked)
        self.assertIn(f'response="{SIP_CREDENTIAL_MASK}"', masked)
        for kept in ('username="alice"', 'realm="example.com"', f'nonce="{NONCE}"', "algorithm=MD5", "qop=auth"):
            self.assertIn(kept, masked)

    def test_basic_bearer_and_unknown_schemes_keep_only_the_scheme(self):
        self.assertEqual(mask_sip_credentials(f"Basic {BASIC_CREDENTIAL}"), f"Basic {SIP_CREDENTIAL_MASK}")
        self.assertEqual(mask_sip_credentials("Bearer abc.def.ghi"), f"Bearer {SIP_CREDENTIAL_MASK}")
        self.assertEqual(mask_sip_credentials("NTLM TlRMTVNTUAAB"), f"NTLM {SIP_CREDENTIAL_MASK}")

    def test_sdp_keys_are_masked_and_the_suite_stays(self):
        from extractors.tshark import mask_sip_text
        masked = mask_sip_text(_sdp())
        for secret in (SRTP_KEY, MIKEY_PAYLOAD, SDP_K_KEY):
            self.assertNotIn(secret, masked)
        self.assertIn(f"AES_CM_128_HMAC_SHA1_80 inline:{SIP_CREDENTIAL_MASK}|2^20|1:4", masked)
        self.assertIn(f"a=key-mgmt:mikey {SIP_CREDENTIAL_MASK}", masked)
        self.assertIn(f"k=clear:{SIP_CREDENTIAL_MASK}", masked)
        self.assertIn("m=audio 49170 RTP/SAVP 0", masked)

    def test_unquoted_response_and_auts(self):
        masked = mask_sip_credentials(f'Digest username="a",response={DIGEST_RESPONSE},auts="AKAresync"')
        self.assertNotIn(DIGEST_RESPONSE, masked)
        self.assertNotIn("AKAresync", masked)


class TestExtraction(SipCaptureCase):
    @unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
    def test_tshark_summary_masks_the_credential(self):
        summary = extract_sip_data(self.pcap)
        self.assertNoCredential(summary)
        packets = json.loads(summary)["sip_packets"]
        auth = [p["authorization"] for p in packets if p["authorization"]]
        self.assertEqual(len(auth), 1)
        for kept in ('username="alice"', 'realm="example.com"', NONCE, "algorithm=MD5"):
            self.assertIn(kept, auth[0])
        proxy = [p["proxy_authorization"] for p in packets if p["proxy_authorization"]]
        self.assertEqual(proxy, [f"Basic {SIP_CREDENTIAL_MASK}"])
        challenge = [p["www_authenticate"] for p in packets if p["www_authenticate"]]
        self.assertIn(NONCE, challenge[0])  # a challenge carries no credential and is kept

    def test_scapy_fallback_masks_the_credential(self):
        text = read_pcap_with_scapy(self.pcap)
        self.assertIn("Authorization: Digest", text)
        self.assertIn("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:", text)
        self.assertIn('username="alice"', text)
        self.assertNoCredential(text)

    @unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
    def test_auth_info_keeps_no_part_of_the_response(self):
        from extractors.auth_info import extract_auth_and_registration_info
        auth = extract_auth_and_registration_info(self.pcap)
        self.assertNoCredential(json.dumps(auth))
        self.assertEqual(auth["auth_responses"][0]["username"], "alice")
        self.assertEqual(auth["auth_responses"][0]["response_hash"], SIP_CREDENTIAL_MASK)
        self.assertNotIn(DIGEST_RESPONSE[:16], json.dumps(auth))


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestLlmPayloadAndReport(SipCaptureCase):
    def test_the_llm_prompt_holds_no_credential(self):
        import dspy
        from ai.analysis import sip_diagnostic_test
        from llm_config import RedactingLM
        seen = []

        def capture(self_lm, prompt=None, *, messages=None, **kwargs):
            seen.append({"prompt": prompt, "messages": messages})
            return ['{"analysis": "{}"}']

        lm = RedactingLM(model="anthropic/claude-haiku-5-5", api_key="placeholder-not-a-key")
        with mock.patch.object(dspy.LM, "__call__", capture):
            sip_diagnostic_test(lm, extract_sip_data(self.pcap), self.pcap)
        payload = json.dumps(seen)
        self.assertTrue(seen, "the LLM client was never called")
        self.assertIn("alice", payload)  # the SIP summary really was in the prompt
        self.assertNoCredential(payload)

    def test_the_llm_prompt_from_the_scapy_fallback_holds_no_credential(self):
        import dspy
        from ai.analysis import sip_diagnostic_test
        from llm_config import RedactingLM
        seen = []

        def capture(self_lm, prompt=None, *, messages=None, **kwargs):
            seen.append({"prompt": prompt, "messages": messages})
            return ['{"analysis": "{}"}']

        lm = RedactingLM(model="anthropic/claude-haiku-5-5", api_key="placeholder-not-a-key")
        with mock.patch.object(dspy.LM, "__call__", capture):
            sip_diagnostic_test(lm, read_pcap_with_scapy(self.pcap), self.pcap)
        payload = json.dumps(seen)
        self.assertIn("AES_CM_128_HMAC_SHA1_80", payload)  # the SDP really was in the prompt
        self.assertNoCredential(payload)

    def test_the_cli_report_holds_no_credential(self):
        report = os.path.join(self.tmp, "report.md")
        env = {k: v for k, v in os.environ.items()
               if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_KEY", "SONIC_ENV_FILE")}
        run = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", self.pcap,
                              "--quality-only", "--save_file", report],
                             cwd=HERE, env=env, capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stderr[-2000:])
        with open(report, encoding="utf-8") as handle:
            saved = handle.read()
        self.assertTrue(saved.strip())
        self.assertNoCredential(saved)
        self.assertNoCredential(run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
