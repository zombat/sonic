#!/usr/bin/env python3
"""Unit tests for Phase 2 auth diagnostics scoring."""

import unittest

from analyzers.call_quality_scoring import CallQualityScorer


class TestAuthDiagnostics(unittest.TestCase):
    def setUp(self):
        self.scorer = CallQualityScorer()

    def test_risky_auth_flow_applies_expected_penalties(self):
        sip_data = {
            "sip_packets": [
                {"status_code": "401"},
                {"status_code": "407"},
                {"status_code": "407"},
                {"status_code": "407"},
                {"status_code": "200"},
            ],
            "rtp_streams": [{"payload_type": "0"}],
        }
        auth_data = {
            "auth_challenges": [
                {"status_code": "401", "algorithm": "MD5", "qop": ""},
                {"status_code": "407", "algorithm": "MD5", "qop": ""},
                {"status_code": "407", "algorithm": "MD5", "qop": ""},
                {"status_code": "407", "algorithm": "MD5", "qop": ""},
            ],
            "auth_responses": [],
            "register_attempts": [{"success": False}],
        }

        result = self.scorer.score_call_quality(sip_data, [], None, auth_data=auth_data)
        details = result.protocol_details

        self.assertEqual(details.get("auth_challenges_401"), 1.0)
        self.assertEqual(details.get("auth_challenges_407"), 3.0)
        self.assertEqual(details.get("register_failures"), 1.0)
        self.assertGreaterEqual(details.get("auth_penalty", 0.0), 60.0)

    def test_healthy_auth_flow_has_zero_auth_penalty(self):
        sip_data = {
            "sip_packets": [
                {"status_code": "401"},
                {"status_code": "200"},
            ],
            "rtp_streams": [{"payload_type": "0"}],
        }
        auth_data = {
            "auth_challenges": [
                {"status_code": "401", "algorithm": "SHA-256", "qop": "auth"},
            ],
            "auth_responses": [
                {"username": "user1", "realm": "example.com"},
            ],
            "register_attempts": [{"success": True}],
        }

        result = self.scorer.score_call_quality(sip_data, [], None, auth_data=auth_data)
        details = result.protocol_details

        self.assertEqual(details.get("auth_penalty"), 0.0)
        self.assertEqual(details.get("authentication"), 100.0)

    def test_sip_packet_fallback_tracks_auth_without_auth_data(self):
        sip_data = {
            "sip_packets": [
                {"status_code": "401", "authorization": ""},
                {"status_code": "407", "authorization": "Digest ..."},
                {"status_code": "200"},
            ],
            "rtp_streams": [{"payload_type": "0"}],
        }

        result = self.scorer.score_call_quality(sip_data, [], None)
        details = result.protocol_details

        self.assertEqual(details.get("auth_challenges_401"), 1.0)
        self.assertEqual(details.get("auth_challenges_407"), 1.0)
        self.assertEqual(details.get("auth_responses"), 1.0)


if __name__ == "__main__":
    unittest.main()
