#!/usr/bin/env python3
"""
Unit tests for Phase 3: Auth Reporting & Visualization

Tests security posture scoring, realm/server mapping, sequence diagrams,
and upgrade recommendations engine.
"""

import unittest
from extractors.auth_info import calculate_auth_security_posture, generate_auth_upgrade_recommendations
from utils.reporting import format_realm_server_mapping, generate_auth_sequence_ascii, generate_mermaid_auth_sequence


class TestAuthSecurityPosture(unittest.TestCase):
    """Test auth security posture scoring function"""
    
    def test_excellent_security_posture(self):
        """Test that SHA-256 with qop=auth-int receives A+ grade"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "SHA-256", "qop": "auth-int", "status_code": "401"},
            ],
            "auth_responses": [
                {"username": "user1", "realm": "pbx.example.com"},
            ],
            "register_attempts": [
                {"success": True, "authenticated": True}
            ]
        }
        
        posture = calculate_auth_security_posture(auth_data)
        
        self.assertIn(posture["grade"], ["A+", "A"])
        self.assertGreaterEqual(posture["score"], 95)
        self.assertGreater(len(posture["factors"]), 0)
        self.assertEqual(len(posture["risks"]), 0)
    
    def test_weak_security_posture(self):
        """Test that MD5 without qop receives low grade"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "MD5", "qop": "", "status_code": "401"},
                {"algorithm": "MD5", "qop": "", "status_code": "401"},
            ],
            "auth_responses": [],
            "register_attempts": [
                {"success": False, "authenticated": False}
            ]
        }
        
        posture = calculate_auth_security_posture(auth_data)
        
        self.assertIn(posture["grade"], ["D", "F"])
        self.assertLess(posture["score"], 60)
        self.assertGreater(len(posture["risks"]), 0)
        self.assertGreater(len(posture["recommendations"]), 0)
    
    def test_mixed_security_posture(self):
        """Test mixed auth configuration receives C grade"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "SHA-256", "qop": "auth", "status_code": "401"},
                {"algorithm": "MD5", "qop": "", "status_code": "407"},
            ],
            "auth_responses": [
                {"username": "user1", "realm": "pbx.example.com"},
            ],
            "register_attempts": [
                {"success": True, "authenticated": True}
            ]
        }
        
        posture = calculate_auth_security_posture(auth_data)
        
        self.assertIn(posture["grade"], ["B", "C"])
        self.assertGreaterEqual(posture["score"], 60)
        self.assertLessEqual(posture["score"], 89)
    
    def test_no_auth_data(self):
        """Test handling of no authentication data"""
        auth_data = {
            "auth_challenges": [],
            "auth_responses": [],
            "register_attempts": []
        }
        
        posture = calculate_auth_security_posture(auth_data)
        
        self.assertEqual(posture["grade"], "N/A")
        self.assertEqual(posture["score"], 0)


class TestUpgradeRecommendations(unittest.TestCase):
    """Test upgrade recommendations engine"""
    
    def test_md5_upgrade_recommendation(self):
        """Test that MD5 algorithm triggers upgrade recommendation"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "MD5", "qop": "auth", "status_code": "401"},
            ],
            "auth_responses": [
                {"username": "user1"},
            ],
            "register_attempts": []
        }
        
        recommendations = generate_auth_upgrade_recommendations(auth_data)
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("SHA-256" in rec for rec in recommendations))
        self.assertTrue(any("MD5" in rec or "Algorithm" in rec for rec in recommendations))
    
    def test_missing_qop_recommendation(self):
        """Test that missing qop triggers recommendation"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "SHA-256", "qop": "", "status_code": "401"},
                {"algorithm": "SHA-256", "qop": "", "status_code": "401"},
            ],
            "auth_responses": [
                {"username": "user1"},
            ],
            "register_attempts": []
        }
        
        recommendations = generate_auth_upgrade_recommendations(auth_data)
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("qop" in rec.lower() for rec in recommendations))
    
    def test_failed_register_recommendation(self):
        """Test that failed REGISTER triggers recommendation"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "SHA-256", "qop": "auth", "status_code": "401"},
            ],
            "auth_responses": [],
            "register_attempts": [
                {"success": False, "authenticated": False}
            ]
        }
        
        recommendations = generate_auth_upgrade_recommendations(auth_data)
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("REGISTER" in rec or "registration" in rec.lower() for rec in recommendations))
    
    def test_cascading_407_recommendation(self):
        """Test that cascading 407s trigger recommendation"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "SHA-256", "qop": "auth", "status_code": "407"},
                {"algorithm": "SHA-256", "qop": "auth", "status_code": "407"},
                {"algorithm": "SHA-256", "qop": "auth", "status_code": "407"},
                {"algorithm": "SHA-256", "qop": "auth", "status_code": "407"},
            ],
            "auth_responses": [
                {"username": "user1"},
            ],
            "register_attempts": []
        }
        
        recommendations = generate_auth_upgrade_recommendations(auth_data)
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("407" in rec or "proxy" in rec.lower() or "cascading" in rec.lower() for rec in recommendations))
    
    def test_no_recommendations_for_good_config(self):
        """Test that good configuration generates fewer recommendations"""
        auth_data = {
            "auth_challenges": [
                {"algorithm": "SHA-256", "qop": "auth-int", "status_code": "401"},
            ],
            "auth_responses": [
                {"username": "user1"},
            ],
            "register_attempts": [
                {"success": True, "authenticated": True}
            ]
        }
        
        recommendations = generate_auth_upgrade_recommendations(auth_data)
        
        # Good config should have 0 or very few recommendations
        self.assertLessEqual(len(recommendations), 1)


class TestRealmServerMapping(unittest.TestCase):
    """Test realm and server mapping display"""
    
    def test_format_realm_server_mapping(self):
        """Test realm/server mapping formatting"""
        auth_data = {
            "sip_servers": {
                "192.168.1.100": {
                    "challenge_count": 2,
                    "server_challenges": 2,
                    "proxy_challenges": 0,
                    "realms": ["pbx.example.com"]
                },
                "10.0.0.50": {
                    "challenge_count": 3,
                    "server_challenges": 0,
                    "proxy_challenges": 3,
                    "realms": ["proxy.example.com"]
                }
            },
            "auth_challenges": [
                {"realm": "pbx.example.com", "algorithm": "SHA-256", "qop": "auth", "from_ip": "192.168.1.100"},
                {"realm": "pbx.example.com", "algorithm": "SHA-256", "qop": "auth", "from_ip": "192.168.1.100"},
                {"realm": "proxy.example.com", "algorithm": "MD5", "qop": "", "from_ip": "10.0.0.50"},
                {"realm": "proxy.example.com", "algorithm": "MD5", "qop": "", "from_ip": "10.0.0.50"},
                {"realm": "proxy.example.com", "algorithm": "MD5", "qop": "", "from_ip": "10.0.0.50"},
            ]
        }
        
        output = format_realm_server_mapping(auth_data)
        
        self.assertIn("192.168.1.100", output)
        self.assertIn("10.0.0.50", output)
        self.assertIn("pbx.example.com", output)
        self.assertIn("proxy.example.com", output)
        self.assertIn("Registrar", output)  # 192.168.1.100 role
        self.assertIn("Proxy", output)  # 10.0.0.50 role
    
    def test_empty_server_data(self):
        """Test handling of empty server data"""
        auth_data = {
            "sip_servers": {},
            "auth_challenges": []
        }
        
        output = format_realm_server_mapping(auth_data)
        
        self.assertIn("No SIP servers", output)


class TestAuthSequenceDiagrams(unittest.TestCase):
    """Test authentication sequence diagram generation"""
    
    def test_ascii_sequence_generation(self):
        """Test ASCII sequence diagram generation"""
        register_attempt = {
            "call_id": "test-123@example.com",
            "packets": [
                {"packet_num": 5, "type": "request", "has_auth": False},
                {"packet_num": 7, "type": "challenge", "status_code": "401"},
                {"packet_num": 9, "type": "request", "has_auth": True},
                {"packet_num": 11, "type": "response", "status_code": "200"}
            ],
            "success": True
        }
        
        auth_challenges = [
            {"packet_num": 7, "realm": "pbx.example.com", "algorithm": "SHA-256"}
        ]
        
        output = generate_auth_sequence_ascii(register_attempt, auth_challenges)
        
        self.assertIn("Client", output)
        self.assertIn("Server", output)
        self.assertIn("REGISTER", output)
        self.assertIn("401", output)
        self.assertIn("200", output)
        self.assertIn("#5", output)  # Packet numbers
        self.assertIn("#7", output)
        self.assertIn("#9", output)
        self.assertIn("#11", output)
    
    def test_mermaid_sequence_generation(self):
        """Test Mermaid diagram generation"""
        register_attempt = {
            "call_id": "test-456@example.com",
            "packets": [
                {"packet_num": 10, "type": "request", "has_auth": False},
                {"packet_num": 12, "type": "challenge", "status_code": "407"},
                {"packet_num": 14, "type": "request", "has_auth": True},
                {"packet_num": 16, "type": "response", "status_code": "200"}
            ],
            "success": True
        }
        
        auth_challenges = [
            {"packet_num": 12, "realm": "proxy.example.com", "algorithm": "MD5", "qop": "auth"}
        ]
        
        output = generate_mermaid_auth_sequence(register_attempt, auth_challenges)
        
        self.assertIn("```mermaid", output)
        self.assertIn("sequenceDiagram", output)
        self.assertIn("participant Client", output)
        self.assertIn("participant Server", output)
        self.assertIn("REGISTER", output)
        self.assertIn("407", output)
        self.assertIn("200", output)
        self.assertIn("✅ Registration Successful", output)
    
    def test_failed_register_mermaid(self):
        """Test Mermaid diagram for failed registration"""
        register_attempt = {
            "call_id": "test-789@example.com",
            "packets": [
                {"packet_num": 20, "type": "request", "has_auth": False},
                {"packet_num": 22, "type": "challenge", "status_code": "401"},
                {"packet_num": 24, "type": "request", "has_auth": True},
                {"packet_num": 26, "type": "challenge", "status_code": "401"}
            ],
            "success": False
        }
        
        output = generate_mermaid_auth_sequence(register_attempt, [])
        
        self.assertIn("❌ Registration Failed", output)
    
    def test_empty_packet_sequence(self):
        """Test handling of empty packet sequence"""
        register_attempt = {
            "call_id": "test-empty@example.com",
            "packets": []
        }
        
        ascii_output = generate_auth_sequence_ascii(register_attempt, [])
        mermaid_output = generate_mermaid_auth_sequence(register_attempt, [])
        
        self.assertIn("No packet sequence", ascii_output)
        self.assertEqual(mermaid_output, "")


if __name__ == "__main__":
    unittest.main()
