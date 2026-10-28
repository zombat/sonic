#!/usr/bin/env python3
"""
Tests for the control plane, crypto and convergence detectors: the zero-cleartext
audit, IKEv2 exchange decoding, ESP SPI liveness, the DMVPN Phase 3 sequence, BGP
(OPEN, MSS, down cause), OSPF stuck in EXSTART/EXCHANGE, and the convergence timeline.

Every fixture is synthetic (built by tests/fixtures/generate_fixtures.py), and the
test names say so. Each detector assertion runs once per backend (tshark, scapy).
TestRealLabCaptures runs on the Pleiades lab captures when they exist on this machine
and skips otherwise.

Run with:  python3 -m unittest -q test_control_plane
"""

import glob
import json
import os
import shutil
import unittest

from analyzers.cleartext_audit import parse_allowlist
from analyzers.convergence import parse_event_time
from analyzers.network_orchestrator import (
    analyze_convergence_capture,
    analyze_network_capture,
    analyze_routing_capture,
    analyze_vpn_capture,
    audit_cleartext_capture,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
HAVE_TSHARK = shutil.which("tshark") is not None
BASE_TIME = 1767225600.0  # the fixtures' first-frame clock
LAB_CAPTURES = sorted(glob.glob("/home/noot/pleiades-cvd/*/project/captures/*.pcap"))
LAB_HUBS = ["172.16.1.2", "172.16.2.2"]


def fixture(name):
    return os.path.join(FIXTURES, name)


def codes(section):
    return {issue["code"] for issue in section["issues"]}


class ControlPlaneAssertions:
    """Findings on the synthetic control plane fixtures; mixed into one TestCase per backend."""

    backend = None

    def ok(self, report):
        self.assertEqual(report["status"], "success", report.get("error"))
        self.assertEqual(report["capture"]["backend"], self.backend)
        json.dumps(report)
        return report

    # -- zero-cleartext audit ------------------------------------------------

    def test_synthetic_audit_passes_a_crypto_only_link(self):
        for name in ("ipsec_ikev2_esp.pcap", "ipsec_natt.pcap"):
            with self.subTest(fixture=name):
                audit = self.ok(audit_cleartext_capture(fixture(name), backend=self.backend))
                self.assertTrue(audit["passed"])
                self.assertEqual(audit["result"], "pass")
                self.assertEqual(audit["frames_outside_allowlist"], 0)
                self.assertEqual(audit["frames_audited"], audit["frames_allowed"])
                self.assertTrue(audit["verdict"].startswith("PASS"))
                self.assertTrue(audit["cannot_show"])

    def test_synthetic_audit_fails_on_one_leaked_packet_of_each_kind(self):
        audit = self.ok(audit_cleartext_capture(fixture("audit_one_leak.pcap"), backend=self.backend))
        self.assertFalse(audit["passed"])
        self.assertEqual(audit["frames_outside_allowlist"], 5)
        found = {v["protocol"]: v for v in audit["violations"]}
        self.assertEqual(set(found), {"gre/ipv4 (bgp inside)", "icmp", "arp", "loop", "cdp"})
        self.assertEqual(found["gre/ipv4 (bgp inside)"]["category"], "tunnel_without_encryption")
        self.assertEqual(found["gre/ipv4 (bgp inside)"]["frames"], [9])
        self.assertEqual((found["icmp"]["src"], found["icmp"]["dst"]), ("198.51.100.2", "203.0.113.1"))
        self.assertEqual(found["cdp"]["category"], "layer2")
        self.assertEqual(audit["first_violation_frame"], 9)
        severities = {i["message"].split(" frame")[0]: i["severity"] for i in audit["issues"]}
        self.assertIn("error", severities.values())

    def test_synthetic_audit_allowlist_scoping(self):
        scoped = self.ok(audit_cleartext_capture(fixture("audit_one_leak.pcap"), backend=self.backend,
                                                 allow=["crypto", "arp", "l2-control", "icmp@203.0.113.1"]))
        self.assertFalse(scoped["passed"])
        self.assertEqual([v["protocol"] for v in scoped["violations"]], ["gre/ipv4 (bgp inside)"])
        self.assertEqual(scoped["allowed_by_rule"]["icmp@203.0.113.1"], 1)
        wrong_scope = self.ok(audit_cleartext_capture(fixture("audit_one_leak.pcap"), backend=self.backend,
                                                      allow=["crypto", "arp", "l2-control", "icmp@192.0.2.0/24"]))
        self.assertIn("icmp", {v["protocol"] for v in wrong_scope["violations"]})
        everything = self.ok(audit_cleartext_capture(fixture("audit_one_leak.pcap"), backend=self.backend,
                                                     allow=["crypto", "arp", "l2-control", "icmp", "gre"]))
        self.assertTrue(everything["passed"])

    def test_synthetic_audit_fails_on_routing_and_gre_without_ipsec(self):
        expectations = {"bgp_session.pcap": "bgp", "ospf_failover.pcap": "ospf", "gre_nhrp.pcap": "gre/nhrp",
                        "eigrp_mismatch.pcap": "eigrp"}
        for name, protocol in expectations.items():
            with self.subTest(fixture=name):
                audit = self.ok(audit_cleartext_capture(fixture(name), backend=self.backend))
                self.assertFalse(audit["passed"])
                self.assertIn(protocol, {p["protocol"] for p in audit["by_protocol"]})
        allowed = self.ok(audit_cleartext_capture(fixture("bgp_session.pcap"), backend=self.backend,
                                                  allow=["routing"]))
        self.assertTrue(allowed["passed"])

    # -- IKEv2 decoding ------------------------------------------------------

    def test_synthetic_ikev2_proposals_dh_retry_and_dpd(self):
        report = self.ok(analyze_vpn_capture(fixture("ikev2_negotiation.pcap"), backend=self.backend))
        sas = {sa["initiator"]: sa for sa in report["ipsec"]["ike_sas"]}
        good = sas["198.51.100.2"]
        neg = good["negotiation"]
        self.assertEqual(len(neg["proposals_offered"]), 2)
        self.assertEqual(neg["proposals_offered"][0]["encryption"], ["AES-GCM-16-256"])
        self.assertEqual(neg["proposals_offered"][0]["prf"], ["HMAC-SHA2-512"])
        self.assertEqual(neg["proposals_offered"][0]["dh_group"], ["ECP-256 (group 19)", "ECP-384 (group 20)"])
        self.assertEqual(neg["proposals_offered"][1]["weak"], ["MODP-1024 (group 2)"])
        self.assertEqual(neg["proposal_chosen"]["encryption"], ["AES-GCM-16-256"])
        self.assertEqual(neg["proposal_chosen"]["dh_group"], ["ECP-256 (group 19)"])
        self.assertEqual(neg["ke_groups_offered"], [20, 19])
        self.assertEqual(neg["ke_group_chosen"], 19)
        self.assertEqual(neg["invalid_ke_payload"][0]["group_requested"], 19)
        self.assertEqual(neg["invalid_ke_payload"][0]["group_offered"], 20)
        self.assertFalse(neg["nat_detection"]["nat_detected"])
        self.assertTrue(neg["nat_detection"]["payloads_seen"])
        self.assertEqual(neg["liveness"]["checks"], 3)  # the DELETE-sized INFORMATIONAL is not a DPD
        self.assertEqual(neg["liveness"]["unanswered"], 0)
        self.assertEqual(neg["liveness"]["interval_s_by_sender"]["198.51.100.2"], 10.0)
        self.assertEqual(good["diagnosis"]["code"], "ok")
        self.assertIn("after a DH group retry", good["diagnosis"]["text"])
        weak = sas["203.0.113.3"]
        self.assertEqual(weak["negotiation"]["proposal_chosen"]["weak"], ["3DES", "MODP-1024 (group 2)"])
        self.assertEqual(weak["negotiation"]["liveness"]["unanswered"], 1)
        self.assertEqual(weak["negotiation"]["liveness"]["unanswered_checks"][0]["transmissions"], 4)
        self.assertEqual(weak["diagnosis"]["code"], "liveness_lost")
        self.assertTrue({"IKE_WEAK_ALGORITHM", "IKE_LIVENESS_UNANSWERED", "IKE_RETRIED"} <= codes(report["ipsec"]))

    def test_synthetic_ikev2_failure_diagnoses(self):
        report = self.ok(analyze_vpn_capture(fixture("ikev2_failures.pcap"), backend=self.backend))
        diag = {d["initiator"]: d["diagnosis"]["code"] for d in report["ike_diagnoses"]}
        self.assertEqual(diag, {"198.51.100.10": "nat_t_missing", "198.51.100.11": "auth_failed",
                                "198.51.100.12": "auth_no_reply", "198.51.100.13": "dh_group_mismatch"})
        sas = {sa["initiator"]: sa for sa in report["ipsec"]["ike_sas"]}
        nat = sas["198.51.100.10"]["negotiation"]["nat_detection"]
        self.assertTrue(nat["nat_detected"])
        self.assertFalse(nat["moved_to_udp_4500"])
        self.assertEqual(nat["translated"][0]["field"], "source")
        self.assertEqual(nat["translated"][0]["observed"], "198.51.100.10:500")
        auth = next(d for d in report["ike_diagnoses"] if d["initiator"] == "198.51.100.11")["diagnosis"]["text"]
        self.assertIn("PSK mismatch", auth)
        self.assertIn("never visible", auth)
        self.assertTrue({"IKE_NAT_T_MISSING", "IKE_AUTH_NO_RESPONSE", "IKE_AUTH_LIKELY_FAILED",
                         "IKE_INVALID_KE_PAYLOAD"} <= codes(report["ipsec"]))

    def test_synthetic_nat_detected_and_moved_to_4500(self):
        report = self.ok(analyze_vpn_capture(fixture("ipsec_natt.pcap"), backend=self.backend))
        nat = report["ipsec"]["ike_sas"][0]["negotiation"]["nat_detection"]
        self.assertTrue(nat["nat_detected"])
        self.assertTrue(nat["moved_to_udp_4500"])
        self.assertEqual(nat["ike_auth_udp_ports"], [4500])
        self.assertEqual(report["ike_diagnoses"][0]["diagnosis"]["code"], "ok")
        clean = self.ok(analyze_vpn_capture(fixture("ipsec_ikev2_esp.pcap"), backend=self.backend))
        self.assertFalse(clean["ipsec"]["ike_sas"][0]["negotiation"]["nat_detection"]["nat_detected"])

    def test_synthetic_proposal_mismatch_names_the_offer(self):
        report = self.ok(analyze_vpn_capture(fixture("ikev2_no_proposal.pcap"), backend=self.backend))
        diag = report["ike_diagnoses"][0]["diagnosis"]
        self.assertEqual(diag["code"], "proposal_mismatch")
        self.assertIn("AES-CBC-256", diag["text"])
        self.assertIn("never crosses the wire", diag["text"])
        silent = self.ok(analyze_vpn_capture(fixture("ikev2_no_response.pcap"), backend=self.backend))
        self.assertEqual(silent["ike_diagnoses"][0]["diagnosis"]["code"], "no_reply")

    def test_synthetic_stale_spi_and_invalid_ike_spi(self):
        report = self.ok(analyze_vpn_capture(fixture("esp_stale_spi.pcap"), backend=self.backend))
        ipsec = report["ipsec"]
        stale = next(f for f in ipsec["esp_flows"] if f["spi"] == "0xaa000001")
        self.assertEqual(stale["stale_packets"], 2)
        self.assertEqual(len(stale["stale_frames"]), 2)
        self.assertTrue({"ESP_STALE_SPI", "IKE_INVALID_IKE_SPI"} <= codes(ipsec))
        issue = next(i for i in ipsec["issues"] if i["code"] == "ESP_STALE_SPI")
        self.assertEqual(issue["newer_spi"], "0xbb000001")
        self.assertEqual(report["ike_diagnoses"][0]["diagnosis"]["code"], "peer_lost_sa")
        fresh = self.ok(analyze_vpn_capture(fixture("ipsec_ikev2_esp.pcap"), backend=self.backend))
        self.assertNotIn("ESP_STALE_SPI", codes(fresh["ipsec"]))

    # -- DMVPN Phase 3 -------------------------------------------------------

    def test_synthetic_phase3_complete_sequence(self):
        report = self.ok(analyze_vpn_capture(fixture("gre_nhrp.pcap"), backend=self.backend))
        p3 = report["dmvpn_phase3"]
        self.assertEqual(len(p3["flows"]), 1)
        flow = p3["flows"][0]
        self.assertEqual(flow["result"], "complete")
        self.assertIsNone(flow["missing_step"])
        self.assertEqual([flow["steps"][s]["frame"] for s in
                          ("via_hub", "redirect", "resolution_request", "resolution_reply", "direct")],
                         [7, 9, 10, 12, 15])
        self.assertEqual(flow["forwarded_by_hub_to"], "203.0.113.3")
        self.assertEqual(flow["timings"]["resolution_rtt_ms"], 10.0)
        self.assertEqual(p3["status"], "ok")

    def test_synthetic_phase3_each_missing_step(self):
        report = self.ok(analyze_vpn_capture(fixture("nhrp_phase3_broken.pcap"), backend=self.backend))
        p3 = report["dmvpn_phase3"]
        missing = {(f["spoke"], f["original_dst"]): f["missing_step"] for f in p3["flows"]}
        self.assertEqual(missing, {("198.51.100.2", "10.1.3.1"): "resolution_reply",
                                   ("203.0.113.3", "10.1.2.1"): "resolution_request",
                                   ("192.0.2.44", "10.1.2.1"): "direct"})
        relayed = p3["hub_relayed_without_redirect"]
        self.assertEqual([(r["spoke"], r["inner_dst"], r["to_spoke"]) for r in relayed],
                         [("192.0.2.44", "10.1.3.1", "203.0.113.3")])
        thrash = p3["resolution_thrashing"]
        self.assertTrue(thrash["thrashing"])
        spoke = next(s for s in thrash["spokes"] if s["spoke_nbma"] == "198.51.100.2")
        self.assertEqual(spoke["requests"], 8)
        self.assertGreaterEqual(spoke["peak_per_second"], 5)
        self.assertEqual(spoke["targets"][0]["unanswered"], 8)
        self.assertTrue({"PHASE3_MISSING_RESOLUTION_REPLY", "PHASE3_MISSING_RESOLUTION_REQUEST",
                         "PHASE3_MISSING_DIRECT", "PHASE3_NO_REDIRECT", "NHRP_RESOLUTION_THRASHING"} <= codes(p3))
        self.assertEqual(p3["status"], "problem")

    def test_synthetic_phase3_encrypted_shortcuts_need_hubs(self):
        report = self.ok(analyze_vpn_capture(fixture("phase3_encrypted.pcap"), backend=self.backend,
                                             hubs=["192.0.2.1", "192.0.2.2"]))
        shortcuts = {tuple(s["spokes"]): s for s in report["dmvpn_phase3"]["encrypted_shortcuts"]["shortcuts"]}
        good = shortcuts[("198.51.100.2", "203.0.113.3")]
        self.assertEqual(good["result"], "complete")
        self.assertEqual(good["setup_ms"], 30.0)
        self.assertIsNotNone(good["steps"]["esp_to_hub_before"])
        bad = shortcuts[("198.51.100.2", "198.51.100.4")]
        self.assertEqual(bad["missing_step"], "ike_sa_init")
        self.assertIn("SHORTCUT_MISSING_IKE_SA_INIT", codes(report["dmvpn_phase3"]))
        self.assertIn("inside ESP", report["dmvpn_phase3"]["encrypted_shortcuts"]["not_visible"])
        without = self.ok(analyze_vpn_capture(fixture("phase3_encrypted.pcap"), backend=self.backend))
        self.assertEqual(without["dmvpn_phase3"]["status"], "not_present")
        self.assertIn("pass hubs", without["phase3_verdict"])

    # -- BGP -----------------------------------------------------------------

    def test_synthetic_bgp_down_causes_mss_and_open(self):
        report = self.ok(analyze_routing_capture(fixture("bgp_failover.pcap"), backend=self.backend,
                                                 expected_mss=1360))
        sessions = {tuple(s["peers"]): s for s in report["routing"]["bgp"]["sessions"]}
        hub1 = sessions[("10.255.0.1", "10.255.0.11")]
        self.assertEqual(hub1["downs"][0]["cause"], "hold_timer_expired")
        self.assertEqual(hub1["downs"][0]["quietest_speaker"], "10.255.0.1")
        self.assertEqual(hub1["downs"][0]["quietest_last_message_t"], 40.002)
        self.assertEqual(hub1["tcp_mss"][0]["mss"], {"10.255.0.11": 1360, "10.255.0.1": 1360})
        self.assertEqual(set(hub1["tcp_mss"][0]["check"].values()), {"ok"})
        speaker = hub1["speakers"]["10.255.0.11"]
        self.assertEqual(speaker["capabilities"], ["multiprotocol", "route-refresh", "4-byte-as"])
        self.assertEqual(speaker["keepalive_interval_s"], 10.0)
        self.assertEqual(hub1["expected_keepalive_interval_s"], 10.0)
        hub2 = sessions[("10.255.0.2", "10.255.0.11")]
        self.assertEqual(hub2["state"], "established")
        self.assertEqual(set(hub2["tcp_mss"][0]["check"].values()), {"above_expected"})
        self.assertEqual(hub2["speakers"]["10.255.0.2"]["updates"][-1]["t"], 70.5)
        self.assertEqual(sessions[("10.255.0.3", "10.255.0.11")]["downs"][0]["cause"], "tcp_rst")
        inferred = sessions[("10.255.0.4", "10.255.0.11")]["downs"][0]
        self.assertEqual(inferred["cause"], "hold_timer_expired_inferred")
        self.assertEqual(inferred["quietest_speaker"], "10.255.0.4")
        self.assertIn("BGP_MSS_NOT_CLAMPED", codes(report["routing"]["bgp"]))
        mss_issue = next(i for i in report["routing"]["bgp"]["issues"] if i["code"] == "BGP_MSS_NOT_CLAMPED"
                         and "1460" in i["message"])
        self.assertEqual(mss_issue["expected_mss"], 1360)
        plain = self.ok(analyze_routing_capture(fixture("bgp_failover.pcap"), backend=self.backend))
        self.assertNotIn("BGP_MSS_NOT_CLAMPED", codes(plain["routing"]["bgp"]))

    # -- OSPF ----------------------------------------------------------------

    def test_synthetic_ospf_stuck_exstart_and_exchange(self):
        report = self.ok(analyze_routing_capture(fixture("ospf_stuck.pcap"), backend=self.backend))
        ospf = report["routing"]["ospf"]
        by_net = {link["network"]: link["adjacencies"][0]["database_exchange"] for link in ospf["links"]}
        self.assertEqual(by_net["10.0.45.0/24"]["stuck"], "exstart")
        self.assertIn("MTU mismatch", by_net["10.0.45.0/24"]["cause"])
        self.assertEqual({s["router"]: s["mtu"] for s in by_net["10.0.45.0/24"]["sides"]},
                         {"4.4.4.4": 1500, "5.5.5.5": 1400})
        self.assertEqual(by_net["10.0.67.0/24"]["stuck"], "exchange")
        sides = {s["router"]: s for s in by_net["10.0.67.0/24"]["sides"]}
        self.assertEqual(sides["7.7.7.7"]["unacknowledged_sequences"], {"7001": 4})
        self.assertTrue({"OSPF_EXSTART_STUCK", "OSPF_EXCHANGE_STUCK", "OSPF_MTU_MISMATCH"} <= codes(ospf))
        mtu = next(i for i in ospf["issues"] if i["code"] == "OSPF_MTU_MISMATCH")
        self.assertTrue(mtu["frames"])
        healthy = self.ok(analyze_routing_capture(fixture("ospf_failover.pcap"), backend=self.backend))
        exchange = healthy["routing"]["ospf"]["links"][0]["adjacencies"][0]["database_exchange"]
        self.assertIsNone(exchange["stuck"])

    # -- Convergence ---------------------------------------------------------

    def test_synthetic_convergence_dpd_driven(self):
        conv = self.ok(analyze_convergence_capture(fixture("convergence_dpd.pcap"), backend=self.backend,
                                                   event_time=30))
        self.assertEqual(conv["failed_peer"], "192.0.2.1")
        self.assertEqual(conv["driver"]["mechanism"], "dpd")
        m = conv["measurements"]
        self.assertEqual(m["first_failure_sign"]["signal"], "esp_stopped")
        self.assertEqual(m["event_to_first_failure_sign_s"], -0.05)
        self.assertEqual(m["detection"]["signal"], "dpd_gave_up")
        self.assertEqual(m["event_to_detection_s"], 11.0)
        self.assertEqual(m["traffic_resumed"]["signal"], "traffic_shift")
        self.assertEqual(m["event_to_traffic_resumed_s"], 12.0)
        self.assertIsNone(m["event_to_first_update_s"])  # BGP is inside ESP here
        self.assertEqual(conv["traffic_shift"]["surviving_pairs"], [["198.51.100.2", "192.0.2.2"],
                                                                     ["192.0.2.2", "198.51.100.2"]])
        phases = [e["phase"] for e in conv["timeline"]]
        self.assertIn("event", phases)
        same = self.ok(analyze_convergence_capture(fixture("convergence_dpd.pcap"), backend=self.backend,
                                                   event_time=BASE_TIME + 30))
        self.assertEqual(same["measurements"]["event_to_detection_s"], 11.0)
        iso = self.ok(analyze_convergence_capture(fixture("convergence_dpd.pcap"), backend=self.backend,
                                                  event_time="2026-01-01T00:00:30Z"))
        self.assertEqual(iso["measurements"]["event_to_detection_s"], 11.0)

    def test_synthetic_convergence_without_event_time(self):
        conv = self.ok(analyze_convergence_capture(fixture("convergence_dpd.pcap"), backend=self.backend))
        self.assertEqual(conv["measurements"]["origin"], "first_failure_sign")
        self.assertEqual(conv["measurements"]["origin_t"], 29.95)
        self.assertEqual(conv["failed_peer"], "192.0.2.1")
        self.assertEqual(conv["driver"]["mechanism"], "dpd")
        quiet = self.ok(analyze_convergence_capture(fixture("ipsec_ikev2_esp.pcap"), backend=self.backend))
        self.assertIsNone(quiet["measurements"]["origin"])
        self.assertTrue(quiet["verdict"].startswith("No failure seen"))

    def test_synthetic_convergence_bgp_hold_timer_driven(self):
        conv = self.ok(analyze_convergence_capture(fixture("bgp_failover.pcap"), backend=self.backend,
                                                   event_time=40.5))
        self.assertEqual(conv["failed_peer"], "10.255.0.1")
        self.assertEqual(conv["driver"]["mechanism"], "bgp_hold_timer")
        m = conv["measurements"]
        self.assertEqual(m["first_failure_sign"]["signal"], "bgp_last_message")
        self.assertEqual(m["event_to_detection_s"], 29.5)
        self.assertEqual(m["detection"]["signal"], "bgp_hold_expired")
        self.assertEqual(m["event_to_first_update_s"], 30.0)
        self.assertEqual(m["first_update_on_surviving_path"]["frame"], 112)
        self.assertIn("10.255.0.2", m["first_update_on_surviving_path"]["detail"])
        self.assertEqual(m["traffic_resumed"]["signal"], "icmp_recovered")
        self.assertEqual(m["event_to_traffic_resumed_s"], 30.52)

    def test_synthetic_convergence_driver_from_timing(self):
        conv = self.ok(analyze_convergence_capture(fixture("convergence_dpd.pcap"), backend=self.backend,
                                                   event_time=30, failed_peer="192.0.2.1", hold_time=30))
        self.assertEqual(conv["failed_peer_source"], "given")
        self.assertEqual(conv["driver"]["mechanism"], "dpd")  # DPD gave up long before 30 s


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestControlPlaneTshark(ControlPlaneAssertions, unittest.TestCase):
    backend = "tshark"


class TestControlPlaneScapy(ControlPlaneAssertions, unittest.TestCase):
    backend = "scapy"


class TestControlPlaneArguments(unittest.TestCase):
    """Argument handling that does not depend on the backend."""

    def test_bad_allowlist_token_is_refused(self):
        result = audit_cleartext_capture(fixture("audit_one_leak.pcap"), allow=["bogus"])
        self.assertEqual(result["status"], "error")
        self.assertIn("bogus", result["error"])
        with self.assertRaises(ValueError):
            parse_allowlist(["icmp@not-a-network"])
        with self.assertRaises(ValueError):
            parse_allowlist(["tcp:abc"])
        self.assertEqual(len(parse_allowlist(None)), 1)

    def test_event_time_forms(self):
        self.assertEqual(parse_event_time(30, 1000.0), 1030.0)
        self.assertEqual(parse_event_time("+2.5", 1000.0), 1002.5)
        self.assertEqual(parse_event_time(BASE_TIME + 1, 0.0), BASE_TIME + 1)
        self.assertEqual(parse_event_time("2026-01-01T00:00:01Z", 0.0), BASE_TIME + 1)
        with self.assertRaises(ValueError):
            parse_event_time("yesterday", 0.0)
        with self.assertRaises(ValueError):
            parse_event_time("2026-01-01T00:00:01", 0.0)  # no zone
        bad = analyze_convergence_capture(fixture("convergence_dpd.pcap"), event_time="yesterday")
        self.assertEqual(bad["status"], "error")

    def test_bad_options_are_refused(self):
        self.assertEqual(analyze_vpn_capture(fixture("gre_nhrp.pcap"), hubs=["hub1"])["status"], "error")
        self.assertEqual(analyze_routing_capture(fixture("bgp_failover.pcap"), expected_mss=-5)["status"], "error")
        self.assertEqual(analyze_convergence_capture(fixture("bgp_failover.pcap"), failed_peer="x")["status"],
                         "error")
        bad = analyze_network_capture(fixture("gre_nhrp.pcap"), options={"colour": "blue"})
        self.assertEqual(bad["status"], "error")

    def test_optional_detectors_run_only_when_named(self):
        report = analyze_network_capture(fixture("audit_one_leak.pcap"), include_sip=False)
        self.assertNotIn("cleartext_audit", report)
        self.assertNotIn("convergence", report)
        named = analyze_network_capture(fixture("audit_one_leak.pcap"), include_sip=False,
                                        detectors=["cleartext_audit", "ipsec"], options={"allow": ["crypto"]})
        self.assertEqual(named["cleartext_audit"]["result"], "fail")
        self.assertEqual(named["overall_status"], "problem")


@unittest.skipUnless(LAB_CAPTURES, "no Pleiades lab captures on this machine")
class TestRealLabCaptures(unittest.TestCase):
    """The Pleiades CML lab's transport-link captures (DMVPN Phase 3 over IKEv2/IPsec)."""

    def test_real_captures_are_crypto_plus_cisco_link_keepalives(self):
        for path in LAB_CAPTURES:
            with self.subTest(capture=path):
                strict = audit_cleartext_capture(path)
                self.assertEqual(strict["status"], "success")
                leaked = {p["protocol"] for p in strict["by_protocol"]}
                self.assertTrue(leaked <= {"loop", "cdp"}, leaked)
                relaxed = audit_cleartext_capture(path, allow=["crypto", "l2-control"])
                self.assertTrue(relaxed["passed"], relaxed["verdict"])

    def test_real_captures_decode_the_lab_proposal(self):
        for path in LAB_CAPTURES:
            report = analyze_vpn_capture(path, hubs=LAB_HUBS)
            for sa in report["ipsec"]["ike_sas"]:
                chosen = (sa.get("negotiation") or {}).get("proposal_chosen")
                if not chosen:
                    continue
                with self.subTest(capture=path, spi=sa["initiator_spi"]):
                    self.assertEqual(chosen["encryption"], ["AES-GCM-16-256"])
                    self.assertEqual(chosen["prf"], ["HMAC-SHA2-512"])
                    self.assertEqual(chosen["dh_group"], ["ECP-256 (group 19)"])
                    self.assertFalse(sa["negotiation"]["nat_detection"]["nat_detected"])

    def test_real_steady_state_captures_show_no_failover(self):
        for path in LAB_CAPTURES:
            with self.subTest(capture=path):
                conv = analyze_convergence_capture(path)
                self.assertEqual(conv["status"], "success")
                self.assertIsNone(conv["measurements"]["origin"], conv["verdict"])


if __name__ == "__main__":
    unittest.main()
