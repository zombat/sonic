#!/usr/bin/env python3
"""
Tests for the deterministic network detectors (IPsec, GRE/NHRP, routing, reachability).

Each fixture in tests/fixtures/ is a small synthetic capture built by
tests/fixtures/generate_fixtures.py. Every detector assertion runs twice, once
through the tshark backend and once through the scapy fallback, so both
extraction paths are held to the same findings.

Run with:  python3 -m pytest -q test_network_detectors.py
      or:  python3 -m unittest -q test_network_detectors.py
"""

import filecmp
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from analyzers.network_common import Context
from analyzers.network_orchestrator import (
    analyze_network_capture,
    analyze_routing_capture,
    analyze_vpn_capture,
)
from analyzers.gre_nhrp import GreNhrpDetector
from analyzers.routing_health import RoutingDetector
from extractors import network as network_extractor

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
HAVE_TSHARK = shutil.which("tshark") is not None


def fixture(name):
    return os.path.join(FIXTURES, name)


def issue_codes(section):
    return {issue["code"] for issue in section["issues"]}


def events(report, event=None):
    return [e for e in report["timeline"] if event is None or e["event"] == event]


class DetectorAssertions:
    """Detector findings on every fixture; mixed into one TestCase per backend."""

    backend = None

    def run_capture(self, name, **kwargs):
        kwargs.setdefault("include_sip", False)
        report = analyze_network_capture(fixture(name), backend=self.backend, **kwargs)
        self.assertEqual(report["status"], "success", report.get("error"))
        self.assertEqual(report["capture"]["backend"], self.backend)
        json.dumps(report)  # every report must be JSON-serializable
        return report

    # -- IPsec ---------------------------------------------------------------

    def test_ikev2_then_esp_is_encrypted(self):
        report = self.run_capture("ipsec_ikev2_esp.pcap")
        ipsec = report["ipsec"]
        self.assertEqual(ipsec["encryption_verdict"], "encrypted")
        self.assertTrue(ipsec["verdict"].startswith("all inter-site traffic encrypted"))
        self.assertEqual(ipsec["status"], "ok")
        self.assertEqual(len(ipsec["ike_sas"]), 1)
        sa = ipsec["ike_sas"][0]
        self.assertEqual(sa["ike_version"], 2)
        self.assertEqual(sa["outcome"], "established")
        self.assertEqual(sa["initiator"], "198.51.100.2")
        self.assertEqual(sa["responder"], "192.0.2.1")
        self.assertEqual(sa["rekeys"], 1)
        self.assertEqual(sa["retransmissions"], 0)
        flows = {(f["src"], f["spi"]): f for f in ipsec["esp_flows"]}
        self.assertEqual(len(flows), 4)
        self.assertEqual(flows[("198.51.100.2", "0xc0ffee01")]["packets"], 10)
        self.assertEqual(flows[("192.0.2.1", "0xc0ffee12")]["packets"], 5)
        self.assertEqual(flows[("198.51.100.2", "0xc0ffee01")]["missing_sequence_numbers"], 0)
        self.assertEqual(len(events(report, "spi_change")), 2)
        self.assertFalse(ipsec["nat_traversal"]["in_use"])
        self.assertTrue(ipsec["nat_traversal"]["nat_detection_payloads_seen"])
        self.assertEqual(ipsec["peer_pairs"][0]["verdict"], "encrypted")
        self.assertEqual(report["overall_status"], "ok")

    def test_cleartext_icmp_between_the_same_peers(self):
        report = self.run_capture("ipsec_cleartext_icmp.pcap")
        ipsec = report["ipsec"]
        self.assertEqual(ipsec["encryption_verdict"], "cleartext_seen")
        self.assertIn("cleartext seen: icmp 198.51.100.2->192.0.2.1 4 packets", ipsec["verdict"])
        directions = {(c["protocol"], c["src"], c["dst"]): c["packets"] for c in ipsec["cleartext"]}
        self.assertEqual(directions[("icmp", "198.51.100.2", "192.0.2.1")], 4)
        self.assertEqual(directions[("icmp", "192.0.2.1", "198.51.100.2")], 4)
        cleartext_issues = [i for i in ipsec["issues"] if i["code"] == "CLEARTEXT_BETWEEN_PEERS"]
        self.assertEqual(len(cleartext_issues), 1)
        self.assertEqual(cleartext_issues[0]["severity"], "warning")  # ICMP only: maybe an underlay ping
        self.assertEqual(ipsec["peer_pairs"][0]["verdict"], "cleartext")

    def test_ikev2_no_proposal_chosen(self):
        report = self.run_capture("ikev2_no_proposal.pcap")
        ipsec = report["ipsec"]
        sa = ipsec["ike_sas"][0]
        self.assertEqual(sa["outcome"], "failed")
        self.assertIn("NO_PROPOSAL_CHOSEN", sa["detail"])
        self.assertIn("IKE_NO_PROPOSAL_CHOSEN", issue_codes(ipsec))
        self.assertTrue(any(n["name"] == "NO_PROPOSAL_CHOSEN" and n["from"] == "192.0.2.1" for n in sa["notifies"]))
        self.assertEqual(sa["retransmissions"], 0)  # each request was answered
        self.assertEqual(ipsec["encryption_verdict"], "no_esp")
        self.assertEqual(ipsec["status"], "problem")

    def test_ikev2_retransmitted_without_reply(self):
        report = self.run_capture("ikev2_no_response.pcap")
        sa = report["ipsec"]["ike_sas"][0]
        self.assertEqual(sa["outcome"], "no_response")
        self.assertEqual(sa["retransmissions"], 3)
        self.assertTrue(sa["exchanges"][0]["unanswered"])
        self.assertIn("IKE_NO_RESPONSE", issue_codes(report["ipsec"]))

    def test_ikev1_main_mode_and_refusal(self):
        report = self.run_capture("ikev1.pcap")
        ipsec = report["ipsec"]
        sas = {sa["initiator"]: sa for sa in ipsec["ike_sas"]}
        good, bad = sas["198.51.100.2"], sas["203.0.113.3"]
        self.assertEqual((good["ike_version"], good["outcome"]), (1, "established"))
        self.assertEqual([e["exchange"] for e in good["exchanges"]], ["Main Mode", "Quick Mode"])
        self.assertEqual(bad["outcome"], "failed")
        self.assertIn("NO-PROPOSAL-CHOSEN", bad["detail"])
        self.assertIn("IKEV1_NO_PROPOSAL_CHOSEN", issue_codes(ipsec))
        pairs = {tuple(p["endpoints"]): p["verdict"] for p in ipsec["peer_pairs"]}
        self.assertEqual(pairs[("192.0.2.1", "198.51.100.2")], "encrypted")
        self.assertEqual(pairs[("192.0.2.1", "203.0.113.3")], "ike_only")
        self.assertEqual(ipsec["encryption_verdict"], "no_esp")
        self.assertTrue(ipsec["verdict"].startswith("1 of 2 peer pair(s) encrypted"))

    def test_nat_traversal_esp_in_udp(self):
        report = self.run_capture("ipsec_natt.pcap")
        ipsec = report["ipsec"]
        nat = ipsec["nat_traversal"]
        self.assertTrue(nat["in_use"])
        self.assertEqual(nat["ike_packets_on_4500"], 2)
        self.assertEqual(nat["esp_in_udp_flows"], 2)
        self.assertEqual(nat["nat_keepalives"], 2)
        self.assertEqual(ipsec["encryption_verdict"], "encrypted")
        self.assertEqual(ipsec["ike_sas"][0]["outcome"], "established")
        self.assertTrue(ipsec["ike_sas"][0]["nat_t"])
        out = next(f for f in ipsec["esp_flows"] if f["spi"] == "0xab000001")
        self.assertTrue(out["udp_encapsulated"])
        self.assertEqual(out["missing_sequence_numbers"], 1)
        self.assertEqual(out["duplicate_sequence_numbers"], 1)
        self.assertIn("ESP_DUPLICATE_SEQUENCE", issue_codes(ipsec))
        self.assertIn("ESP_SEQUENCE_GAP", issue_codes(ipsec))
        self.assertIn("nat-t", report["protocols_present"])

    # -- GRE / NHRP ----------------------------------------------------------

    def test_gre_nhrp_registration_and_redirect(self):
        report = self.run_capture("gre_nhrp.pcap")
        gre = report["gre_nhrp"]
        self.assertEqual(gre["dmvpn_phase_hint"], "phase3")
        self.assertEqual(len(gre["hubs"]), 1)
        hub = gre["hubs"][0]
        self.assertEqual(hub["nbma"], "192.0.2.1")
        self.assertEqual(hub["tunnel_ip"], "10.0.0.1")
        self.assertEqual(sorted(hub["spokes_registered"]), ["198.51.100.2", "203.0.113.3"])
        self.assertEqual(hub["spokes_refused"], ["192.0.2.44"])
        refused = next(r for r in gre["registrations"] if r["spoke_nbma"] == "192.0.2.44")
        self.assertEqual(refused["result"], "refused")
        self.assertIn("Administratively Prohibited", refused["reply_codes"])
        self.assertIn("NHRP_REGISTRATION_REFUSED", issue_codes(gre))
        self.assertEqual(len(gre["redirects"]), 1)
        redirect = gre["redirects"][0]
        self.assertEqual((redirect["from"], redirect["to"]), ("192.0.2.1", "198.51.100.2"))
        self.assertEqual(redirect["original_dst"], "10.1.3.1")
        resolved = next(r for r in gre["resolutions"] if r["target"] == "10.1.3.1")
        self.assertEqual(resolved["result"], "resolved")
        self.assertEqual(resolved["answers"][0]["client_nbma"], "203.0.113.3")
        self.assertEqual(resolved["answers"][0]["client_tunnel_ip"], "10.0.0.3")
        failed = next(r for r in gre["resolutions"] if r["target"] == "10.9.9.9")
        self.assertEqual(failed["result"], "error_indication")
        self.assertEqual(gre["error_indications"][0]["error"], "Protocol Address Unreachable")
        self.assertEqual(len(gre["spoke_to_spoke_tunnels"]), 1)
        self.assertTrue(all(t["gre_keys"] == [100] for t in gre["tunnels"]))
        self.assertNotIn("GRE_KEY_MISMATCH", issue_codes(gre))
        # GRE with no ESP on the underlay is cleartext.
        self.assertEqual(report["ipsec"]["encryption_verdict"], "cleartext_seen")
        self.assertIn("gre/nhrp", report["ipsec"]["verdict"])

    # -- Routing -------------------------------------------------------------

    def test_routing_inside_gre_uses_tunnel_addresses(self):
        report = self.run_capture("routing_over_gre.pcap")
        self.assertTrue({"gre", "eigrp", "bgp"} <= set(report["protocols_present"]))
        session = report["routing"]["bgp"]["sessions"][0]
        self.assertEqual(session["peers"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(session["state"], "established")
        self.assertTrue(session["over_gre"])
        self.assertEqual(session["negotiated_hold_time"], 180)
        speakers = {s["address"]: s for link in report["routing"]["eigrp"]["links"] for s in link["speakers"]}
        self.assertEqual(sorted(speakers), ["10.0.0.1", "10.0.0.2"])
        self.assertTrue(all(s["over_gre"] for s in speakers.values()))
        self.assertTrue(report["routing"]["eigrp"]["links"][0]["adjacencies"][0]["init_exchanged"])
        # The WAN pair carries GRE with no ESP: cleartext.
        self.assertEqual(report["ipsec"]["encryption_verdict"], "cleartext_seen")

    def test_bgp_session_notification_and_reset(self):
        report = self.run_capture("bgp_session.pcap")
        bgp = report["routing"]["bgp"]
        sessions = {tuple(s["peers"]): s for s in bgp["sessions"]}
        main = sessions[("10.255.0.1", "10.255.0.2")]
        self.assertEqual(main["state"], "established")
        self.assertTrue(main["ibgp"])
        self.assertEqual(main["negotiated_hold_time"], 30)
        self.assertEqual(main["times_established"], 2)
        self.assertEqual(main["times_down"], 1)
        self.assertEqual(main["speakers"]["10.255.0.1"]["as"], 65000)
        self.assertEqual(main["speakers"]["10.255.0.2"]["hold_time_offered"], 90)
        self.assertEqual(main["speakers"]["10.255.0.1"]["prefixes_announced"], 4)
        self.assertEqual(main["speakers"]["10.255.0.1"]["prefixes_withdrawn"], 1)
        self.assertEqual(main["speakers"]["10.255.0.2"]["prefixes_announced"], 2)
        note = main["notifications"][0]
        self.assertEqual((note["code"], note["from"]), (4, "10.255.0.1"))
        self.assertEqual(note["name"], "Hold Timer Expired")
        bad_as = sessions[("10.255.0.1", "10.255.0.3")]
        self.assertEqual(bad_as["state"], "open_rejected")
        self.assertEqual((bad_as["notifications"][0]["code"], bad_as["notifications"][0]["subcode"]), (2, 2))
        self.assertIn("Bad Peer AS", bad_as["notifications"][0]["name"])
        self.assertEqual(sessions[("10.255.0.1", "10.255.0.4")]["state"], "tcp_refused")
        codes = issue_codes(bgp)
        self.assertTrue({"BGP_NOTIFICATION", "BGP_TCP_REFUSED", "BGP_SESSION_FLAP"} <= codes)
        timeline = [(e["event"], e["t"]) for e in report["routing"]["failover_timeline"] if e["protocol"] == "bgp"]
        kinds = [k for k, _ in timeline]
        self.assertLess(kinds.index("notification"), kinds.index("down"))
        self.assertEqual(kinds.count("established"), 2)
        self.assertIn(("down", 40.5), timeline)

    def test_ospf_hello_interval_mismatch(self):
        report = self.run_capture("ospf_hello_mismatch.pcap")
        ospf = report["routing"]["ospf"]
        self.assertEqual(len(ospf["links"]), 1)
        link = ospf["links"][0]
        self.assertEqual(link["network"], "10.0.12.0/24")
        mismatch = {m["parameter"]: m["values"] for m in link["mismatches"]}
        self.assertEqual(mismatch["hello_interval"], {"1.1.1.1": 10, "2.2.2.2": 5})
        self.assertEqual(mismatch["dead_interval"], {"1.1.1.1": 40, "2.2.2.2": 20})
        self.assertEqual(link["adjacencies"][0]["state_hint"], "none")
        self.assertIn("OSPF_HELLO_INTERVAL_MISMATCH", issue_codes(ospf))
        self.assertIn("OSPF_DEAD_INTERVAL_MISMATCH", issue_codes(ospf))
        self.assertEqual(report["routing"]["status"], "problem")

    def test_ospf_failover_timeline(self):
        report = analyze_routing_capture(fixture("ospf_failover.pcap"), backend=self.backend)
        self.assertEqual(report["status"], "success")
        link = report["routing"]["ospf"]["links"][0]
        adjacency = link["adjacencies"][0]
        self.assertEqual(adjacency["state_hint"], "2-way_or_better")
        self.assertTrue(adjacency["dbd_exchanged"])
        self.assertIn("OSPF_HELLO_GAP", issue_codes(report["routing"]["ospf"]))
        timeline = [(e["event"], e["t"], e["detail"]) for e in report["failover_timeline"]]
        down = [t for kind, t, detail in timeline if kind == "neighbor_down" and "dropped neighbor 3.3.3.3" in detail]
        up = [t for kind, t, detail in timeline if kind == "neighbor_up" and "now lists neighbor 3.3.3.3" in detail]
        self.assertEqual(down, [80.0])
        self.assertEqual(up, [1.0, 90.0])
        gap = next(t for kind, t, _ in timeline if kind == "hello_gap")
        self.assertEqual(gap, 30.5)

    def test_eigrp_k_mismatch_goodbye_and_silence(self):
        report = self.run_capture("eigrp_mismatch.pcap")
        eigrp = report["routing"]["eigrp"]
        codes = issue_codes(eigrp)
        self.assertTrue({"EIGRP_K_VALUE_MISMATCH", "EIGRP_GOODBYE", "EIGRP_NEIGHBOR_SILENT"} <= codes)
        silent = next(i for i in eigrp["issues"] if i["code"] == "EIGRP_NEIGHBOR_SILENT")
        self.assertIn("10.0.23.3", silent["message"])
        mismatch = next(i for i in eigrp["issues"] if i["code"] == "EIGRP_K_VALUE_MISMATCH")
        self.assertIn("10.0.23.3 cannot form adjacencies", mismatch["message"])
        link = eigrp["links"][0]
        pair = next(a for a in link["adjacencies"] if a["speakers"] == ["10.0.23.1", "10.0.23.2"])
        self.assertTrue(pair["init_exchanged"])
        speakers = {s["address"]: s for s in link["speakers"]}
        self.assertEqual(speakers["10.0.23.2"]["goodbyes"], 1)
        self.assertEqual(speakers["10.0.23.1"]["hold_time"], 15)
        self.assertEqual(speakers["10.0.23.3"]["k_values"], [1, 1, 1, 0, 0, 0])
        self.assertTrue(events(report, "query"))

    # -- Reachability --------------------------------------------------------

    def test_icmp_echo_loss_and_errors(self):
        report = self.run_capture("icmp_loss.pcap")
        reach = report["reachability"]
        pair = next(p for p in reach["echo"] if p["dst"] == "10.2.2.2")
        self.assertEqual((pair["sent"], pair["answered"], pair["lost"]), (10, 7, 3))
        self.assertEqual(pair["loss_percent"], 30.0)
        self.assertEqual(pair["verdict"], "loss")
        self.assertAlmostEqual(pair["rtt_ms"]["min"], 11.0, places=2)
        self.assertAlmostEqual(pair["rtt_ms"]["max"], 20.0, places=2)
        self.assertEqual(len(pair["outages"]), 1)
        outage = pair["outages"][0]
        self.assertEqual(outage["lost_requests"], 3)
        self.assertEqual(outage["start_t"], 3.0)
        self.assertAlmostEqual(outage["recovered_t"], 6.017, places=3)
        kinds = {(e["type"], e["code"]) for e in reach["icmp_errors"]}
        self.assertEqual(kinds, {(3, 1), (3, 3), (11, 0)})
        host_unreach = next(e for e in reach["icmp_errors"] if e["code"] == 1)
        self.assertEqual(host_unreach["original_dst"], "10.3.3.3")
        self.assertEqual(host_unreach["code_text"], "host unreachable")
        self.assertEqual([a["target"] for a in reach["arp_unanswered"]], ["10.1.1.99"])
        self.assertEqual(reach["arp_unanswered"][0]["requests"], 3)
        self.assertEqual(reach["summary"]["arp_targets_answered"], 1)
        self.assertIn("ICMP_LOSS", issue_codes(reach))
        self.assertIn("ARP_NO_REPLY", issue_codes(reach))

    def test_conversations_summary(self):
        report = self.run_capture("ipsec_ikev2_esp.pcap", detectors=["conversations"])
        conv = report["conversations"]
        self.assertEqual(conv["totals"]["packets"], 36)
        protocols = {p["protocol"]: p for p in conv["protocols"]}
        self.assertEqual(protocols["esp"]["packets"], 30)
        self.assertEqual(protocols["ike"]["packets"], 6)
        self.assertEqual(conv["top_conversations"][0]["packets"], 36)
        self.assertEqual(report["detectors_requested"], ["conversations"])


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestNetworkDetectorsTshark(DetectorAssertions, unittest.TestCase):
    backend = "tshark"


class TestNetworkDetectorsScapy(DetectorAssertions, unittest.TestCase):
    backend = "scapy"


class TestNetworkOrchestrator(unittest.TestCase):
    """Entry point behaviour that does not depend on the backend."""

    def test_backends_produce_identical_records(self):
        if not HAVE_TSHARK:
            self.skipTest("tshark is not installed")
        for name in sorted(os.listdir(FIXTURES)):
            if not name.endswith(".pcap"):
                continue
            with self.subTest(fixture=name):
                tshark = list(network_extractor.iter_records_tshark(fixture(name)))
                scapy = list(network_extractor.iter_records_scapy(fixture(name)))
                self.assertEqual(len(tshark), len(scapy))
                for a, b in zip(tshark, scapy):
                    self.assertAlmostEqual(a.pop("t"), b.pop("t"), places=5)
                    self.assertEqual(a, b)

    def test_backends_produce_identical_reports(self):
        if not HAVE_TSHARK:
            self.skipTest("tshark is not installed")
        for name in sorted(os.listdir(FIXTURES)):
            if not name.endswith(".pcap"):
                continue
            with self.subTest(fixture=name):
                reports = []
                for backend in ("tshark", "scapy"):
                    report = analyze_network_capture(fixture(name), backend=backend, include_sip=False)
                    report["capture"].pop("backend")
                    report["capture"].pop("missing_tshark_fields")
                    reports.append(json.dumps(report, sort_keys=True))
                self.assertEqual(reports[0], reports[1])

    def test_vpn_overlay_hint_when_gre_is_inside_esp(self):
        vpn = analyze_vpn_capture(fixture("ipsec_ikev2_esp.pcap"))
        self.assertIn("inside ESP", vpn["overlay_verdict"])

    def test_auto_falls_back_to_scapy_without_tshark(self):
        with mock.patch.object(network_extractor.shutil, "which", return_value=None):
            report = analyze_network_capture(fixture("ipsec_ikev2_esp.pcap"), include_sip=False)
        self.assertEqual(report["capture"]["backend"], "scapy")
        self.assertEqual(report["ipsec"]["encryption_verdict"], "encrypted")

    def test_display_filter_without_tshark_is_refused(self):
        with mock.patch.object(network_extractor.shutil, "which", return_value=None):
            report = analyze_network_capture(fixture("ipsec_ikev2_esp.pcap"), display_filter="esp")
        self.assertEqual(report["status"], "error")
        self.assertIn("display_filter needs tshark", report["error"])

    @unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
    def test_display_filter_narrows_the_capture(self):
        report = analyze_network_capture(fixture("ipsec_cleartext_icmp.pcap"), display_filter="not icmp",
                                         include_sip=False)
        self.assertEqual(report["capture"]["packets"], 36)
        self.assertEqual(report["ipsec"]["encryption_verdict"], "encrypted")

    def test_peers_select_the_pairs_judged(self):
        report = analyze_network_capture(fixture("ipsec_cleartext_icmp.pcap"), peers=["192.0.2.1", "198.51.100.2"],
                                         include_sip=False)
        self.assertEqual(report["ipsec"]["encryption_verdict"], "cleartext_seen")
        report = analyze_network_capture(fixture("ipsec_cleartext_icmp.pcap"), peers=["192.0.2.1", "192.0.2.99"],
                                         include_sip=False)
        self.assertEqual(report["ipsec"]["encryption_verdict"], "not_present")

    def test_detector_selection_and_auto_detection(self):
        report = analyze_network_capture(fixture("bgp_session.pcap"), include_sip=False)
        self.assertEqual(report["detectors_run"], ["routing", "tcp", "conversations"])  # BGP rides on TCP
        self.assertIn("ipsec", report["detectors_not_present"])
        self.assertEqual(report["protocols_present"], ["bgp", "tcp"])
        only = analyze_network_capture(fixture("bgp_session.pcap"), detectors=["routing"])
        self.assertNotIn("ipsec", only)
        self.assertIn("routing", only)

    def test_bad_arguments_are_refused(self):
        self.assertEqual(analyze_network_capture("/nonexistent.pcap")["status"], "error")
        bad = analyze_network_capture(fixture("bgp_session.pcap"), detectors=["sip", "routing"])
        self.assertEqual(bad["status"], "error")
        self.assertIn("valid_detectors", bad)
        bad = analyze_network_capture(fixture("bgp_session.pcap"), peers=["not-an-ip"])
        self.assertEqual(bad["status"], "error")

    def test_vpn_and_routing_entry_points_lift_their_verdicts(self):
        vpn = analyze_vpn_capture(fixture("gre_nhrp.pcap"))
        self.assertEqual(vpn["encryption_verdict"], "cleartext_seen")
        self.assertTrue(vpn["overlay_verdict"].startswith("DMVPN overlay: 2 of 3 spoke(s) registered"))
        self.assertEqual(list(vpn)[:5], ["status", "encryption_verdict", "verdict", "negotiation_verdict",
                                         "overlay_verdict"])
        routing = analyze_routing_capture(fixture("icmp_loss.pcap"))
        self.assertEqual(len(routing["ping_outages"]), 2)
        self.assertIn("No BGP, OSPF or EIGRP", routing["verdict"])

    def test_sip_path_runs_when_sip_is_present(self):
        report = analyze_network_capture(fixture("sip_minimal.pcap"))
        self.assertIn("sip", report["protocols_present"])
        self.assertTrue(report["sip"]["present"])
        self.assertIn("quality_analysis", report["sip"])
        self.assertIn("grade", report["sip"]["quality_analysis"])
        json.dumps(report)
        report = analyze_network_capture(fixture("bgp_session.pcap"))
        self.assertFalse(report["sip"]["present"])

    def test_max_items_caps_lists(self):
        report = analyze_network_capture(fixture("ipsec_ikev2_esp.pcap"), max_items=1, include_sip=False)
        self.assertEqual(len(report["ipsec"]["esp_flows"]), 1)
        self.assertEqual(report["ipsec"]["esp_flows_omitted"], 3)


class TestDetectorEdgeCases(unittest.TestCase):
    """Branches the fixtures do not reach, fed with hand-built records."""

    def setUp(self):
        self.ctx = Context(0.0, 100.0)

    @staticmethod
    def ospf(n, t, src, rid, ptype=1, mtu=None, dst="224.0.0.5"):
        return {"n": n, "t": t, "len": 80, "ip": {"v": 4, "src": src, "dst": dst, "proto": 89, "ttl": 1},
                "ospf": {"type": ptype, "rid": rid, "area": "0.0.0.0", "auth": 0,
                         "mask": "255.255.255.0" if ptype == 1 else None, "hello": 10 if ptype == 1 else None,
                         "dead": 40 if ptype == 1 else None, "prio": 1, "dr": "0.0.0.0", "bdr": "0.0.0.0",
                         "neighbors": [], "options": 2, "mtu": mtu}}

    def test_ospf_mtu_mismatch(self):
        detector = RoutingDetector()
        records = [
            self.ospf(1, 0.0, "10.0.0.1", "1.1.1.1"),
            self.ospf(2, 0.5, "10.0.0.2", "2.2.2.2"),
            self.ospf(3, 1.0, "10.0.0.1", "1.1.1.1", ptype=2, mtu=1500, dst="10.0.0.2"),
            self.ospf(4, 1.1, "10.0.0.2", "2.2.2.2", ptype=2, mtu=1400, dst="10.0.0.1"),
        ]
        for rec in records:
            detector.feed(rec)
        report = detector.report(Context(0.0, 2.0))
        self.assertIn("OSPF_MTU_MISMATCH", {i["code"] for i in report["ospf"]["issues"]})

    def test_gre_key_mismatch(self):
        detector = GreNhrpDetector()
        for n, (src, dst, key) in enumerate([("192.0.2.1", "198.51.100.2", 100), ("198.51.100.2", "192.0.2.1", 200)], 1):
            detector.feed({"n": n, "t": float(n), "len": 100, "ip": {"v": 4, "src": src, "dst": dst, "proto": 47, "ttl": 255},
                           "gre": {"key": key, "ptype": 0x0800}})
        report = detector.report(self.ctx)
        self.assertIn("GRE_KEY_MISMATCH", {i["code"] for i in report["issues"]})

    def test_eigrp_as_mismatch(self):
        detector = RoutingDetector()
        for n, (src, asn) in enumerate([("10.0.0.1", 100), ("10.0.0.2", 200)], 1):
            detector.feed({"n": n, "t": float(n), "len": 70, "ip": {"v": 4, "src": src, "dst": "224.0.0.10", "proto": 88, "ttl": 2},
                           "eigrp": {"opcode": 5, "as": asn, "flags": 0, "seq": 0, "ack": 0, "tlvs": [1, 4],
                                     "k": [1, 0, 1, 0, 0, 0], "hold": 15}})
        report = detector.report(Context(0.0, 3.0))
        self.assertIn("EIGRP_AS_MISMATCH", {i["code"] for i in report["eigrp"]["issues"]})


class TestFixtures(unittest.TestCase):
    def test_fixtures_are_small(self):
        for name in os.listdir(FIXTURES):
            if name.endswith(".pcap"):
                self.assertLess(os.path.getsize(fixture(name)), 200 * 1024, name)

    def test_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_fixtures.py"), out],
                           check=True, capture_output=True)
            for name in os.listdir(out):
                with self.subTest(fixture=name):
                    self.assertTrue(filecmp.cmp(os.path.join(out, name), fixture(name), shallow=False),
                                    f"{name} differs from a fresh generation; rerun generate_fixtures.py")


if __name__ == "__main__":
    unittest.main()
