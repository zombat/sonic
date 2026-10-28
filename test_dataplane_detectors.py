#!/usr/bin/env python3
"""
Tests for the data plane detectors (path_mtu, esp_overhead, tcp, tls, qos), the
multi-capture correlation and the merged timeline.

Every fixture is synthetic, built by tests/fixtures/generate_dataplane_fixtures.py
(names start with dp_), and the test names say so. Detector assertions run once
per backend (tshark and the scapy fallback), as test_network_detectors.py does.
The tests at the end run the same code over real lab captures when they exist on
this machine and only check that the reports are well formed.

Run with:  python3 -m unittest -q test_dataplane_detectors.py
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

from analyzers.correlate import correlate_captures, packet_identity
from analyzers.esp_overhead import EspOverheadDetector, _families_for
from analyzers.network_common import Context
from analyzers.network_orchestrator import analyze_data_plane_capture, analyze_network_capture
from analyzers.timeline import merge_timelines
from analyzers.tls_inspect import normalize_version, parse_client_hello

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
HAVE_TSHARK = shutil.which("tshark") is not None
REAL_CAPTURES = sorted(p for p in glob.glob("/home/noot/pleiades-cvd/*/project/captures/*.pcap")
                       if os.path.getsize(p) < 50 * 1024 * 1024)[:4]


def fixture(name):
    return os.path.join(FIXTURES, name)


def codes(section):
    return {issue["code"] for issue in section["issues"]}


class DataPlaneAssertions:
    backend = None

    def run_dp(self, name, **kwargs):
        report = analyze_data_plane_capture(fixture(name), backend=self.backend, **kwargs)
        self.assertEqual(report["status"], "success", report.get("error"))
        self.assertEqual(report["capture"]["backend"], self.backend)
        json.dumps(report)
        return report

    # -- path MTU ---------------------------------------------------------------

    def test_synthetic_frag_needed_is_matched_to_its_probe(self):
        pm = self.run_dp("dp_pmtu_frag_needed.pcap")["path_mtu"]
        self.assertEqual(pm["status"], "warning")
        ptb = pm["frag_needed"][0]
        self.assertEqual((ptb["router"], ptb["mtu"], ptb["original_len"]), ("10.1.1.1", 1400, 1500))
        self.assertEqual(ptb["probe_frames"], [3])
        self.assertEqual(pm["summary"]["smallest_mtu_advertised"], 1400)
        self.assertEqual(pm["black_holes"], [])  # the vanished probe was answered by ICMP: not a black hole
        self.assertIn("PMTU_FRAG_NEEDED", codes(pm))

    def test_synthetic_pmtud_black_hole_icmp_and_tcp(self):
        pm = self.run_dp("dp_pmtu_black_hole.pcap")["path_mtu"]
        holes = {h["kind"]: h for h in pm["black_holes"]}
        echo = holes["icmp_echo"]
        self.assertEqual((echo["src"], echo["dst"]), ("10.1.1.10", "10.3.3.30"))
        self.assertEqual(echo["path_mtu_between"], [1400, 1499])
        self.assertEqual(echo["vanished_probes"], 3)
        tcp = holes["tcp"]
        self.assertEqual((tcp["src"], tcp["sport"]), ("10.3.3.30", 80))
        self.assertEqual(tcp["smallest_vanished"], 1488)
        self.assertEqual(len(holes), 2)  # random loss on 10.1.1.11 (same size answered and lost) is not a hole
        self.assertEqual(pm["status"], "problem")
        self.assertTrue({"PMTU_BLACK_HOLE", "TCP_PMTU_BLACK_HOLE"} <= codes(pm))

    def test_synthetic_fragments_complete_incomplete_overlap(self):
        report = self.run_dp("dp_fragments.pcap")
        fr = report["path_mtu"]["fragments"]
        self.assertEqual((fr["datagrams"], fr["complete"], fr["incomplete_count"]), (3, 2, 1))  # overlap still covers
        self.assertEqual(fr["incomplete"][0]["missing"], ["middle"])
        self.assertEqual(fr["overlapping"][0]["id"], 4444)
        split = next(p for p in fr["by_pair"] if p["protocol"] == 17)
        self.assertEqual(split["split_at_mtu"], 1500)
        self.assertTrue({"FRAGMENT_INCOMPLETE", "FRAGMENT_OVERLAP", "FRAGMENT_REASSEMBLY_TIMEOUT"}
                        <= codes(report["path_mtu"]))
        self.assertEqual(report["esp_overhead"]["status"], "not_present")  # UDP fragments are not ESP

    # -- ESP overhead -------------------------------------------------------------

    def test_synthetic_esp_cipher_family_estimates(self):
        esp = self.run_dp("dp_esp_sizes.pcap", tunnel_mtu=1400)["esp_overhead"]
        self.assertTrue(esp["estimate"])
        flows = {f["spi"]: f for f in esp["flows"]}
        gcm, cbc, natt = flows["0xc0000001"], flows["0xcb000001"], flows["0xab000001"]
        self.assertTrue(gcm["estimate"].startswith("AES-GCM"))
        self.assertEqual(gcm["confidence"], "high")
        self.assertEqual(cbc["estimate"], "AES-CBC + HMAC-SHA1-96")
        self.assertTrue(natt["nat_t"])
        self.assertTrue(natt["estimate"].startswith("AES-GCM"))
        family = next(f for f in gcm["consistent_families"] if f["family"] == gcm["estimate"])
        gre = family["modes"]["transport_over_gre"]
        self.assertEqual(gre["overhead_bytes"], [62, 65])            # 20 + 8 + 8 + 16 + 2 + GRE 8 (+ pad 0..3)
        self.assertTrue(gre["fits_transport_mtu"])
        bounds = {b["esp_payload"]: b["inner_bytes"] for b in family["inner_size_bounds"]}
        for size in (60, 100, 128, 576, 1000, 1400):  # the inner packets the fixture encrypted, plus GRE 8
            self.assertTrue(any(lo <= size + 8 <= hi for lo, hi in bounds.values()), size)
        self.assertNotIn("ESP_EXCEEDS_TRANSPORT_MTU", codes(esp))
        frag = esp["outer_fragmentation"][0]
        self.assertEqual((frag["src"], frag["fragments"], frag["datagrams"]), ("198.51.100.3", 2, 1))
        self.assertIn("ESP_OUTER_FRAGMENTED", codes(esp))

    def test_synthetic_esp_tunnel_mtu_too_large_for_transport(self):
        esp = self.run_dp("dp_esp_sizes.pcap", tunnel_mtu=1476)["esp_overhead"]
        over = [i for i in esp["issues"] if i["code"] == "ESP_EXCEEDS_TRANSPORT_MTU"]
        self.assertEqual(len(over), 3)
        self.assertIn("1476-byte inner packet becomes", over[0]["message"])

    # -- TCP ------------------------------------------------------------------------

    def test_synthetic_tcp_verdicts(self):
        tcp = self.run_dp("dp_tcp_health.pcap")["tcp"]
        by_port = {int(c["client"].rsplit(":", 1)[1]): c for c in tcp["connections"]}
        self.assertEqual(by_port[41001]["verdict"], "no_answer")
        self.assertIn("communication administratively prohibited", by_port[41001]["detail"])
        self.assertEqual(by_port[41001]["handshake"]["syn_count"], 3)
        self.assertEqual(by_port[41002]["verdict"], "refused")
        self.assertEqual(by_port[41000]["verdict"], "healthy")
        zero = by_port[41003]
        self.assertEqual(zero["verdict"], "receiver_buffer_exhausted")
        self.assertIn("receive buffer is exhausted", zero["detail"])
        self.assertEqual(zero["directions"]["client_to_server"]["zero_window_seconds"], 2.0)
        loss = by_port[41004]
        self.assertEqual(loss["verdict"], "loss_on_path")
        sent = loss["directions"]["server_to_client"]
        self.assertEqual((sent["retransmissions"], sent["fast_retransmissions"], sent["timeout_retransmissions"]),
                         (2, 1, 1))
        self.assertEqual(sent["observed_retransmission_timeout_ms"]["median"], 1000.0)
        self.assertEqual(sent["gaps_before_capture_point"], 1)
        self.assertGreaterEqual(loss["directions"]["client_to_server"]["duplicate_ack_runs_of_3"], 1)
        self.assertEqual(by_port[41005]["verdict"], "receive_window_limited")
        self.assertEqual(by_port[41005]["directions"]["client_to_server"]["mss"], 1360)
        self.assertEqual(by_port[41006]["verdict"], "reset")
        healthy = by_port[41000]
        self.assertEqual(healthy["handshake"]["capture_point_to_server_ms"], 10.0)
        self.assertEqual(healthy["directions"]["client_to_server"]["window_scale"], 7)
        self.assertTrue(healthy["directions"]["client_to_server"]["sack_permitted"])
        self.assertTrue({"TCP_NO_ANSWER", "TCP_REFUSED", "TCP_ZERO_WINDOW", "TCP_LOSS", "TCP_WINDOW_FULL",
                         "TCP_RESET", "TCP_MSS_BELOW_1460"} <= codes(tcp))
        self.assertEqual(tcp["status"], "problem")

    # -- TLS ------------------------------------------------------------------------

    def test_synthetic_tls_handshakes_and_baseline(self):
        tls = self.run_dp("dp_tls.pcap", tls_baseline={"versions": ["TLS1.3"]})["tls"]
        by_sni = {s["sni"]: s for s in tls["sessions"]}
        modern = by_sni["app.example.com"]
        self.assertEqual(modern["client_offered"]["versions"], ["TLS1.3", "TLS1.2"])  # GREASE dropped
        self.assertEqual(modern["client_offered"]["alpn"], ["h2", "http/1.1"])
        self.assertNotIn("0x0a0a", modern["client_offered"]["cipher_suites"])
        self.assertEqual(modern["server_chose"]["version"], "TLS1.3")
        self.assertEqual(modern["server_chose"]["cipher_suite"], "TLS_AES_128_GCM_SHA256")
        self.assertFalse(modern["certificate"]["visible"])
        self.assertIn("TLS 1.3 encrypts", modern["certificate"]["reason"])
        self.assertTrue(modern["baseline_pass"])
        legacy = by_sni["legacy.example.net"]  # ClientHello split over two segments
        self.assertEqual(legacy["server_chose"]["cipher_suite"], "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
        self.assertTrue(legacy["certificate"]["visible"])
        if legacy["certificate"].get("parsed"):
            self.assertEqual(legacy["certificate"]["subject"], "legacy.example.net")
            self.assertFalse(legacy["certificate"]["valid_at_capture_time"])
        self.assertFalse(legacy["baseline_pass"])
        old = by_sni["old.example.org"]
        self.assertEqual(old["server_chose"]["version"], "TLS1.0")
        found = {f["code"] for f in old["findings"]}
        self.assertTrue({"TLS_BASELINE_VERSION", "TLS_WEAK_CIPHER_CHOSEN", "TLS_WEAK_OFFERED"} <= found)
        strict = by_sni["strict.example.com"]
        self.assertEqual(strict["server"], "198.51.100.90:9443")  # found by content, not port
        self.assertEqual(strict["alerts"][0]["description"], "handshake_failure")
        self.assertIn("TLS_ALERT", codes(tls))
        self.assertEqual(tls["summary"]["baseline_failures"], 2)

    def test_synthetic_tls_without_baseline_still_flags_weak(self):
        tls = self.run_dp("dp_tls.pcap")["tls"]
        self.assertIsNone(tls["baseline"])
        self.assertIn("TLS_OLD_VERSION", codes(tls))
        self.assertNotIn("TLS_BASELINE_VERSION", codes(tls))

    # -- QoS ------------------------------------------------------------------------

    def test_synthetic_qos_rtp_and_tunnels(self):
        qos = self.run_dp("dp_qos_rtp.pcap")["qos"]
        streams = {s["ssrc"]: s for s in qos["rtp_streams"]}
        ef = streams["0x11111111"]
        self.assertEqual((ef["expected"], ef["lost"], ef["loss_percent"]), (100, 2, 2.0))
        self.assertEqual(ef["dscp"], {"EF": 98})
        self.assertEqual(ef["codec"], "G.711")
        self.assertIsNotNone(ef["mos_estimate"])
        jittery = streams["0x22222222"]
        self.assertEqual(jittery["dscp"], {"CS0/BE": 100})
        self.assertAlmostEqual(jittery["jitter_ms"]["final"], 15.0, delta=1.0)
        opus = streams["0x33333333"]
        self.assertEqual((opus["clock_rate"], opus["clock_rate_source"]), (48000, "estimated"))
        tunnels = {t["outer_src"]: t for t in qos["gre_tunnels"]}
        self.assertEqual(tunnels["198.51.100.2"]["inner_marked_outer_zero"], 5)
        self.assertEqual(tunnels["192.0.2.1"]["copied"], 5)
        self.assertEqual(qos["summary"]["ecn_ce_packets"], 3)
        self.assertTrue({"QOS_RTP_LOSS", "QOS_RTP_NOT_EF", "QOS_GRE_DSCP_NOT_COPIED", "QOS_ECN_CE"} <= codes(qos))

    def test_synthetic_esp_dscp_copied_reading(self):
        qos = self.run_dp("dp_esp_sizes.pcap")["qos"]
        sas = {s["spi"]: s for s in qos["esp_sas"]}
        self.assertIn("copied", sas["0xc0000001"]["reading"])
        self.assertIn("inside capture tells which", sas["0xcb000001"]["reading"])


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestDataPlaneTshark(DataPlaneAssertions, unittest.TestCase):
    backend = "tshark"


class TestDataPlaneScapy(DataPlaneAssertions, unittest.TestCase):
    backend = "scapy"


class TestDataPlaneUnits(unittest.TestCase):
    """Pieces checked without a capture."""

    def test_cipher_families_from_sizes(self):
        names = [f["family"] for f in _families_for([76, 96, 108, 136])]
        self.assertTrue(names[0].startswith("AES-GCM"))
        self.assertNotIn("AES-CBC + HMAC-SHA1-96", names)  # 96 - 28 is not a multiple of 16
        self.assertIn("AES-CBC + HMAC-SHA1-96", [f["family"] for f in _families_for([60, 76, 92, 1468])])

    def test_esp_detector_ignores_non_esp(self):
        detector = EspOverheadDetector()
        detector.feed({"n": 1, "t": 0.0, "len": 60, "ip": {"v": 4, "src": "10.0.0.1", "dst": "10.0.0.2", "proto": 6},
                       "dp": {"hl": 20, "tl": 40, "id": 1, "df": 1, "mf": 0, "off": 0, "dscp": 0, "ecn": 0}})
        self.assertEqual(detector.report(Context(0.0, 1.0))["status"], "not_present")

    def test_version_spellings(self):
        for text in ("TLS1.3", "TLSv1.3", "tls 1.3", "1.3", 0x0304):
            self.assertEqual(normalize_version(text), "TLS1.3")

    def test_truncated_client_hello_is_refused(self):
        self.assertIsNone(parse_client_hello(b"\x03\x03" + b"\x00" * 10))

    def test_options_are_validated(self):
        bad = analyze_network_capture(fixture("dp_tls.pcap"), options={"tcp": {"x": 1}})
        self.assertEqual(bad["status"], "error")
        bad = analyze_network_capture(fixture("dp_tls.pcap"), options={"tls": {"baselin": {}}})
        self.assertIn("valid_options", bad)


class CorrelationAssertions:
    backend = None

    def correlate(self, pairs, **kwargs):
        result = correlate_captures([{"path": fixture(p), "label": label} for label, p in pairs],
                                    backend=self.backend, **kwargs)
        self.assertEqual(result["status"], "success", result.get("error"))
        json.dumps(result)
        return result

    def test_synthetic_nat_translations_and_drops(self):
        r = self.correlate([("inside", "dp_corr_inside.pcap"), ("outside", "dp_corr_outside.pcap")])
        nat = {m["at_inside"]: m for m in r["nat"]}
        web = nat["10.0.0.10:40000"]
        self.assertEqual((web["at_outside"], web["remote"]), ("203.0.113.5:61000", "198.51.100.80:443"))
        self.assertEqual(web["packets"], 5)  # both directions fold into one mapping
        self.assertEqual(nat["10.0.0.13:4660"]["at_outside"], "203.0.113.5:32769")  # ICMP id under PAT
        conns = {c["flow"]: c for c in r["connections"]}
        lost = conns["tcp 10.0.0.11:40001 -> 198.51.100.81:443"]
        self.assertEqual(lost["verdict"], "reply_lost")
        self.assertIn("SYN-ACK was last seen at outside and never reached inside", lost["detail"])
        probe = conns["udp 10.0.0.12:33434 -> 198.51.100.82:33434"]
        self.assertEqual(probe["verdict"], "seen_only_at")
        self.assertIn("stopped after inside", probe["detail"])
        self.assertEqual(conns["tcp 10.0.0.10:40000 -> 198.51.100.80:443"]["verdict"], "ok")
        transit = r["transit"][0]
        self.assertEqual((transit["ttl_decrement"], transit["delta_ms"]["median"]), (1, 0.5))
        change = r["dscp_changes"][0]
        self.assertEqual((change["dscp_before"], change["dscp_after"]), ("EF", "CS0/BE"))
        self.assertIn("CORRELATE_REPLY_LOST", {i["code"] for i in r["issues"]})

    def test_synthetic_asymmetric_paths(self):
        r = self.correlate([("lan", "dp_corr_lan.pcap"), ("wan1", "dp_corr_wan1.pcap"), ("wan2", "dp_corr_wan2.pcap")])
        self.assertEqual(len(r["connections"]), 1)
        conn = r["connections"][0]
        self.assertEqual(conn["verdict"], "asymmetric")
        self.assertIn("out through wan1, back through wan2", conn["detail"])
        self.assertEqual(r["nat"], [])

    def test_synthetic_clock_offset_and_window(self):
        r = self.correlate([("inside", "dp_corr_inside.pcap"), ("outside", "dp_corr_outside.pcap")],
                           clock_offsets_s={"outside": 100.0})
        self.assertEqual(r["matching"]["packets_matched"], 0)
        self.assertIn("clock_offsets_s", r["verdict"])
        r = self.correlate([("inside", "dp_corr_inside.pcap"), ("outside", "dp_corr_outside.pcap")],
                           max_packets_held=100)
        self.assertEqual(r["matching"]["max_packets_held"], 100)


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestCorrelationTshark(CorrelationAssertions, unittest.TestCase):
    backend = "tshark"


class TestCorrelationScapy(CorrelationAssertions, unittest.TestCase):
    backend = "scapy"


class TestCorrelationArguments(unittest.TestCase):
    def test_bad_arguments_are_refused(self):
        one = [{"path": fixture("dp_corr_inside.pcap"), "label": "a"}]
        self.assertEqual(correlate_captures(one)["status"], "error")
        dup = one + [{"path": fixture("dp_corr_outside.pcap"), "label": "a"}]
        self.assertIn("duplicate", correlate_captures(dup)["error"])
        missing = one + [{"path": "/nonexistent.pcap", "label": "b"}]
        self.assertIn("File not found", correlate_captures(missing)["error"])
        ok = one + [{"path": fixture("dp_corr_outside.pcap"), "label": "b"}]
        self.assertIn("unknown label", correlate_captures(ok, clock_offsets_s={"zz": 1})["error"])
        self.assertEqual(correlate_captures(ok, window_s=0)["status"], "error")

    def test_identity_ignores_nat_fields(self):
        base = {"n": 1, "t": 0.0, "len": 60,
                "dp": {"hl": 20, "tl": 60, "id": 7, "df": 1, "mf": 0, "off": 0, "dscp": 0, "ecn": 0,
                       "tcp": {"seq": 10, "ack": 20, "win": 100, "hl": 20, "mss": None, "ws": None, "sack": False,
                               "ts": False}, "ph": "abc"}}
        a = dict(base, ip={"v": 4, "src": "10.0.0.1", "dst": "192.0.2.1", "proto": 6, "ttl": 64},
                 tcp={"sport": 1000, "dport": 443, "flags": 0x18, "len": 20})
        b = dict(base, ip={"v": 4, "src": "203.0.113.5", "dst": "192.0.2.1", "proto": 6, "ttl": 63},
                 tcp={"sport": 61000, "dport": 443, "flags": 0x18, "len": 20})
        self.assertEqual(packet_identity(a)[0], packet_identity(b)[0])
        self.assertNotEqual(packet_identity(a)[1], packet_identity(b)[1])


class TestMergedTimeline(unittest.TestCase):
    CAPTURES = [{"path": fixture("ospf_failover.pcap"), "label": "core"},
                {"path": fixture("icmp_loss.pcap"), "label": "lan"}]

    def test_synthetic_merge_orders_events_across_captures(self):
        r = merge_timelines(self.CAPTURES)
        self.assertEqual(r["status"], "success")
        times = [e["t"] for e in r["timeline"]]
        self.assertEqual(times, sorted(times))
        self.assertEqual({e["capture"] for e in r["timeline"]}, {"core", "lan"})
        outage = next(e for e in r["timeline"] if e["event"] == "outage" and "10.2.2.2" in e["detail"])
        self.assertEqual(outage["t"], 3.0)  # t=0 is the earliest capture start
        kinds = {m["kind"] for m in r["auto_measurements"]}
        self.assertEqual(kinds, {"ping_outage", "routing_convergence"})

    def test_synthetic_measurement_against_threshold(self):
        spec = {"name": "ospf failover", "from": {"capture": "core", "event": "neighbor_down"},
                "to": {"event": "neighbor_up", "contains": "3.3.3.3"}, "max_s": 15}
        r = merge_timelines(self.CAPTURES, measurements=[spec])
        m = r["measurements"][0]
        self.assertEqual((m["verdict"], m["delta_s"]), ("within", 10.0))
        r = merge_timelines(self.CAPTURES, measurements=[dict(spec, max_s=5)])
        self.assertEqual(r["measurements"][0]["verdict"], "exceeded")
        r = merge_timelines(self.CAPTURES, measurements=[dict(spec, to={"event": "established"})])
        self.assertEqual(r["measurements"][0]["verdict"], "not_found")
        self.assertIn("1 outside the threshold or not found", r["verdict"])

    def test_synthetic_auto_thresholds(self):
        r = merge_timelines(self.CAPTURES, failover_max_s=5)
        verdicts = {(m["kind"], m["verdict"]) for m in r["auto_measurements"]}
        self.assertIn(("ping_outage", "within"), verdicts)
        self.assertIn(("ping_outage", "not_recovered"), verdicts)
        self.assertIn(("routing_convergence", "exceeded"), verdicts)

    def test_output_file_is_written_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as out:
            path = os.path.join(out, "timing.json")
            r = merge_timelines(self.CAPTURES, output_path=path)
            self.assertEqual(r["written_to"], path)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["schema"], "sonic.merged_timeline/1")
            self.assertEqual(merge_timelines(self.CAPTURES, output_path=path)["status"], "error")
            self.assertEqual(merge_timelines(self.CAPTURES, output_path=path, overwrite=True)["status"], "success")
            self.assertEqual(merge_timelines(self.CAPTURES, output_path=os.path.join(out, "x.txt"))["status"], "error")

    def test_bad_selectors_are_refused(self):
        r = merge_timelines(self.CAPTURES, measurements=[{"from": {"evnt": "down"}, "to": {}}])
        self.assertIn("valid_keys", r)
        r = merge_timelines(self.CAPTURES, measurements=[{"from": {"capture": "nope"}, "to": {}}])
        self.assertEqual(r["status"], "error")


class TestDataPlaneFixtures(unittest.TestCase):
    def test_synthetic_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_dataplane_fixtures.py"), out],
                           check=True, capture_output=True)
            names = sorted(os.listdir(out))
            self.assertEqual(len(names), 12)
            for name in names:
                with self.subTest(fixture=name):
                    self.assertTrue(filecmp.cmp(os.path.join(out, name), fixture(name), shallow=False),
                                    f"{name} differs from a fresh generation; rerun generate_dataplane_fixtures.py")
                    self.assertLess(os.path.getsize(fixture(name)), 200 * 1024)


REAL_PAIR = ["/home/noot/pleiades-cvd/claude/project/captures/br1-wan.pcap",
             "/home/noot/pleiades-cvd/claude/project/captures/core1-wan.pcap"]


@unittest.skipUnless(all(os.path.exists(p) for p in REAL_PAIR), "the real br1/core1 lab pair is not on this machine")
class TestRealLabCorrelation(unittest.TestCase):
    """Two real captures taken at the same time on two WAN links of the CML DMVPN lab."""

    def test_real_pair_matches_esp_between_the_links(self):
        r = correlate_captures([{"path": REAL_PAIR[0], "label": "br1-wan"},
                                {"path": REAL_PAIR[1], "label": "core1-wan"}])
        self.assertEqual(r["status"], "success")
        self.assertGreater(r["matching"]["packets_matched"], 0)
        self.assertEqual(r["transit"][0]["ttl_decrement"], 1)
        self.assertNotIn("partial_loss", r["summary"]["by_verdict"])  # capture start times are respected


@unittest.skipUnless(REAL_CAPTURES, "no real lab captures on this machine")
class TestRealLabCaptures(unittest.TestCase):
    """Real CML lab captures (ESP between DMVPN routers): reports must be complete and well formed."""

    def test_real_captures_produce_data_plane_reports(self):
        for path in REAL_CAPTURES:
            with self.subTest(capture=os.path.basename(path)):
                report = analyze_data_plane_capture(path)
                self.assertEqual(report["status"], "success", report.get("error"))
                json.dumps(report)
                for name in ("path_mtu", "esp_overhead", "tcp", "tls", "qos"):
                    self.assertIn("limits", report[name])
                if report["esp_overhead"]["status"] != "not_present":
                    self.assertTrue(report["esp_overhead"]["flows"])


if __name__ == "__main__":
    unittest.main()
