#!/usr/bin/env python3
"""
Tests for gRPC troubleshooting (analyzers/grpc_inspect.py, extractors/http2.py,
analyzers/gnmi_decode.py, utils/grpc_protos.py), and for what it changed elsewhere:
the cleartext audit's recognition of SSH, TLS and HTTP/2 by content, the TLS
detector's IP SANs, alert meanings and HelloRetryRequest fix, and flows labelled by
their service port.

Synthetic fixtures (names start with grpc_) are built by
tests/fixtures/generate_grpc_fixtures.py; the test names say so. A TLS 1.3 gNMI
session with its key log is generated at test time with Python's ssl module (real
TLS, never committed). TestRealCaptures runs on two real captures when they are on
this machine (SONIC_GRPC_CAPTURES names their directory) and skips otherwise:
S.O.N.I.C. commits only synthetic fixtures. No credential value is written in this
file: the real capture's values are read from it with tshark at test time, and every
assertion is that they do not appear.

Run with:  python3 -m unittest -q test_grpc
"""

import filecmp
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from analyzers.gnmi_decode import decode_request, decode_response, parse_fields, render_path
from analyzers.grpc_inspect import analyze_grpc_capture, parse_timeout
from analyzers.network_orchestrator import analyze_network_capture, audit_cleartext_capture
from extractors.http2 import header_kind, plan_decode_as, protobuf_options

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
sys.path.insert(0, FIXTURES)
import generate_grpc_fixtures as gen  # noqa: E402

HAVE_TSHARK = shutil.which("tshark") is not None
CAPTURES = os.environ.get("SONIC_GRPC_CAPTURES", "/home/noot/auto-roboto/.IGNORE/cml-capture/proj/captures")
PLAINTEXT = os.path.join(CAPTURES, "gnmi-plaintext.pcap")
ENCRYPTED = os.path.join(CAPTURES, "netconf-restconf-ssh.pcap")
SYNTHETIC_SECRETS = [gen.SYNTHETIC_USER.decode(), gen.SYNTHETIC_PASSWORD.decode(), gen.SYNTHETIC_API_KEY.decode()]


def fixture(name):
    return os.path.join(FIXTURES, name)


def codes(report):
    return [issue["code"] for issue in report["issues"]]


def rpc_by_stream(report, flow_port=None):
    return {r["stream_id"]: r for r in report["rpcs"] if flow_port is None or r["flow"].endswith(f":{flow_port}")}


def metadata_values(path, port, names):
    """The values of the named metadata headers in a capture, read with tshark (never printed)."""
    out = subprocess.run(["tshark", "-n", "-r", path, "-d", f"tcp.port=={port},http2", "-Y", "http2.header",
                          "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=\x1f",
                          "-e", "http2.header.name", "-e", "http2.header.value"],
                         capture_output=True, text=True, check=True).stdout
    values = set()
    for line in out.splitlines():
        hnames, _, hvalues = line.partition("\t")
        for name, value in zip(hnames.split("\x1f"), hvalues.split("\x1f")):
            if name in names and value:
                values.add(value)
    return values


class TestGnmiDecode(unittest.TestCase):
    """The protobuf reader and the gNMI/gNOI messages, on bytes built here."""

    def test_wire_format_and_paths(self):
        path = gen.gnmi_path("interfaces") + gen.pb_bytes(3, gen.pb_bytes(1, b"interface") + gen.pb_bytes(
            2, gen.pb_bytes(1, b"name") + gen.pb_bytes(2, b"ethernet-1/1")))
        self.assertEqual(render_path(path + gen.pb_bytes(2, b"openconfig")),
                         "openconfig:/interfaces/interface[name=ethernet-1/1]")
        self.assertEqual(parse_fields(gen.pb_varint(5, 300)), [(5, 0, 300)])
        with self.assertRaises(ValueError):
            parse_fields(b"\x12\x05ab")  # a length past the end

    def test_get_encoding_absent_is_json(self):
        get = gen.pb_bytes(2, gen.gnmi_path("system", "state", "hostname"))
        decoded = decode_request("/gnmi.gNMI/Get", get)
        self.assertEqual(decoded["paths"], ["/system/state/hostname"])
        self.assertEqual(decoded["encoding"], "JSON")
        self.assertFalse(decoded["encoding_field_present"])
        self.assertEqual(decode_request("/gnmi.gNMI/Get", get + gen.pb_varint(5, 4))["encoding"], "JSON_IETF")
        self.assertEqual(decode_request("/gnmi.gNMI/Get", get + gen.pb_varint(5, 45))["encoding"],
                         "vendor encoding 45")

    def test_subscribe_set_capabilities_and_time(self):
        sub = gen.pb_bytes(1, gen.pb_bytes(2, gen.pb_bytes(1, gen.gnmi_path("system")) + gen.pb_varint(2, 2)
                                           + gen.pb_varint(3, 10_000_000_000)) + gen.pb_varint(5, 1))
        decoded = decode_request("/gnmi.gNMI/Subscribe", sub)
        self.assertEqual(decoded["mode"], "ONCE")
        self.assertEqual(decoded["subscriptions"], [{"path": "/system", "mode": "SAMPLE", "sample_interval_s": 10.0}])
        self.assertEqual(decode_request("/gnmi.gNMI/Subscribe", gen.pb_bytes(3, b"")), {"poll": True})
        setreq = gen.pb_bytes(2, gen.gnmi_path("a")) + gen.pb_bytes(4, gen.pb_bytes(1, gen.gnmi_path("b")))
        decoded = decode_request("/gnmi.gNMI/Set", setreq)
        self.assertEqual((decoded["delete"]["paths"], decoded["update"]["paths"]), (["/a"], ["/b"]))
        caps = decode_response("/gnmi.gNMI/Capabilities", gen.capabilities_response())
        self.assertEqual(caps["supported_encodings"], ["JSON_IETF", "PROTO", "ASCII"])
        self.assertEqual(caps["gnmi_version"], "0.10.0")
        time = decode_response("/gnoi.system.System/Time", gen.pb_varint(1, 1_700_000_010_000_000_000),
                               capture_time=1_700_000_000.0)
        self.assertEqual(time["skew_s"], 10.0)
        self.assertEqual(parse_timeout("14999982u"), 14.999982)
        self.assertEqual(parse_timeout("2S"), 2.0)


class TestHttp2Extraction(unittest.TestCase):
    def test_header_values_are_shown_only_by_allowlist(self):
        for name in (":path", "grpc-status", "grpc-message", "content-type", "user-agent"):
            self.assertEqual(header_kind(name), "shown", name)
        for name in ("username", "password", "Authorization", "x-api-key", "cookie", "x-auth-token",
                     "my-secret", "client-credential"):
            self.assertEqual(header_kind(name), "credential", name)
        self.assertEqual(header_kind("x-request-id"), "masked")

    def test_protobuf_search_paths_are_quoted(self):
        self.assertEqual(protobuf_options(['/a"b']), ["-o", 'uat:protobuf_search_paths:"/a\\"b","TRUE"',
                                                    "-o", "protobuf.pbf_as_hf:TRUE"])
        self.assertEqual(protobuf_options(None), [])

    def test_decode_as_plan(self):
        from extractors.http2 import TcpConnection
        plain = TcpConnection(0, ("10.0.0.1", 41000), ("10.0.0.2", 7777), 1, 0.0)
        plain.set_server(("10.0.0.2", 7777), "syn")
        plain.preface_frame = 4
        tls = TcpConnection(1, ("10.0.0.1", 41001), ("10.0.0.3", 443), 9, 1.0)
        tls.set_server(("10.0.0.3", 443), "syn")
        tls.tls_client_hello, tls.alpn = 12, ["h2"]
        options, reasons = plan_decode_as({0: plain, 1: tls}, extra_ports=[9999])
        self.assertEqual(reasons, {7777: "preface", 443: "tls_h2", 9999: "requested"})
        self.assertIn("tcp.port==7777,http2", options)
        self.assertIn("tcp.port==443,tls", options)


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestSyntheticGrpc(unittest.TestCase):
    """The synthetic HTTP/2, gRPC and TLS fixtures through analyze_grpc_capture."""

    def ok(self, report):
        self.assertEqual(report["status"], "success", report.get("error"))
        text = json.dumps(report)
        for secret in SYNTHETIC_SECRETS:
            self.assertNotIn(secret, text)
        return report

    def test_synthetic_rpc_statuses_and_diagnoses(self):
        report = self.ok(analyze_grpc_capture(fixture("grpc_h2_trouble.pcap")))
        rpcs = rpc_by_stream(report)
        self.assertEqual(rpcs[1]["grpc_status_name"], "OK")
        self.assertEqual(rpcs[1]["decoded"]["response"]["supported_encodings"], ["JSON_IETF", "PROTO", "ASCII"])
        get = rpcs[3]
        self.assertEqual((get["grpc_status_name"], get["grpc_message"]), ("UNIMPLEMENTED", "unsupported encoding: JSON"))
        self.assertTrue(get["trailers_only"])
        self.assertIn("lists only JSON_IETF, PROTO, ASCII", get["diagnosis"])
        self.assertEqual(rpcs[5]["grpc_status_name"], "UNAUTHENTICATED")
        self.assertIn("username", rpcs[5]["diagnosis"])
        self.assertEqual(rpcs[7]["decoded"]["request"]["mode"], "STREAM")
        self.assertIn("long-lived stream", rpcs[7]["diagnosis"])
        self.assertEqual(rpcs[9]["outcome"], "reset")
        self.assertIn("deadline (2.0 s)", rpcs[9]["diagnosis"])
        self.assertIn("unknown", rpcs[9]["diagnosis"])  # whether a cancelled Set applied
        self.assertTrue(rpcs[11]["state_changing"])
        self.assertEqual(rpcs[11]["reset"]["error"], "REFUSED_STREAM")
        self.assertEqual(rpcs[15]["grpc_status_name"], "RESOURCE_EXHAUSTED")
        self.assertTrue(rpcs[15]["reset_after_end"])
        self.assertEqual(rpcs[15]["request"]["largest"], 5_000_000)
        self.assertIn("4 MiB", rpcs[15]["diagnosis"])
        self.assertEqual(report["connections"][0]["service"], "tcp/9339")
        self.assertEqual(report["connections"][0]["service_name"], "gnmi-gnoi (IANA)")

    def test_synthetic_http2_trouble(self):
        report = self.ok(analyze_grpc_capture(fixture("grpc_h2_trouble.pcap")))
        found = codes(report)
        for code in ("HTTP2_RST_STREAM", "HTTP2_FRAME_TOO_LARGE", "HTTP2_HEADER_LIST_TOO_LARGE",
                     "HTTP2_MAX_CONCURRENT_STREAMS_EXCEEDED", "GRPC_MESSAGE_OVER_DEFAULT_LIMIT",
                     "HTTP2_FLOW_CONTROL_STALL", "GRPC_CLEARTEXT", "GRPC_UNAUTHENTICATED", "GRPC_UNIMPLEMENTED"):
            self.assertIn(code, found)
        conn = report["connections"][0]
        stall = conn["flow_control"]["stalls"][0]
        self.assertEqual((stall["sender"], stall["stream_id"], stall["window"]), ("server", 7, "stream"))
        self.assertEqual(stall["duration_s"], 1.5)
        self.assertTrue(stall["resolved"] and stall["data_waiting"])
        self.assertEqual(conn["settings"]["server"]["max_concurrent_streams"], 2)
        self.assertEqual(conn["settings"]["client"]["initial_window_size"], 8192)
        cleanup = [i for i in report["issues"] if i["code"] == "HTTP2_RST_STREAM" and "normal cleanup" in i["message"]]
        self.assertEqual(len(cleanup), 1)  # the CANCEL after the RESOURCE_EXHAUSTED trailers

    def test_synthetic_credentials_by_key_never_value(self):
        report = self.ok(analyze_grpc_capture(fixture("grpc_h2_trouble.pcap")))
        keys = sorted(c["key"] for c in report["credentials"])
        self.assertEqual(keys, ["password", "username", "x-api-key"])
        self.assertTrue(all(c["cleartext"] and c["value"] == "masked" for c in report["credentials"]))
        self.assertEqual(codes(report).count("CLEARTEXT_CREDENTIAL"), 3)
        self.assertEqual(report["connections"][0]["metadata_keys"], ["password", "username", "x-api-key",
                                                                     "x-trace-context"])

    def test_synthetic_goaway_reset_preface_and_mid_connection(self):
        report = self.ok(analyze_grpc_capture(fixture("grpc_connection_trouble.pcap")))
        found = codes(report)
        for code in ("HTTP2_TOO_MANY_PINGS", "HTTP2_GOAWAY", "TCP_RESET_DURING_RPC", "HTTP2_PREFACE_UNANSWERED",
                     "HTTP2_HPACK_DECODE_FAILED"):
            self.assertIn(code, found)
        graceful = next(i for i in report["issues"] if i["code"] == "HTTP2_GOAWAY")
        self.assertIn("streams [3] were not processed", graceful["message"])
        pings = report["connections"][0]["pings"]["client"]
        self.assertEqual((pings["sent"], pings["acked"], pings["interval_s_min"]), (3, 3, 1.0))
        mid = next(c for c in report["connections"] if c["client"].endswith(":52004"))
        self.assertEqual((mid["service"], mid["server_known_by"]), ("tcp/50051", "port"))
        # decode-as tcp/50051 also hits a connection whose client port is 50051: it is not read as gRPC
        self.assertNotIn("tcp/8080", {c["service"] for c in report["connections"]})

    def test_synthetic_tls12_alert_certificate_and_ip_san(self):
        report = self.ok(analyze_grpc_capture(fixture("grpc_tls12_alert.pcap")))
        tls = report["connections"][0]["tls"]
        cert = tls["certificate"]
        self.assertEqual((cert["subject"], cert["issuer"], cert["self_signed"]),
                         ("gnmi.example.net", "gnmi.example.net", True))
        self.assertEqual((cert["dns_names"], cert["ip_addresses"]), (["gnmi.example.net"], []))
        self.assertEqual(tls["version"], "TLS1.2")
        self.assertEqual(tls["alpn_offered"], ["h2"])
        alert = tls["alerts"][0]
        self.assertEqual((alert["description"], alert["sender"]), ("unknown_ca", "client"))
        self.assertIn("refused the server's certificate", alert["hint"])
        self.assertTrue({"TLS_ALERT", "TLS_CERT_NO_IP_SAN", "GRPC_TLS_NOT_DECRYPTED"} <= set(codes(report)))

    def test_synthetic_tls13_hello_retry_request(self):
        for backend in ("tshark", "scapy"):
            with self.subTest(backend=backend):
                tls = analyze_network_capture(fixture("grpc_tls13_hrr.pcap"), detectors=["tls"],
                                              backend=backend)["tls"]
                session = tls["sessions"][0]
                self.assertTrue(session["hello_retry_request"])
                self.assertEqual(session["server_chose"]["version"], "TLS1.3")
                self.assertNotIn("TLS_NO_SERVER_HELLO", codes(tls))
        report = self.ok(analyze_grpc_capture(fixture("grpc_tls13_hrr.pcap")))
        self.assertIn("TLS_NO_SNI", codes(report))

    def test_synthetic_tls13_key_log_decrypts_rpcs(self):
        with tempfile.TemporaryDirectory() as out:
            pcap, keylog = gen.build_tls13_keylog(out)
            with open(keylog) as handle:
                secrets = [line.split()[-1] for line in handle if line.strip()]
            closed = self.ok(analyze_grpc_capture(pcap))
            self.assertEqual(closed["rpcs"], [])
            self.assertIn("GRPC_TLS_NOT_DECRYPTED", codes(closed))
            report = self.ok(analyze_grpc_capture(pcap, keylog_file=keylog))
            text = json.dumps(report)
            self.assertNotIn(keylog, text)
            for secret in secrets:
                self.assertNotIn(secret, text)
            self.assertTrue(report["capture"]["keylog_file_given"])
            rpcs = rpc_by_stream(report)
            self.assertEqual((rpcs[1]["method"], rpcs[1]["grpc_status_name"]), ("/gnmi.gNMI/Capabilities", "OK"))
            self.assertEqual(rpcs[3]["grpc_status_name"], "UNAUTHENTICATED")
            conn = report["connections"][0]
            self.assertEqual(conn["transport"], "tls (decrypted with the key log)")
            self.assertTrue(conn["tls"]["certificate"]["decrypted_with_key_log"])
            self.assertEqual(conn["tls"]["certificate"]["ip_addresses"], [])
            self.assertIn("TLS_CERT_NO_IP_SAN", codes(report))
            self.assertNotIn("CLEARTEXT_CREDENTIAL", codes(report))
            self.assertEqual(codes(report).count("CREDENTIAL_IN_METADATA"), 2)

    def test_errors_are_data(self):
        self.assertEqual(analyze_grpc_capture("/nonexistent.pcap")["status"], "error")
        self.assertIn("keylog_file", analyze_grpc_capture(fixture("grpc_tls12_alert.pcap"),
                                                          keylog_file="/nonexistent.keys")["error"])
        self.assertIn("Not a TCP port", analyze_grpc_capture(fixture("grpc_tls12_alert.pcap"), ports=[70000])["error"])
        empty = self.ok(analyze_grpc_capture(fixture("bgp_session.pcap")))
        self.assertEqual(empty["overall_status"], "not_present")


class AuditAssertions:
    """The cleartext audit's recognition by content; mixed into one TestCase per backend."""

    backend = None

    def audit(self, name, **kwargs):
        report = audit_cleartext_capture(fixture(name), backend=self.backend, **kwargs)
        self.assertEqual(report["status"], "success", report.get("error"))
        self.assertEqual(report["capture"]["backend"], self.backend)
        return report

    def test_synthetic_management_sessions_named_by_content(self):
        report = self.audit("grpc_mgmt_mix.pcap")
        sessions = {s["service"]: s for s in report["tcp_sessions"]}
        self.assertEqual(sessions["tcp/830"]["protocol"], "netconf over ssh (tcp/830)")
        self.assertEqual(sessions["tcp/830"]["protection"], {"key_exchange": 10, "encrypted": 8})
        self.assertEqual(sessions["tcp/443"]["protocol"], "tls (tcp/443 https)")
        self.assertEqual(sessions["tcp/23"]["protection"], {"cleartext": 5})
        self.assertEqual(sessions["tcp/50001"]["server"], "10.70.0.1:50001")  # not the client's 41000
        self.assertEqual(report["protection"]["cleartext"], 12)
        found = codes(report)
        # The default allowlist (encrypted) accepts the SSH and TLS sessions; crypto alone (IPsec) does not.
        self.assertNotIn("ENCRYPTED_OUTSIDE_ALLOWLIST", found)
        self.assertIn("ENCRYPTED_OUTSIDE_TUNNEL", found)
        self.assertEqual(codes(self.audit("grpc_mgmt_mix.pcap", allow=["crypto"])).count("ENCRYPTED_OUTSIDE_ALLOWLIST"),
                         4)
        if HAVE_TSHARK:
            self.assertEqual(sessions["tcp/50001"]["protocol"], "grpc (tcp/50001)")
            self.assertEqual([c["key"] for c in report["credentials"]], ["authorization"])
            self.assertIn("CLEARTEXT_CREDENTIAL", found)
            self.assertNotIn(gen.SYNTHETIC_API_KEY.decode(), json.dumps(report))

    def test_synthetic_encrypted_token_accepts_transport_encryption(self):
        report = self.audit("grpc_mgmt_mix.pcap", allow=["encrypted"])
        self.assertFalse(report["passed"])
        self.assertEqual(report["frames_outside_allowlist"], 12)  # the login and the cleartext gRPC
        report = self.audit("grpc_tls12_alert.pcap", allow=["tls"])
        self.assertTrue(report["passed"])
        report = self.audit("grpc_mgmt_mix.pcap", allow=["netconf", "tls", "tcp:23", "http2"])
        self.assertTrue(report["passed"], report["verdict"])

    def test_synthetic_flows_labelled_by_listening_port(self):
        report = analyze_network_capture(fixture("grpc_mgmt_mix.pcap"), detectors=["conversations"],
                                         backend=self.backend)
        labels = {p["protocol"] for p in report["conversations"]["protocols"]}
        self.assertIn("tcp/50001", labels)
        self.assertNotIn("tcp/41000", labels)


class TestAuditTshark(AuditAssertions, unittest.TestCase):
    backend = "tshark"

    def setUp(self):
        if not HAVE_TSHARK:
            self.skipTest("tshark is not installed")


class TestAuditScapy(AuditAssertions, unittest.TestCase):
    backend = "scapy"


@unittest.skipUnless(HAVE_TSHARK and os.path.exists(PLAINTEXT) and os.path.exists(ENCRYPTED),
                     "the real gNMI and NETCONF/RESTCONF/SSH captures are not on this machine")
class TestRealCaptures(unittest.TestCase):
    """
    Two real captures: plaintext gNMI/gNOI to Stratum on tcp/50001 with throwaway metadata
    credentials, and NETCONF over SSH, RESTCONF over TLS 1.3 and SSH to a Catalyst 8000V.
    """

    @classmethod
    def setUpClass(cls):
        cls.secrets = metadata_values(PLAINTEXT, 50001, {"username", "password"})

    def no_secret(self, text):
        self.assertTrue(self.secrets)
        for secret in self.secrets:
            self.assertNotIn(secret, text)

    def test_real_plaintext_rpcs_by_name_with_status(self):
        report = analyze_grpc_capture(PLAINTEXT)
        self.assertEqual(report["status"], "success")
        self.no_secret(json.dumps(report))
        seen = [(r["method"], r["grpc_status_name"]) for r in report["rpcs"]]
        self.assertEqual(seen, [
            ("/gnmi.gNMI/Capabilities", "OK"), ("/gnmi.gNMI/Get", "INVALID_ARGUMENT"),
            ("/gnmi.gNMI/Get", "INVALID_ARGUMENT"), ("/gnmi.gNMI/Subscribe", "OK"),
            ("/gnmi.gNMI/Capabilities", "OK"), ("/gnoi.system.System/Time", "OK"),
            ("/gnoi.certificate.CertificateManagement/GetCertificates", "OK"), ("/gnoi.os.OS/Verify", "UNIMPLEMENTED"),
            ("/gnoi.file.File/Stat", "OK"), ("/gnoi.file.File/Stat", "OK")])
        refused = report["rpcs"][1]
        self.assertEqual((refused["grpc_status"], refused["grpc_message"]),
                         (3, "Get response can only be encoded as PROTO."))
        self.assertEqual(refused["decoded"]["request"]["encoding"], "JSON_IETF")
        self.assertIn("lists only PROTO", refused["diagnosis"])
        caps = report["rpcs"][0]["decoded"]["response"]
        self.assertEqual((caps["gnmi_version"], caps["supported_encodings"], caps["models"]), ("0.7.0", ["PROTO"], 22))
        self.assertEqual(report["rpcs"][3]["decoded"]["request"]["mode"], "ONCE")
        self.assertEqual(report["rpcs"][3]["decoded"]["response"]["errors"][0]["message"], "Unsupported path.")
        conn = report["connections"][0]
        self.assertEqual((conn["service"], conn["server"], conn["detected_by"]),
                         ("tcp/50001", "172.17.0.2:50001", "preface"))
        self.assertEqual(conn["goaways"][0]["debug_data"], "client transport shutdown")

    def test_real_plaintext_one_credential_finding_per_key(self):
        report = analyze_grpc_capture(PLAINTEXT)
        creds = [i for i in report["issues"] if i["code"] == "CLEARTEXT_CREDENTIAL"]
        self.assertEqual(sorted(i["key"] for i in creds), ["password", "username"])
        self.assertTrue(all("tcp/50001" in i["message"] for i in creds))
        audit = audit_cleartext_capture(PLAINTEXT)
        self.no_secret(json.dumps(audit))
        self.assertEqual(sorted(c["key"] for c in audit["credentials"]), ["password", "username"])
        self.assertEqual(codes(audit).count("CLEARTEXT_CREDENTIAL"), 2)
        self.assertEqual([s["protocol"] for s in audit["tcp_sessions"]], ["grpc (tcp/50001)"])
        self.assertEqual(audit["cleartext_frames"], 57)
        labels = {p["protocol"] for p in analyze_network_capture(PLAINTEXT, detectors=["conversations"])
                  ["conversations"]["protocols"]}
        self.assertEqual(labels, {"tcp/50001"})

    def test_real_plaintext_cli_and_report_files_hold_no_value(self):
        with tempfile.TemporaryDirectory() as out:
            for name in ("report.md", "report.json"):
                done = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file", PLAINTEXT,
                                       "--grpc", "--save_file", os.path.join(out, name)],
                                      capture_output=True, text=True, timeout=300, cwd=HERE)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn("CLEARTEXT_CREDENTIAL", done.stdout)
                self.no_secret(done.stdout + done.stderr)
                with open(os.path.join(out, name)) as handle:
                    self.no_secret(handle.read())

    def test_real_encrypted_capture_has_no_cleartext(self):
        for backend in ("tshark", "scapy"):
            with self.subTest(backend=backend):
                audit = audit_cleartext_capture(ENCRYPTED, backend=backend)
                self.assertEqual(audit["cleartext_frames"], 0)
                self.assertEqual(audit["protection"]["cleartext"], 0)
                self.assertEqual(audit["protection"]["encrypted"] + audit["protection"]["key_exchange"], 1030)
                self.assertNotIn("CLEARTEXT_OUTSIDE_ALLOWLIST", codes(audit))
                self.assertNotIn("CLEARTEXT_CREDENTIAL", codes(audit))
                self.assertTrue(audit["passed"] and audit["clean"], audit["verdict"])  # the default: encrypted
                names = [s["protocol"] for s in audit["tcp_sessions"]]
                self.assertEqual(names, ["netconf over ssh (tcp/830)", "tls (tcp/443 https)", "tls (tcp/443 https)",
                                         "tls (tcp/443 https)", "ssh (tcp/22)"])
                tunnel = audit_cleartext_capture(ENCRYPTED, backend=backend, allow=["crypto"])
                self.assertFalse(tunnel["passed"])
                self.assertIn("none of them is cleartext", tunnel["verdict"])

    def test_real_encrypted_tls13_after_hello_retry_and_no_grpc_claimed(self):
        tls = analyze_network_capture(ENCRYPTED, detectors=["tls"])["tls"]
        self.assertEqual([s["server_chose"]["version"] for s in tls["sessions"]], ["TLS1.3"] * 3)
        self.assertNotIn("TLS_NO_SERVER_HELLO", codes(tls))
        report = analyze_grpc_capture(ENCRYPTED)
        self.assertEqual(report["rpcs"], [])
        self.assertEqual(report["credentials"], [])
        self.assertEqual({c["protocol"] for c in report["connections"]}, {"tls, h2 offered"})
        self.assertIn("whether they carry gRPC cannot be seen", report["verdict"])


def proto_dir():
    for path in [os.environ.get("SONIC_PROTO_PATH", "")] + [os.path.expanduser("~/.cache/sonic/grpc-protos")]:
        if path and os.path.exists(os.path.join(path, "github.com/openconfig/gnmi/proto/gnmi/gnmi.proto")):
            return path
    return None


@unittest.skipUnless(HAVE_TSHARK and proto_dir(), "no gNMI .proto files (run sonic.py --fetch-grpc-protos)")
class TestWiresharkProtobuf(unittest.TestCase):
    def test_synthetic_message_types_named_by_wireshark(self):
        report = analyze_grpc_capture(fixture("grpc_h2_trouble.pcap"), proto_paths=[proto_dir()])
        self.assertEqual(report["capture"]["warnings"], [])
        types = {p["message_type"] for r in report["rpcs"] for p in r.get("wireshark_protobuf", [])}
        self.assertTrue({"gnmi.CapabilityResponse", "gnmi.GetRequest", "gnmi.SubscribeRequest"} <= types, types)
        get = rpc_by_stream(report)[5]["wireshark_protobuf"][0]
        self.assertIn({"field": "gnmi.GetRequest.encoding", "value": "JSON_IETF (4)"}, get["fields"])


class TestProtoFetch(unittest.TestCase):
    """The .proto fetcher against a fake opener: pins checked, nothing written on a mismatch."""

    def test_fetch_checks_every_pin(self):
        from utils import grpc_protos
        contents = {}
        for (repo, _tag, commit), path, target, _sha in grpc_protos.FILES:
            contents[grpc_protos.RAW.format(repo=repo, commit=commit, path=path)] = f"// {target}\n".encode()
        pins = {target: hashlib.sha256(f"// {target}\n".encode()).hexdigest()
                for _s, _p, target, _sha in grpc_protos.FILES}
        with tempfile.TemporaryDirectory() as out:
            result = grpc_protos.fetch_protos(out, opener=contents.__getitem__, pins=pins)
            self.assertEqual(result["status"], "success")
            self.assertTrue(os.path.exists(os.path.join(out, "github.com/openconfig/gnmi/proto/gnmi/gnmi.proto")))
            self.assertTrue(os.path.exists(os.path.join(out, "LICENSES/openconfig-gnoi.LICENSE")))
        with tempfile.TemporaryDirectory() as out:
            bad = dict(pins)
            bad["github.com/openconfig/gnmi/proto/gnmi/gnmi.proto"] = "0" * 64
            result = grpc_protos.fetch_protos(out, opener=contents.__getitem__, pins=bad)
            self.assertEqual(result["status"], "error")
            self.assertIn("SHA-256 mismatch", result["error"])
            self.assertFalse(os.path.exists(os.path.join(out, "github.com/openconfig/gnmi/proto/gnmi/gnmi.proto")))
        self.assertEqual(len(grpc_protos.PINS), len(grpc_protos.FILES))


@unittest.skipUnless(HAVE_TSHARK, "tshark is not installed")
class TestGrpcInterfaces(unittest.TestCase):
    def test_mcp_tool_function(self):
        import mcp_server
        tool = mcp_server.analyze_grpc_pcap
        fn = getattr(tool, "fn", tool)
        result = fn(file_path=fixture("grpc_h2_trouble.pcap"))
        json.dumps(result)
        self.assertEqual(result["status"], "success")
        self.assertIn("CLEARTEXT_CREDENTIAL", codes(result))
        self.assertEqual(fn(file_path="/nonexistent.pcap")["status"], "error")

    def test_cli_json_mode(self):
        with tempfile.TemporaryDirectory() as out:
            done = subprocess.run([sys.executable, os.path.join(HERE, "sonic.py"), "--file",
                                   fixture("grpc_connection_trouble.pcap"), "--grpc", "--json", "--save_file",
                                   os.path.join(out, "r.md")], capture_output=True, text=True, timeout=300, cwd=HERE)
            self.assertEqual(done.returncode, 0, done.stderr)
            report = json.loads(done.stdout)
            self.assertIn("HTTP2_TOO_MANY_PINGS", codes(report))
            with open(os.path.join(out, "r.md")) as handle:
                self.assertIn("# S.O.N.I.C. gRPC troubleshooting", handle.read())


class TestGrpcFixtures(unittest.TestCase):
    def test_synthetic_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, os.path.join(FIXTURES, "generate_grpc_fixtures.py"), out],
                           check=True, capture_output=True)
            names = sorted(os.listdir(out))
            self.assertEqual(names, sorted(os.path.basename(p) for p in glob.glob(fixture("grpc_*.pcap"))))
            self.assertEqual(len(names), 5)
            for name in names:
                with self.subTest(fixture=name):
                    self.assertTrue(filecmp.cmp(os.path.join(out, name), fixture(name), shallow=False),
                                    f"{name} differs from a fresh generation; rerun generate_grpc_fixtures.py")
                    self.assertLess(os.path.getsize(fixture(name)), 200 * 1024)


if __name__ == "__main__":
    unittest.main()
