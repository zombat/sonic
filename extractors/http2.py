#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. HTTP/2 and gRPC Extraction Module

Reads HTTP/2 (and the gRPC carried in it) from a capture with Wireshark's own
dissectors, through tshark. Wireshark does the parts that are hard to get right:
TCP reassembly, TLS decryption from a key log, HTTP/2 framing and HPACK header
decompression (Huffman coding and the dynamic table). This module turns its output
into plain records for analyzers/grpc_inspect.py.

Passes over the capture, each streamed (memory stays flat):

1. Discovery (-T fields, a narrow display filter): every SYN, SYN-ACK and RST, every
   TLS ClientHello and ServerHello (SNI, ALPN), and the payload segments of each
   connection on a well-known gRPC port. It tells which side of each TCP connection is
   the server (the SYN's destination) and which connections are TLS.

2. Prefaces (-T fields, one row per match): every segment that opens with the HTTP/2
   connection preface ("PRI * HTTP/2.0..."), on any port, and who sent it.

3. HTTP/2 (-T pdml, -Y http2): with decode-as for each port where the preface was
   seen (plaintext, h2c), each well-known gRPC port without TLS, and, for TLS on a
   gRPC port or with ALPN h2, TLS then HTTP/2 inside it (decrypted only with a key
   log). The PDML tree keeps each HTTP/2 frame with its own fields, so headers,
   SETTINGS, WINDOW_UPDATE, PING, RST_STREAM, GOAWAY and DATA stay attributed to the
   right stream.

Header values are masked here, at the source, before anything else sees them: only
the values of the names in SHOWN_HEADERS (pseudo-headers, content-type, grpc-status,
grpc-message, user-agent, grpc-timeout and a few more) are kept. Every other value is
replaced by None, and a credential-like name (username, password, authorization,
x-api-key, token, cookie, ...) is marked as such. The masked values are kept only in
memory, on the extraction object (secret_values), so the analyzer can scrub any echo
of them (for example inside a grpc-message) from its report; they are never written
into a record.

A key log (SSLKEYLOGFILE format) is passed to tshark by path (-o tls.keylog_file:)
and never read or copied here. Proto files for Wireshark's protobuf dissector are
passed as search paths (the protobuf_search_paths table).

Author: Raymond A Rizzo | Zombat
"""

import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import unquote

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
PREFACE_FILTER = ":".join(f"{b:02x}" for b in PREFACE)

# Ports where gRPC management services listen by default. A port in this table is
# decoded as HTTP/2 when its connections are not TLS, even when the preface was not
# captured (a capture that starts mid-connection).
GRPC_PORTS = {
    9339: "gnmi-gnoi (IANA)",
    9340: "gribi (IANA)",
    9559: "p4runtime (IANA)",
    57400: "gnmi (Nokia SR Linux, Cisco IOS XR)",
    6030: "gnmi (Arista EOS)",
    50001: "gnmi (Stratum)",
    50051: "grpc (common default; Cisco NX-OS gNMI)",
    50052: "gnmi insecure (Cisco IOS XE)",
    32767: "gnmi (Juniper Junos)",
}

# Header names whose values may appear in a report. Everything else is masked.
SHOWN_HEADERS = {
    ":method", ":scheme", ":path", ":authority", ":status",
    "content-type", "te", "user-agent", "grpc-status", "grpc-message", "grpc-timeout",
    "grpc-encoding", "grpc-accept-encoding", "accept-encoding", "content-encoding",
    "grpc-message-type", "server", "date", "content-length", "grpc-previous-rpc-attempts",
    "grpc-retry-pushback-ms",
}

# A metadata name that carries a credential: flagged, and its value never shown.
CREDENTIAL_NAME = re.compile(
    r"^(username|user|user-name|login|password|passwd|pass|pwd|authorization|proxy-authorization|"
    r"cookie|set-cookie|x-api-key|api-key|apikey|api_key|x-auth-token|auth-token|x-access-token|"
    r"access-token|token|x-token|secret|client-secret|x-client-secret|x-amz-security-token)$"
    r"|(password|passwd|secret|token|api-?key|credential|authorization)", re.IGNORECASE)

MIN_SCRUB_LENGTH = 4  # secret values shorter than this are not scrubbed by value from report text


def header_kind(name: str) -> str:
    """'shown' (the value may be reported), 'credential' or 'masked' for one header name."""
    lowered = name.lower()
    if lowered in SHOWN_HEADERS:
        return "shown"
    if CREDENTIAL_NAME.search(lowered):
        return "credential"
    return "masked"


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def tshark_version() -> Optional[str]:
    """The first line of tshark --version, or None."""
    try:
        out = subprocess.run(["tshark", "--version"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return out.splitlines()[0].strip() if out else None


def _int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Pass 1: discovery
# ---------------------------------------------------------------------------

DISCOVERY_FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                    "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len", "frame.protocols",
                    "tls.handshake.type", "tls.handshake.extensions_server_name",
                    "tls.handshake.extensions_alpn_str"]


def discovery_filter() -> str:
    ports = " ".join(str(p) for p in sorted(GRPC_PORTS))
    return (f"tcp.flags.syn==1 || tcp.flags.reset==1 || tls.handshake.type==1 || tls.handshake.type==2 || "
            f"(tcp.len>=24 && tcp.payload[0:24]=={PREFACE_FILTER}) || (tcp.port in {{{ports}}} && tcp.len>0)")


class TcpConnection:
    """What the discovery pass learned about one TCP connection (one tcp.stream index)."""

    __slots__ = ("index", "a", "b", "client", "server", "server_known_by", "first_frame", "first_t", "last_t",
                 "preface_frame", "preface_from", "tls_client_hello", "tls_server_hello", "sni", "alpn",
                 "resets", "first_payload_tls", "first_payload_frame", "syn_frame")

    def __init__(self, index: int, a: Tuple[str, int], b: Tuple[str, int], frame: int, t: float):
        self.index = index
        self.a, self.b = a, b
        self.client: Optional[Tuple[str, int]] = None
        self.server: Optional[Tuple[str, int]] = None
        self.server_known_by: Optional[str] = None
        self.first_frame, self.first_t, self.last_t = frame, t, t
        self.preface_frame: Optional[int] = None
        self.preface_from: Optional[Tuple[str, int]] = None
        self.tls_client_hello: Optional[int] = None
        self.tls_server_hello: Optional[int] = None
        self.sni: Optional[str] = None
        self.alpn: List[str] = []
        self.resets: List[Dict[str, Any]] = []
        self.first_payload_tls: Optional[bool] = None
        self.first_payload_frame: Optional[int] = None
        self.syn_frame: Optional[int] = None

    def set_server(self, server: Tuple[str, int], how: str):
        """Record the listening side, keeping the strongest evidence (SYN beats everything)."""
        rank = {"syn": 4, "syn-ack": 3, "preface": 2, "client_hello": 2, "port": 1}
        if self.server_known_by and rank[self.server_known_by] >= rank[how]:
            return
        self.server = server
        self.client = self.b if server == self.a else self.a
        self.server_known_by = how

    def service_port(self) -> int:
        """The server's port: the SYN's destination, else the best other evidence, else the lower port."""
        if self.server:
            return self.server[1]
        for end in (self.a, self.b):
            if end[1] in GRPC_PORTS:
                return end[1]
        return min(self.a[1], self.b[1])

    def is_tls(self) -> bool:
        return self.tls_client_hello is not None or self.tls_server_hello is not None or bool(self.first_payload_tls)


def discover(file_path: str, display_filter: Optional[str] = None, max_packets: Optional[int] = None,
             status: Optional[Dict[str, Any]] = None) -> Dict[int, TcpConnection]:
    """
    Pass 1: the TCP connections that matter for HTTP/2, keyed by tcp.stream index.

    Raises:
        RuntimeError: tshark failed before producing anything
    """
    flt = discovery_filter()
    if display_filter:
        flt = f"({display_filter}) && ({flt})"
    command = ["tshark", "-n", "-r", file_path, "-Y", flt, "-T", "fields", "-E", "separator=\t",
               "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=n"]
    for name in DISCOVERY_FIELDS:
        command += ["-e", name]
    if max_packets:
        command += ["-c", str(int(max_packets))]
    conns: Dict[int, TcpConnection] = {}
    with tempfile.TemporaryFile(mode="w+") as err:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True, bufsize=1 << 16)
        produced = 0
        try:
            for line in proc.stdout:
                produced += 1
                parts = line.rstrip("\n").split("\t")
                parts += [""] * (len(DISCOVERY_FIELDS) - len(parts))
                row = dict(zip(DISCOVERY_FIELDS, parts))
                _discovery_row(conns, row)
        finally:
            if proc.poll() is None:
                proc.stdout.close()
                proc.terminate()
            proc.wait()
            err.seek(0)
            stderr_text = err.read()[-2000:].strip()
        if status is not None:
            status["discovery_returncode"] = proc.returncode
            status["discovery_stderr"] = stderr_text
        if proc.returncode not in (0, None) and produced == 0:
            raise RuntimeError(f"tshark failed (exit {proc.returncode}): {stderr_text}")
    for index, (frame, sender) in find_prefaces(file_path, display_filter, max_packets).items():
        conn = conns.get(index)
        if conn is None:
            continue
        conn.preface_frame, conn.preface_from = frame, sender
        conn.set_server(conn.b if sender == conn.a else conn.a, "preface")
    return conns


def _discovery_row(conns: Dict[int, TcpConnection], row: Dict[str, str]):
    index = _int(row["tcp.stream"].split("|")[0])
    if index is None:
        return
    src = (row["ip.src"] or row["ipv6.src"]).split("|")[0]
    dst = (row["ip.dst"] or row["ipv6.dst"]).split("|")[0]
    sport, dport = _int(row["tcp.srcport"].split("|")[0]), _int(row["tcp.dstport"].split("|")[0])
    if not src or not dst or sport is None or dport is None:
        return
    frame = _int(row["frame.number"]) or 0
    t = float(row["frame.time_epoch"] or 0.0)
    me, peer = (src, sport), (dst, dport)
    conn = conns.get(index)
    if conn is None:
        conn = TcpConnection(index, me, peer, frame, t)
        conns[index] = conn
    conn.last_t = max(conn.last_t, t)
    flags = _int(row["tcp.flags"].split("|")[0]) or 0
    syn, ack, rst = bool(flags & 0x02), bool(flags & 0x10), bool(flags & 0x04)
    if syn and not ack:
        conn.set_server(peer, "syn")
        conn.syn_frame = conn.syn_frame or frame
    elif syn and ack:
        conn.set_server(me, "syn-ack")
    if rst:
        conn.resets.append({"frame": frame, "t": t, "from": me})
    payload_len = _int(row["tcp.len"].split("|")[0]) or 0
    protocols = row["frame.protocols"]
    hs_types = [_int(v) for v in row["tls.handshake.type"].split("|") if v]
    if 1 in hs_types:
        conn.tls_client_hello = conn.tls_client_hello or frame
        conn.set_server(peer, "client_hello")
        sni = row["tls.handshake.extensions_server_name"].split("|")[0]
        conn.sni = conn.sni or (sni or None)
        alpn = [a for a in row["tls.handshake.extensions_alpn_str"].split("|") if a]
        if alpn and not conn.alpn:
            conn.alpn = alpn
    if 2 in hs_types:
        conn.tls_server_hello = conn.tls_server_hello or frame
    if payload_len and conn.first_payload_frame is None:
        conn.first_payload_frame = frame
        conn.first_payload_tls = ":tls" in protocols or ":ssl" in protocols


def find_prefaces(file_path: str, display_filter: Optional[str] = None,
                  max_packets: Optional[int] = None) -> Dict[int, Tuple[int, Tuple[str, int]]]:
    """
    The frames that open with the HTTP/2 connection preface: tcp.stream -> (frame, sender).

    A separate, tiny pass (one row per preface) so the discovery pass needs no payload column.
    """
    flt = f"tcp.len>=24 && tcp.payload[0:24]=={PREFACE_FILTER}"
    if display_filter:
        flt = f"({display_filter}) && ({flt})"
    command = ["tshark", "-n", "-r", file_path, "-Y", flt, "-T", "fields", "-E", "separator=\t",
               "-e", "frame.number", "-e", "tcp.stream", "-e", "ip.src", "-e", "ipv6.src", "-e", "tcp.srcport"]
    if max_packets:
        command += ["-c", str(int(max_packets))]
    out: Dict[int, Tuple[int, Tuple[str, int]]] = {}
    proc = subprocess.run(command, capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        parts = line.split("\t") + [""] * 5
        frame, index, src4, src6, sport = parts[:5]
        index_i = _int(index)
        if index_i is None or index_i in out:
            continue
        out[index_i] = (_int(frame) or 0, ((src4 or src6).split(",")[0], _int(sport) or 0))
    return out


def plan_decode_as(conns: Dict[int, TcpConnection], extra_ports: Optional[List[int]] = None
                   ) -> Tuple[List[str], Dict[int, str]]:
    """
    The tshark decode-as options for the HTTP/2 pass, and why each port is decoded.

    Returns (options, {port: reason}) where reason is "preface", "grpc_port" (no TLS, preface
    not captured), "tls_h2" (TLS offering ALPN h2, or TLS on a gRPC port) or "requested".
    """
    reasons: Dict[int, str] = {}
    for conn in sorted(conns.values(), key=lambda c: c.first_frame):
        port = conn.service_port()
        if conn.preface_frame is not None and not conn.is_tls():
            reasons[port] = "preface"
        elif conn.is_tls() and ("h2" in conn.alpn or port in GRPC_PORTS):
            reasons.setdefault(port, "tls_h2")
        elif port in GRPC_PORTS and conn.first_payload_frame is not None and not conn.is_tls():
            reasons.setdefault(port, "grpc_port")
    for port in extra_ports or []:
        reasons.setdefault(int(port), "requested")
    options: List[str] = []
    for port, reason in sorted(reasons.items()):
        if reason == "tls_h2":
            options += ["-d", f"tcp.port=={port},tls"]  # HTTP/2 inside follows ALPN or the TLS heuristic
        else:
            options += ["-d", f"tcp.port=={port},http2"]
    return options, reasons


# ---------------------------------------------------------------------------
# Pass 2: HTTP/2 frames from PDML
# ---------------------------------------------------------------------------

FRAME_TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE",
               6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}
SETTINGS_NAMES = {1: "header_table_size", 2: "enable_push", 3: "max_concurrent_streams",
                  4: "initial_window_size", 5: "max_frame_size", 6: "max_header_list_size",
                  8: "enable_connect_protocol"}
MAX_DATA_KEEP = 65536  # bytes of DATA kept per HTTP/2 frame for gRPC framing and message decoding

# Protobuf fields (Wireshark field names with protobuf.pbf_as_hf) whose values are safe to show:
# enums, counts, versions and path element names. Values of anything else are never read.
PROTOBUF_SHOWN_FIELDS = {
    "pbf.gnmi.GetRequest.encoding", "pbf.gnmi.GetRequest.type",
    "pbf.gnmi.SubscriptionList.mode", "pbf.gnmi.SubscriptionList.encoding",
    "pbf.gnmi.SubscriptionList.updates_only", "pbf.gnmi.Subscription.mode",
    "pbf.gnmi.Subscription.sample_interval", "pbf.gnmi.CapabilityResponse.gNMI_version",
    "pbf.gnmi.CapabilityResponse.supported_encodings", "pbf.gnmi.SubscribeResponse.sync_response",
    "pbf.gnmi.PathElem.name", "pbf.gnmi.Path.origin", "pbf.gnmi.Error.code", "pbf.gnmi.Error.message",
    "pbf.gnmi.UpdateResult.op", "pbf.gnoi.system.TimeResponse.time",
}


def protobuf_options(proto_paths: Optional[List[str]]) -> List[str]:
    """tshark options that load .proto files for the protobuf dissector, one search path per directory."""
    options: List[str] = []
    for path in proto_paths or []:
        quoted = path.replace("\\", "\\\\").replace('"', '\\"')
        options += ["-o", f'uat:protobuf_search_paths:"{quoted}","TRUE"']
    if options:
        options += ["-o", "protobuf.pbf_as_hf:TRUE"]
    return options


def _fields(elem: ET.Element, name: str) -> List[ET.Element]:
    return [child for child in elem if child.tag == "field" and child.get("name") == name]


def _first(elem: ET.Element, name: str) -> Optional[ET.Element]:
    for child in elem.iter("field"):
        if child.get("name") == name:
            return child
    return None


def _show(elem: ET.Element, name: str) -> Optional[str]:
    found = _first(elem, name)
    return found.get("show") if found is not None else None


class Http2Extraction:
    """
    The HTTP/2 pass: packets (a generator) and what the pass learned.

    secret_values holds the masked credential values seen, in memory only, so the
    analyzer can scrub an echo of one from its report. It is never serialized.
    """

    def __init__(self):
        self.secret_values: Set[str] = set()
        self.status: Dict[str, Any] = {}
        self.packets: Iterator[Dict[str, Any]] = iter(())


def _header_block(stream_field: ET.Element, extraction: Http2Extraction) -> Dict[str, Any]:
    """Decoded headers of one HEADERS/CONTINUATION frame, masked by name."""
    headers: List[Dict[str, Any]] = []
    size = 0
    unresolved = False
    for header in _fields(stream_field, "http2.header"):
        name = _show(header, "http2.header.name")
        value = _show(header, "http2.header.value")
        if name is None:
            continue
        if name == "<unknown>":
            # Wireshark could not resolve a dynamic table entry: the connection's earlier header
            # blocks (where the entry was added) are not in the capture.
            unresolved = True
            continue
        value = value or ""
        size += len(name) + len(value) + 32  # RFC 9113 6.5.2 header list size
        kind = header_kind(name)
        if kind == "shown":
            if name.lower() == "grpc-message":
                value = unquote(value)
            headers.append({"name": name, "value": value})
        else:
            if kind == "credential" and len(value) >= MIN_SCRUB_LENGTH:
                extraction.secret_values.add(value)
                # The value may be quoted again in percent-encoded or base64-wrapped form.
                if " " in value:
                    extraction.secret_values.add(value.split(" ", 1)[1])
            headers.append({"name": name, "value": None, "masked": True, "credential": kind == "credential"})
    count = _int(_show(stream_field, "http2.header.count"))
    failed = unresolved or (bool(_fields(stream_field, "http2.headers")) and not headers and count is None)
    return {"headers": headers, "header_list_size": size, "decode_failed": failed}


def _frame_from_pdml(stream_field: ET.Element, extraction: Http2Extraction) -> Optional[Dict[str, Any]]:
    ftype = _int(_show(stream_field, "http2.type"))
    if ftype is None:
        magic = _first(stream_field, "http2.magic")
        return {"type": "MAGIC"} if magic is not None else None
    frame: Dict[str, Any] = {
        "type": FRAME_TYPES.get(ftype, f"TYPE_{ftype}"),
        "type_code": ftype,
        "stream_id": _int(_show(stream_field, "http2.streamid")) or 0,
        "length": _int(_show(stream_field, "http2.length")) or 0,
        "flags": _int(_show(stream_field, "http2.flags")) or 0,
    }
    flags = frame["flags"]
    if ftype in (0, 1):
        frame["end_stream"] = bool(flags & 0x01)
    if ftype in (1, 9):
        frame["end_headers"] = bool(flags & 0x04)
        frame.update(_header_block(stream_field, extraction))
    if ftype in (4, 6):
        frame["ack"] = bool(flags & 0x01)
    if ftype == 0:
        data = _first(stream_field, "http2.data.data")
        raw = data.get("value") if data is not None else None
        try:
            frame["data"] = bytes.fromhex(raw[:MAX_DATA_KEEP * 2]) if raw else b""
        except ValueError:
            frame["data"] = b""
        frame["data_len"] = len(raw) // 2 if raw else 0
    elif ftype == 3:
        frame["error_code"] = _int(_show(stream_field, "http2.rst_stream.error"))
    elif ftype == 4:
        settings = {}
        for item in _fields(stream_field, "http2.settings"):
            sid = _int(_show(item, "http2.settings.id"))
            if sid is None:
                continue
            value = None
            for child in item:
                if child.tag == "field" and child.get("name") not in ("http2.settings.id",):
                    value = _int(child.get("show"))
            settings[SETTINGS_NAMES.get(sid, f"id_{sid}")] = value
        frame["settings"] = settings
    elif ftype == 6:
        payload = _first(stream_field, "http2.pong" if frame["ack"] else "http2.ping")
        frame["opaque"] = (payload.get("value") or payload.get("show") or "") if payload is not None else ""
    elif ftype == 7:
        frame["last_stream_id"] = _int(_show(stream_field, "http2.goaway.last_stream_id"))
        frame["error_code"] = _int(_show(stream_field, "http2.goaway.error"))
        debug = _first(stream_field, "http2.goaway.addata")
        raw = debug.get("value") if debug is not None else None
        text = None
        if raw:
            try:
                decoded = bytes.fromhex(raw).decode("utf-8", "replace")
                text = "".join(ch for ch in decoded if ch.isprintable())[:200]
            except ValueError:
                text = None
        frame["debug_data"] = text
    elif ftype == 8:
        frame["increment"] = _int(_show(stream_field, "http2.window_update.window_size_increment")) or 0
    return frame


def _protobuf_from_pdml(proto: ET.Element) -> Dict[str, Any]:
    """The message type Wireshark resolved and the allowlisted field values of one protobuf proto."""
    showname = proto.get("showname") or ""
    match = re.search(r"\(Message: ([\w.]+)\)", showname)
    head = re.match(r"Protocol Buffers: ([^,]+),(request|response)", showname)
    fields: List[Dict[str, Any]] = []
    for field in proto.iter("field"):
        name = field.get("name") or ""
        if name in PROTOBUF_SHOWN_FIELDS:
            label = field.get("showname") or ""
            shown = label.split(": ", 1)[1] if ": " in label else field.get("show")
            fields.append({"field": name[4:], "value": shown})
    return {"message_type": match.group(1) if match else None,
            "path": head.group(1) if head else None,
            "direction": head.group(2) if head else None,
            "fields": fields[:64]}


def decrypted_certificates(file_path: str, decode_as: List[str], keylog_file: str,
                           display_filter: Optional[str] = None,
                           max_packets: Optional[int] = None) -> Dict[int, bytes]:
    """
    With a key log: the leaf certificate (DER) each decrypted TLS 1.3 session's server sent, by tcp.stream.

    TLS 1.3 encrypts the Certificate message; once tshark decrypts it, its certificate field is
    readable like a TLS 1.2 one.
    """
    flt = "tls.handshake.certificate"
    if display_filter:
        flt = f"({display_filter}) && {flt}"
    command = ["tshark", "-n", "-r", file_path, "-o", "tcp.reassemble_out_of_order:TRUE", *decode_as,
               "-o", f"tls.keylog_file:{keylog_file}", "-Y", flt, "-T", "fields", "-E", "separator=\t",
               "-E", "occurrence=f", "-e", "tcp.stream", "-e", "tls.handshake.certificate"]
    if max_packets:
        command += ["-c", str(int(max_packets))]
    out: Dict[int, bytes] = {}
    proc = subprocess.run(command, capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        index = _int(parts[0].split(",")[0])
        if index is None or index in out:
            continue
        try:
            out[index] = bytes.fromhex(parts[1].split(",")[0].replace(":", ""))
        except ValueError:
            continue
    return out


def iter_http2_packets(file_path: str, decode_as: List[str], keylog_file: Optional[str] = None,
                       proto_paths: Optional[List[str]] = None, display_filter: Optional[str] = None,
                       max_packets: Optional[int] = None) -> Http2Extraction:
    """
    Pass 2: stream the HTTP/2 frames of the capture.

    Each packet: {"n", "t", "tcp_stream", "src", "sport", "dst", "dport", "tls": bool,
    "frames": [frame, ...], "protobuf": [{"message_type", "path", "direction", "fields"}]}.
    A frame: {"type", "type_code", "stream_id", "length", "flags", ...} plus, by type,
    end_stream, end_headers, headers (masked), header_list_size, decode_failed, data
    (bytes, at most MAX_DATA_KEEP), data_len, error_code, settings, ack, opaque,
    last_stream_id, debug_data, increment.
    """
    extraction = Http2Extraction()
    flt = "http2"
    if display_filter:
        flt = f"({display_filter}) && http2"
    command = ["tshark", "-n", "-r", file_path, "-o", "tcp.reassemble_out_of_order:TRUE", *decode_as]
    if keylog_file:
        command += ["-o", f"tls.keylog_file:{keylog_file}"]
    command += protobuf_options(proto_paths)
    top = "ip ipv6 tcp tls http2" + (" protobuf" if proto_paths else "")
    command += ["-Y", flt, "-T", "pdml", "-J", top]
    if max_packets:
        command += ["-c", str(int(max_packets))]
    extraction.status["decode_as"] = [opt for opt in decode_as if opt != "-d"]

    def generate():
        with tempfile.TemporaryFile(mode="w+b") as err:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, bufsize=1 << 16)
            produced = 0
            try:
                context = ET.iterparse(proc.stdout, events=("start", "end"))
                root = None
                for event, elem in context:
                    if event == "start":
                        if root is None:
                            root = elem
                        continue
                    if elem.tag != "packet":
                        continue
                    packet = _packet_from_pdml(elem, extraction)
                    elem.clear()
                    if root is not None:
                        root.clear()
                    if packet is not None:
                        produced += 1
                        yield packet
            except ET.ParseError as exc:
                extraction.status["parse_error"] = str(exc)
            finally:
                if proc.poll() is None:
                    proc.stdout.close()
                    proc.terminate()
                proc.wait()
                err.seek(0)
                stderr_text = err.read()[-4000:].decode("utf-8", "replace").strip()
                extraction.status["returncode"] = proc.returncode
                extraction.status["stderr"] = stderr_text
                extraction.status["packets"] = produced
            if proc.returncode not in (0, None) and produced == 0:
                raise RuntimeError(f"tshark failed (exit {proc.returncode}): {stderr_text}")

    extraction.packets = generate()
    return extraction


def _packet_from_pdml(elem: ET.Element, extraction: Http2Extraction) -> Optional[Dict[str, Any]]:
    packet: Dict[str, Any] = {"n": 0, "t": 0.0, "tcp_stream": None, "src": None, "dst": None, "sport": None,
                              "dport": None, "tls": False, "frames": [], "protobuf": []}
    for proto in elem:
        if proto.tag != "proto":
            continue
        name = proto.get("name")
        if name == "geninfo":
            packet["n"] = _int(_show(proto, "num")) or 0
            stamp = _first(proto, "timestamp")
            try:
                packet["t"] = float(stamp.get("value")) if stamp is not None else 0.0
            except (TypeError, ValueError):
                packet["t"] = 0.0
        elif name == "ip" and packet["src"] is None:
            packet["src"], packet["dst"] = _show(proto, "ip.src"), _show(proto, "ip.dst")
        elif name == "ipv6" and packet["src"] is None:
            packet["src"], packet["dst"] = _show(proto, "ipv6.src"), _show(proto, "ipv6.dst")
        elif name == "tcp" and packet["tcp_stream"] is None:
            packet["tcp_stream"] = _int(_show(proto, "tcp.stream"))
            packet["sport"], packet["dport"] = _int(_show(proto, "tcp.srcport")), _int(_show(proto, "tcp.dstport"))
        elif name == "tls":
            packet["tls"] = True
        elif name == "http2":
            for child in proto:
                if child.tag == "field" and child.get("name") in ("http2.stream", "http2.magic"):
                    if child.get("name") == "http2.magic":
                        packet["frames"].append({"type": "MAGIC"})
                        continue
                    frame = _frame_from_pdml(child, extraction)
                    if frame:
                        packet["frames"].append(frame)
        elif name == "protobuf":
            packet["protobuf"].append(_protobuf_from_pdml(proto))
    if packet["tcp_stream"] is None or not (packet["frames"] or packet["protobuf"]):
        return None
    return packet
