#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. gRPC Troubleshooting (gNMI, gNOI and any gRPC service)

Reads gRPC from a capture with Wireshark's own HTTP/2, HPACK, gRPC, TLS and
protobuf dissectors through tshark (extractors/http2.py), and answers the questions
an engineer asks when a gRPC client and server do not get along:

Where gRPC runs
    Plaintext HTTP/2 (h2c) by its connection preface on any port, TLS-wrapped HTTP/2 by
    ALPN h2 in the ClientHello, and the well-known gRPC management ports (9339 gNMI/gNOI,
    9340 gRIBI, 9559 P4Runtime, 57400 SR Linux and IOS XR, 6030 Arista, 50001 Stratum,
    50051, 50052 IOS XE insecure, 32767 Junos). Each flow is named by its service port: the
    SYN's destination, else the side that received the preface or the ClientHello.

Per RPC
    The method (:path), authority, content-type, user-agent, deadline (grpc-timeout), the
    request and response message counts and sizes (from the gRPC length-prefixed framing),
    the HTTP status, grpc-status by name and grpc-message from the trailers (or a
    trailers-only response), the time from the request to the first response and to the
    trailers, and a plain-language diagnosis. Metadata keys are listed by name only.

HTTP/2 trouble per connection
    RST_STREAM with its error code, GOAWAY with its last stream id, error and debug data
    (too_many_pings named), flow-control stalls (a sender's window at zero while its stream
    is still open, and how long until a WINDOW_UPDATE reopened it), PING keepalives and their
    round trip, each side's SETTINGS (max frame size, max concurrent streams, initial window,
    header list size), a frame over the peer's max frame size, a header list over the peer's
    limit, more concurrent streams than the server allows, a gRPC message over the common
    4 MiB receive default, a preface the server never answered, and a TCP reset with RPCs
    still open.

gNMI and gNOI
    The gNMI RPCs by name (Capabilities, Get, Set, Subscribe and its mode) and the gNOI
    services; requests and responses decoded by analyzers/gnmi_decode.py (paths, encodings,
    modes, counts, in-band errors, the target's clock from gNOI system.Time), the requested
    encoding checked against the Capabilities answer on the same connection, and, when .proto
    files are given (proto_paths or SONIC_PROTO_PATH), Wireshark's protobuf dissector names
    each message type and its enum fields.

Credentials in metadata
    username, password, authorization, x-api-key and similar keys, read from the HPACK
    decoded headers (a byte search cannot find them: HPACK Huffman-codes values). Each key
    is one finding per flow, with the frames it was seen in. Values are never shown: they
    are masked in the extractor before the analyzer sees them, and any echo of one (for
    example in a grpc-message) is scrubbed from the report by value.

TLS without keys
    SNI, ALPN, version, the certificate's subject, issuer, validity, DNS and IP SANs (TLS 1.2
    and older; TLS 1.3 encrypts it), alerts with who sent them and what they mean (a client
    alert unknown_ca or bad_certificate: the client refused the server's certificate), and a
    hint when the client connected by IP and the certificate has no IP SAN. With a key log
    (SSLKEYLOGFILE format, keylog_file) the TLS sessions are decrypted and every RPC check
    above runs on them; the key log is passed to tshark by path and never read or copied.

Author: Raymond A Rizzo | Zombat
"""

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from analyzers.gnmi_decode import decode_request, decode_response
from analyzers.network_common import (
    Context, add_frame, cap, iso_time, make_event, make_issue, sort_issues, status_from_issues,
)
from utils.grpc_protos import DEFAULT_PROTO_DIR
from extractors.http2 import (
    GRPC_PORTS, MIN_SCRUB_LENGTH, decrypted_certificates, discover, iter_http2_packets, plan_decode_as,
    tshark_available, tshark_version,
)

REPORT_SCHEMA = "sonic.grpc_report/1"
PROTO_PATH_VARIABLE = "SONIC_PROTO_PATH"

GRPC_STATUS = {0: "OK", 1: "CANCELLED", 2: "UNKNOWN", 3: "INVALID_ARGUMENT", 4: "DEADLINE_EXCEEDED",
               5: "NOT_FOUND", 6: "ALREADY_EXISTS", 7: "PERMISSION_DENIED", 8: "RESOURCE_EXHAUSTED",
               9: "FAILED_PRECONDITION", 10: "ABORTED", 11: "OUT_OF_RANGE", 12: "UNIMPLEMENTED",
               13: "INTERNAL", 14: "UNAVAILABLE", 15: "DATA_LOSS", 16: "UNAUTHENTICATED"}
GRPC_STATUS_HINTS = {
    1: "the client cancelled the RPC (its own deadline, or the caller gave up)",
    2: "the server failed with an error it did not classify; read grpc-message",
    3: "the server refused the request as malformed for this target: check the path, the encoding and the values",
    4: "the RPC ran past its deadline (grpc-timeout): the target was slow or the deadline is too short",
    5: "the target has no such path or object",
    6: "the object already exists",
    7: "the credentials were accepted but this user may not call this RPC or touch this path: check the role "
       "or AAA authorization on the target",
    8: "a limit was hit: a message over the receiver's maximum size (4 MiB by default), too many streams, or "
       "rate limiting",
    9: "the target is not in a state that allows this request (a precondition failed)",
    10: "the operation was aborted, typically a conflict with a concurrent change; retry",
    11: "a value was out of range",
    12: "the server does not implement this RPC, or an option it asked for (for gNMI often an encoding)",
    13: "the server hit an internal error; read grpc-message and the target's logs",
    14: "the server is unavailable or shutting down (transient): retry with backoff",
    15: "unrecoverable data loss on the server",
    16: "the server rejected the credentials: check the username and password metadata (gNMI sends them as "
        "'username' and 'password'), a token, or the client certificate",
}
H2_ERRORS = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
             4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL",
             9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY",
             13: "HTTP_1_1_REQUIRED"}
H2_ERROR_HINTS = {
    0: "closed without an error",
    1: "a protocol violation: one side sent something HTTP/2 does not allow",
    2: "the sender hit an internal error",
    3: "a peer sent more data than the flow-control window allowed",
    4: "SETTINGS were not acknowledged in time",
    5: "a frame arrived on a stream that was already closed",
    6: "a frame was larger than the receiver's SETTINGS_MAX_FRAME_SIZE",
    7: "the server refused the stream before processing it (too many concurrent streams, or shutting down): safe to "
       "retry; gRPC reports it as UNAVAILABLE",
    8: "the stream was cancelled: from the client usually a deadline or a cancelled call (gRPC CANCELLED or "
       "DEADLINE_EXCEEDED), from the server an aborted handler",
    9: "the HPACK header compression state broke",
    11: "the peer is generating excessive load (for gRPC usually too many keepalive pings)",
    12: "the TLS parameters are below what HTTP/2 requires",
    13: "the server wants HTTP/1.1, which gRPC cannot use",
}
HTTP_TO_GRPC = {400: 13, 401: 16, 403: 7, 404: 12, 429: 14, 502: 14, 503: 14, 504: 14}

DEFAULT_WINDOW = 65535
DEFAULT_MAX_FRAME = 16384
GRPC_DEFAULT_MAX_RECV = 4 * 1024 * 1024
STALL_WARN_S = 0.2
MAX_MESSAGES_DECODED = 50
MAX_DECODE_BYTES = 65536  # bytes of one message kept for decoding

SERVICE_FAMILIES = [("gnmi.", "gNMI"), ("gnoi.", "gNOI"), ("gribi.", "gRIBI"), ("p4.v1.", "P4Runtime"),
                    ("gnsi.", "gNSI"), ("grpc.health.", "gRPC health"), ("grpc.reflection.", "gRPC reflection")]
STATE_CHANGING = {
    "gnmi.gNMI/Set", "gnoi.system.System/Reboot", "gnoi.system.System/SetPackage",
    "gnoi.system.System/SwitchControlProcessor", "gnoi.system.System/KillProcess",
    "gnoi.factory_reset.FactoryReset/Start", "gnoi.os.OS/Install", "gnoi.os.OS/Activate", "gnoi.file.File/Put",
    "gnoi.file.File/Remove", "gnoi.certificate.CertificateManagement/Install",
    "gnoi.certificate.CertificateManagement/Rotate", "gnoi.certificate.CertificateManagement/RevokeCertificates",
    "gnoi.containerz.Containerz/Deploy",
    "gnoi.containerz.Containerz/RemoveContainer", "gribi.gRIBI/Modify",
}

# Header names gRPC reserves for itself: everything else a client sends is metadata.
RESERVED_HEADERS = {"content-type", "te", "user-agent", "grpc-timeout", "grpc-encoding", "grpc-accept-encoding",
                    "accept-encoding", "content-length", "grpc-message-type"}

LIMITS = [
    "Wireshark needs the start of each HTTP/2 connection: HPACK headers are compressed against a table both "
    "sides build from the first request on, so a capture that begins mid-connection may show headers as "
    "undecodable and RPCs without a method.",
    "Without a key log, TLS-wrapped gRPC shows only the handshake: no method, status or metadata. In TLS 1.3 "
    "the certificate is encrypted too.",
    "Plaintext HTTP/2 is found by its preface on any port and assumed on the well-known gRPC ports; HTTP/2 that "
    "upgraded from HTTP/1.1 (Upgrade: h2c) on another port is not decoded.",
    "Flow control is followed only when the connection's start was captured (the initial windows are in it).",
    "A gRPC message over 4 MiB is flagged against the common default receive limit; the receiver's real limit "
    "is configuration and is not on the wire.",
    "Message contents are decoded only for gNMI and gNOI system.Time (paths, encodings, modes, counts); values "
    "are never decoded. Other services show sizes and counts, or Wireshark's protobuf view with .proto files.",
]


def _endpoint(end: Optional[Tuple[str, int]]) -> Optional[str]:
    if not end:
        return None
    addr, port = end
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def service_family(method: Optional[str]) -> Optional[str]:
    if not method:
        return None
    service = method.strip("/").split("/", 1)[0]
    for prefix, family in SERVICE_FAMILIES:
        if service.startswith(prefix):
            return family
    return "gRPC"


def parse_timeout(value: Optional[str]) -> Optional[float]:
    """grpc-timeout ("14999982u", "5S", "100m") to seconds."""
    if not value:
        return None
    match = re.fullmatch(r"(\d{1,8})([HMSmun])", value.strip())
    if not match:
        return None
    scale = {"H": 3600.0, "M": 60.0, "S": 1.0, "m": 1e-3, "u": 1e-6, "n": 1e-9}[match.group(2)]
    return round(int(match.group(1)) * scale, 6)


def resolve_proto_paths(proto_paths: Optional[List[str]]) -> List[str]:
    """The .proto search paths: the argument, else SONIC_PROTO_PATH (os.pathsep separated), else the default dir."""
    if proto_paths:
        return [p for p in proto_paths if p]
    env = os.environ.get(PROTO_PATH_VARIABLE)
    if env:
        return [p for p in env.split(os.pathsep) if p]
    if os.path.isdir(DEFAULT_PROTO_DIR):
        return [DEFAULT_PROTO_DIR]
    return []


class _Framer:
    """gRPC length-prefixed messages (1 flag byte, 4 length bytes, the message) from one direction's DATA."""

    def __init__(self):
        self.buf = bytearray()
        self.skip = 0
        self.lost = False
        self.messages: List[Dict[str, Any]] = []
        self.count = 0
        self.total = 0
        self.max = 0
        self.compressed = 0

    def feed(self, data: bytes, length: int, frame: int, t: float):
        """data: the bytes kept of this DATA frame (its head); length: the frame's real data length."""
        if self.lost:
            return
        pos = 0
        while pos < len(data):
            if self.skip:
                take = min(self.skip, len(data) - pos)
                msg = self.messages[-1] if self.messages else None
                if msg is not None and msg.get("partial") is not None and msg.get("open"):
                    room = MAX_DECODE_BYTES - len(msg["partial"])
                    if room > 0:
                        msg["partial"] += data[pos:pos + min(take, room)]
                self.skip -= take
                pos += take
                if not self.skip and msg is not None and msg.get("open"):
                    msg["open"] = False
                    msg["end_frame"], msg["end_t"] = frame, t
                continue
            need = 5 - len(self.buf)
            self.buf += data[pos:pos + need]
            pos += min(need, len(data) - pos)
            if len(self.buf) < 5:
                break
            flag, size = self.buf[0], int.from_bytes(self.buf[1:5], "big")
            self.buf = bytearray()
            if flag not in (0, 1):
                self.lost = True
                return
            self.count += 1
            self.total += size
            self.max = max(self.max, size)
            self.compressed += flag
            if len(self.messages) < MAX_MESSAGES_DECODED:
                entry = {"size": size, "compressed": bool(flag), "frame": frame, "t": t, "open": size > 0,
                         "partial": bytearray() if not flag else None}
                if size == 0:
                    entry["end_frame"], entry["end_t"] = frame, t
                self.messages.append(entry)
            elif self.messages:
                self.messages[-1]["open"] = False  # past the decode cap only counts and sizes are kept
            self.skip = size
        hidden = length - len(data)  # bytes the extractor did not keep (a very large DATA frame)
        if hidden > 0:
            if self.skip >= hidden and not self.buf:
                self.skip -= hidden
            else:
                self.lost = True

    def summary(self) -> Dict[str, Any]:
        return {"messages": self.count, "bytes": self.total, "largest": self.max if self.count else None,
                "compressed": self.compressed, "framing_lost": self.lost}



class _Rpc:
    def __init__(self, conn, stream_id: int, frame: int, t: float):
        self.conn = conn
        self.stream_id = stream_id
        self.frames = {"request": frame}
        self.t_request = t
        self.request_headers: List[Dict[str, Any]] = []
        self.response_headers: List[Dict[str, Any]] = []
        self.trailers: List[Dict[str, Any]] = []
        self.t_first_response: Optional[float] = None
        self.t_end: Optional[float] = None
        self.client_ended = False
        self.server_ended = False
        self.reset: Optional[Dict[str, Any]] = None
        self.server_ended_before_reset = False
        self.framers = {"client": _Framer(), "server": _Framer()}
        self.header_blocks = {"client": 0, "server": 0}
        self.decode_failed = False
        self.protobuf: List[Dict[str, Any]] = []

    def header(self, name: str, block: str = "request") -> Optional[str]:
        source = {"request": self.request_headers, "response": self.response_headers,
                  "trailers": self.trailers}[block]
        for h in source:
            if h["name"].lower() == name:
                return h["value"]
        return None

    @property
    def method(self) -> Optional[str]:
        return self.header(":path")

    def is_open(self) -> bool:
        return self.reset is None and not (self.client_ended and self.server_ended)


class _Conn:
    def __init__(self, index: int, disc):
        self.index = index
        self.disc = disc
        self.client = disc.client if disc else None
        self.server = disc.server if disc else None
        self.server_known_by = disc.server_known_by if disc else None
        if disc and self.server is None:
            # No SYN, preface or ClientHello captured: the side on the service port is the server.
            self.server_known_by = "port"
            port = disc.service_port()
            self.server = disc.a if disc.a[1] == port else disc.b
            self.client = disc.b if self.server == disc.a else disc.a
        self.first_frame: Optional[int] = None
        self.first_t: Optional[float] = None
        self.last_t: Optional[float] = None
        self.tls_seen = False
        self.magic_frame: Optional[int] = None
        self.packets = {"client": 0, "server": 0}
        self.frames_by_type: Dict[str, int] = {}
        self.settings: Dict[str, Dict[str, Any]] = {"client": {}, "server": {}}
        self.settings_frames: Dict[str, Optional[int]] = {"client": None, "server": None}
        self.rpcs: Dict[int, _Rpc] = {}
        self.rst_streams: List[Dict[str, Any]] = []
        self.goaways: List[Dict[str, Any]] = []
        self.pings: Dict[str, Dict[str, Any]] = {side: {"sent": 0, "acked": 0, "rtt_ms": [], "idle": 0,
                                                         "first_frame": None, "times": []}
                                                  for side in ("client", "server")}
        self.pending_pings: Dict[Tuple[str, str], float] = {}
        self.conn_window = {"client": DEFAULT_WINDOW, "server": DEFAULT_WINDOW}
        self.stream_window: Dict[Tuple[str, int], int] = {}
        self.stalls: List[Dict[str, Any]] = []
        self.open_stall: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.track_flow = False
        self.oversize_frames: List[Dict[str, Any]] = []
        self.oversize_headers: List[Dict[str, Any]] = []
        self.max_open = 0
        self.max_open_frame: Optional[int] = None
        self.credentials: Dict[str, Dict[str, Any]] = {}
        self.metadata_keys: Dict[str, int] = {}
        self.hpack_failures: List[int] = []
        self.capabilities: Optional[Dict[str, Any]] = None
        self.events: List[Dict[str, Any]] = []

    def side_of(self, src: str, sport: int) -> str:
        if self.server and (src, sport) == self.server:
            return "server"
        if self.client and (src, sport) == self.client:
            return "client"
        return "unknown"

    def peer(self, side: str) -> str:
        return "server" if side == "client" else "client"

    def receiver_setting(self, sender: str, name: str, default):
        value = self.settings[self.peer(sender)].get(name)
        return default if value is None else value


class GrpcAnalysis:
    """Feeds the HTTP/2 packets into per-connection state and builds the report."""

    def __init__(self, conns_disc: Dict[int, Any]):
        self.disc = conns_disc
        self.conns: Dict[int, _Conn] = {}
        self.packets = 0
        self.start: Optional[float] = None
        self.end: Optional[float] = None

    # -- feeding -----------------------------------------------------------------

    def conn_for(self, packet) -> _Conn:
        index = packet["tcp_stream"]
        conn = self.conns.get(index)
        if conn is None:
            conn = _Conn(index, self.disc.get(index))
            self.conns[index] = conn
        return conn

    def feed(self, packet: Dict[str, Any]):
        self.packets += 1
        t, n = packet["t"], packet["n"]
        self.start = t if self.start is None else min(self.start, t)
        self.end = t if self.end is None else max(self.end, t)
        conn = self.conn_for(packet)
        if conn.first_frame is None:
            conn.first_frame, conn.first_t = n, t
        conn.last_t = t
        conn.tls_seen = conn.tls_seen or packet["tls"]
        src, sport = packet["src"], packet["sport"]
        side = conn.side_of(src, sport)
        if side == "unknown":
            side = self._infer_side(conn, packet)
        conn.packets[side] = conn.packets.get(side, 0) + 1
        for frame in packet["frames"]:
            conn.frames_by_type[frame["type"]] = conn.frames_by_type.get(frame["type"], 0) + 1
            handler = getattr(self, "_on_" + frame["type"].lower(), None)
            if frame["type"] == "MAGIC":
                conn.magic_frame = conn.magic_frame or n
                conn.track_flow = True
                continue
            max_frame = conn.receiver_setting(side, "max_frame_size", DEFAULT_MAX_FRAME)
            if frame.get("length", 0) > max_frame and len(conn.oversize_frames) < 10:
                conn.oversize_frames.append({"from": side, "type": frame["type"], "length": frame["length"],
                                             "peer_max_frame_size": max_frame, "frame": n,
                                             "stream_id": frame.get("stream_id")})
            if handler:
                handler(conn, side, frame, n, t)
        for proto in packet["protobuf"]:
            self._on_protobuf(conn, proto, n)

    def _infer_side(self, conn: _Conn, packet) -> str:
        """With no SYN or preface seen: the sender of request headers (:method) is the client."""
        for frame in packet["frames"]:
            if frame["type"] == "MAGIC" or any(h["name"] in (":method", ":path") for h in frame.get("headers", [])):
                conn.client = (packet["src"], packet["sport"])
                conn.server = (packet["dst"], packet["dport"])
                return "client"
            if any(h["name"] == ":status" for h in frame.get("headers", [])):
                conn.server = (packet["src"], packet["sport"])
                conn.client = (packet["dst"], packet["dport"])
                return "server"
        return "unknown"

    def _on_settings(self, conn: _Conn, side, frame, n, t):
        if frame.get("ack") or side == "unknown":
            return
        new = frame.get("settings", {})
        old_initial = conn.settings[side].get("initial_window_size", DEFAULT_WINDOW)
        conn.settings[side].update(new)
        conn.settings_frames[side] = conn.settings_frames[side] or n
        if "initial_window_size" in new:
            delta = new["initial_window_size"] - old_initial
            sender = conn.peer(side)  # the other side's stream windows follow this side's setting
            for key in list(conn.stream_window):
                if key[0] == sender:
                    conn.stream_window[key] += delta

    def _rpc(self, conn: _Conn, sid: int, n: int, t: float, create: bool) -> Optional[_Rpc]:
        rpc = conn.rpcs.get(sid)
        if rpc is None and create:
            rpc = _Rpc(conn, sid, n, t)
            conn.rpcs[sid] = rpc
            for sender in ("client", "server"):
                initial = conn.receiver_setting(sender, "initial_window_size", DEFAULT_WINDOW)
                conn.stream_window[(sender, sid)] = initial
            open_now = sum(1 for r in conn.rpcs.values() if r.is_open())
            if open_now > conn.max_open:
                conn.max_open, conn.max_open_frame = open_now, n
        return rpc

    def _on_headers(self, conn: _Conn, side, frame, n, t):
        sid = frame.get("stream_id", 0)
        headers = frame.get("headers", [])
        if frame.get("decode_failed"):
            conn.hpack_failures.append(n)
        is_request = side == "client" or any(h["name"] == ":method" for h in headers)
        rpc = self._rpc(conn, sid, n, t, create=is_request)
        if rpc is None:
            rpc = self._rpc(conn, sid, n, t, create=True)
            rpc.frames.pop("request", None)
            rpc.t_request = None
        if frame.get("decode_failed"):
            rpc.decode_failed = True
        limit = conn.receiver_setting(side, "max_header_list_size", None)
        if limit is not None and frame.get("header_list_size", 0) > limit and len(conn.oversize_headers) < 10:
            conn.oversize_headers.append({"from": side, "stream_id": sid, "frame": n,
                                          "header_list_size": frame["header_list_size"], "peer_limit": limit})
        if side == "client":
            rpc.header_blocks["client"] += 1
            if rpc.header_blocks["client"] == 1:
                rpc.request_headers = headers
                rpc.frames["request"] = n
                rpc.t_request = t if rpc.t_request is None else rpc.t_request
                for h in headers:
                    if not h["name"].startswith(":") and h["name"].lower() not in RESERVED_HEADERS:
                        conn.metadata_keys[h["name"].lower()] = conn.metadata_keys.get(h["name"].lower(), 0) + 1
                    if h.get("credential"):
                        entry = conn.credentials.setdefault(h["name"].lower(), {"requests": 0, "frames": [],
                                                                               "first_frame": n, "first_t": t})
                        entry["requests"] += 1
                        add_frame(entry["frames"], n)
            else:
                rpc.trailers = rpc.trailers or headers  # client trailers are unusual; kept for completeness
            if frame.get("end_stream"):
                rpc.client_ended = True
        else:
            rpc.header_blocks["server"] += 1
            if rpc.t_first_response is None:
                rpc.t_first_response = t
                rpc.frames["first_response"] = n
            if rpc.header_blocks["server"] == 1 and not frame.get("end_stream"):
                rpc.response_headers = headers
            elif rpc.header_blocks["server"] == 1:
                rpc.response_headers = [h for h in headers if h["name"] in (":status", "content-type")]
                rpc.trailers = headers  # trailers-only response
                rpc.frames["trailers"] = n
            else:
                rpc.trailers = headers
                rpc.frames["trailers"] = n
            if frame.get("end_stream"):
                rpc.server_ended = True
                rpc.t_end = t
                self._close_stalls(conn, rpc.stream_id, t, n, "the stream ended")

    def _on_data(self, conn: _Conn, side, frame, n, t):
        sid = frame.get("stream_id", 0)
        rpc = self._rpc(conn, sid, n, t, create=False)
        if rpc is not None and side in ("client", "server"):
            rpc.framers[side].feed(frame.get("data", b""), frame.get("data_len", 0), n, t)
            if side == "server" and rpc.t_first_response is None:
                rpc.t_first_response = t
                rpc.frames["first_response"] = n
            if frame.get("end_stream"):
                if side == "client":
                    rpc.client_ended = True
                else:
                    rpc.server_ended = True
                    rpc.t_end = t
        if not conn.track_flow or side not in ("client", "server"):
            return
        length = frame.get("length", 0)
        conn.conn_window[side] -= length
        key = (side, sid)
        if key in conn.stream_window:
            conn.stream_window[key] -= length
        stall_key = (side, sid)
        open_stall = conn.open_stall.get(stall_key)
        if open_stall is not None and open_stall.get("reopened_t") is not None:
            open_stall["data_waiting"] = True
            del conn.open_stall[stall_key]
        if frame.get("end_stream"):
            return
        exhausted = None
        if conn.conn_window[side] <= 0:
            exhausted = "connection"
        elif conn.stream_window.get(key, 1) <= 0:
            exhausted = "stream"
        if exhausted and stall_key not in conn.open_stall:
            stall = {"sender": side, "stream_id": sid, "window": exhausted, "frame": n, "t": t,
                     "reopened_t": None, "reopened_frame": None, "data_waiting": False,
                     "method": rpc.method if rpc else None}
            conn.open_stall[stall_key] = stall
            conn.stalls.append(stall)

    def _on_window_update(self, conn: _Conn, side, frame, n, t):
        if not conn.track_flow or side not in ("client", "server"):
            return
        sender = conn.peer(side)
        sid, inc = frame.get("stream_id", 0), frame.get("increment", 0)
        if sid == 0:
            conn.conn_window[sender] += inc
        elif (sender, sid) in conn.stream_window:
            conn.stream_window[(sender, sid)] += inc
        for key, stall in list(conn.open_stall.items()):
            if key[0] != sender or stall["reopened_t"] is not None:
                continue
            if conn.conn_window[sender] > 0 and conn.stream_window.get(key, 1) > 0:
                stall["reopened_t"], stall["reopened_frame"] = t, n

    def _close_stalls(self, conn: _Conn, sid: int, t: float, n: int, why: str):
        for key in [k for k in conn.open_stall if k[1] == sid]:
            stall = conn.open_stall.pop(key)
            if stall["reopened_t"] is None:
                stall["ended_by"] = why
                stall["ended_t"] = t

    def _on_rst_stream(self, conn: _Conn, side, frame, n, t):
        sid = frame.get("stream_id", 0)
        code = frame.get("error_code")
        rpc = self._rpc(conn, sid, n, t, create=False)
        entry = {"from": side, "stream_id": sid, "error_code": code, "error": H2_ERRORS.get(code, f"code {code}"),
                 "frame": n, "t": t, "method": rpc.method if rpc else None}
        conn.rst_streams.append(entry)
        if rpc is not None and rpc.reset is None:
            rpc.reset = entry
            rpc.server_ended_before_reset = rpc.server_ended
            entry["after_end"] = rpc.server_ended
            rpc.t_end = rpc.t_end or t
        self._close_stalls(conn, sid, t, n, "the stream was reset")

    def _on_goaway(self, conn: _Conn, side, frame, n, t):
        code = frame.get("error_code")
        conn.goaways.append({"from": side, "last_stream_id": frame.get("last_stream_id"), "error_code": code,
                             "error": H2_ERRORS.get(code, f"code {code}"), "debug_data": frame.get("debug_data"),
                             "frame": n, "t": t})

    def _on_ping(self, conn: _Conn, side, frame, n, t):
        if side not in ("client", "server"):
            return
        opaque = frame.get("opaque", "")
        if frame.get("ack"):
            sent = conn.pending_pings.pop((conn.peer(side), opaque), None)
            if sent is not None:
                stats = conn.pings[conn.peer(side)]
                stats["acked"] += 1
                if len(stats["rtt_ms"]) < 1000:
                    stats["rtt_ms"].append(round((t - sent) * 1000, 3))
            return
        stats = conn.pings[side]
        stats["sent"] += 1
        stats["first_frame"] = stats["first_frame"] or n
        if len(stats["times"]) < 1000:
            stats["times"].append(t)
        if not any(r.is_open() for r in conn.rpcs.values()):
            stats["idle"] += 1
        conn.pending_pings[(side, opaque)] = t

    def _on_protobuf(self, conn: _Conn, proto: Dict[str, Any], n: int):
        """Attach Wireshark's protobuf view to the RPC on this connection with that method."""
        if not proto.get("path"):
            return
        candidates = [r for r in conn.rpcs.values() if r.method == proto["path"]]
        if not candidates:
            return
        rpc = min(candidates, key=lambda r: abs((r.frames.get("request") or 0) - n))
        if len(rpc.protobuf) < 20:
            rpc.protobuf.append({"frame": n, "direction": proto["direction"], "message_type": proto["message_type"],
                                 "fields": proto["fields"]})

    # -- report ----------------------------------------------------------------------

    def rpc_report(self, conn: _Conn, rpc: _Rpc, ctx: Context) -> Dict[str, Any]:
        method = rpc.method
        service, name = None, None
        if method and method.count("/") >= 2:
            service, name = method.strip("/").split("/", 1)
        http_status = rpc.header(":status", "response") or rpc.header(":status", "trailers")
        grpc_status_raw = rpc.header("grpc-status", "trailers")
        grpc_status = int(grpc_status_raw) if grpc_status_raw and grpc_status_raw.isdigit() else None
        mapped = False
        if grpc_status is None and http_status and http_status.isdigit() and int(http_status) != 200:
            grpc_status = HTTP_TO_GRPC.get(int(http_status), 2)
            mapped = True
        timeout = parse_timeout(rpc.header("grpc-timeout"))
        req, resp = rpc.framers["client"].summary(), rpc.framers["server"].summary()
        timing = {}
        if rpc.t_request is not None and rpc.t_first_response is not None:
            timing["to_first_response_ms"] = round((rpc.t_first_response - rpc.t_request) * 1000, 3)
        if rpc.t_request is not None and rpc.t_end is not None:
            timing["to_end_ms"] = round((rpc.t_end - rpc.t_request) * 1000, 3)
        reset_after_end = bool(rpc.reset) and grpc_status is not None and rpc.server_ended_before_reset
        if rpc.reset and not reset_after_end:
            outcome = "reset"
        elif grpc_status is None:
            outcome = "incomplete"
        else:
            outcome = "ok" if grpc_status == 0 else "error"
        out: Dict[str, Any] = {
            "flow": f"{_endpoint(conn.client)} -> {_endpoint(conn.server)}",
            "stream_id": rpc.stream_id,
            "method": method,
            "family": service_family(method),
            "service": service,
            "rpc": name,
            "authority": rpc.header(":authority"),
            "content_type": rpc.header("content-type"),
            "user_agent": rpc.header("user-agent"),
            "grpc_timeout_s": timeout,
            "grpc_encoding": rpc.header("grpc-encoding"),
            "metadata_keys": sorted({h["name"].lower() for h in rpc.request_headers
                                     if not h["name"].startswith(":") and h["name"].lower() not in RESERVED_HEADERS}),
            "request": req,
            "response": resp,
            "http_status": int(http_status) if http_status and http_status.isdigit() else None,
            "grpc_status": grpc_status,
            "grpc_status_name": GRPC_STATUS.get(grpc_status, f"code {grpc_status}") if grpc_status is not None else None,
            "grpc_status_from_http": mapped,
            "grpc_message": rpc.header("grpc-message", "trailers"),
            "trailers_only": bool(rpc.trailers) and rpc.header_blocks["server"] == 1 and not resp["messages"],
            "outcome": outcome,
            "reset": {k: v for k, v in rpc.reset.items() if k != "t"} if rpc.reset else None,
            "reset_after_end": reset_after_end,
            "timing": timing,
            "t": ctx.rel(rpc.t_request),
            "frames": dict(rpc.frames),
            "state_changing": bool(method and method.strip("/") in STATE_CHANGING),
        }
        decoded = self._decode(rpc, method)
        if decoded:
            out["decoded"] = decoded
        if rpc.protobuf:
            out["wireshark_protobuf"] = rpc.protobuf
        if rpc.decode_failed:
            out["headers_decoded"] = False
        out["diagnosis"] = self._diagnose(conn, rpc, out, timeout)
        return out

    def _decode(self, rpc: _Rpc, method: Optional[str]) -> Dict[str, Any]:
        family = service_family(method)
        if family not in ("gNMI", "gNOI", "gRPC health"):
            return {}
        out: Dict[str, Any] = {}
        errors = []
        requests = []
        for msg in rpc.framers["client"].messages:
            data = msg.get("partial")
            if data is None or len(data) < msg["size"]:
                continue
            try:
                requests.append(decode_request(method, bytes(data)))
            except ValueError as exc:
                errors.append(f"request at frame {msg['frame']}: {exc}")
        responses = []
        for msg in rpc.framers["server"].messages:
            data = msg.get("partial")
            if data is None or len(data) < msg["size"]:
                continue
            try:
                responses.append(decode_response(method, bytes(data), msg.get("t")))
            except ValueError as exc:
                errors.append(f"response at frame {msg['frame']}: {exc}")
        name = method.rsplit("/", 1)[-1]
        if requests and any(requests):
            subs = [r for r in requests if r and not r.get("poll")]
            out["request"] = subs[0] if subs else requests[0]
            polls = sum(1 for r in requests if r.get("poll"))
            if polls:
                out["polls"] = polls
        if responses and family == "gNMI" and name == "Subscribe":
            notes = [r for r in responses if r.get("notification")]
            out["response"] = {"messages": len(responses), "notifications": len(notes),
                               "updates": sum(r.get("updates", 0) for r in notes),
                               "deletes": sum(r.get("deletes", 0) for r in notes),
                               "sync_response": any(r.get("sync_response") for r in responses)}
            errs = [r["error"] for r in responses if r.get("error")]
            if errs:
                out["response"]["errors"] = errs[:5]
        elif responses and any(responses):
            out["response"] = responses[0]
        if rpc.framers["server"].count > len(responses):
            out["responses_not_decoded"] = rpc.framers["server"].count - len(responses)
        if errors:
            out["decode_errors"] = errors[:5]
        if family == "gNMI" and name == "Capabilities" and out.get("response"):
            rpc.conn.capabilities = out["response"]
        return out

    def _diagnose(self, conn: _Conn, rpc: _Rpc, out: Dict[str, Any], timeout: Optional[float]) -> str:
        text = self._diagnose_status(conn, rpc, out, timeout)
        if out.get("headers_decoded") is False and out["method"]:
            text += ("; some headers could not be decoded (HPACK state missing: the capture started after the "
                     "connection opened), so metadata and status may be incomplete")
        return text

    def _diagnose_status(self, conn: _Conn, rpc: _Rpc, out: Dict[str, Any], timeout: Optional[float]) -> str:
        method = out["method"] or f"stream {rpc.stream_id}"
        family = out["family"]
        status, name = out["grpc_status"], out["grpc_status_name"]
        decoded = out.get("decoded", {})
        request = decoded.get("request", {})
        response = decoded.get("response", {})
        if out.get("headers_decoded") is False and not out["method"]:
            return ("headers could not be decoded (HPACK state missing: the capture probably started after the "
                    "connection opened), so the method and status are unknown")
        if out["content_type"] and not out["content_type"].startswith("application/grpc"):
            return f"HTTP/2 request with content-type {out['content_type']}: not gRPC"
        if rpc.reset and not out["reset_after_end"]:
            code = rpc.reset["error_code"]
            hint = H2_ERROR_HINTS.get(code, "")
            text = f"{method}: stream reset by the {rpc.reset['from']} with {rpc.reset['error']} ({hint})"
            if timeout is not None and out["timing"].get("to_end_ms") is not None and \
                    out["timing"]["to_end_ms"] / 1000 >= timeout * 0.95 and rpc.reset["from"] == "client":
                text += f"; the reset came at the deadline ({timeout} s): the client gave up waiting"
            if family == "gNMI" and rpc.method and rpc.method.endswith("/Set"):
                text += ("; whether the target applied the Set is unknown (it may have committed before the cancel): "
                         "read the paths back with Get")
            return text
        if status is None:
            if rpc.t_first_response is None:
                return f"{method}: no response from the server before the capture ended"
            if self._long_lived(rpc, request):
                return (f"{method}: a long-lived stream ({request.get('mode') or 'streaming'}) still open when the "
                        f"capture ended, {out['response']['messages']} response message(s) so far (normal)")
            return f"{method}: no trailers (grpc-status) before the capture ended; the RPC was still open"
        prefix = f"{method}: {name}"
        if out["grpc_message"]:
            prefix += f" ({out['grpc_message']})"
        if out["grpc_status_from_http"]:
            prefix += f", mapped from HTTP {out['http_status']} (a proxy or a non-gRPC server answered)"
        if status == 0:
            if family == "gNMI" and rpc.method.endswith("/Get") and response:
                if response.get("notifications", 0) and not response.get("updates"):
                    return (f"{prefix}: answered with {response['notifications']} notification(s) and no updates: the "
                            "path exists but holds nothing, or the target returns an empty notification for an "
                            "absent path (measured on SR Linux)")
                return f"{prefix}: {response.get('notifications', 0)} notification(s), {response.get('updates', 0)} update(s)"
            if family == "gNMI" and rpc.method.endswith("/Subscribe") and response:
                errs = response.get("errors")
                if errs:
                    first = errs[0]
                    return (f"{prefix}, but the target answered in-band with an error (code {first['code']}: "
                            f"{first['message']}) in the deprecated SubscribeResponse.error field: the subscription "
                            "did not deliver data")
                mode = request.get("mode")
                sync = "with" if response.get("sync_response") else "without"
                return (f"{prefix}: {request.get('mode', '?')} subscription, {response.get('notifications', 0)} "
                        f"notification(s), {sync} sync_response" + ("" if mode != "ONCE" or response.get("sync_response")
                                                                   else "; a ONCE subscription should end with "
                                                                        "sync_response"))
            if family == "gNMI" and rpc.method.endswith("/Capabilities") and response:
                return (f"{prefix}: gNMI {response.get('gnmi_version')}, encodings "
                        f"{', '.join(response.get('supported_encodings') or []) or 'none listed'}, "
                        f"{response.get('models', 0)} model(s)")
            if response.get("serving_status"):
                serving = response["serving_status"]
                return f"{prefix}: the service reports {serving}" + (
                    "" if serving == "SERVING" else ": the server is up but says it cannot serve")
            if decoded.get("response", {}).get("skew_s") is not None:
                skew = decoded["response"]["skew_s"]
                if abs(skew) < 0.001:
                    return f"{prefix}: the target's clock matches the capture's clock"
                return (f"{prefix}: the target's clock is {abs(skew)} s {'ahead of' if skew > 0 else 'behind'} the "
                        "capture's clock" + (" (check NTP on the target)" if abs(skew) > 1 else ""))
            return f"{prefix}: succeeded"
        hint = GRPC_STATUS_HINTS.get(status, "")
        text = f"{prefix}: {hint}" if hint else prefix
        enc = request.get("encoding")
        caps = conn.capabilities
        if family == "gNMI" and enc and status in (3, 12):
            if caps and caps.get("supported_encodings") and enc not in caps["supported_encodings"]:
                text += (f". The request asked for encoding {enc}"
                         + (" (the field was absent, which means JSON)" if not request.get("encoding_field_present")
                            else "")
                         + f"; Capabilities on this connection lists only {', '.join(caps['supported_encodings'])}")
            elif enc:
                text += f". The request asked for encoding {enc}" + (
                    " (absent field: the proto3 default JSON)" if not request.get("encoding_field_present") else "")
        if status == 4 and timeout is not None:
            text += f" (deadline {timeout} s)"
        if status == 8 and max(out["request"]["largest"] or 0, out["response"]["largest"] or 0) > GRPC_DEFAULT_MAX_RECV:
            text += (f"; a message of {max(out['request']['largest'] or 0, out['response']['largest'] or 0)} bytes "
                     "exceeds the 4 MiB default: raise the receiver's max receive message size or ask for less "
                     "(a narrower path, or Subscribe instead of Get)")
        if family == "gNMI" and rpc.method.endswith("/Set"):
            text += ". gNMI Set is all or none: none of its operations were applied"
        return text

    @staticmethod
    def _long_lived(rpc: _Rpc, request: Dict[str, Any]) -> bool:
        """A STREAM or POLL subscription (or any server stream with responses) is meant to stay open."""
        if rpc.method and rpc.method.endswith("/gnmi.gNMI/Subscribe") and request.get("mode") in ("STREAM", "POLL"):
            return True
        return False

    def connection_report(self, conn: _Conn, ctx: Context, tls_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        disc = conn.disc
        port = disc.service_port() if disc else (conn.server[1] if conn.server else None)
        methods = [r.method for r in conn.rpcs.values() if r.method]
        is_grpc = any((r.header("content-type") or "").startswith("application/grpc") for r in conn.rpcs.values())
        services = sorted({m.strip("/").split("/", 1)[0] for m in methods if "/" in m.strip("/")})
        if conn.tls_seen:
            transport = "tls (decrypted with the key log)"
        elif disc and disc.is_tls():
            transport = "tls"
        else:
            transport = "cleartext"
        detected = None
        if disc:
            if disc.preface_frame is not None:
                detected = "preface"
            elif disc.is_tls() and "h2" in disc.alpn:
                detected = "alpn h2"
            elif port in GRPC_PORTS:
                detected = "grpc port"
        ping_report = {}
        for side, stats in conn.pings.items():
            if not stats["sent"]:
                continue
            times = stats["times"]
            gaps = [round(b - a, 3) for a, b in zip(times, times[1:])]
            ping_report[side] = {"sent": stats["sent"], "acked": stats["acked"],
                                 "rtt_ms_median": sorted(stats["rtt_ms"])[len(stats["rtt_ms"]) // 2]
                                 if stats["rtt_ms"] else None,
                                 "interval_s_min": min(gaps) if gaps else None,
                                 "interval_s_median": sorted(gaps)[len(gaps) // 2] if gaps else None,
                                 "first_frame": stats["first_frame"]}
        stalls = []
        for stall in conn.stalls:
            reopened = stall["reopened_t"]
            end = reopened if reopened is not None else stall.get("ended_t", self.end)
            stalls.append({"sender": stall["sender"], "stream_id": stall["stream_id"], "method": stall["method"],
                           "window": stall["window"], "frame": stall["frame"], "t": ctx.rel(stall["t"]),
                           "duration_s": round((end or stall["t"]) - stall["t"], 3),
                           "reopened_frame": stall["reopened_frame"],
                           "resolved": reopened is not None, "ended_by": stall.get("ended_by"),
                           "data_waiting": stall["data_waiting"]})
        statuses: Dict[str, int] = {}
        out = {
            "flow": f"{_endpoint(conn.client)} -> {_endpoint(conn.server)}",
            "client": _endpoint(conn.client),
            "server": _endpoint(conn.server),
            "service": f"tcp/{port}" if port else None,
            "service_name": GRPC_PORTS.get(port),
            "server_known_by": conn.server_known_by or "headers",
            "transport": transport,
            "detected_by": detected,
            "protocol": "grpc" if is_grpc else ("http2" if conn.rpcs or conn.frames_by_type else
                                                ("tls, h2 offered" if disc and "h2" in disc.alpn else
                                                 "tls" if disc and disc.is_tls() else "unknown")),
            "services": services,
            "first_frame": conn.first_frame,
            "t": ctx.rel(conn.first_t),
            "duration_s": round(conn.last_t - conn.first_t, 3) if conn.first_t is not None else None,
            "rpcs": len(conn.rpcs),
            "rpc_status": statuses,
            "frames_by_type": dict(sorted(conn.frames_by_type.items())),
            "settings": conn.settings,
            "max_concurrent_streams_used": conn.max_open,
            "pings": ping_report,
            "goaways": [{k: v for k, v in g.items() if k != "t"} for g in conn.goaways],
            "rst_streams": [{k: v for k, v in r.items() if k != "t"} for r in conn.rst_streams],
            "flow_control": {"followed": conn.track_flow, "stalls": stalls},
            "oversize_frames": conn.oversize_frames,
            "oversize_header_lists": conn.oversize_headers,
            "tcp_resets": [{"frame": r["frame"], "from": _endpoint(r["from"])} for r in (disc.resets if disc else [])],
            "credential_keys": sorted(conn.credentials),
            "metadata_keys": sorted(conn.metadata_keys),
        }
        if conn.capabilities:
            out["capabilities"] = conn.capabilities
        if tls_info:
            out["tls"] = tls_info
        return out


def _scrub(value: Any, secrets: List[str]) -> Any:
    """Replace any echo of a masked credential value inside report text."""
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            if secret in value:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value


def _error(message: str, **extra) -> Dict[str, Any]:
    out = {"status": "error", "error": message}
    out.update(extra)
    return out


def _tls_sessions(file_path: str, conns: Dict[int, Any], display_filter: Optional[str],
                  max_packets: Optional[int]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """The TLS detector's sessions for the TLS connections that may carry gRPC, keyed by (client, server)."""
    wanted = [c.index for c in conns.values() if c.is_tls() and ("h2" in c.alpn or c.service_port() in GRPC_PORTS)]
    if not wanted:
        return {}
    from analyzers.network_orchestrator import analyze_network_capture
    flt = "tcp.stream in {" + " ".join(str(i) for i in sorted(wanted)) + "}"
    if display_filter:
        flt = f"({display_filter}) && {flt}"
    report = analyze_network_capture(file_path, detectors=["tls"], display_filter=flt, max_packets=max_packets,
                                     include_sip=False, max_items=500, backend="tshark")
    sessions = {}
    for session in (report.get("tls") or {}).get("sessions", []):
        sessions[(session["client"], session["server"])] = session
    return sessions


def _tls_view(disc, session: Optional[Dict[str, Any]], decrypted: bool, keylog_given: bool,
              decrypted_der: Optional[bytes] = None, capture_time: Optional[float] = None) -> Dict[str, Any]:
    """What a TLS-wrapped gRPC connection shows without (or with) keys."""
    from analyzers.tls_inspect import parse_certificate, session_hints
    view: Dict[str, Any] = {"sni": disc.sni, "alpn_offered": disc.alpn, "decrypted": decrypted}
    hints: List[Dict[str, str]] = []
    if session:
        chose = session.get("server_chose") or {}
        view.update({"version": chose.get("version"), "cipher_suite": chose.get("cipher_suite"),
                     "alpn_chosen": chose.get("alpn"), "certificate": session.get("certificate"),
                     "alerts": session.get("alerts", []), "hello_retry_request": session.get("hello_retry_request")})
        certificate = view["certificate"] or {}
        if decrypted_der and not certificate.get("visible"):
            # TLS 1.3 encrypts the certificate; the key log made it readable.
            body = (len(decrypted_der) + 3).to_bytes(3, "big") + len(decrypted_der).to_bytes(3, "big") + decrypted_der
            certificate = parse_certificate(body, capture_time or 0.0)
            certificate["decrypted_with_key_log"] = True
            view["certificate"] = certificate
            server = disc.server or disc.b
            hints.extend(session_hints({"client_hello": {"sni": disc.sni}, "server": server}, view["version"],
                                       certificate))
        else:
            hints.extend(session.get("hints", []))
        if not chose and session.get("client_offered") and not session.get("alerts"):
            hints.append({"code": "TLS_NO_SERVER_HELLO", "severity": "warning", "text":
                          "ClientHello with no ServerHello: if this is a plaintext (insecure) gRPC port the client "
                          "should not use TLS there; otherwise the server's TLS is not enabled or not answering"})
    if not decrypted:
        if keylog_given:
            hints.append({"code": "GRPC_TLS_NOT_DECRYPTED", "severity": "info", "text":
                          "a key log was given but holds no keys for this session (or the session began before "
                          "the capture): the RPCs stay encrypted"})
        else:
            hints.append({"code": "GRPC_TLS_NOT_DECRYPTED", "severity": "info", "text":
                          "the RPCs are encrypted; have the client write a TLS key log while capturing (gnmic "
                          "--log-tls-secret, SSLKEYLOGFILE for Python and curl, tls.Config.KeyLogWriter in Go) "
                          "and pass the file as keylog_file to decode them"})
    view["hints"] = hints
    return view


def analyze_grpc_capture(file_path: str, keylog_file: Optional[str] = None,
                         proto_paths: Optional[List[str]] = None, ports: Optional[List[int]] = None,
                         display_filter: Optional[str] = None, max_packets: Optional[int] = None,
                         max_items: int = 25, include_tls: bool = True) -> Dict[str, Any]:
    """
    Troubleshoot gRPC (gNMI, gNOI, any service) in one capture with Wireshark's dissectors.

    Args:
        file_path: pcap or pcapng path
        keylog_file: optional TLS key log (SSLKEYLOGFILE format) to decrypt TLS; passed to tshark,
                     never read or copied
        proto_paths: optional directories of .proto files for Wireshark's protobuf dissector
                     (default: SONIC_PROTO_PATH, else ~/.cache/sonic/grpc-protos when it exists)
        ports: extra TCP ports to decode as HTTP/2 (beyond the preface, ALPN and well-known ports)
        display_filter: optional Wireshark display filter applied first
        max_packets: read at most this many frames
        max_items: cap on list lengths
        include_tls: read the TLS handshakes of TLS-wrapped gRPC (one more pass)

    Returns:
        dict: the report (status "success"), or {"status": "error", "error": ...}
    """
    if not file_path or not os.path.exists(file_path):
        return _error(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        return _error(f"File not readable: {file_path}")
    if not tshark_available():
        return _error("gRPC analysis needs tshark (Wireshark's HTTP/2, HPACK and gRPC dissectors); install it")
    if keylog_file:
        if not os.path.isfile(keylog_file) or not os.access(keylog_file, os.R_OK):
            return _error("keylog_file is not a readable file")
    if max_packets is not None and int(max_packets) <= 0:
        return _error("max_packets must be a positive number")
    extra_ports = []
    for port in ports or []:
        try:
            value = int(port)
        except (TypeError, ValueError):
            return _error(f"Not a TCP port: {port!r}")
        if not 1 <= value <= 65535:
            return _error(f"Not a TCP port: {port!r}")
        extra_ports.append(value)
    proto_dirs = resolve_proto_paths(proto_paths)
    for path in proto_dirs:
        if not os.path.isdir(path):
            return _error(f"proto path is not a directory: {path}")
    max_items = max(1, int(max_items or 25))

    status: Dict[str, Any] = {}
    try:
        disc = discover(file_path, display_filter=display_filter, max_packets=max_packets, status=status)
    except RuntimeError as exc:
        return _error(str(exc))
    decode_as, reasons = plan_decode_as(disc, extra_ports)
    extraction = iter_http2_packets(file_path, decode_as, keylog_file=keylog_file, proto_paths=proto_dirs,
                                    display_filter=display_filter, max_packets=max_packets)
    analysis = GrpcAnalysis(disc)
    try:
        for packet in extraction.packets:
            analysis.feed(packet)
    except RuntimeError as exc:
        return _error(str(exc))
    secrets = sorted((s for s in extraction.secret_values if len(s) >= MIN_SCRUB_LENGTH), key=len, reverse=True)

    start = analysis.start
    for conn in disc.values():
        start = conn.first_t if start is None else min(start, conn.first_t)
    end = analysis.end
    for conn in disc.values():
        end = conn.last_t if end is None else max(end, conn.last_t)
    ctx = Context(start, end, max_items=max_items)

    tls_sessions = {}
    certificates: Dict[int, bytes] = {}
    if include_tls:
        try:
            tls_sessions = _tls_sessions(file_path, disc, display_filter, max_packets)
            if keylog_file:
                certificates = decrypted_certificates(file_path, decode_as, keylog_file, display_filter, max_packets)
        except Exception as exc:  # the TLS view is an addition; its failure must not hide the RPCs
            status["tls_error"] = f"{type(exc).__name__}: {exc}"

    # Connections to report: every one that carried HTTP/2, plus TLS ones that may carry gRPC,
    # plus a preface or gRPC port with no HTTP/2 answer.
    for index, dconn in disc.items():
        relevant = (dconn.preface_frame is not None or (dconn.is_tls() and ("h2" in dconn.alpn or
                    dconn.service_port() in GRPC_PORTS)) or (dconn.service_port() in GRPC_PORTS and
                    dconn.first_payload_frame is not None) or dconn.service_port() in extra_ports)
        if relevant and index not in analysis.conns:
            conn = _Conn(index, dconn)
            conn.first_frame, conn.first_t, conn.last_t = dconn.first_frame, dconn.first_t, dconn.last_t
            analysis.conns[index] = conn

    issues: List[Dict[str, Any]] = []
    events: List[Dict[str, Any]] = []
    connections, rpcs, credentials = [], [], []
    status_counts: Dict[str, int] = {}
    for conn in sorted(analysis.conns.values(), key=lambda c: c.first_frame or 0):
        dconn = conn.disc
        tls_info = None
        if dconn and dconn.is_tls():
            session = tls_sessions.get((_endpoint(dconn.client), _endpoint(dconn.server)))
            tls_info = _tls_view(dconn, session, decrypted=conn.tls_seen and bool(conn.rpcs),
                                 keylog_given=bool(keylog_file), decrypted_der=certificates.get(conn.index),
                                 capture_time=dconn.first_t)
        report_conn = analysis.connection_report(conn, ctx, tls_info)
        flow = report_conn["flow"]
        label = f"{flow} ({report_conn['service']})"
        conn_rpcs = [analysis.rpc_report(conn, rpc, ctx) for rpc in sorted(conn.rpcs.values(),
                                                                               key=lambda r: r.stream_id)]
        for rpc in conn_rpcs:
            key = rpc["grpc_status_name"] or rpc["outcome"]
            report_conn["rpc_status"][key] = report_conn["rpc_status"].get(key, 0) + 1
            status_counts[key] = status_counts.get(key, 0) + 1
            frames = [f for f in (rpc["frames"].get("request"), rpc["frames"].get("trailers")) if f]
            if rpc["outcome"] == "error":
                code = rpc["grpc_status_name"]
                severity = "warning" if rpc["grpc_status"] in (1, 5, 6) else "error"
                issues.append(make_issue(severity, f"GRPC_{code}", f"{label}: {rpc['diagnosis']}", frames,
                                         method=rpc["method"], grpc_status=rpc["grpc_status"]))
            elif rpc["outcome"] == "incomplete" and rpc["method"]:
                long_lived = "long-lived stream" in rpc["diagnosis"]
                issues.append(make_issue("info" if long_lived else "warning", "GRPC_NO_STATUS",
                                         f"{label}: {rpc['diagnosis']}", frames, method=rpc["method"]))
            errs = (rpc.get("decoded", {}).get("response") or {}).get("errors")
            if errs and rpc["outcome"] == "ok":
                issues.append(make_issue("warning", "GNMI_INBAND_ERROR", f"{label}: {rpc['diagnosis']}", frames,
                                         method=rpc["method"]))
            if rpc["state_changing"]:
                events.append(make_event(ctx, ctx.start + (rpc["t"] or 0) if ctx.start is not None else 0, "grpc",
                                         "state_changing_rpc", f"{rpc['method']} on {flow}: "
                                         f"{rpc['grpc_status_name'] or rpc['outcome']}", rpc["frames"].get("request")))
            for size_key in ("request", "response"):
                largest = rpc[size_key]["largest"] or 0
                if largest > GRPC_DEFAULT_MAX_RECV:
                    issues.append(make_issue("warning", "GRPC_MESSAGE_OVER_DEFAULT_LIMIT",
                                             f"{label}: {rpc['method']} {size_key} message of {largest} bytes exceeds "
                                             "the common 4 MiB default receive limit (grpc-go, grpc-java, C core); "
                                             "the receiver fails it with RESOURCE_EXHAUSTED unless its limit was raised",
                                             frames, method=rpc["method"]))
            if rpc["t"] is not None and ctx.start is not None:
                events.append(make_event(ctx, ctx.start + rpc["t"], "grpc", "rpc",
                                         f"{rpc['method']} {rpc['grpc_status_name'] or rpc['outcome']}",
                                         rpc["frames"].get("request")))
        if report_conn["transport"] == "cleartext" and conn.rpcs:
            issues.append(make_issue("warning", "GRPC_CLEARTEXT",
                                     f"{label}: {report_conn['protocol']} over cleartext HTTP/2 (h2c): every request, "
                                     "response and metadata value crosses the network readable",
                                     [conn.magic_frame or conn.first_frame]))
        for key, entry in sorted(conn.credentials.items(), key=lambda kv: kv[1]["first_frame"]):
            cleartext = report_conn["transport"] == "cleartext"
            finding = {"flow": flow, "service": report_conn["service"], "key": key, "cleartext": cleartext,
                       "transport": report_conn["transport"], "requests": entry["requests"],
                       "first_frame": entry["first_frame"], "frames": entry["frames"], "value": "masked"}
            credentials.append(finding)
            if cleartext:
                issues.append(make_issue("error", "CLEARTEXT_CREDENTIAL",
                                         f"{label}: gRPC metadata key '{key}' sent in cleartext in "
                                         f"{entry['requests']} request(s) (value masked): anyone on the path can "
                                         "read it; use TLS", entry["frames"], key=key, flow=flow))
            else:
                issues.append(make_issue("info", "CREDENTIAL_IN_METADATA",
                                         f"{label}: gRPC metadata key '{key}' in {entry['requests']} request(s), "
                                         "protected by TLS on the wire (seen because the key log decrypted it; "
                                         "value masked)", entry["frames"], key=key, flow=flow))
        for rst in conn.rst_streams:
            severity = "warning" if rst["error_code"] in (0, 8) else "error"
            text = (f"{label}: RST_STREAM {rst['error']} from the {rst['from']} on stream {rst['stream_id']}"
                    f"{' (' + rst['method'] + ')' if rst['method'] else ''}: ")
            if rst.get("after_end") and rst["from"] == "client":
                severity = "info"
                text += ("after the server had already ended the stream with its status: the client closing its "
                         "half (normal cleanup)")
            else:
                text += H2_ERROR_HINTS.get(rst["error_code"], "")
            issues.append(make_issue(severity, "HTTP2_RST_STREAM", text, [rst["frame"]], error=rst["error"]))
            events.append(make_event(ctx, rst["t"], "http2", "rst_stream", text, rst["frame"]))
        for goaway in conn.goaways:
            debug = goaway["debug_data"] or ""
            unprocessed = [r.stream_id for r in conn.rpcs.values()
                           if goaway["last_stream_id"] is not None and r.stream_id > goaway["last_stream_id"]
                           and r.stream_id % 2 == 1]
            if goaway["error_code"] == 11 and "too_many_pings" in debug:
                text = (f"{label}: GOAWAY ENHANCE_YOUR_CALM 'too_many_pings' from the {goaway['from']}: the client's "
                        "keepalive is more frequent than the server allows (grpc-go servers refuse pings more often "
                        "than every 5 minutes by default); raise the client's keepalive time or the server's "
                        "keepalive enforcement policy")
                issues.append(make_issue("error", "HTTP2_TOO_MANY_PINGS", text, [goaway["frame"]]))
            else:
                text = (f"{label}: GOAWAY {goaway['error']} from the {goaway['from']}, last stream "
                        f"{goaway['last_stream_id']}" + (f", debug data '{debug}'" if debug else ""))
                if goaway["error_code"] == 0 and goaway["from"] == "client":
                    text += ": the client closed the channel"
                    severity = "info"
                elif goaway["error_code"] == 0:
                    text += (": the server is closing the connection gracefully (shutdown, restart or max connection "
                             "age); streams above the last stream id were not processed and may be retried")
                    severity = "warning"
                else:
                    text += f": {H2_ERROR_HINTS.get(goaway['error_code'], 'connection error')}"
                    severity = "error"
                if unprocessed:
                    text += f"; streams {unprocessed[:10]} were not processed"
                issues.append(make_issue(severity, "HTTP2_GOAWAY", text, [goaway["frame"]], error=goaway["error"]))
            events.append(make_event(ctx, goaway["t"], "http2", "goaway", text, goaway["frame"]))
        for stall in report_conn["flow_control"]["stalls"]:
            waiting = "with data waiting" if stall["data_waiting"] else "while its stream was still open"
            if stall["resolved"]:
                text = (f"{label}: the {stall['sender']}'s {stall['window']} flow-control window reached 0 on stream "
                        f"{stall['stream_id']}{' (' + stall['method'] + ')' if stall['method'] else ''} {waiting}, "
                        f"for {stall['duration_s']} s until a WINDOW_UPDATE (frame {stall['reopened_frame']}): the "
                        "receiver reads slower than the sender writes")
                severity = "warning" if stall["duration_s"] >= STALL_WARN_S else "info"
            else:
                text = (f"{label}: the {stall['sender']}'s {stall['window']} flow-control window reached 0 on stream "
                        f"{stall['stream_id']}{' (' + stall['method'] + ')' if stall['method'] else ''} and never "
                        f"reopened ({stall['ended_by'] or 'until the capture ended'}, {stall['duration_s']} s): the "
                        "receiver stopped reading (a stuck or overloaded consumer)")
                severity = "error"
            issues.append(make_issue(severity, "HTTP2_FLOW_CONTROL_STALL", text, [stall["frame"]]))
            events.append(make_event(ctx, (ctx.start or 0) + (stall["t"] or 0), "http2", "flow_control_stall", text,
                                     stall["frame"]))
        for big in conn.oversize_frames:
            issues.append(make_issue("error", "HTTP2_FRAME_TOO_LARGE",
                                     f"{label}: the {big['from']} sent a {big['type']} frame of {big['length']} bytes, "
                                     f"over the peer's SETTINGS_MAX_FRAME_SIZE {big['peer_max_frame_size']}: the peer "
                                     "must fail the connection with FRAME_SIZE_ERROR", [big["frame"]]))
        for big in conn.oversize_headers:
            issues.append(make_issue("warning", "HTTP2_HEADER_LIST_TOO_LARGE",
                                     f"{label}: the {big['from']} sent a header list of {big['header_list_size']} bytes "
                                     f"on stream {big['stream_id']}, over the peer's SETTINGS_MAX_HEADER_LIST_SIZE "
                                     f"{big['peer_limit']} (large metadata): expect RESOURCE_EXHAUSTED or INTERNAL",
                                     [big["frame"]]))
        limit = conn.settings["server"].get("max_concurrent_streams")
        if limit is not None and conn.max_open > limit:
            issues.append(make_issue("warning", "HTTP2_MAX_CONCURRENT_STREAMS_EXCEEDED",
                                     f"{label}: {conn.max_open} streams open at once, over the server's "
                                     f"SETTINGS_MAX_CONCURRENT_STREAMS {limit}: the excess is refused (REFUSED_STREAM, "
                                     "gRPC UNAVAILABLE) or queued by the client", [conn.max_open_frame]))
        if dconn and dconn.preface_frame is not None and not conn.packets.get("server"):
            issues.append(make_issue("error", "HTTP2_PREFACE_UNANSWERED",
                                     f"{label}: the client sent the HTTP/2 preface in cleartext and the server never "
                                     "answered with HTTP/2: the port may expect TLS (the client used an insecure "
                                     "channel), or it is not a gRPC server", [dconn.preface_frame]))
        if conn.hpack_failures:
            issues.append(make_issue("warning", "HTTP2_HPACK_DECODE_FAILED",
                                     f"{label}: {len(conn.hpack_failures)} header block(s) could not be decoded (HPACK "
                                     "state missing: the capture started after the connection opened)",
                                     conn.hpack_failures))
        open_rpcs = [r for r in conn.rpcs.values() if r.is_open()]
        for reset in (dconn.resets if dconn else []):
            in_flight = [r.method for r in open_rpcs if r.t_request is not None and r.t_request <= reset["t"]]
            text = f"{label}: TCP reset from {_endpoint(reset['from'])}"
            if in_flight:
                text += (f" with {len(in_flight)} RPC(s) still open ({', '.join(m for m in in_flight[:5] if m)}): the "
                         "client sees UNAVAILABLE")
                issues.append(make_issue("error", "TCP_RESET_DURING_RPC", text, [reset["frame"]]))
            events.append(make_event(ctx, reset["t"], "tcp", "reset", text, reset["frame"]))
        if tls_info:
            for alert in tls_info.get("alerts", []):
                if alert.get("level") in ("fatal", "warning") and alert.get("description") != "close_notify":
                    hint = alert.get("hint") or ""
                    issues.append(make_issue("error" if alert["level"] == "fatal" else "warning", "TLS_ALERT",
                                             f"{label}: TLS {alert['level']} alert {alert['description']} from "
                                             f"{alert['from']}" + (f": {hint}" if hint else ""), [alert["frame"]]))
            hello = [dconn.tls_client_hello] if dconn.tls_client_hello else []
            for hint in tls_info.get("hints", []):
                text = f"{label}: {hint['text']}"
                if hint["code"] == "TLS_CERT_NO_IP_SAN":
                    issues.append(make_issue("warning", "TLS_CERT_NO_IP_SAN", text, hello))
                elif hint["code"] == "TLS_NO_SERVER_HELLO":
                    issues.append(make_issue("warning", "TLS_NO_SERVER_HELLO", text, hello))
                elif hint["code"] == "TLS_NO_SNI":
                    issues.append(make_issue("info", "TLS_NO_SNI", text, hello))
                else:
                    issues.append(make_issue("info", "GRPC_TLS_NOT_DECRYPTED", text, hello))
        connections.append(report_conn)
        rpcs.extend(conn_rpcs)

    present = bool(connections)
    total = len(rpcs)
    if not present:
        verdict = "No gRPC or HTTP/2 found: no HTTP/2 preface, no TLS offering h2, and nothing on a well-known gRPC port."
    else:
        parts = []
        clear = [c for c in connections if c["transport"] == "cleartext" and c["rpcs"]]
        tls = [c for c in connections if c["transport"].startswith("tls")]
        if clear:
            parts.append(f"{len(clear)} cleartext {('gRPC' if any(c['protocol'] == 'grpc' for c in clear) else 'HTTP/2')} "
                         f"connection(s) ({', '.join(sorted({c['service'] for c in clear}))})")
        if tls:
            decrypted = sum(1 for c in tls if c.get("tls", {}).get("decrypted"))
            ports = ", ".join(sorted({c["service"] for c in tls}))
            parts.append(f"{len(tls)} TLS connection(s) on a gRPC port or offering ALPN h2 ({ports}), {decrypted} "
                         "decrypted" + ("" if decrypted else ": without a key log only the handshake is visible, so "
                                        "whether they carry gRPC cannot be seen"))
        verdict = "; ".join(parts) or f"{len(connections)} connection(s)"
        if total:
            status_text = ", ".join(f"{n} {k}" for k, n in sorted(status_counts.items(), key=lambda kv: -kv[1]))
            verdict += f". {total} RPC(s): {status_text}"
        if credentials:
            clear_keys = sorted({c["key"] for c in credentials if c["cleartext"]})
            if clear_keys:
                verdict += f". Credentials in cleartext metadata: {', '.join(clear_keys)} (values masked)"
        verdict += "."
    listed_rpcs, rpcs_omitted = cap(rpcs, max_items * 4)
    listed_conns, conns_omitted = cap(connections, max_items)
    events.sort(key=lambda e: (e["t"] if e["t"] is not None else 0, e.get("frame") or 0))
    report = {
        "status": "success",
        "schema": REPORT_SCHEMA,
        "file": file_path,
        "overall_status": status_from_issues(issues, present),
        "verdict": verdict,
        "capture": {
            "start": iso_time(start), "end": iso_time(end),
            "http2_packets": analysis.packets,
            "tshark": tshark_version(),
            "decode_as": extraction.status.get("decode_as", []),
            "decode_as_reasons": {f"tcp/{p}": r for p, r in sorted(reasons.items())},
            "keylog_file_given": bool(keylog_file),
            "proto_paths": proto_dirs,
            "display_filter": display_filter,
            "max_packets": max_packets,
            "warnings": [w for w in (status.get("tls_error"), extraction.status.get("parse_error")) if w]
            + _protobuf_warnings(extraction.status.get("stderr", "")),
        },
        "summary": {"connections": len(connections), "rpcs": total, "rpc_status": status_counts,
                    "cleartext_credentials": sum(1 for c in credentials if c["cleartext"])},
        "connections": listed_conns,
        "connections_omitted": conns_omitted,
        "rpcs": listed_rpcs,
        "rpcs_omitted": rpcs_omitted,
        "credentials": credentials,
        "issues": sort_issues(issues),
        "timeline": events[:max_items * 8],
        "timeline_omitted": max(len(events) - max_items * 8, 0),
        "limits": LIMITS,
    }
    return _scrub(report, secrets)


def _protobuf_warnings(stderr: str) -> List[str]:
    """tshark's protobuf loading errors, one line each (paths of .proto files Wireshark could not parse)."""
    out = []
    for line in stderr.splitlines():
        if "Protobuf" in line and ("failed" in line or "does not exist" in line):
            out.append(line.strip()[:300])
    return out[:10]
