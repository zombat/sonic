#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. gNMI and gNOI Message Decoding

A small protobuf wire-format reader and the few gNMI and gNOI messages a
troubleshooter needs, decoded without any .proto file:

    gNMI Capabilities   response: gNMI version, supported encodings, model count and names
    gNMI Get            request: paths, data type, encoding (absent means JSON, the proto3 default);
                        response: notifications and updates, an empty notification, an in-band error
    gNMI Set            request: the paths deleted, replaced and updated (counts and paths, never values);
                        response: results per operation, an in-band error
    gNMI Subscribe      request: mode (STREAM, ONCE, POLL), encoding, each subscription's path, mode and
                        sample interval, updates_only, a Poll; response: notifications, updates,
                        sync_response, an in-band error (the deprecated error field some targets use)
    gNOI system.Time    response: the target's clock, compared with the capture's clock
    gRPC health         grpc.health.v1.Health Check and Watch responses: SERVING, NOT_SERVING, ...

Field numbers are those of github.com/openconfig/gnmi proto/gnmi/gnmi.proto and
github.com/openconfig/gnoi system/system.proto (Apache-2.0); only the numbers and
enum names are used here, no file is copied. Values (TypedValue) are never decoded:
a Set or a notification can carry configuration secrets, and a path and a count
are what troubleshooting needs.

Wireshark's own protobuf dissector decodes every field when it is given the .proto
files (see analyzers/grpc_inspect.py, proto_paths); this module works without them.

Author: Raymond A Rizzo | Zombat
"""

from typing import Any, Dict, List, Optional, Tuple

ENCODINGS = {0: "JSON", 1: "BYTES", 2: "PROTO", 3: "ASCII", 4: "JSON_IETF"}
DATA_TYPES = {0: "ALL", 1: "CONFIG", 2: "STATE", 3: "OPERATIONAL"}
SUBSCRIPTION_LIST_MODES = {0: "STREAM", 1: "ONCE", 2: "POLL"}
SUBSCRIPTION_MODES = {0: "TARGET_DEFINED", 1: "ON_CHANGE", 2: "SAMPLE"}
UPDATE_OPS = {0: "INVALID", 1: "DELETE", 2: "REPLACE", 3: "UPDATE", 4: "UNION_REPLACE"}
HEALTH_STATUS = {0: "UNKNOWN", 1: "SERVING", 2: "NOT_SERVING", 3: "SERVICE_UNKNOWN"}

MAX_FIELDS = 20000
MAX_LIST = 20


def encoding_name(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return ENCODINGS.get(value, f"vendor encoding {value}")


def read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf) or shift > 63:
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def parse_fields(buf: bytes) -> List[Tuple[int, int, Any]]:
    """
    One protobuf message's top-level fields: [(number, wire type, value)].

    Varints are ints, length-delimited fields bytes, fixed32/fixed64 ints. Raises
    ValueError on malformed or truncated input.
    """
    out = []
    pos = 0
    while pos < len(buf):
        if len(out) >= MAX_FIELDS:
            raise ValueError("too many fields")
        key, pos = read_varint(buf, pos)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("field number 0")
        if wire == 0:
            value, pos = read_varint(buf, pos)
        elif wire == 1:
            if pos + 8 > len(buf):
                raise ValueError("truncated fixed64")
            value, pos = int.from_bytes(buf[pos:pos + 8], "little"), pos + 8
        elif wire == 2:
            length, pos = read_varint(buf, pos)
            if pos + length > len(buf):
                raise ValueError("truncated length-delimited field")
            value, pos = bytes(buf[pos:pos + length]), pos + length
        elif wire == 5:
            if pos + 4 > len(buf):
                raise ValueError("truncated fixed32")
            value, pos = int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
        out.append((number, wire, value))
    return out


def _all(fields, number: int) -> List[Any]:
    return [value for num, _, value in fields if num == number]


def _one(fields, number: int, default=None):
    values = _all(fields, number)
    return values[-1] if values else default


def _packed_varints(values: List[Any]) -> List[int]:
    """A repeated enum may be packed (one bytes value) or not (several ints)."""
    out: List[int] = []
    for value in values:
        if isinstance(value, int):
            out.append(value)
        else:
            pos = 0
            while pos < len(value):
                item, pos = read_varint(value, pos)
                out.append(item)
    return out


def _text(value: Any) -> Optional[str]:
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return None


def render_path(buf: Optional[bytes]) -> Optional[str]:
    """A gnmi.Path as text: origin:/elem[key=value]/elem (target in angle brackets)."""
    if buf is None:
        return None
    fields = parse_fields(buf)
    origin = _text(_one(fields, 2))
    target = _text(_one(fields, 4))
    parts = []
    for elem in _all(fields, 3):
        efields = parse_fields(elem)
        name = _text(_one(efields, 1)) or ""
        keys = []
        for entry in _all(efields, 2):
            kv = parse_fields(entry)
            keys.append((_text(_one(kv, 1)) or "", _text(_one(kv, 2)) or ""))
        parts.append(name + "".join(f"[{k}={v}]" for k, v in sorted(keys)))
    if not parts:
        parts = [_text(v) or "" for v in _all(fields, 1)]  # the deprecated element field
    text = "/" + "/".join(parts) if parts else "/"
    if origin:
        text = f"{origin}:{text}"
    if target:
        text = f"<{target}>{text}"
    return text


def join_paths(prefix: Optional[str], path: Optional[str]) -> Optional[str]:
    if not prefix or prefix in ("/",):
        return path
    if not path or path == "/":
        return prefix
    return prefix.rstrip("/") + path


def _error(buf: Optional[bytes]) -> Optional[Dict[str, Any]]:
    """The deprecated gnmi.Error {code, message} some targets still send in-band."""
    if buf is None:
        return None
    fields = parse_fields(buf)
    return {"code": _one(fields, 1, 0), "message": _text(_one(fields, 2))}


def _notification_counts(buf: bytes) -> Tuple[int, int]:
    """(updates, deletes) in one gnmi.Notification."""
    fields = parse_fields(buf)
    return len(_all(fields, 4)), len(_all(fields, 5))


def decode_request(method: str, message: bytes) -> Dict[str, Any]:
    """The troubleshooting fields of one request message of a gNMI or gNOI RPC."""
    rpc = method.rsplit("/", 1)[-1]
    service = method.strip("/").split("/", 1)[0]
    fields = parse_fields(message)
    if service == "gnmi.gNMI" and rpc == "Get":
        prefix = render_path(_one(fields, 1))
        encoding = _one(fields, 5)
        return {"paths": [join_paths(prefix, render_path(p)) for p in _all(fields, 2)][:MAX_LIST],
                "type": DATA_TYPES.get(_one(fields, 3, 0), str(_one(fields, 3))),
                "encoding": encoding_name(encoding if encoding is not None else 0),
                "encoding_field_present": encoding is not None}
    if service == "gnmi.gNMI" and rpc == "Set":
        prefix = render_path(_one(fields, 1))
        out: Dict[str, Any] = {}
        for label, number in (("delete", 2), ("replace", 3), ("update", 4), ("union_replace", 6)):
            values = _all(fields, number)
            if number == 2:
                paths = [join_paths(prefix, render_path(v)) for v in values]
            else:
                paths = [join_paths(prefix, render_path(_one(parse_fields(v), 1))) for v in values]
            out[label] = {"count": len(values), "paths": paths[:MAX_LIST]}
        return out
    if service == "gnmi.gNMI" and rpc == "Subscribe":
        if _one(fields, 3) is not None:
            return {"poll": True}
        sub = _one(fields, 1)
        if sub is None:
            return {}
        sfields = parse_fields(sub)
        prefix = render_path(_one(sfields, 1))
        subs = []
        for item in _all(sfields, 2)[:MAX_LIST]:
            ifields = parse_fields(item)
            entry = {"path": join_paths(prefix, render_path(_one(ifields, 1))),
                     "mode": SUBSCRIPTION_MODES.get(_one(ifields, 2, 0), str(_one(ifields, 2)))}
            if _one(ifields, 3):
                entry["sample_interval_s"] = round(_one(ifields, 3) / 1e9, 3)
            if _one(ifields, 5):
                entry["heartbeat_interval_s"] = round(_one(ifields, 5) / 1e9, 3)
            subs.append(entry)
        encoding = _one(sfields, 8)
        return {"mode": SUBSCRIPTION_LIST_MODES.get(_one(sfields, 5, 0), str(_one(sfields, 5))),
                "encoding": encoding_name(encoding if encoding is not None else 0),
                "encoding_field_present": encoding is not None,
                "updates_only": bool(_one(sfields, 9, 0)), "subscriptions": subs,
                "subscription_count": len(_all(sfields, 2))}
    return {}


def decode_response(method: str, message: bytes, capture_time: Optional[float] = None) -> Dict[str, Any]:
    """The troubleshooting fields of one response message of a gNMI or gNOI RPC."""
    rpc = method.rsplit("/", 1)[-1]
    service = method.strip("/").split("/", 1)[0]
    fields = parse_fields(message)
    if service == "gnmi.gNMI" and rpc == "Capabilities":
        models = _all(fields, 1)
        names = []
        for model in models[:MAX_LIST]:
            mfields = parse_fields(model)
            name, version = _text(_one(mfields, 1)), _text(_one(mfields, 3))
            names.append(f"{name} {version}" if version else name)
        return {"gnmi_version": _text(_one(fields, 3)),
                "supported_encodings": [encoding_name(v) for v in _packed_varints(_all(fields, 2))],
                "models": len(models), "model_names": names}
    if service == "gnmi.gNMI" and rpc == "Get":
        notes = _all(fields, 1)
        updates = sum(_notification_counts(n)[0] for n in notes)
        out = {"notifications": len(notes), "updates": updates}
        if _error(_one(fields, 2)):
            out["error"] = _error(_one(fields, 2))
        return out
    if service == "gnmi.gNMI" and rpc == "Set":
        ops: Dict[str, int] = {}
        for result in _all(fields, 2):
            op = UPDATE_OPS.get(_one(parse_fields(result), 4, 0), "INVALID")
            ops[op] = ops.get(op, 0) + 1
        out = {"results": sum(ops.values()), "ops": ops}
        if _error(_one(fields, 3)):
            out["error"] = _error(_one(fields, 3))
        return out
    if service == "gnmi.gNMI" and rpc == "Subscribe":
        out: Dict[str, Any] = {}
        update = _one(fields, 1)
        if update is not None:
            out["notification"] = True
            out["updates"], out["deletes"] = _notification_counts(update)
        if _one(fields, 3):
            out["sync_response"] = True
        if _error(_one(fields, 4)):
            out["error"] = _error(_one(fields, 4))
        return out
    if service == "grpc.health.v1.Health" and rpc in ("Check", "Watch"):
        return {"serving_status": HEALTH_STATUS.get(_one(fields, 1, 0), str(_one(fields, 1)))}
    if service == "gnoi.system.System" and rpc == "Time":
        ns = _one(fields, 1)
        if ns is None:
            return {}
        out = {"target_time_epoch_s": round(ns / 1e9, 6)}
        if capture_time:
            out["skew_s"] = round(ns / 1e9 - capture_time, 3)
        return out
    return {}
