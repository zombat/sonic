#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. IPsec ESP decryption from SA keys

Decrypts ESP with the Security Association keys an operator supplies, using Wireshark's
own ESP decryption through tshark. The SA keys are written to tshark's esp_sa UAT inside a
temporary WIRESHARK_CONFIG_DIR (extractors/wsconfig.py), never on the command line, so the
keys are not visible in the tshark process's argv. tshark decrypts each ESP packet whose
(src, dst, SPI) matches an SA, and S.O.N.I.C. reads the decrypted inner IP packet from the
esp.decrypted_data field and reconstructs it into a new capture, so the existing analyzers
can run over the inner traffic.

The SA keys are secrets: they are read by path (an operator's SA file or an `ip xfrm state`
dump), handed here as data, and never logged, returned or written to a report.

Author: Raymond A Rizzo | Zombat
"""

import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from extractors.http2 import tshark_available, tshark_version  # noqa: F401 (re-exported)
from extractors.wsconfig import tshark_env, wireshark_config

# Friendly encryption names -> the exact Wireshark esp_sa UAT label (checked against tshark 3.6.2).
ENCRYPTION_LABELS = {
    "aes-cbc": "AES-CBC [RFC3602]", "aes": "AES-CBC [RFC3602]", "cbc(aes)": "AES-CBC [RFC3602]",
    "aes-ctr": "AES-CTR [RFC3686]", "rfc3686(ctr(aes))": "AES-CTR [RFC3686]",
    "3des-cbc": "TripleDES-CBC [RFC2451]", "3des": "TripleDES-CBC [RFC2451]", "cbc(des3_ede)": "TripleDES-CBC [RFC2451]",
    "des-cbc": "DES-CBC [RFC2405]", "des": "DES-CBC [RFC2405]", "cbc(des)": "DES-CBC [RFC2405]",
    "null": "NULL", "ecb(cipher_null)": "NULL",  # the ESP table's label (NULL [RFC2410] is the IKEv2 one)
    "aes-gcm": "AES-GCM with 16 octet ICV [RFC4106]", "aes-gcm-16": "AES-GCM with 16 octet ICV [RFC4106]",
    "aes-gcm-12": "AES-GCM with 12 octet ICV [RFC4106]", "aes-gcm-8": "AES-GCM with 8 octet ICV [RFC4106]",
    "rfc4106(gcm(aes))": "AES-GCM with 16 octet ICV [RFC4106]",
}
INTEGRITY_LABELS = {
    "hmac-sha1-96": "HMAC-SHA-1-96 [RFC2404]", "hmac(sha1)": "HMAC-SHA-1-96 [RFC2404]", "sha1": "HMAC-SHA-1-96 [RFC2404]",
    "hmac-sha256-128": "HMAC-SHA-256-128 [RFC4868]", "hmac(sha256)": "HMAC-SHA-256-128 [RFC4868]",
    "sha256": "HMAC-SHA-256-128 [RFC4868]",
    "hmac-sha384-192": "HMAC-SHA-384-192 [RFC4868]", "hmac(sha384)": "HMAC-SHA-384-192 [RFC4868]",
    "hmac-sha512-256": "HMAC-SHA-512-256 [RFC4868]", "hmac(sha512)": "HMAC-SHA-512-256 [RFC4868]",
    "hmac-md5-96": "HMAC-MD5-96 [RFC2403]", "hmac(md5)": "HMAC-MD5-96 [RFC2403]", "md5": "HMAC-MD5-96 [RFC2403]",
    "none": "NULL", "null": "NULL", "": "NULL",
    "any-96": "ANY 96 bit authentication [no checking]", "any-128": "ANY 128 bit authentication [no checking]",
}
AEAD_LABELS = {lbl for lbl in ENCRYPTION_LABELS.values() if "GCM" in lbl}
# ICV length in bytes per integrity label: tshark 3.6.2 leaves the ICV inside esp.decrypted_data when the
# encryption is NULL, so it is stripped by this length before the trailer is read.
ICV_BYTES = {"HMAC-SHA-1-96 [RFC2404]": 12, "HMAC-MD5-96 [RFC2403]": 12, "HMAC-SHA-256-128 [RFC4868]": 16,
             "HMAC-SHA-384-192 [RFC4868]": 24, "HMAC-SHA-512-256 [RFC4868]": 32,
             "ANY 96 bit authentication [no checking]": 12, "ANY 128 bit authentication [no checking]": 16,
             "NULL": 0}
# Labels as tshark 3.6.2 shows them, accepted too in an SA file.
ENCRYPTION_LABELS.update({label.lower(): label for label in set(ENCRYPTION_LABELS.values())})
INTEGRITY_LABELS.update({label.lower(): label for label in set(INTEGRITY_LABELS.values())})


class SaError(ValueError):
    """An SA file or xfrm dump that cannot be parsed into usable Security Associations."""


def _hex_key(value: str) -> str:
    """Normalise a key to `0x<hex>` (accepts 0x-prefixed or bare hex); empty stays empty."""
    value = value.strip()
    if not value:
        return ""
    body = value[2:] if value.lower().startswith("0x") else value
    body = body.replace(":", "").replace(" ", "")
    if body and not re.fullmatch(r"[0-9a-fA-F]+", body):
        raise SaError("a key is not hexadecimal (0x followed by hex digits)")  # never echo any part of a key
    return "0x" + body.lower() if body else ""


def _label(mapping: Dict[str, str], name: str, what: str) -> str:
    key = name.strip().lower()
    if key in mapping:
        return mapping[key]
    # Already a full Wireshark label?
    if name in mapping.values():
        return name
    raise SaError(f"unknown {what} algorithm: {name!r}")


def sa_uat_row(sa: Dict[str, str]) -> str:
    """One esp_sa UAT record line for an SA (the key material is a secret)."""
    proto = sa.get("protocol", "IPv4")
    enc_label = _label(ENCRYPTION_LABELS, sa.get("encryption", "null"), "encryption")
    enc_key = _hex_key(sa.get("encryption_key", ""))
    if enc_label in AEAD_LABELS:
        auth_label, auth_key = "NULL", ""  # AEAD: the integrity is built into the cipher
    else:
        auth_label = _label(INTEGRITY_LABELS, sa.get("integrity", "none"), "integrity")
        auth_key = _hex_key(sa.get("integrity_key", ""))
    fields = [proto, sa["src"], sa["dst"], _spi(sa["spi"]), enc_label, enc_key, auth_label, auth_key]
    return ",".join('"' + f.replace('"', '') + '"' for f in fields)


def _spi(value: str) -> str:
    """An SPI in one canonical form, 0x and eight hex digits, as tshark prints it (0x100 is 0x00000100)."""
    text = str(value).strip().lower()
    try:
        number = int(text, 16) if text.startswith("0x") or any(c in "abcdef" for c in text) else int(text)
    except ValueError:
        raise SaError(f"SPI is not a number: {value!r}")
    if not 0 <= number <= 0xFFFFFFFF:
        raise SaError(f"SPI out of range: {value!r}")
    return f"0x{number:08x}"


# ---------------------------------------------------------------------------
# SA file and `ip xfrm state` parsers (read by path; keys never echoed)
# ---------------------------------------------------------------------------

_FIELD_ALIASES = {
    "src": "src", "source": "src", "dst": "dst", "dest": "dst", "destination": "dst",
    "spi": "spi", "protocol": "protocol", "proto": "protocol",
    "encryption": "encryption", "enc": "encryption", "cipher": "encryption", "encryption_algo": "encryption",
    "encryption_key": "encryption_key", "enc_key": "encryption_key", "key": "encryption_key",
    "integrity": "integrity", "auth": "integrity", "authentication": "integrity", "authentication_algo": "integrity",
    "integrity_key": "integrity_key", "auth_key": "integrity_key", "authentication_key": "integrity_key",
}


def parse_sa_file(text: str) -> List[Dict[str, str]]:
    """
    SAs from an operator's SA file: records separated by a blank line (or a `---`/`[sa]` header),
    each a set of `field: value` or `field = value` lines. Falls through to the xfrm parser when
    the text looks like `ip xfrm state` output.

    Raises:
        SaError: no usable SA is found
    """
    if re.search(r"^\s*src\s+\S+\s+dst\s+\S+", text, re.MULTILINE) and ("proto esp" in text or "spi " in text):
        return parse_xfrm_state(text)
    records: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            if current:
                records.append(current)
                current = {}
            continue
        if line.lower() in ("---", "[sa]"):
            if current:
                records.append(current)
                current = {}
            continue
        sep = ":" if (":" in line and (("=" not in line) or line.index(":") < line.index("="))) else "="
        if sep not in line:
            continue
        name, _, value = line.partition(sep)
        canon = _FIELD_ALIASES.get(name.strip().lower())
        if canon:
            current[canon] = value.strip().strip('"').strip("'")
    if current:
        records.append(current)
    sas = [sa for sa in records if sa.get("src") and sa.get("dst") and sa.get("spi")]
    if not sas:
        raise SaError("no Security Association with src, dst and spi found in the SA file")
    return sas


def parse_xfrm_state(text: str) -> List[Dict[str, str]]:
    """
    SAs from `ip -s xfrm state` output. Each state begins `src <ip> dst <ip>` and carries
    `proto esp spi <spi>`, then one of `aead rfc4106(gcm(aes)) <key> <icvbits>` or
    `enc <cipher> <key>` plus `auth-trunc <hmac> <key> <bits>` / `auth <hmac> <key>`.
    """
    sas: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^src\s+(\S+)\s+dst\s+(\S+)", line)
        if m:
            if current and current.get("spi"):
                sas.append(current)
            proto = "IPv6" if ":" in m.group(1) else "IPv4"
            current = {"src": m.group(1), "dst": m.group(2), "protocol": proto}
            continue
        if current is None:
            continue
        m = re.search(r"\bproto\s+esp\s+spi\s+(\S+)", line)
        if m:
            current["spi"] = m.group(1)
        m = re.match(r"^aead\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(\d+)", line)
        if m:
            algo, key, icv = m.group(1), m.group(2), int(m.group(3))
            current["encryption"] = {128: "aes-gcm-16", 96: "aes-gcm-12", 64: "aes-gcm-8"}.get(icv, "aes-gcm-16") \
                if "gcm(aes)" in algo else algo
            current["encryption_key"] = key
            current["integrity"] = "none"
            continue
        m = re.match(r"^enc\s+(\S+)\s+(0x[0-9a-fA-F]+)", line)
        if m:
            algo, key = m.group(1), m.group(2)
            current["encryption"] = {"cbc(aes)": "aes-cbc", "cbc(des3_ede)": "3des-cbc", "cbc(des)": "des-cbc",
                                     "ecb(cipher_null)": "null"}.get(algo, algo)
            current["encryption_key"] = key
            continue
        m = re.match(r"^auth(?:-trunc)?\s+(\S+)\s+(0x[0-9a-fA-F]+)(?:\s+(\d+))?", line)
        if m:
            algo, key = m.group(1), m.group(2)
            friendly = {"hmac(sha1)": "hmac-sha1-96", "hmac(sha256)": "hmac-sha256-128",
                        "hmac(sha384)": "hmac-sha384-192", "hmac(sha512)": "hmac-sha512-256",
                        "hmac(md5)": "hmac-md5-96"}.get(algo, algo)
            current["integrity"] = friendly
            current["integrity_key"] = key
            continue
    if current and current.get("spi"):
        sas.append(current)
    sas = [sa for sa in sas if sa.get("src") and sa.get("dst") and sa.get("spi")]
    if not sas:
        raise SaError("no ESP Security Association found in the xfrm state dump")
    return sas


# ---------------------------------------------------------------------------
# Decryption and inner-packet reconstruction
# ---------------------------------------------------------------------------

ESP_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
              "esp.spi", "esp.decrypted_data", "esp.icv_good", "esp.icv_bad"]

# Next headers a real ESP trailer names (RFC 4303 2.6): IPv4 and IPv6 in tunnel mode, a transport
# protocol in transport mode, or "no next header" (a dummy packet).
TUNNEL_NEXT_HEADERS = {4: "IPv4", 41: "IPv6"}
TRANSPORT_NEXT_HEADERS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
NO_NEXT_HEADER = 59


def decrypt_esp(file_path: str, sas: List[Dict[str, str]], display_filter: Optional[str] = None,
                max_packets: Optional[int] = None
                ) -> Tuple[List[Dict[str, Any]], Dict[Tuple[str, str, str], Dict[str, Any]], List[str]]:
    """
    Decrypt ESP with the SAs and return (inner packets, per-SA stats).

    tshark fills esp.decrypted_data under any key, right or wrong, so a packet counts as decrypted
    only when its decrypted ESP trailer is real (see esp_trailer). tshark's ICV check is on, so each
    SA also says whether its integrity key verified.

    inner packets: [{"t": epoch, "bytes": IP packet bytes, "spi", "src", "dst", "mode"}], tunnel-mode
    inner packets as sent, transport-mode payloads given back their outer IP header.
    per-SA stats: {(src, dst, spi): {"src", "dst", "spi", "encryption", "integrity", "packets",
    "decrypted", "tunnel", "transport", "icv_good", "icv_bad"}}.
    warnings: tshark's complaints about the esp_sa table (a row it refused names a line and a label,
    never a key).
    """
    uat_rows = [sa_uat_row(sa) for sa in sas]
    preferences = {"esp.enable_encryption_decode": "TRUE", "esp.enable_authentication_check": "TRUE"}
    inner: List[Dict[str, Any]] = []
    stats: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for sa in sas:
        key = (sa["src"], sa["dst"], _spi(sa["spi"]).lower())
        stats[key] = {"src": sa["src"], "dst": sa["dst"], "spi": _spi(sa["spi"]).lower(),
                      "encryption": sa.get("encryption"), "integrity": sa.get("integrity"),
                      "packets": 0, "decrypted": 0, "tunnel": 0, "transport": 0, "icv_good": 0, "icv_bad": 0,
                      "_null_icv": _null_icv_bytes(sa)}
    with wireshark_config(preferences=preferences, uats={"esp_sa": uat_rows}) as config_dir:
        env = tshark_env(config_dir)
        flt = "esp"
        if display_filter:
            flt = f"({display_filter}) && esp"
        command = ["tshark", "-n", "-r", file_path, "-Y", flt, "-T", "fields", "-E", "separator=\t",
                   "-E", "occurrence=a", "-E", "aggregator=\x1f", "-E", "quote=n"]
        for name in ESP_FIELDS:
            command += ["-e", name]
        if max_packets:
            command += ["-c", str(int(max_packets))]
        with tempfile.TemporaryFile(mode="w+") as err:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True, env=env, bufsize=1 << 16)
            produced = 0
            try:
                for line in proc.stdout:
                    produced += 1
                    _esp_row(line, inner, stats)
            finally:
                if proc.poll() is None:
                    proc.stdout.close()
                    proc.terminate()
                proc.wait()
                err.seek(0)
                stderr_text = err.read()[-2000:].strip()
            if proc.returncode not in (0, None) and produced == 0:
                raise RuntimeError(f"tshark failed (exit {proc.returncode}): {stderr_text}")
    warnings = [line.strip()[:300] for line in stderr_text.splitlines() if "esp_sa" in line or "ESP SAs" in line]
    return inner, stats, warnings


def _first(row: Dict[str, str], name: str) -> str:
    return row[name].split("\x1f")[0]


def _esp_row(line: str, inner: List[Dict[str, Any]], stats: Dict[Tuple[str, str, str], Dict[str, Any]]) -> None:
    parts = line.rstrip("\n").split("\t")
    parts += [""] * (len(ESP_FIELDS) - len(parts))
    row = dict(zip(ESP_FIELDS, parts))
    src = _first(row, "ip.src") or _first(row, "ipv6.src")  # the first address of each is the outer header's
    dst = _first(row, "ip.dst") or _first(row, "ipv6.dst")
    try:
        spi = _spi(_first(row, "esp.spi"))
    except SaError:
        return
    stat = stats.get((src, dst, spi))
    if stat is None:
        return  # ESP of an SA the file does not name
    stat["packets"] += 1
    if _first(row, "esp.icv_good") in ("1", "True"):
        stat["icv_good"] += 1
    if _first(row, "esp.icv_bad") in ("1", "True"):
        stat["icv_bad"] += 1
        return  # the integrity check failed: whatever tshark decrypted is not trusted
    try:
        data = bytes.fromhex(_first(row, "esp.decrypted_data").replace(":", ""))
    except ValueError:
        return
    trailer = esp_trailer(data)
    if trailer is None and stat["_null_icv"]:
        trailer = esp_trailer(data[:-stat["_null_icv"]])  # NULL encryption: tshark left the ICV in
    if trailer is None:
        return
    payload, next_header = trailer
    try:
        t = float(row["frame.time_epoch"] or 0.0)
    except ValueError:
        t = 0.0
    if next_header in TUNNEL_NEXT_HEADERS:
        packet = _inner_ip_packet(payload, next_header)
        if packet is None:
            return  # a tunnel-mode trailer whose inner packet does not parse: a wrong key that matched by chance
        stat["decrypted"] += 1
        stat["tunnel"] += 1
        inner.append({"t": t, "bytes": packet, "spi": spi, "src": src, "dst": dst, "mode": "tunnel"})
    elif next_header in TRANSPORT_NEXT_HEADERS:
        stat["decrypted"] += 1
        stat["transport"] += 1
        packet = _transport_ip_packet(src, dst, next_header, payload)
        if packet is not None:
            inner.append({"t": t, "bytes": packet, "spi": spi, "src": src, "dst": dst, "mode": "transport"})
    elif next_header == NO_NEXT_HEADER:
        stat["decrypted"] += 1  # a dummy packet (RFC 4303 2.6): real, carries nothing


def _null_icv_bytes(sa: Dict[str, str]) -> int:
    """For a NULL-encryption SA, the length of the ICV tshark leaves in its decrypted data; else 0."""
    try:
        if _label(ENCRYPTION_LABELS, sa.get("encryption", "null"), "encryption") != "NULL":
            return 0
        return ICV_BYTES.get(_label(INTEGRITY_LABELS, sa.get("integrity", "none"), "integrity"), 0)
    except SaError:
        return 0


def esp_trailer(data: bytes) -> Optional[Tuple[bytes, int]]:
    """
    (payload, next header) when decrypted ESP bytes end in a real ESP trailer, else None.

    The trailer is padding, a pad length and a next header (RFC 4303 2.4 to 2.6). The default
    padding (which Linux, strongSwan and scapy send) is the bytes 1, 2, 3, ...: with a wrong key
    the last two bytes are noise, so a pad length whose padding does not read 1..n, or a next header
    that is no protocol, rejects the packet. A sender using other padding is not recognised.
    """
    if len(data) < 2:
        return None
    pad_len, next_header = data[-2], data[-1]
    if pad_len > len(data) - 2:
        return None
    if data[len(data) - 2 - pad_len:len(data) - 2] != bytes(range(1, pad_len + 1)):
        return None
    if next_header not in TUNNEL_NEXT_HEADERS and next_header not in TRANSPORT_NEXT_HEADERS \
            and next_header != NO_NEXT_HEADER:
        return None
    return data[:len(data) - 2 - pad_len], next_header


def _inner_ip_packet(payload: bytes, next_header: int) -> Optional[bytes]:
    """A tunnel-mode inner IP packet, only when its own length is exactly the ESP payload's."""
    if next_header == 4 and len(payload) >= 20 and payload[0] >> 4 == 4:
        if int.from_bytes(payload[2:4], "big") == len(payload):
            return payload
    if next_header == 41 and len(payload) >= 40 and payload[0] >> 4 == 6:
        if 40 + int.from_bytes(payload[4:6], "big") == len(payload):
            return payload
    return None


def _transport_ip_packet(src: str, dst: str, next_header: int, payload: bytes) -> Optional[bytes]:
    """A transport-mode payload given back the outer IP header (its addresses), so detectors can read it."""
    try:
        from scapy.all import IP, IPv6, Raw
        layer = IPv6(src=src, dst=dst, nh=next_header) if ":" in src else IP(src=src, dst=dst, proto=next_header)
        return bytes(layer / Raw(payload))
    except Exception:  # noqa: BLE001 - an address scapy refuses is skipped, not fatal
        return None
