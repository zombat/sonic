#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Network Detector Common Helpers

Shared vocabulary for the non-SIP network detectors: issue and event builders,
status rules, protocol labels, and the code-to-name tables (IKE, NHRP, BGP,
OSPF, EIGRP, ICMP) that turn numbers on the wire into words.

Every detector produces plain dicts that json.dumps can serialize, with:
    detector   the detector name
    status     "ok" | "warning" | "problem" | "not_present"
    verdict    one plain sentence
    issues     [{"severity": "error"|"warning"|"info", "code", "message", "frames"}]
    events     timeline entries (merged into the combined report's timeline)

Author: Raymond A Rizzo | Zombat
"""

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

STATUS_ORDER = {"not_present": 0, "ok": 1, "warning": 2, "problem": 3}
SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}
MAX_FRAMES = 10


class Context:
    """Capture-wide facts every detector report needs."""

    def __init__(self, start: Optional[float], end: Optional[float], max_items: int = 25):
        self.start = start
        self.end = end
        self.max_items = max_items

    def rel(self, t: Optional[float]) -> Optional[float]:
        """Seconds since the first frame, rounded to the millisecond."""
        if t is None or self.start is None:
            return None
        return round(t - self.start, 3)


def iso_time(t: Optional[float]) -> Optional[str]:
    """Epoch seconds to an ISO-8601 UTC string with milliseconds."""
    if t is None:
        return None
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_issue(severity: str, code: str, message: str, frames: Optional[Iterable[int]] = None, **details) -> Dict[str, Any]:
    """Build one issue. frames are Wireshark frame numbers (first few only)."""
    issue = {"severity": severity, "code": code, "message": message,
             "frames": list(frames)[:MAX_FRAMES] if frames else []}
    issue.update(details)
    return issue


def make_event(ctx: Context, t: float, protocol: str, event: str, detail: str, frame: Optional[int] = None) -> Dict[str, Any]:
    """Build one timeline event."""
    return {"t": ctx.rel(t), "time": iso_time(t), "protocol": protocol, "event": event,
            "detail": detail, "frame": frame}


def status_from_issues(issues: List[Dict[str, Any]], present: bool) -> str:
    """not_present when nothing relevant was seen; else the worst issue decides."""
    if not present:
        return "not_present"
    severities = {issue["severity"] for issue in issues}
    if "error" in severities:
        return "problem"
    if "warning" in severities:
        return "warning"
    return "ok"


def worst_status(statuses: Iterable[str]) -> str:
    """The most severe status in the list (not_present when the list is empty)."""
    worst = "not_present"
    for status in statuses:
        if STATUS_ORDER.get(status, 0) > STATUS_ORDER[worst]:
            worst = status
    return worst


def sort_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(issues, key=lambda issue: SEVERITY_ORDER.get(issue["severity"], 9))


def ip_sort_key(addr: str):
    """Sort addresses numerically (IPv4 before IPv6), falling back to text."""
    try:
        parsed = ipaddress.ip_address(addr)
        return (parsed.version, int(parsed))
    except (ValueError, TypeError):
        return (9, 0)


def pair_key(a: str, b: str) -> Tuple[str, str]:
    """An unordered address pair in a stable order."""
    return tuple(sorted((a, b), key=ip_sort_key))


def cap(items: List[Any], limit: int) -> Tuple[List[Any], int]:
    """First `limit` items and the number left out."""
    if limit is None or len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def add_frame(frames: List[int], frame: int):
    if len(frames) < MAX_FRAMES:
        frames.append(frame)


def median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


# ---------------------------------------------------------------------------
# Protocol labels
# ---------------------------------------------------------------------------

SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 49: "tacacs", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 123: "ntp", 161: "snmp", 162: "snmp-trap",
    179: "bgp", 443: "https", 500: "ike", 514: "syslog", 520: "rip", 646: "ldp", 830: "netconf",
    1812: "radius", 1813: "radius-acct", 1985: "hsrp", 3784: "bfd", 3785: "bfd-echo",
    4500: "ipsec-nat-t", 4789: "vxlan", 5060: "sip", 5061: "sips", 6633: "openflow", 6653: "openflow",
}

IP_PROTOCOL_NAMES = {1: "icmp", 2: "igmp", 4: "ipip", 6: "tcp", 17: "udp", 41: "ipv6-in-ipv4",
                     47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 88: "eigrp", 89: "ospf",
                     103: "pim", 112: "vrrp", 115: "l2tp", 132: "sctp"}

ETHERTYPE_NAMES = {0x0806: "arp", 0x8035: "rarp", 0x8100: "vlan", 0x88CC: "lldp", 0x8847: "mpls",
                   0x8863: "pppoe-discovery", 0x8864: "pppoe", 0x88A8: "qinq", 0x8809: "lacp", 0x9000: "loopback"}

PROTECTED_LABELS = {"esp", "esp-in-udp", "ike", "nat-keepalive", "ah"}


def service_port(sport: Optional[int], dport: Optional[int]) -> Optional[int]:
    """The port that names the service: the well-known side when there is one."""
    if sport is None or dport is None:
        return dport if dport is not None else sport
    for port in (dport, sport):
        if port in SERVICE_NAMES:
            return port
    if dport <= 1023 or sport <= 1023:
        return min(sport, dport)
    return min(sport, dport) if min(sport, dport) <= 49151 else dport


def protocol_label(rec: Dict[str, Any]) -> str:
    """
    One label per frame, used for protocol counts and for the encrypted/cleartext
    split: esp, esp-in-udp, ike, nat-keepalive, gre/nhrp, gre/ipv4, gre, ospf,
    eigrp, icmp, icmpv6, tcp/<port>, udp/<port>, ip-proto-<n>, arp, ethertype-0x<n>.
    """
    if "esp" in rec:
        return "esp-in-udp" if rec["esp"].get("udp") else "esp"
    if "ike" in rec:
        return "ike"
    if rec.get("nat_keepalive"):
        return "nat-keepalive"
    if "gre" in rec:
        ptype = rec["gre"].get("ptype")
        if ptype == 0x2001:
            return "gre/nhrp"
        if ptype == 0x0800:
            return "gre/ipv4"
        if ptype == 0x86DD:
            return "gre/ipv6"
        return "gre"
    ip = rec.get("ip")
    if not ip:
        if "arp" in rec:
            return "arp"
        eth_type = rec.get("eth_type")
        if eth_type is not None:
            return ETHERTYPE_NAMES.get(eth_type, f"ethertype-0x{eth_type:04x}")
        return "other"
    proto = ip.get("proto")
    if "tcp" in rec:
        return f"tcp/{service_port(rec['tcp']['sport'], rec['tcp']['dport'])}"
    if "udp" in rec:
        return f"udp/{service_port(rec['udp']['sport'], rec['udp']['dport'])}"
    if proto in IP_PROTOCOL_NAMES:
        return IP_PROTOCOL_NAMES[proto]
    return f"ip-proto-{proto}"


def label_service(label: str) -> Optional[str]:
    """The service name for a tcp/<port> or udp/<port> label, when known."""
    if "/" in label and label.split("/")[0] in ("tcp", "udp"):
        try:
            return SERVICE_NAMES.get(int(label.split("/")[1]))
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Code tables
# ---------------------------------------------------------------------------

IKEV2_EXCHANGES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
                   38: "IKE_SESSION_RESUME", 43: "IKE_INTERMEDIATE", 44: "IKE_FOLLOWUP_KE"}
IKEV1_EXCHANGES = {1: "Base", 2: "Main Mode", 3: "Authentication Only", 4: "Aggressive Mode",
                   5: "Informational", 6: "Transaction (Config Mode)", 32: "Quick Mode", 33: "New Group Mode"}

IKEV2_NOTIFY = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 40: "UNACCEPTABLE_ADDRESSES",
    41: "UNEXPECTED_NAT_DETECTED", 43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND",
    45: "INVALID_GROUP_ID", 46: "AUTHORIZATION_FAILED",
    16384: "INITIAL_CONTACT", 16385: "SET_WINDOW_SIZE", 16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED", 16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE", 16391: "USE_TRANSPORT_MODE", 16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA", 16394: "ESP_TFC_PADDING_NOT_SUPPORTED", 16395: "NON_FIRST_FRAGMENTS_ALSO",
    16396: "MOBIKE_SUPPORTED", 16404: "MULTIPLE_AUTH_SUPPORTED", 16406: "EAP_ONLY_AUTHENTICATION",
    16418: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
}
IKEV2_NOTIFY_HINTS = {
    14: "the peers share no common proposal: compare the IKEv2 proposal (encryption, integrity, PRF, DH group) on both ends",
    17: "the initiator offered a DH group the responder does not accept; it normally retries with the group the responder names",
    24: "pre-shared key, certificate or identity mismatch",
    38: "traffic selectors (crypto ACL / proxy identities) do not match",
    7: "a malformed message, often a mismatched IKE version or proposal syntax",
    4: "the peer has no IKE SA for this SPI (it restarted or cleared its SAs)",
    11: "the peer has no IPsec SA for this SPI (stale SA after a rekey or restart)",
    43: "the peer is busy (rekey collision); a retry normally succeeds",
}
IKEV1_NOTIFY = {
    1: "INVALID-PAYLOAD-TYPE", 2: "DOI-NOT-SUPPORTED", 3: "SITUATION-NOT-SUPPORTED", 4: "INVALID-COOKIE",
    5: "INVALID-MAJOR-VERSION", 6: "INVALID-MINOR-VERSION", 7: "INVALID-EXCHANGE-TYPE", 8: "INVALID-FLAGS",
    9: "INVALID-MESSAGE-ID", 10: "INVALID-PROTOCOL-ID", 11: "INVALID-SPI", 12: "INVALID-TRANSFORM-ID",
    13: "ATTRIBUTES-NOT-SUPPORTED", 14: "NO-PROPOSAL-CHOSEN", 15: "BAD-PROPOSAL-SYNTAX",
    16: "PAYLOAD-MALFORMED", 17: "INVALID-KEY-INFORMATION", 18: "INVALID-ID-INFORMATION",
    19: "INVALID-CERT-ENCODING", 20: "INVALID-CERTIFICATE", 21: "CERT-TYPE-UNSUPPORTED",
    22: "INVALID-CERT-AUTHORITY", 23: "INVALID-HASH-INFORMATION", 24: "AUTHENTICATION-FAILED",
    25: "INVALID-SIGNATURE", 26: "ADDRESS-NOTIFICATION", 27: "NOTIFY-SA-LIFETIME",
    28: "CERTIFICATE-UNAVAILABLE", 29: "UNSUPPORTED-EXCHANGE-TYPE", 30: "UNEQUAL-PAYLOAD-LENGTHS",
    24576: "RESPONDER-LIFETIME", 24577: "REPLAY-STATUS", 24578: "INITIAL-CONTACT",
    36136: "R-U-THERE", 36137: "R-U-THERE-ACK",
}


def ike_notify_name(version: int, code: int) -> str:
    table = IKEV2_NOTIFY if version == 2 else IKEV1_NOTIFY
    return table.get(code, f"NOTIFY_{code}")


def ike_notify_is_error(version: int, code: int) -> bool:
    return code < (16384 if version == 2 else 8192)


NHRP_OPS = {1: "resolution_request", 2: "resolution_reply", 3: "registration_request",
            4: "registration_reply", 5: "purge_request", 6: "purge_reply", 7: "error_indication",
            8: "traffic_indication"}
NHRP_CIE_CODES = {0: "Success", 4: "Administratively Prohibited", 5: "Insufficient Resources",
                  12: "No Internetworking Layer Address to NBMA Address Binding Exists",
                  13: "Binding Exists But Is Not Unique", 14: "Unique Internetworking Layer Address Already Registered"}
NHRP_ERROR_CODES = {1: "Unrecognized Extension", 3: "NHRP Loop Detected", 6: "Protocol Address Unreachable",
                    7: "Protocol Error", 8: "NHRP SDU Size Exceeded", 9: "Invalid Extension",
                    10: "Invalid NHRP Resolution Reply Received", 11: "Authentication Failure",
                    15: "Hop Count Exceeded"}

BGP_TYPES = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}
BGP_ERRORS = {
    1: ("Message Header Error", {1: "Connection Not Synchronized", 2: "Bad Message Length", 3: "Bad Message Type"}),
    2: ("OPEN Message Error", {1: "Unsupported Version Number", 2: "Bad Peer AS", 3: "Bad BGP Identifier",
                               4: "Unsupported Optional Parameter", 6: "Unacceptable Hold Time",
                               7: "Unsupported Capability", 8: "Role Mismatch"}),
    3: ("UPDATE Message Error", {1: "Malformed Attribute List", 2: "Unrecognized Well-known Attribute",
                                 3: "Missing Well-known Attribute", 4: "Attribute Flags Error",
                                 5: "Attribute Length Error", 6: "Invalid ORIGIN Attribute",
                                 8: "Invalid NEXT_HOP Attribute", 9: "Optional Attribute Error",
                                 10: "Invalid Network Field", 11: "Malformed AS_PATH"}),
    4: ("Hold Timer Expired", {}),
    5: ("Finite State Machine Error", {1: "Unexpected Message in OpenSent", 2: "Unexpected Message in OpenConfirm",
                                       3: "Unexpected Message in Established"}),
    6: ("Cease", {1: "Maximum Number of Prefixes Reached", 2: "Administrative Shutdown", 3: "Peer De-configured",
                  4: "Administrative Reset", 5: "Connection Rejected", 6: "Other Configuration Change",
                  7: "Connection Collision Resolution", 8: "Out of Resources", 9: "Hard Reset", 10: "BFD Down"}),
    7: ("ROUTE-REFRESH Message Error", {1: "Invalid Message Length"}),
}
BGP_ERROR_HINTS = {
    (2, 2): "the AS this speaker sent does not match the remote-as configured on the receiver",
    (2, 3): "duplicate or invalid BGP router ID",
    (2, 6): "a hold time of 1 or 2 seconds was proposed (not allowed)",
    (2, 7): "a required capability (address family, 4-byte AS) is not supported by the peer",
    (4, None): "no KEEPALIVE or UPDATE arrived within the hold time: peer down, path to it lost, or TCP 179 filtered",
    (6, 2): "the neighbor was shut down by configuration",
    (6, 3): "the neighbor was removed from the configuration",
    (6, 4): "the session was cleared administratively (clear ip bgp)",
    (6, 5): "the receiver has no neighbor statement for this source address",
    (6, 6): "a configuration change forced a reset",
    (6, 7): "two TCP connections collided; one was closed (normal and harmless)",
    (6, 10): "BFD declared the neighbor down",
}


def bgp_error_name(major: Optional[int], minor: Optional[int]) -> str:
    if major is None:
        return "unknown"
    name, subcodes = BGP_ERRORS.get(major, (f"error {major}", {}))
    if subcodes and minor is not None:
        return f"{name} / {subcodes.get(minor, f'subcode {minor}')}"
    return name


def bgp_error_hint(major: Optional[int], minor: Optional[int]) -> Optional[str]:
    return BGP_ERROR_HINTS.get((major, minor)) or BGP_ERROR_HINTS.get((major, None))


OSPF_TYPES = {1: "Hello", 2: "DB Description", 3: "LS Request", 4: "LS Update", 5: "LS Ack"}
EIGRP_OPCODES = {1: "Update", 3: "Query", 4: "Reply", 5: "Hello", 6: "IPX SAP", 10: "SIA-Query", 11: "SIA-Reply"}

ICMP_TYPES = {0: "echo_reply", 3: "destination_unreachable", 4: "source_quench", 5: "redirect",
              8: "echo_request", 11: "time_exceeded", 12: "parameter_problem"}
ICMP_UNREACH_CODES = {0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable",
                      3: "port unreachable", 4: "fragmentation needed and DF set", 5: "source route failed",
                      6: "destination network unknown", 7: "destination host unknown",
                      9: "network administratively prohibited", 10: "host administratively prohibited",
                      11: "network unreachable for ToS", 12: "host unreachable for ToS",
                      13: "communication administratively prohibited (ACL)", 14: "host precedence violation",
                      15: "precedence cutoff"}
ICMP_TIME_EXCEEDED_CODES = {0: "TTL exceeded in transit", 1: "fragment reassembly time exceeded"}
ICMP_REDIRECT_CODES = {0: "redirect for network", 1: "redirect for host", 2: "redirect for ToS and network",
                       3: "redirect for ToS and host"}
ICMPV6_TYPES = {1: "destination_unreachable", 2: "packet_too_big", 3: "time_exceeded", 4: "parameter_problem",
                128: "echo_request", 129: "echo_reply"}
ICMPV6_UNREACH_CODES = {0: "no route to destination", 1: "administratively prohibited", 2: "beyond scope of source",
                        3: "address unreachable", 4: "port unreachable", 5: "source address failed policy",
                        6: "reject route"}


def icmp_describe(v6: bool, icmp_type: int, code: int) -> Tuple[str, str]:
    """(type name, code description) for an ICMP or ICMPv6 message."""
    if v6:
        name = ICMPV6_TYPES.get(icmp_type, f"type_{icmp_type}")
        if icmp_type == 1:
            return name, ICMPV6_UNREACH_CODES.get(code, f"code {code}")
        if icmp_type == 3:
            return name, "hop limit exceeded in transit" if code == 0 else "fragment reassembly time exceeded"
        return name, f"code {code}"
    name = ICMP_TYPES.get(icmp_type, f"type_{icmp_type}")
    if icmp_type == 3:
        return name, ICMP_UNREACH_CODES.get(code, f"code {code}")
    if icmp_type == 11:
        return name, ICMP_TIME_EXCEEDED_CODES.get(code, f"code {code}")
    if icmp_type == 5:
        return name, ICMP_REDIRECT_CODES.get(code, f"code {code}")
    return name, f"code {code}"
