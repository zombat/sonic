#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. IPsec / VPN Detector

Deterministic analysis of IKE and ESP traffic, answering three questions from
packets alone:

1. Did IKE negotiate? Per IKE SA (keyed by initiator SPI): IKEv2 IKE_SA_INIT and
   IKE_AUTH outcomes, cleartext NOTIFY errors (NO_PROPOSAL_CHOSEN,
   INVALID_KE_PAYLOAD, ...), requests retransmitted without a reply, rekeys
   (CREATE_CHILD_SA), and IKEv1 Main/Aggressive/Quick Mode progress.
2. Is ESP flowing? Per SPI and direction: packets, bytes, sequence gaps,
   duplicates (possible replay), out-of-order arrivals, SPI changes (rekeys).
   NAT-T: IKE floated to UDP 4500 (non-ESP marker), ESP-in-UDP, keepalives.
3. Is the traffic between the VPN peers encrypted? Every packet between the
   same two addresses is classed as protected (ESP, IKE, NAT-T keepalive) or
   cleartext (ICMP, GRE without ESP, TCP/UDP payload, OSPF, ...).

What packets cannot show, and the detector says so rather than guessing:
- IKEv2 IKE_AUTH content is encrypted, so AUTHENTICATION_FAILED is never visible.
  The detector reports "established" only when ESP follows, and flags a small
  IKE_AUTH response (the size of an encrypted error notification) as a likely
  failure, labelled as a heuristic.
- ESP with NULL encryption looks like any other ESP without keys.
- The verdict covers only what crossed the capture point.

Author: Raymond A Rizzo | Zombat
"""

from collections import Counter, deque
from typing import Any, Dict, List, Optional

from analyzers.network_common import (
    IKEV1_EXCHANGES, IKEV2_EXCHANGES, IKEV2_NOTIFY_HINTS, PROTECTED_LABELS, Context, add_frame, cap,
    ike_notify_is_error, ike_notify_name, make_event, make_issue, pair_key, protocol_label, sort_issues,
    status_from_issues,
)

# An IKEv2 IKE_AUTH response this small carries no SA/TS/AUTH payloads: it is
# almost always an encrypted error notification. 28-byte header + SK payload
# (4) + IV (8-16) + one encrypted notify (8) + padding + ICV (12-16) <= ~100.
SMALL_IKE_AUTH_RESPONSE = 112
REPLAY_WINDOW = 2048


class _EspFlow:
    """Per-SPI, per-direction ESP counters."""

    __slots__ = ("src", "dst", "spi", "udp", "packets", "bytes", "first_t", "last_t", "first_seq",
                 "max_seq", "missing", "duplicates", "out_of_order", "window", "window_set", "frames",
                 "dup_frames")

    def __init__(self, src, dst, spi, udp):
        self.src, self.dst, self.spi, self.udp = src, dst, spi, udp
        self.packets = self.bytes = 0
        self.first_t = self.last_t = None
        self.first_seq = self.max_seq = None
        self.missing = self.duplicates = self.out_of_order = 0
        self.window = deque()
        self.window_set = set()
        self.frames: List[int] = []
        self.dup_frames: List[int] = []

    def feed(self, rec):
        seq = rec["esp"]["seq"]
        self.packets += 1
        self.bytes += rec["len"]
        if self.first_t is None:
            self.first_t = rec["t"]
        self.last_t = rec["t"]
        add_frame(self.frames, rec["n"])
        if seq is None:
            return
        if self.first_seq is None:
            self.first_seq = self.max_seq = seq
        elif seq > self.max_seq:
            self.missing += seq - self.max_seq - 1
            self.max_seq = seq
        elif seq in self.window_set:
            self.duplicates += 1
            add_frame(self.dup_frames, rec["n"])
            return
        else:
            self.out_of_order += 1
            self.missing = max(self.missing - 1, 0)
        self.window.append(seq)
        self.window_set.add(seq)
        if len(self.window) > REPLAY_WINDOW:
            self.window_set.discard(self.window.popleft())


class _IkeSa:
    """One IKE SA, keyed by the initiator SPI."""

    def __init__(self, ispi, version):
        self.ispi = ispi
        self.version = version
        self.rspi = None
        self.initiator = None
        self.responder = None
        self.ports = set()
        self.natt = False
        self.first_t = self.last_t = None
        self.frames: List[int] = []
        # (exchange, message id) -> state
        self.exchanges: Dict[tuple, Dict[str, Any]] = {}
        self.order: List[tuple] = []
        self.notifies: List[Dict[str, Any]] = []
        self.messages_by_side = Counter()
        self.ikev1_counts = Counter()


class IPsecDetector:
    """Streaming IPsec/IKE/ESP detector. Feed records, then call report()."""

    name = "ipsec"

    def __init__(self, peers: Optional[List[str]] = None):
        self.peers = set(peers or [])
        self.sas: Dict[str, _IkeSa] = {}
        self.esp: Dict[tuple, _EspFlow] = {}
        self.pairs: Dict[tuple, Dict[str, Any]] = {}
        self.keepalives = 0
        self.keepalive_frames: List[int] = []
        self.ike_packets = 0
        self.ike_on_4500 = 0
        self.nat_detection = False
        self.seen_ipsec = False

    # -- feeding -----------------------------------------------------------

    def feed(self, rec: Dict[str, Any]):
        ip = rec.get("ip")
        if not ip:
            return
        src, dst = ip["src"], ip["dst"]
        label = protocol_label(rec)
        key = pair_key(src, dst)
        pair = self.pairs.get(key)
        if pair is None:
            pair = {"protected": Counter(), "cleartext": {}, "esp_after": None, "first_t": rec["t"]}
            self.pairs[key] = pair
        if label in PROTECTED_LABELS:
            pair["protected"][label] += 1
        else:
            entry = pair["cleartext"].get((label, src, dst))
            if entry is None:
                entry = {"packets": 0, "bytes": 0, "frames": [], "first_t": rec["t"]}
                pair["cleartext"][(label, src, dst)] = entry
            entry["packets"] += 1
            entry["bytes"] += rec["len"]
            add_frame(entry["frames"], rec["n"])

        if "ike" in rec:
            self.seen_ipsec = True
            self._feed_ike(rec, src, dst)
        if "esp" in rec:
            self.seen_ipsec = True
            esp = rec["esp"]
            flow_key = (src, dst, esp["spi"])
            flow = self.esp.get(flow_key)
            if flow is None:
                flow = _EspFlow(src, dst, esp["spi"], esp["udp"])
                self.esp[flow_key] = flow
            flow.feed(rec)
        if rec.get("nat_keepalive"):
            self.seen_ipsec = True
            self.keepalives += 1
            add_frame(self.keepalive_frames, rec["n"])

    def _feed_ike(self, rec, src, dst):
        ike = rec["ike"]
        self.ike_packets += 1
        if ike["natt"]:
            self.ike_on_4500 += 1
        if 16388 in ike["notify"] or 16389 in ike["notify"]:
            self.nat_detection = True
        sa = self.sas.get(ike["ispi"])
        if sa is None:
            sa = _IkeSa(ike["ispi"], ike["version"])
            self.sas[ike["ispi"]] = sa
        if sa.first_t is None:
            sa.first_t = rec["t"]
        sa.last_t = rec["t"]
        add_frame(sa.frames, rec["n"])
        if ike["rspi"] and ike["rspi"].strip("0"):
            sa.rspi = sa.rspi or ike["rspi"]
        if "udp" in rec:
            sa.ports.add(rec["udp"]["dport"])
        sa.natt = sa.natt or ike["natt"]

        if ike["version"] == 2:
            is_response = bool(ike["flags"] & 0x20)
            from_initiator = bool(ike["flags"] & 0x08)
            if sa.initiator is None:
                if from_initiator:
                    sa.initiator, sa.responder = src, dst
                else:
                    sa.initiator, sa.responder = dst, src
        else:
            if sa.initiator is None:
                sa.initiator, sa.responder = src, dst
            is_response = src != sa.initiator
            sa.ikev1_counts[(ike["exch"], "responder" if is_response else "initiator")] += 1
        sa.messages_by_side["responder" if src == sa.responder else "initiator"] += 1

        ex_key = (ike["exch"], ike["msgid"])
        ex = sa.exchanges.get(ex_key)
        if ex is None:
            ex = {"requests": 0, "responses": 0, "retransmissions": 0, "awaiting": False,
                  "first_t": rec["t"], "last_t": rec["t"], "req_frames": [], "resp_frames": [],
                  "resp_lengths": [], "resp_notifies": [], "req_notifies": [],
                  "encrypted": ike["encrypted"]}
            sa.exchanges[ex_key] = ex
            sa.order.append(ex_key)
        ex["last_t"] = rec["t"]
        if is_response:
            ex["responses"] += 1
            ex["awaiting"] = False
            add_frame(ex["resp_frames"], rec["n"])
            ex["resp_lengths"].append(ike["length"])
            ex["resp_notifies"].append(list(ike["notify"]))
        else:
            if ex["awaiting"]:
                ex["retransmissions"] += 1
            ex["requests"] += 1
            ex["awaiting"] = True
            add_frame(ex["req_frames"], rec["n"])
            ex["req_notifies"].append(list(ike["notify"]))
        for code in ike["notify"]:
            sa.notifies.append({"type": code, "name": ike_notify_name(ike["version"], code),
                                "from": src, "to": dst, "frame": rec["n"], "t": rec["t"],
                                "exchange": ike["exch"], "error": ike_notify_is_error(ike["version"], code)})

    # -- reporting ---------------------------------------------------------

    def present(self) -> bool:
        return self.seen_ipsec or self._candidate_pairs() != []

    def _candidate_pairs(self) -> List[tuple]:
        """Address pairs the encryption verdict judges."""
        if self.peers:
            return [key for key in self.pairs if key[0] in self.peers and key[1] in self.peers]
        out = []
        for key, pair in self.pairs.items():
            if pair["protected"]:
                out.append(key)
            elif any(label.startswith("gre") for (label, _, _) in pair["cleartext"]):
                out.append(key)
        return out

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []

        esp_pairs = {}
        for flow in self.esp.values():
            esp_pairs.setdefault(pair_key(flow.src, flow.dst), []).append(flow)

        ike_sas = [self._report_sa(sa, ctx, esp_pairs, issues, events) for sa in
                   sorted(self.sas.values(), key=lambda s: s.first_t or 0)]
        esp_flows = self._report_esp(ctx, issues, events)
        encryption = self._report_encryption(ctx, issues)
        nat = self._report_nat()

        present = self.present()
        status = status_from_issues(issues, present)
        if not present:
            verdict = "No IPsec (IKE/ESP) or GRE tunnel traffic in this capture."
        else:
            verdict = encryption["verdict"]
        negotiation = self._negotiation_verdict(ike_sas)
        if present and any(sa["outcome"] != "established" for sa in ike_sas):
            verdict = f"{verdict}; IKE: {negotiation}"
        ike_list, ike_omitted = cap(ike_sas, ctx.max_items)
        esp_list, esp_omitted = cap(esp_flows, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "encryption_verdict": encryption["code"],
            "negotiation_verdict": negotiation,
            "summary": {
                "ike_packets": self.ike_packets,
                "ike_sas": len(self.sas),
                "ike_sas_established": sum(1 for sa in ike_sas if sa["outcome"] == "established"),
                "esp_flows": len(self.esp),
                "esp_packets": sum(flow.packets for flow in self.esp.values()),
                "nat_keepalives": self.keepalives,
            },
            "peer_pairs": encryption["pairs"],
            "peer_pairs_omitted": encryption["omitted"],
            "cleartext": encryption["cleartext"],
            "ike_sas": ike_list,
            "ike_sas_omitted": ike_omitted,
            "esp_flows": esp_list,
            "esp_flows_omitted": esp_omitted,
            "nat_traversal": nat,
            "issues": sort_issues(issues),
            "events": events,
        }

    def _report_sa(self, sa: _IkeSa, ctx: Context, esp_pairs, issues, events) -> Dict[str, Any]:
        exchange_names = IKEV2_EXCHANGES if sa.version == 2 else IKEV1_EXCHANGES
        exchanges = []
        retransmissions = 0
        for ex_key in sa.order:
            ex = sa.exchanges[ex_key]
            retransmissions += ex["retransmissions"]
            exchanges.append({
                "exchange": exchange_names.get(ex_key[0], f"exchange_{ex_key[0]}"),
                "message_id": ex_key[1],
                "requests": ex["requests"],
                "responses": ex["responses"],
                "retransmissions": ex["retransmissions"],
                "unanswered": ex["awaiting"] and sa.version == 2,
                "encrypted": ex["encrypted"],
                "t": ctx.rel(ex["first_t"]),
                "request_frames": ex["req_frames"],
                "response_frames": ex["resp_frames"],
            })
        pair = pair_key(sa.initiator, sa.responder) if sa.initiator and sa.responder else None
        esp_after = [flow for flow in esp_pairs.get(pair, []) if flow.last_t and flow.last_t >= (sa.first_t or 0)]
        label = f"{sa.initiator} -> {sa.responder}"
        frames = sa.frames
        rekeys = 0
        if sa.version == 2:
            outcome, detail = self._ikev2_outcome(sa, esp_after, label, ctx, issues, events)
            rekeys = sum(1 for (exch, _), ex in sa.exchanges.items() if exch == 36 and ex["responses"] > 0)
        else:
            outcome, detail = self._ikev1_outcome(sa, esp_after, label, ctx, issues, events)
            rekeys = max(sum(1 for (exch, _) in sa.exchanges if exch == 32) - 1, 0)
        if rekeys:
            events.append(make_event(ctx, sa.last_t, "ike", "rekey",
                                     f"{rekeys} rekey exchange(s) on IKE SA {sa.ispi} ({label})"))
        notify_list = [{"type": n["type"], "name": n["name"], "from": n["from"], "frame": n["frame"],
                        "error": n["error"]} for n in sa.notifies]
        return {
            "ike_version": sa.version,
            "initiator_spi": sa.ispi,
            "responder_spi": sa.rspi,
            "initiator": sa.initiator,
            "responder": sa.responder,
            "udp_ports": sorted(sa.ports),
            "nat_t": sa.natt,
            "outcome": outcome,
            "detail": detail,
            "retransmissions": retransmissions,
            "rekeys": rekeys,
            "notifies": notify_list[:20],
            "exchanges": exchanges[:20],
            "first_t": ctx.rel(sa.first_t),
            "last_t": ctx.rel(sa.last_t),
            "frames": frames,
        }

    def _ikev2_outcome(self, sa, esp_after, label, ctx, issues, events):
        init = [sa.exchanges[k] for k in sa.order if k[0] == 34]
        auth = [sa.exchanges[k] for k in sa.order if k[0] == 35]
        if not init and not auth:
            # Mid-SA capture: only CREATE_CHILD_SA / INFORMATIONAL seen.
            if esp_after:
                return "established", "IKE SA was already up when the capture began; ESP is flowing"
            return "in_progress", "only post-authentication exchanges were captured"
        if init:
            ex = init[-1]
            if ex["responses"] == 0:
                issues.append(make_issue(
                    "error", "IKE_NO_RESPONSE",
                    f"{sa.responder} never answered IKE_SA_INIT from {sa.initiator} "
                    f"({ex['requests']} request(s), {ex['retransmissions']} retransmission(s)): "
                    "UDP 500 blocked, wrong peer address, or IKE not configured on the peer",
                    ex["req_frames"], initiator=sa.initiator, responder=sa.responder))
                events.append(make_event(ctx, ex["first_t"], "ike", "no_response",
                                         f"IKE_SA_INIT {label} unanswered", ex["req_frames"][0]))
                return "no_response", f"IKE_SA_INIT sent {ex['requests']} time(s), never answered"
            last_notifies = ex["resp_notifies"][-1] if ex["resp_notifies"] else []
            errors = [code for code in last_notifies if ike_notify_is_error(2, code)]
            if errors:
                names = ", ".join(ike_notify_name(2, code) for code in errors)
                hint = IKEV2_NOTIFY_HINTS.get(errors[0], "")
                issues.append(make_issue(
                    "error", f"IKE_{ike_notify_name(2, errors[0])}",
                    f"{sa.responder} refused IKE_SA_INIT from {sa.initiator}: {names}"
                    + (f" ({hint})" if hint else "") + f"; {ex['requests']} attempt(s)",
                    ex["resp_frames"], notify=names))
                events.append(make_event(ctx, ex["first_t"], "ike", "negotiation_failed",
                                         f"IKE_SA_INIT {label} refused: {names}", ex["resp_frames"][0]))
                return "failed", f"IKE_SA_INIT refused: {names}"
            earlier = sorted({code for notes in ex["resp_notifies"][:-1] for code in notes
                              if ike_notify_is_error(2, code) or code == 16390})
            if earlier:
                issues.append(make_issue(
                    "info", "IKE_RETRIED",
                    f"IKE_SA_INIT {label} succeeded after a retry ({', '.join(ike_notify_name(2, c) for c in earlier)})",
                    ex["resp_frames"]))
        if not auth:
            if esp_after:
                return "established", "ESP flows between the peers (IKE_AUTH not captured)"
            return "sa_init_only", "IKE_SA_INIT completed; IKE_AUTH not seen"
        ex = auth[-1]
        if ex["responses"] == 0:
            issues.append(make_issue(
                "error", "IKE_AUTH_NO_RESPONSE",
                f"{sa.responder} never answered IKE_AUTH from {sa.initiator} ({ex['requests']} request(s)): "
                "often a large IKE_AUTH (certificates) fragmented and dropped, or the responder silently rejecting it",
                ex["req_frames"]))
            events.append(make_event(ctx, ex["first_t"], "ike", "no_response",
                                     f"IKE_AUTH {label} unanswered", ex["req_frames"][0]))
            return "auth_no_response", "IKE_AUTH sent, never answered"
        resp_len = ex["resp_lengths"][-1] if ex["resp_lengths"] else 0
        if esp_after:
            events.append(make_event(ctx, ex["first_t"], "ike", "established",
                                     f"IKE SA {label} established (IKE_AUTH answered, ESP followed)",
                                     ex["resp_frames"][0]))
            return "established", "IKE_SA_INIT and IKE_AUTH completed and ESP followed"
        if resp_len and resp_len <= SMALL_IKE_AUTH_RESPONSE:
            issues.append(make_issue(
                "warning", "IKE_AUTH_LIKELY_FAILED",
                f"IKE_AUTH response from {sa.responder} is only {resp_len} bytes and no ESP followed: "
                "the size of an encrypted error notification (often AUTHENTICATION_FAILED or TS_UNACCEPTABLE). "
                "Heuristic: the payload is encrypted and cannot be read",
                ex["resp_frames"], response_length=resp_len))
            return "auth_likely_failed", f"IKE_AUTH answered with a {resp_len}-byte response and no ESP followed"
        issues.append(make_issue(
            "info", "IKE_NO_ESP_YET",
            f"IKE_AUTH {label} completed but no ESP was seen afterwards (no traffic yet, or the capture ended)",
            ex["resp_frames"]))
        return "authenticated_no_esp", "IKE_AUTH completed; no ESP seen afterwards"

    def _ikev1_outcome(self, sa, esp_after, label, ctx, issues, events):
        counts = sa.ikev1_counts
        errors = [n for n in sa.notifies if n["error"]]
        if errors:
            names = ", ".join(sorted({n["name"] for n in errors}))
            issues.append(make_issue("error", f"IKEV1_{errors[0]['name'].replace('-', '_')}",
                                     f"IKEv1 {label}: {names} (cleartext notification)",
                                     [n["frame"] for n in errors]))
            events.append(make_event(ctx, errors[0]["t"], "ike", "negotiation_failed",
                                     f"IKEv1 {label}: {names}", errors[0]["frame"]))
            return "failed", f"IKEv1 notification: {names}"
        phase1_init = counts[(2, "initiator")] + counts[(4, "initiator")]
        phase1_resp = counts[(2, "responder")] + counts[(4, "responder")]
        quick = counts[(32, "initiator")] + counts[(32, "responder")]
        if phase1_init and not phase1_resp:
            issues.append(make_issue("error", "IKE_NO_RESPONSE",
                                     f"{sa.responder} never answered IKEv1 phase 1 from {sa.initiator} "
                                     f"({phase1_init} message(s))", sa.frames))
            return "no_response", "IKEv1 phase 1 never answered"
        if esp_after:
            events.append(make_event(ctx, sa.last_t, "ike", "established",
                                     f"IKEv1 SA {label} established (ESP followed)", sa.frames[-1]))
            return "established", "IKEv1 negotiated and ESP followed"
        if quick:
            return "phase2_seen", "IKEv1 Quick Mode seen; no ESP afterwards"
        if phase1_init and phase1_resp:
            return "phase1_seen", "IKEv1 phase 1 exchanged; no Quick Mode or ESP seen"
        return "in_progress", "IKEv1 messages seen; outcome not determinable"

    def _report_esp(self, ctx: Context, issues, events) -> List[Dict[str, Any]]:
        flows = sorted(self.esp.values(), key=lambda f: (f.first_t or 0))
        out = []
        by_direction: Dict[tuple, List[_EspFlow]] = {}
        for flow in flows:
            by_direction.setdefault((flow.src, flow.dst), []).append(flow)
            if flow.duplicates:
                issues.append(make_issue(
                    "warning", "ESP_DUPLICATE_SEQUENCE",
                    f"ESP SPI 0x{flow.spi:08x} {flow.src}->{flow.dst}: {flow.duplicates} packet(s) repeated a sequence "
                    "number already seen (possible replay, or the capture saw the same packet twice)",
                    flow.dup_frames, spi=f"0x{flow.spi:08x}"))
            if flow.missing:
                issues.append(make_issue(
                    "warning", "ESP_SEQUENCE_GAP",
                    f"ESP SPI 0x{flow.spi:08x} {flow.src}->{flow.dst}: {flow.missing} sequence number(s) missing "
                    "(loss before the capture point)", flow.frames, spi=f"0x{flow.spi:08x}"))
            out.append({
                "src": flow.src, "dst": flow.dst, "spi": f"0x{flow.spi:08x}", "udp_encapsulated": flow.udp,
                "packets": flow.packets, "bytes": flow.bytes,
                "first_t": ctx.rel(flow.first_t), "last_t": ctx.rel(flow.last_t),
                "first_seq": flow.first_seq, "last_seq": flow.max_seq,
                "missing_sequence_numbers": flow.missing, "duplicate_sequence_numbers": flow.duplicates,
                "out_of_order": flow.out_of_order, "frames": flow.frames,
            })
        for (src, dst), group in by_direction.items():
            for old, new in zip(group, group[1:]):
                events.append(make_event(ctx, new.first_t, "esp", "spi_change",
                                         f"{src}->{dst} ESP SPI 0x{old.spi:08x} replaced by 0x{new.spi:08x} (rekey)",
                                         new.frames[0] if new.frames else None))
            if group:
                events.append(make_event(ctx, group[0].first_t, "esp", "esp_start",
                                         f"first ESP {src}->{dst} (SPI 0x{group[0].spi:08x})",
                                         group[0].frames[0] if group[0].frames else None))
        # One-way ESP: a peer that sends but never receives.
        for (src, dst), group in by_direction.items():
            if (dst, src) not in by_direction:
                issues.append(make_issue(
                    "warning", "ESP_ONE_WAY",
                    f"ESP flows {src}->{dst} only; nothing returns from {dst} at this capture point "
                    "(return path, SA mismatch, or asymmetric routing)",
                    group[0].frames))
        return out

    def _report_encryption(self, ctx: Context, issues) -> Dict[str, Any]:
        candidates = self._candidate_pairs()
        pairs_out = []
        cleartext_all = []
        no_esp = []
        for key in sorted(candidates):
            pair = self.pairs[key]
            cleartext = []
            for (label, src, dst), entry in sorted(pair["cleartext"].items(), key=lambda kv: -kv[1]["packets"]):
                cleartext.append({"protocol": label, "src": src, "dst": dst, "packets": entry["packets"],
                                  "bytes": entry["bytes"], "first_t": ctx.rel(entry["first_t"]),
                                  "frames": entry["frames"]})
            protected = dict(pair["protected"])
            has_esp = bool(protected.get("esp") or protected.get("esp-in-udp"))
            if cleartext:
                verdict = "cleartext"
            elif has_esp:
                verdict = "encrypted"
            elif protected.get("ike"):
                verdict = "ike_only"
                no_esp.append(key)
            else:
                verdict = "no_traffic"
            pairs_out.append({"endpoints": list(key), "verdict": verdict, "protected_packets": protected,
                              "cleartext_packets": sum(c["packets"] for c in cleartext),
                              "cleartext": cleartext[:10]})
            cleartext_all.extend(cleartext)
        cleartext_all.sort(key=lambda c: -c["packets"])
        if cleartext_all:
            parts = [f"{c['protocol']} {c['src']}->{c['dst']} {c['packets']} packets" for c in cleartext_all[:5]]
            more = len(cleartext_all) - 5
            text = "cleartext seen: " + "; ".join(parts) + (f"; and {more} more" if more > 0 else "")
            code = "cleartext_seen"
            # One issue per peer pair, listing every cleartext protocol and direction in it.
            for pair in pairs_out[:ctx.max_items]:
                if not pair["cleartext"]:
                    continue
                protocols = sorted({c["protocol"] for c in pair["cleartext"]})
                only_icmp = all(p in ("icmp", "icmpv6") for p in protocols)
                severity = "warning" if only_icmp else "error"
                hint = ""
                if any(p.startswith("gre") for p in protocols):
                    hint = " GRE without IPsec: the tunnel is not encrypted."
                elif only_icmp:
                    hint = (" Expected if someone pinged or tracerouted the peer's WAN address; "
                            "otherwise traffic is bypassing the tunnel.")
                detail = "; ".join(f"{c['protocol']} {c['src']}->{c['dst']} {c['packets']} packets"
                                   for c in pair["cleartext"])
                a, b = pair["endpoints"]
                issues.append(make_issue(severity, "CLEARTEXT_BETWEEN_PEERS",
                                         f"cleartext between {a} and {b}: {detail}.{hint}",
                                         [f for c in pair["cleartext"] for f in c["frames"][:3]],
                                         endpoints=pair["endpoints"], protocols=protocols,
                                         packets=pair["cleartext_packets"]))
        elif pairs_out and all(p["verdict"] == "encrypted" for p in pairs_out):
            esp_packets = sum(p["protected_packets"].get("esp", 0) + p["protected_packets"].get("esp-in-udp", 0)
                              for p in pairs_out)
            text = (f"all inter-site traffic encrypted: {len(pairs_out)} peer pair(s), {esp_packets} ESP packets, "
                    "no cleartext between the same endpoints")
            code = "encrypted"
        elif no_esp:
            names = ", ".join(f"{a}<->{b}" for a, b in no_esp[:5])
            text = f"no ESP between IKE peers {names}: the tunnel carried no protected traffic (or failed to come up)"
            encrypted = [p for p in pairs_out if p["verdict"] == "encrypted"]
            if encrypted:
                text = f"{len(encrypted)} of {len(pairs_out)} peer pair(s) encrypted (ESP, no cleartext); " + text
            code = "no_esp"
        elif pairs_out:
            encrypted = [p for p in pairs_out if p["verdict"] == "encrypted"]
            text = f"{len(encrypted)} of {len(pairs_out)} peer pair(s) carry ESP; the others carried no traffic"
            code = "encrypted" if encrypted else "no_esp"
        else:
            text = "no traffic between the given peers" if self.peers else "no IPsec peers found"
            code = "not_present"
        pairs_list, omitted = cap(pairs_out, ctx.max_items)
        cleartext_list, _ = cap(cleartext_all, ctx.max_items)
        return {"verdict": text, "code": code, "pairs": pairs_list, "omitted": omitted, "cleartext": cleartext_list}

    def _report_nat(self) -> Dict[str, Any]:
        udp_flows = [flow for flow in self.esp.values() if flow.udp]
        in_use = bool(self.ike_on_4500 or udp_flows or self.keepalives)
        if in_use:
            verdict = ("NAT-T in use: " + ", ".join(part for part in [
                f"IKE on UDP 4500 ({self.ike_on_4500} packets)" if self.ike_on_4500 else "",
                f"{len(udp_flows)} ESP-in-UDP flow(s)" if udp_flows else "",
                f"{self.keepalives} NAT keepalive(s)" if self.keepalives else ""] if part))
        elif self.nat_detection:
            verdict = "NAT detection payloads exchanged; no NAT found (IKE stayed on UDP 500, ESP not encapsulated)"
        else:
            verdict = "NAT-T not in use"
        return {"in_use": in_use, "ike_packets_on_4500": self.ike_on_4500,
                "esp_in_udp_flows": len(udp_flows), "nat_keepalives": self.keepalives,
                "keepalive_frames": self.keepalive_frames,
                "nat_detection_payloads_seen": self.nat_detection, "verdict": verdict}

    @staticmethod
    def _negotiation_verdict(ike_sas: List[Dict[str, Any]]) -> str:
        if not ike_sas:
            return "no IKE seen"
        counts = Counter(sa["outcome"] for sa in ike_sas)
        parts = [f"{count} {outcome.replace('_', ' ')}" for outcome, count in counts.most_common()]
        return f"{len(ike_sas)} IKE SA(s): " + ", ".join(parts)
