#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. GRE / NHRP (DMVPN) Detector

Deterministic analysis of GRE tunnels (IP protocol 47) and the NHRP control
plane they carry (GRE protocol type 0x2001), which is how a DMVPN overlay forms:

- GRE tunnels per outer address pair: packets, bytes, GRE keys, inner protocols,
  and a key mismatch between the two directions of one tunnel.
- NHRP registration requests/replies (spoke to hub), with the CIE result code,
  unanswered and refused registrations.
- Hub and spoke roles, inferred from who registers with whom: the receiver of a
  Registration Request is a hub (NHS), its sender a spoke (NHC).
- Resolution requests/replies (spoke-to-spoke shortcut lookups) and the NBMA
  address each answer maps to.
- Traffic Indications (Cisco NHRP redirect, DMVPN Phase 3 shortcut signalling)
  and Error Indications with their error codes.
- Spoke-to-spoke GRE tunnels (both ends are spokes), the proof a shortcut formed.

Author: Raymond A Rizzo | Zombat
"""

from collections import Counter
from typing import Any, Dict, List

from analyzers.network_common import (
    NHRP_CIE_CODES, NHRP_ERROR_CODES, NHRP_OPS, Context, add_frame, cap, make_event, make_issue,
    pair_key, sort_issues, status_from_issues,
)

GRE_PTYPES = {0x0800: "ipv4", 0x86DD: "ipv6", 0x2001: "nhrp", 0x6558: "ethernet", 0x8847: "mpls"}


class GreNhrpDetector:
    """Streaming GRE/NHRP detector. Feed records, then call report()."""

    name = "gre_nhrp"

    def __init__(self):
        self.tunnels: Dict[tuple, Dict[str, Any]] = {}
        self.registrations: Dict[tuple, Dict[str, Any]] = {}
        self.resolutions: Dict[tuple, Dict[str, Any]] = {}
        self.redirects: Dict[tuple, Dict[str, Any]] = {}
        self.errors: List[Dict[str, Any]] = []
        self.purges = Counter()
        self.nhrp_counts = Counter()
        self.nhrp_events: List[Dict[str, Any]] = []

    def feed(self, rec: Dict[str, Any]):
        if "gre" not in rec or "ip" not in rec:
            return
        src, dst = rec["ip"]["src"], rec["ip"]["dst"]
        gre = rec["gre"]
        tunnel = self.tunnels.get((src, dst))
        if tunnel is None:
            tunnel = {"packets": 0, "bytes": 0, "keys": Counter(), "inner": Counter(), "frames": [],
                      "first_t": rec["t"], "last_t": rec["t"]}
            self.tunnels[(src, dst)] = tunnel
        tunnel["packets"] += 1
        tunnel["bytes"] += rec["len"]
        tunnel["keys"][gre["key"]] += 1
        tunnel["inner"][GRE_PTYPES.get(gre["ptype"], f"0x{gre['ptype']:04x}")] += 1
        tunnel["last_t"] = rec["t"]
        add_frame(tunnel["frames"], rec["n"])
        if "nhrp" in rec:
            self._feed_nhrp(rec, src, dst, rec["nhrp"])

    def _feed_nhrp(self, rec, src, dst, nhrp):
        op = nhrp["op"]
        self.nhrp_counts[NHRP_OPS.get(op, f"type_{op}")] += 1
        t, n = rec["t"], rec["n"]
        if op in (3, 4):
            # Key by (spoke NBMA, hub NBMA); NHRP keeps the requester's addresses in the reply.
            spoke_nbma = nhrp["src_nbma"] or (src if op == 3 else dst)
            hub_nbma = dst if op == 3 else src
            reg = self.registrations.get((spoke_nbma, hub_nbma))
            if reg is None:
                reg = {"spoke_nbma": spoke_nbma, "spoke_tunnel_ip": nhrp["src_proto"], "hub_nbma": hub_nbma,
                       "hub_tunnel_ip": nhrp["dst_proto"], "requests": 0, "replies": 0, "codes": Counter(),
                       "last_code": None, "request_frames": [], "reply_frames": [], "first_t": t, "last_t": t,
                       "last_success_t": None}
                self.registrations[(spoke_nbma, hub_nbma)] = reg
            reg["last_t"] = t
            if op == 3:
                reg["requests"] += 1
                add_frame(reg["request_frames"], n)
            else:
                reg["replies"] += 1
                reg["codes"][nhrp["code"]] += 1
                reg["last_code"] = nhrp["code"]
                add_frame(reg["reply_frames"], n)
                if nhrp["code"] == 0:
                    reg["last_success_t"] = t
        elif op in (1, 2):
            key = (nhrp["src_proto"], nhrp["dst_proto"], nhrp["reqid"])
            res = self.resolutions.get(key)
            if res is None:
                res = {"requester_tunnel_ip": nhrp["src_proto"], "requester_nbma": nhrp["src_nbma"],
                       "target": nhrp["dst_proto"], "request_id": nhrp["reqid"], "requests": 0,
                       "replies": 0, "answers": [], "request_frames": [], "reply_frames": [], "first_t": t,
                       "error": None}
                self.resolutions[key] = res
            if op == 1:
                res["requests"] += 1
                add_frame(res["request_frames"], n)
            else:
                res["replies"] += 1
                add_frame(res["reply_frames"], n)
                answer = {"code": nhrp["code"], "code_name": NHRP_CIE_CODES.get(nhrp["code"], f"code {nhrp['code']}"),
                          "client_nbma": nhrp["client_nbma"], "client_tunnel_ip": nhrp["client_proto"],
                          "prefix_length": nhrp["prefix"], "answered_by": src, "frame": n}
                if answer not in res["answers"]:
                    res["answers"].append(answer)
        elif op == 8:
            key = (src, dst, nhrp["orig_dst"])
            red = self.redirects.get(key)
            if red is None:
                red = {"from": src, "to": dst, "redirecting_tunnel_ip": nhrp["src_proto"],
                       "original_src": nhrp["orig_src"], "original_dst": nhrp["orig_dst"],
                       "count": 0, "frames": [], "first_t": t}
                self.redirects[key] = red
            red["count"] += 1
            add_frame(red["frames"], n)
        elif op == 7:
            self.errors.append({"from": src, "to": dst, "error_code": nhrp["err_code"],
                                "error": NHRP_ERROR_CODES.get(nhrp["err_code"], f"error {nhrp['err_code']}"),
                                "request_id": nhrp["reqid"], "frame": n, "t": t})
        elif op in (5, 6):
            self.purges["requests" if op == 5 else "replies"] += 1

    def present(self) -> bool:
        return bool(self.tunnels)

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []

        # Roles from registrations.
        hubs: Dict[str, Dict[str, Any]] = {}
        spokes: Dict[str, Dict[str, Any]] = {}
        registrations = []
        for reg in sorted(self.registrations.values(), key=lambda r: r["first_t"]):
            hub = hubs.setdefault(reg["hub_nbma"], {"nbma": reg["hub_nbma"], "tunnel_ip": reg["hub_tunnel_ip"],
                                                    "spokes_registered": [], "spokes_refused": [],
                                                    "spokes_unanswered": []})
            spoke = spokes.setdefault(reg["spoke_nbma"], {"nbma": reg["spoke_nbma"],
                                                          "tunnel_ip": reg["spoke_tunnel_ip"], "hubs": []})
            if reg["hub_nbma"] not in spoke["hubs"]:
                spoke["hubs"].append(reg["hub_nbma"])
            if reg["replies"] == 0:
                result = "unanswered"
                hub["spokes_unanswered"].append(reg["spoke_nbma"])
                issues.append(make_issue(
                    "error", "NHRP_REGISTRATION_UNANSWERED",
                    f"spoke {reg['spoke_nbma']} ({reg['spoke_tunnel_ip']}) sent {reg['requests']} registration "
                    f"request(s) to hub {reg['hub_nbma']} and got no reply (NHS unreachable, GRE/IPsec down, "
                    "or the hub has no matching tunnel/network-id)", reg["request_frames"]))
            elif reg["last_code"] == 0:
                result = "registered"
                hub["spokes_registered"].append(reg["spoke_nbma"])
                events.append(make_event(ctx, reg["last_success_t"], "nhrp", "registered",
                                         f"spoke {reg['spoke_nbma']} ({reg['spoke_tunnel_ip']}) registered with hub "
                                         f"{reg['hub_nbma']}", reg["reply_frames"][-1] if reg["reply_frames"] else None))
            else:
                result = "refused"
                hub["spokes_refused"].append(reg["spoke_nbma"])
                name = NHRP_CIE_CODES.get(reg["last_code"], f"code {reg['last_code']}")
                issues.append(make_issue(
                    "error", "NHRP_REGISTRATION_REFUSED",
                    f"hub {reg['hub_nbma']} refused the registration of spoke {reg['spoke_nbma']} "
                    f"({reg['spoke_tunnel_ip']}): {name}", reg["reply_frames"], nhrp_code=reg["last_code"]))
                events.append(make_event(ctx, reg["last_t"], "nhrp", "registration_refused",
                                         f"hub {reg['hub_nbma']} refused spoke {reg['spoke_nbma']}: {name}",
                                         reg["reply_frames"][-1] if reg["reply_frames"] else None))
            registrations.append({
                "spoke_nbma": reg["spoke_nbma"], "spoke_tunnel_ip": reg["spoke_tunnel_ip"],
                "hub_nbma": reg["hub_nbma"], "hub_tunnel_ip": reg["hub_tunnel_ip"], "result": result,
                "requests": reg["requests"], "replies": reg["replies"],
                "reply_codes": {NHRP_CIE_CODES.get(code, f"code {code}"): count for code, count in reg["codes"].items()},
                "first_t": ctx.rel(reg["first_t"]), "last_t": ctx.rel(reg["last_t"]),
                "request_frames": reg["request_frames"], "reply_frames": reg["reply_frames"],
            })

        resolutions = []
        for res in sorted(self.resolutions.values(), key=lambda r: r["first_t"]):
            matching_errors = [e for e in self.errors if e["request_id"] is not None and e["request_id"] == res["request_id"]]
            if res["replies"]:
                result = "resolved" if any(a["code"] == 0 for a in res["answers"]) else "negative_reply"
            elif matching_errors:
                result = "error_indication"
            else:
                result = "unanswered"
                issues.append(make_issue(
                    "warning", "NHRP_RESOLUTION_UNANSWERED",
                    f"{res['requester_tunnel_ip']} asked to resolve {res['target']} and got no reply in this capture",
                    res["request_frames"]))
            for answer in res["answers"]:
                if answer["code"] == 0:
                    events.append(make_event(ctx, res["first_t"], "nhrp", "resolved",
                                             f"{res['target']} resolved for {res['requester_tunnel_ip']}: tunnel "
                                             f"{answer['client_tunnel_ip']} at NBMA {answer['client_nbma']}",
                                             answer["frame"]))
            resolutions.append({
                "requester_tunnel_ip": res["requester_tunnel_ip"], "requester_nbma": res["requester_nbma"],
                "target": res["target"], "request_id": res["request_id"], "result": result,
                "requests_seen": res["requests"], "replies": res["replies"], "answers": res["answers"][:5],
                "first_t": ctx.rel(res["first_t"]), "request_frames": res["request_frames"],
                "reply_frames": res["reply_frames"],
            })

        redirects = []
        for red in sorted(self.redirects.values(), key=lambda r: r["first_t"]):
            redirects.append({"from": red["from"], "to": red["to"], "redirecting_tunnel_ip": red["redirecting_tunnel_ip"],
                              "original_src": red["original_src"], "original_dst": red["original_dst"],
                              "count": red["count"], "first_t": ctx.rel(red["first_t"]), "frames": red["frames"]})
            events.append(make_event(ctx, red["first_t"], "nhrp", "redirect",
                                     f"{red['from']} redirected {red['to']} for traffic to {red['original_dst']} "
                                     "(Phase 3 shortcut signal)", red["frames"][0]))

        errors_out = []
        for err in self.errors:
            errors_out.append({k: (ctx.rel(v) if k == "t" else v) for k, v in err.items()})
            issues.append(make_issue("warning", "NHRP_ERROR_INDICATION",
                                     f"NHRP error indication {err['from']}->{err['to']}: {err['error']}",
                                     [err["frame"]], error_code=err["error_code"]))
            events.append(make_event(ctx, err["t"], "nhrp", "error_indication",
                                     f"{err['from']}->{err['to']}: {err['error']}", err["frame"]))

        tunnels, spoke_to_spoke = self._report_tunnels(ctx, hubs, spokes, issues, events)

        if redirects:
            phase = "phase3"
        elif any(r["result"] == "resolved" for r in resolutions) or spoke_to_spoke:
            phase = "phase2_or_phase3"
        elif registrations:
            phase = "hub_and_spoke_only"
        else:
            phase = "unknown"

        present = self.present()
        status = status_from_issues(issues, present)
        verdict = self._verdict(present, hubs, registrations, spoke_to_spoke, tunnels)
        tunnels_list, tunnels_omitted = cap(tunnels, ctx.max_items)
        regs_list, regs_omitted = cap(registrations, ctx.max_items)
        res_list, res_omitted = cap(resolutions, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "dmvpn_phase_hint": phase,
            "summary": {
                "gre_tunnels": len(self.tunnels),
                "gre_packets": sum(t["packets"] for t in self.tunnels.values()),
                "nhrp_messages": dict(self.nhrp_counts),
                "hubs": len(hubs),
                "spokes": len(spokes),
                "spokes_registered": sum(1 for r in registrations if r["result"] == "registered"),
                "spoke_to_spoke_tunnels": len(spoke_to_spoke),
            },
            "hubs": list(hubs.values()),
            "spokes": list(spokes.values()),
            "registrations": regs_list,
            "registrations_omitted": regs_omitted,
            "resolutions": res_list,
            "resolutions_omitted": res_omitted,
            "redirects": redirects[:ctx.max_items],
            "error_indications": errors_out[:ctx.max_items],
            "purges": dict(self.purges),
            "tunnels": tunnels_list,
            "tunnels_omitted": tunnels_omitted,
            "spoke_to_spoke_tunnels": spoke_to_spoke,
            "issues": sort_issues(issues),
            "events": events,
        }

    def _report_tunnels(self, ctx, hubs, spokes, issues, events):
        tunnels = []
        seen_pairs = set()
        spoke_to_spoke = []
        for (src, dst), tun in sorted(self.tunnels.items(), key=lambda kv: kv[1]["first_t"]):
            keys = sorted(k for k in tun["keys"] if k is not None)
            tunnels.append({"src": src, "dst": dst, "packets": tun["packets"], "bytes": tun["bytes"],
                            "gre_keys": keys, "keyless_packets": tun["keys"].get(None, 0),
                            "inner_protocols": dict(tun["inner"]), "first_t": ctx.rel(tun["first_t"]),
                            "last_t": ctx.rel(tun["last_t"]), "frames": tun["frames"]})
            key = pair_key(src, dst)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            reverse = self.tunnels.get((dst, src))
            if reverse:
                fwd_keys = set(tun["keys"])
                rev_keys = set(reverse["keys"])
                if fwd_keys != rev_keys:
                    issues.append(make_issue(
                        "error", "GRE_KEY_MISMATCH",
                        f"GRE key differs by direction: {src}->{dst} uses {sorted(map(str, fwd_keys))}, "
                        f"{dst}->{src} uses {sorted(map(str, rev_keys))}; the receiver drops packets whose key "
                        "does not match its tunnel key", tun["frames"][:3] + reverse["frames"][:3]))
            if src in spokes and dst in spokes and src not in hubs and dst not in hubs:
                total = tun["packets"] + (reverse["packets"] if reverse else 0)
                spoke_to_spoke.append({"endpoints": list(key), "packets": total, "first_t": ctx.rel(tun["first_t"])})
                events.append(make_event(ctx, tun["first_t"], "gre", "spoke_to_spoke",
                                         f"direct spoke-to-spoke GRE {src}->{dst}", tun["frames"][0]))
        return tunnels, spoke_to_spoke

    @staticmethod
    def _verdict(present, hubs, registrations, spoke_to_spoke, tunnels) -> str:
        if not present:
            return "No GRE traffic in this capture."
        if not registrations:
            return (f"{len(tunnels)} GRE tunnel direction(s) seen; no NHRP registrations captured "
                    "(static GRE, or NHRP outside the capture window)")
        parts = []
        for hub in hubs.values():
            ok = len(hub["spokes_registered"])
            total = ok + len(hub["spokes_refused"]) + len(hub["spokes_unanswered"])
            text = f"{ok} of {total} spoke(s) registered with hub {hub['nbma']} ({hub['tunnel_ip']})"
            if hub["spokes_refused"]:
                text += f"; refused: {', '.join(hub['spokes_refused'])}"
            if hub["spokes_unanswered"]:
                text += f"; unanswered: {', '.join(hub['spokes_unanswered'])}"
            parts.append(text)
        if spoke_to_spoke:
            parts.append(f"{len(spoke_to_spoke)} spoke-to-spoke tunnel(s) carried traffic")
        return "DMVPN overlay: " + "; ".join(parts)
