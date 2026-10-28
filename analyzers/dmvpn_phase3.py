#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. DMVPN Phase 3 Sequence Detector

Proves (or disproves) a DMVPN Phase 3 shortcut from packets, step by step, for
each spoke-to-spoke flow:

    1. via_hub              data from spoke S reaches the hub inside GRE (and the hub
                            forwards it to the other spoke)
    2. redirect             the hub sends S an NHRP Traffic Indication for that flow
    3. resolution_request   S asks NHRP to resolve the destination
    4. resolution_reply     the other spoke (or the hub) answers with its NBMA address
    5. direct               data from S goes straight to that NBMA address inside GRE

Each flow gets its steps with frame numbers and times, the first missing step,
and a diagnosis. Also reported: hub-relayed spoke-to-spoke traffic that never
got a redirect, NHRP resolution thrashing (requests per spoke per second,
repeats with no reply) and error indications.

With tunnel protection the GRE/NHRP steps travel inside ESP and are invisible on
the transport link. Given the hub NBMA addresses (or when NHRP registrations
show them), the detector then reports the encrypted evidence instead: a new IKE
SA between two spokes, IKE_AUTH answered, and the first ESP directly between
them, saying plainly that steps 2 to 4 cannot be seen there.

Author: Raymond A Rizzo | Zombat
"""

import ipaddress
from typing import Any, Dict, List, Optional

from analyzers.network_common import (
    NHRP_CIE_CODES, NHRP_ERROR_CODES, Context, add_frame, cap, make_event, make_issue, pair_key, sort_issues,
    status_from_issues,
)

THRASH_RATE_PER_S = 5          # resolution requests from one spoke inside any one second
THRASH_UNANSWERED_REPEATS = 5  # requests for one target that never got a reply
STEPS = ["via_hub", "redirect", "resolution_request", "resolution_reply", "direct"]
MISSING_HINTS = {
    "via_hub": "no packet of this flow was seen going through the hub (the capture probably started after it)",
    "redirect": "the hub relayed spoke-to-spoke traffic but sent no NHRP redirect: 'ip nhrp redirect' missing on the "
                "hub tunnel, or the traffic did not enter and leave the same tunnel interface",
    "resolution_request": "the spoke got the redirect but never asked NHRP to resolve the destination: "
                          "'ip nhrp shortcut' missing on the spoke, or the redirect was rate limited",
    "resolution_reply": "the resolution request was never answered: the remote spoke did not receive it or could not "
                        "answer (not registered, no route back over the tunnel, or NHRP blocked)",
    "direct": "the destination was resolved but no data went directly between the spokes: the spoke-to-spoke tunnel "
              "(and its IPsec SA, if protected) never carried traffic, or the flow ended",
}
ENCRYPTED_NOT_VISIBLE = ("NHRP redirect, resolution request and resolution reply travel inside ESP on a protected "
                         "tunnel, so on the transport link only the IKE negotiation and ESP between the spokes are "
                         "visible; capture on the tunnel interface to see steps 2 to 4")


def _in_prefix(addr: Optional[str], base: Optional[str], prefix: Optional[int]) -> bool:
    if not addr or not base:
        return False
    try:
        net = ipaddress.ip_network(f"{base}/{prefix if prefix is not None else 32}", strict=False)
        return ipaddress.ip_address(addr) in net
    except ValueError:
        return False


class DmvpnPhase3Detector:
    """Streaming Phase 3 sequence detector. Feed records, then call report()."""

    name = "dmvpn_phase3"

    def __init__(self, hubs: Optional[List[str]] = None):
        self.hubs_given = list(hubs or [])
        self.registered_hubs = set()
        self.ti_senders = set()
        # inner (src, dst) -> outer (src, dst) -> {first_t, first_n, last_t, count}
        self.data: Dict[tuple, Dict[tuple, Dict[str, Any]]] = {}
        self.indications: Dict[tuple, Dict[str, Any]] = {}
        self.requests: List[Dict[str, Any]] = []
        self.replies: Dict[int, List[Dict[str, Any]]] = {}
        self.errors: List[Dict[str, Any]] = []
        # encrypted view
        self.ike: Dict[tuple, Dict[str, Any]] = {}
        self.esp: Dict[tuple, Dict[str, Any]] = {}
        self.seen = False

    # -- feeding -----------------------------------------------------------

    def feed(self, rec: Dict[str, Any]):
        ip = rec.get("ip")
        if not ip:
            return
        src, dst, t, n = ip["src"], ip["dst"], rec["t"], rec["n"]
        if "gre" in rec:
            inner = rec.get("inner")
            if inner and inner.get("src"):
                outers = self.data.setdefault((inner["src"], inner["dst"]), {})
                entry = outers.get((src, dst))
                if entry is None:
                    if len(outers) < 64:
                        outers[(src, dst)] = {"first_t": t, "first_n": n, "last_t": t, "count": 1}
                else:
                    entry["last_t"] = t
                    entry["count"] += 1
            nhrp = rec.get("nhrp")
            if nhrp:
                self.seen = True
                self._feed_nhrp(nhrp, src, dst, t, n)
        if "ike" in rec:
            ike = rec["ike"]
            key = pair_key(src, dst)
            state = self.ike.setdefault(key, {"init_t": None, "init_n": None, "initiator": None, "auth_t": None,
                                              "auth_n": None, "init_requests": 0, "init_responses": 0})
            is_response = bool(ike["flags"] & 0x20)
            if ike["version"] == 2 and ike["exch"] == 34:
                if not is_response:
                    state["init_requests"] += 1
                    if state["init_t"] is None:
                        state.update(init_t=t, init_n=n, initiator=src)
                else:
                    state["init_responses"] += 1
            elif ike["version"] == 2 and ike["exch"] == 35 and is_response and state["auth_t"] is None:
                state.update(auth_t=t, auth_n=n)
        if "esp" in rec:
            flow = self.esp.setdefault((src, dst), {"times": [], "first_t": t, "first_n": n, "last_t": t,
                                                    "packets": 0})
            flow["packets"] += 1
            flow["last_t"] = t
            if len(flow["times"]) < 4096:
                flow["times"].append((t, n))

    def _feed_nhrp(self, nhrp, src, dst, t, n):
        op = nhrp["op"]
        if op == 3:
            self.registered_hubs.add(dst)
        elif op == 8:
            self.ti_senders.add(src)
            key = (dst, nhrp.get("orig_src"), nhrp.get("orig_dst"))
            ind = self.indications.get(key)
            if ind is None:
                self.indications[key] = {"hub": src, "spoke": dst, "orig_src": nhrp.get("orig_src"),
                                         "orig_dst": nhrp.get("orig_dst"), "t": t, "n": n, "count": 1}
            else:
                ind["count"] += 1
        elif op == 1:
            if len(self.requests) < 100000:
                self.requests.append({"requester_nbma": nhrp.get("src_nbma") or src, "requester": nhrp.get("src_proto"),
                                      "target": nhrp.get("dst_proto"), "reqid": nhrp.get("reqid"), "t": t, "n": n,
                                      "outer_src": src, "outer_dst": dst})
        elif op == 2:
            self.replies.setdefault(nhrp.get("reqid"), []).append(
                {"t": t, "n": n, "from": src, "code": nhrp.get("code"), "client_nbma": nhrp.get("client_nbma"),
                 "client_proto": nhrp.get("client_proto"), "prefix": nhrp.get("prefix")})
        elif op == 7:
            self.errors.append({"t": t, "n": n, "from": src, "to": dst, "reqid": nhrp.get("reqid"),
                                "code": nhrp.get("err_code"),
                                "error": NHRP_ERROR_CODES.get(nhrp.get("err_code"), f"error {nhrp.get('err_code')}")})

    def hubs(self) -> List[str]:
        return sorted(set(self.hubs_given) | self.registered_hubs | self.ti_senders)

    def present(self) -> bool:
        return self.seen or bool(self.data) or bool(self._encrypted_candidates(self.hubs()))

    # -- reporting ---------------------------------------------------------

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        hubs = self.hubs()
        flows = [self._flow(ind, hubs, ctx, issues, events) for ind in
                 sorted(self.indications.values(), key=lambda i: i["t"])]
        relayed = self._relayed_without_redirect(hubs, ctx, issues)
        thrash = self._thrashing(ctx, issues)
        errors = [{"from": e["from"], "to": e["to"], "error": e["error"], "error_code": e["code"],
                   "request_id": e["reqid"], "t": ctx.rel(e["t"]), "frame": e["n"]} for e in self.errors]
        encrypted = self._encrypted(hubs, ctx, issues, events)

        complete = [f for f in flows if f["result"] == "complete"]
        enc_ok = [e for e in encrypted["shortcuts"] if e["result"] == "complete"]
        present = self.present()
        if not present:
            negotiated = sum(1 for state in self.ike.values() if state["init_t"] is not None)
            verdict = "No GRE/NHRP and no spoke-to-spoke IKE in this capture."
            if negotiated and not hubs:
                verdict = (f"No GRE/NHRP visible; {negotiated} IKE SA(s) were negotiated during the capture: pass "
                           "hubs (the hub NBMA addresses) to test them as encrypted spoke-to-spoke shortcuts.")
        else:
            parts = []
            if flows:
                parts.append(f"{len(complete)} of {len(flows)} redirected flow(s) completed the Phase 3 sequence")
                for f in flows:
                    if f["result"] != "complete":
                        parts.append(f"{f['spoke']} -> {f['original_dst']}: stops before {f['missing_step']}")
            if relayed:
                parts.append(f"{len(relayed)} hub-relayed spoke-to-spoke flow(s) with no redirect")
            if thrash["thrashing"]:
                parts.append("NHRP resolution thrashing")
            if encrypted["shortcuts"]:
                parts.append(f"{len(enc_ok)} of {len(encrypted['shortcuts'])} encrypted spoke-to-spoke shortcut(s) "
                             "formed (IKE then direct ESP)")
            elif encrypted["note"] and not flows:
                parts.append(encrypted["note"])
            verdict = "Phase 3: " + ("; ".join(parts) if parts else "no redirect, resolution or shortcut seen")
        status = status_from_issues(issues, present)
        flows_list, flows_omitted = cap(flows, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "hubs": hubs,
            "hubs_source": {"given": self.hubs_given, "from_registrations": sorted(self.registered_hubs),
                            "from_redirects": sorted(self.ti_senders)},
            "flows": flows_list,
            "flows_omitted": flows_omitted,
            "hub_relayed_without_redirect": relayed[:ctx.max_items],
            "resolution_thrashing": thrash,
            "error_indications": errors[:ctx.max_items],
            "encrypted_shortcuts": encrypted,
            "cannot_show": [ENCRYPTED_NOT_VISIBLE,
                            "Which application flow triggered a redirect is known only from the original packet "
                            "header the hub copies into the Traffic Indication."],
            "issues": sort_issues(issues),
            "events": events,
        }

    def _flow(self, ind, hubs, ctx, issues, events) -> Dict[str, Any]:
        spoke, hub, a, b = ind["spoke"], ind["hub"], ind["orig_src"], ind["orig_dst"]
        steps: Dict[str, Optional[Dict[str, Any]]] = {name: None for name in STEPS}
        outers = self.data.get((a, b), {})
        to_hub = outers.get((spoke, hub))
        forwarded_to = None
        if to_hub:
            steps["via_hub"] = {"t": ctx.rel(to_hub["first_t"]), "frame": to_hub["first_n"],
                                "detail": f"{a} -> {b} inside GRE {spoke} -> {hub}"}
            for (osrc, odst), entry in outers.items():
                if osrc == hub and odst != spoke:
                    forwarded_to = odst
                    steps["via_hub"]["detail"] += f", forwarded by the hub to {odst}"
                    break
        steps["redirect"] = {"t": ctx.rel(ind["t"]), "frame": ind["n"],
                             "detail": f"Traffic Indication {hub} -> {spoke} for {a} -> {b} ({ind['count']} sent)"}
        requests = [r for r in self.requests if r["requester_nbma"] == spoke and r["t"] >= ind["t"]]
        matching = [r for r in requests if r["target"] == b] or requests
        request = matching[0] if matching else None
        reply = None
        if request:
            steps["resolution_request"] = {"t": ctx.rel(request["t"]), "frame": request["n"],
                                           "detail": f"{request['requester']} asks for {request['target']} "
                                                     f"(request id {request['reqid']})"}
            reqids = {r["reqid"] for r in matching}
            answers = sorted((rep for rid in reqids for rep in self.replies.get(rid, [])), key=lambda r: r["t"])
            good = [rep for rep in answers if rep["code"] == 0]
            reply = good[0] if good else (answers[0] if answers else None)
            if reply:
                steps["resolution_reply"] = {
                    "t": ctx.rel(reply["t"]), "frame": reply["n"],
                    "detail": f"{reply['from']} answers {NHRP_CIE_CODES.get(reply['code'], reply['code'])}: "
                              f"{b} is behind tunnel {reply['client_proto']} at NBMA {reply['client_nbma']} "
                              f"(prefix /{reply['prefix']})"}
                if reply["code"] != 0:
                    steps["resolution_reply"]["negative"] = True
        if reply and reply["code"] == 0 and reply["client_nbma"]:
            target_nbma = reply["client_nbma"]
            direct = None
            for (isrc, idst), outer_map in self.data.items():
                entry = outer_map.get((spoke, target_nbma))
                if entry and entry["first_t"] >= reply["t"] and \
                        (idst == b or _in_prefix(idst, b, reply["prefix"])):
                    if direct is None or entry["first_t"] < direct["first_t"]:
                        direct = dict(entry, inner=(isrc, idst))
            if direct:
                steps["direct"] = {"t": ctx.rel(direct["first_t"]), "frame": direct["first_n"],
                                   "detail": f"{direct['inner'][0]} -> {direct['inner'][1]} inside GRE {spoke} -> "
                                             f"{target_nbma} ({direct['count']} packet(s))"}
        # The redirect is what starts a flow here, so step 1 missing only means the capture began late.
        missing = next((name for name in STEPS[1:] if steps[name] is None or steps[name].get("negative")), None)
        result = "complete" if missing is None else "incomplete"
        req_errors = [e for e in self.errors if request and e["reqid"] in {r["reqid"] for r in matching}]
        diagnosis = "Phase 3 shortcut formed: redirect, resolution and direct spoke-to-spoke data all seen"
        if missing:
            diagnosis = MISSING_HINTS[missing]
            if missing == "resolution_reply" and req_errors:
                diagnosis = f"the resolution got an NHRP error indication instead of a reply: {req_errors[0]['error']}"
            elif missing == "resolution_reply" and reply and reply["code"] != 0:
                diagnosis = (f"the resolution was refused: "
                             f"{NHRP_CIE_CODES.get(reply['code'], 'code ' + str(reply['code']))}")
            severity = "warning" if missing == "direct" else "error"
            issues.append(make_issue(severity, f"PHASE3_MISSING_{missing.upper()}",
                                     f"Phase 3 flow {a} -> {b} from spoke {spoke}: stops before {missing}: {diagnosis}",
                                     [s["frame"] for s in steps.values() if s], spoke=spoke, missing_step=missing))
        timeline = [s["t"] for s in steps.values() if s and s.get("t") is not None]
        timings = {}
        if steps["via_hub"] and steps["redirect"]:
            timings["redirect_after_first_data_ms"] = round((steps["redirect"]["t"] - steps["via_hub"]["t"]) * 1000, 1)
        if steps["resolution_request"] and steps["resolution_reply"]:
            timings["resolution_rtt_ms"] = round((steps["resolution_reply"]["t"] -
                                                  steps["resolution_request"]["t"]) * 1000, 1)
        if steps["direct"]:
            first = steps["via_hub"]["t"] if steps["via_hub"] else steps["redirect"]["t"]
            timings["shortcut_after_first_data_ms"] = round((steps["direct"]["t"] - first) * 1000, 1)
        events.append(make_event(ctx, (ctx.start or 0) + min(timeline), "nhrp",
                                 "phase3_complete" if result == "complete" else "phase3_incomplete",
                                 f"{spoke} {a} -> {b}: " + ("shortcut formed" if result == "complete"
                                                            else f"stops before {missing}"), ind["n"]))
        if steps["via_hub"] is None:
            diagnosis += "; " + MISSING_HINTS["via_hub"]
        return {"spoke": spoke, "hub": hub, "original_src": a, "original_dst": b,
                "forwarded_by_hub_to": forwarded_to, "result": result, "missing_step": missing,
                "diagnosis": diagnosis, "steps": steps, "timings": timings,
                "error_indications": [e["error"] for e in req_errors]}

    def _relayed_without_redirect(self, hubs, ctx, issues) -> List[Dict[str, Any]]:
        hub_set = set(hubs)
        redirected = {(ind["spoke"], ind["orig_src"], ind["orig_dst"]) for ind in self.indications.values()}
        out = []
        for (a, b), outers in self.data.items():
            for (osrc, odst), entry in outers.items():
                if odst not in hub_set or osrc in hub_set:
                    continue
                onward = [(s, d) for (s, d) in outers if s == odst and d not in hub_set and d != osrc]
                if not onward or (osrc, a, b) in redirected:
                    continue
                item = {"spoke": osrc, "hub": odst, "to_spoke": onward[0][1], "inner_src": a, "inner_dst": b,
                        "packets_via_hub": entry["count"], "first_t": ctx.rel(entry["first_t"]),
                        "frame": entry["first_n"]}
                out.append(item)
                issues.append(make_issue("warning", "PHASE3_NO_REDIRECT",
                                         f"{a} -> {b} went spoke {osrc} -> hub {odst} -> spoke {onward[0][1]} "
                                         f"({entry['count']} packet(s)) with no NHRP redirect: "
                                         + MISSING_HINTS["redirect"], [entry["first_n"]]))
        return out

    def _thrashing(self, ctx, issues) -> Dict[str, Any]:
        by_requester: Dict[str, List[Dict[str, Any]]] = {}
        seen = set()
        for req in self.requests:
            key = (req["requester_nbma"], req["reqid"], req["target"])
            if key in seen:
                continue  # the same request relayed by the hub
            seen.add(key)
            by_requester.setdefault(req["requester_nbma"], []).append(req)
        spokes = []
        thrashing = False
        for spoke, reqs in sorted(by_requester.items()):
            times = sorted(r["t"] for r in reqs)
            peak = 0
            start = 0
            for end in range(len(times)):
                while times[end] - times[start] >= 1.0:
                    start += 1
                peak = max(peak, end - start + 1)
            per_target: Dict[str, Dict[str, Any]] = {}
            for r in reqs:
                tgt = per_target.setdefault(r["target"], {"target": r["target"], "requests": 0, "answered": 0,
                                                          "frames": []})
                tgt["requests"] += 1
                if self.replies.get(r["reqid"]):
                    tgt["answered"] += 1
                add_frame(tgt["frames"], r["n"])
            targets = sorted(per_target.values(), key=lambda x: -x["requests"])
            for tgt in targets:
                tgt["unanswered"] = tgt["requests"] - tgt["answered"]
            bad_targets = [x for x in targets if x["unanswered"] >= THRASH_UNANSWERED_REPEATS]
            spoke_thrash = peak >= THRASH_RATE_PER_S or bool(bad_targets)
            thrashing = thrashing or spoke_thrash
            duration = times[-1] - times[0] if len(times) > 1 else 0.0
            spokes.append({"spoke_nbma": spoke, "requests": len(reqs), "peak_per_second": peak,
                           "average_per_second": round(len(reqs) / duration, 2) if duration else None,
                           "targets": targets[:10], "thrashing": spoke_thrash})
            if spoke_thrash:
                detail = "; ".join(f"{x['target']} asked {x['requests']} time(s), {x['unanswered']} unanswered"
                                   for x in (bad_targets or targets)[:3])
                issues.append(make_issue("warning", "NHRP_RESOLUTION_THRASHING",
                                         f"spoke {spoke} sent {len(reqs)} resolution request(s), peaking at {peak} in "
                                         f"one second: {detail}. Repeated unanswered resolutions usually mean the "
                                         "remote spoke is unreachable over the tunnel, or a redirect loop",
                                         [f for x in (bad_targets or targets)[:2] for f in x["frames"][:5]]))
        return {"thrashing": thrashing, "spokes": spokes[:ctx.max_items],
                "thresholds": {"peak_per_second": THRASH_RATE_PER_S,
                               "unanswered_repeats_per_target": THRASH_UNANSWERED_REPEATS}}

    def _encrypted_candidates(self, hubs) -> List[tuple]:
        hub_set = set(hubs)
        return [key for key, state in self.ike.items()
                if state["init_t"] is not None and hub_set and key[0] not in hub_set and key[1] not in hub_set]

    def _encrypted(self, hubs, ctx, issues, events) -> Dict[str, Any]:
        hub_set = set(hubs)
        if not hub_set:
            new = [k for k, s in self.ike.items() if s["init_t"] is not None]
            note = ("hub addresses unknown (no NHRP visible): pass hubs to classify the "
                    f"{len(new)} IKE SA(s) negotiated during the capture as spoke-to-spoke shortcuts") if new else None
            return {"shortcuts": [], "note": note, "not_visible": ENCRYPTED_NOT_VISIBLE}
        out = []
        for key in sorted(self._encrypted_candidates(hubs), key=lambda k: self.ike[k]["init_t"]):
            state = self.ike[key]
            a, b = key
            initiator = state["initiator"]
            other = b if initiator == a else a
            steps: Dict[str, Optional[Dict[str, Any]]] = {"esp_to_hub_before": None, "ike_sa_init": None,
                                                          "ike_auth": None, "direct_esp": None}
            before = None
            for (src, dst), flow in self.esp.items():
                if src in key and dst in hub_set:
                    prior = [x for x in flow["times"] if x[0] <= state["init_t"]]
                    if prior and (before is None or prior[-1][0] > before[0]):
                        before = (prior[-1][0], prior[-1][1], src, dst)
            if before:
                steps["esp_to_hub_before"] = {"t": ctx.rel(before[0]), "frame": before[1],
                                              "detail": f"last ESP {before[2]} -> hub {before[3]} before the "
                                                        "shortcut (data and routing keepalives look alike inside ESP)"}
            steps["ike_sa_init"] = {"t": ctx.rel(state["init_t"]), "frame": state["init_n"],
                                    "detail": f"{initiator} starts IKE_SA_INIT to {other}"
                                              + ("" if state["init_responses"] else ", never answered")}
            if not state["init_responses"]:
                steps["ike_sa_init"]["negative"] = True
            if state["auth_t"] is not None:
                steps["ike_auth"] = {"t": ctx.rel(state["auth_t"]), "frame": state["auth_n"],
                                     "detail": "IKE_AUTH answered"}
            direct = None
            for direction in ((a, b), (b, a)):
                flow = self.esp.get(direction)
                if flow:
                    after = [x for x in flow["times"] if x[0] >= state["init_t"]]
                    if after and (direct is None or after[0][0] < direct[0]):
                        direct = (after[0][0], after[0][1], direction)
            if direct:
                steps["direct_esp"] = {"t": ctx.rel(direct[0]), "frame": direct[1],
                                       "detail": f"first ESP {direct[2][0]} -> {direct[2][1]}"}
            order = ["ike_sa_init", "ike_auth", "direct_esp"]
            missing = next((s for s in order if steps[s] is None or steps[s].get("negative")), None)
            result = "complete" if missing is None else "incomplete"
            if missing:
                text = {"ike_sa_init": f"{other} never answered IKE_SA_INIT from {initiator}: UDP 500 blocked "
                                       "between the spokes, or the remote spoke has no matching IKEv2 policy",
                        "ike_auth": "IKE_AUTH never completed between the spokes (authentication or NAT-T problem; "
                                    "see the ipsec detector's diagnosis for this SA)",
                        "direct_esp": "the spokes negotiated IPsec but no ESP went directly between them"}[missing]
                issues.append(make_issue("error" if missing != "direct_esp" else "warning",
                                         f"SHORTCUT_MISSING_{missing.upper()}",
                                         f"spoke-to-spoke shortcut {a} <-> {b}: {text}",
                                         [s["frame"] for s in steps.values() if s]))
            else:
                events.append(make_event(ctx, direct[0], "ipsec", "shortcut_formed",
                                         f"encrypted spoke-to-spoke shortcut {a} <-> {b} carries ESP "
                                         f"({round((direct[0] - state['init_t']) * 1000, 1)} ms after IKE_SA_INIT)",
                                         direct[1]))
            out.append({"spokes": [a, b], "initiator": initiator, "result": result, "missing_step": missing,
                        "steps": steps,
                        "setup_ms": round((direct[0] - state["init_t"]) * 1000, 1) if direct else None})
        return {"shortcuts": out[:ctx.max_items], "note": None, "not_visible": ENCRYPTED_NOT_VISIBLE}
