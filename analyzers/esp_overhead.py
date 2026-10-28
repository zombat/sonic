#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. ESP Overhead Audit

EspOverheadDetector (deterministic, from packet sizes only):
    ESP is encrypted, so the cipher, the mode and the inner packet cannot be read.
    What the sizes do show: every ESP packet is
        outer IP + [UDP 8 for NAT-T] + SPI/sequence 8 + IV + ciphertext + ICV
    where the ciphertext (inner packet + padding + 2-byte trailer) is a multiple of
    the cipher's block alignment. Each cipher family has a fixed IV, ICV and
    alignment, so the set of ESP payload sizes a flow carries is consistent with
    some families and not others. Per ESP flow (source, destination, SPI) the audit
    reports:
        - the size distribution and which cipher families fit every size
        - per family, the inner packet size bounds and the per-packet overhead in
          tunnel mode and in transport mode over GRE (the DMVPN case)
        - whether the largest inner packet the tunnel MTU allows still fits the
          transport MTU once encrypted (else the router fragments after encryption)
        - outer ESP packets fragmented at the transport edge (post-encryption
          fragmentation), counted per flow with frames

Everything here is an estimate from sizes and is labelled so: a family that fits
every size by chance is possible when a flow has few distinct sizes, and the
reported confidence says how many distinct sizes back it.

Options (dict, all optional):
    transport_mtu      MTU of the link carrying ESP (default 1500)
    tunnel_mtu         the tunnel's ip mtu, the largest inner packet (for example 1400)
    gre_header_bytes   GRE header inside ESP in transport mode (default 8: GRE with a key, as
                       DMVPN tunnels usually have; 4 without a key)

Author: Raymond A Rizzo | Zombat
"""

from collections import Counter
from typing import Any, Dict, List, Optional

from analyzers.network_common import Context, add_frame, cap, make_event, make_issue, sort_issues, status_from_issues

# (family, IV bytes, ICV bytes, ciphertext alignment). Families with the same
# numbers cannot be told apart by size and are listed together.
CIPHER_FAMILIES = [
    ("AES-GCM / AES-CCM / ChaCha20-Poly1305 (16-byte ICV)", 8, 16, 4),
    ("AES-CBC + HMAC-SHA1-96", 16, 12, 16),
    ("AES-CBC + HMAC-SHA256-128", 16, 16, 16),
    ("AES-CBC + HMAC-SHA384-192", 16, 24, 16),
    ("AES-CBC + HMAC-SHA512-256", 16, 32, 16),
    ("3DES/DES-CBC + HMAC-SHA1-96", 8, 12, 8),
    ("3DES/DES-CBC + HMAC-MD5-96", 8, 12, 8),
    ("NULL encryption + HMAC-SHA1-96", 0, 12, 4),
]
ESP_HEADER = 8
ESP_TRAILER = 2
MIN_INNER = 20  # an IPv4 header (tunnel mode) or GRE + inner header (transport mode) at least
MAX_FLOWS = 5000
MAX_SIZES_PER_FLOW = 256

LIMITS = [
    "ESP is encrypted: the cipher, tunnel or transport mode, and the inner packets are estimates from packet "
    "sizes, never read from the packet. Families with equal IV, ICV and alignment (AES-GCM, AES-CCM, "
    "ChaCha20-Poly1305) cannot be told apart.",
    "Padding is assumed minimal (no TFC padding); an implementation that pads more makes the inner sizes "
    "smaller than the bounds shown.",
    "Tunnel versus transport mode cannot be read from sizes alone; both are computed. The IKE exchange that "
    "agreed the mode is encrypted (IKEv2 IKE_AUTH, IKEv1 Quick Mode).",
]


def _best_family(families: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    The family the sizes favour: the strictest grid that fits (fitting a 16-byte grid
    by chance is 4x less likely per distinct size than a 4-byte one), encryption over NULL.
    """
    return max(families, key=lambda f: (f["iv"] > 0, f["align"], f["icv"]), default=None)


def _families_for(sizes: List[int]) -> List[Dict[str, Any]]:
    """Cipher families consistent with every ESP payload size (bytes after SPI and sequence)."""
    out = []
    seen = set()
    for name, iv, icv, align in CIPHER_FAMILIES:
        if (iv, icv, align) in seen:
            for fam in out:
                if (fam["iv"], fam["icv"], fam["align"]) == (iv, icv, align):
                    fam["also"].append(name)
            continue
        ok = all(size - iv - icv >= ESP_TRAILER + MIN_INNER and (size - iv - icv) % align == 0 for size in sizes)
        if ok:
            seen.add((iv, icv, align))
            out.append({"family": name, "iv": iv, "icv": icv, "align": align, "also": []})
    return out


class EspOverheadDetector:
    """ESP size audit per flow, with cipher family and overhead estimates."""

    name = "esp_overhead"

    def __init__(self, transport_mtu: int = 1500, tunnel_mtu: Optional[int] = None, gre_header_bytes: int = 8):
        self.transport_mtu = int(transport_mtu or 1500)
        self.tunnel_mtu = int(tunnel_mtu) if tunnel_mtu else None
        self.gre_header_bytes = int(gre_header_bytes if gre_header_bytes is not None else 8)
        self.flows: Dict[tuple, Dict[str, Any]] = {}
        self.fragments: Dict[tuple, Dict[str, Any]] = {}
        self.esp_datagrams = set()  # (src, dst, id) of first fragments that carry ESP-in-UDP
        self.flows_dropped = 0

    def feed(self, rec: Dict[str, Any]):
        dp = rec.get("dp")
        ip = rec.get("ip")
        if not dp or not ip:
            return
        fragment = bool(dp["mf"]) or dp["off"] > 0
        esp = rec.get("esp")
        if fragment:
            datagram = (ip["src"], ip["dst"], dp["id"])
            if esp is not None and ip["proto"] == 17 and len(self.esp_datagrams) < 100000:
                self.esp_datagrams.add(datagram)
            if ip["proto"] == 50 or esp is not None or datagram in self.esp_datagrams:
                self._feed_fragment(rec, ip, dp, esp)
            return
        if esp is None or fragment:
            return
        key = (ip["src"], ip["dst"], esp["spi"], bool(esp["udp"]))
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= MAX_FLOWS:
                self.flows_dropped += 1
                return
            flow = {"src": ip["src"], "dst": ip["dst"], "spi": esp["spi"], "udp": bool(esp["udp"]),
                    "v6": ip["v"] == 6, "sizes": Counter(), "packets": 0, "outer_max": 0, "frames": [],
                    "first_t": rec["t"], "df_set": 0}
            self.flows[key] = flow
        payload = dp["tl"] - dp["hl"] - (8 if esp["udp"] else 0) - ESP_HEADER
        flow["packets"] += 1
        flow["outer_max"] = max(flow["outer_max"], dp["tl"])
        if dp["df"]:
            flow["df_set"] += 1
        if payload in flow["sizes"] or len(flow["sizes"]) < MAX_SIZES_PER_FLOW:
            flow["sizes"][payload] += 1
        add_frame(flow["frames"], rec["n"])

    def _feed_fragment(self, rec, ip, dp, esp):
        key = (ip["src"], ip["dst"])
        entry = self.fragments.get(key)
        if entry is None:
            entry = {"src": ip["src"], "dst": ip["dst"], "fragments": 0, "datagrams": set(), "spis": set(),
                     "largest_fragment": 0, "first_t": rec["t"], "frames": []}
            self.fragments[key] = entry
        entry["fragments"] += 1
        if len(entry["datagrams"]) < 100000:
            entry["datagrams"].add(dp["id"])
        entry["largest_fragment"] = max(entry["largest_fragment"], dp["tl"])
        if esp is not None:
            entry["spis"].add(esp["spi"])
        add_frame(entry["frames"], rec["n"])

    def present(self) -> bool:
        return bool(self.flows or self.fragments)

    def _overheads(self, flow, fam):
        natt = 8 if flow["udp"] else 0
        outer_ip = 40 if flow["v6"] else 20
        fixed = outer_ip + natt + ESP_HEADER + fam["iv"] + fam["icv"] + ESP_TRAILER
        pad_max = fam["align"] - 1
        modes = {}
        for mode, extra in (("tunnel", 20), ("transport_over_gre", self.gre_header_bytes)):

            def outer_size(packet: int) -> int:
                body = packet + extra + ESP_TRAILER
                body += (-body) % fam["align"]
                return outer_ip + natt + ESP_HEADER + fam["iv"] + body + fam["icv"]

            # overhead added to the customer's IP packet; padding adds 0..align-1 more
            entry = {"overhead_bytes": [fixed + extra, fixed + extra + pad_max]}
            largest_fit = self.transport_mtu - fixed - extra
            while largest_fit > 0 and outer_size(largest_fit) > self.transport_mtu:
                largest_fit -= 1
            entry["largest_inner_packet_without_fragmentation"] = largest_fit
            if self.tunnel_mtu:
                outer = outer_size(self.tunnel_mtu)
                entry["outer_size_at_tunnel_mtu"] = outer
                entry["fits_transport_mtu"] = outer <= self.transport_mtu
            modes[mode] = entry
        return modes

    def report(self, ctx: Context) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        flows = []
        family_votes = Counter()
        pooled_sizes = sorted({size for flow in self.flows.values() for size in flow["sizes"]})
        pooled = _best_family(_families_for(pooled_sizes))
        for flow in sorted(self.flows.values(), key=lambda f: f["first_t"]):
            sizes = sorted(flow["sizes"])
            families = _families_for(sizes)
            distinct = len(sizes)
            best = _best_family(families)
            basis = "this flow's sizes"
            if best is None:
                confidence = "none"
            elif distinct >= 4:
                confidence = "high"
            elif pooled and any(f["family"] == pooled["family"] for f in families):
                # Few sizes fit a stricter grid by chance; the capture-wide estimate is better evidence.
                best = next(f for f in families if f["family"] == pooled["family"])
                confidence = "medium"
                basis = "every ESP flow in the capture, assuming one cipher profile"
            else:
                confidence = "low"
            fam_out = []
            for fam in families:
                inner = []
                for size in sizes[:12]:
                    body = size - fam["iv"] - fam["icv"]
                    inner.append({"esp_payload": size, "packets": flow["sizes"][size],
                                  "inner_bytes": [max(body - ESP_TRAILER - (fam["align"] - 1), 0), body - ESP_TRAILER]})
                fam_out.append({"family": fam["family"], "indistinguishable_from": fam["also"],
                                "iv": fam["iv"], "icv": fam["icv"], "alignment": fam["align"],
                                "inner_size_bounds": inner, "modes": self._overheads(flow, fam)})
            if best:
                family_votes[best["family"]] += 1
            spi = f"0x{flow['spi']:08x}" if isinstance(flow["spi"], int) else str(flow["spi"])
            entry = {"src": flow["src"], "dst": flow["dst"], "spi": spi, "nat_t": flow["udp"],
                     "packets": flow["packets"], "distinct_sizes": distinct, "largest_outer_packet": flow["outer_max"],
                     "df_set_packets": flow["df_set"],
                     "size_histogram": [{"esp_payload": s, "packets": flow["sizes"][s]} for s in sizes[:24]],
                     "estimate": best["family"] if best else None, "confidence": confidence,
                     "estimate_basis": basis,
                     "consistent_families": fam_out, "frames": flow["frames"]}
            if best is None:
                issues.append(make_issue("info", "ESP_SIZES_UNEXPLAINED",
                                         f"ESP {flow['src']} -> {flow['dst']} SPI {spi}: no known cipher family fits "
                                         "every size (TFC padding, a cipher not in the table, or not ESP)",
                                         flow["frames"]))
            elif self.tunnel_mtu:
                modes = fam_out[[f["family"] for f in fam_out].index(best["family"])]["modes"]
                over = {mode: data["outer_size_at_tunnel_mtu"] for mode, data in modes.items()
                        if not data.get("fits_transport_mtu", True)}
                if over:
                    sizes_text = ", ".join(f"{size} bytes in {mode.replace('_', ' ')} mode" for mode, size in over.items())
                    text = (f"ESP {flow['src']} -> {flow['dst']} SPI {spi} (estimated {best['family']}): a "
                            f"{self.tunnel_mtu}-byte inner packet becomes {sizes_text}, over the "
                            f"{self.transport_mtu}-byte transport MTU: the router fragments after encryption; "
                            "lower the tunnel ip mtu")
                    issues.append(make_issue("warning", "ESP_EXCEEDS_TRANSPORT_MTU", text, flow["frames"][:1],
                                             estimate=True))
            flows.append(entry)
        fragments = []
        for entry in sorted(self.fragments.values(), key=lambda e: e["first_t"]):
            spis = sorted(f"0x{s:08x}" for s in entry["spis"] if isinstance(s, int))
            item = {"src": entry["src"], "dst": entry["dst"], "fragments": entry["fragments"],
                    "datagrams": len(entry["datagrams"]), "largest_fragment": entry["largest_fragment"],
                    "spis": spis, "first_t": ctx.rel(entry["first_t"]), "frames": entry["frames"]}
            text = (f"ESP {entry['src']} -> {entry['dst']} fragmented after encryption: {entry['fragments']} "
                    f"fragment(s) of {item['datagrams']} datagram(s), largest {entry['largest_fragment']} bytes; "
                    "the receiver must reassemble before decrypting (CPU cost, drops under load): lower the tunnel "
                    "ip mtu or adjust the MSS so encrypted packets fit the transport MTU")
            issues.append(make_issue("warning", "ESP_OUTER_FRAGMENTED", text, entry["frames"]))
            events.append(make_event(ctx, entry["first_t"], "esp", "outer_fragmented", text, entry["frames"][0]))
            fragments.append(item)
        present = self.present()
        status = status_from_issues(issues, present)
        if not present:
            verdict = "No ESP in this capture."
        else:
            parts = []
            if flows:
                if family_votes:
                    estimates = ", ".join(f"{family} on {count} flow(s)" for family, count in family_votes.most_common(3))
                    parts.append(f"{len(flows)} ESP flow(s); sizes fit {estimates} (estimate)")
                else:
                    parts.append(f"{len(flows)} ESP flow(s); no known cipher family fits the sizes")
            if fragments:
                parts.append(f"{sum(f['fragments'] for f in fragments)} ESP fragment(s): encrypted packets "
                             "fragmented at the transport edge")
            elif flows:
                parts.append(f"no ESP fragmentation, largest outer packet {max(f['largest_outer_packet'] for f in flows)} bytes")
            verdict = "; ".join(parts) + "."
        flows_list, flows_omitted = cap(flows, ctx.max_items)
        return {
            "detector": self.name,
            "status": status,
            "verdict": verdict,
            "estimate": True,
            "assumptions": {"transport_mtu": self.transport_mtu, "tunnel_mtu": self.tunnel_mtu,
                            "gre_header_bytes": self.gre_header_bytes},
            "summary": {"esp_flows": len(self.flows), "esp_fragments": sum(f["fragments"] for f in fragments),
                        "flows_dropped_at_cap": self.flows_dropped,
                        "family_estimates": dict(family_votes),
                        "capture_wide_estimate": pooled["family"] if pooled else None,
                        "capture_wide_distinct_sizes": len(pooled_sizes)},
            "flows": flows_list,
            "flows_omitted": flows_omitted,
            "outer_fragmentation": fragments,
            "limits": LIMITS,
            "issues": sort_issues(issues),
            "events": events,
        }
