#!/usr/bin/env python3
"""
S.O.N.I.C. MCP Server

FastMCP server exposing S.O.N.I.C. VoIP analysis and the deterministic network
detectors (IPsec/IKE/ESP, GRE/NHRP, BGP/OSPF/EIGRP, ICMP/ARP) as tools for AI
assistants. Works with Claude Desktop, Cline, and other MCP clients.

Network tools (no LLM): analyze_network_pcap, analyze_vpn_pcap, analyze_routing_pcap,
audit_cleartext_pcap, analyze_convergence_pcap.

Usage:
    python3 mcp_server.py

Configure in Claude Desktop mcp.json:
    {
      "mcpServers": {
        "sonic": {
          "command": "python3",
          "args": ["/home/noot/sonic/mcp_server.py"],
          "env": {
            "SONIC_LLM_PROVIDER": "anthropic"
          }
        }
      }
    }
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

from fastmcp import FastMCP

# Add parent directory to path to import sonic modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.orchestrator import run_analysis_mode
from extractors.tshark import extract_sip_data
from extractors.auth_info import extract_auth_and_registration_info
from analyzers.call_quality_scoring import CallQualityScorer
from analyzers.rtp_mos_analysis import AdvancedRTPMOSAnalyzer
from llm_config import list_available_providers
from analyzers.network_orchestrator import (
    analyze_convergence_capture,
    analyze_network_capture,
    analyze_routing_capture,
    analyze_vpn_capture,
    audit_cleartext_capture,
)

# Create MCP server
mcp = FastMCP(
    "S.O.N.I.C. VoIP and Network Analyzer",
    instructions=(
        "S.O.N.I.C. analyzes pcap/pcapng files on this machine. Pass absolute file paths. "
        "For any capture that is not only VoIP (IPsec, GRE/DMVPN, BGP, OSPF, EIGRP, ICMP, ARP), "
        "start with analyze_network_pcap: it reports which protocols are present and gives "
        "deterministic verdicts without an LLM. Use analyze_vpn_pcap to prove inter-site traffic "
        "is encrypted and the IPsec/DMVPN overlay formed, and analyze_routing_pcap for adjacency "
        "health and failover timelines. To gate on encryption, call audit_cleartext_pcap: it "
        "returns passed true/false against an allowlist, so one leaked cleartext packet fails it. "
        "To time a failover, call analyze_convergence_pcap with the event time. For SIP/RTP calls "
        "use quick_quality_check (no LLM) or analyze_pcap (LLM-assisted)."
    ),
)


@mcp.tool()
def analyze_pcap(
    file_path: str,
    provider: str = "ollama",
    model: str = "combined",
    enable_quality: bool = True,
    enable_mos: bool = True
) -> Dict[str, Any]:
    """
    Analyze a VoIP packet capture file for call quality issues.
    
    Args:
        file_path: Absolute path to pcap/pcapng file on disk
        provider: LLM provider (ollama, anthropic, openai, azure)
        model: Analysis mode (fast, detailed, combined)
        enable_quality: Include call quality scoring
        enable_mos: Include MOS (Mean Opinion Score) analysis
    
    Returns:
        JSON with diagnostic report, quality analysis, and recommendations
    
    Example:
        analyze_pcap("/path/to/capture.pcapng", provider="anthropic", model="fast")
    """
    try:
        # Validate file exists
        if not os.path.exists(file_path):
            return {
                "status": "error",
                "error": f"File not found: {file_path}"
            }
        
        if not os.access(file_path, os.R_OK):
            return {
                "status": "error",
                "error": f"File not readable: {file_path}"
            }
        
        # Run analysis
        result = run_analysis_mode(
            file_path=file_path,
            model_mode=model,
            enable_quality=enable_quality,
            enable_mos=enable_mos,
            provider=provider
        )
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__
        }


@mcp.tool()
def quick_quality_check(file_path: str) -> Dict[str, Any]:
    """
    Fast quality-only analysis without AI model inference.
    
    Provides MOS scores, quality grades, and network metrics.
    No LLM required - analyzes RTP streams directly.
    
    Args:
        file_path: Absolute path to pcap/pcapng file on disk
    
    Returns:
        JSON with quality score, grade, MOS analysis, network metrics
    
    Example:
        quick_quality_check("/path/to/capture.pcapng")
    """
    try:
        # Validate file
        if not os.path.exists(file_path):
            return {"status": "error", "error": f"File not found: {file_path}"}
        
        # Extract SIP data
        sip_data = extract_sip_data(file_path)
        if not sip_data:
            return {"status": "error", "error": "No SIP data found in capture"}
        
        results = {"status": "success", "file": file_path}
        
        # Run quality scoring
        try:
            auth_data = extract_auth_and_registration_info(file_path)
            quality_scorer = CallQualityScorer()
            quality_result = quality_scorer.score_call_quality(
                sip_data,
                [],
                None,
                file_path,
                auth_data=auth_data,
            )
            results["quality_analysis"] = quality_result
        except Exception as e:
            results["quality_error"] = str(e)
        
        # Run MOS analysis
        try:
            mos_analyzer = AdvancedRTPMOSAnalyzer()
            mos_result = mos_analyzer.analyze_rtp_streams(sip_data, file_path)
            results["mos_analysis"] = mos_result
        except Exception as e:
            results["mos_error"] = str(e)
        
        return results
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__
        }


@mcp.tool()
def list_llm_providers() -> Dict[str, Any]:
    """
    List available LLM providers and their model options.
    
    Returns:
        JSON with provider list, model mappings, and current configuration
    
    Example:
        list_llm_providers()
    """
    try:
        providers = list_available_providers()
        
        # Add current config
        providers["current_config"] = {
            "provider": os.getenv("SONIC_LLM_PROVIDER", "ollama"),
            "anthropic_key_set": bool(os.getenv("ANTHROPIC_API_KEY")),
            "openai_key_set": bool(os.getenv("OPENAI_API_KEY"))
        }
        
        return providers
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@mcp.tool()
def analyze_batch_pcaps(
    directory: str,
    provider: str = "anthropic",
    model: str = "fast",
    mode: str = "sequential"
) -> Dict[str, Any]:
    """
    Batch analyze multiple pcaps in a directory.
    
    Supports sequential (one at a time) or parallel (multiple at once) processing.
    
    Args:
        directory: Path to directory containing pcap files
        provider: LLM provider (ollama/anthropic/openai/azure)
        model: Analysis mode (fast/detailed)
        mode: Processing mode (sequential/parallel)
    
    Returns:
        Batch results with per-file analysis and aggregate metrics
    
    Example:
        analyze_batch_pcaps("/path/to/pcaps", provider="anthropic", mode="parallel")
    """
    from ai.batch_streaming import analyze_batch, ProcessingMode
    from pathlib import Path as PathlibPath
    
    try:
        if not os.path.isdir(directory):
            return {"status": "error", "error": f"Directory not found: {directory}"}
        
        files = list(PathlibPath(directory).glob("*.pcap*"))
        if not files:
            return {"status": "error", "error": f"No pcap files in {directory}"}
        
        mode_enum = ProcessingMode.PARALLEL if mode == "parallel" else ProcessingMode.SEQUENTIAL
        return analyze_batch(
            [str(f) for f in files],
            provider=provider,
            model=model,
            mode=mode_enum,
            max_workers=3
        )
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__
        }


@mcp.tool()
def analyze_pcap_partial_streaming(
    file_path: str,
    provider: str = "anthropic"
) -> Dict[str, Any]:
    """
    Partial streaming: returns quality/MOS immediately, streams LLM after.
    
    Best for: Getting quick quality insight while LLM analysis runs in background.
    Returns timing metrics showing how fast quality results were available.
    
    Args:
        file_path: Absolute path to pcap file
        provider: LLM provider (anthropic/openai/azure for streaming)
    
    Returns:
        Complete analysis {quality, mos, llm_analysis, timing}
    
    Example:
        analyze_pcap_partial_streaming("/path/to/capture.pcapng", provider="anthropic")
    """
    from ai.partial_streaming import run_partial_analysis_streaming
    
    try:
        if not os.path.exists(file_path):
            return {"status": "error", "error": f"File not found: {file_path}"}
        
        return run_partial_analysis_streaming(file_path, provider=provider)
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__
        }


@mcp.tool()
def analyze_network_pcap(
    file_path: str,
    detectors: Optional[List[str]] = None,
    peers: Optional[List[str]] = None,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    include_sip: bool = True,
    max_items: int = 25,
    hubs: Optional[List[str]] = None,
    expected_mss: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Analyze any packet capture (not only VoIP) and return deterministic findings as JSON.

    No LLM is used: every verdict comes from decoding the packets (tshark, with scapy as
    the fallback). Use this as the first tool on an unknown capture: it reports which
    protocols are present and runs every detector that applies.

    Detectors (pass a subset in `detectors`; default is the first six):
      - "ipsec": IKEv1/IKEv2 negotiation per IKE SA (outcome: established, failed,
        no_response, auth_likely_failed, ...), the IKEv2 proposals offered and chosen
        (encryption, PRF, integrity, DH group, weak algorithms), KE groups and
        INVALID_KE_PAYLOAD retries, NAT detection hashes checked against the addresses
        on the wire and the move to UDP 4500, DPD liveness checks (interval, unanswered),
        a "diagnosis" per SA (ok, proposal_mismatch, dh_group_mismatch, auth_failed,
        auth_no_reply, nat_t_missing, no_reply, liveness_lost, peer_lost_sa), NOTIFY
        errors, IKE SA collisions, rekeys, ESP flows per SPI (sequence gaps, duplicates,
        an old SPI still used after a newer one took over), NAT-T, and the encryption
        verdict "encrypted" or "cleartext_seen" between the same two endpoints.
      - "gre_nhrp": GRE tunnels (keys, inner protocols, key mismatch), NHRP registrations
        (spoke -> hub, result registered/refused/unanswered), hub and spoke roles,
        resolution requests/replies, redirects (DMVPN Phase 3), error indications,
        and spoke-to-spoke tunnels.
      - "dmvpn_phase3": per redirected flow, the ordered Phase 3 steps (via_hub,
        redirect, resolution_request, resolution_reply, direct) with frames and
        times, the first missing step and why; hub-relayed spoke traffic with no
        redirect; resolution thrashing; and, with `hubs`, encrypted spoke-to-spoke
        shortcuts (IKE then direct ESP) when NHRP is hidden inside ESP.
      - "routing": BGP sessions (state, OPEN AS/hold time/router ID/capabilities,
        keepalive cadence, UPDATE timing, NOTIFICATION code/subcode decoded with a hint,
        why each session went down: hold_timer_expired, notification, tcp_rst, tcp_fin
        or hold_timer_expired_inferred; the TCP MSS in each SYN and SYN-ACK, checked
        against `expected_mss`), OSPF per link (hello/dead/mask/area/auth/MTU mismatches,
        one-way neighbors, DR/BDR, hello gaps, adjacencies stuck in EXSTART or EXCHANGE
        from DB Description retransmissions), EIGRP (K-value and AS mismatches,
        goodbyes, hold time expiry, INIT restarts, queries/SIA), plus a failover_timeline.
      - "reachability": ICMP echo loss/RTT per source->destination pair with outage
        windows, ICMP unreachable/TTL-exceeded with decoded codes, ARP with no reply,
        duplicate IPs.
      - "conversations": protocol mix by packets and bytes, top conversations, top talkers.
      Run only when named: "cleartext_audit" (see audit_cleartext_pcap) and
      "convergence" (see analyze_convergence_pcap).

    Output (JSON):
        {"status": "success", "overall_status": "ok"|"warning"|"problem"|"not_present",
         "protocols_present": [...], "detectors_run": [...], "verdicts": {detector: sentence},
         "issues": [{severity, code, message, frames, detector}], "timeline": [{t, time,
         protocol, event, detail, frame}], "capture": {...}, plus one section per detector
         ("ipsec", "gre_nhrp", "routing", "reachability", "conversations") and "sip"}.
        On failure: {"status": "error", "error": "..."}.
        Each section has "status" and a one-sentence "verdict". Times "t" are seconds
        from the first frame; "frames" are Wireshark frame numbers to inspect.
        overall_status is the worst detector status (conversations and SIP excluded).

    Limits: a verdict covers only what crossed the capture point. IKEv2 IKE_AUTH is
    encrypted, so the child SA proposal, identities and AUTH are never visible: a PSK
    mismatch shows only as a small encrypted IKE_AUTH response or as retransmissions
    with no reply, and is labelled as a heuristic. DPD is recognised by message size.
    INVALID_SPI normally travels encrypted; only an unprotected one is read. ESP with
    NULL encryption cannot be told apart from real encryption without keys. With
    tunnel protection, GRE, NHRP and BGP travel inside ESP and are not visible on the
    transport link. OSPFv3 and IS-IS are not decoded.

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        detectors: Optional list from ["ipsec", "gre_nhrp", "dmvpn_phase3", "routing",
            "reachability", "conversations", "cleartext_audit", "convergence"]. Unknown
            names return an error listing the valid ones.
        peers: Optional list of IP addresses (for example the WAN addresses of the hub
            and spokes). The encryption verdict then judges all traffic between any two
            of them. Without it, the verdict judges every pair that exchanged IKE/ESP,
            plus GRE tunnel endpoints.
        display_filter: Optional Wireshark display filter applied before detection,
            for example "ip.addr==192.0.2.1" or "not arp". Needs tshark.
        max_packets: Optional cap on frames read (for very large captures).
        include_sip: When SIP is present, also run the existing SIP quality scoring
            (no LLM) and attach it under "sip". For full SIP call analysis use analyze_pcap.
        max_items: Cap on the length of each list in the result (default 25).
        hubs: Optional hub NBMA (transport) addresses, for dmvpn_phase3 to classify
            IKE SAs between two other addresses as spoke-to-spoke shortcuts.
        expected_mss: Optional TCP MSS the BGP SYNs should carry (for example 1360
            for "ip tcp adjust-mss 1360"); larger or missing values are flagged.

    Returns:
        The JSON object described under Output above.

    Example:
        analyze_network_pcap("/captures/hub-wan.pcap")
        analyze_network_pcap("/captures/r1-r2.pcap", detectors=["routing"])
    """
    try:
        return analyze_network_capture(
            file_path,
            detectors=detectors,
            peers=peers,
            display_filter=display_filter,
            max_packets=max_packets,
            include_sip=include_sip,
            max_items=max_items,
            options={"hubs": hubs, "expected_mss": expected_mss},
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def analyze_vpn_pcap(
    file_path: str,
    peers: Optional[List[str]] = None,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
    hubs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Prove from packets whether VPN traffic between sites is encrypted and whether the
    IPsec and DMVPN overlay formed. Deterministic, no LLM.

    Use it on a capture of a WAN/underlay link (between hub and spoke routers). It runs
    the "ipsec", "gre_nhrp" and "dmvpn_phase3" detectors of analyze_network_pcap and puts the
    answers first:

      - encryption_verdict: "encrypted" (only ESP/IKE/NAT-T keepalives between the
        peers), "cleartext_seen" (some ICMP, GRE without ESP, TCP/UDP payload or routing
        protocol between the same endpoints), "no_esp" (IKE seen but no ESP: the
        tunnel never carried traffic or failed), or "not_present".
      - verdict: one sentence, for example "all inter-site traffic encrypted: 2 peer
        pair(s), 480 ESP packets, no cleartext between the same endpoints" or
        "cleartext seen: icmp 198.51.100.2->192.0.2.1 4 packets".
      - negotiation_verdict: IKE SA outcomes (established, failed with the NOTIFY name,
        no_response, auth_likely_failed).
      - overlay_verdict: NHRP registrations per hub (who registered, who was refused).
      - phase3_verdict: the DMVPN Phase 3 sequence per redirected flow (which step is
        missing when one is), or, with `hubs`, the encrypted spoke-to-spoke shortcuts.
      - ike_diagnoses: one line per IKE SA, with a stable code: ok, proposal_mismatch,
        dh_group_mismatch, auth_failed, auth_no_reply, nat_t_missing, udp_4500_blocked,
        no_reply, no_esp_after_auth, liveness_lost, peer_lost_sa. Each SA in
        ipsec.ike_sas also has "negotiation": proposals_offered and proposal_chosen
        (encryption, prf, integrity, dh_group, weak), ke_groups_offered,
        invalid_ke_payload, nat_detection (nat_detected, translated, moved_to_udp_4500)
        and liveness (DPD checks, interval_s_by_sender, unanswered_checks).

    Where to capture: on the physical/underlay link, ESP proves encryption. If you
    capture on the tunnel interface itself you see decrypted traffic, and GRE without
    ESP on the underlay means the tunnel has no IPsec protection.

    Output (JSON):
        {"status": "success", "encryption_verdict", "verdict", "negotiation_verdict",
         "overlay_verdict", "phase3_verdict", "ike_diagnoses", "ipsec": {peer_pairs,
         cleartext, ike_sas, esp_flows, nat_traversal, issues}, "gre_nhrp": {hubs,
         spokes, registrations, resolutions, redirects, error_indications, tunnels,
         spoke_to_spoke_tunnels, issues}, "dmvpn_phase3": {flows, hub_relayed_without_redirect,
         resolution_thrashing, encrypted_shortcuts, cannot_show, issues}, "issues",
         "timeline", "capture"} or {"status": "error", "error"}.

    Limits: IKE_AUTH and everything after it is encrypted (see analyze_network_pcap).
    A PSK mismatch is never visible as a hash: it shows as auth_failed (a small
    encrypted IKE_AUTH response) or auth_no_reply (retransmissions, no reply).

    Args:
        file_path: Absolute path to a pcap/pcapng file.
        peers: Optional list of the VPN endpoints' WAN IP addresses. All traffic between
            any two of them is judged. Without it, pairs that spoke IKE/ESP and GRE
            endpoints are judged.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
        max_packets: Optional cap on frames read.
        max_items: Cap on list lengths (default 25).
        hubs: Optional hub NBMA (WAN) addresses. On a protected DMVPN the NHRP steps are
            inside ESP; with the hubs named, an IKE SA between two other addresses is
            checked as a spoke-to-spoke shortcut (IKE_SA_INIT, IKE_AUTH, direct ESP).

    Returns:
        The JSON object described under Output above.

    Example:
        analyze_vpn_pcap("/captures/hub-wan.pcap", peers=["192.0.2.1", "198.51.100.2"])
    """
    try:
        return analyze_vpn_capture(file_path, peers=peers, display_filter=display_filter,
                                   max_packets=max_packets, max_items=max_items, hubs=hubs)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def analyze_routing_pcap(
    file_path: str,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
    expected_mss: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Check routing protocol health (BGP, OSPF, EIGRP) and reachability from a capture,
    and read a failover in order. Deterministic, no LLM.

    Use it to prove that adjacencies formed, to find why they did not (mismatched
    timers, AS, K-values, MTU, refused TCP 179, NOTIFICATION codes), or to show how
    routing reconverged after a router or link failed. It runs the "routing" and
    "reachability" detectors of analyze_network_pcap and puts first:

      - verdict: per protocol, for example "BGP: 1 of 3 session(s) established at
        capture end, 1 session reset(s); problems: BGP_NOTIFICATION."
      - reachability_verdict: ping loss per pair, ICMP errors, ARP without replies.
      - failover_timeline: ordered events with "t" (seconds from the first frame):
        BGP established/notification/down/End-of-RIB/withdraw, OSPF hello_gap,
        neighbor_down/neighbor_up, dr_change, router_silent, EIGRP goodbye,
        hold_expired, adjacency_init, query.
      - ping_outages: runs of consecutive unanswered pings with start, recovery time
        and duration. Compare them with the timeline to measure convergence time.

    Capture both sides of an adjacency when you can: a link capture shows hellos from
    every router on that link. Issue codes are stable strings, for example
    OSPF_HELLO_INTERVAL_MISMATCH, OSPF_MTU_MISMATCH, OSPF_EXSTART_STUCK,
    OSPF_EXCHANGE_STUCK, OSPF_ONE_WAY, BGP_TCP_REFUSED, BGP_PEER_SILENT,
    BGP_MSS_NOT_CLAMPED, EIGRP_K_VALUE_MISMATCH, EIGRP_NEIGHBOR_SILENT, ICMP_LOSS.
    Each BGP session lists "downs" with a cause (hold_timer_expired, notification,
    bfd_down, tcp_rst, tcp_fin, hold_timer_expired_inferred) and "tcp_mss" per
    connection; each OSPF adjacency has "database_exchange" (stuck: exstart or
    exchange, and the cause, for example the DBD MTU mismatch).

    Output (JSON):
        {"status": "success", "verdict", "reachability_verdict", "failover_timeline",
         "ping_outages", "routing": {"bgp": {sessions}, "ospf": {links}, "eigrp": {links},
         issues}, "reachability": {echo, icmp_errors, arp_unanswered}, "issues",
         "timeline", "capture"} or {"status": "error", "error"}.

    Args:
        file_path: Absolute path to a pcap/pcapng file.
        display_filter: Optional Wireshark display filter applied first (needs tshark),
            for example "ospf or icmp".
        max_packets: Optional cap on frames read.
        max_items: Cap on list lengths (default 25).
        expected_mss: Optional MSS the BGP SYN and SYN-ACK should carry (for example
            1360 for "ip tcp adjust-mss 1360"). The value is what crossed the capture
            point; adjust-mss rewrites SYNs only where they cross the interface it is on.

    Returns:
        The JSON object described under Output above.

    Example:
        analyze_routing_pcap("/captures/r1-r2-failover.pcap")
    """
    try:
        return analyze_routing_capture(file_path, display_filter=display_filter,
                                       max_packets=max_packets, max_items=max_items,
                                       expected_mss=expected_mss)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def audit_cleartext_pcap(
    file_path: str,
    allow: Optional[List[str]] = None,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
) -> Dict[str, Any]:
    """
    Assert that a crypto transport link carried nothing but allowed traffic: every frame
    is checked against an allowlist and the result is pass or fail. Deterministic, no LLM.

    Use it as a gate after capturing a WAN/transport link of an IPsec or DMVPN network:
    one leaked GRE, BGP, OSPF, ICMP, ARP or any other frame outside the allowlist fails
    the audit and is reported by protocol and address pair with its frame numbers.

    Allowlist tokens (default ["crypto"]):
      crypto (= esp, ike, nat-t), esp (IP 50 and ESP-in-UDP), ike (UDP 500/4500),
      nat-t (ESP-in-UDP, IKE on 4500, keepalives), ah, arp, icmp, icmpv6,
      routing (= bgp, ospf, eigrp, rip, ldp, bfd, pim, vrrp, hsrp) or each by name,
      gre, l2-control (= cdp, stp, lldp, lacp, loop: Cisco keepalives, EtherType 0x9000),
      dhcp, dns, ntp, ssh, snmp, syslog, tacacs, radius, tcp:N, udp:N, proto:N,
      ethertype:0xNNNN. Scope a token to addresses with @, for example
      "icmp@203.0.113.1" (ICMP only to or from the provider) or "bgp@198.51.100.0/30".
    A Cisco router's transport link normally also carries loopback keepalives and CDP:
    add "l2-control" to accept them, or leave it out to treat them as findings.

    Output (JSON):
        {"status": "success", "passed": true|false, "result": "pass"|"fail", "verdict",
         "allowlist", "frames_audited", "frames_allowed", "frames_outside_allowlist",
         "first_violation_frame", "by_protocol": [{protocol, category, packets, bytes,
         pairs, first_frame}], "violations": [{protocol, category, src, dst, packets,
         bytes, first_frame, first_t, last_frame, last_t, frames, hint}],
         "allowed_by_rule", "cannot_show", "capture"} or {"status": "error", "error"}.
        Categories: crypto, tunnel_without_encryption (GRE outside ESP), routing, icmp,
        layer2, authenticated_only (AH), cleartext. An empty capture fails.

    Limits (also returned in "cannot_show"): only frames that crossed this capture
    point and that the capture kept are audited; ESP with NULL or weak encryption
    passes, because ESP payload is opaque; a non-first IP fragment has no port, so
    without tshark's reassembly a fragment of allowed UDP is reported as udp.

    Args:
        file_path: Absolute path to a pcap/pcapng file.
        allow: Optional list of allowlist tokens (above). An unknown token is an error.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
            Narrowing the capture also narrows what the audit proves.
        max_packets: Optional cap on frames read (the audit then covers only those).
        max_items: Cap on the violations list (default 25; counts stay complete).

    Returns:
        The JSON object described under Output above.

    Example:
        audit_cleartext_pcap("/captures/br1-wan.pcap")
        audit_cleartext_pcap("/captures/br1-wan.pcap", allow=["crypto", "l2-control", "icmp@172.16.11.1"])
    """
    try:
        return audit_cleartext_capture(file_path, allow=allow, display_filter=display_filter,
                                       max_packets=max_packets, max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def analyze_convergence_pcap(
    file_path: str,
    event_time: Optional[Union[str, float]] = None,
    failed_peer: Optional[str] = None,
    hold_time: Optional[float] = None,
    silence_s: Optional[float] = None,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
) -> Dict[str, Any]:
    """
    Measure a failover from one capture and say what drove it. Deterministic, no LLM.

    From an event (for example the moment a runbook stopped a link or a router) or,
    without one, from the first sign of failure, it measures the time to detection,
    to the first BGP UPDATE or withdrawal on the surviving path, and to traffic
    resuming, and names the driver.

    Signals used: the last ESP/IKE packet from a peer before it went quiet; IKEv2 DPD
    liveness checks left unanswered and the last retransmission (DPD giving up); BGP
    NOTIFICATIONs (Hold Timer Expired, Cease/BFD Down), RST or FIN, and a hold expiry
    inferred from a speaker's silence; BGP UPDATEs on sessions not involving the failed
    peer; ICMP echo outages and their recovery; and, on encrypted transport captures,
    the surviving tunnels' ESP rate rising to carry the failed tunnel's traffic.

    Output (JSON):
        {"status": "success", "verdict", "driver": {"mechanism": "bfd"|"bgp_hold_timer"|
         "dpd"|"explicit_close"|"undetermined", "reason"}, "failed_peer",
         "failed_peer_source", "event_time", "measurements": {origin, origin_t,
         first_failure_sign, detection, first_update_on_surviving_path, traffic_resumed,
         event_to_first_failure_sign_s, event_to_detection_s, event_to_first_update_s,
         event_to_traffic_resumed_s}, "timeline": [{t, time, delta_s, phase (event,
         failure, teardown, detection, reaction, recovery), signal, peer, detail, frame}],
         "traffic_shift", "issues", "cannot_show", "capture"} or {"status": "error"}.
        Deltas are seconds from the event (or the first failure sign); a negative
        first_failure_sign delta means the failure showed before the given event time.

    Limits (also returned in "cannot_show"): on a protected tunnel BGP and user traffic
    are inside ESP, so the reaction is inferred from ESP rates and the driver from
    timing; DPD is recognised by size; the event time comes from another clock than
    the capture, so a skew shifts every delta; only this capture point is seen.

    Args:
        file_path: Absolute path to a pcap/pcapng file.
        event_time: Optional time of the event: epoch seconds ("1767225630.5"), seconds
            from the first frame ("30" or "+30"), or ISO-8601 with a zone
            ("2026-10-27T19:49:30Z"). Without it the earliest failure sign is the start,
            and a quiet period counts only when the other side kept sending into it.
        failed_peer: Optional address of the peer that failed (a hub's WAN address, or a
            BGP neighbor). Without it, it is inferred and the report says how.
        hold_time: Optional BGP hold time in seconds, used to infer a hold-timer driven
            failover from timing when BGP itself is inside ESP and not visible.
        silence_s: Optional seconds of silence that count as a peer stopping. Default:
            twice the direction's usual longest gap, at least 3 s, and at least 1.5 DPD
            intervals when DPD is periodic.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
        max_packets: Optional cap on frames read.
        max_items: Caps the timeline at four times this (default 25).

    Returns:
        The JSON object described under Output above.

    Example:
        analyze_convergence_pcap("/captures/br1-wan-failover.pcap", event_time="+30")
        analyze_convergence_pcap("/captures/core1-wan.pcap", event_time="2026-10-27T19:49:30Z",
                                 failed_peer="172.16.1.2", hold_time=30)
    """
    try:
        return analyze_convergence_capture(file_path, event_time=event_time, failed_peer=failed_peer,
                                           hold_time=hold_time, silence_s=silence_s,
                                           display_filter=display_filter, max_packets=max_packets,
                                           max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


if __name__ == "__main__":
    # Run MCP server
    mcp.run()
