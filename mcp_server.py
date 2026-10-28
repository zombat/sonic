#!/usr/bin/env python3
"""
S.O.N.I.C. MCP Server

FastMCP server exposing S.O.N.I.C. VoIP analysis and the deterministic network
detectors (IPsec/IKE/ESP, GRE/NHRP, BGP/OSPF/EIGRP, ICMP/ARP) as tools for AI
assistants. Works with Claude Desktop, Cline, and other MCP clients.

Network tools (no LLM): analyze_network_pcap, analyze_vpn_pcap, analyze_routing_pcap,
analyze_data_plane_pcap, correlate_pcaps, merge_pcap_timelines.

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
from typing import Dict, Any, List, Optional

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
    analyze_data_plane_capture,
    analyze_network_capture,
    analyze_routing_capture,
    analyze_vpn_capture,
)
from analyzers.correlate import correlate_captures
from analyzers.timeline import merge_timelines

# Create MCP server
mcp = FastMCP(
    "S.O.N.I.C. VoIP and Network Analyzer",
    instructions=(
        "S.O.N.I.C. analyzes pcap/pcapng files on this machine. Pass absolute file paths. "
        "For any capture that is not only VoIP (IPsec, GRE/DMVPN, BGP, OSPF, EIGRP, ICMP, ARP), "
        "start with analyze_network_pcap: it reports which protocols are present and gives "
        "deterministic verdicts without an LLM. Use analyze_vpn_pcap to prove inter-site traffic "
        "is encrypted and the IPsec/DMVPN overlay formed, and analyze_routing_pcap for adjacency "
        "health and failover timelines. For SIP/RTP calls use quick_quality_check (no LLM) or "
        "analyze_pcap (LLM-assisted)."
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
    options: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Analyze any packet capture (not only VoIP) and return deterministic findings as JSON.

    No LLM is used: every verdict comes from decoding the packets (tshark, with scapy as
    the fallback). Use this as the first tool on an unknown capture: it reports which
    protocols are present and runs every detector that applies.

    Detectors (pass a subset in `detectors`; default is all):
      - "ipsec": IKEv1/IKEv2 negotiation per IKE SA (outcome: established, failed,
        no_response, auth_likely_failed, ...), NOTIFY errors such as NO_PROPOSAL_CHOSEN,
        retransmissions without a reply, rekeys (CREATE_CHILD_SA, ESP SPI changes),
        ESP flows per SPI (packets, sequence gaps, duplicates = possible replay),
        NAT-T (IKE on UDP 4500, ESP-in-UDP, keepalives), and the encryption verdict:
        "encrypted" or "cleartext_seen" for traffic between the same two endpoints.
      - "gre_nhrp": GRE tunnels (keys, inner protocols, key mismatch), NHRP registrations
        (spoke -> hub, result registered/refused/unanswered), hub and spoke roles,
        resolution requests/replies, redirects (DMVPN Phase 3), error indications,
        and spoke-to-spoke tunnels.
      - "routing": BGP sessions (state, OPEN AS/hold time/router ID, NOTIFICATION
        code/subcode decoded with a hint, resets, End-of-RIB, refused TCP 179), OSPF
        per link (hello/dead/mask/area/auth/MTU mismatches, one-way neighbors, DR/BDR,
        hello gaps past the dead interval), EIGRP (K-value and AS mismatches, goodbyes,
        hold time expiry, INIT restarts, queries/SIA), plus a failover_timeline.
      - "reachability": ICMP echo loss/RTT per source->destination pair with outage
        windows, ICMP unreachable/TTL-exceeded with decoded codes, ARP with no reply,
        duplicate IPs.
      - "path_mtu": ICMP Fragmentation Needed / Packet Too Big (router, next-hop MTU,
        the probe frame it refers to), PMTUD black holes (large DF probes or TCP
        segments that vanished with no ICMP while smaller ones got through), IP
        fragments (complete, incomplete, overlapping), reassembly timeouts.
      - "esp_overhead": per ESP SA, packet sizes against cipher families (AES-GCM,
        AES-CBC with SHA1/SHA2, 3DES, NULL), inner size bounds, overhead in tunnel and
        transport-over-GRE mode, tunnel MTU fit, ESP fragmented after encryption.
        Estimates from sizes only; ESP is encrypted.
      - "tcp": per connection: SYN without SYN-ACK, refused, retransmissions (fast or
        timeout), gaps, duplicate ACKs, zero window, window full, RSTs, MSS/window
        scale, RTT and RFC 6298 RTO, and a verdict (no_answer, refused,
        receiver_buffer_exhausted, loss_on_path, receive_window_limited, reset, healthy).
      - "tls": ClientHello SNI, versions, suites, ALPN, groups; ServerHello choice;
        TLS 1.2 certificate (subject, issuer, validity at capture time); cleartext
        alerts; an optional baseline (see options).
      - "qos": DSCP per flow, GRE inner vs outer DSCP, ESP outer DSCP per SA, RTP
        streams with loss, RFC 3550 jitter, DSCP and an E-model MOS estimate, ECN CE.
      - "conversations": protocol mix by packets and bytes, top conversations, top talkers.

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        detectors: Optional list from ["ipsec", "gre_nhrp", "routing", "reachability",
            "conversations"]. Unknown names return an error listing the valid ones.
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
        options: Optional per-detector settings: {"esp_overhead": {"transport_mtu": 1500,
            "tunnel_mtu": 1400, "gre_header_bytes": 8}, "tls": {"baseline": {...}}} with the
            baseline keys of analyze_data_plane_pcap's tls_baseline.

    Returns:
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
    encrypted, so an authentication failure is inferred (small response, no ESP) and
    labelled as a heuristic. ESP with NULL encryption cannot be told apart from real
    encryption without keys. OSPFv3 and IS-IS are not decoded.

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
            options=options,
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
) -> Dict[str, Any]:
    """
    Prove from packets whether VPN traffic between sites is encrypted and whether the
    IPsec and DMVPN overlay formed. Deterministic, no LLM.

    Use it on a capture of a WAN/underlay link (between hub and spoke routers). It runs
    the "ipsec" and "gre_nhrp" detectors of analyze_network_pcap and puts the answers first:

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

    Where to capture: on the physical/underlay link, ESP proves encryption. If you
    capture on the tunnel interface itself you see decrypted traffic, and GRE without
    ESP on the underlay means the tunnel has no IPsec protection.

    Args:
        file_path: Absolute path to a pcap/pcapng file.
        peers: Optional list of the VPN endpoints' WAN IP addresses. All traffic between
            any two of them is judged. Without it, pairs that spoke IKE/ESP and GRE
            endpoints are judged.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
        max_packets: Optional cap on frames read.
        max_items: Cap on list lengths (default 25).

    Returns:
        {"status": "success", "encryption_verdict", "verdict", "negotiation_verdict",
         "overlay_verdict", "ipsec": {peer_pairs, cleartext, ike_sas, esp_flows,
         nat_traversal, issues}, "gre_nhrp": {hubs, spokes, registrations, resolutions,
         redirects, error_indications, tunnels, spoke_to_spoke_tunnels, issues},
         "issues", "timeline", "capture"} or {"status": "error", "error"}.

    Example:
        analyze_vpn_pcap("/captures/hub-wan.pcap", peers=["192.0.2.1", "198.51.100.2"])
    """
    try:
        return analyze_vpn_capture(file_path, peers=peers, display_filter=display_filter,
                                   max_packets=max_packets, max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def analyze_routing_pcap(
    file_path: str,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
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
    OSPF_HELLO_INTERVAL_MISMATCH, OSPF_MTU_MISMATCH, OSPF_ONE_WAY, BGP_TCP_REFUSED,
    BGP_PEER_SILENT, EIGRP_K_VALUE_MISMATCH, EIGRP_NEIGHBOR_SILENT, ICMP_LOSS.

    Args:
        file_path: Absolute path to a pcap/pcapng file.
        display_filter: Optional Wireshark display filter applied first (needs tshark),
            for example "ospf or icmp".
        max_packets: Optional cap on frames read.
        max_items: Cap on list lengths (default 25).

    Returns:
        {"status": "success", "verdict", "reachability_verdict", "failover_timeline",
         "ping_outages", "routing": {"bgp": {sessions}, "ospf": {links}, "eigrp": {links},
         issues}, "reachability": {echo, icmp_errors, arp_unanswered}, "issues",
         "timeline", "capture"} or {"status": "error", "error"}.

    Example:
        analyze_routing_pcap("/captures/r1-r2-failover.pcap")
    """
    try:
        return analyze_routing_capture(file_path, display_filter=display_filter,
                                       max_packets=max_packets, max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def analyze_data_plane_pcap(
    file_path: str,
    tls_baseline: Optional[Dict[str, Any]] = None,
    transport_mtu: int = 1500,
    tunnel_mtu: Optional[int] = None,
    gre_header_bytes: int = 8,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
) -> Dict[str, Any]:
    """
    Look into the data plane of one capture: path MTU and fragmentation, ESP overhead,
    TCP health per connection, TLS handshakes against a baseline, and QoS markings with
    RTP quality. Deterministic, no LLM; one read of the capture.

    It runs the "path_mtu", "esp_overhead", "tcp", "tls" and "qos" detectors of
    analyze_network_pcap and puts one verdict per detector first:

      - path_mtu_verdict: Fragmentation Needed / Packet Too Big with the next-hop MTU and
        the probe frame, PMTUD black holes ("DF probes up to 1400 answered, 1500 vanished
        with no ICMP; path MTU between 1400 and 1499"), fragments complete/incomplete.
      - esp_overhead_verdict: per ESP SA the cipher families its sizes fit (an estimate:
        ESP is encrypted), the overhead in tunnel and transport-over-GRE mode, whether a
        tunnel_mtu packet still fits transport_mtu once encrypted, outer ESP fragments.
      - tcp_verdict: per connection one of no_answer, refused, receiver_buffer_exhausted
        ("the endpoint's receive buffer is exhausted"), loss_on_path, receive_window_limited,
        reset, healthy, with retransmission/gap/dup-ACK/zero-window counts and frames.
      - tls_verdict: versions negotiated and baseline failures. In TLS 1.3 the certificate
        is encrypted and reported as not visible; in TLS 1.2 it is read.
      - qos_verdict: marked flows, GRE marking copied or lost, ESP DSCP per SA, RTP streams
        with loss, jitter, DSCP and a MOS estimate.

    Every section has "issues" (stable codes such as PMTU_BLACK_HOLE, PMTU_FRAG_NEEDED,
    ESP_OUTER_FRAGMENTED, ESP_EXCEEDS_TRANSPORT_MTU, TCP_NO_ANSWER, TCP_ZERO_WINDOW,
    TCP_LOSS, TLS_BASELINE_VERSION, TLS_ALERT, QOS_RTP_NOT_EF, QOS_GRE_DSCP_NOT_COPIED),
    Wireshark frame numbers, and "limits": what this capture cannot show.

    Args:
        file_path: Absolute path to a pcap/pcapng file.
        tls_baseline: Optional TLS policy, for example {"versions": ["TLS1.3"]} or
            {"min_version": "TLS1.2", "cipher_suites": ["TLS_AES_128_GCM_SHA256", "0x1302"],
            "require_sni": true, "alpn": ["h2"], "require_forward_secrecy": true,
            "forbid_weak_offers": true}. Without it, versions below TLS 1.2 and weak
            chosen suites are still flagged.
        transport_mtu: MTU of the link that carries ESP (default 1500).
        tunnel_mtu: The tunnel's ip mtu (for example 1400): checks that a full-size inner
            packet still fits transport_mtu after encryption.
        gre_header_bytes: GRE header inside ESP in transport mode: 8 with a tunnel key
            (default, usual for DMVPN), 4 without.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
        max_packets: Optional cap on frames read.
        max_items: Cap on list lengths (default 25).

    Returns:
        {"status": "success", "overall_status", "path_mtu_verdict", "esp_overhead_verdict",
         "tcp_verdict", "tls_verdict", "qos_verdict", "path_mtu": {...}, "esp_overhead": {...},
         "tcp": {"connections": [...]}, "tls": {"sessions": [...]}, "qos": {...}, "issues",
         "timeline", "capture"} or {"status": "error", "error"}.

    Limits: verdicts cover only what crossed this capture point (an ICMP dropped before
    it is invisible, so a black hole means "no ICMP seen here"); ESP cipher and mode are
    estimates; QUIC, DTLS and STARTTLS are not decoded; RTP latency needs two capture
    points (use correlate_pcaps).

    Example:
        analyze_data_plane_pcap("/captures/br1-wan.pcap", tunnel_mtu=1400)
        analyze_data_plane_pcap("/captures/dmz.pcap", tls_baseline={"versions": ["TLS1.3"]})
    """
    try:
        return analyze_data_plane_capture(file_path, tls_baseline=tls_baseline, transport_mtu=transport_mtu,
                                          tunnel_mtu=tunnel_mtu, gre_header_bytes=gre_header_bytes,
                                          display_filter=display_filter, max_packets=max_packets,
                                          max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def correlate_pcaps(
    captures: List[Dict[str, Any]],
    window_s: float = 2.0,
    max_packets_held: int = 200000,
    clock_offsets_s: Optional[Dict[str, float]] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
) -> Dict[str, Any]:
    """
    Follow the same packets through two or more captures taken at different points
    (inside and outside of a NAT router, WAN1 and WAN2, before and after a firewall)
    and report what happened between them. Deterministic, no LLM.

    Packets are recognised by fields NAT leaves alone: ESP SPI and sequence number,
    TCP sequence/acknowledgement numbers with flags, length and a payload hash, UDP
    length and payload hash, ICMP echo sequence with IP identification, else IP
    identification and length. GRE carrying IPv4 is matched on the inner packet.

    Reports:
      - nat: each translation, for example {"at_inside": "10.0.0.10:40000",
        "at_outside": "203.0.113.5:61000", "remote": "198.51.100.80:443",
        "kind": "source NAT with port/id translation", "packets"}.
      - connections: per conversation, linked across captures through NAT, a verdict:
        "reply_lost" (for example "the SYN-ACK was last seen at outside and never
        reached inside"), "partial_loss", "asymmetric" ("out through wan1, back
        through wan2"), "seen_only_at" (a probe seen before a device but never after
        it: an ACL, a route or a drop), "ok".
      - transit: per capture pair, packets matched, time between sightings (one-way
        delay plus clock offset), TTL decrement (routed hops between the points).
      - dscp_changes: the same packet carrying a different DSCP at two points.

    Memory is bounded: captures are merged by timestamp and streamed; a packet waits at
    most window_s for its copy and at most max_packets_held packets wait at once (the
    oldest are evicted early and counted in matching.evicted_early).

    Args:
        captures: Two or more {"path": "/abs/file.pcap", "label": "inside"}; labels must be
            unique. List them in path order when they lie on one path.
        window_s: Seconds a packet waits for its copy in another capture (default 2.0, max 60).
        max_packets_held: Cap on packets held for matching at once (default 200000, min 100).
        clock_offsets_s: Optional {label: seconds} added to that capture's timestamps when
            the capturing clocks differ.
        max_packets: Optional cap on frames read from each capture.
        max_items: Cap on list lengths (default 25).

    Returns:
        {"status": "success", "verdict", "captures": [{label, packets, unmatched_packets,
         start, end}], "matching": {window_s, max_packets_held, evicted_early,
         packets_matched}, "nat", "connections", "transit", "dscp_changes", "issues",
         "limits"} or {"status": "error", "error"}. Frames are given per capture label.

    Limits: a device that randomizes TCP sequence numbers or rewrites payloads breaks
    matching for those flows; "seen_only_at" cannot tell a drop from a flow that never
    needed to cross the other points; times include clock differences between hosts.

    Example:
        correlate_pcaps([{"path": "/captures/edge-inside.pcap", "label": "inside"},
                         {"path": "/captures/edge-outside.pcap", "label": "outside"}])
    """
    try:
        return correlate_captures(captures, window_s=window_s, max_packets_held=max_packets_held,
                                  clock_offsets_s=clock_offsets_s, max_packets=max_packets, max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def merge_pcap_timelines(
    captures: List[Dict[str, Any]],
    measurements: Optional[List[Dict[str, Any]]] = None,
    detectors: Optional[List[str]] = None,
    failover_max_s: Optional[float] = None,
    clock_offsets_s: Optional[Dict[str, float]] = None,
    max_events: int = 500,
    output_path: Optional[str] = None,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """
    Merge several captures of one chaos or failover run into a single event timeline
    and measure the time between chosen events against design thresholds.
    Deterministic, no LLM.

    Each capture is analyzed once by the analyze_network_pcap detectors; their notable
    events (BGP down/established, OSPF neighbor_down/up, EIGRP goodbye, ping outages,
    ICMP errors, Fragmentation Needed, TCP no_answer/RST/zero window, TLS alerts, ESP
    fragmentation, ...) are merged by absolute timestamp, each tagged with its capture
    label and detector.

    A measurement picks two events with selectors and reports the delta:
        {"name": "wan1 failover", "from": {"capture": "wan1", "event": "down"},
         "to": {"event": "established", "contains": "10.255.0.2"}, "max_s": 30}
    Selector keys (all optional): capture, detector, protocol, event, contains
    (substring of the detail), occurrence ("first", "last" or a 1-based number). The
    "to" event is searched after the "from" event. Verdicts: within, exceeded,
    below_min, not_found. Without measurements, auto_measurements lists every ping
    outage duration and each routing down event paired with the next up event of the
    same protocol, judged against failover_max_s when given.

    Args:
        captures: One or more {"path": "/abs/file.pcap", "label": "wan1"}; labels unique.
        measurements: Optional list of {"name", "from", "to", "max_s", "min_s"}.
        detectors: Optional subset of analyze_network_pcap detectors (default all).
        failover_max_s: Optional threshold in seconds for the automatic measurements.
        clock_offsets_s: Optional {label: seconds} added to that capture's timestamps.
        max_events: Cap on timeline events returned (default 500).
        output_path: Optional absolute path ending in .json: the result is also written
            there so the run keeps it next to its captures. Refused if the file exists
            unless overwrite is true, or if the directory does not exist.
        overwrite: Replace an existing output_path.

    Returns:
        {"status": "success", "verdict", "origin" (time of t=0, the earliest capture
         start), "captures": [{label, packets, start, end, overall_status, events,
         verdicts}], "measurements": [{name, from, to, delta_s, max_s, verdict, detail}],
         "auto_measurements", "timeline": [{t, time, capture, detector, protocol, event,
         detail, frame}], "timeline_omitted", "written_to"} or {"status": "error", "error"}.

    Limits: events are packet timestamps at each capture point (millisecond precision),
    only as comparable as the capturing clocks; timers inside a router between packets
    are invisible.

    Example:
        merge_pcap_timelines([{"path": "/run/wan1.pcap", "label": "wan1"},
                              {"path": "/run/lan.pcap", "label": "lan"}], failover_max_s=30,
                             output_path="/run/failover-timing.json")
    """
    try:
        return merge_timelines(captures, measurements=measurements, detectors=detectors,
                               failover_max_s=failover_max_s, clock_offsets_s=clock_offsets_s,
                               max_events=max_events, output_path=output_path, overwrite=overwrite)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


if __name__ == "__main__":
    # Run MCP server
    mcp.run()
