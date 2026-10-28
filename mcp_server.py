#!/usr/bin/env python3
"""
S.O.N.I.C. MCP Server

FastMCP server exposing S.O.N.I.C. VoIP analysis and the deterministic network
detectors (IPsec/IKE/ESP, GRE/NHRP, BGP/OSPF/EIGRP, ICMP/ARP) as tools for AI
assistants. Works with Claude Desktop, Cline, and other MCP clients.

Network tools (no LLM): analyze_network_pcap, analyze_vpn_pcap, analyze_routing_pcap,
audit_cleartext_pcap, analyze_convergence_pcap.

The server teaches its client how to use it: the initialize result carries
instructions (which tool for which question, cost, limits), every tool has a
title, annotations and a description that says when to use it and what it
returns, the guide topics are resources (sonic://guide/<topic>), and common
investigations are prompts. All of it comes from utils/agent_guide.py.

Usage:
    python3 mcp_server.py                     # serve MCP over stdio
    python3 mcp_server.py --create-skill [DIR]  # write the Agent Skill and exit
    python3 mcp_server.py --env-file PATH       # read API keys from a dotenv file

API keys come from the environment (an MCP client's "env" block passes them
through) and then from the dotenv file named by --env-file or SONIC_ENV_FILE.
They are redacted from every tool result, log line and prompt (utils/credentials.py).

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
from llm_config import list_available_providers, resolve_provider
from analyzers.network_orchestrator import (
    analyze_convergence_capture,
    analyze_network_capture,
    analyze_routing_capture,
    analyze_vpn_capture,
    audit_cleartext_capture,
)
from utils.credentials import (
    EnvFileError,
    configure as configure_credentials,
    credential_status,
    install_output_redaction,
    redact_result,
)
from utils.agent_guide import (
    DEFAULT_SKILL_DIR,
    TOPICS,
    WORKFLOWS,
    build_instructions,
    create_skill_command,
    render_skill_md,
    render_topic,
    tool_options,
    workflow_text,
)

# Create MCP server. The instructions, tool titles, annotations, prompts and
# guide resources all come from utils/agent_guide.py, the same source the
# --create-skill command renders the Agent Skill from.
mcp = FastMCP("S.O.N.I.C. VoIP and Network Analyzer", instructions=build_instructions())


@mcp.tool(**tool_options("analyze_pcap"))
@redact_result
def analyze_pcap(
    file_path: str,
    provider: Optional[str] = None,
    model: str = "combined",
    enable_quality: bool = True,
    enable_mos: bool = True
) -> Dict[str, Any]:
    """
    Diagnose the SIP calls in a capture with an LLM: a written explanation of each call
    (why it failed, dropped, rang out, or had one-way or choppy audio) plus the
    deterministic quality score and MOS.

    Calls an LLM: tens of seconds to minutes, and with a cloud provider (anthropic,
    openai, azure) the extracted SIP/SDP data, including authentication headers,
    leaves this machine, so ask the user first. For numbers only, quick_quality_check
    answers in seconds without an LLM. Needs SIP in the capture; for anything else use
    analyze_network_pcap. Without provider it uses the server's SONIC_LLM_PROVIDER, else
    ollama; list_llm_providers says which.

    Returns a JSON object with status, output.diagnostic_report (per-call findings,
    overall assessment, recommendations), quality_analysis (call_quality and
    mos_analysis when enabled), sip_data and auth_data; on failure
    {"status": "error", "error": "..."}, for example "No SIP data found".
    For example, analyze_pcap(file_path="/captures/call.pcapng", provider="ollama", model="fast").

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        provider: LLM provider: "ollama" (local), "anthropic", "openai" or "azure".
            Default: the server's SONIC_LLM_PROVIDER, else "ollama". Cloud providers need
            their API key in the server's environment or in the env file named by
            --env-file or SONIC_ENV_FILE.
        model: "fast" (small model, quickest), "detailed" (the provider's default model),
            "deep" (its most capable model, for example claude-opus-5-5) or "combined"
            (fast and detailed, recommended).
        enable_quality: Also run the deterministic call quality scoring (default true).
        enable_mos: Also run the RTP MOS analysis per stream (default true).
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
            provider=resolve_provider(provider)
        )
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__
        }


@mcp.tool(**tool_options("quick_quality_check"))
@redact_result
def quick_quality_check(file_path: str) -> Dict[str, Any]:
    """
    Score SIP/RTP call quality without an LLM: the first tool for "how good were the
    calls in this capture". Deterministic, a few seconds.

    Runs the weighted call quality scoring (network, protocol, codec and completion
    scores, an overall score and a grade A+ to F) and the RTP MOS analysis per stream
    (ITU-T G.107 E-model: average, worst and best MOS, a category, and what degraded
    it). Needs SIP in the capture; for other traffic use analyze_network_pcap. For a
    written diagnosis of why a call failed, follow with analyze_pcap (LLM).

    Returns a JSON object with status, file, quality_analysis (overall_score, grade,
    the four component scores and their details, quality_factors,
    degradation_factors) and mos_analysis (streams, average_mos, worst_mos, best_mos,
    overall_category, recommendations). A part that failed is reported as
    quality_error or mos_error instead. On failure {"status": "error", "error": "..."}.
    For example, quick_quality_check(file_path="/captures/call.pcapng").

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
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


@mcp.tool(**tool_options("list_llm_providers"))
@redact_result
def list_llm_providers() -> Dict[str, Any]:
    """
    List the LLM providers and models the LLM tools (analyze_pcap,
    analyze_pcap_partial_streaming, analyze_batch_pcaps) can use, and whether each
    cloud API key is set. No LLM is called; instant. Call it before choosing a
    provider other than ollama, or to see which provider an LLM tool uses when a call
    does not pass one.

    Returns a JSON object with providers (names), models (provider to its "fast",
    "detailed" and, for anthropic, "deep" model names), default (used when
    SONIC_LLM_PROVIDER is unset), and current_config: provider (what every LLM tool
    uses when a call does not pass one) and credentials, which says for each API key only
    whether it is configured and where it came from ("environment" or the env file's
    path), never any part of the key. For example, list_llm_providers().
    """
    try:
        providers = list_available_providers()
        
        # Add current config: whether each key is configured and where it came
        # from (environment or env file path), never any part of a value.
        credentials = credential_status()
        providers["current_config"] = {
            "provider": resolve_provider(),
            "credentials": credentials,
            "anthropic_key_set": credentials["ANTHROPIC_API_KEY"]["configured"],
            "openai_key_set": credentials["OPENAI_API_KEY"]["configured"],
        }
        
        return providers
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@mcp.tool(**tool_options("analyze_batch_pcaps"))
@redact_result
def analyze_batch_pcaps(
    directory: str,
    provider: Optional[str] = None,
    model: str = "fast",
    mode: str = "sequential"
) -> Dict[str, Any]:
    """
    Diagnose every SIP capture in one directory with an LLM, one analyze_pcap run per
    file, plus aggregate counts.

    Calls an LLM once per file: minutes for a directory. Without provider it uses the
    server's SONIC_LLM_PROVIDER, else ollama; a cloud provider receives the SIP data, so
    ask the user before choosing one. Reads files matching *.pcap* directly
    in the directory (not subdirectories). For one capture use analyze_pcap; for
    non-SIP captures call analyze_network_pcap per file.

    Returns a JSON object with files (one result per capture) and aggregate
    (successful, failed, total_tokens, total_duration); on failure {"status": "error", "error": "..."},
    for example when the directory has no pcap files.
    For example, analyze_batch_pcaps(directory="/captures/branch-a", provider="ollama").

    Args:
        directory: Absolute path to a directory of pcap/pcapng files on the machine
            running this server.
        provider: LLM provider: "ollama", "anthropic", "openai" or "azure". Default: the
            server's SONIC_LLM_PROVIDER, else "ollama".
        model: "fast" (default) or "detailed".
        mode: "sequential" (one file at a time, default) or "parallel" (up to 3 at once).
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
            provider=resolve_provider(provider),
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


@mcp.tool(**tool_options("analyze_pcap_partial_streaming"))
@redact_result
def analyze_pcap_partial_streaming(
    file_path: str,
    provider: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run the deterministic SIP quality and MOS analysis, then the LLM diagnosis, on one
    capture, and report how long each part took.

    Calls an LLM: tens of seconds to minutes. Without provider it uses the server's
    SONIC_LLM_PROVIDER, else ollama; a cloud provider receives the SIP data, so ask the
    user before choosing one. The MCP result arrives once, after the LLM finishes;
    to get the numbers sooner, call quick_quality_check first and analyze_pcap after.

    Returns a JSON object with status, quality_analysis, mos_analysis, llm_analysis
    (the diagnostic report), timing (partial_result_ms, llm_streaming_ms, total_ms)
    and streaming_metadata (provider, tokens); on failure
    {"status": "error", "error": "..."}.
    For example, analyze_pcap_partial_streaming(file_path="/captures/call.pcapng", provider="openai").

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        provider: LLM provider: "anthropic", "openai" or "azure" stream; "ollama" runs
            the same diagnosis without streaming. Default: the server's
            SONIC_LLM_PROVIDER, else "ollama".
    """
    from ai.partial_streaming import run_partial_analysis_streaming
    
    try:
        if not os.path.exists(file_path):
            return {"status": "error", "error": f"File not found: {file_path}"}
        
        return run_partial_analysis_streaming(file_path, provider=resolve_provider(provider))
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__
        }


@mcp.tool(**tool_options("analyze_network_pcap"))
@redact_result
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
    The first tool on an unknown capture.

    No LLM is used: every verdict comes from decoding the packets (tshark, with scapy as
    the fallback), in seconds for a typical capture. It reports which protocols are
    present and runs every detector that applies. For a focused answer use
    analyze_vpn_pcap (encryption, IPsec, DMVPN) or analyze_routing_pcap (adjacencies,
    failover); for SIP call quality, quick_quality_check.

    Detectors (pass a subset in `detectors`; the default runs the first six):
      - "ipsec": IKEv1/IKEv2 negotiation per IKE SA (outcome: established, failed,
        no_response, auth_likely_failed, ...), the IKEv2 proposals offered and chosen
        (encryption, PRF, integrity, DH group, weak algorithms), KE groups and
        INVALID_KE_PAYLOAD retries, NAT detection hashes checked against the wire and
        the move to UDP 4500, DPD liveness checks, a "diagnosis" per SA (ok,
        proposal_mismatch, dh_group_mismatch, auth_failed, auth_no_reply, nat_t_missing,
        no_reply, liveness_lost, peer_lost_sa), NOTIFY errors, IKE SA collisions, rekeys,
        ESP flows per SPI (sequence gaps, duplicates, an old SPI still used after a newer
        one took over), NAT-T, and the encryption verdict: "encrypted" or
        "cleartext_seen" for traffic between the same two endpoints.
      - "gre_nhrp": GRE tunnels (keys, inner protocols, key mismatch), NHRP registrations
        (spoke -> hub, result registered/refused/unanswered), hub and spoke roles,
        resolution requests/replies, redirects (DMVPN Phase 3), error indications,
        and spoke-to-spoke tunnels.
      - "dmvpn_phase3": per redirected flow the ordered Phase 3 steps (via_hub, redirect,
        resolution_request, resolution_reply, direct) with frames and times, the first
        missing step and why; hub-relayed spoke traffic with no redirect; resolution
        thrashing; and, with `hubs`, encrypted spoke-to-spoke shortcuts (IKE then direct
        ESP) when NHRP is hidden inside ESP.
      - "routing": BGP sessions (state, OPEN AS/hold time/router ID/capabilities,
        keepalive cadence, UPDATE timing, NOTIFICATION code/subcode decoded with a hint,
        the cause of each drop, the MSS of each SYN and SYN-ACK checked against
        `expected_mss`, refused TCP 179), OSPF per link (hello/dead/mask/area/auth/MTU
        mismatches, one-way neighbors, DR/BDR, hello gaps, adjacencies stuck in EXSTART
        or EXCHANGE), EIGRP (K-value and AS mismatches, goodbyes, hold time expiry, INIT
        restarts, queries/SIA), plus a failover_timeline.
      - "reachability": ICMP echo loss/RTT per source->destination pair with outage
        windows, ICMP unreachable/TTL-exceeded with decoded codes, ARP with no reply,
        duplicate IPs.
      - "conversations": protocol mix by packets and bytes, top conversations, top talkers.
      - Run only when named: "cleartext_audit" (audit_cleartext_pcap) and "convergence"
        (analyze_convergence_pcap).

    Returns a JSON object: status "success", schema, overall_status ("ok", "warning",
    "problem" or "not_present"; the worst detector status, conversations and SIP
    excluded), protocols_present, detectors_run, verdicts (detector to one sentence),
    issues (severity, stable code, message, Wireshark frame numbers, detector; errors
    first), timeline (t in seconds from the first frame, time, protocol, event, detail,
    frame), capture (backend, packets, duration, missing tshark fields, warnings), one
    section per detector, each with status, verdict and issues, and sip. Lists are cut
    at max_items; issues_omitted and timeline_omitted count the rest. On failure
    {"status": "error", "error": "..."}, plus valid_detectors for an unknown detector.

    Limits: a verdict covers only what crossed the capture point. IKEv2 IKE_AUTH is
    encrypted, so the child SA proposal, identities and AUTH are never visible: a PSK
    mismatch shows only as a small encrypted IKE_AUTH response or as retransmissions with
    no reply (a labelled heuristic). DPD is recognised by message size; INVALID_SPI
    normally travels encrypted. ESP with NULL encryption cannot be told apart from real
    encryption without keys. With tunnel protection, GRE, NHRP and BGP are inside ESP on
    the transport link. OSPFv3 and IS-IS are not decoded.

    For example, analyze_network_pcap(file_path="/captures/hub-wan.pcap") or
    analyze_network_pcap(file_path="/captures/r1-r2.pcap", detectors=["routing"]).

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
        hubs: Optional hub NBMA (transport) addresses, so dmvpn_phase3 can check IKE SAs
            between two other addresses as spoke-to-spoke shortcuts.
        expected_mss: Optional TCP MSS the BGP SYNs should carry (for example 1360 for
            "ip tcp adjust-mss 1360"); larger or missing values are flagged.
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


@mcp.tool(**tool_options("analyze_vpn_pcap"))
@redact_result
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
    the "ipsec", "gre_nhrp" and "dmvpn_phase3" detectors of analyze_network_pcap and puts
    the answers first:

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
      - ike_diagnoses: one line per IKE SA with a stable code: ok, proposal_mismatch,
        dh_group_mismatch, auth_failed, auth_no_reply, nat_t_missing, udp_4500_blocked,
        no_reply, no_esp_after_auth, liveness_lost, peer_lost_sa. Each SA in
        ipsec.ike_sas also has "negotiation": proposals_offered and proposal_chosen
        (encryption, prf, integrity, dh_group, weak), ke_groups_offered,
        invalid_ke_payload, nat_detection (nat_detected, translated, moved_to_udp_4500)
        and liveness (DPD checks, interval_s_by_sender, unanswered_checks).

    Where to capture: on the physical/underlay link, ESP proves encryption. If you
    capture on the tunnel interface itself you see decrypted traffic, and GRE without
    ESP on the underlay means the tunnel has no IPsec protection. Seconds for a typical
    capture.

    Returns a JSON object with status, encryption_verdict, verdict, negotiation_verdict,
    overlay_verdict, phase3_verdict and ike_diagnoses first, then ipsec (peer_pairs,
    cleartext, ike_sas, esp_flows, nat_traversal, issues), gre_nhrp (hubs, spokes,
    registrations, resolutions, redirects, error_indications, tunnels,
    spoke_to_spoke_tunnels, issues), dmvpn_phase3 (flows, hub_relayed_without_redirect,
    resolution_thrashing, encrypted_shortcuts, cannot_show, issues), issues, timeline
    and capture. On failure {"status": "error", "error": "..."}.

    Limits: IKE_AUTH and everything after it is encrypted. A PSK mismatch is never
    visible as a hash: it shows as auth_failed (a small encrypted IKE_AUTH response) or
    auth_no_reply (retransmissions, no reply). On a protected DMVPN the NHRP steps are
    inside ESP; only the IKE and ESP between spokes can be checked, given `hubs`.

    For example, analyze_vpn_pcap(file_path="/captures/hub-wan.pcap",
    peers=["192.0.2.1", "198.51.100.2"]).

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        peers: Optional list of the VPN endpoints' WAN IP addresses. All traffic between
            any two of them is judged. Without it, pairs that spoke IKE/ESP and GRE
            endpoints are judged.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
        max_packets: Optional cap on frames read.
        max_items: Cap on list lengths (default 25).
        hubs: Optional hub NBMA (WAN) addresses. With them, an IKE SA between two other
            addresses is checked as a spoke-to-spoke shortcut (IKE_SA_INIT, IKE_AUTH,
            direct ESP).
    """
    try:
        return analyze_vpn_capture(file_path, peers=peers, display_filter=display_filter,
                                   max_packets=max_packets, max_items=max_items, hubs=hubs)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool(**tool_options("analyze_routing_pcap"))
@redact_result
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
    exchange, and the cause, for example the DBD MTU mismatch). To time a failover
    from an event, analyze_convergence_pcap measures it directly.
    Seconds for a typical capture.

    Returns a JSON object with status, verdict, reachability_verdict,
    failover_timeline and ping_outages first, then routing (bgp sessions, ospf links,
    eigrp links, issues), reachability (echo, icmp_errors, arp_unanswered), issues,
    timeline and capture. On failure {"status": "error", "error": "..."}.

    For example, analyze_routing_pcap(file_path="/captures/r1-r2-failover.pcap").

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        display_filter: Optional Wireshark display filter applied first (needs tshark),
            for example "ospf or icmp".
        max_packets: Optional cap on frames read.
        max_items: Cap on list lengths (default 25).
        expected_mss: Optional MSS the BGP SYN and SYN-ACK should carry (for example 1360
            for "ip tcp adjust-mss 1360"). The value is what crossed the capture point;
            adjust-mss rewrites SYNs only where they cross the interface it is on.
    """
    try:
        return analyze_routing_capture(file_path, display_filter=display_filter,
                                       max_packets=max_packets, max_items=max_items,
                                       expected_mss=expected_mss)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool(**tool_options("audit_cleartext_pcap"))
@redact_result
def audit_cleartext_pcap(
    file_path: str,
    allow: Optional[List[str]] = None,
    display_filter: Optional[str] = None,
    max_packets: Optional[int] = None,
    max_items: int = 25,
) -> Dict[str, Any]:
    """
    Assert that a crypto transport link carried nothing but allowed traffic: every frame
    is checked against an allowlist and the audit passes or fails. Deterministic, no LLM,
    seconds for a typical capture.

    Use it as a gate after capturing the WAN/transport link of an IPsec or DMVPN network:
    one leaked GRE, BGP, OSPF, ICMP, ARP or other frame outside the allowlist fails the
    audit and is reported by protocol and address pair with its frame numbers. To explain
    an IPsec negotiation instead, use analyze_vpn_pcap.

    Allowlist tokens (default ["crypto"]): crypto (= esp, ike, nat-t), esp (IP 50 and
    ESP-in-UDP), ike (UDP 500/4500), nat-t (ESP-in-UDP, IKE on 4500, keepalives), ah,
    arp, icmp, icmpv6, routing (= bgp, ospf, eigrp, rip, ldp, bfd, pim, vrrp, hsrp) or each
    by name, gre, l2-control (= cdp, stp, lldp, lacp, loop: Cisco keepalives, EtherType
    0x9000), dhcp, dns, ntp, ssh, snmp, syslog, tacacs, radius, tcp:N, udp:N, proto:N,
    ethertype:0xNNNN. Scope a token to addresses with @: "icmp@203.0.113.1" (ICMP only to
    or from the provider), "bgp@198.51.100.0/30". A Cisco router's transport link also
    carries loopback keepalives and CDP: add "l2-control" to accept them.

    Returns a JSON object: status "success", passed (true or false), result ("pass" or
    "fail"), verdict, allowlist, frames_audited, frames_allowed,
    frames_outside_allowlist, first_violation_frame, by_protocol (protocol, category,
    packets, bytes, pairs, first_frame), violations (protocol, category, src, dst,
    packets, bytes, first_frame, first_t, last_frame, last_t, frames, hint),
    allowed_by_rule, cannot_show and capture. Categories: crypto,
    tunnel_without_encryption (GRE outside ESP), routing, icmp, layer2,
    authenticated_only (AH), cleartext. An empty capture fails. On failure
    {"status": "error", "error": "..."}, for example for an unknown allowlist token.

    Limits (also in cannot_show): only frames that crossed this capture point and that
    the capture kept are audited; ESP with NULL or weak encryption passes, because ESP
    payload is opaque; a non-first IP fragment has no port, so without tshark's
    reassembly a fragment of allowed UDP is reported as udp (fail-closed).

    For example, audit_cleartext_pcap(file_path="/captures/br1-wan.pcap") or
    audit_cleartext_pcap(file_path="/captures/br1-wan.pcap",
    allow=["crypto", "l2-control", "icmp@172.16.11.1"]).

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        allow: Optional allowlist tokens (see above). An unknown token is an error.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
            Narrowing the capture also narrows what the audit proves.
        max_packets: Optional cap on frames read (the audit then covers only those).
        max_items: Cap on the violations list (default 25; the counts stay complete).
    """
    try:
        return audit_cleartext_capture(file_path, allow=allow, display_filter=display_filter,
                                       max_packets=max_packets, max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool(**tool_options("analyze_convergence_pcap"))
@redact_result
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
    Measure a failover from one capture and say what drove it. Deterministic, no LLM,
    seconds for a typical capture.

    From an event (for example the moment a runbook stopped a link or a router) or,
    without one, from the first sign of failure, it measures the time to detection, to
    the first BGP UPDATE or withdrawal on the surviving path, and to traffic resuming.
    Signals: the last ESP/IKE from a peer before it went quiet; IKEv2 DPD checks left
    unanswered and the last retransmission (DPD giving up); BGP NOTIFICATIONs (Hold Timer
    Expired, Cease/BFD Down), RST or FIN, and a hold expiry inferred from silence; BGP
    UPDATEs on sessions not involving the failed peer; ping outages and their recovery;
    and on encrypted transport captures the surviving tunnels' ESP rate taking over the
    failed tunnel's. For adjacency health without an event, use analyze_routing_pcap.

    Returns a JSON object: status "success", verdict, driver (mechanism "bfd",
    "bgp_hold_timer", "dpd", "explicit_close" or "undetermined", and reason),
    failed_peer and failed_peer_source, event_time, measurements (origin, origin_t,
    first_failure_sign, detection, first_update_on_surviving_path, traffic_resumed, and
    event_to_first_failure_sign_s, event_to_detection_s, event_to_first_update_s,
    event_to_traffic_resumed_s), timeline (t, time, delta_s, phase: event, failure,
    teardown, detection, reaction or recovery, signal, peer, detail, frame),
    traffic_shift, issues, cannot_show and capture. Deltas are seconds from the event (or
    the first failure sign); a negative first-sign delta means the failure showed before
    the given event time. On failure {"status": "error", "error": "..."}.

    Limits (also in cannot_show): on a protected tunnel BGP and user traffic are inside
    ESP, so the reaction is inferred from ESP rates and the driver from timing against
    hold_time; DPD is recognised by size; the event time comes from another clock than
    the capture, so a skew shifts every delta; only this capture point is seen.

    For example, analyze_convergence_pcap(file_path="/captures/br1-wan.pcap",
    event_time="+30") or analyze_convergence_pcap(file_path="/captures/core1-wan.pcap",
    event_time="2026-10-27T19:49:30Z", failed_peer="172.16.1.2", hold_time=30).

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        event_time: Optional time of the event: epoch seconds, seconds from the first frame
            ("30" or "+30"), or ISO-8601 with a zone ("2026-10-27T19:49:30Z"). Without it
            the earliest failure sign is the start, and a quiet period counts only when the
            other side kept sending into it.
        failed_peer: Optional address of the peer that failed (a hub's WAN address or a BGP
            neighbor). Without it, it is inferred and failed_peer_source says how.
        hold_time: Optional BGP hold time in seconds, to infer a hold-timer driven failover
            from timing when BGP is inside ESP.
        silence_s: Optional seconds of silence that count as a peer stopping. Default:
            twice the direction's usual longest gap, at least 3 s, and at least 1.5 DPD
            intervals when DPD is periodic.
        display_filter: Optional Wireshark display filter applied first (needs tshark).
        max_packets: Optional cap on frames read.
        max_items: Caps the timeline at four times this (default 25).
    """
    try:
        return analyze_convergence_capture(file_path, event_time=event_time, failed_peer=failed_peer,
                                           hold_time=hold_time, silence_s=silence_s,
                                           display_filter=display_filter, max_packets=max_packets,
                                           max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


# ---------------------------------------------------------------------------
# Guide resources and workflow prompts (progressive disclosure for MCP clients)
# ---------------------------------------------------------------------------

def _register_guide_resource(topic: str, title: str):
    @mcp.resource(f"sonic://guide/{topic}", name=f"guide-{topic}", title=title,
                  description=f"S.O.N.I.C. guide: {title}. Read it when you need this area in depth.",
                  mime_type="text/markdown")
    async def _guide() -> str:
        return render_topic(topic, list(await mcp.list_tools()))


@mcp.resource("sonic://guide/overview", name="guide-overview", title="S.O.N.I.C. overview",
              description="What S.O.N.I.C. answers, which tool for which question, and the guide topics.",
              mime_type="text/markdown")
def guide_overview() -> str:
    return render_skill_md()


for _topic, _title in TOPICS:
    _register_guide_resource(_topic, _title)


@mcp.prompt(name="diagnose_capture", title="Diagnose an unknown capture",
            description="Walk through an unknown capture: protocols present, then VPN, routing and SIP as they apply.")
def diagnose_capture(file_path: str) -> str:
    return workflow_text("diagnose_capture", file_path=file_path)


@mcp.prompt(name="check_vpn_encryption", title="Is the VPN traffic encrypted?",
            description="Prove from a WAN capture whether inter-site traffic is encrypted and the IPsec/DMVPN overlay formed.")
def check_vpn_encryption(file_path: str, peers: str = "") -> str:
    peer_list = [p.strip() for p in peers.split(",") if p.strip()]
    return workflow_text("check_vpn_encryption", file_path=file_path, peers=peer_list)


@mcp.prompt(name="investigate_failover", title="Read a routing failover from a capture",
            description="Order BGP/OSPF/EIGRP events and ping outages to measure convergence.")
def investigate_failover(file_path: str) -> str:
    return workflow_text("investigate_failover", file_path=file_path)


@mcp.prompt(name="diagnose_sip_call", title="Diagnose SIP call quality",
            description="Quality and MOS first without an LLM, then an LLM diagnosis only if wanted.")
def diagnose_sip_call(file_path: str) -> str:
    return workflow_text("diagnose_sip_call", file_path=file_path)


def main(argv=None) -> int:
    """Serve MCP over stdio, or write the Agent Skill with --create-skill."""
    import argparse
    parser = argparse.ArgumentParser(description="S.O.N.I.C. MCP server (stdio).")
    parser.add_argument("--create-skill", nargs="?", const=DEFAULT_SKILL_DIR, metavar="DIR",
                        help="Write the S.O.N.I.C. Agent Skill into DIR (default: "
                             f"{DEFAULT_SKILL_DIR}) and exit instead of serving.")
    parser.add_argument("--env-file", metavar="PATH",
                        help="Dotenv file to read API keys from when they are not in the environment "
                             "(default: $SONIC_ENV_FILE). Values are never printed or returned.")
    args = parser.parse_args(argv)
    # stdout is the JSON-RPC stream; tool results are redacted by redact_result.
    install_output_redaction(stdout=False)
    try:
        configure_credentials(args.env_file)
    except EnvFileError as exc:
        parser.error(str(exc))
    if args.create_skill:
        return create_skill_command(args.create_skill)
    # stdout is the protocol channel from here on: every print goes to stderr.
    from utils.protocol_stdout import reserve_stdout_for_protocol
    reserve_stdout_for_protocol()
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
