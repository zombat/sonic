#!/usr/bin/env python3
"""
S.O.N.I.C. MCP Server

FastMCP server exposing S.O.N.I.C. VoIP analysis and the deterministic network
detectors (IPsec/IKE/ESP, GRE/NHRP, BGP/OSPF/EIGRP, ICMP/ARP) as tools for AI
assistants. Works with Claude Desktop, Cline, and other MCP clients.

Network tools (no LLM): analyze_network_pcap, analyze_vpn_pcap, analyze_routing_pcap.

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
    analyze_network_capture,
    analyze_routing_capture,
    analyze_vpn_capture,
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
    provider: str = "ollama",
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
    analyze_network_pcap. SONIC_LLM_PROVIDER does not change the provider default here,
    so pass provider explicitly.

    Returns a JSON object with status, output.diagnostic_report (per-call findings,
    overall assessment, recommendations), quality_analysis (call_quality and
    mos_analysis when enabled), sip_data and auth_data; on failure
    {"status": "error", "error": "..."}, for example "No SIP data found".
    For example, analyze_pcap(file_path="/captures/call.pcapng", provider="ollama", model="fast").

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        provider: LLM provider: "ollama" (local, default), "anthropic", "openai" or "azure".
            Cloud providers need their API key in the server's environment or in the
            env file named by --env-file or SONIC_ENV_FILE.
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
            provider=provider
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
    provider other than ollama.

    Returns a JSON object with providers (names), models (provider to its "fast",
    "detailed" and, for anthropic, "deep" model names), default, and current_config:
    the SONIC_LLM_PROVIDER value and credentials, which says for each API key only
    whether it is configured and where it came from ("environment" or the env file's
    path), never any part of the key. For example, list_llm_providers().
    """
    try:
        providers = list_available_providers()
        
        # Add current config: whether each key is configured and where it came
        # from (environment or env file path), never any part of a value.
        credentials = credential_status()
        providers["current_config"] = {
            "provider": os.getenv("SONIC_LLM_PROVIDER", "ollama"),
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
    provider: str = "anthropic",
    model: str = "fast",
    mode: str = "sequential"
) -> Dict[str, Any]:
    """
    Diagnose every SIP capture in one directory with an LLM, one analyze_pcap run per
    file, plus aggregate counts.

    Calls an LLM once per file: minutes for a directory, and the provider default is
    anthropic (a cloud API that needs ANTHROPIC_API_KEY and receives the SIP data), so
    ask the user and pass provider explicitly. Reads files matching *.pcap* directly
    in the directory (not subdirectories). For one capture use analyze_pcap; for
    non-SIP captures call analyze_network_pcap per file.

    Returns a JSON object with files (one result per capture) and aggregate
    (successful, failed, total_tokens, total_duration); on failure {"status": "error", "error": "..."},
    for example when the directory has no pcap files.
    For example, analyze_batch_pcaps(directory="/captures/branch-a", provider="ollama").

    Args:
        directory: Absolute path to a directory of pcap/pcapng files on the machine
            running this server.
        provider: LLM provider: "anthropic" (default), "ollama", "openai" or "azure".
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


@mcp.tool(**tool_options("analyze_pcap_partial_streaming"))
@redact_result
def analyze_pcap_partial_streaming(
    file_path: str,
    provider: str = "anthropic"
) -> Dict[str, Any]:
    """
    Run the deterministic SIP quality and MOS analysis, then the LLM diagnosis, on one
    capture, and report how long each part took.

    Calls an LLM: tens of seconds to minutes. The provider default is anthropic (a
    cloud API that needs ANTHROPIC_API_KEY and receives the SIP data), so ask the user
    and pass provider explicitly. The MCP result arrives once, after the LLM finishes;
    to get the numbers sooner, call quick_quality_check first and analyze_pcap after.

    Returns a JSON object with status, quality_analysis, mos_analysis, llm_analysis
    (the diagnostic report), timing (partial_result_ms, llm_streaming_ms, total_ms)
    and streaming_metadata (provider, tokens); on failure
    {"status": "error", "error": "..."}.
    For example, analyze_pcap_partial_streaming(file_path="/captures/call.pcapng", provider="openai").

    Args:
        file_path: Absolute path to a pcap/pcapng file on the machine running this server.
        provider: LLM provider with streaming support: "anthropic" (default), "openai"
            or "azure".
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
) -> Dict[str, Any]:
    """
    Analyze any packet capture (not only VoIP) and return deterministic findings as JSON.
    The first tool on an unknown capture.

    No LLM is used: every verdict comes from decoding the packets (tshark, with scapy as
    the fallback), in seconds for a typical capture. It reports which protocols are
    present and runs every detector that applies. For a focused answer use
    analyze_vpn_pcap (encryption, IPsec, DMVPN) or analyze_routing_pcap (adjacencies,
    failover); for SIP call quality, quick_quality_check.

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
      - "conversations": protocol mix by packets and bytes, top conversations, top talkers.

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
    encrypted, so an authentication failure is inferred (small response, no ESP) and
    labelled as a heuristic. ESP with NULL encryption cannot be told apart from real
    encryption without keys. OSPFv3 and IS-IS are not decoded.

    For example, analyze_network_pcap(file_path="/captures/hub-wan.pcap") or
    analyze_network_pcap(file_path="/captures/r1-r2.pcap", detectors=["routing"]).

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
    ESP on the underlay means the tunnel has no IPsec protection. Seconds for a typical
    capture.

    Returns a JSON object with status, encryption_verdict, verdict, negotiation_verdict
    and overlay_verdict first, then ipsec (peer_pairs, cleartext, ike_sas, esp_flows,
    nat_traversal, issues), gre_nhrp (hubs, spokes, registrations, resolutions,
    redirects, error_indications, tunnels, spoke_to_spoke_tunnels, issues), issues,
    timeline and capture. On failure {"status": "error", "error": "..."}.

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
    """
    try:
        return analyze_vpn_capture(file_path, peers=peers, display_filter=display_filter,
                                   max_packets=max_packets, max_items=max_items)
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}


@mcp.tool(**tool_options("analyze_routing_pcap"))
@redact_result
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
    """
    try:
        return analyze_routing_capture(file_path, display_filter=display_filter,
                                       max_packets=max_packets, max_items=max_items)
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
