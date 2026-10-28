#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. - SIP Observation and Network Inspection Console

Main entry point for the modular S.O.N.I.C. diagnostic tool.
This module orchestrates the complete SIP analysis workflow using modular components.
Includes advanced call quality scoring and RTP MOS analysis capabilities.

Author: Raymond A Rizzo | Zombat
Version: 3.2 (Enhanced with MOS Analysis)
Last Updated: 2025-07-15
"""

import argparse
import os
import sys
import json
from typing import Dict, Any

# Import S.O.N.I.C. modules
from analyzers.orchestrator import run_analysis_mode
from analyzers.call_quality_scoring import CallQualityScorer, print_quality_score_analysis
from analyzers.rtp_mos_analysis import AdvancedRTPMOSAnalyzer, print_mos_analysis
from extractors.tshark import extract_sip_data
from extractors.auth_info import extract_auth_and_registration_info
from utils.reporting import print_diagnostic_report, save_report_to_file
from utils.agent_guide import DEFAULT_SKILL_DIR


def build_parser() -> argparse.ArgumentParser:
    """
    Build the S.O.N.I.C. command-line parser.

    The generated agent skill (--create-skill) reads its CLI reference from this
    parser, so every option documented there is one the CLI really accepts.
    """
    parser = argparse.ArgumentParser(
        description="Run SIP diagnostic analysis on a pcap file to identify call quality issues like choppy audio and unexpected disconnects.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file capture.pcapng --model combined                                  # Default: combined analysis
  %(prog)s --file capture.pcapng --model fast --provider ollama                    # Quick local analysis
  %(prog)s --file capture.pcapng --provider anthropic --model detailed             # Use Claude
  %(prog)s --file capture.pcapng --provider openai --model combined                # Use GPT-4o
  %(prog)s --file capture.pcapng --quality-only                                    # Quality metrics only (no AI)
  %(prog)s --file wan.pcap --network-only                                          # IPsec/GRE/NHRP/BGP/OSPF/EIGRP/ICMP detectors (no AI)
  %(prog)s --file wan.pcap --network-only --detectors ipsec,gre_nhrp --json        # VPN detectors only, JSON on stdout
  %(prog)s --file wan.pcap --network-only --save_file wan-report.json              # write the report as JSON
  %(prog)s --create-skill                                                          # write the agent skill to .claude/skills/sonic

Providers:
  ollama     - Local inference (free, default) - requires Ollama installed
  anthropic  - Claude models (ANTHROPIC_API_KEY from the environment or --env-file / SONIC_ENV_FILE)
  openai     - GPT models (requires OPENAI_API_KEY)
  azure      - Azure OpenAI (requires AZURE_OPENAI_KEY and endpoint config)
        """
    )
    
    parser.add_argument(
        "--file",
        help="Path to the capture file (pcap/pcapng) to analyze. Required for every mode except --create-skill."
    )
    
    parser.add_argument(
        "--model",
        choices=["fast", "detailed", "deep", "combined", "all"],
        default="combined",
        help="Analysis mode: 'combined' (recommended), 'fast', 'detailed', 'deep' (the provider's most capable model, "
             "for example claude-opus-5-5), or 'all'"
    )
    
    parser.add_argument(
        "--save_file",
        help="Path to save the diagnostic report as a markdown file."
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display all tracked NOTIFY events including hidden ones for comprehensive call progression analysis"
    )
    
    # Advanced Quality Analysis Options
    parser.add_argument(
        "--mos",
        action="store_true",
        help="Enable Advanced RTP MOS (Mean Opinion Score) analysis based on ITU-T G.107 E-Model"
    )
    
    parser.add_argument(
        "--quality",
        action="store_true", 
        help="Enable Call Quality Scoring analysis with weighted component scoring"
    )
    
    parser.add_argument(
        "--quality-only",
        action="store_true",
        help="Run only quality analysis (MOS + Quality Scoring) without AI model analysis"
    )
    
    # Network detectors (deterministic, no LLM)
    parser.add_argument(
        "--network-only",
        action="store_true",
        help="Run the non-SIP network detectors (IPsec/IKE/ESP, GRE/NHRP, BGP/OSPF/EIGRP, ICMP/ARP, "
             "conversations) without any AI model. Writes the report to --save_file "
             "(default: <capture>.network.md; a path ending in .json writes JSON)."
    )

    parser.add_argument(
        "--detectors",
        help="Comma-separated subset for --network-only: ipsec, gre_nhrp, routing, reachability, conversations"
    )

    parser.add_argument(
        "--peers",
        help="Comma-separated VPN endpoint IPs for the encrypted/cleartext verdict (--network-only)"
    )

    parser.add_argument(
        "--display-filter",
        help="Wireshark display filter applied before the network detectors run (needs tshark)"
    )

    parser.add_argument(
        "--max-packets",
        type=int,
        help="Read at most this many frames in --network-only mode"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="With --network-only, print the full report as JSON on stdout instead of the summary"
    )

    # Multi-provider LLM support
    parser.add_argument(
        "--provider",
        choices=["ollama", "anthropic", "openai", "azure"],
        default="ollama",
        help="LLM provider: 'ollama' (default, local), 'anthropic' (Claude), 'openai' (GPT), or 'azure' (Azure OpenAI)"
    )
    
    parser.add_argument(
        "--model-name",
        help="Override default model name for the provider (advanced users only)"
    )
    
    parser.add_argument(
        "--env-file",
        metavar="PATH",
        help="Dotenv file to read API keys from when they are not in the environment "
             "(default: $SONIC_ENV_FILE). Only ANTHROPIC_API_KEY, OPENAI_API_KEY and AZURE_OPENAI_KEY are read; "
             "values are never printed"
    )

    parser.add_argument(
        "--api-key",
        help="API key for cloud providers (optional, prefers environment variable - ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.)"
    )
    
    # Batch and streaming options
    parser.add_argument(
        "--batch-dir",
        help="Directory containing multiple pcap files to analyze (batch mode)"
    )
    
    parser.add_argument(
        "--batch-mode",
        choices=["sequential", "parallel"],
        default="sequential",
        help="Batch processing mode: 'sequential' (one file at a time) or 'parallel' (multiple at once)"
    )
    
    parser.add_argument(
        "--batch-workers",
        type=int,
        default=3,
        help="Max parallel workers for batch mode (default: 3)"
    )
    
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Enable streaming output: display LLM tokens in real-time as they arrive (requires streaming-capable provider)"
    )
    
    parser.add_argument(
        "--partial",
        action="store_true",
        help="Return quality/MOS metrics immediately, then stream LLM analysis (requires --stream)"
    )

    parser.add_argument(
        "--create-skill",
        nargs="?",
        const=DEFAULT_SKILL_DIR,
        metavar="DIR",
        help="Write an Agent Skill that teaches an AI agent to use S.O.N.I.C. (SKILL.md plus reference/ files "
             f"read on demand) into DIR (default: {DEFAULT_SKILL_DIR}), then exit. Refuses to replace a "
             "SKILL.md it did not write."
    )

    return parser


def main():
    """
    Main entry point for S.O.N.I.C. command-line interface.
    """
    parser = build_parser()
    args = parser.parse_args()

    from utils.credentials import EnvFileError, configure, install_output_redaction
    install_output_redaction()
    try:
        configure(args.env_file)
    except EnvFileError as exc:
        parser.error(str(exc))

    if args.create_skill:
        from utils.agent_guide import create_skill_command
        sys.exit(create_skill_command(args.create_skill))

    if not args.file:
        parser.error("the following arguments are required: --file (unless --create-skill)")

    # Handle network-only mode (its default report path is next to the capture)
    if args.network_only:
        run_network_only_analysis(args)
        return

    # Set default save_file if not provided
    if not args.save_file:
        args.save_file = "TEST_CAPTURE.md"
    
    # Handle quality-only mode
    if args.quality_only:
        run_quality_only_analysis(args.file, args.save_file, enable_mos=True, enable_quality=True)
        return
    
    # Handle batch mode
    if args.batch_dir:
        handle_batch_analysis(args)
        return
    
    # Handle streaming and partial streaming modes
    if args.stream or args.partial:
        handle_streaming_analysis(args)
        return
    
    # Standard analysis mode
    result = run_analysis_mode(args.file, args.model, enable_quality=args.quality, enable_mos=args.mos, provider=args.provider)
    
    # Extract auth data for reporting
    auth_data = None
    try:
        auth_data = extract_auth_and_registration_info(args.file)
    except Exception as e:
        print(f"⚠️  Auth extraction failed: {e}")
    
    # Print results
    if result.get("status") == "success":
        diagnostic_report = result["output"]["diagnostic_report"]
        sip_data = result.get("sip_data")
        print_diagnostic_report(diagnostic_report, sip_data, args.file, auth_data)
        
        # Get quality results from orchestrator if they were run
        quality_results = result.get("quality_analysis", {})
        
        # Save report with quality results
        save_report_to_file(diagnostic_report, sip_data, args.file, args.save_file, quality_results, auth_data)
    else:
        print(f"\n❌ Analysis failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)


def run_additional_quality_analysis(sip_data: str, file_path: str, enable_mos: bool = False, enable_quality: bool = False) -> Dict[str, Any]:
    """
    Run additional quality analysis based on user flags.
    
    Args:
        sip_data: Extracted SIP data from capture
        file_path: Path to original pcap file
        enable_mos: Whether to run MOS analysis
        enable_quality: Whether to run quality scoring
        
    Returns:
        Dict[str, Any]: Quality analysis results
    """
    results = {}
    
    if enable_quality or enable_mos:
        print("\n🎯 PERFORMING ADDITIONAL QUALITY ANALYSIS...")
    
    # Call Quality Scoring
    if enable_quality:
        print("\n📊 Running Call Quality Scoring Analysis...")
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
            print_quality_score_analysis(quality_result, file_path)
            results["call_quality"] = quality_result
        except Exception as e:
            print(f"⚠️ Call quality scoring failed: {e}")
            results["call_quality"] = None
    
    # Advanced RTP MOS Analysis
    if enable_mos:
        print("\n🎵 Running Advanced RTP MOS Analysis...")
        try:
            mos_analyzer = AdvancedRTPMOSAnalyzer()
            mos_result = mos_analyzer.analyze_rtp_streams(sip_data, file_path)
            print_mos_analysis(mos_result, file_path)
            results["mos_analysis"] = mos_result
        except Exception as e:
            print(f"⚠️ RTP MOS analysis failed: {e}")
            results["mos_analysis"] = None
    
    return results


def run_quality_only_analysis(file_path: str, save_file: str, enable_mos: bool = True, enable_quality: bool = True):
    """
    Run only quality analysis without AI model analysis.
    
    Args:
        file_path: Path to the pcap file to analyze
        save_file: Path to save the report
        enable_mos: Whether to run MOS analysis
        enable_quality: Whether to run quality scoring
    """
    print("🎯 S.O.N.I.C. - Quality Analysis Only Mode")
    print("="*80)
    print(f"📂 Analyzing: {file_path}")
    
    # Extract SIP data
    print("\n🔍 Extracting SIP data...")
    sip_data = extract_sip_data(file_path)
    
    if not sip_data:
        print("❌ No SIP data found in capture")
        sys.exit(1)
    
    # Run quality analysis
    quality_results = run_additional_quality_analysis(
        sip_data, file_path, enable_mos=enable_mos, enable_quality=enable_quality
    )
    
    # Extract auth data for reporting
    auth_data = None
    try:
        auth_data = extract_auth_and_registration_info(file_path)
    except Exception as e:
        print(f"⚠️  Auth extraction failed: {e}")
    
    # Create a basic report for quality-only mode
    basic_report = {
        "total_calls_analyzed": 0,
        "calls": [],
        "overall_assessment": "Quality-only analysis completed.",
        "recommendations": [
            "Quality analysis performed without full SIP call analysis",
            "For complete call flow analysis, run without --quality-only flag"
        ]
    }
    
    # Save report
    try:
        save_report_to_file(basic_report, sip_data, file_path, save_file, quality_results, auth_data)
        print(f"\n💾 Quality analysis report saved to: {save_file}")
    except Exception as e:
        print(f"⚠️ Failed to save report: {e}")
    
    print("\n" + "="*80)
    print("✅ Quality analysis completed successfully!")


def _split_csv(value):
    """Split a comma-separated CLI value into a list (None stays None)."""
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def run_network_only_analysis(args):
    """
    Run the deterministic network detectors (no LLM) and write the report.

    Exit status: 0 when the analysis ran (whatever it found), 1 when it could not run.
    """
    from analyzers.network_orchestrator import analyze_network_capture
    from utils.network_reporting import print_network_summary, save_network_report

    report = analyze_network_capture(
        args.file,
        detectors=_split_csv(args.detectors),
        peers=_split_csv(args.peers),
        display_filter=args.display_filter,
        max_packets=args.max_packets,
    )
    if report.get("status") != "success":
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"❌ Network analysis failed: {report.get('error')}")
        sys.exit(1)

    save_path = args.save_file or f"{args.file}.network.md"
    try:
        save_network_report(report, save_path)
    except OSError as e:
        print(f"⚠️ Failed to save report: {e}", file=sys.stderr)
        save_path = None

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_network_summary(report)
        if save_path:
            print(f"\n💾 Network report saved to: {save_path}")


def handle_batch_analysis(args):
    """Handle batch analysis of multiple pcap files"""
    import json
    from pathlib import Path
    from ai.batch_streaming import analyze_batch, ProcessingMode
    
    batch_files = list(Path(args.batch_dir).glob("*.pcap*"))
    if not batch_files:
        print(f"❌ No pcap files found in {args.batch_dir}")
        sys.exit(1)
    
    print(f"📦 Batch Analysis: {len(batch_files)} files detected")
    print(f"📋 Mode: {args.batch_mode} | Provider: {args.provider}\n")
    
    def batch_progress(progress):
        status_symbol = "✓" if progress.status == "completed" else "✗" if progress.status == "error" else "⟳"
        filename = Path(progress.file_path).name
        print(f"  [{status_symbol}] ({progress.index+1}/{progress.total_files}) {filename}: {progress.status}", file=sys.stderr)
    
    mode = ProcessingMode.PARALLEL if args.batch_mode == "parallel" else ProcessingMode.SEQUENTIAL
    result = analyze_batch(
        [str(f) for f in batch_files],
        provider=args.provider,
        model=args.model,
        mode=mode,
        max_workers=args.batch_workers,
        on_file_progress=batch_progress
    )
    
    # Print summary
    print("\n" + "="*80)
    print("📊 BATCH ANALYSIS SUMMARY")
    print("="*80)
    agg = result["aggregate"]
    print(f"✓ Successful: {agg['successful']}")
    print(f"✗ Failed: {agg['failed']}")
    print(f"🔤 Total Tokens: {agg['total_tokens']}")
    print(f"⏱️  Total Duration: {agg['total_duration']:.1f}s")
    
    # Output full results as JSON
    print("\n" + json.dumps(result, indent=2))


def handle_streaming_analysis(args):
    """Handle streaming and partial streaming analysis"""
    import json
    
    if args.partial:
        # Partial streaming: quality + MOS first, then LLM
        from ai.partial_streaming import run_partial_analysis_streaming
        
        print(f"🔄 Partial Streaming Analysis (Quality → MOS → LLM)")
        print(f"📊 File: {args.file}")
        print(f"🤖 Provider: {args.provider}\n")
        
        def partial_callback(partial):
            grade = partial.get("quality_analysis", {}).get("grade", "N/A")
            mos = partial.get("mos_analysis", {}).get("mean_mos", 0)
            partial_ms = partial.get("partial_result_time_ms", 0)
            print(f"\n⚡ PARTIAL RESULT (Ready in {partial_ms}ms)")
            print(f"   Quality Grade: {grade}")
            print(f"   Mean MOS: {mos:.2f}")
            print(f"\n🌊 LLM Analysis streaming...\n")
        
        def token_callback(token: str):
            print(token, end='', flush=True)
        
        result = run_partial_analysis_streaming(
            args.file,
            provider=args.provider,
            on_token=token_callback,
            on_partial_result=partial_callback
        )
        
        print("\n\n" + "="*80)
        print("FULL ANALYSIS RESULTS")
        print("="*80)
        print(json.dumps(result, indent=2, default=str))
    
    else:
        # Full streaming: only LLM tokens
        from ai.streaming_analysis import run_combined_analysis_streaming
        from extractors.tshark import extract_sip_data
        
        print(f"🌊 Streaming Analysis (Full LLM Tokens)")
        print(f"📊 File: {args.file}")
        print(f"🤖 Provider: {args.provider}\n")
        print("LLM Output:\n")
        
        def token_callback(token: str):
            print(token, end='', flush=True)
        
        def progress_callback(msg: str):
            print(f"\n[i] {msg}", file=sys.stderr)
        
        # Extract SIP data first
        sip_data = extract_sip_data(args.file)
        if not sip_data:
            print("❌ No SIP data found in capture")
            sys.exit(1)
        
        result = run_combined_analysis_streaming(
            sip_data,
            args.file,
            provider=args.provider,
            on_token=token_callback,
            on_progress=progress_callback
        )
        
        print("\n\n" + "="*80)
        print("STREAMING METADATA")
        print("="*80)
        metadata = result.get("streaming_metadata", {})
        print(f"✓ Status: {result.get('status')}")
        print(f"🤖 Provider: {metadata.get('provider')}")
        print(f"🔤 Tokens: {metadata.get('total_tokens')}")


if __name__ == "__main__":
    main()
