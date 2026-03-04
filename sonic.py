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


def main():
    """
    Main entry point for S.O.N.I.C. command-line interface.
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

Providers:
  ollama     - Local inference (free, default) - requires Ollama installed
  anthropic  - Claude models (requires ANTHROPIC_API_KEY)
  openai     - GPT models (requires OPENAI_API_KEY)
  azure      - Azure OpenAI (requires AZURE_OPENAI_KEY and endpoint config)
        """
    )
    
    parser.add_argument(
        "--file", 
        required=True,
        help="Path to the SIP capture file (pcap/pcapng) to analyze."
    )
    
    parser.add_argument(
        "--model",
        choices=["fast", "detailed", "combined", "all"],
        default="combined",
        help="Analysis mode: 'combined' (recommended), 'fast', 'detailed', or 'all'. Available models: qwen2.5:0.5b, qwen2.5vl:7b"
    )
    
    parser.add_argument(
        "--save_file",
        help="Path to save the diagnostic report as a markdown file. Only TEST_CAPTURE.md is allowed (default)."
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
    
    args = parser.parse_args()
    
    # Enforce single allowed report filename policy
    if not args.save_file:
        args.save_file = "TEST_CAPTURE.md"

    if os.path.basename(args.save_file) != "TEST_CAPTURE.md":
        print("\n❌ Invalid --save_file. Only TEST_CAPTURE.md is allowed.")
        sys.exit(2)
    
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
