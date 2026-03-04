#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Analysis Orchestrator Module

Coordinates different analysis modes and handles the main analysis workflow.
Includes advanced call quality scoring and RTP MOS analysis.

Author: Raymond A Rizzo | Zombat
Version: 3.1 (Enhanced with MOS Analysis)
Last Updated: 2025-07-15
"""

import time
from typing import Dict, Any
from extractors.tshark import extract_sip_data
from extractors.auth_info import extract_auth_and_registration_info
from ai.analysis import run_combined_analysis, sip_diagnostic_test, MODELS_TO_TEST
from analyzers.call_quality_scoring import CallQualityScorer, print_quality_score_analysis
from analyzers.rtp_mos_analysis import AdvancedRTPMOSAnalyzer, print_mos_analysis
from llm_config import get_llm
import dspy

try:
    from tqdm import tqdm
except ImportError:
    print("tqdm is not installed. Please run 'pip install tqdm' for progress bars.")
    # Fallback to a simple no-op progress bar
    def tqdm(iterable, **kwargs):
        return iterable


def run_analysis_mode(file_path: str, model_mode: str, enable_quality: bool = False, enable_mos: bool = False, provider: str = None) -> Dict[str, Any]:
    """
    Runs SIP analysis in the specified mode.
    
    Args:
        file_path: Path to the pcap file to analyze
        model_mode: Analysis mode ('fast', 'detailed', 'combined', or 'all')
        enable_quality: Whether to run call quality scoring
        enable_mos: Whether to run MOS analysis
        provider: LLM provider (ollama, anthropic, openai, azure) - defaults to SONIC_LLM_PROVIDER env var
        
    Returns:
        Dict[str, Any]: Analysis results
    """
    print(f"🔧 Enriching SIP data with codec analysis context...")
    print(f"🎵 Analyzing RTP streams and correlating with SDP information...")
    
    # Extract SIP data from the capture
    sip_data = extract_sip_data(file_path)
    if not sip_data:
        print("❌ No SIP data found in the capture file.")
        return {"status": "error", "error": "No SIP data found"}
    
    # Extract authentication and registration information
    print(f"🔐 Analyzing SIP authentication and registration flows...")
    auth_data = extract_auth_and_registration_info(file_path)
    
    # Run analysis based on mode
    result = None
    if model_mode == "combined":
        print("🔄 Running combined analysis (recommended)...")
        result = run_combined_analysis(sip_data, file_path, provider=provider)
    elif model_mode == "fast":
        print("⚡ Running fast analysis...")
        fast_lm = get_llm(profile="fast", provider=provider)
        result = sip_diagnostic_test(fast_lm, sip_data, file_path)
    elif model_mode == "detailed":
        print("🔍 Running detailed analysis...")
        detailed_lm = get_llm(profile="detailed", provider=provider)
        result = sip_diagnostic_test(detailed_lm, sip_data, file_path)
    elif model_mode == "all":
        print("🧪 Running comprehensive analysis with all models...")
        result = run_all_models_analysis(sip_data, file_path, provider=provider)
    else:
        print(f"❌ Unknown model mode: {model_mode}")
        return {"status": "error", "error": f"Unknown model mode: {model_mode}"}
    
    # Include raw SIP data in result for codec extraction fallback
    if result and result.get("status") == "success":
        result["sip_data"] = sip_data
        result["auth_data"] = auth_data
        
        # Perform advanced quality analysis if requested
        if enable_quality or enable_mos:
            print("\n🎯 PERFORMING ADVANCED QUALITY ANALYSIS...")
            
            quality_results = {}
            
            # 1. Traditional Call Quality Scoring
            if enable_quality:
                print("\n📊 Running Call Quality Scoring Analysis...")
                try:
                    quality_scorer = CallQualityScorer()
                    quality_result = quality_scorer.score_call_quality(
                        sip_data,
                        [],
                        None,
                        file_path,
                        auth_data=auth_data,
                    )
                    print_quality_score_analysis(quality_result, file_path)
                    quality_results["call_quality"] = quality_result
                except Exception as e:
                    print(f"⚠️ Call quality scoring failed: {e}")
                    quality_results["call_quality"] = None
            
            # 2. Advanced RTP MOS Analysis
            if enable_mos:
                print("\n🎵 Running Advanced RTP MOS Analysis...")
                try:
                    mos_analyzer = AdvancedRTPMOSAnalyzer()
                    mos_result = mos_analyzer.analyze_rtp_streams(sip_data, file_path)
                    print_mos_analysis(mos_result, file_path)
                    quality_results["mos_analysis"] = mos_result
                except Exception as e:
                    print(f"⚠️ RTP MOS analysis failed: {e}")
                    quality_results["mos_analysis"] = None
            
            # Add quality metrics to result
            if quality_results:
                result["quality_analysis"] = quality_results
    
    return result


def run_all_models_analysis(sip_data: str, file_path: str = None, provider: str = None) -> Dict[str, Any]:
    """
    Runs analysis with all available models for comprehensive testing.
    
    Args:
        sip_data: Extracted SIP data from capture
        file_path: Path to original pcap file
        provider: LLM provider (defaults to ollama for model testing)
        
    Returns:
        Dict[str, Any]: Combined results from all models
    """
    results = {}
    
    with tqdm(total=len(MODELS_TO_TEST), desc="Testing models", unit="model") as pbar:
        for model_name in MODELS_TO_TEST:
            model_desc = f"Testing {model_name}"
            pbar.set_description(model_desc)
            
            start_time = time.time()
            
            try:
                # Use get_llm with model_name to test each model in MODELS_TO_TEST
                lm = get_llm(profile="fast", provider=provider or "ollama", model_name=model_name)
                result = sip_diagnostic_test(lm, sip_data, file_path)
                
                end_time = time.time()
                duration = end_time - start_time
                
                if result.get('status') == 'success':
                    status = "✅"
                    print(f"\n✅ Analysis completed by {model_name} in {duration:.4f} seconds.")
                else:
                    status = "❌"
                    print(f"\n❌ Analysis failed for {model_name}: {result.get('error', 'Unknown error')}")
                
                results[model_name] = {
                    "result": result,
                    "duration": duration,
                    "status": status
                }
                
                pbar.set_postfix(status=status, time=f"{duration:.2f}s")
                
            except Exception as e:
                end_time = time.time()
                duration = end_time - start_time
                
                print(f"\n❌ Model {model_name} failed with error: {e}")
                results[model_name] = {
                    "result": {"status": "error", "error": str(e)},
                    "duration": duration,
                    "status": "❌"
                }
                
                pbar.set_postfix(status="❌", time=f"{duration:.2f}s")
            
            pbar.update(1)
    
    # Return the best successful result
    for model_name in MODELS_TO_TEST:
        if results[model_name]["result"].get("status") == "success":
            return results[model_name]["result"]
    
    # If no models succeeded, return error
    return {"status": "error", "error": "All models failed to provide analysis"}
