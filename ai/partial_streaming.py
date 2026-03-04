#!/usr/bin/env python3
"""
S.O.N.I.C. Partial Results Streaming

Returns deterministic results (quality, MOS) immediately,
then streams LLM analysis as it completes.
"""

from typing import Dict, Any, Callable, Optional
import json
import time
from concurrent.futures import ThreadPoolExecutor

from extractors.tshark import extract_sip_data
from analyzers.call_quality_scoring import CallQualityScorer
from analyzers.rtp_mos_analysis import AdvancedRTPMOSAnalyzer
from ai.streaming_analysis import run_combined_analysis_streaming
from extractors.auth_info import extract_auth_and_registration_info
from utils.serialization import ResultSerializer


def run_partial_analysis_streaming(
    file_path: str,
    provider: str = None,
    on_token: Optional[Callable[[str], None]] = None,
    on_progress: Optional[Callable[[str], None]] = None,
    on_partial_result: Optional[Callable[[Dict[str, Any]], None]] = None
) -> Dict[str, Any]:
    """
    Streams LLM analysis while returning quality metrics immediately.
    
    Flow:
    1. Extract SIP data (fast)
    2. Run quality scoring (seconds)
    3. Run MOS analysis (seconds)
    4. Return partial result immediately
    5. Start LLM streaming in background
    6. Accumulate LLM tokens
    7. Return final result with LLM analysis appended
    
    Args:
        file_path: Path to pcap file
        provider: LLM provider
        on_token: Callback for LLM tokens
        on_progress: Callback for progress messages
        on_partial_result: Callback when quality/MOS complete (before LLM)
    
    Returns:
        Complete analysis {quality, mos, llm_analysis, timing}
    
    Example:
        >>> def partial_cb(p):
        ...     print(f"[PARTIAL] Quality: {p['quality_analysis']['grade']}")
        >>> 
        >>> result = run_partial_analysis_streaming(
        ...     "/path/to/capture.pcapng",
        ...     provider="anthropic",
        ...     on_partial_result=partial_cb
        ... )
    """
    start_time = time.time()
    
    if on_progress:
        on_progress("Extracting SIP data...")
    
    sip_data = extract_sip_data(file_path)
    if not sip_data:
        return {"status": "error", "error": "No SIP data found"}
    
    # Run quality and MOS in parallel
    quality_result = None
    mos_result = None
    
    if on_progress:
        on_progress("Running quality and MOS analysis (parallel)...")
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        quality_future = executor.submit(_run_quality, sip_data, file_path)
        mos_future = executor.submit(_run_mos, sip_data, file_path)
        
        quality_result = quality_future.result()
        mos_result = mos_future.result()
    
    # Create partial result
    partial_time = time.time() - start_time
    partial_result = {
        "status": "partial",
        "quality_analysis": quality_result,
        "mos_analysis": mos_result,
        "partial_result_time_ms": int(partial_time * 1000)
    }
    
    if on_partial_result:
        on_partial_result(partial_result)
    
    # Now stream LLM analysis
    if on_progress:
        on_progress("Starting LLM streaming...")
    
    llm_start = time.time()
    llm_result = run_combined_analysis_streaming(
        sip_data, file_path, provider, on_token=on_token
    )
    llm_time = time.time() - llm_start
    
    # Merge results
    final_result = {
        "status": "success",
        "quality_analysis": quality_result,
        "mos_analysis": mos_result,
        "llm_analysis": llm_result.get("output", {}).get("diagnostic_report", {}),
        "timing": {
            "partial_result_ms": int(partial_time * 1000),
            "llm_streaming_ms": int(llm_time * 1000),
            "total_ms": int((time.time() - start_time) * 1000)
        },
        "streaming_metadata": {
            "provider": provider,
            "tokens": llm_result.get("streaming_metadata", {}).get("total_tokens", 0)
        }
    }
    
    return final_result


def _run_quality(sip_data: str, file_path: str) -> Dict[str, Any]:
    """Run quality scoring"""
    try:
        auth_data = extract_auth_and_registration_info(file_path)
        scorer = CallQualityScorer()
        result = scorer.score_call_quality(
            sip_data,
            [],
            None,
            file_path,
            auth_data=auth_data,
        )
        return ResultSerializer.convert_result(result)
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _run_mos(sip_data: str, file_path: str) -> Dict[str, Any]:
    """Run MOS analysis"""
    try:
        analyzer = AdvancedRTPMOSAnalyzer()
        result = analyzer.analyze_rtp_streams(sip_data, file_path)
        return ResultSerializer.convert_result(result)
    except Exception as e:
        return {"status": "error", "error": str(e)}
