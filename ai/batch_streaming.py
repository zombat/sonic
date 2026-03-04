#!/usr/bin/env python3
"""
S.O.N.I.C. Batch Streaming Analysis

Handles analysis of multiple pcaps with unified progress tracking
and optional parallel processing.
"""

from typing import Dict, Any, List, Callable, Optional
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class ProcessingMode(Enum):
    """Batch processing modes"""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


@dataclass
class BatchProgress:
    """Batch processing progress snapshot"""
    file_path: str
    index: int
    total_files: int
    status: str  # "queued", "analyzing", "completed", "error"
    elapsed_time: float
    tokens_streamed: int
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict"""
        return asdict(self)


def analyze_batch(
    file_paths: List[str],
    provider: str = "anthropic",
    model: str = "fast",
    enable_quality: bool = True,
    enable_mos: bool = True,
    mode: ProcessingMode = ProcessingMode.SEQUENTIAL,
    max_workers: int = 3,
    on_file_progress: Optional[Callable[[BatchProgress], None]] = None,
    on_token: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Analyze multiple pcap files with streaming and progress tracking.
    
    Args:
        file_paths: List of absolute paths to pcap files
        provider: LLM provider
        model: Analysis mode (fast/detailed)
        enable_quality: Include quality scoring
        enable_mos: Include MOS analysis
        mode: SEQUENTIAL or PARALLEL processing
        max_workers: Max parallel workers (ignored if SEQUENTIAL)
        on_file_progress: Callback for per-file progress (BatchProgress)
        on_token: Callback for LLM tokens (shared across all files)
    
    Returns:
        Batch results with per-file analysis and aggregate metrics
    
    Example:
        >>> def progress_cb(p):
        ...     print(f"[{p.index}/{p.total_files}] {p.file_path}: {p.status}")
        >>> 
        >>> result = analyze_batch(
        ...     ["/path/to/1.pcap", "/path/to/2.pcap"],
        ...     provider="anthropic",
        ...     on_file_progress=progress_cb
        ... )
    """
    from ai.streaming_analysis import run_combined_analysis_streaming
    from extractors.tshark import extract_sip_data
    
    results = {
        "status": "success",
        "batch_metadata": {
            "mode": mode.value,
            "total_files": len(file_paths),
            "provider": provider,
            "model": model
        },
        "files": [],
        "aggregate": {
            "successful": 0,
            "failed": 0,
            "total_tokens": 0,
            "total_duration": 0,
            "quality_summary": {
                "avg_grade": None,
                "call_count": 0,
                "calls_by_grade": {}
            }
        }
    }
    
    start_time = time.time()
    file_results = []
    
    if mode == ProcessingMode.SEQUENTIAL:
        for idx, file_path in enumerate(file_paths):
            result = _analyze_single_file(
                file_path, idx, len(file_paths), provider, model,
                enable_quality, enable_mos, on_file_progress, on_token
            )
            file_results.append(result)
    
    else:  # PARALLEL
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _analyze_single_file,
                    file_paths[idx], idx, len(file_paths), provider, model,
                    enable_quality, enable_mos, on_file_progress, on_token
                ): idx for idx in range(len(file_paths))
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    file_results.append(result)
                except Exception as e:
                    file_results.append({"status": "error", "error": str(e)})
    
    # Aggregate results
    total_tokens = 0
    grades = []
    
    for file_result in sorted(file_results, key=lambda x: x.get("index", 0)):
        results["files"].append(file_result)
        
        if file_result.get("status") == "success":
            results["aggregate"]["successful"] += 1
            total_tokens += file_result.get("streaming_metadata", {}).get("total_tokens", 0)
            
            # Collect quality grades
            grade = file_result.get("quality_analysis", {}).get("grade")
            if grade:
                grades.append(grade)
                results["aggregate"]["quality_summary"]["calls_by_grade"][grade] = \
                    results["aggregate"]["quality_summary"]["calls_by_grade"].get(grade, 0) + 1
        else:
            results["aggregate"]["failed"] += 1
    
    results["aggregate"]["total_tokens"] = total_tokens
    results["aggregate"]["total_duration"] = time.time() - start_time
    results["aggregate"]["quality_summary"]["call_count"] = len(grades)
    
    return results


def _analyze_single_file(
    file_path: str,
    index: int,
    total_files: int,
    provider: str,
    model: str,
    enable_quality: bool,
    enable_mos: bool,
    on_file_progress: Optional[Callable],
    on_token: Optional[Callable]
) -> Dict[str, Any]:
    """Analyze a single file with streaming"""
    from ai.streaming_analysis import run_combined_analysis_streaming
    from extractors.tshark import extract_sip_data
    
    file_start = time.time()
    tokens = []
    
    def token_callback(token: str):
        tokens.append(token)
        if on_token:
            on_token(token)
    
    if on_file_progress:
        on_file_progress(BatchProgress(
            file_path=file_path, index=index, total_files=total_files,
            status="analyzing", elapsed_time=0, tokens_streamed=0
        ))
    
    try:
        sip_data = extract_sip_data(file_path)
        if not sip_data:
            raise ValueError("No SIP data found")
        
        result = run_combined_analysis_streaming(
            sip_data, file_path, provider, on_token=token_callback
        )
        
        elapsed = time.time() - file_start
        result["index"] = index
        result["file"] = file_path
        
        if "streaming_metadata" not in result:
            result["streaming_metadata"] = {}
        
        result["streaming_metadata"]["total_tokens"] = len(tokens)
        result["streaming_metadata"]["elapsed_time"] = elapsed
        
        if on_file_progress:
            on_file_progress(BatchProgress(
                file_path=file_path, index=index, total_files=total_files,
                status="completed", elapsed_time=elapsed, tokens_streamed=len(tokens)
            ))
        
        return result
    
    except Exception as e:
        elapsed = time.time() - file_start
        if on_file_progress:
            on_file_progress(BatchProgress(
                file_path=file_path, index=index, total_files=total_files,
                status="error", elapsed_time=elapsed, tokens_streamed=len(tokens),
                error=str(e)
            ))
        
        return {
            "status": "error",
            "file": file_path,
            "index": index,
            "error": str(e),
            "elapsed_time": elapsed
        }
