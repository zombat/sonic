#!/usr/bin/env python3
"""
S.O.N.I.C. Streaming Analysis Module

Handles streaming LLM responses for real-time analysis feedback.
Accumulates streamed tokens into complete analysis results.
"""

from typing import Dict, Any, Callable, Iterator, Optional
import json
from io import StringIO

from llm_config import get_llm_streaming


def run_combined_analysis_streaming(
    file_content: str,
    file_path: str = None,
    provider: str = None,
    on_token: Optional[Callable[[str], None]] = None,
    on_progress: Optional[Callable[[str], None]] = None
) -> Dict[str, Any]:
    """
    Streams combined analysis output token-by-token.
    
    Args:
        file_content: SIP data to analyze
        file_path: Optional file path for context
        provider: LLM provider (must support streaming)
        on_token: Callback for each token (for real-time display)
        on_progress: Callback for progress messages
    
    Returns:
        Complete analysis result (accumulated from stream)
    
    Example:
        >>> def token_cb(t): print(t, end='', flush=True)
        >>> def progress_cb(msg): print(f"[{msg}]")
        >>> result = run_combined_analysis_streaming(
        ...     sip_data,
        ...     provider="anthropic",
        ...     on_token=token_cb,
        ...     on_progress=progress_cb
        ... )
    """
    if on_progress:
        on_progress("Initializing streaming analysis...")
    
    # Get streaming factory
    try:
        stream_fn = get_llm_streaming(profile="fast", provider=provider, on_token=on_token)
    except ValueError as e:
        # Fallback to non-streaming
        if on_progress:
            on_progress(f"Streaming not supported for {provider}, using standard analysis")
        from ai.analysis import run_combined_analysis
        return run_combined_analysis(file_content, file_path, provider)
    
    # Build prompt
    prompt = f"""Analyze this VoIP SIP capture data for call quality issues:

{file_content}

Respond with ONLY a valid JSON object (no markdown, no explanation)."""
    
    if on_progress:
        on_progress("Streaming analysis from LLM...")
    
    # Accumulate streamed response
    accumulated = StringIO()
    for token in stream_fn(prompt):
        accumulated.write(token)
    
    result_text = accumulated.getvalue()
    
    if on_progress:
        on_progress("Parsing analysis result...")
    
    # Parse accumulated JSON
    try:
        # Try to parse as JSON
        analysis = json.loads(result_text)
        return {
            "status": "success",
            "output": {
                "diagnostic_report": analysis,
                "analysis_method": "Streaming combined analysis"
            },
            "streaming_metadata": {
                "total_tokens": len(result_text.split()),
                "provider": provider
            }
        }
    except json.JSONDecodeError:
        return {
            "status": "error",
            "error": "Invalid JSON in streaming response",
            "raw_response": result_text[:500]  # First 500 chars for debugging
        }
