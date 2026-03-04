#!/usr/bin/env python3
"""
S.O.N.I.C. AI Analysis Module

This module handles AI model integration and SIP diagnostic analysis using DSPy.
It provides model management, analysis orchestration, and result combination.

Author: Raymond A Rizzo | Zombat
"""

import dspy
from typing import Dict, Any

from models.schemas import SipDiagnosticReport
from llm_config import get_llm


# Top performing models for SIP diagnostic analysis
# These models were selected after comprehensive testing across 41 diverse pcap files
# Performance characteristics:
# - qwen2.5:0.5b: Fast execution (0.01-4.6s), excellent format conversion, structured output
# - qwen2.5vl:7b: Detailed analysis (30s+), rich natural language insights, comprehensive diagnostics
MODELS_TO_TEST = [
    "qwen2.5:0.5b",    # Fast model: Excellent format conversion, structured output
    "qwen2.5vl:7b"     # Detailed model: Rich natural language analysis, comprehensive insights
]


class SipDiagnosticSignature(dspy.Signature):
    """
    Analyzes SIP capture data to diagnose call quality issues like choppy audio and unexpected disconnects.

    You must respond with ONLY a valid JSON object. Replace ALL values with actual data from the capture:

    {
        "totalCalls": NUMBER_OF_CALLS_FOUND,
        "calls": [
            {
                "callId": "REAL_CALL_ID_FROM_DATA",
                "callerIp": "REAL_CALLER_IP",
                "calleeIp": "REAL_CALLEE_IP", 
                "userAgents": ["REAL_USER_AGENT_STRINGS"],
                "audioQuality": {
                    "codecUsed": "REAL_CODEC_NAME",
                    "payloadTypes": ["REAL_PAYLOAD_NUMBERS"],
                    "rtpPort": "REAL_PORT_NUMBER",
                    "potentialIssues": ["IDENTIFIED_ISSUES_OR_EMPTY_ARRAY"]
                },
                "callFlow": {
                    "callSetupMethod": "REAL_METHOD_LIKE_INVITE",
                    "callTermination": "REAL_TERMINATION_OR_null",
                    "responseCodes": ["REAL_STATUS_CODES"],
                    "callDurationIndicators": "YOUR_ANALYSIS"
                },
                "diagnosticSummary": "YOUR_ANALYSIS_OF_THIS_CALL"
            }
        ],
        "overallAssessment": "YOUR_OVERALL_ANALYSIS",
        "recommendations": ["YOUR_SPECIFIC_RECOMMENDATIONS"]
    }

    CRITICAL: Do NOT include placeholder text like "<actual_value>" or "REAL_VALUE". 
    Use actual extracted values or "Unknown" if data is not available.
    
    Focus on identifying:
    1. Audio codec issues that could cause choppy audio
    2. Call setup/teardown problems that cause disconnects  
    3. RTP/media negotiation issues
    4. Network-related problems in SIP headers
    
    Codec Analysis Guidelines:
    - G.711 (PCMU=0, PCMA=8): High quality (64 kbps), check for network congestion
    - G.729 (typically=18): Low bandwidth (8 kbps), watch for implementation quality issues
    - Opus (dynamic 96-127): Adaptive codec, look for configuration mismatches
    - iLBC (dynamic 96-127): Packet loss resistant, check for compatibility issues
    - Unknown/Unsupported codecs: Flag as potential compatibility problems
    
    Respond with ONLY valid JSON, no explanations.
    """
    capture_data: str = dspy.InputField(desc="The structured JSON or raw text output from the capture file.")
    analysis: str = dspy.OutputField(desc="A JSON object containing comprehensive diagnostic report focused on call quality issues.")


def run_combined_analysis(file_content: str, file_path: str = None, provider: str = None) -> Dict[str, Any]:
    """
    Runs analysis with both top models and combines the results.
    
    This function orchestrates the combined analysis workflow:
    1. Run fast model (qwen2.5:0.5b) for structured, reliable output
    2. Run detailed model (qwen2.5vl:7b) for comprehensive natural language insights  
    3. Combine results using merge logic to get best of both analyses
    
    The combined approach leverages the strengths of each model:
    - Fast model: Excellent JSON format compliance, structured data extraction
    - Detailed model: Rich natural language analysis, comprehensive issue identification
    
    Args:
        file_content: Extracted SIP data from packet capture (JSON or raw text format)
        provider: LLM provider (ollama, anthropic, openai, azure) - defaults to SONIC_LLM_PROVIDER env var
    
    Returns:
        Dict[str, Any]: Combined analysis result with enhanced diagnostic information
        
    Performance:
        - Fast model: ~0.01-4.6 seconds
        - Detailed model: ~30+ seconds  
        - Total combined time: ~20-35 seconds
        
    Example:
        >>> sip_data = extract_sip_data("capture.pcapng")
        >>> result = run_combined_analysis(sip_data)
        >>> print(result["output"]["diagnostic_report"]["analysis_method"])
        'Combined: Fast structured analysis + Detailed natural language insights'
    """
    print("🔄 Running combined analysis with top 2 models...")
    
    # Run fast model
    print("  📊 Step 1: Fast structured analysis...")
    fast_lm = get_llm(profile="fast", provider=provider)
    fast_result = sip_diagnostic_test(fast_lm, file_content, file_path)
    
    # Run detailed model  
    print("  🔍 Step 2: Detailed natural language analysis...")
    detailed_lm = get_llm(profile="detailed", provider=provider)
    detailed_result = sip_diagnostic_test(detailed_lm, file_content, file_path)
    
    # Combine results
    print("  🔗 Step 3: Combining insights from both models...")
    combined_result = combine_diagnostic_results(fast_result, detailed_result)
    
    # Try to extract codec directly from raw responses if needed
    if combined_result.get("status") == "success":
        calls = combined_result["output"]["diagnostic_report"].get("calls", [])
        for call in calls:
            audio_quality = call.get("audioQuality", {})
            if audio_quality.get("codecUsed") == "Unknown":
                # Try to extract codec from raw AI responses
                direct_codec = extract_codec_from_raw_responses(fast_result, detailed_result)
                if direct_codec != "Unknown":
                    audio_quality["codecUsed"] = direct_codec
                    print(f"   ℹ️  Recovered codec from raw AI response: {direct_codec}")
    
    return combined_result


def combine_diagnostic_results(fast_result: Dict[str, Any], detailed_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combines results from fast and detailed models to create a comprehensive diagnostic report.
    
    This function implements the core logic of the combined analysis approach, merging
    structured output from the fast model with detailed insights from the comprehensive model.
    
    The combination strategy:
    1. Use fast model results as the structural foundation (more reliable JSON format)
    2. Enhance with detailed insights from the comprehensive model
    3. Merge potential issues lists from both analyses
    4. Combine recommendations while avoiding duplicates
    5. Add metadata about the combined analysis approach
    
    Args:
        fast_result: Result dictionary from qwen2.5:0.5b (structured, reliable)
                    Expected format: {"status": "success", "output": {"diagnostic_report": {...}}}
        detailed_result: Result dictionary from qwen2.5vl:7b (detailed, natural language)
                        Expected format: {"status": "success", "output": {"diagnostic_report": {...}}}
    
    Returns:
        Dict[str, Any]: Combined diagnostic report with best of both analyses
                       Format: {"status": "success", "output": {"diagnostic_report": {...}}}
                       
    Raises:
        No exceptions raised - handles all error cases gracefully with status indicators
        
    Example:
        >>> fast_res = {"status": "success", "output": {"diagnostic_report": {...}}}
        >>> detailed_res = {"status": "success", "output": {"diagnostic_report": {...}}}
        >>> combined = combine_diagnostic_results(fast_res, detailed_res)
        >>> print(combined["output"]["diagnostic_report"]["analysis_method"])
        'Combined: Fast structured analysis + Detailed natural language insights'
    """
    if fast_result.get('status') != 'success' and detailed_result.get('status') != 'success':
        return {"status": "error", "error": "Both models failed to provide analysis"}
    
    # Use fast result as base since it's more reliably structured
    if fast_result.get('status') == 'success':
        combined_report = fast_result['output']['diagnostic_report'].copy()
        base_calls = combined_report.get('calls', [])
    else:
        # Fallback to detailed result if fast failed
        combined_report = detailed_result['output']['diagnostic_report'].copy()
        base_calls = combined_report.get('calls', [])
    
    # Enhance with insights from detailed model
    if detailed_result.get('status') == 'success':
        detailed_report = detailed_result['output']['diagnostic_report']
        detailed_calls = detailed_report.get('calls', [])
        
        # Merge call-level insights  
        for i, base_call in enumerate(base_calls):
            if i < len(detailed_calls):
                detailed_call = detailed_calls[i]
                
                # Preserve codec data from detailed model if base has Unknown
                base_audio = base_call.get('audioQuality', {})
                detailed_audio = detailed_call.get('audioQuality', {})
                
                # If base codec is Unknown but detailed has good codec data, use detailed
                if base_audio.get('codecUsed') == 'Unknown' and detailed_audio.get('codecUsed') != 'Unknown':
                    base_call['audioQuality']['codecUsed'] = detailed_audio['codecUsed']
                    print(f"   ℹ️  Using codec from detailed model: {detailed_audio['codecUsed']}")
                
                # Similarly for payload types and RTP port
                if not base_audio.get('payloadTypes') and detailed_audio.get('payloadTypes'):
                    base_call['audioQuality']['payloadTypes'] = detailed_audio['payloadTypes']
                
                if base_audio.get('rtpPort') == 'Unknown' and detailed_audio.get('rtpPort') != 'Unknown':
                    base_call['audioQuality']['rtpPort'] = detailed_audio['rtpPort']
                
                # Enhance potential issues with detailed analysis
                base_issues = base_call.get('audioQuality', {}).get('potentialIssues', [])
                detailed_issues = detailed_call.get('audioQuality', {}).get('potentialIssues', [])
                
                # Combine unique issues
                combined_issues = list(set(base_issues + detailed_issues))
                if 'audioQuality' in base_call:
                    base_call['audioQuality']['potentialIssues'] = combined_issues
                
                # Enhance diagnostic summary with detailed insights
                if detailed_call.get('diagnostic_summary') and detailed_call['diagnostic_summary'] != 'No summary available':
                    enhanced_summary = f"{base_call.get('diagnostic_summary', '')} | Enhanced: {detailed_call['diagnostic_summary']}"
                    base_call['diagnostic_summary'] = enhanced_summary
        
        # Enhance overall assessment
        detailed_assessment = detailed_report.get('overall_assessment', '')
        if detailed_assessment and 'Analysis extracted from natural language' in detailed_assessment:
            base_assessment = combined_report.get('overall_assessment', '')
            combined_report['overall_assessment'] = f"{base_assessment} | Detailed Analysis: Rich natural language insights provided additional context."
        
        # Combine recommendations
        base_recommendations = combined_report.get('recommendations', [])
        detailed_recommendations = detailed_report.get('recommendations', [])
        
        # Add unique detailed recommendations
        for rec in detailed_recommendations:
            if rec not in base_recommendations and 'JSON-focused prompting' not in rec:
                base_recommendations.append(f"[Detailed Analysis] {rec}")
        
        combined_report['recommendations'] = base_recommendations
    
    # Add combination metadata
    combined_report['analysis_method'] = 'Combined: Fast structured analysis + Detailed natural language insights'
    combined_report['models_used'] = ['qwen2.5:0.5b (structured)', 'qwen2.5vl:7b (detailed)']
    
    return {
        "status": "success",
        "output": {
            "diagnostic_report": combined_report
        }
    }


def sip_diagnostic_test(lm: dspy.LM, file_content: str, file_path: str = None) -> Dict[str, Any]:
    """
    Performs diagnostic analysis of SIP messages focused on call quality and disconnect issues.
    
    This is the core analysis function that uses AI models to examine SIP packet data
    and identify potential call quality problems. The function includes comprehensive
    error handling and format conversion to handle various AI model response formats.
    
    Key Features:
    - Robust JSON parsing with multiple fallback strategies
    - Automatic format conversion for 6 different AI response types
    - Natural language parsing as final fallback
    - DSPy error recovery with JSON extraction
    - Codec-aware analysis with enriched context for G.711, G.729, Opus, and iLBC
    
    Args:
        lm: Configured DSPy.LM instance with model settings
           Common models: "ollama/qwen2.5:0.5b", "ollama/qwen2.5vl:7b"
        file_content: Structured JSON or raw text extracted from pcap file
                     Typically from tshark JSON output or scapy text extraction
                     Will be automatically enriched with codec analysis context
    
    Returns:
        Dict[str, Any]: Analysis result dictionary with structure:
        {
            "status": "success" | "error" | "skipped",
            "output": {
                "diagnostic_report": SipDiagnosticReport dict
            },
            "error": "error message if status is error"
        }
        
    Error Handling:
        - Graceful degradation through multiple parsing strategies
        - Comprehensive format conversion for AI model inconsistencies  
        - Natural language processing fallback for unparseable responses
        - DSPy error message JSON recovery
        
    Performance Notes:
        - qwen2.5:0.5b: 0.01-4.6 seconds, excellent format compliance
        - qwen2.5vl:7b: 30+ seconds, detailed insights but variable format
        
    Example:
        >>> lm = dspy.LM(model="ollama/qwen2.5:0.5b", temperature=0.7, max_tokens=4000)
        >>> sip_data = '{"sip_messages": [...]}'
        >>> result = sip_diagnostic_test(lm, sip_data)
        >>> if result["status"] == "success":
        ...     print(f"Found {result['output']['diagnostic_report']['total_calls_analyzed']} calls")
    """
    print(f"Running sip_diagnostic_test for model: {lm.model}")
    if not file_content:
        print(f"Warning: No SIP data was extracted from the file for model {lm.model}. Skipping analysis.")
        return {"status": "skipped", "error": "No SIP data extracted from the provided pcap file."}
    
    try:
        # Import here to avoid circular imports
        from utils.codecs import enrich_sip_data_with_codec_context
        from handlers.generic import parse_ai_response
        
        # Enrich SIP data with codec analysis context for better AI diagnostics
        enriched_content = enrich_sip_data_with_codec_context(file_content)
        
        dspy.configure(lm=lm)

        # Use dspy.Predict with the simplified signature
        sip_analyzer = dspy.Predict(SipDiagnosticSignature)
        result = sip_analyzer(capture_data=enriched_content)

        # Get the analysis result as string
        analysis_result = result.analysis
        
        # Use the modular response parser
        report_dict = parse_ai_response(analysis_result, lm.model, file_content, file_path)
        
        return {
            "status": "success",
            "output": {
                "diagnostic_report": report_dict,
            }
        }
        
    except Exception as e:
        # Import here to avoid circular imports
        from handlers.generic import handle_dspy_error
        
        # Try to recover from DSPy errors
        recovery_result = handle_dspy_error(str(e), lm.model, file_content, file_path)
        if recovery_result:
            return recovery_result
        
        print(f"An unexpected error occurred during SIP diagnostic analysis for {lm.model}: {e}")
        return {"status": "error", "error": str(e)}


def extract_codec_from_raw_responses(fast_result: Dict[str, Any], detailed_result: Dict[str, Any]) -> str:
    """
    Extract codec information directly from raw AI model responses, bypassing validation issues.
    
    Args:
        fast_result: Result from fast model (may contain raw response data)
        detailed_result: Result from detailed model (may contain raw response data)
        
    Returns:
        str: Codec name if found, "Unknown" otherwise
    """
    import re
    import json
    
    # Check both results for raw response data
    results_to_check = [fast_result, detailed_result]
    
    for result in results_to_check:
        # Look for raw response in error messages or debug data
        raw_response = None
        
        if result.get("raw_response"):
            raw_response = result["raw_response"]
        elif result.get("error"):
            # Try to extract JSON from error messages that contain "LM Response:"
            error_str = str(result["error"])
            if "LM Response:" in error_str:
                # Extract JSON that comes after "LM Response:"
                json_start = error_str.find("LM Response:") + len("LM Response:")
                json_end = error_str.find("Expected to find output fields")
                if json_end == -1:
                    json_end = len(error_str)
                json_str = error_str[json_start:json_end].strip()
                try:
                    raw_response = json.loads(json_str)
                except:
                    continue
            else:
                # Look for any JSON in error messages
                json_match = re.search(r'\{.*\}', error_str, re.DOTALL)
                if json_match:
                    try:
                        raw_response = json.loads(json_match.group())
                    except:
                        continue
        
        if raw_response:
            try:
                # Parse the raw response if it's a string
                if isinstance(raw_response, str):
                    data = json.loads(raw_response)
                else:
                    data = raw_response
                    
                # Look for codec information in the data
                if isinstance(data, dict):
                    calls = data.get("calls", [])
                    for call in calls:
                        audio_quality = call.get("audioQuality", {})
                        codec = audio_quality.get("codecUsed")
                        if codec and codec != "Unknown":
                            return codec
                            
            except Exception as e:
                continue
    
    return "Unknown"
