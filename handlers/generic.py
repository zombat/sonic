#!/usr/bin/env python3
"""
S.O.N.I.C. Generic Response Handlers

This module provides generic response parsing and error handling for AI model outputs.
It handles multiple response formats and provides fallback strategies.

Author: Raymond A Rizzo | Zombat
"""

import json
import ast
import re
from typing import Dict, Any, Optional

from models.schemas import SipDiagnosticReport


def parse_ai_response(analysis_result: str, model_name: str, sip_data: str = None, file_path: str = None) -> Dict[str, Any]:
    """
    Parses AI model response with multiple fallback strategies.
    
    This function handles various AI response formats and converts them to
    the standard SIP diagnostic report format. It includes comprehensive
    error handling and format conversion.
    
    Args:
        analysis_result: Raw AI model response string
        model_name: Name of the AI model for error context
        
    Returns:
        Dict[str, Any]: Parsed diagnostic report dictionary
        
    Raises:
        ValueError: If no valid format can be parsed
    """
    # Clean up the result if it has extra text
    analysis_str = str(analysis_result).strip()
    
    # Find JSON object in the response
    start_idx = analysis_str.find('{')
    end_idx = analysis_str.rfind('}') + 1
    
    if start_idx != -1 and end_idx > start_idx:
        json_str = analysis_str[start_idx:end_idx]
        
        # Try JSON parsing first
        try:
            report_data = json.loads(json_str)
        except json.JSONDecodeError:
            # If JSON fails, try Python literal_eval (handles single quotes)
            try:
                report_data = ast.literal_eval(json_str)
            except (ValueError, SyntaxError):
                # If that fails too, try replacing single quotes with double quotes
                json_str_fixed = json_str.replace("'", '"')
                report_data = json.loads(json_str_fixed)
        
        # Validate and create Pydantic object
        try:
            # Check if this is actually a direct response format before validation
            if 'enhanced_codec_analysis' in report_data:
                return convert_partial_response(report_data, model_name, sip_data, file_path)
            
            report_obj = SipDiagnosticReport(**report_data)
            return report_obj.model_dump()
        except Exception as validation_error:
            # If direct validation fails, try to construct a valid report from partial data
            print(f"Warning: Direct validation failed, attempting to construct report from partial data")
            return convert_partial_response(report_data, model_name, sip_data, file_path)
    else:
        raise ValueError("No valid JSON object found in response")


def convert_partial_response(report_data: Dict[str, Any], model_name: str, sip_data: str = None, file_path: str = None) -> Dict[str, Any]:
    """
    Converts partial or non-standard AI responses to valid diagnostic reports.
    
    This function handles various AI response formats that don't match the
    expected schema and converts them to valid diagnostic reports.
    
    Args:
        report_data: Partial response data from AI model
        model_name: Name of the AI model for context
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    # Import here to avoid circular imports
    from handlers.sip import (
        handle_single_call_format,
        handle_messages_array_format, 
        handle_elasticsearch_format,
        handle_statistics_format,
        handle_structured_issues_format,
        handle_codec_analysis_format,
        handle_enhanced_codec_format
    )
    
    # Check different response formats and convert appropriately
    if 'audioQuality' in report_data and 'callFlow' in report_data:
        return handle_single_call_format(report_data)
    elif 'messages' in report_data and isinstance(report_data['messages'], list):
        return handle_messages_array_format(report_data)
    elif 'query' in report_data and 'aggregations' in report_data:
        return handle_elasticsearch_format(report_data)
    elif 'total_numbers_of_calls' in report_data:
        return handle_statistics_format(report_data)
    elif any(key.startswith(('audioCodecIssue', 'callSetupMethod')) for key in report_data.keys()):
        return handle_structured_issues_format(report_data)
    elif 'codec_types' in report_data and 'common_issues' in report_data:
        return handle_codec_analysis_format(report_data)
    elif 'media_sessions' in report_data:
        return handle_media_sessions_format(report_data)
    elif 'enhanced_codec_analysis' in report_data:
        return handle_enhanced_codec_format(report_data, sip_data, file_path)
    elif any(codec_key in report_data for codec_key in ['g_711_mu_law', 'g_711_a_law', 'g_729_low_bitrate_codec', 'opus', 'ilbc']):
        # This is a direct codec analysis response - wrap it in enhanced format
        wrapped_data = {'enhanced_codec_analysis': report_data}
        return handle_enhanced_codec_format(wrapped_data, sip_data, file_path)
    else:
        # Natural language fallback
        return handle_natural_language_response(str(report_data), model_name)


def handle_media_sessions_format(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles AI responses in media sessions format.
    
    Args:
        report_data: Response data containing media session information
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    media_sessions = report_data.get('media_sessions', 0)
    rtp_packets = report_data.get('rtp_packets_analyzed', 0)
    correlation_created = report_data.get('sdp_to_rtp_correlation_created', False)
    
    # Analyze the data for potential issues
    potential_issues = []
    if media_sessions == 0:
        potential_issues.append("No media sessions detected in capture")
    if rtp_packets == 0:
        potential_issues.append("No RTP packets found for analysis")
    if not correlation_created:
        potential_issues.append("Unable to correlate SDP with RTP streams")
    
    # Create diagnostic report from media session analysis
    calls = []
    if media_sessions > 0 or rtp_packets > 0:
        calls.append({
            "callId": "media-session-analysis",
            "callerIp": "Media-Session",
            "calleeIp": "Analysis",
            "userAgents": [],
            "audioQuality": {
                "codecUsed": "Unknown",
                "payloadTypes": [],
                "rtpPort": "Unknown",
                "potentialIssues": potential_issues
            },
            "callFlow": {
                "callSetupMethod": "Unknown",
                "callTermination": "Unknown",
                "responseCodes": [],
                "callDurationIndicators": f"Media sessions: {media_sessions}, RTP packets: {rtp_packets}"
            },
            "diagnosticSummary": f"Media session analysis detected {media_sessions} sessions with {rtp_packets} RTP packets"
        })
    
    assessment = f"Media session analysis found {media_sessions} sessions and {rtp_packets} RTP packets."
    if not correlation_created:
        assessment += " SDP-to-RTP correlation could not be established."
    
    recommendations = ["Check for complete SIP call flows in capture"]
    if rtp_packets == 0:
        recommendations.append("Verify RTP traffic is included in capture")
    if not correlation_created:
        recommendations.append("Ensure SDP information is present in SIP messages")
    
    report_obj = SipDiagnosticReport(
        totalCalls=len(calls),
        calls=calls,
        overallAssessment=assessment,
        recommendations=recommendations
    )
    return report_obj.model_dump()


def handle_natural_language_response(analysis_text: str, model_name: str) -> Dict[str, Any]:
    """
    Handles AI responses in natural language format.
    
    This function extracts structured information from natural language
    responses when JSON parsing fails completely.
    
    Args:
        analysis_text: Natural language response text
        model_name: Name of the AI model for context
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary extracted from text
    """
    print(f"Warning: Could not parse LLM response as JSON, using natural language extraction")
    print(f"Raw response: {analysis_text}")
    
    # Try to extract structured information from natural language
    analysis_lower = analysis_text.lower()
    calls = []
    potential_issues = []
    ips_found = []
    
    # Extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, analysis_text)
    ips_found = list(set(ips))
    
    # Look for SIP methods and status codes
    sip_methods = []
    status_codes = []
    
    if 'invite' in analysis_lower:
        sip_methods.append('INVITE')
    if 'bye' in analysis_lower:
        sip_methods.append('BYE')
    if 'ack' in analysis_lower:
        sip_methods.append('ACK')
    if 'ringing' in analysis_lower:
        status_codes.append('180 Ringing')
    if '200 ok' in analysis_lower:
        status_codes.append('200 OK')
    
    # Identify potential issues from the text
    if 'multiple bye' in analysis_lower or 'repeats' in analysis_lower:
        potential_issues.append("Multiple BYE messages detected - possible call termination issues")
    if 'timeout' in analysis_lower:
        potential_issues.append("Timeout issues detected")
    if 'error' in analysis_lower or 'fail' in analysis_lower:
        potential_issues.append("Error conditions detected in call flow")
    
    # Create diagnostic report from extracted information
    if ips_found and len(ips_found) >= 2:
        calls = [{
            "callId": f"nlp-extracted-{ips_found[0]}-{ips_found[1]}",
            "callerIp": ips_found[0],
            "calleeIp": ips_found[1],
            "userAgents": [],
            "audioQuality": {
                "codecUsed": "Unknown",
                "payloadTypes": [],
                "rtpPort": "Unknown",
                "potentialIssues": potential_issues
            },
            "callFlow": {
                "callSetupMethod": sip_methods[0] if sip_methods else "Unknown",
                "callTermination": "BYE" if "BYE" in sip_methods else "Unknown",
                "responseCodes": status_codes,
                "callDurationIndicators": "Natural language analysis of SIP flow"
            },
            "diagnosticSummary": f"NLP analysis extracted call between {ips_found[0]} and {ips_found[1]} with {', '.join(sip_methods)} methods"
        }]
    
    if calls:
        report_dict = {
            "total_calls_analyzed": len(calls),
            "calls": calls,
            "overall_assessment": "Analysis extracted from natural language response instead of JSON format",
            "recommendations": ["Model provided detailed analysis in text format", "Consider JSON-focused prompting for structured output"]
        }
    else:
        report_dict = {
            "total_calls_analyzed": 0,
            "calls": [],
            "overall_assessment": f"Analysis failed due to parsing error - model: {model_name}",
            "recommendations": ["Review the capture file format", "Try with a different model"]
        }
    
    return report_dict


def handle_dspy_error(error_str: str, model_name: str, sip_data: str = None, file_path: str = None) -> Optional[Dict[str, Any]]:
    """
    Attempts to recover JSON from DSPy adapter errors.
    
    DSPy sometimes includes valid JSON in error messages that we can extract.
    
    Args:
        error_str: Error message string from DSPy
        model_name: Name of the AI model for context
        
    Returns:
        Optional[Dict[str, Any]]: Recovered diagnostic report or None if recovery fails
    """
    if "LM Response:" in error_str and "Expected to find output fields" in error_str:
        try:
            start_marker = "LM Response: "
            end_marker = "\n\nExpected to find"
            start_idx = error_str.find(start_marker) + len(start_marker)
            end_idx = error_str.find(end_marker)
            
            if start_idx > len(start_marker) - 1 and end_idx > start_idx:
                json_str = error_str[start_idx:end_idx].strip()
                report_data = json.loads(json_str)
                
                # Handle different response formats
                if 'enhanced_codec_analysis' in report_data:
                    from handlers.sip import handle_enhanced_codec_format
                    report_dict = handle_enhanced_codec_format(report_data, sip_data, file_path)
                elif any(codec_key in report_data for codec_key in ['g_711_mu_law', 'g_711_a_law', 'g_729_low_bitrate_codec', 'opus', 'ilbc']):
                    # This is a direct codec analysis response - wrap it in enhanced format
                    from handlers.sip import handle_enhanced_codec_format
                    wrapped_data = {'enhanced_codec_analysis': report_data}
                    report_dict = handle_enhanced_codec_format(wrapped_data, sip_data, file_path)
                elif 'media_sessions' in report_data:
                    report_dict = handle_media_sessions_format(report_data)
                else:
                    # Try standard validation
                    report_obj = SipDiagnosticReport(**report_data)
                    report_dict = report_obj.model_dump()
                
                print(f"Successfully recovered JSON from DSPy error for model: {model_name}")
                return {
                    "status": "success",
                    "output": {
                        "diagnostic_report": report_dict,
                    }
                }
        except Exception as recovery_error:
            print(f"Failed to recover JSON from error: {recovery_error}")
    
    return None
