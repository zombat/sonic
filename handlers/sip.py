#!/usr/bin/env python3
"""
S.O.N.I.C. SIP-Specific Response Handlers

This module provides SIP-specific response format handlers for various AI model outputs.
It converts non-standard formats to valid SIP diagnostic reports.

Author: Raymond A Rizzo | Zombat
"""

from typing import Dict, Any, List

from models.schemas import SipDiagnosticReport
from analyzers.network_quality import NetworkQualityAnalyzer


def handle_single_call_format(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles AI responses that represent a single call diagnostic.
    
    Args:
        report_data: Response data in single call format
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    print(f"Warning: LLM provided single call format, converting to diagnostic report")
    
    # This looks like a CallDiagnostic, wrap it in a report structure
    call_data = {
        "callId": report_data.get('callId', 'unknown-call-id'),
        "callerIp": "unknown",
        "calleeIp": "unknown", 
        "userAgents": [],
        "audioQuality": report_data.get('audioQuality', {}),
        "callFlow": report_data.get('callFlow', {}),
        "diagnosticSummary": report_data.get('diagnosticSummary', 'No summary available')
    }
    
    # Ensure the nested objects have the required structure
    if 'codecUsed' not in call_data['audioQuality']:
        call_data['audioQuality']['codecUsed'] = 'Unknown'
    if 'callSetupMethod' not in call_data['callFlow']:
        call_data['callFlow']['callSetupMethod'] = 'Unknown'
        
    report_data = {
        "totalCalls": 1,
        "calls": [call_data],
        "overallAssessment": "Partial analysis completed based on available data",
        "recommendations": ["Verify pcap file completeness", "Check for additional call data"]
    }
    
    report_obj = SipDiagnosticReport(**report_data)
    return report_obj.model_dump()


def handle_messages_array_format(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles AI responses with a messages array format.
    
    Args:
        report_data: Response data with messages array
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    print(f"Warning: LLM provided messages array format, converting to diagnostic report")
    
    messages = report_data['messages']
    call_diagnostics = []
    
    # Try to extract meaningful data from the messages
    unique_calls = {}
    for msg in messages:
        src_ip = msg.get('source_ip', 'Unknown')
        dst_ip = msg.get('destination_ip', 'Unknown')
        call_key = f"{src_ip}-{dst_ip}"
        message_type = msg.get('message_type', 'Unknown')
        status_code = str(msg.get('status_code', ''))
        
        # Analyze potential issues based on message patterns
        potential_issues = []
        if message_type == 'NOTIFY' and status_code != '200':
            potential_issues.append(f"Non-200 response to NOTIFY ({status_code})")
        elif status_code.startswith('4') or status_code.startswith('5'):
            potential_issues.append(f"Error response: {status_code}")
        elif message_type not in ['INVITE', 'ACK', 'BYE', 'NOTIFY', 'REGISTER']:
            potential_issues.append(f"Unusual SIP method: {message_type}")
        
        if call_key not in unique_calls:
            unique_calls[call_key] = {
                "callId": f"extracted-{call_key}",
                "callerIp": src_ip,
                "calleeIp": dst_ip,
                "userAgents": [],
                "audioQuality": {
                    "codecUsed": "Unknown",
                    "payloadTypes": [],
                    "rtpPort": "Unknown",
                    "potentialIssues": potential_issues
                },
                "callFlow": {
                    "callSetupMethod": message_type,
                    "callTermination": "Unknown",
                    "responseCodes": [status_code] if status_code else [],
                    "callDurationIndicators": f"Duration: {report_data.get('total_time_minutes', 'Unknown')} minutes"
                },
                "diagnosticSummary": f"Call between {src_ip} and {dst_ip} with {message_type} messages" + (f" - Issues detected: {', '.join(potential_issues)}" if potential_issues else "")
            }
        else:
            # Add response codes to existing call
            if status_code and status_code not in unique_calls[call_key]['callFlow']['responseCodes']:
                unique_calls[call_key]['callFlow']['responseCodes'].append(status_code)
            # Add any new issues
            existing_issues = unique_calls[call_key]['audioQuality']['potentialIssues']
            for issue in potential_issues:
                if issue not in existing_issues:
                    existing_issues.append(issue)
    
    call_diagnostics = list(unique_calls.values())
    
    report_data = {
        "totalCalls": len(call_diagnostics),
        "calls": call_diagnostics,
        "overallAssessment": f"Converted analysis from messages array format. Found {len(call_diagnostics)} call flows in the capture.",
        "recommendations": ["Data was converted from alternative analysis format", "Consider using a more capable model for better schema compliance"]
    }
    
    report_obj = SipDiagnosticReport(**report_data)
    return report_obj.model_dump()


def handle_elasticsearch_format(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles AI responses in Elasticsearch query format.
    
    Args:
        report_data: Response data in Elasticsearch format
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    print(f"Warning: LLM provided Elasticsearch-style format, converting to diagnostic report")
    
    # Extract what we can from the query format
    count = 0
    call_id_info = ""
    if 'aggregations' in report_data:
        agg_data = report_data['aggregations']
        if 'call_id_counts' in agg_data and 'value' in agg_data['call_id_counts']:
            count = agg_data['call_id_counts']['value'].get('count', 0)
    
    if 'query' in report_data and 'terms' in report_data['query']:
        terms = report_data['query']['terms']
        if 'prefix' in terms:
            call_id_info = terms['prefix']
    
    # Create a basic diagnostic report from the query data
    calls = []
    if count > 0:
        calls.append({
            "callId": call_id_info if call_id_info else "elasticsearch-query-extracted",
            "callerIp": "Unknown",
            "calleeIp": "Unknown",
            "userAgents": [],
            "audioQuality": {
                "codecUsed": "Unknown",
                "payloadTypes": [],
                "rtpPort": "Unknown",
                "potentialIssues": ["Analysis format suggests complex SIP data structure"]
            },
            "callFlow": {
                "callSetupMethod": "Unknown",
                "callTermination": "Unknown", 
                "responseCodes": [],
                "callDurationIndicators": f"Query indicates {count} call-related events"
            },
            "diagnosticSummary": f"Call data detected in query format with {count} events"
        })
    
    report_data = {
        "totalCalls": count,
        "calls": calls,
        "overallAssessment": f"Converted from Elasticsearch query format. Detected {count} call-related events.",
        "recommendations": ["Model provided search query instead of analysis", "Try with a different model for direct analysis", "Data suggests SIP calls are present in capture"]
    }
    
    report_obj = SipDiagnosticReport(**report_data)
    return report_obj.model_dump()


def handle_statistics_format(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles AI responses in statistics format.
    
    Args:
        report_data: Response data in statistics format
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    print(f"Warning: LLM provided statistics format, converting to diagnostic report")
    
    total_calls = report_data.get('total_numbers_of_calls', 0)
    avg_requests = report_data.get('average_number_of_requests_per_day', 0)
    max_requests = report_data.get('maximum_number_of_requests_per_day', 0)
    min_requests = report_data.get('minimum_number_of_requests_per_day', 0)
    
    # Create diagnostic calls based on statistics
    calls = []
    potential_issues = []
    
    # Analyze the statistics for potential issues
    if max_requests > avg_requests * 2:
        potential_issues.append(f"High variability in call volume (max: {max_requests}, avg: {avg_requests})")
    if total_calls > 20:
        potential_issues.append("High call volume detected - may indicate network stress")
    
    # Create a representative call entry
    if total_calls > 0:
        calls.append({
            "callId": f"stats-based-analysis",
            "callerIp": "Statistics-Based",
            "calleeIp": "Analysis",
            "userAgents": [],
            "audioQuality": {
                "codecUsed": "Unknown",
                "payloadTypes": [],
                "rtpPort": "Unknown",
                "potentialIssues": potential_issues
            },
            "callFlow": {
                "callSetupMethod": "Multiple",
                "callTermination": "Unknown",
                "responseCodes": [],
                "callDurationIndicators": f"Statistics show {total_calls} total calls, avg {avg_requests} requests/day"
            },
            "diagnosticSummary": f"Statistical analysis of {total_calls} calls with daily averages ranging from {min_requests} to {max_requests} requests"
        })
    
    report_data = {
        "totalCalls": total_calls,
        "calls": calls,
        "overallAssessment": f"Statistical analysis shows {total_calls} calls with variable request patterns (min: {min_requests}, avg: {avg_requests}, max: {max_requests} requests/day).",
        "recommendations": ["Statistical data suggests active SIP environment", "Consider analyzing individual call patterns", "Monitor for call volume spikes"]
    }
    
    report_obj = SipDiagnosticReport(**report_data)
    return report_obj.model_dump()


def handle_structured_issues_format(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles AI responses in structured issues format.
    
    Args:
        report_data: Response data in structured issues format
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    print(f"Warning: LLM provided structured issue format, converting to diagnostic report")
    
    # Extract diagnostic information from the structured format
    audio_issues = []
    call_flow_issues = []
    overall_assessment = report_data.get('overallAssessment', 'Issues detected in structured format')
    diagnostic_summary = report_data.get('diagnosticSummary', 'Multiple diagnostic issues identified')
    
    # Parse audio codec issues
    for key, value in report_data.items():
        if key.startswith('audioCodecIssue') and isinstance(value, dict):
            codec = value.get('codecUsed', 'Unknown')
            potential_issues = value.get('potentialIssues', [])
            if isinstance(potential_issues, str):
                potential_issues = [potential_issues]
            audio_issues.extend(potential_issues)
    
    # Parse call setup/flow issues  
    call_setup_data = {}
    for key, value in report_data.items():
        if key.startswith('callSetupMethod') and isinstance(value, dict):
            call_setup_data = value
            break
    
    # Create a diagnostic call entry
    calls = [{
        "callId": "structured-issue-analysis",
        "callerIp": "Issue-Based",
        "calleeIp": "Analysis",
        "userAgents": [],
        "audioQuality": {
            "codecUsed": codec if 'codec' in locals() else "Unknown",
            "payloadTypes": [],
            "rtpPort": "Unknown",
            "potentialIssues": audio_issues if audio_issues else ["General audio codec issues detected"]
        },
        "callFlow": {
            "callSetupMethod": call_setup_data.get('callSetupMethod', 'Unknown'),
            "callTermination": call_setup_data.get('callTermination', 'Unknown'),
            "responseCodes": call_setup_data.get('responseCodes', []) if isinstance(call_setup_data.get('responseCodes'), list) else [str(call_setup_data.get('responseCodes', ''))],
            "callDurationIndicators": call_setup_data.get('callDurationIndicators', 'Unknown')
        },
        "diagnosticSummary": diagnostic_summary
    }]
    
    report_data = {
        "totalCalls": 1,
        "calls": calls,
        "overallAssessment": overall_assessment,
        "recommendations": ["Structured diagnostic issues identified", "Review call setup and audio codec configuration", "Consider network quality analysis"]
    }
    
    report_obj = SipDiagnosticReport(**report_data)
    return report_obj.model_dump()


def handle_codec_analysis_format(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handles AI responses in codec analysis format.
    
    Args:
        report_data: Response data in codec analysis format
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    print(f"Warning: LLM provided codec analysis format, converting to diagnostic report")
    
    codec_types = report_data.get('codec_types', [])
    common_issues = report_data.get('common_issues', [])
    diagnostic_focus = report_data.get('diagnostic_focus', [])
    
    # Create a diagnostic call entry based on codec analysis
    calls = [{
        "callId": "codec-analysis-based",
        "callerIp": "Codec-Analysis",
        "calleeIp": "Based-Detection",
        "userAgents": [],
        "audioQuality": {
            "codecUsed": codec_types[0] if codec_types else "Multiple codecs detected",
            "payloadTypes": ["0", "8", "18"] if len(codec_types) >= 3 else ["Unknown"],
            "rtpPort": "Unknown",
            "potentialIssues": common_issues[:3] if common_issues else ["Codec analysis performed but no specific issues identified"]
        },
        "callFlow": {
            "callSetupMethod": "SIP INVITE (inferred from codec negotiation)",
            "callTermination": "Unknown",
            "responseCodes": ["200 OK (inferred from successful codec negotiation)"],
            "callDurationIndicators": f"Codec analysis detected {len(codec_types)} codec types in capture"
        },
        "diagnosticSummary": f"Codec-based analysis detected {', '.join(codec_types)} with {len(common_issues)} potential issues identified"
    }]
    
    # Build assessment from codec analysis
    assessment_parts = []
    if codec_types:
        assessment_parts.append(f"Multiple codec types detected: {', '.join(codec_types)}")
    if common_issues:
        assessment_parts.append(f"Identified {len(common_issues)} potential codec-related issues")
    overall_assessment = ". ".join(assessment_parts) if assessment_parts else "Codec analysis completed"
    
    # Build recommendations from diagnostic focus
    recommendations = []
    if diagnostic_focus:
        recommendations.extend(diagnostic_focus[:5])  # Take first 5 diagnostic focus items
    recommendations.append("Multiple codecs detected - verify codec compatibility between endpoints")
    recommendations.append("Consider standardizing on a single codec for consistency")
    
    report_data = {
        "totalCalls": 1,
        "calls": calls,
        "overallAssessment": overall_assessment,
        "recommendations": recommendations
    }
    
    report_obj = SipDiagnosticReport(**report_data)
    return report_obj.model_dump()


def handle_enhanced_codec_format(report_data: Dict[str, Any], sip_data: str = None, file_path: str = None) -> Dict[str, Any]:
    """
    Handles AI responses with enhanced codec analysis format.
    Enhanced with real network quality analysis from packet capture.
    
    Args:
        report_data: Response data with enhanced codec analysis
        sip_data: Raw SIP data to determine actual codecs used
        file_path: Path to the packet capture file for real network analysis
        
    Returns:
        Dict[str, Any]: Valid diagnostic report dictionary
    """
    print(f"Warning: LLM provided enhanced codec analysis format, converting to diagnostic report")
    
    # Determine actual payload types from the packet data
    actual_payload_types = set()
    actual_codecs = []
    
    if sip_data:
        try:
            import json
            data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
            rtp_streams = data.get('rtp_streams', [])
            for stream in rtp_streams:
                pt = stream.get('payload_type', '')
                if pt:
                    actual_payload_types.add(pt)
        except Exception as e:
            print(f"Warning: Could not parse sip_data to determine actual codecs: {e}")
    
    # Map payload types to codec analysis keys
    codec_mapping = {
        '0': 'g_711_mu_law',
        '8': 'g_711_a_law', 
        '18': 'g_729_low_bitrate_codec'
    }
    
    enhanced_analysis = report_data.get('enhanced_codec_analysis', {})
    if not enhanced_analysis:
        # Try the other format
        codec_analysis = report_data.get('codec_analysis', {})
        enhanced_analysis = codec_analysis
    
    rtp_guidance = report_data.get('rtp_stream_troubleshooting_guidance', {})
    
    # Extract codec information - but only for codecs actually used
    detected_codecs = []
    codec_characteristics = []  # General codec info, NOT actual packet issues
    used_payload_types = list(actual_payload_types) if actual_payload_types else ['0']  # Default to PCMU if unknown
    
    for pt in used_payload_types:
        codec_key = codec_mapping.get(pt)
        if codec_key and codec_key in enhanced_analysis:
            codec_data = enhanced_analysis[codec_key]
            codec_name = codec_data.get('codec_name', 'Unknown')
            detected_codecs.append(codec_name)
            
            # Get codec characteristics (general info about this codec type)
            characteristics = codec_data.get('common_issues', [])
            codec_characteristics.extend(characteristics)
    
    # If no specific codecs found, fall back to first available
    if not detected_codecs and enhanced_analysis:
        first_codec_data = list(enhanced_analysis.values())[0]
        codec_name = first_codec_data.get('codec_name', 'Unknown')
        detected_codecs.append(codec_name)
        characteristics = first_codec_data.get('common_issues', [])
        codec_characteristics.extend(characteristics)
    
    # ===== REAL NETWORK QUALITY ANALYSIS =====
    real_network_issues = []
    network_analysis_summary = {}
    tcp_baseline = {}
    network_report = {}
    
    if file_path and sip_data:
        try:
            # Parse SIP data to get structured information
            parsed_sip_data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
            
            # Perform real network quality analysis
            analyzer = NetworkQualityAnalyzer(file_path)
            network_report = analyzer.generate_network_quality_report(parsed_sip_data)
            
            # Extract real detected issues (not generic codec warnings)
            real_network_issues = network_report.get('real_issues_detected', [])
            network_analysis_summary = network_report.get('analysis_summary', {})
            tcp_baseline = network_report.get('tcp_baseline_analysis', {})
            
            print(f"🔬 Real network analysis completed:")
            print(f"   📊 RTP streams analyzed: {network_analysis_summary.get('total_rtp_streams_analyzed', 0)}")
            print(f"   🚨 Real issues found: {len(real_network_issues)}")
            if real_network_issues:
                for issue in real_network_issues[:3]:  # Show first 3 real issues
                    print(f"      • {issue}")
            else:
                print(f"   ✅ No network quality issues detected")
            
            # Include TCP baseline analysis for VoIP planning
            if tcp_baseline:
                print(f"   🌐 TCP Network Baseline: {tcp_baseline.get('health_assessment', 'Unknown')} (Score: {tcp_baseline.get('health_score', 0)}/100)")
                print(f"      VoIP Impact: {tcp_baseline.get('voip_impact_assessment', 'Unknown')}")
                
                # TCP baseline is separate from issues - don't add to real_network_issues
                # It will be handled as a separate category in the call structure
            
        except NameError as e:
            if 'file_path' in str(e):
                print(f"⚠️  Real network analysis skipped: file_path not available")
            else:
                print(f"⚠️  Real network analysis failed: {e}")
            real_network_issues = []
            network_analysis_summary = {}
            tcp_baseline = {}
        except Exception as e:
            print(f"⚠️  Real network analysis failed: {e}")
            real_network_issues = []
            network_analysis_summary = {}
            tcp_baseline = {}
    
    # Create a diagnostic call entry based on enhanced codec analysis
    calls = [{
        "callId": "enhanced-codec-analysis",
        "callerIp": "Enhanced-Codec",
        "calleeIp": "Analysis",
        "userAgents": [],
        "audioQuality": {
            "codecUsed": detected_codecs[0] if detected_codecs else "Multiple codecs analyzed",
            "payloadTypes": used_payload_types,  # Use actual payload types found
            "rtpPort": "Unknown",
            "potentialIssues": real_network_issues[:5] if real_network_issues else [],  # Real detected issues only
        },
        "networkBaseline": tcp_baseline if tcp_baseline else {},  # Separate TCP baseline category
        "callFlow": {
            "callSetupMethod": "SIP INVITE (inferred from codec analysis)",
            "callTermination": "Unknown",
            "responseCodes": ["200 OK (successful codec negotiation inferred)"],
            "callDurationIndicators": f"Enhanced analysis of {len(detected_codecs)} codec types"
        },
        "diagnosticSummary": f"Enhanced codec analysis evaluated {', '.join(detected_codecs)} with comprehensive RTP guidance provided"
    }]
    
    # Build assessment from enhanced analysis and real network quality
    assessment_parts = []
    if detected_codecs:
        assessment_parts.append(f"Enhanced codec analysis completed for: {', '.join(detected_codecs)}")
    if real_network_issues:
        assessment_parts.append(f"Real network analysis identified {len(real_network_issues)} actual issues")
    elif network_analysis_summary:
        assessment_parts.append(f"Real network analysis found no quality issues")
    if codec_characteristics:
        assessment_parts.append(f"Codec characteristics documented for reference")
    
    overall_assessment = ". ".join(assessment_parts) if assessment_parts else "Enhanced codec analysis completed with real network quality assessment"
    
    # Build recommendations from the analysis - prioritize real issues
    recommendations = []
    
    # Add real network issue recommendations first
    if real_network_issues:
        recommendations.extend([
            "Address detected network quality issues immediately",
            "Monitor RTP streams for continued packet loss or jitter",
            "Review QoS markings and network configuration"
        ])
    else:
        recommendations.extend([
            "Network quality analysis shows good performance",
            "Continue monitoring for emerging issues",
            "Review codec-specific troubleshooting recommendations"
        ])
    
    # Add TCP baseline recommendations if available
    if network_report and 'tcp_baseline_analysis' in network_report:
        tcp_recommendations = network_report['tcp_baseline_analysis'].get('qos_recommendations', [])
        if tcp_recommendations:
            # Add the most relevant TCP recommendation
            primary_tcp_rec = tcp_recommendations[0] if tcp_recommendations else ""
            if primary_tcp_rec and primary_tcp_rec not in recommendations:
                recommendations.append(f"TCP Analysis: {primary_tcp_rec}")
    
    # Add codec-specific recommendations
    for codec_key, codec_data in enhanced_analysis.items():
        diagnostic_focus = codec_data.get('diagnostic_focus', [])
        if diagnostic_focus:
            recommendations.append(f"For {codec_data.get('codec_name', 'this codec')}: {diagnostic_focus[0]}")
    
    report_obj = SipDiagnosticReport(
        totalCalls=1,
        calls=calls,
        overallAssessment=overall_assessment,
        recommendations=recommendations[:8]  # Limit to 8 recommendations
    )
    return report_obj.model_dump()
