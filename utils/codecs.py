#!/usr/bin/env python3
"""
S.O.N.I.C. Codec Analysis Utilities

This module provides codec-specific analysis and context enrichment for SIP/RTP diagnostics.
It includes detailed information about common VoIP codecs and their characteristics.

Author: Raymond A Rizzo | Zombat
"""

from typing import Dict, Any
import json
import re


def get_codec_analysis_context(codec_name: str, payload_type: str = None) -> Dict[str, Any]:
    """
    Provides detailed analysis context for audio codecs commonly used in VoIP.
    
    This function returns comprehensive information about codec characteristics,
    quality expectations, bandwidth usage, and common issues. The data is used
    to enrich AI analysis with codec-specific diagnostic guidance.
    
    Codec Database:
    - G.711 μ-law (PCMU): Payload 0, 64 kbps, excellent quality, high bandwidth
    - G.711 A-law (PCMA): Payload 8, 64 kbps, excellent quality, high bandwidth  
    - G.729: Payload 18, 8 kbps, good quality, efficient bandwidth
    - Opus: Dynamic payload, 6-510 kbps, adaptive quality, modern codec
    - iLBC: Dynamic payload, 13.3/15.2 kbps, packet loss resistant
    
    Args:
        codec_name: Name of the codec to analyze (e.g., "G.711", "PCMU", "Opus")
        payload_type: RTP payload type number (e.g., "0", "8", "18")
        
    Returns:
        Dict[str, Any]: Comprehensive codec analysis data:
        {
            "codec_name": str,
            "standard_payload_type": int,
            "bandwidth_kbps": int, 
            "quality_rating": str,
            "common_issues": List[str],
            "diagnostic_focus": List[str],
            "rtp_analysis_guidance": Dict[str, Any]
        }
        
    Example:
        >>> analysis = get_codec_analysis_context("PCMU")
        >>> print(f"Bandwidth: {analysis['bandwidth_kbps']} kbps")
        Bandwidth: 64 kbps
    """
    # Normalize codec name for lookup
    codec_lower = codec_name.lower().replace('.', '').replace('-', '').replace('_', '')
    
    # Comprehensive codec database with diagnostic information
    codec_database = {
        "pcmu": {
            "codec_name": "G.711 μ-law (PCMU)",
            "standard_payload_type": 0,
            "bandwidth_kbps": 64,
            "quality_rating": "Excellent audio quality, toll-quality voice",
            "common_issues": [
                "Network congestion due to high bandwidth usage",
                "Packet loss more noticeable due to no compression"
            ],
            "diagnostic_focus": [
                "Check for packet loss indicators in RTP streams",
                "Monitor network utilization during calls", 
                "Look for jitter buffer issues in high-traffic networks",
                "Verify QoS prioritization for G.711 traffic"
            ],
            "rtp_analysis_guidance": {
                "packet_loss_sensitivity": "High - uncompressed audio",
                "jitter_tolerance": "Moderate - 20-50ms acceptable",
                "bandwidth_monitoring": "Critical - 64 kbps per call",
                "quality_indicators": ["Clear speech patterns", "Low jitter variance"]
            }
        },
        "pcma": {
            "codec_name": "G.711 A-law (PCMA)", 
            "standard_payload_type": 8,
            "bandwidth_kbps": 64,
            "quality_rating": "Excellent audio quality, toll-quality voice",
            "common_issues": [
                "Network congestion due to high bandwidth usage",
                "Packet loss more noticeable due to no compression",
                "A-law/μ-law compatibility issues between regions"
            ],
            "diagnostic_focus": [
                "Check for A-law/μ-law compatibility between endpoints",
                "Monitor network utilization during calls",
                "Look for jitter buffer issues in high-traffic networks", 
                "Verify QoS prioritization for G.711 traffic"
            ],
            "rtp_analysis_guidance": {
                "packet_loss_sensitivity": "High - uncompressed audio",
                "jitter_tolerance": "Moderate - 20-50ms acceptable", 
                "bandwidth_monitoring": "Critical - 64 kbps per call",
                "quality_indicators": ["Clear speech patterns", "Low jitter variance"]
            }
        },
        "g729": {
            "codec_name": "G.729 Low Bitrate Codec",
            "standard_payload_type": 18,
            "bandwidth_kbps": 8, 
            "quality_rating": "Good quality with proper implementation, may degrade with packet loss",
            "common_issues": [
                "Quality degradation with poor G.729 implementations",
                "Licensing compliance issues on some platforms",
                "CPU overhead for encoding/decoding"
            ],
            "diagnostic_focus": [
                "Check for G.729 licensing compliance on endpoints",
                "Monitor CPU usage during calls for codec processing overhead",
                "Look for transcoding delays in mixed codec environments",
                "Verify packet loss rates - G.729 is more sensitive than G.711"
            ],
            "rtp_analysis_guidance": {
                "packet_loss_sensitivity": "Very High - compressed audio degrades quickly",
                "jitter_tolerance": "Low - 10-20ms recommended",
                "bandwidth_monitoring": "Efficient - 8 kbps per call",
                "quality_indicators": ["Stable jitter patterns", "Minimal packet loss"]
            }
        },
        "opus": {
            "codec_name": "Opus Modern Adaptive Codec",
            "standard_payload_type": 96,  # Dynamic range 96-127
            "bandwidth_kbps": 32,  # Variable 6-510 kbps
            "quality_rating": "Excellent quality at all bitrates, superior packet loss resilience", 
            "common_issues": [
                "Configuration mismatches between different Opus implementations",
                "Bandwidth negotiation issues in SDP",
                "Limited support on legacy systems"
            ],
            "diagnostic_focus": [
                "Verify Opus configuration parameters in SDP",
                "Check for adaptive bitrate changes during calls",
                "Monitor for packet loss recovery mechanisms",
                "Look for compatibility issues with non-Opus endpoints"
            ],
            "rtp_analysis_guidance": {
                "packet_loss_sensitivity": "Low - excellent packet loss recovery",
                "jitter_tolerance": "High - adaptive buffering",
                "bandwidth_monitoring": "Variable - 6-510 kbps adaptive",
                "quality_indicators": ["Adaptive bitrate changes", "Smooth quality transitions"]
            }
        },
        "ilbc": {
            "codec_name": "iLBC Internet Low Bitrate Codec",
            "standard_payload_type": 97,  # Dynamic range 96-127
            "bandwidth_kbps": 15.2,  # 13.3 or 15.2 kbps modes
            "quality_rating": "Moderate quality, excellent packet loss resistance",
            "common_issues": [
                "Limited availability on some platforms",
                "Frame size configuration mismatches",
                "Quality trade-offs for packet loss resistance"
            ],
            "diagnostic_focus": [
                "Check iLBC frame size configuration (20ms vs 30ms)",
                "Verify packet loss recovery performance",
                "Monitor for compatibility issues with other codecs",
                "Look for quality vs. resilience trade-offs"
            ],
            "rtp_analysis_guidance": {
                "packet_loss_sensitivity": "Very Low - designed for poor networks",
                "jitter_tolerance": "High - robust buffering",
                "bandwidth_monitoring": "Low - 13.3-15.2 kbps",
                "quality_indicators": ["Consistent performance in poor conditions", "Graceful degradation"]
            }
        }
    }
    
    # Handle common codec name variations
    codec_mappings = {
        "g711": "pcmu",  # Default G.711 to μ-law
        "g711u": "pcmu",
        "g711a": "pcma", 
        "ulaw": "pcmu",
        "alaw": "pcma",
        "mulaw": "pcmu",
        "g729a": "g729",
        "g729ab": "g729"
    }
    
    # Look up codec in database
    lookup_key = codec_mappings.get(codec_lower, codec_lower)
    codec_info = codec_database.get(lookup_key)
    
    if not codec_info:
        # Return generic analysis for unknown codecs
        return {
            "codec_name": f"Unknown Codec ({codec_name})",
            "standard_payload_type": int(payload_type) if payload_type and payload_type.isdigit() else 96,
            "bandwidth_kbps": 32,  # Default estimate
            "quality_rating": "Unknown quality characteristics",
            "common_issues": [
                f"Unknown codec '{codec_name}' may have compatibility issues",
                "Verify codec support on all endpoints",
                "Check for proper SDP negotiation"
            ],
            "diagnostic_focus": [
                "Identify the specific codec implementation",
                "Verify codec support across all call participants",
                "Check SDP media format strings for codec details",
                "Look for codec negotiation failures"
            ],
            "rtp_analysis_guidance": {
                "packet_loss_sensitivity": "Unknown - requires codec-specific analysis",
                "jitter_tolerance": "Unknown - monitor call quality indicators",
                "bandwidth_monitoring": "Unknown - analyze RTP packet sizes",
                "quality_indicators": ["Monitor for call quality issues", "Check for audio dropouts"]
            }
        }
    
    # Enhance with payload type information if provided
    if payload_type and payload_type.isdigit():
        payload_num = int(payload_type)
        if payload_num != codec_info["standard_payload_type"]:
            codec_info["payload_type_note"] = f"Using non-standard payload type {payload_num} (standard: {codec_info['standard_payload_type']})"
    
    return codec_info


def enrich_sip_data_with_codec_context(sip_data: str) -> str:
    """
    Enriches SIP capture data with codec analysis context for enhanced AI diagnostics.
    
    This function analyzes the SIP data to identify codecs in use and adds
    comprehensive codec information to help the AI model provide better diagnostics.
    
    Enhancement Process:
    1. Parse SIP data to identify codecs and payload types
    2. Look up detailed codec information from the database
    3. Add codec context as structured data
    4. Include RTP analysis guidance for AI processing
    
    Args:
        sip_data: Raw SIP capture data (JSON or text format)
        
    Returns:
        str: Enhanced SIP data with codec analysis context appended
        
    Example:
        >>> raw_data = '{"sip_messages": [...]}'
        >>> enriched = enrich_sip_data_with_codec_context(raw_data)
        >>> # Now contains codec analysis guidance for AI
    """
    if not sip_data:
        return sip_data
    
    # Build codec context based on common VoIP codecs
    codec_context = {
        "enhanced_codec_analysis": {
            "g_711_mu_law": get_codec_analysis_context("PCMU"),
            "g_729_low_bitrate_codec": get_codec_analysis_context("G.729"),
            "g_711_a_law": get_codec_analysis_context("PCMA")
        },
        "rtp_stream_troubleshooting_guidance": {
            "g_711_mu_law": {
                "packet_loss_thresholds": ["<1%", "1-3%", ">5%"],
                "jitter_thresholds": ["<20ms", "20-50ms", ">50ms"]
            },
            "g_729_low_bitrate_codec": {
                "packet_loss_thresholds": ["<1%", "1-3%"],
                "jitter_thresholds": ["<20ms", "20-50ms"]
            },
            "g_711_a_law": {
                "packet_loss_thresholds": ["<1%", "1-3%"], 
                "jitter_thresholds": ["<20ms", "20-50ms"]
            }
        }
    }
    
    # Add codec context to the SIP data
    context_json = json.dumps(codec_context, indent=2)
    
    enhanced_data = f"{sip_data}\n\n--- CODEC ANALYSIS CONTEXT ---\n{context_json}"
    
    return enhanced_data


def extract_codec_directly(sip_data: str) -> str:
    """
    Extract codec information directly from RTP payload types in the SIP data.
    This bypasses the AI analysis pipeline to ensure reliable codec detection.
    
    Args:
        sip_data: Raw extracted SIP data
        
    Returns:
        str: Codec name (e.g., "G.711 μ-law (PCMU)") or "Unknown"
    """
    # Standard RTP payload type to codec mapping
    PAYLOAD_TYPE_CODECS = {
        0: "G.711 μ-law (PCMU)",
        8: "G.711 A-law (PCMA)", 
        9: "G.722",
        18: "G.729",
        96: "Dynamic (often Opus)",
        97: "Dynamic (often iLBC)",
        98: "Dynamic (often Speex)",
        99: "Dynamic (often H.264)",
        # Add more as needed
    }
    
    try:
        # Parse the JSON data
        data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
        
        # Look for RTP streams with payload types
        detected_codecs = set()
        
        # Search for payload type patterns in the data
        if isinstance(data, list):
            for packet in data:
                # Look for RTP payload type fields
                if "rtp" in str(packet).lower():
                    # Search for payload type in various possible fields
                    packet_str = str(packet)
                    payload_matches = re.findall(r'"rtp\.p_type":\s*"(\d+)"', packet_str)
                    
                    for match in payload_matches:
                        pt = int(match)
                        if pt in PAYLOAD_TYPE_CODECS:
                            detected_codecs.add(PAYLOAD_TYPE_CODECS[pt])
        
        # If we found any codecs, return the first one (they're usually the same)
        if detected_codecs:
            return list(detected_codecs)[0]
            
        # Fallback: look for common codec names in the data
        data_str = str(data).lower()
        if "pcmu" in data_str or "μ-law" in data_str:
            return "G.711 μ-law (PCMU)"
        elif "pcma" in data_str or "a-law" in data_str:
            return "G.711 A-law (PCMA)"
        elif "g722" in data_str:
            return "G.722"
        elif "g729" in data_str:
            return "G.729"
            
    except Exception as e:
        print(f"   ℹ️  Direct codec extraction error: {e}")
    
    return "Unknown"
