#!/usr/bin/env python3
"""
S.O.N.I.C. Bypass Mode - Packet Analysis without AI

This mode provides comprehensive packet analysis and call tracking without relying on AI models.
Useful when AI models are having issues or for pure packet-based analysis.
"""

import sys
import os
import json
sys.path.append('/home/noot/sonic')

from extractors.tshark import extract_sip_data
from analyzers.call_tracking import extract_and_analyze_call_tracking, print_call_tracking_analysis
from analyzers.call_quality_scoring import CallQualityScorer, print_quality_score_analysis
from analyzers.rtp_mos_analysis import AdvancedRTPMOSAnalyzer, print_mos_analysis
from extractors.auth_info import extract_auth_and_registration_info
from utils.reporting import print_diagnostic_report, save_report_to_file
from utils.wireshark import print_wireshark_summary
from analyzers.endpoint_analysis import print_endpoint_analysis
from analyzers.overlap_dialing import print_overlap_dialing_analysis
from utils.codecs import extract_codec_directly

def analyze_without_ai(file_path: str, save_file: str = None):
    """
    Analyze SIP capture without AI models - pure packet analysis.
    """
    print("📞 S.O.N.I.C. - Packet Analysis Mode (No AI)")
    print("="*80)
    print(f"📂 Analyzing: {file_path}")
    
    # Extract SIP data
    print("\n🔍 Extracting SIP data...")
    sip_data = extract_sip_data(file_path)
    
    if not sip_data:
        print("❌ No SIP data found in capture")
        return
    
    # Direct codec extraction
    print("\n🎵 Analyzing audio codecs...")
    codec = extract_codec_directly(sip_data)
    print(f"   Detected codec: {codec}")
    
    # Call tracking analysis
    print("\n📞 Analyzing call patterns...")
    try:
        from utils.sip_converter import convert_sip_data_for_tracking
        tracking_data = convert_sip_data_for_tracking(sip_data)
        sessions, tracking_analysis = extract_and_analyze_call_tracking(tracking_data)
        print_call_tracking_analysis(sessions, tracking_analysis)
    except Exception as e:
        print(f"⚠️ Call tracking failed: {e}")
        # Fallback to simple extraction
        from call_tracker import extract_sip_with_simple_tshark
        simple_data = extract_sip_with_simple_tshark(file_path)
        if simple_data:
            sessions, tracking_analysis = extract_and_analyze_call_tracking(simple_data)
            print_call_tracking_analysis(sessions, tracking_analysis)
    
    # Endpoint analysis
    print("\n🌐 Analyzing endpoints...")
    try:
        print_endpoint_analysis(sip_data, file_path)
    except Exception as e:
        print(f"⚠️ Endpoint analysis failed: {e}")
    
    # Overlap dialing analysis
    print("\n📞 Analyzing dialing patterns...")
    try:
        print_overlap_dialing_analysis(sip_data, file_path)
    except Exception as e:
        print(f"⚠️ Overlap dialing analysis failed: {e}")
     # Wireshark analysis
    print("\n🔍 Generating Wireshark analysis...")
    try:
        print_wireshark_summary(sip_data)
    except Exception as e:
        print(f"⚠️ Wireshark analysis failed: {e}")
    
    # Advanced Quality Analysis
    print("\n🎯 PERFORMING ADVANCED QUALITY ANALYSIS...")
    
    # Call Quality Scoring
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
    except Exception as e:
        print(f"⚠️ Call quality scoring failed: {e}")
        quality_result = None
    
    # Advanced RTP MOS Analysis
    print("\n🎵 Running Advanced RTP MOS Analysis...")
    try:
        mos_analyzer = AdvancedRTPMOSAnalyzer()
        mos_result = mos_analyzer.analyze_rtp_streams(sip_data, file_path)
        print_mos_analysis(mos_result, file_path)
    except Exception as e:
        print(f"⚠️ RTP MOS analysis failed: {e}")
        mos_result = None

    # Create a basic report without AI
    report = create_basic_report(sip_data, tracking_analysis if 'tracking_analysis' in locals() else {}, 
                               quality_result if 'quality_result' in locals() else None,
                               mos_result if 'mos_result' in locals() else None)
    
    # Save report if requested
    if save_file:
        try:
            # Get auth_data if it was extracted earlier
            auth_data_for_report = auth_data if 'auth_data' in locals() else None
            save_report_to_file(report, sip_data, file_path, save_file, None, auth_data_for_report)
            print(f"\n💾 Report saved to: {save_file}")
        except Exception as e:
            print(f"⚠️ Failed to save report: {e}")
    
    print("\n" + "="*80)
    print("✅ Packet analysis completed successfully!")

def create_basic_report(sip_data: str, tracking_analysis: dict, quality_result=None, mos_result=None) -> dict:
    """Create a basic diagnostic report from packet analysis."""
    
    # Extract basic information
    codec = extract_codec_directly(sip_data)
    
    # Create a minimal report structure
    report = {
        "total_calls_analyzed": tracking_analysis.get("total_calls", 0),
        "calls": [],
        "overall_assessment": f"Packet-based analysis completed. Found {tracking_analysis.get('total_calls', 0)} call(s).",
        "recommendations": [
            "Use call tracking results to understand call flow patterns",
            "Review Wireshark filters for detailed packet investigation", 
            "Check endpoint analysis for capability mismatches",
            "Monitor disconnect codes for call quality issues"
        ]
    }
    
    # Add quality analysis results
    if quality_result:
        report["quality_analysis"] = {
            "overall_grade": quality_result.overall_grade.value if hasattr(quality_result, 'overall_grade') else "Unknown",
            "total_score": quality_result.total_score if hasattr(quality_result, 'total_score') else 0
        }
        
    if mos_result:
        report["mos_analysis"] = {
            "average_mos": mos_result.average_mos,
            "overall_category": mos_result.overall_category.value if hasattr(mos_result, 'overall_category') else "Unknown",
            "streams_analyzed": len(mos_result.streams) if mos_result.streams else 0
        }
    
    # Add basic call information if available
    if tracking_analysis.get("total_calls", 0) > 0:
        basic_call = {
            "callId": "packet-analysis-summary",
            "callerIp": "Multiple",
            "calleeIp": "Multiple", 
            "userAgents": [],
            "audioQuality": {
                "codecUsed": codec,
                "payloadTypes": [],
                "rtpPort": "Various",
                "potentialIssues": []
            },
            "callFlow": {
                "callSetupMethod": "INVITE",
                "callTermination": f"{tracking_analysis.get('normal_terminations', 0)} normal, {tracking_analysis.get('error_terminations', 0)} errors",
                "responseCodes": [],
                "callDurationIndicators": f"Complete: {tracking_analysis.get('complete_calls', 0)}, Incomplete: {tracking_analysis.get('incomplete_calls', 0)}"
            },
            "diagnosticSummary": f"Packet analysis found {tracking_analysis.get('total_calls', 0)} calls with {tracking_analysis.get('error_terminations', 0)} error terminations"
        }
        report["calls"] = [basic_call]
    
    return report

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="S.O.N.I.C. Packet Analysis Mode - Comprehensive SIP analysis without AI models"
    )
    parser.add_argument("--file", required=True, help="Path to the SIP capture file (pcap/pcapng)")
    parser.add_argument("--save_file", help="Path to save the diagnostic report as markdown")
    
    args = parser.parse_args()
    
    # Set default save file name to TEST_CAPTURE.md per policy
    if not args.save_file:
        args.save_file = "TEST_CAPTURE.md"
    
    analyze_without_ai(args.file, args.save_file)

if __name__ == "__main__":
    main()
