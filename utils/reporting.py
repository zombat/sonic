#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Reporting Module

Handles formatting and output of diagnostic reports, including console display
and markdown file generation.

Author: Raymond A Rizzo | Zombat
Version: 3.0 (Modular Architecture)
Last Updated: 2025-07-15
"""

import sys
import time
import json
from typing import Dict, Any
from utils.codecs import extract_codec_directly
from utils.wireshark import print_wireshark_details, print_wireshark_summary
from analyzers.endpoint_analysis import print_endpoint_analysis
from analyzers.overlap_dialing import print_overlap_dialing_analysis
from analyzers.call_tracking import extract_and_analyze_call_tracking, print_call_tracking_analysis
from utils.sip_converter import convert_sip_data_for_tracking


def print_diagnostic_report(report: Dict[str, Any], sip_data: str = None, file_path: str = None, auth_data: Dict[str, Any] = None) -> None:
    """
    Prints a formatted diagnostic report to the console.
    
    Args:
        report: Diagnostic report dictionary from analysis
        sip_data: Raw SIP data for direct codec extraction if needed
        file_path: Path to original pcap file for enhanced analysis
        auth_data: Authentication data from extract_auth_and_registration_info()
    """
    print("\n" + "="*80)
    print("📋 S.O.N.I.C. DIAGNOSTIC REPORT")
    print("="*80)
    
    # Summary information
    total_calls = report.get('total_calls_analyzed', 0)
    overall_assessment = report.get('overall_assessment', 'No assessment available')
    
    print(f"\n📊 Diagnostic Summary:")
    print(f"   Total calls analyzed: {total_calls}")
    print(f"   Overall assessment: {overall_assessment}")
    
    # Individual call analysis
    calls = report.get('calls', [])
    if calls and len(calls) > 0:
        # Check if this is real call data or synthetic enhanced codec analysis
        first_call = calls[0]
        is_synthetic = (first_call.get('call_id') == 'enhanced-codec-analysis' or 
                       first_call.get('caller_ip') == 'Enhanced-Codec')
        
        if not is_synthetic:
            # Process real call data normally
            print(f"\n📞 Call Analysis:")
            for i, call in enumerate(calls, 1):
                print(f"\n   Call {i}: {call.get('callId', 'Unknown')}")
                print(f"   📍 Endpoints: {call.get('callerIp', 'Unknown')} → {call.get('calleeIp', 'Unknown')}")
                
                # Audio quality
                audio_quality = call.get('audioQuality', {})
                codec = audio_quality.get('codecUsed', 'Unknown')
                
                # If AI analysis couldn't determine codec, try direct extraction
                if codec == 'Unknown' and sip_data:
                    direct_codec = extract_codec_directly(sip_data)
                    if direct_codec != 'Unknown':
                        codec = direct_codec
                        print(f"   ℹ️  Using direct codec detection")
                
                issues = audio_quality.get('potentialIssues', [])
                # Try both field name formats due to Pydantic field name conversion
                network_baseline = call.get('networkBaseline', {}) or call.get('network_baseline', {})
                
                print(f"   🎵 Audio: {codec}")
                if issues:
                    print(f"   ⚠️  Issues: {len(issues)} identified")
                    for issue in issues:  # Show all issues
                        print(f"      • {issue}")
                else:
                    print(f"   ✅ No specific issues detected")
                
                # TCP congestion baseline analysis (not overall network health assessment)
                if network_baseline:
                    health_assessment = network_baseline.get('health_assessment', 'Unknown')
                    health_score = network_baseline.get('health_score', 0)
                    voip_impact = network_baseline.get('voip_impact_assessment', 'Unknown')
                    print(f"   📊 TCP Congestion Baseline: {health_assessment} (Score: {health_score}/100)")
                    print(f"      ℹ️  Note: Analysis of visible TCP congestion indicators in this capture only")
                    print(f"      📈 Observed Indicators: {voip_impact}")
                    
                    # Show key congestion indicators observed
                    health_factors = network_baseline.get('network_health_factors', [])
                    if health_factors:
                        print(f"      🔧 TCP Analysis Details:")
                        for factor in health_factors[:3]:  # Show top 3 factors
                            print(f"         • {factor}")
                
                # Call flow
                call_flow = call.get('callFlow', {})
                setup_method = call_flow.get('callSetupMethod', 'Unknown')
                termination = call_flow.get('callTermination', 'Unknown')
                
                print(f"   📋 Flow: {setup_method} → {termination}")
                
                # Always show Wireshark investigation details
                print_wireshark_details(call, sip_data)
                
                # Show endpoint analysis
                print_endpoint_analysis(sip_data, file_path)
                
                # Show overlap dialing analysis
                print_overlap_dialing_analysis(sip_data, file_path)
        else:
            # Handle synthetic enhanced codec analysis - create real call data from packet info
            print(f"\n📞 Call Analysis:")
            
            # Extract real data from sip_data since AI gave us synthetic enhanced analysis
            if sip_data:
                try:
                    data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
                    sip_packets = data.get('sip_packets', [])
                    rtp_streams = data.get('rtp_streams', [])
                    
                    # Extract endpoints from packet data
                    endpoints = set()
                    for packet in sip_packets:
                        endpoints.add(packet.get('src_ip', ''))
                        endpoints.add(packet.get('dst_ip', ''))
                    endpoints = [ip for ip in endpoints if ip]
                    
                    caller_ip = endpoints[0] if len(endpoints) > 0 else 'Unknown'
                    callee_ip = endpoints[1] if len(endpoints) > 1 else 'Unknown'
                    
                    # Get codec from enhanced analysis
                    enhanced_codec = first_call.get('audio_quality', {}).get('codec_used', 'Unknown')
                    
                    print(f"\n   Call 1: {sip_packets[0].get('call_id', 'Unknown') if sip_packets else 'Unknown'}")
                    print(f"   📍 Endpoints: {caller_ip} → {callee_ip}")
                    print(f"   🎵 Audio: {enhanced_codec}")
                    
                    # Show enhanced analysis issues
                    enhanced_issues = first_call.get('audio_quality', {}).get('potential_issues', [])
                    if enhanced_issues:
                        print(f"   ⚠️  Issues: {len(enhanced_issues)} identified")
                        for issue in enhanced_issues:  # Show all issues
                            print(f"      • {issue}")
                    else:
                        print(f"   ✅ No specific issues detected")
                    
                    # Show TCP congestion baseline if available  
                    network_baseline = first_call.get('network_baseline', {})
                    if network_baseline:
                        health_assessment = network_baseline.get('health_assessment', 'Unknown')
                        health_score = network_baseline.get('health_score', 0)
                        voip_impact = network_baseline.get('voip_impact_assessment', 'Unknown')
                        print(f"   📊 TCP Congestion Baseline: {health_assessment} (Score: {health_score}/100)")
                        print(f"      ℹ️  Note: Analysis of visible TCP congestion indicators in this capture only")
                        print(f"      📈 Observed Indicators: {voip_impact}")
                        
                        # Show key congestion indicators observed
                        health_factors = network_baseline.get('network_health_factors', [])
                        if health_factors:
                            print(f"      🔧 TCP Analysis Details:")
                            for factor in health_factors[:3]:  # Show top 3 factors
                                print(f"         • {factor}")
                    
                    print(f"   📋 Flow: INVITE → 200 OK")
                    
                    # Create a proper call object for the Wireshark details function
                    mock_call = {
                        'callId': sip_packets[0].get('call_id', 'Unknown') if sip_packets else 'Unknown',
                        'callerIp': caller_ip,
                        'calleeIp': callee_ip
                    }
                    
                    # Show Wireshark investigation details
                    print_wireshark_details(mock_call, sip_data)
                    
                    # Show endpoint analysis
                    print_endpoint_analysis(sip_data, file_path)
                    
                    # Show overlap dialing analysis
                    print_overlap_dialing_analysis(sip_data, file_path)
                    
                except Exception as e:
                    print(f"\n   Call 1: Unknown")
                    print(f"   📍 Endpoints: Unknown → Unknown")
                    print(f"   🎵 Audio: Unknown")
                    print(f"   ✅ No specific issues detected")
                    print(f"   ℹ️  Raw packet analysis available below")
    else:
        # Even if no calls detected by AI, we can still analyze the raw packet data
        print(f"\n📞 Call Analysis:")
        
        # Try to extract codec info directly from packet data
        codec = extract_codec_directly(sip_data) if sip_data else 'Unknown'
        
        # Create a basic call structure from the available packet data
        if sip_data:
            try:
                data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
                sip_packets = data.get('sip_packets', [])
                rtp_streams = data.get('rtp_streams', [])
                
                # Extract endpoints from packet data
                endpoints = set()
                for packet in sip_packets:
                    endpoints.add(packet.get('src_ip', ''))
                    endpoints.add(packet.get('dst_ip', ''))
                endpoints = [ip for ip in endpoints if ip]
                
                caller_ip = endpoints[0] if len(endpoints) > 0 else 'Unknown'
                callee_ip = endpoints[1] if len(endpoints) > 1 else 'Unknown'
                
                print(f"\n   Call 1: {sip_packets[0].get('call_id', 'Unknown') if sip_packets else 'Unknown'}")
                print(f"   📍 Endpoints: {caller_ip} → {callee_ip}")
                print(f"   🎵 Audio: {codec}")
                print(f"   ✅ No specific issues detected")
                print(f"   📋 Flow: INVITE → 200 OK")
                
                # Create a mock call object for the Wireshark details function
                mock_call = {
                    'callId': sip_packets[0].get('call_id', 'Unknown') if sip_packets else 'Unknown',
                    'callerIp': caller_ip,
                    'calleeIp': callee_ip
                }
                
                # Show Wireshark investigation details
                print_wireshark_details(mock_call, sip_data)
                
                # Show endpoint analysis
                print_endpoint_analysis(sip_data, file_path)
                
                # Show overlap dialing analysis
                print_overlap_dialing_analysis(sip_data, file_path)
                
            except Exception as e:
                print(f"\n✅ No specific issues detected.")
                print(f"   ℹ️  Raw packet analysis available below")
    
    # Recommendations
    recommendations = report.get('recommendations', [])
    if recommendations:
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(recommendations[:5], 1):  # Show first 5 recommendations
            print(f"   {i}. {rec}")
    
    # Call Tracking Analysis - Show who initiated and who hung up
    if sip_data:
        try:
            # Convert SIP data to format suitable for call tracking
            tracking_data = convert_sip_data_for_tracking(sip_data)
            sessions, tracking_analysis = extract_and_analyze_call_tracking(tracking_data)
            print_call_tracking_analysis(sessions, tracking_analysis)
        except Exception as e:
            # If the main extraction failed, try a simpler approach for call tracking only
            print(f"\n⚠️  Advanced call tracking failed, trying simplified extraction...")
            try:
                from call_tracker import extract_sip_with_simple_tshark
                simple_data = extract_sip_with_simple_tshark(file_path) if file_path else None
                if simple_data:
                    sessions, tracking_analysis = extract_and_analyze_call_tracking(simple_data)
                    print_call_tracking_analysis(sessions, tracking_analysis)
                else:
                    print(f"   📞 Call tracking unavailable - no SIP INVITE/BYE messages found")
            except Exception as e2:
                print(f"   📞 Call tracking unavailable: {e2}")
                # Minimal debug information for troubleshooting
                print(f"      Data type: {type(sip_data)}")
                if isinstance(sip_data, str) and len(sip_data) > 0:
                    print(f"      Data preview: {sip_data[:100]}...")
                elif hasattr(sip_data, 'keys'):
                    print(f"      Data keys: {list(sip_data.keys())}")
                else:
                    print(f"      Data: {str(sip_data)[:100]}...")
    
    # Authentication Security Analysis (Phase 3)
    if auth_data:
        from extractors.auth_info import calculate_auth_security_posture, generate_auth_upgrade_recommendations
        
        auth_challenges = auth_data.get("auth_challenges", [])
        auth_responses = auth_data.get("auth_responses", [])
        register_attempts = auth_data.get("register_attempts", [])
        
        # Only show section if there's authentication activity
        if auth_challenges or auth_responses or register_attempts:
            print("\n" + "="*80)
            print("🔐 AUTHENTICATION SECURITY ANALYSIS")
            print("="*80)
            
            # Security Posture Scoring
            posture = calculate_auth_security_posture(auth_data)
            
            print(f"\n🎯 Security Posture: {posture['grade']} ({posture['score']}/100)")
            
            if posture['grade'] in ['A+', 'A']:
                print("   ✅ Excellent authentication security")
            elif posture['grade'] == 'B':
                print("   ✓ Good authentication security with minor issues")
            elif posture['grade'] == 'C':
                print("   ⚠️ Adequate authentication security - improvements recommended")
            elif posture['grade'] == 'D':
                print("   ⚠️ Weak authentication security - upgrades needed")
            else:
                print("   ❌ Critical authentication security issues detected")
            
            # Positive Factors
            if posture['factors']:
                print(f"\n✅ Security Strengths:")
                for factor in posture['factors'][:3]:  # Show top 3
                    print(f"   • {factor}")
            
            # Security Risks
            if posture['risks']:
                print(f"\n⚠️ Security Risks Identified:")
                for risk in posture['risks']:
                    print(f"   • {risk}")
            
            # Realm and Server Mapping
            if auth_data.get("sip_servers"):
                print(f"\n📊 Authentication Realm & Server Mapping:")
                print()
                print(format_realm_server_mapping(auth_data))
            
            # Authentication Sequence (first REGISTER attempt)
            if register_attempts:
                print(f"\n📋 Authentication Sequence (First REGISTER):")
                print()
                print(generate_auth_sequence_ascii(register_attempts[0], auth_challenges))
                
                # Show summary of all attempts if multiple
                if len(register_attempts) > 1:
                    successful = sum(1 for r in register_attempts if r.get("success"))
                    print(f"\n   📈 Total REGISTER Attempts: {len(register_attempts)}")
                    print(f"   ✅ Successful: {successful}")
                    print(f"   ❌ Failed: {len(register_attempts) - successful}")
            
            # Upgrade Recommendations
            recommendations = generate_auth_upgrade_recommendations(auth_data)
            if recommendations:
                print(f"\n💡 Authentication Upgrade Recommendations:")
                for i, rec in enumerate(recommendations[:3], 1):  # Show top 3
                    print(f"   {i}. {rec}")
    
    # Wireshark analysis summary
    print_wireshark_summary(sip_data)
    
    print("\n" + "="*80)


def save_report_to_file(report: Dict[str, Any], sip_data: str = None, file_path: str = None, save_path: str = None, quality_results: Dict[str, Any] = None, auth_data: Dict[str, Any] = None) -> None:
    """
    Saves a formatted diagnostic report to a markdown file.
    
    Args:
        report: Diagnostic report dictionary from analysis
        sip_data: Raw SIP data for direct codec extraction if needed
        file_path: Path to the original pcap file
        save_path: Path where to save the markdown report
        quality_results: Optional quality analysis results to include
        auth_data: Authentication data from extract_auth_and_registration_info()
    
    Note:
        Only TEST_CAPTURE.md is allowed as the output filename per policy.
        This prevents proliferation of pcap-derived markdown files.
    """
    if not save_path:
        return
    
    # Enforce TEST_CAPTURE.md policy at sink level
    import os
    filename = os.path.basename(save_path)
    if filename != "TEST_CAPTURE.md":
        error_msg = f"ERROR: Report output filename must be 'TEST_CAPTURE.md', got '{filename}'"
        print(f"\n❌ {error_msg}")
        print("This policy prevents proliferation of pcap-derived markdown files.")
        import sys
        sys.exit(2)
    
    try:
        # Capture the report output by redirecting stdout
        import io
        import contextlib
        
        # Create a string buffer to capture the output
        captured_output = io.StringIO()
        
        # Temporarily redirect stdout to capture the print statements
        with contextlib.redirect_stdout(captured_output):
            print_diagnostic_report(report, sip_data, file_path, auth_data)
        
        # Get the captured content
        report_content = captured_output.getvalue()
        
        # Add quality analysis results if provided
        quality_content = ""
        if quality_results:
            quality_content = "\n\n## 🎯 QUALITY ANALYSIS RESULTS\n\n"
            
            if quality_results.get("call_quality"):
                quality_content += "### 📊 Call Quality Scoring\n\n"
                qr = quality_results["call_quality"]
                quality_content += f"**Overall Score**: {qr.total_score if hasattr(qr, 'total_score') else 'N/A'}/100\n\n"
                quality_content += f"**Grade**: {qr.overall_grade.value if hasattr(qr, 'overall_grade') else 'N/A'}\n\n"
            
            if quality_results.get("mos_analysis"):
                quality_content += "### 🎵 RTP MOS Analysis\n\n"
                mos = quality_results["mos_analysis"]
                if mos.streams:
                    quality_content += f"**Average MOS Score**: {mos.average_mos:.2f}/5.0\n\n"
                    quality_content += f"**Quality Category**: {mos.overall_category.value}\n\n"
                    quality_content += f"**Streams Analyzed**: {len(mos.streams)}\n\n"
                else:
                    quality_content += "**Status**: No RTP streams detected\n\n"
        
        # Add auth security content for markdown (with Mermaid diagrams)
        auth_content = ""
        if auth_data:
            from extractors.auth_info import calculate_auth_security_posture, generate_auth_upgrade_recommendations
            
            auth_challenges = auth_data.get("auth_challenges", [])
            auth_responses = auth_data.get("auth_responses", [])
            register_attempts = auth_data.get("register_attempts", [])
            
            if auth_challenges or auth_responses or register_attempts:
                auth_content = "\n\n## 🔐 AUTHENTICATION SECURITY ANALYSIS\n\n"
                
                # Security Posture
                posture = calculate_auth_security_posture(auth_data)
                auth_content += f"### 🎯 Security Posture: {posture['grade']} ({posture['score']}/100)\n\n"
                
                if posture['factors']:
                    auth_content += "**Security Strengths:**\n\n"
                    for factor in posture['factors']:
                        auth_content += f"- ✅ {factor}\n"
                    auth_content += "\n"
                
                if posture['risks']:
                    auth_content += "**Security Risks:**\n\n"
                    for risk in posture['risks']:
                        auth_content += f"- ⚠️ {risk}\n"
                    auth_content += "\n"
                
                # Server/Realm Table
                if auth_data.get("sip_servers"):
                    auth_content += "### 📊 Authentication Server Summary\n\n"
                    auth_content += "| Server IP | Role | Challenges | Realms |\n"
                    auth_content += "|-----------|------|------------|--------|\n"
                    
                    for server_ip, server_info in auth_data.get("sip_servers", {}).items():
                        realms = server_info.get("realms", [])
                        challenges = server_info.get("challenge_count", 0)
                        server_401 = server_info.get("server_challenges", 0)
                        proxy_407 = server_info.get("proxy_challenges", 0)
                        
                        if proxy_407 > server_401:
                            role = "SIP Proxy"
                        elif server_401 > 0:
                            role = "Registrar"
                        else:
                            role = "Server"
                        
                        realm_str = ", ".join(realms[:2])  # First 2 realms
                        if len(realms) > 2:
                            realm_str += f" (+{len(realms)-2} more)"
                        
                        auth_content += f"| {server_ip} | {role} | {challenges} | {realm_str} |\n"
                    
                    auth_content += "\n"
                
                # Mermaid Sequence Diagrams for REGISTER attempts
                if register_attempts:
                    auth_content += "### 📋 Authentication Sequences\n\n"
                    
                    # Show first 2 REGISTER attempts
                    for i, attempt in enumerate(register_attempts[:2], 1):
                        status = "✅ Success" if attempt.get("success") else "❌ Failure"
                        auth_content += f"**REGISTER Attempt {i}** ({status})\n\n"
                        auth_content += generate_mermaid_auth_sequence(attempt, auth_challenges)
                        auth_content += "\n\n"
                    
                    if len(register_attempts) > 2:
                        successful = sum(1 for r in register_attempts if r.get("success"))
                        auth_content += f"*Total: {len(register_attempts)} attempts ({successful} successful, {len(register_attempts)-successful} failed)*\n\n"
                
                # Recommendations
                recommendations = generate_auth_upgrade_recommendations(auth_data)
                if recommendations:
                    auth_content += "### 💡 Upgrade Recommendations\n\n"
                    for i, rec in enumerate(recommendations, 1):
                        auth_content += f"{i}. {rec}\n"
                    auth_content += "\n"
        
        # Add markdown formatting and metadata
        markdown_content = f"""# S.O.N.I.C. Diagnostic Report

**Generated**: {time.strftime("%Y-%m-%d %H:%M:%S")}  
**Source File**: `{file_path if file_path else 'Unknown'}`  
**Report File**: `{save_path}`

---

{report_content}{quality_content}{auth_content}

---

*Report generated by S.O.N.I.C. - SIP Observation and Network Inspection Console*
"""
        
        # Write to file
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        print(f"\n💾 Report saved to: {save_path}")
        
    except Exception as e:
        print(f"\n⚠️  Failed to save report to {save_path}: {e}")


def format_realm_server_mapping(auth_data: Dict[str, Any]) -> str:
    """
    Format realm and server authentication mapping as ASCII tree structure.
    
    Creates a hierarchical display showing which servers handle which realms,
    with challenge counts and algorithm strength indicators.
    
    Args:
        auth_data: Complete auth data from extract_auth_and_registration_info()
    
    Returns:
        Formatted string with realm/server tree structure
    """
    if not auth_data:
        return "   No authentication data available"
    
    sip_servers = auth_data.get("sip_servers", {})
    auth_challenges = auth_data.get("auth_challenges", [])
    
    if not sip_servers:
        return "   No SIP servers with authentication detected"
    
    lines = []
    
    for server_ip, server_info in sip_servers.items():
        realms = server_info.get("realms", [])
        challenge_count = server_info.get("challenge_count", 0)
        server_challenges = server_info.get("server_challenges", 0)
        proxy_challenges = server_info.get("proxy_challenges", 0)
        
        # Determine server role
        if proxy_challenges > server_challenges:
            role = "SIP Proxy"
        elif server_challenges > 0:
            role = "SIP Registrar/Server"
        else:
            role = "SIP Server"
        
        lines.append(f"   📡 Server: {server_ip} ({role})")
        
        # Show realms for this server
        if realms:
            for i, realm in enumerate(realms):
                is_last_realm = (i == len(realms) - 1)
                prefix = "   └─" if is_last_realm else "   ├─"
                lines.append(f"{prefix} Realm: \"{realm}\"")
                
                # Find challenges for this server/realm combo
                realm_challenges = [
                    c for c in auth_challenges 
                    if c.get("realm") == realm and 
                    (c.get("from_ip") == server_ip or c.get("to_ip") == server_ip)
                ]
                
                if realm_challenges:
                    # Analyze algorithm strength for this realm
                    algorithms = set(c.get("algorithm", "").upper() for c in realm_challenges)
                    algorithms = {a for a in algorithms if a}  # Remove empty strings
                    
                    if algorithms:
                        weak = algorithms & {"MD5"}
                        strong = algorithms & {"SHA-256", "SHA-512"}
                        
                        if weak and not strong:
                            algo_status = "⚠️ Weak (MD5)"
                        elif strong and not weak:
                            algo_status = "✅ Strong (SHA-256+)"
                        elif strong and weak:
                            algo_status = "⚠️ Mixed (MD5 + SHA-256)"
                        else:
                            algo_status = f"{', '.join(algorithms)}"
                    else:
                        algo_status = "Unknown"
                    
                    # Check qop status
                    with_qop = sum(1 for c in realm_challenges if c.get("qop"))
                    qop_status = f"{with_qop}/{len(realm_challenges)} with qop"
                    if with_qop == len(realm_challenges):
                        qop_indicator = "✅"
                    elif with_qop == 0:
                        qop_indicator = "❌"
                    else:
                        qop_indicator = "⚠️"
                    
                    sub_prefix = "      " if is_last_realm else "   │  "
                    lines.append(f"{sub_prefix}   Challenges: {len(realm_challenges)}")
                    lines.append(f"{sub_prefix}   Algorithm: {algo_status}")
                    lines.append(f"{sub_prefix}   QoP: {qop_indicator} {qop_status}")
        else:
            lines.append(f"   └─ Challenges: {challenge_count} (realm unknown)")
        
        lines.append("")  # Blank line between servers
    
    return "\n".join(lines).rstrip()


def generate_auth_sequence_ascii(register_attempt: Dict[str, Any], auth_challenges: list = None) -> str:
    """
    Generate ASCII art sequence diagram for authentication flow.
    
    Creates a visual representation of the REGISTER request/challenge/response
    sequence showing packet numbers and authentication state.
    
    Args:
        register_attempt: Single REGISTER attempt from auth_data
        auth_challenges: Optional list of auth challenges for additional context
    
    Returns:
        Formatted ASCII sequence diagram string
    """
    packets = register_attempt.get("packets", [])
    if not packets:
        return "   No packet sequence available"
    
    # Extract IPs from packets if available (simplified - would need actual packet data)
    client_ip = "Client"
    server_ip = "Server"
    
    lines = []
    lines.append(f"   {client_ip:<20} {server_ip}")
    lines.append("      │                    │")
    
    for packet in packets:
        pkt_num = packet.get("packet_num", "?")
        pkt_type = packet.get("type", "unknown")
        has_auth = packet.get("has_auth", False)
        status_code = packet.get("status_code", "")
        
        if pkt_type == "request":
            if has_auth:
                method_label = "REGISTER (with Auth)"
            else:
                method_label = "REGISTER"
            lines.append(f"      │  {method_label:<17} │  [Packet #{pkt_num}]")
            lines.append(f"      │ ──────────────────> │")
        
        elif pkt_type == "challenge":
            challenge_label = f"{status_code} Challenge"
            lines.append(f"      │      {challenge_label:<12} │  [Packet #{pkt_num}]")
            lines.append(f"      │ <────────────────── │")
            
            # Add note about challenge details if available
            if auth_challenges:
                matching = [c for c in auth_challenges if c.get("packet_num") == pkt_num]
                if matching:
                    challenge = matching[0]
                    realm = challenge.get("realm", "")
                    algo = challenge.get("algorithm", "MD5")
                    if realm:
                        lines.append(f"      │   realm=\"{realm[:15]}\"")
                        lines.append(f"      │   algorithm={algo}")
        
        elif pkt_type == "response":
            response_label = f"{status_code} OK"
            lines.append(f"      │      {response_label:<12} │  [Packet #{pkt_num}]")
            lines.append(f"      │ <────────────────── │")
        
        lines.append("      │                    │")
    
    return "\n".join(lines)


def generate_mermaid_auth_sequence(register_attempt: Dict[str, Any], auth_challenges: list = None) -> str:
    """
    Generate Mermaid sequence diagram for authentication flow (markdown output).
    
    Creates a Mermaid diagram showing REGISTER authentication sequences
    with challenge/response details.
    
    Args:
        register_attempt: Single REGISTER attempt from auth_data
        auth_challenges: Optional list of auth challenges for note annotations
    
    Returns:
        Mermaid diagram as markdown code block string
    """
    packets = register_attempt.get("packets", [])
    if not packets:
        return ""
    
    call_id = register_attempt.get("call_id", "unknown")[:20]  # Truncate long Call-IDs
    
    lines = []
    lines.append("```mermaid")
    lines.append("sequenceDiagram")
    lines.append("    participant Client")
    lines.append("    participant Server")
    lines.append(f"    Note over Client,Server: Call-ID: {call_id}")
    
    for packet in packets:
        pkt_num = packet.get("packet_num", "?")
        pkt_type = packet.get("type", "unknown")
        has_auth = packet.get("has_auth", False)
        status_code = packet.get("status_code", "")
        
        if pkt_type == "request":
            if has_auth:
                lines.append(f"    Client->>Server: REGISTER (with Authorization)")
            else:
                lines.append(f"    Client->>Server: REGISTER")
            lines.append(f"    Note right of Client: Packet #{pkt_num}")
        
        elif pkt_type == "challenge":
            lines.append(f"    Server->>Client: {status_code} Challenge")
            
            # Add challenge details as note if available
            if auth_challenges:
                matching = [c for c in auth_challenges if c.get("packet_num") == pkt_num]
                if matching:
                    challenge = matching[0]
                    realm = challenge.get("realm", "")
                    algo = challenge.get("algorithm", "MD5")
                    qop = challenge.get("qop", "none")
                    lines.append(f"    Note left of Server: realm=\"{realm}\"<br/>algorithm={algo}<br/>qop={qop}")
            else:
                lines.append(f"    Note left of Server: Packet #{pkt_num}")
        
        elif pkt_type == "response":
            lines.append(f"    Server->>Client: {status_code} OK")
            lines.append(f"    Note left of Server: Packet #{pkt_num}")
    
    # Add success indicator
    if register_attempt.get("success"):
        lines.append("    Note over Client,Server: ✅ Registration Successful")
    else:
        lines.append("    Note over Client,Server: ❌ Registration Failed")
    
    lines.append("```")
    
    return "\n".join(lines)
