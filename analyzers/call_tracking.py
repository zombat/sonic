#!/usr/bin/env python3
"""
S.O.N.I.C. Call Tracking Module

This module tracks INVITE and BYE messages to determine call initiation and termination patterns.
Provides detailed analysis of who initiated calls and who hung up with disconnect codes.

Author: Raymond A Rizzo | Zombat
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CallEvent:
    """Represents a SIP call event (INVITE/BYE)"""
    frame_number: int
    timestamp: str
    call_id: str
    method: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    status_code: Optional[str] = None
    reason_phrase: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class CallSession:
    """Represents a complete call session with initiation and termination tracking"""
    call_id: str
    invite_event: Optional[CallEvent] = None
    bye_event: Optional[CallEvent] = None
    initiator_ip: Optional[str] = None
    terminator_ip: Optional[str] = None
    disconnect_code: Optional[str] = None
    disconnect_reason: Optional[str] = None
    call_direction: Optional[str] = None  # "outbound" or "inbound" relative to first IP
    
    def is_complete(self) -> bool:
        """Check if we have both INVITE and BYE for this call"""
        return self.invite_event is not None and self.bye_event is not None
    
    def get_session_type(self) -> str:
        """Get the type of session for better user understanding"""
        if self.invite_event and self.bye_event:
            return "complete"
        elif self.invite_event and not self.bye_event:
            return "invite_only"  # Call started but end not captured
        elif not self.invite_event and self.bye_event:
            return "bye_only"  # Call end captured but start not captured
        else:
            return "unknown"  # Should not happen
    
    def get_capture_context(self) -> str:
        """Get context about what's missing from the capture"""
        session_type = self.get_session_type()
        
        if session_type == "complete":
            return "Complete call session captured"
        elif session_type == "invite_only":
            return "Call start captured, but termination occurred outside capture window"
        elif session_type == "bye_only":
            return "Call termination captured, but initiation occurred before capture started"
        else:
            return "Partial session data"
    
    def get_call_summary(self) -> Dict[str, Any]:
        """Get a summary of the call session"""
        summary = {
            "call_id": self.call_id,
            "initiator_ip": self.initiator_ip,
            "terminator_ip": self.terminator_ip,
            "disconnect_code": self.disconnect_code,
            "disconnect_reason": self.disconnect_reason,
            "call_direction": self.call_direction,
            "invite_timestamp": self.invite_event.timestamp if self.invite_event else None,
            "bye_timestamp": self.bye_event.timestamp if self.bye_event else None,
            "complete_session": self.is_complete(),
            "session_type": self.get_session_type(),
            "capture_context": self.get_capture_context()
        }
        
        if self.invite_event and self.bye_event:
            # Determine who hung up
            if self.bye_event.src_ip == self.initiator_ip:
                summary["hangup_pattern"] = "Initiator hung up"
            else:
                summary["hangup_pattern"] = "Recipient hung up"
        
        return summary


def parse_sip_events_from_json(json_data: str) -> List[CallEvent]:
    """
    Parse SIP events from tshark JSON output.
    
    Args:
        json_data: JSON string from tshark SIP extraction
        
    Returns:
        List of CallEvent objects for INVITE and BYE messages
    """
    events = []
    
    try:
        # Handle both string and dict input
        if isinstance(json_data, str):
            packets = json.loads(json_data)
        else:
            packets = json_data
        
        # Handle different possible JSON structures
        if isinstance(packets, dict):
            # If it's a summary structure with sip_packets
            if 'sip_packets' in packets:
                packets = packets['sip_packets']
            # If it's raw tshark output
            elif '_source' in packets:
                packets = [packets]
            else:
                # Try to find packet data in the structure
                packets = []
        
        for packet in packets:
            # Handle different packet structures
            if '_source' in packet:
                # Raw tshark JSON format
                layers = packet.get("_source", {}).get("layers", {})
            else:
                # Processed format - treat packet as the layers
                layers = packet
            
            # Check if this packet has SIP data
            sip_data = layers.get("sip") or layers.get("sip_layer")
            if not sip_data:
                # Check if SIP data is in the packet directly
                if "call_id" in layers or "method" in layers:
                    # This looks like processed SIP data
                    sip_data = layers
                else:
                    continue
            
            # Extract basic packet info with fallbacks
            frame_layer = layers.get("frame", {})
            ip_layer = layers.get("ip", {})
            udp_layer = layers.get("udp", {})
            
            frame_number = (frame_layer.get("frame.number", ["0"])[0] if isinstance(frame_layer.get("frame.number"), list) 
                           else frame_layer.get("frame.number", 0))
            timestamp = (frame_layer.get("frame.time", ["Unknown"])[0] if isinstance(frame_layer.get("frame.time"), list)
                        else frame_layer.get("frame.time", layers.get("timestamp", "Unknown")))
            
            # Handle different IP address formats
            src_ip = (ip_layer.get("ip.src", ["Unknown"])[0] if isinstance(ip_layer.get("ip.src"), list)
                     else ip_layer.get("ip.src", layers.get("src_ip", "Unknown")))
            dst_ip = (ip_layer.get("ip.dst", ["Unknown"])[0] if isinstance(ip_layer.get("ip.dst"), list)
                     else ip_layer.get("ip.dst", layers.get("dst_ip", "Unknown")))
            
            # Handle port formats
            src_port = (udp_layer.get("udp.srcport", ["Unknown"])[0] if isinstance(udp_layer.get("udp.srcport"), list)
                       else udp_layer.get("udp.srcport", layers.get("src_port", "Unknown")))
            dst_port = (udp_layer.get("udp.dstport", ["Unknown"])[0] if isinstance(udp_layer.get("udp.dstport"), list)
                       else udp_layer.get("udp.dstport", layers.get("dst_port", "Unknown")))
            
            # Extract SIP-specific info with multiple fallback formats
            call_id = (sip_data.get("sip.Call-ID", ["Unknown"])[0] if isinstance(sip_data.get("sip.Call-ID"), list)
                      else sip_data.get("sip.Call-ID", sip_data.get("call_id", "Unknown")))
            
            method = sip_data.get("sip.Method", sip_data.get("method"))
            status_code = sip_data.get("sip.Status-Code", sip_data.get("status_code"))
            user_agent = sip_data.get("sip.User-Agent", sip_data.get("user_agent"))
            
            # Handle list formats
            if isinstance(method, list):
                method = method[0] if len(method) > 0 else None
            if isinstance(status_code, list):
                status_code = status_code[0] if len(status_code) > 0 else None
            if isinstance(user_agent, list):
                user_agent = user_agent[0] if len(user_agent) > 0 else None
            
            # Only track INVITE and BYE methods
            if method and method in ["INVITE", "BYE"]:
                event = CallEvent(
                    frame_number=int(frame_number) if str(frame_number).isdigit() else 0,
                    timestamp=timestamp,
                    call_id=call_id,
                    method=method,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=str(src_port),
                    dst_port=str(dst_port),
                    user_agent=user_agent
                )
                events.append(event)
            
            # Also track SIP responses that might indicate call termination
            elif status_code and status_code in ["486", "487", "603", "600", "480", "408", "504"]:
                event = CallEvent(
                    frame_number=int(frame_number) if str(frame_number).isdigit() else 0,
                    timestamp=timestamp,
                    call_id=call_id,
                    method=f"RESPONSE_{status_code}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=str(src_port),
                    dst_port=str(dst_port),
                    status_code=status_code,
                    reason_phrase=get_reason_phrase(status_code),
                    user_agent=user_agent
                )
                events.append(event)
                    
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing SIP JSON data: {e}")
        return []
    except Exception as e:
        print(f"❌ Error processing SIP events: {e}")
        return []
    
    return events


def get_reason_phrase(status_code: str) -> str:
    """Get the standard reason phrase for a SIP status code"""
    reason_phrases = {
        "408": "Request Timeout",
        "480": "Temporarily Unavailable", 
        "486": "Busy Here",
        "487": "Request Terminated",
        "504": "Server Time-out",
        "600": "Busy Everywhere",
        "603": "Decline"
    }
    return reason_phrases.get(status_code, f"Unknown ({status_code})")


def track_call_sessions(events: List[CallEvent]) -> Dict[str, CallSession]:
    """
    Track call sessions by correlating INVITE and BYE events.
    
    Args:
        events: List of SIP call events (INVITE/BYE)
        
    Returns:
        Dictionary of call sessions keyed by Call-ID
    """
    sessions = {}
    
    for event in events:
        call_id = event.call_id
        
        # Initialize session if not exists
        if call_id not in sessions:
            sessions[call_id] = CallSession(call_id=call_id)
        
        session = sessions[call_id]
        
        if event.method == "INVITE":
            # Record the INVITE (call initiation)
            session.invite_event = event
            session.initiator_ip = event.src_ip
            session.call_direction = "outbound"  # From initiator's perspective
            
        elif event.method == "BYE":
            # Record the BYE (call termination)
            session.bye_event = event
            session.terminator_ip = event.src_ip
            session.disconnect_code = "BYE"
            session.disconnect_reason = "Normal call termination"
            
            # If we don't have an INVITE for this BYE, this call started before capture
            if not session.invite_event:
                # We can try to infer the initiator from the BYE direction
                # The party receiving the BYE was likely the initiator
                session.initiator_ip = event.dst_ip
            
        elif event.method.startswith("RESPONSE_"):
            # Handle error responses that terminate calls
            session.disconnect_code = event.status_code
            session.disconnect_reason = event.reason_phrase
            session.terminator_ip = event.src_ip
            
            # For responses, if we don't have an INVITE, try to infer the initiator
            if not session.invite_event:
                # The party receiving the error response was likely the initiator
                session.initiator_ip = event.dst_ip
    
    return sessions


def analyze_call_patterns(sessions: Dict[str, CallSession]) -> Dict[str, Any]:
    """
    Analyze patterns in call initiation and termination.
    
    Args:
        sessions: Dictionary of call sessions
        
    Returns:
        Analysis results with patterns and statistics
    """
    analysis = {
        "total_calls": len(sessions),
        "complete_calls": 0,
        "incomplete_calls": 0,
        "invite_only_calls": 0,  # INVITE captured, BYE missing (call continues beyond capture)
        "bye_only_calls": 0,     # BYE captured, INVITE missing (call started before capture)
        "normal_terminations": 0,
        "error_terminations": 0,
        "initiator_hangups": 0,
        "recipient_hangups": 0,
        "disconnect_codes": {},
        "call_patterns": [],
        "capture_analysis": {
            "calls_started_in_capture": 0,
            "calls_ended_in_capture": 0,
            "calls_spanning_capture_window": 0
        }
    }
    
    for session in sessions.values():
        session_type = session.get_session_type()
        
        if session.is_complete():
            analysis["complete_calls"] += 1
            analysis["capture_analysis"]["calls_started_in_capture"] += 1
            analysis["capture_analysis"]["calls_ended_in_capture"] += 1
            
            # Check termination type
            if session.disconnect_code == "BYE":
                analysis["normal_terminations"] += 1
            else:
                analysis["error_terminations"] += 1
            
            # Track who hung up
            if session.bye_event and session.initiator_ip:
                if session.bye_event.src_ip == session.initiator_ip:
                    analysis["initiator_hangups"] += 1
                else:
                    analysis["recipient_hangups"] += 1
        else:
            analysis["incomplete_calls"] += 1
            
            if session_type == "invite_only":
                analysis["invite_only_calls"] += 1
                analysis["capture_analysis"]["calls_started_in_capture"] += 1
                # For invite_only sessions, if they have a disconnect code, count as termination
                if session.disconnect_code:
                    analysis["capture_analysis"]["calls_ended_in_capture"] += 1
                    if session.disconnect_code == "BYE":
                        analysis["normal_terminations"] += 1
                    else:
                        analysis["error_terminations"] += 1
            elif session_type == "bye_only":
                analysis["bye_only_calls"] += 1
                analysis["capture_analysis"]["calls_ended_in_capture"] += 1
                # Handle termination tracking for bye_only calls
                if session.disconnect_code == "BYE":
                    analysis["normal_terminations"] += 1
                else:
                    analysis["error_terminations"] += 1
        
        # Track disconnect codes
        if session.disconnect_code:
            if session.disconnect_code not in analysis["disconnect_codes"]:
                analysis["disconnect_codes"][session.disconnect_code] = 0
            analysis["disconnect_codes"][session.disconnect_code] += 1
    
    # Generate patterns summary with capture context
    if analysis["total_calls"] > 0:
        patterns = []
        
        # Hangup patterns (only for complete calls)
        if analysis["initiator_hangups"] > analysis["recipient_hangups"]:
            patterns.append("📞 Callers tend to hang up more often than recipients")
        elif analysis["recipient_hangups"] > analysis["initiator_hangups"]:
            patterns.append("📞 Recipients tend to hang up more often than callers")
        elif analysis["complete_calls"] > 0:
            patterns.append("📞 Balanced hangup pattern between callers and recipients")
        
        # Error patterns
        if analysis["error_terminations"] > analysis["normal_terminations"]:
            patterns.append("⚠️ More calls end with errors than normal termination")
        
        # Capture window analysis
        if analysis["invite_only_calls"] > 0:
            patterns.append(f"📤 {analysis['invite_only_calls']} call(s) started during capture but continued beyond")
        
        if analysis["bye_only_calls"] > 0:
            patterns.append(f"📥 {analysis['bye_only_calls']} call(s) ended during capture but started before")
        
        if analysis["complete_calls"] == 0 and analysis["total_calls"] > 0:
            patterns.append("🔄 No complete call sessions - all calls span beyond capture window")
        
        # Overall capture coverage
        total_events = analysis["capture_analysis"]["calls_started_in_capture"] + analysis["capture_analysis"]["calls_ended_in_capture"]
        if total_events > analysis["total_calls"]:
            patterns.append("📊 Good capture coverage - multiple call events captured")
        
        analysis["call_patterns"] = patterns
    
    return analysis


def print_call_tracking_analysis(sessions: Dict[str, CallSession], analysis: Dict[str, Any]):
    """
    Print formatted call tracking analysis.
    
    Args:
        sessions: Dictionary of call sessions
        analysis: Analysis results from analyze_call_patterns
    """
    print("\n" + "="*80)
    print("📞 CALL INITIATION & TERMINATION TRACKING")
    print("="*80)
    
    print(f"\n📊 CALL STATISTICS:")
    print(f"   • Total calls tracked: {analysis['total_calls']}")
    print(f"   • Complete sessions (INVITE + BYE): {analysis['complete_calls']}")
    print(f"   • Incomplete sessions: {analysis['incomplete_calls']}")
    
    # Enhanced incomplete session breakdown
    if analysis['incomplete_calls'] > 0:
        print(f"     ├─ INVITE only (call continues beyond capture): {analysis['invite_only_calls']}")
        print(f"     └─ BYE only (call started before capture): {analysis['bye_only_calls']}")
    
    print(f"   • Normal terminations (BYE): {analysis['normal_terminations']}")
    print(f"   • Error terminations: {analysis['error_terminations']}")
    
    # Capture window analysis
    if analysis.get('capture_analysis'):
        capture_stats = analysis['capture_analysis']
        print(f"\n📋 CAPTURE WINDOW ANALYSIS:")
        print(f"   • Calls started in capture: {capture_stats['calls_started_in_capture']}")
        print(f"   • Calls ended in capture: {capture_stats['calls_ended_in_capture']}")
        
        if analysis['invite_only_calls'] > 0:
            print(f"   📤 Note: {analysis['invite_only_calls']} call(s) may still be active beyond capture")
        if analysis['bye_only_calls'] > 0:
            print(f"   📥 Note: {analysis['bye_only_calls']} call(s) started before capture began")
    
    # Only show hangup patterns for complete calls
    if analysis['complete_calls'] > 0:
        print(f"\n🏁 HANGUP PATTERNS (Complete Calls Only):")
        print(f"   • Initiator hung up: {analysis['initiator_hangups']}")
        print(f"   • Recipient hung up: {analysis['recipient_hangups']}")
    
    if analysis["disconnect_codes"]:
        print(f"\n🔌 DISCONNECT CODES:")
        for code, count in analysis["disconnect_codes"].items():
            print(f"   • {code}: {count} times")
    
    if analysis["call_patterns"]:
        print(f"\n🔍 PATTERNS DETECTED:")
        for pattern in analysis["call_patterns"]:
            print(f"   {pattern}")
    
    # Show detailed call sessions with enhanced context
    print(f"\n📋 DETAILED CALL SESSIONS:")
    print("-" * 80)
    
    for call_id, session in sessions.items():
        summary = session.get_call_summary()
        session_type = summary['session_type']
        
        print(f"\n🆔 Call-ID: {call_id[:20]}{'...' if len(call_id) > 20 else ''}")
        
        # Show session type context
        if session_type == "complete":
            print(f"   ✅ Complete session - full call captured")
        elif session_type == "invite_only":
            print(f"   📤 Partial session - call started in capture, termination outside window")
        elif session_type == "bye_only":
            print(f"   📥 Partial session - call termination captured, started before capture")
        
        if session.invite_event:
            print(f"   📞 INVITE: {session.initiator_ip} → {session.invite_event.dst_ip} at {session.invite_event.timestamp}")
        else:
            print(f"   📞 INVITE: Not captured (call started before capture window)")
        
        if session.bye_event:
            print(f"   📴 BYE: {session.terminator_ip} → {session.bye_event.dst_ip} at {session.bye_event.timestamp}")
            if summary.get("hangup_pattern"):
                print(f"   🏁 Pattern: {summary['hangup_pattern']}")
        elif session.disconnect_code and session.disconnect_code != "BYE":
            print(f"   ❌ TERMINATED: {session.disconnect_code} - {session.disconnect_reason}")
        else:
            if session_type == "invite_only":
                print(f"   📴 BYE: Not captured (call may still be active or ended outside capture)")
            else:
                print(f"   📴 BYE: Not captured")
        
        # Enhanced context explanation
        print(f"   💭 Context: {summary['capture_context']}")
        
        if session_type == "invite_only":
            print(f"   ℹ️  This call was initiated during the capture period but may have")
            print(f"      continued beyond the capture window or on different interfaces")
        elif session_type == "bye_only":
            print(f"   ℹ️  This call was already in progress when the capture started")
            print(f"      and we only captured its termination")


def extract_and_analyze_call_tracking(sip_json_data: str) -> Tuple[Dict[str, CallSession], Dict[str, Any]]:
    """
    Main function to extract and analyze call tracking from SIP data.
    
    Args:
        sip_json_data: JSON string from tshark SIP extraction
        
    Returns:
        Tuple of (call_sessions, analysis_results)
    """
    # Parse SIP events
    events = parse_sip_events_from_json(sip_json_data)
    
    # Track call sessions
    sessions = track_call_sessions(events)
    
    # Analyze patterns
    analysis = analyze_call_patterns(sessions)
    
    return sessions, analysis
