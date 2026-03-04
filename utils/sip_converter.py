#!/usr/bin/env python3
"""
S.O.N.I.C. SIP Data Converter

Converts raw SIP text data from scapy into structured format for call tracking analysis.

Author: Raymond A Rizzo | Zombat
"""

import re
from typing import Dict, List, Any
import json


def parse_scapy_sip_text(sip_text: str) -> Dict[str, Any]:
    """
    Parse raw SIP text data from scapy into structured format for call tracking.
    
    Args:
        sip_text: Raw SIP text messages separated by ---PACKET--- markers
        
    Returns:
        Structured dictionary with SIP packet data
    """
    structured_data = {
        "sip_packets": [],
        "total_packets": 0
    }
    
    if not sip_text:
        return structured_data
    
    # Split by packet markers
    packets = sip_text.split("---PACKET---")
    packet_number = 1
    
    for packet_text in packets:
        if not packet_text.strip():
            continue
            
        # Extract SIP information from the raw text
        packet_info = extract_sip_info_from_text(packet_text, packet_number)
        if packet_info:
            structured_data["sip_packets"].append(packet_info)
            packet_number += 1
    
    structured_data["total_packets"] = len(structured_data["sip_packets"])
    return structured_data


def extract_sip_info_from_text(packet_text: str, frame_number: int) -> Dict[str, Any]:
    """
    Extract SIP information from a single packet's text.
    
    Args:
        packet_text: Raw text of a single SIP packet
        frame_number: Sequential frame number
        
    Returns:
        Dictionary with extracted SIP information
    """
    lines = packet_text.strip().split('\n')
    if not lines:
        return None
    
    # Initialize packet info
    packet_info = {
        "frame.number": str(frame_number),
        "frame.time": "Unknown",
        "src_ip": "Unknown",
        "dst_ip": "Unknown", 
        "src_port": "Unknown",
        "dst_port": "Unknown"
    }
    
    # Parse the first line to determine if it's a request or response
    first_line = lines[0].strip()
    
    if first_line.startswith(('INVITE', 'BYE', 'ACK', 'CANCEL', 'REGISTER', 'OPTIONS', 'NOTIFY', 'SUBSCRIBE')):
        # SIP Request
        method_match = re.match(r'^(\w+)\s+(.+?)\s+SIP/2\.0', first_line)
        if method_match:
            packet_info["method"] = method_match.group(1)
            packet_info["request_uri"] = method_match.group(2)
    
    elif first_line.startswith('SIP/2.0'):
        # SIP Response
        response_match = re.match(r'^SIP/2\.0\s+(\d+)\s+(.+)', first_line)
        if response_match:
            packet_info["status_code"] = response_match.group(1)
            packet_info["reason_phrase"] = response_match.group(2)
    
    # Parse headers
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
            
        # Call-ID header
        if line.lower().startswith('call-id:'):
            packet_info["call_id"] = line.split(':', 1)[1].strip()
        
        # From header (extract IP if possible)
        elif line.lower().startswith('from:'):
            from_header = line.split(':', 1)[1].strip()
            ip_match = re.search(r'@(\d+\.\d+\.\d+\.\d+)', from_header)
            if ip_match and packet_info["src_ip"] == "Unknown":
                packet_info["src_ip"] = ip_match.group(1)
        
        # To header (extract IP if possible)
        elif line.lower().startswith('to:'):
            to_header = line.split(':', 1)[1].strip()
            ip_match = re.search(r'@(\d+\.\d+\.\d+\.\d+)', to_header)
            if ip_match and packet_info["dst_ip"] == "Unknown":
                packet_info["dst_ip"] = ip_match.group(1)
        
        # Contact header (extract IP if possible)
        elif line.lower().startswith('contact:'):
            contact_header = line.split(':', 1)[1].strip()
            ip_match = re.search(r'@(\d+\.\d+\.\d+\.\d+)', contact_header)
            if ip_match:
                # Use contact IP as more specific endpoint info
                if packet_info.get("method") in ["INVITE", "REGISTER"]:
                    packet_info["src_ip"] = ip_match.group(1)
        
        # Via header (extract source IP and port)
        elif line.lower().startswith('via:'):
            via_header = line.split(':', 1)[1].strip()
            # Look for IP:port pattern
            ip_port_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', via_header)
            if ip_port_match and packet_info["src_ip"] == "Unknown":
                packet_info["src_ip"] = ip_port_match.group(1)
                packet_info["src_port"] = ip_port_match.group(2)
        
        # User-Agent header
        elif line.lower().startswith('user-agent:'):
            packet_info["user_agent"] = line.split(':', 1)[1].strip()
    
    # Try to extract IPs from SIP URI patterns if still unknown
    if packet_info["src_ip"] == "Unknown" or packet_info["dst_ip"] == "Unknown":
        for line in lines:
            # Look for sip: URIs with IP addresses
            sip_uri_matches = re.findall(r'sip:.*?@(\d+\.\d+\.\d+\.\d+)', line)
            if sip_uri_matches:
                if packet_info["dst_ip"] == "Unknown":
                    packet_info["dst_ip"] = sip_uri_matches[0]
                if len(sip_uri_matches) > 1 and packet_info["src_ip"] == "Unknown":
                    packet_info["src_ip"] = sip_uri_matches[1]
    
    # Set default ports if not found
    if packet_info["src_port"] == "Unknown":
        packet_info["src_port"] = "5060"
    if packet_info["dst_port"] == "Unknown":
        packet_info["dst_port"] = "5060"
    
    return packet_info


def convert_sip_data_for_tracking(sip_data: str) -> str:
    """
    Convert SIP data from any format into JSON format suitable for call tracking.
    
    Args:
        sip_data: SIP data in any format (raw text, JSON, etc.)
        
    Returns:
        JSON string compatible with call tracking module
    """
    try:
        # First, try to parse as JSON (tshark format)
        json_data = json.loads(sip_data)
        # If it's already in the right format, return as-is
        return sip_data
    except (json.JSONDecodeError, TypeError):
        # If it's not JSON, assume it's raw text from scapy
        structured = parse_scapy_sip_text(sip_data)
        return json.dumps(structured)


def test_scapy_parser():
    """Test the scapy text parser with sample data"""
    sample_text = """INVITE sip:Overlap_sending@sipserver SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnec17076c10000
From: <sip:4001@192.0.2.1>;tag=NEC17076c10000
To: <sip:Overlap_sending@sipserver>
Call-ID: 4001@192.0.2.1
CSeq: 1 INVITE
Contact: <sip:4001@192.0.2.1:5060>
User-Agent: Test Phone
Content-Type: application/sdp

---PACKET---

BYE sip:4001@192.0.2.1:5060 SIP/2.0
Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKnec17077c20000
From: <sip:Overlap_sending@sipserver>;tag=NEC17077c20000
To: <sip:4001@192.0.2.1>;tag=NEC17076c10000
Call-ID: 4001@192.0.2.1
CSeq: 2 BYE
Contact: <sip:Overlap_sending@198.51.100.1:5060>
User-Agent: Test Server"""
    
    result = parse_scapy_sip_text(sample_text)
    print("📋 Parsed SIP data:")
    print(json.dumps(result, indent=2))
    
    return result


if __name__ == "__main__":
    print("🧪 Testing SIP Data Converter")
    print("=" * 50)
    test_scapy_parser()
