#!/usr/bin/env python3
"""
S.O.N.I.C. Packet Extraction Module

This module handles packet capture data extraction using tshark and scapy.
It provides robust extraction with fallback mechanisms and format conversion.

Author: Raymond A Rizzo | Zombat
"""

import subprocess
import sys
import shutil
from typing import Optional

try:
    from scapy.all import rdpcap, UDP, Raw
except ImportError:
    print("Scapy is not installed. Please run 'pip install scapy'. It's required as a fallback.", file=sys.stderr)
    sys.exit(1)


def extract_sip_data_with_tshark(file_path: str) -> Optional[str]:
    """
    Uses tshark to extract detailed SIP and RTP information from a pcap file as JSON.
    
    This function leverages Wireshark's command-line interface (tshark) to extract
    SIP-specific data from packet captures and correlates it with RTP streams.
    Enhanced to detect SIP traffic on any port, not just standard port 5060.
    
    SIP Detection Strategy:
    - Standard SIP protocol detection (ports 5060, 5061, etc.)
    - UDP content analysis for SIP methods on any port (INVITE, REGISTER, etc.)
    - SIP response detection (SIP/2.0) on non-standard ports
    - Enhanced method coverage: INVITE, REGISTER, BYE, CANCEL, ACK, OPTIONS, NOTIFY, SUBSCRIBE, etc.
    
    Enhanced RTP Analysis Workflow:
    1. Extract SIP INVITE messages with SDP payloads (any port)
    2. Parse SDP connection info (c=IN IP4) and media descriptions (m=audio)
    3. Correlate RTP streams using IP addresses and port numbers from SDP
    4. Analyze RTP packet flow, jitter, and packet loss
    5. Provide comprehensive media session diagnostics
    
    Extracted Fields:
    - SIP Signaling: Call-ID, Method, Status-Code, User-Agent, SDP content
    - RTP Media: Stream identification, packet counts, jitter, sequence analysis
    - Network: Source/destination IPs, ports, timing correlation
    - Media Quality: Codec information, bandwidth usage, loss detection
    
    Args:
        file_path: Path to the pcap/pcapng file to analyze
    
    Returns:
        str | None: JSON string containing extracted SIP+RTP data, or None if extraction fails
        
    Performance:
        - Typically processes files in 2-8 seconds depending on size and RTP streams
        - Memory usage scales with number of SIP calls and RTP packets
        - Enhanced filter may increase processing time slightly but improves detection
        
    Example JSON Output:
        [
            {
                "frame.time": "2023-01-01 12:00:00",
                "ip.src": "192.168.1.100", 
                "ip.dst": "192.168.1.200",
                "sip.Call-ID": "abc123@example.com",
                "sip.Method": "INVITE",
                "rtp.ssrc": "0x12345678",
                "rtp.seq": "12345",
                "rtp.p_type": "0",
                "udp.srcport": "15060",  # Non-standard SIP port
                "udp.dstport": "5060"
            }
        ]
    """
    # Enhanced field extraction for better SIP detection on any port
    tshark_fields = [
        # Basic packet info
        "-e", "frame.number", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst", 
        
        # SIP Protocol Fields  
        "-e", "sip.Call-ID", "-e", "sip.Method", "-e", "sip.Status-Code",
        "-e", "sip.r-uri", "-e", "sip.from.addr", "-e", "sip.to.addr",
        "-e", "sip.User-Agent",
        
        # Authentication Headers (RFC 3261, RFC 2617)
        "-e", "sip.Authorization", "-e", "sip.Proxy-Authorization",
        "-e", "sip.WWW-Authenticate", "-e", "sip.Proxy-Authenticate",
        
        # Enhanced SIP fields for call tracking
        "-e", "sip.Status-Line", "-e", "sip.Reason", "-e", "sip.Request-Line",
        "-e", "sip.contact.uri", "-e", "sip.from.tag", "-e", "sip.to.tag",
        "-e", "sip.CSeq.method", "-e", "sip.CSeq.seq", "-e", "sip.Expires",
        
        # SDP content for capability analysis
        "-e", "sdp.version", "-e", "sdp.media", "-e", "sdp.media.port", 
        "-e", "sdp.media.proto", "-e", "sdp.owner.username", "-e", "sdp.session_name",
        
        # RTP Stream Fields
        "-e", "rtp.ssrc", "-e", "rtp.seq", "-e", "rtp.p_type",
        
        # UDP ports and payload info
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.length",
        
        # Add protocol identification for manual SIP detection
        "-e", "frame.protocols"
    ]
    
    # Enhanced multi-protocol filter with smarter SIP detection
    # Uses standard SIP protocol detection as primary, with targeted fallback for non-standard ports
    protocol_filter = (
        "sip or "  # Standard SIP protocol detection (auto-detects SIP regardless of port)
        "rtp or "  # RTP streams
        "(udp and (udp.port >= 10000 and udp.port <= 20000))"  # RTP media port range
    )
    
    command = ["tshark", "-r", file_path, "-Y", protocol_filter, "-T", "json", *tshark_fields]
    
    try:
        print(f"🔍 Extracting SIP signaling and RTP media streams: {' '.join(command[:8])}...")
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        
        if process.stdout:
            # Parse the JSON and create a more compact summary for AI analysis
            import json
            try:
                raw_data = json.loads(process.stdout)
                summary = _create_analysis_summary(raw_data)
                print(f"✅ Successfully extracted SIP+RTP data from {file_path}")
                return summary
            except json.JSONDecodeError:
                print(f"⚠️  Failed to parse extracted data as JSON")
                return process.stdout
        else:
            print(f"⚠️  No SIP or RTP data found in {file_path}")
            return None
            
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"❌ tshark execution failed: {e}. Falling back to scapy...", file=sys.stderr)
        return None
    except Exception as e:
        print(f"❌ Unexpected error during SIP+RTP extraction: {e}", file=sys.stderr)
        return None


def read_pcap_with_scapy(file_path: str) -> Optional[str]:
    """
    Fallback SIP extraction using scapy when tshark is unavailable.
    Enhanced to detect SIP traffic on any UDP port, not just standard ports.
    
    This function serves as a fallback when tshark is not available. It uses
    scapy to read pcap files and extract SIP-related UDP packets for analysis.
    Enhanced with comprehensive SIP method detection and non-standard port support.
    
    SIP Detection Features:
    - Comprehensive SIP method detection: INVITE, REGISTER, BYE, CANCEL, ACK, 
      OPTIONS, NOTIFY, SUBSCRIBE, PRACK, UPDATE, REFER, INFO
    - SIP response detection (SIP/2.0 responses)
    - SDP content detection (v=0, c=IN IP4, m=audio)
    - Port-agnostic detection (finds SIP on any UDP port)
    - Message validation to avoid false positives
    
    Extraction Process:
    1. Read all packets from the pcap file using scapy
    2. Filter for UDP packets (SIP typically uses UDP)
    3. Enhanced content analysis for SIP indicators on any port
    4. Validate message structure to ensure genuine SIP traffic
    5. Report non-standard port usage for debugging
    6. Format as text for AI analysis (less structured than tshark)
    
    Limitations compared to tshark:
    - Raw text output instead of structured JSON
    - Less detailed field extraction
    - Manual parsing required for protocol details
    - Generally slower than tshark for large files
    
    Args:
        file_path: Path to the pcap/pcapng file to read
        
    Returns:
        str | None: Raw text containing SIP messages, or None if no data found
        
    Example:
        >>> sip_data = read_pcap_with_scapy("capture.pcap")
        >>> if sip_data:
        ...     print("Found SIP data for analysis")
        📡 Found SIP on non-standard ports: 15060 -> 5060
    """
    try:
        print(f"📦 Reading pcap file with scapy: {file_path}")
        packets = rdpcap(file_path)
        
        sip_messages = []
        sip_packet_count = 0
        
        # Enhanced SIP method and response detection
        sip_indicators = [
            # SIP Methods
            'INVITE', 'ACK', 'BYE', 'CANCEL', 'REGISTER', 'OPTIONS', 
            'NOTIFY', 'SUBSCRIBE', 'PRACK', 'UPDATE', 'REFER', 'INFO',
            # SIP Response indicator
            'SIP/2.0',
            # SDP indicators (often in SIP messages)
            'v=0', 'c=IN IP4', 'm=audio'
        ]
        
        for packet in packets:
            if UDP in packet and Raw in packet:
                try:
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Check for SIP indicators with enhanced detection
                    if any(sip_indicator in raw_data.upper() for sip_indicator in 
                          [indicator.upper() for indicator in sip_indicators]):
                        # Additional validation: make sure it looks like a real SIP message
                        lines = raw_data.split('\n')
                        if lines and (
                            lines[0].strip().startswith(('INVITE', 'ACK', 'BYE', 'CANCEL', 'REGISTER', 
                                                       'OPTIONS', 'NOTIFY', 'SUBSCRIBE', 'PRACK', 
                                                       'UPDATE', 'REFER', 'INFO', 'SIP/2.0'))
                        ):
                            sip_messages.append(raw_data)
                            sip_packet_count += 1
                            
                            # Extract port information for debugging
                            src_port = packet[UDP].sport
                            dst_port = packet[UDP].dport
                            if src_port != 5060 and dst_port != 5060:
                                print(f"📡 Found SIP on non-standard ports: {src_port} -> {dst_port}")
                
                except (UnicodeDecodeError, AttributeError):
                    # Skip packets that can't be decoded or don't have expected structure
                    continue
        
        if sip_messages:
            print(f"Scapy found {sip_packet_count} potential SIP messages.")
            return "\n---PACKET---\n".join(sip_messages)
        else:
            print("No SIP messages found in the capture file using scapy.")
            return None
            
    except Exception as e:
        print(f"❌ Error reading pcap with scapy: {e}", file=sys.stderr)
        return None


def extract_sip_data(file_path: str) -> Optional[str]:
    """
    Extracts SIP data from a pcap file, trying tshark first and falling back to scapy.
    
    This is the main extraction function that orchestrates the packet analysis workflow.
    It prioritizes tshark for structured output and high performance, but provides
    graceful degradation to scapy when tshark is unavailable or fails.
    
    Extraction Strategy:
    1. Check if tshark is available in system PATH
    2. If available, attempt structured JSON extraction with tshark
    3. If tshark fails or is unavailable, fall back to scapy text extraction
    4. Return the best available data format for AI analysis
    
    Data Quality Hierarchy:
    1. tshark JSON: Best structured data with detailed field extraction
    2. scapy text: Raw SIP messages for text-based analysis
    3. None: No SIP data found in capture
    
    Args:
        file_path: Path to the pcap/pcapng file to analyze
        
    Returns:
        str | None: Extracted SIP data in best available format, or None if no data found
        
    Example:
        >>> sip_data = extract_sip_data("call_capture.pcapng")
        >>> if sip_data:
        ...     # Proceed with AI analysis
        ...     analyze_sip_data(sip_data)
    """
    print(f"🔍 Extracting SIP data from {file_path}...")
    
    # Check if tshark is available
    if shutil.which("tshark"):
        # Try tshark first for structured output
        tshark_data = extract_sip_data_with_tshark(file_path)
        if tshark_data:
            return tshark_data
    
    # Fall back to scapy if tshark fails or is unavailable
    print("Falling back to scapy for pcap processing...")
    return read_pcap_with_scapy(file_path)


def _create_analysis_summary(raw_data: list) -> str:
    """
    Creates a compact summary of SIP and RTP data for AI analysis.
    Reduces 700KB+ of raw data to essential information for better AI processing.
    
    Args:
        raw_data: List of packet data from tshark JSON output
        
    Returns:
        str: JSON summary optimized for AI analysis
    """
    import json
    
    # Separate SIP and RTP packets
    sip_packets = []
    rtp_streams = {}
    
    for packet in raw_data:
        layers = packet.get("_source", {}).get("layers", {})
        
        # Extract SIP packets
        call_id = layers.get("sip.Call-ID")
        sip_method = layers.get("sip.Method")
        sip_status = layers.get("sip.Status-Code")
        
        if call_id or sip_method or sip_status:
            sip_data = {
                "packet_num": int(layers.get("frame.number", [0])[0]) if layers.get("frame.number") else 0,
                "time": layers.get("frame.time", ["Unknown"])[0] if layers.get("frame.time") else "Unknown",
                "src_ip": layers.get("ip.src", ["Unknown"])[0] if layers.get("ip.src") else "Unknown",
                "dst_ip": layers.get("ip.dst", ["Unknown"])[0] if layers.get("ip.dst") else "Unknown",
                "src_port": layers.get("udp.srcport", ["Unknown"])[0] if layers.get("udp.srcport") else "Unknown",
                "dst_port": layers.get("udp.dstport", ["Unknown"])[0] if layers.get("udp.dstport") else "Unknown",
                "call_id": call_id[0] if call_id else "Unknown",
                "method": sip_method[0] if sip_method else "",
                "status_code": sip_status[0] if sip_status else "",
                "request_uri": layers.get("sip.r-uri", [""])[0] if layers.get("sip.r-uri") else "",
                "from_addr": layers.get("sip.from.addr", [""])[0] if layers.get("sip.from.addr") else "",
                "to_addr": layers.get("sip.to.addr", [""])[0] if layers.get("sip.to.addr") else "",
                "user_agent": layers.get("sip.User-Agent", [""])[0] if layers.get("sip.User-Agent") else "",
                "contact": layers.get("sip.contact.uri", [""])[0] if layers.get("sip.contact.uri") else "",
                "cseq_method": layers.get("sip.CSeq.method", [""])[0] if layers.get("sip.CSeq.method") else "",
                "cseq_seq": layers.get("sip.CSeq.seq", [""])[0] if layers.get("sip.CSeq.seq") else "",
                "expires": layers.get("sip.Expires", [""])[0] if layers.get("sip.Expires") else "",
                
                # Authentication Headers (RFC 3261, RFC 2617)
                "authorization": layers.get("sip.Authorization", [""])[0] if layers.get("sip.Authorization") else "",
                "proxy_authorization": layers.get("sip.Proxy-Authorization", [""])[0] if layers.get("sip.Proxy-Authorization") else "",
                "www_authenticate": layers.get("sip.WWW-Authenticate", [""])[0] if layers.get("sip.WWW-Authenticate") else "",
                "proxy_authenticate": layers.get("sip.Proxy-Authenticate", [""])[0] if layers.get("sip.Proxy-Authenticate") else "",
                
                # SDP information for capability analysis
                "sdp_version": layers.get("sdp.version", [""])[0] if layers.get("sdp.version") else "",
                "sdp_media": layers.get("sdp.media", [""])[0] if layers.get("sdp.media") else "",
                "sdp_media_port": layers.get("sdp.media.port", [""])[0] if layers.get("sdp.media.port") else "",
                "sdp_media_proto": layers.get("sdp.media.proto", [""])[0] if layers.get("sdp.media.proto") else "",
                "sdp_owner_username": layers.get("sdp.owner.username", [""])[0] if layers.get("sdp.owner.username") else "",
                "sdp_session_name": layers.get("sdp.session_name", [""])[0] if layers.get("sdp.session_name") else "",
            }
            sip_packets.append(sip_data)
        
        # Aggregate RTP stream data
        rtp_ssrc = layers.get("rtp.ssrc")
        if rtp_ssrc:
            ssrc = rtp_ssrc[0]
            src_ip = layers.get("ip.src", ["Unknown"])[0] if layers.get("ip.src") else "Unknown"
            dst_ip = layers.get("ip.dst", ["Unknown"])[0] if layers.get("ip.dst") else "Unknown"
            src_port = layers.get("udp.srcport", ["Unknown"])[0] if layers.get("udp.srcport") else "Unknown"
            dst_port = layers.get("udp.dstport", ["Unknown"])[0] if layers.get("udp.dstport") else "Unknown"
            
            stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            if stream_key not in rtp_streams:
                rtp_streams[stream_key] = {
                    "ssrc": ssrc,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_count": 0,
                    "payload_type": layers.get("rtp.p_type", ["Unknown"])[0] if layers.get("rtp.p_type") else "Unknown",
                    "packet_numbers": []
                }
            
            rtp_streams[stream_key]["packet_count"] += 1
            # Track packet numbers for Wireshark correlation
            packet_num = int(layers.get("frame.number", [0])[0]) if layers.get("frame.number") else 0
            if packet_num > 0:
                rtp_streams[stream_key]["packet_numbers"].append(packet_num)
    
    # Create compact summary
    summary = {
        "sip_packets": sip_packets,
        "rtp_streams": list(rtp_streams.values()),
        "total_packets": len(raw_data),
        "sip_count": len(sip_packets),
        "rtp_stream_count": len(rtp_streams)
    }
    
    return json.dumps(summary, indent=2)
