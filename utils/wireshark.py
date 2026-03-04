#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Wireshark Integration Module

Handles Wireshark filter generation and correlation of SIP/RTP packets.

Author: Raymond A Rizzo | Zombat
Version: 3.0 (Modular Architecture)
Last Updated: 2025-07-15
"""

import sys
import json
from typing import Dict, Any


def get_codec_name_from_payload_type(payload_type) -> str:
    """
    Maps RTP payload types to codec names for filter descriptions.
    
    Args:
        payload_type: RTP payload type number as string or int
        
    Returns:
        str: Human-readable codec name with technical details
    """
    # Convert to string for consistent mapping
    pt_str = str(payload_type)
    
    payload_map = {
        "0": "PCMU (G.711 μ-law)",
        "8": "PCMA (G.711 A-law)",
        "9": "G.722",
        "18": "G.729",
        "96": "Dynamic (often Opus)",
        "97": "Dynamic (often iLBC)",
        "98": "Dynamic (often Speex)",
        "99": "Dynamic (often H.264)",
        "101": "DTMF/Telephone-Event (RFC 4733)"
    }
    return payload_map.get(pt_str, f"Unknown (PT {pt_str})")


def print_wireshark_details(call: Dict[str, Any], sip_data: str) -> None:
    """
    Prints Wireshark correlation details including packet numbers and filters.
    
    Args:
        call: Call diagnostic data
        sip_data: Raw SIP data for packet correlation
    """
    try:
        # Parse the SIP data to get packet information
        data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
        
        call_id = call.get('callId', '')
        caller_ip = call.get('callerIp', '')
        callee_ip = call.get('calleeIp', '')
        
        # Find SIP packets and RTP streams
        sip_packets = []
        rtp_packet_ranges = []
        
        if isinstance(data, dict):
            # Get all SIP packets since AI analysis may not have specific call correlation
            all_sip_packets = data.get('sip_packets', [])
            all_rtp_streams = data.get('rtp_streams', [])
            
            # If we have specific IPs from AI analysis, filter by them
            if caller_ip != 'Unknown' and callee_ip != 'Unknown':
                for packet in all_sip_packets:
                    if (packet.get('src_ip') in [caller_ip, callee_ip] and 
                        packet.get('dst_ip') in [caller_ip, callee_ip]):
                        sip_packets.append(packet)
                
                for stream in all_rtp_streams:
                    if (stream.get('src_ip') in [caller_ip, callee_ip] and 
                        stream.get('dst_ip') in [caller_ip, callee_ip]):
                        packet_nums = stream.get('packet_numbers', [])
                        if packet_nums:
                            rtp_packet_ranges.append({
                                'stream': f"{stream.get('src_ip')}:{stream.get('src_port')} → {stream.get('dst_ip')}:{stream.get('dst_port')}",
                                'packets': packet_nums,
                                'payload_type': stream.get('payload_type', 'Unknown')
                            })
            else:
                # If AI analysis didn't provide specific IPs, show all available data
                sip_packets = all_sip_packets[:10]  # Show first 10 SIP packets
                for stream in all_rtp_streams[:3]:  # Show first 3 RTP streams
                    packet_nums = stream.get('packet_numbers', [])
                    if packet_nums:
                        rtp_packet_ranges.append({
                            'stream': f"{stream.get('src_ip')}:{stream.get('src_port')} → {stream.get('dst_ip')}:{stream.get('dst_port')}",
                            'packets': packet_nums,
                            'payload_type': stream.get('payload_type', 'Unknown')
                        })
        
        if sip_packets or rtp_packet_ranges:
            print(f"   📡 Wireshark Investigation:")
            sys.stdout.flush()  # Force output flush
            
            # SIP packet details
            if sip_packets:
                print(f"      🔍 SIP Signaling:")
                for i, packet in enumerate(sip_packets[:5], 1):  # Show first 5
                    packet_num = packet.get('packet_num', 0)
                    method = packet.get('method', '')
                    status = packet.get('status_code', '')
                    src = f"{packet.get('src_ip', '')}:{packet.get('src_port', '')}"
                    dst = f"{packet.get('dst_ip', '')}:{packet.get('dst_port', '')}"
                    
                    if method:
                        print(f"         Packet #{packet_num}: {method} - {src} → {dst}")
                    elif status:
                        print(f"         Packet #{packet_num}: {status} Response - {src} → {dst}")
                    else:
                        print(f"         Packet #{packet_num}: SIP - {src} → {dst}")
                
                # Generate SIP filters
                if call_id and call_id != 'Unknown' and 'nlp-extracted' not in call_id:
                    print(f"      📋 Call ID Filter: sip.Call-ID == \"{call_id}\"")
                
                # Get unique IPs from SIP packets for filtering
                sip_ips = set()
                for packet in sip_packets:
                    sip_ips.add(packet.get('src_ip', ''))
                    sip_ips.add(packet.get('dst_ip', ''))
                sip_ips.discard('')
                sip_ips.discard('Unknown')
                
                if len(sip_ips) >= 2:
                    ip_list = list(sip_ips)[:2]
                    print(f"      📋 SIP Filter: sip and (ip.addr == {ip_list[0]} and ip.addr == {ip_list[1]})")
            
            # RTP stream details
            if rtp_packet_ranges:
                print(f"      🎵 RTP Media Streams:")
                for i, stream_info in enumerate(rtp_packet_ranges, 1):
                    packets = stream_info['packets']
                    if packets:
                        packet_range = f"{min(packets)}-{max(packets)}" if len(packets) > 1 else str(packets[0])
                        print(f"         Stream {i}: {stream_info['stream']}")
                        print(f"         Packets: #{packet_range} ({len(packets)} total)")
                        payload_type = stream_info['payload_type']
                        codec_name = get_codec_name_from_payload_type(payload_type)
                        print(f"         Codec: {codec_name}")
                        
                        # Generate RTP filter for this stream
                        stream_parts = stream_info['stream'].split(' → ')
                        if len(stream_parts) == 2:
                            src_part = stream_parts[0].split(':')
                            dst_part = stream_parts[1].split(':')
                            if len(src_part) == 2 and len(dst_part) == 2:
                                src_ip, src_port = src_part
                                dst_ip, dst_port = dst_part
                                rtp_filter = f"rtp and ip.src == {src_ip} and ip.dst == {dst_ip} and udp.srcport == {src_port} and udp.dstport == {dst_port}"
                                print(f"         📋 Filter: {rtp_filter}")
            
            # Combined filter for complete call analysis
            all_ips = set()
            for packet in sip_packets:
                all_ips.add(packet.get('src_ip', ''))
                all_ips.add(packet.get('dst_ip', ''))
            for stream_info in rtp_packet_ranges:
                stream_parts = stream_info['stream'].split(' → ')
                for part in stream_parts:
                    ip = part.split(':')[0]
                    all_ips.add(ip)
            all_ips.discard('')
            all_ips.discard('Unknown')
            
            if len(all_ips) >= 2:
                ip_list = list(all_ips)[:2]
                combined_filter = f"(sip or rtp) and (ip.addr == {ip_list[0]} and ip.addr == {ip_list[1]})"
                print(f"      📋 Complete Call Filter: {combined_filter}")
                
    except Exception as e:
        print(f"      ℹ️  Wireshark correlation data not available: {e}")


def print_wireshark_summary(sip_data: str) -> None:
    """
    Prints a summary of Wireshark investigation details.
    
    Args:
        sip_data: Raw SIP data for analysis
    """
    try:
        data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
        
        if isinstance(data, dict):
            total_packets = data.get('total_packets', 0)
            sip_count = data.get('sip_count', 0)
            rtp_stream_count = data.get('rtp_stream_count', 0)
            
            print(f"\n🔬 Wireshark Analysis Summary:")
            print(f"   📊 Total packets analyzed: {total_packets}")
            print(f"   📞 SIP signaling packets: {sip_count}")
            print(f"   🎵 RTP media streams: {rtp_stream_count}")
            
            # Get unique IPs for broader analysis
            unique_ips = set()
            if 'sip_packets' in data:
                for packet in data['sip_packets']:
                    src_ip = packet.get('src_ip')
                    dst_ip = packet.get('dst_ip')
                    if src_ip and src_ip != 'Unknown':
                        unique_ips.add(src_ip)
                    if dst_ip and dst_ip != 'Unknown':
                        unique_ips.add(dst_ip)
            
            if 'rtp_streams' in data:
                for stream in data['rtp_streams']:
                    src_ip = stream.get('src_ip')
                    dst_ip = stream.get('dst_ip')
                    if src_ip and src_ip != 'Unknown':
                        unique_ips.add(src_ip)
                    if dst_ip and dst_ip != 'Unknown':
                        unique_ips.add(dst_ip)
            
            if unique_ips:
                print(f"   🌐 IP addresses involved: {', '.join(sorted(unique_ips))}")
                
                # Provide useful Wireshark filters
                print(f"\n📋 Useful Wireshark Filters:")
                print(f"   • All SIP traffic: sip")
                print(f"   • All RTP traffic: rtp")
                print(f"   • All VoIP traffic: sip or rtp")
                
                if len(unique_ips) >= 2:
                    ip_list = list(unique_ips)
                    print(f"   • Traffic between endpoints: ip.addr == {ip_list[0]} and ip.addr == {ip_list[1]}")
                
                # Codec-specific filters
                payload_types = set()
                
                # Get payload types from RTP streams (actual usage)
                if 'rtp_streams' in data:
                    for stream in data['rtp_streams']:
                        pt = stream.get('payload_type')
                        if pt and pt != 'Unknown':
                            payload_types.add(pt)
                
                # Get payload types from SDP offers (advertised capabilities)
                if 'sip_packets' in data:
                    for packet in data['sip_packets']:
                        sdp_media = packet.get('sdp_media', '')
                        if sdp_media and 'RTP/AVP' in sdp_media:
                            # Extract payload types from SDP media line
                            # e.g., "audio 49198 RTP/AVP 0 101" -> [0, 101]
                            parts = sdp_media.split('RTP/AVP')
                            if len(parts) > 1:
                                pts = parts[1].strip().split()
                                for pt in pts:
                                    if pt.isdigit():
                                        payload_types.add(pt)
                
                if payload_types:
                    print(f"   • Codec analysis:")
                    for pt in sorted(payload_types, key=int):
                        codec_name = get_codec_name_from_payload_type(pt)
                        print(f"     - {codec_name}: rtp.p_type == {pt}")
                            
    except Exception as e:
        print(f"   ℹ️  Wireshark summary not available: {e}")
