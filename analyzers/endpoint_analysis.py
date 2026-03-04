#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Endpoint Analysis Module

Analyzes SIP endpoints to determine capabilities, roles, and configurations.

Author: Raymond A Rizzo | Zombat
Version: 3.0 (Modular Architecture)
Last Updated: 2025-07-15
"""

import json
import re
from typing import Dict, Any, Set
from utils.wireshark import get_codec_name_from_payload_type
from extractors.auth_info import extract_auth_and_registration_info


def analyze_sdp_media_line(media_line: str) -> Dict[str, Any]:
    """
    Analyzes an SDP media line to extract detailed codec and capability information.
    
    Args:
        media_line: SDP media line (e.g., "audio 49198 RTP/AVP 0 101")
        
    Returns:
        Dict containing detailed analysis of the media line
    """
    analysis = {
        'media_type': None,
        'port': None,
        'protocol': None,
        'payload_types': [],
        'audio_codecs': [],
        'dtmf_support': False,
        'dynamic_payloads': [],
        'explanation': []
    }
    
    if not media_line or not media_line.strip():
        return analysis
        
    # Parse the media line: m=audio 49198 RTP/AVP 0 101
    parts = media_line.replace('m=', '').strip().split()
    
    if len(parts) >= 4:
        analysis['media_type'] = parts[0]  # audio
        analysis['port'] = parts[1]        # 49198
        analysis['protocol'] = parts[2]    # RTP/AVP
        analysis['payload_types'] = parts[3:]  # [0, 101]
        
        # Analyze each payload type
        for pt in analysis['payload_types']:
            codec_name = get_codec_name_from_payload_type(pt)
            
            if pt == '101':
                analysis['dtmf_support'] = True
                analysis['explanation'].append(
                    f"Payload type 101: DTMF/Telephone-Event support (RFC 4733). "
                    f"DTMF tones will be sent out-of-band as separate RTP packets, "
                    f"not as in-band audio tones."
                )
            elif pt in ['0', '8', '9', '18']:  # Standard audio codecs
                analysis['audio_codecs'].append(codec_name)
                analysis['explanation'].append(f"Payload type {pt}: {codec_name} audio codec")
            elif int(pt) >= 96:  # Dynamic payload types
                analysis['dynamic_payloads'].append(pt)
                analysis['explanation'].append(f"Payload type {pt}: {codec_name} (dynamic assignment)")
            else:
                analysis['explanation'].append(f"Payload type {pt}: {codec_name}")
    
    return analysis


def print_endpoint_analysis(sip_data: str, file_path: str = None) -> None:
    """
    Analyzes and displays detailed information about each endpoint in the call.
    
    This function examines SIP signaling to identify endpoint capabilities,
    SDP offers, User-Agent information, advertised features, and authentication details.
    
    Args:
        sip_data: Raw SIP data containing packet information
        file_path: Optional path to pcap file for enhanced auth extraction
    """
    try:
        data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
        
        if not isinstance(data, dict) or 'sip_packets' not in data:
            print("   ℹ️  No SIP packet data available for endpoint analysis")
            return
            
        sip_packets = data.get('sip_packets', [])
        rtp_streams = data.get('rtp_streams', [])
        
        if not sip_packets:
            print("   ℹ️  No SIP packets found for endpoint analysis")
            return
            
        print(f"\n🖥️  Endpoint Analysis")
        print("=" * 60)
        
        # Extract enhanced authentication info if file path provided
        auth_info = {}
        if file_path:
            auth_info = extract_auth_and_registration_info(file_path)
        
        # Build endpoint profiles
        endpoints = {}
        
        # Also add endpoints from authentication challenges (important for registrars)
        if auth_info and 'auth_challenges' in auth_info:
            for challenge in auth_info['auth_challenges']:
                # Add destination endpoint (the one receiving the auth challenge)
                dst_ip = challenge['dst_ip']
                if dst_ip not in endpoints:
                    endpoints[dst_ip] = {
                        'ip': dst_ip,
                        'sip_addresses': set(),
                        'methods_sent': set(),
                        'status_codes_sent': set(),
                        'sdp_offers': [],
                        'user_agents': set(),
                        'codecs_offered': set(),
                        'role': 'registration_client',  # These are trying to register
                        'auth_realms': set(),
                        'auth_challenges': [],
                        'register_info': []
                    }
                # Add realm info
                if challenge['realm']:
                    endpoints[dst_ip]['auth_realms'].add(challenge['realm'])
        
        for packet in sip_packets:
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            from_addr = packet.get('from_addr', '')
            to_addr = packet.get('to_addr', '')
            
            # Process source endpoint
            if src_ip and src_ip != 'Unknown':
                if src_ip not in endpoints:
                    endpoints[src_ip] = {
                        'ip': src_ip,
                        'sip_addresses': set(),
                        'methods_sent': set(),
                        'status_codes_sent': set(),
                        'sdp_offers': [],
                        'user_agents': set(),
                        'codecs_offered': set(),
                        'role': 'unknown',
                        'auth_realms': set(),
                        'auth_challenges': [],
                        'register_info': []
                    }
                
                # Collect SIP addresses (only from packets this endpoint sends)
                if from_addr and packet.get('method'):  # Only for requests from this IP
                    endpoints[src_ip]['sip_addresses'].add(from_addr)
                
                # Track methods sent and assign roles based on SIP method patterns
                if packet.get('method'):
                    endpoints[src_ip]['methods_sent'].add(packet.get('method'))
                    
                    # Role assignment based on SIP methods
                    if packet.get('method') == 'INVITE':
                        endpoints[src_ip]['role'] = 'caller'
                    elif packet.get('method') == 'REGISTER':
                        endpoints[src_ip]['role'] = 'registration_client'
                        
                        # Extract registration details including WWW-Authenticate info
                        reg_info = {
                            'packet_num': packet.get('packet_num', ''),
                            'method': 'REGISTER',
                            'to_addr': packet.get('to_addr', ''),
                            'from_addr': packet.get('from_addr', ''),
                            'request_uri': packet.get('request_uri', ''),
                            'user_agent': packet.get('user_agent', ''),
                            'expires': packet.get('expires', ''),
                            'contact': packet.get('contact', ''),
                            'authorization': packet.get('authorization', ''),
                            'www_authenticate': packet.get('www_authenticate', ''),
                            'timestamp': packet.get('time', '')
                        }
                        endpoints[src_ip]['register_info'].append(reg_info)
                
                # Track status codes sent by this endpoint
                if packet.get('status_code'):
                    endpoints[src_ip]['status_codes_sent'].add(packet.get('status_code'))
                    
                    # Role assignment based on response patterns
                    if packet.get('status_code') in ['100', '180', '183', '200']:
                        # Only assign callee if not already a server or registration client
                        if endpoints[src_ip]['role'] == 'unknown':
                            endpoints[src_ip]['role'] = 'callee'
                    
                    # Special handling for 401 Unauthorized (indicates SIP server/proxy)
                    if packet.get('status_code') == '401':
                        endpoints[src_ip]['role'] = 'sip_server'
                        
                        # Extract WWW-Authenticate details for troubleshooting
                        www_auth = packet.get('www_authenticate', '')
                        auth_realm = ''
                        auth_nonce = ''
                        auth_algorithm = ''
                        
                        # Parse WWW-Authenticate header
                        if www_auth:
                            realm_match = re.search(r'realm="([^"]*)"', www_auth)
                            nonce_match = re.search(r'nonce="([^"]*)"', www_auth)
                            algorithm_match = re.search(r'algorithm=([^,\s]*)', www_auth)
                            
                            auth_realm = realm_match.group(1) if realm_match else ''
                            auth_nonce = nonce_match.group(1) if nonce_match else ''
                            auth_algorithm = algorithm_match.group(1) if algorithm_match else ''
                        
                        auth_challenge = {
                            'packet_num': packet.get('packet_num', ''),
                            'method': packet.get('method', 'Unknown'),
                            'status': '401 Unauthorized',
                            'dst_ip': packet.get('dst_ip', ''),
                            'call_id': packet.get('call_id', ''),
                            'www_authenticate': www_auth,
                            'realm': auth_realm,
                            'nonce': auth_nonce,
                            'algorithm': auth_algorithm,
                            'cseq_method': packet.get('cseq_method', ''),
                            'timestamp': packet.get('time', '')
                        }
                        endpoints[src_ip]['auth_challenges'].append(auth_challenge)
                
                # Track SDP offers
                if packet.get('sdp_media'):
                    sdp_info = {
                        'media': packet.get('sdp_media', ''),
                        'port': packet.get('sdp_media_port', ''),
                        'protocol': packet.get('sdp_media_proto', ''),
                        'packet_num': packet.get('packet_num', ''),
                        'owner_username': packet.get('sdp_owner_username', ''),
                        'session_name': packet.get('sdp_session_name', '')
                    }
                    endpoints[src_ip]['sdp_offers'].append(sdp_info)
                    
                    # Extract codec information from SDP media line
                    media_line = packet.get('sdp_media', '')
                    if 'RTP/AVP' in media_line:
                        # Extract payload types (numbers after RTP/AVP)
                        parts = media_line.split('RTP/AVP')
                        if len(parts) > 1:
                            payload_types = parts[1].strip().split()
                            for pt in payload_types:
                                if pt.isdigit():
                                    codec_name = get_codec_name_from_payload_type(int(pt))
                                    endpoints[src_ip]['codecs_offered'].add(f"{codec_name} ({pt})")
                
                # Track User-Agent information
                if packet.get('user_agent'):
                    endpoints[src_ip]['user_agents'].add(packet.get('user_agent'))
            
            # Process destination endpoint  
            if dst_ip and dst_ip != 'Unknown':
                if dst_ip not in endpoints:
                    endpoints[dst_ip] = {
                        'ip': dst_ip,
                        'sip_addresses': set(),
                        'methods_sent': set(),
                        'status_codes_sent': set(),
                        'sdp_offers': [],
                        'user_agents': set(),
                        'codecs_offered': set(),
                        'role': 'unknown',
                        'auth_realms': set(),
                        'auth_challenges': [],
                        'register_info': []
                    }
                
                # Collect SIP addresses (only from packets this endpoint receives)
                if to_addr and packet.get('method'):  # Only for requests to this IP
                    endpoints[dst_ip]['sip_addresses'].add(to_addr)
                
                # Track SDP offers in responses
                if packet.get('sdp_media') and packet.get('status_code'):
                    sdp_info = {
                        'media': packet.get('sdp_media', ''),
                        'port': packet.get('sdp_media_port', ''),
                        'protocol': packet.get('sdp_media_proto', ''),
                        'packet_num': packet.get('packet_num', ''),
                        'response_code': packet.get('status_code', ''),
                        'owner_username': packet.get('sdp_owner_username', ''),
                        'session_name': packet.get('sdp_session_name', '')
                    }
                    endpoints[dst_ip]['sdp_offers'].append(sdp_info)
                    
                    # Extract codec information
                    media_line = packet.get('sdp_media', '')
                    if 'RTP/AVP' in media_line:
                        parts = media_line.split('RTP/AVP')
                        if len(parts) > 1:
                            payload_types = parts[1].strip().split()
                            for pt in payload_types:
                                if pt.isdigit():
                                    codec_name = get_codec_name_from_payload_type(int(pt))
                                    endpoints[dst_ip]['codecs_offered'].add(f"{codec_name} ({pt})")
                
                # NOTE: User-Agent header belongs to the SOURCE endpoint only
                # It identifies who sent the packet, not who received it
        
        # Add RTP stream information
        for stream in rtp_streams:
            src_ip = stream.get('src_ip', '')
            dst_ip = stream.get('dst_ip', '')
            payload_type = stream.get('payload_type', '')
            
            # Add actual RTP codec usage
            if src_ip in endpoints and payload_type:
                codec_name = get_codec_name_from_payload_type(int(payload_type))
                endpoints[src_ip]['codecs_offered'].add(f"{codec_name} ({payload_type}) - Used in RTP")
        
        # Display endpoint analysis with enhanced authentication info
        # Sort endpoints to show SIP servers first, then by role importance
        role_priority = {
            'sip_server': 1,
            'caller': 2, 
            'callee': 3,
            'registration_client': 4,
            'unknown': 5
        }
        
        sorted_endpoints = sorted(endpoints.items(), key=lambda x: (role_priority.get(x[1]['role'], 5), x[0]))
        
        for i, (ip, info) in enumerate(sorted_endpoints, 1):
            role_emoji = "🖥️" if info['role'] == 'sip_server' else "📞" if info['role'] == 'caller' else "📱" if info['role'] == 'callee' else "📋" if info['role'] == 'registration_client' else "🖥️"
            role_text = f" ({info['role'].replace('_', ' ').title()})" if info['role'] != 'unknown' else ""
            
            # Use "Server" instead of "Endpoint" for SIP servers
            endpoint_label = "Server" if info['role'] == 'sip_server' else "Endpoint"
            
            print(f"\n{role_emoji} {endpoint_label} {i}: {ip}{role_text}")
            print("-" * 40)
            
            # Show authentication challenges issued by this server
            if info['role'] == 'sip_server' and info['auth_challenges']:
                print(f"🔒 Authentication Challenges Issued: {len(info['auth_challenges'])}")
                for challenge in info['auth_challenges'][:3]:  # Show first 3
                    method_info = f" for {challenge['cseq_method']}" if challenge['cseq_method'] else ""
                    dst_info = f" to {challenge['dst_ip']}" if challenge['dst_ip'] else ""
                    print(f"   • Packet #{challenge['packet_num']}: 401 Unauthorized{method_info}{dst_info}")
                    
                    if challenge['realm']:
                        print(f"     🌐 Realm: {challenge['realm']}")
                    if challenge['algorithm']:
                        print(f"     🔐 Algorithm: {challenge['algorithm']}")
                    if challenge['nonce']:
                        nonce_preview = challenge['nonce'][:16] + "..." if len(challenge['nonce']) > 16 else challenge['nonce']
                        print(f"     🎲 Nonce: {nonce_preview}")
                        
                if len(info['auth_challenges']) > 3:
                    print(f"   ... and {len(info['auth_challenges']) - 3} more challenges")
            
            # Show registration attempts for registration clients
            if info['role'] == 'registration_client' and info['register_info']:
                print(f"📝 Registration Attempts: {len(info['register_info'])}")
                for reg in info['register_info'][:3]:  # Show first 3
                    to_user = reg['to_addr'].split('@')[0].replace('sip:', '') if '@' in reg['to_addr'] else 'Unknown'
                    auth_status = " (with auth)" if reg['authorization'] else " (no auth)"
                    print(f"   • Packet #{reg['packet_num']}: {to_user}@{ip.split('.')[-1]}...{auth_status}")
                    
                    if reg['user_agent']:
                        print(f"     🌐 User-Agent: {reg['user_agent']}")
                    if reg['expires']:
                        print(f"     ⏰ Expires: {reg['expires']} seconds")
                    if reg['contact']:
                        contact_preview = reg['contact'][:40] + "..." if len(reg['contact']) > 40 else reg['contact']
                        print(f"     📞 Contact: {contact_preview}")
                    if reg['www_authenticate']:
                        print(f"     🔐 Received Challenge: Yes")
                        
                if len(info['register_info']) > 3:
                    print(f"   ... and {len(info['register_info']) - 3} more registrations")
            
            # Show realm info for registration clients
            if info['role'] == 'registration_client' and info['auth_realms']:
                print(f"🌐 SIP Server Realms: {', '.join(info['auth_realms'])}")
            
            # SIP Identity
            if info['sip_addresses']:
                print(f"📧 SIP Addresses:")
                for addr in sorted(info['sip_addresses']):
                    print(f"   • {addr}")
            
            # Authentication and Registration Info (from enhanced extraction)
            if auth_info and 'sip_servers' in auth_info and ip in auth_info['sip_servers']:
                server_info = auth_info['sip_servers'][ip]
                print(f"🛡️ Authentication Server Details:")
                if server_info['realms']:
                    print(f"   🌐 Realms: {', '.join(server_info['realms'])}")
                if server_info['auth_methods']:
                    print(f"   🔐 Auth Methods: {', '.join(server_info['auth_methods'])}")
                print(f"   📊 Challenge Count: {server_info['challenge_count']}")
                
            # Registration attempts FROM this endpoint
            if auth_info and 'register_attempts' in auth_info:
                reg_attempts = [r for r in auth_info['register_attempts'] if r['src_ip'] == ip]
                if reg_attempts:
                    print(f"📝 Registration Attempts: {len(reg_attempts)}")
                    for reg in reg_attempts[:3]:  # Show first 3
                        user_info = f"{reg['user']}@{reg['domain']}" if reg['user'] and reg['domain'] else "Unknown user"
                        auth_status = " (with auth)" if reg['authorization'] else " (no auth)"
                        print(f"   • Packet #{reg['packet_num']}: {user_info}{auth_status}")
                    if len(reg_attempts) > 3:
                        print(f"   ... and {len(reg_attempts) - 3} more")
            
            # Authentication challenges received by this endpoint
            if auth_info and 'auth_challenges' in auth_info:
                challenges = [c for c in auth_info['auth_challenges'] if c['dst_ip'] == ip]
                if challenges:
                    print(f"🔒 Authentication Challenges Received: {len(challenges)}")
                    for challenge in challenges[:2]:  # Show first 2
                        realm_info = f" (realm: {challenge['realm']})" if challenge['realm'] else ""
                        method_info = f" for {challenge['cseq_method']}" if challenge['cseq_method'] else ""
                        src_info = f" from {challenge['src_ip']}"
                        print(f"   • Packet #{challenge['packet_num']}: 401 Unauthorized{realm_info}{method_info}{src_info}")
                    if len(challenges) > 2:
                        print(f"   ... and {len(challenges) - 2} more")
            
            # Methods and capabilities
            if info['methods_sent']:
                print(f"📤 SIP Methods Sent: {', '.join(sorted(info['methods_sent']))}")
            
            if info['status_codes_sent']:
                print(f"📥 SIP Responses Sent: {', '.join(sorted(info['status_codes_sent']))}")
            
            # Media capabilities
            if info['codecs_offered']:
                print(f"🎵 Advertised Codecs:")
                for codec in sorted(info['codecs_offered']):
                    print(f"   • {codec}")
            
            # SDP offers
            if info['sdp_offers']:
                print(f"📋 SDP Media Offers ({len(info['sdp_offers'])}):")
                for j, offer in enumerate(info['sdp_offers'], 1):
                    response_info = f" (Response {offer.get('response_code')})" if offer.get('response_code') else ""
                    media_line = offer['media']
                    print(f"   {j}. {media_line}")
                    print(f"      Port: {offer['port']}, Protocol: {offer['protocol']}")
                    print(f"      Packet #{offer['packet_num']}{response_info}")
                    
                    # Add detailed SDP analysis
                    sdp_analysis = analyze_sdp_media_line(media_line)
                    if sdp_analysis['dtmf_support']:
                        print(f"      🎯 DTMF Support: Out-of-band telephone events (RFC 4733)")
                    if sdp_analysis['audio_codecs']:
                        print(f"      🎵 Audio Codecs: {', '.join(sdp_analysis['audio_codecs'])}")
                    if sdp_analysis['dynamic_payloads']:
                        print(f"      🔧 Dynamic Payloads: {', '.join(sdp_analysis['dynamic_payloads'])} (vendor-specific)")
                    
                    # Add SDP owner and session information
                    if offer.get('owner_username'):
                        print(f"      👤 SDP Owner: {offer['owner_username']}")
                    if offer.get('session_name'):
                        print(f"      📝 Session Name: {offer['session_name']}")
            
            # User-Agent information
            if info['user_agents']:
                print(f"🌐 User-Agent(s):")
                for user_agent in sorted(info['user_agents']):
                    print(f"   • {user_agent}")
        
        # Summary
        print(f"\n📊 Endpoint Summary:")
        caller_ips = [ip for ip, info in endpoints.items() if info['role'] == 'caller']
        callee_ips = [ip for ip, info in endpoints.items() if info['role'] == 'callee']
        
        if caller_ips:
            print(f"   📞 Caller(s): {', '.join(caller_ips)}")
        if callee_ips:
            print(f"   📱 Callee(s): {', '.join(callee_ips)}")
        
        # Codec compatibility check
        all_codecs = set()
        for info in endpoints.values():
            all_codecs.update(info['codecs_offered'])
        
        if len(all_codecs) > 0:
            print(f"   🎵 Total unique codecs negotiated: {len(all_codecs)}")
            
        print()
            
    except Exception as e:
        print(f"   ℹ️  Endpoint analysis not available: {e}")
