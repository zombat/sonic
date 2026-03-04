#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Overlap Dialing Analysis Module

Detects and analyzes SIP overlap dialing patterns in VoIP calls.

Author: Raymond A Rizzo | Zombat
Version: 3.0 (Modular Architecture)
Last Updated: 2025-07-15
"""

import json
import re
import sys
from typing import Dict, Any, List


def extract_digit_keys_from_sip_data(sip_data: str) -> Dict[str, Any]:
    """
    Extracts digit keys and overlap dialing patterns from SIP data.
    
    Detects:
    - DTMF digits (via Signal= in INFO)
    - Function keys (F1-F24)
    - Special keys (HOLD, TRANSFER, etc.)
    - Digit keys in NOTIFY messages
    - Progressive digits in Request-URI (INVITE variations)
    
    Args:
        sip_data: Raw SIP data to analyze
        
    Returns:
        Dict containing overlap dialing analysis results with collected digits
    """
    digit_events = []
    call_setup_method = "en-bloc"  # Default assumption
    overlap_detected = False
    
    try:
        # Parse SIP data - handle both JSON and raw string formats
        if isinstance(sip_data, str):
            # Try JSON first
            try:
                data = json.loads(sip_data)
                packets = data.get('sip_packets', []) if isinstance(data, dict) else []
            except (json.JSONDecodeError, TypeError):
                # Fall back to string parsing
                packets = [sip_data]
        else:
            packets = [sip_data]
        
        # Collect all digit patterns from packets
        for packet_idx, packet in enumerate(packets):
            packet_str = str(packet.get('packet_data', packet)) if isinstance(packet, dict) else str(packet)
            
            # 1. DTMF digits in INFO messages (Signal=)
            signal_matches = re.finditer(r'Signal\s*=\s*([0-9*#ABCD])', packet_str, re.IGNORECASE)
            for match in signal_matches:
                digit_events.append({
                    'digit': match.group(1),
                    'packet': packet_idx,
                    'pattern': 'info_dtmf',
                    'key_type': 'dtmf'
                })
                call_setup_method = "overlap"
                overlap_detected = True
            
            # 2. Function keys (F1-F24)
            function_matches = re.finditer(r'(?:Signal|Key|Event)\s*=\s*(F[0-9]{1,2})', packet_str, re.IGNORECASE)
            for match in function_matches:
                digit_events.append({
                    'digit': match.group(1).upper(),
                    'packet': packet_idx,
                    'pattern': 'info_function',
                    'key_type': 'function'
                })
                overlap_detected = True
            
            # 3. Special keys (business phone keys)
            special_keys = ['HOLD', 'TRANSFER', 'CONFERENCE', 'MUTE', 'SPEAKER', 'HEADSET',
                          'VOLUME_UP', 'VOLUME_DOWN', 'REDIAL', 'FLASH', 'HOOK', 'SOFTKEY']
            for special_key in special_keys:
                if special_key.lower() in packet_str.lower():
                    digit_events.append({
                        'digit': special_key,
                        'packet': packet_idx,
                        'pattern': 'info_special',
                        'key_type': 'special'
                    })
                    overlap_detected = True
            
            # 4. Digit keys in NOTIFY messages
            if 'NOTIFY' in packet_str.upper():
                digit_key_matches = re.finditer(r'digitkey["\s]*[:=]\s*([0-9*#ABCD])', packet_str, re.IGNORECASE)
                for match in digit_key_matches:
                    digit_events.append({
                        'digit': match.group(1),
                        'packet': packet_idx,
                        'pattern': 'notify_digit',
                        'key_type': 'dtmf',
                        'legacy': True
                    })
                    call_setup_method = "overlap"
                    overlap_detected = True
            
            # 5. Progressive digits in Request-URI (multiple INVITEs)
            invite_matches = re.finditer(r'INVITE\s+sip:([0-9*#+]+)@', packet_str)
            for match in invite_matches:
                number = match.group(1)
                digit_events.append({
                    'digit_sequence': number,
                    'packet': packet_idx,
                    'pattern': 'progressive_digits',
                    'key_type': 'uri_digits'
                })
                # Only mark as overlap if multiple progressions detected
        
        # Determine call setup method
        if len(digit_events) > 1:
            call_setup_method = "overlap"
            overlap_detected = True
        elif any(d.get('pattern') == 'progressive_digits' for d in digit_events):
            call_setup_method = "overlap"
            overlap_detected = True
        
        return {
            "overlap_dialing_detected": overlap_detected,
            "digit_events": digit_events,
            "call_setup_method": call_setup_method,
            "total_events": len(digit_events)
        }
        
    except Exception as e:
        # Fallback on any parsing errors
        return {
            "overlap_dialing_detected": False,
            "digit_events": [],
            "call_setup_method": "en-bloc",
            "error": str(e)
        }


def extract_digit_keys_with_scapy(file_path: str) -> Dict[str, Any]:
    """
    Analyzes SIP traffic from a pcap file to detect overlap dialing patterns
    using Scapy for enhanced packet analysis.
    
    Args:
        file_path: Path to the pcap/pcapng file
        
    Returns:
        Dictionary containing overlap dialing analysis results
    """
    try:
        from scapy.all import rdpcap, IP, UDP
        from scapy.layers.inet import TCP
        
        packets = rdpcap(file_path)
        digit_events = []
        call_analysis = {}
        
        for i, packet in enumerate(packets):
            if not (packet.haslayer(UDP) or packet.haslayer(TCP)):
                continue
                
            # Extract SIP payload
            if packet.haslayer(UDP):
                payload = bytes(packet[UDP].payload)
            elif packet.haslayer(TCP):
                payload = bytes(packet[TCP].payload)
            else:
                continue
                
            try:
                sip_data = payload.decode('utf-8', errors='ignore')
            except:
                continue
                
            # Look for SIP messages
            if not any(method in sip_data for method in ['INVITE', 'INFO', 'NOTIFY', 'BYE', 'CANCEL', 'ACK']):
                continue
                
            # Extract Call-ID for correlation
            call_id_match = re.search(r'Call-ID:\s*([^\r\n]+)', sip_data, re.IGNORECASE)
            call_id = call_id_match.group(1).strip() if call_id_match else f"unknown_{i}"
            
            # Initialize call tracking
            if call_id not in call_analysis:
                call_analysis[call_id] = {
                    'packets': [],
                    'invites': [],
                    'digits_collected': [],
                    'pattern_type': 'unknown'
                }
            
            call_analysis[call_id]['packets'].append({
                'packet_num': i + 1,
                'sip_data': sip_data,
                'timestamp': float(packet.time) if hasattr(packet, 'time') else 0
            })
            
            # Check for INVITE with Request-URI progression
            invite_match = re.search(r'^INVITE\s+sip:([^@\s]+)@', sip_data, re.MULTILINE | re.IGNORECASE)
            if invite_match:
                number = invite_match.group(1)
                call_analysis[call_id]['invites'].append({
                    'packet': i + 1,
                    'number': number,
                    'method': 'invite'
                })
            
            # Check for INFO messages with DTMF and function keys
            if 'INFO' in sip_data and ('Signal=' in sip_data or 'application/dtmf' in sip_data):
                # Standard DTMF digits
                signal_match = re.search(r'Signal=\s*([0-9*#ABCD])', sip_data, re.IGNORECASE)
                if signal_match:
                    digit = signal_match.group(1)
                    call_analysis[call_id]['digits_collected'].append({
                        'digit': digit,
                        'packet': i + 1,
                        'pattern': 'info_dtmf',
                        'key_type': 'dtmf'
                    })
                
                # Function keys (F1-F24, common on business phones)
                function_key_match = re.search(r'(?:Signal=\s*|Key=\s*|Event=\s*)(F[0-9]{1,2})', sip_data, re.IGNORECASE)
                if function_key_match:
                    key = function_key_match.group(1).upper()
                    call_analysis[call_id]['digits_collected'].append({
                        'digit': key,
                        'packet': i + 1,
                        'pattern': 'info_function',
                        'key_type': 'function'
                    })
                
                # Special keys (commonly found on VoIP phones)
                special_keys = ['HOLD', 'TRANSFER', 'CONFERENCE', 'MUTE', 'SPEAKER', 'HEADSET', 
                               'VOLUME_UP', 'VOLUME_DOWN', 'REDIAL', 'FLASH', 'HOOK', 'SOFTKEY']
                for special_key in special_keys:
                    if special_key.lower() in sip_data.lower():
                        call_analysis[call_id]['digits_collected'].append({
                            'digit': special_key,
                            'packet': i + 1,
                            'pattern': 'info_special',
                            'key_type': 'special'
                        })
            
            # Check for digit events and function keys in NOTIFY
            if 'NOTIFY' in sip_data:
                # Extract comprehensive NOTIFY message body information
                notify_info = extract_notify_message_body(sip_data, i + 1, call_id)
                if notify_info:
                    call_analysis[call_id]['digits_collected'].extend(notify_info)
                
                # Legacy digit key detection (keep for compatibility)
                if 'digit' in sip_data.lower():
                    # Standard digit keys
                    digit_match = re.search(r'digitkey["\s]*[:=]\s*([0-9*#ABCD])', sip_data, re.IGNORECASE)
                    if digit_match:
                        digit = digit_match.group(1)
                        call_analysis[call_id]['digits_collected'].append({
                            'digit': digit,
                            'packet': i + 1,
                            'pattern': 'notify_digit',
                            'key_type': 'dtmf',
                            'legacy': True
                        })
        
        # Analyze patterns
        overlap_detected = False
        for call_id, analysis in call_analysis.items():
            # Check for URI progression (multiple INVITEs with increasing number length)
            invites = analysis['invites']
            if len(invites) > 1:
                numbers = [inv['number'] for inv in invites]
                # Check if numbers are progressively longer and share prefixes
                for i in range(1, len(numbers)):
                    if len(numbers[i]) > len(numbers[i-1]) and numbers[i].startswith(numbers[i-1]):
                        analysis['pattern_type'] = 'progressive_digits'
                        overlap_detected = True
                        break
            
            # Check for digit collection via INFO/NOTIFY
            if analysis['digits_collected']:
                analysis['pattern_type'] = 'info_based' if any(d['pattern'] == 'info_dtmf' for d in analysis['digits_collected']) else 'notify_based'
                overlap_detected = True
        
        # Collect all digit events from all calls
        all_digit_events = []
        for call_id, analysis in call_analysis.items():
            all_digit_events.extend(analysis['digits_collected'])
        
        return {
            'overlap_dialing_detected': overlap_detected,
            'call_analysis': call_analysis,
            'digit_events': all_digit_events,  # Include all collected events
            'total_calls': len(call_analysis),
            'overlap_calls': sum(1 for a in call_analysis.values() if a['pattern_type'] != 'unknown')
        }
        
    except Exception as e:
        return {
            'overlap_dialing_detected': False,
            'error': str(e),
            'call_analysis': {},
            'total_calls': 0,
            'overlap_calls': 0
        }


def extract_notify_message_body(sip_data: str, packet_num: int, call_id: str) -> list:
    """
    Extracts comprehensive information from NOTIFY message body for call progression tracking.
    
    Args:
        sip_data: Raw SIP message data
        packet_num: Packet number for tracking
        call_id: Call ID for correlation
        
    Returns:
        List of event dictionaries containing NOTIFY message body information
    """
    events = []
    
    try:
        # Split message into headers and body
        if '\r\n\r\n' in sip_data:
            headers, body = sip_data.split('\r\n\r\n', 1)
        elif '\n\n' in sip_data:
            headers, body = sip_data.split('\n\n', 1)
        else:
            # No body found
            return events
        
        # Extract Event header for context
        event_header = None
        event_match = re.search(r'Event:\s*([^\r\n]+)', headers, re.IGNORECASE)
        if event_match:
            event_header = event_match.group(1).strip()
        
        # Extract Content-Type for processing hints
        content_type = None
        content_type_match = re.search(r'Content-Type:\s*([^\r\n]+)', headers, re.IGNORECASE)
        if content_type_match:
            content_type = content_type_match.group(1).strip()
        
        # Extract Request-URI and method for context
        request_uri = None
        method = None
        request_line_match = re.search(r'^(NOTIFY)\s+([^\s]+)', sip_data, re.MULTILINE)
        if request_line_match:
            method = request_line_match.group(1)
            request_uri = request_line_match.group(2)
        
        # Parse message body for various event types
        body_lines = body.strip().split('\n')
        
        for line_num, line in enumerate(body_lines):
            line = line.strip()
            if not line:
                continue
                
            # Event-Digitkey tracking (DTMF digits)
            digitkey_match = re.search(r'Event-Digitkey["\s]*[:=]\s*([0-9*#ABCD])', line, re.IGNORECASE)
            if digitkey_match:
                digit = digitkey_match.group(1)
                events.append({
                    'event_type': 'Event-Digitkey',
                    'digit': digit,
                    'key_type': 'dtmf',
                    'packet': packet_num,
                    'call_id': call_id,
                    'pattern': 'notify_digitkey',
                    'event_header': event_header,
                    'content_type': content_type,
                    'request_uri': request_uri,
                    'body_line': line_num + 1,
                    'raw_line': line,
                    'display_enabled': True
                })
            
            # Event-Fkey tracking (Function keys - NEC format: Event-Fkey=8:speaker)
            fkey_match = re.search(r'Event-Fkey["\s]*[:=]\s*([0-9]{1,2}):?([a-zA-Z_]*)', line, re.IGNORECASE)
            if fkey_match:
                key_num = fkey_match.group(1)
                key_desc = fkey_match.group(2) if fkey_match.group(2) else ''
                fkey_display = f'F{key_num}' + (f':{key_desc}' if key_desc else '')
                events.append({
                    'event_type': 'Event-Fkey',
                    'digit': fkey_display,
                    'key_type': 'function',
                    'packet': packet_num,
                    'call_id': call_id,
                    'pattern': 'notify_fkey',
                    'event_header': event_header,
                    'content_type': content_type,
                    'request_uri': request_uri,
                    'body_line': line_num + 1,
                    'raw_line': line,
                    'display_enabled': True,
                    'key_number': key_num,
                    'key_description': key_desc
                })
            
            # Event-Jkey tracking (Jog dial or navigation keys - NEC format)
            jkey_match = re.search(r'Event-Jkey["\s]*[:=]\s*([0-9A-Za-z_:]+)', line, re.IGNORECASE)
            if jkey_match:
                jkey = jkey_match.group(1).upper()
                events.append({
                    'event_type': 'Event-Jkey',
                    'digit': jkey,
                    'key_type': 'navigation',
                    'packet': packet_num,
                    'call_id': call_id,
                    'pattern': 'notify_jkey',
                    'event_header': event_header,
                    'content_type': content_type,
                    'request_uri': request_uri,
                    'body_line': line_num + 1,
                    'raw_line': line,
                    'display_enabled': True
                })
            
            # Collect all other event types for comprehensive tracking (but don't display by default)
            other_event_patterns = [
                # NEC-style patterns
                (r'Event-LineKey["\s]*[:=]\s*([0-9]{1,2}):?([a-zA-Z_]*)', 'Event-LineKey', 'line'),
                (r'Event-SpeedDial["\s]*[:=]\s*([0-9]{1,3}):?([a-zA-Z_]*)', 'Event-SpeedDial', 'speed_dial'),
                (r'Event-SoftKey["\s]*[:=]\s*([0-9A-Za-z_:]+)', 'Event-SoftKey', 'soft_key'),
                (r'Event-Hold["\s]*[:=]\s*([A-Za-z0-9_:]*)', 'Event-Hold', 'special'),
                (r'Event-Transfer["\s]*[:=]\s*([A-Za-z0-9_:]*)', 'Event-Transfer', 'special'),
                (r'Event-Conference["\s]*[:=]\s*([A-Za-z0-9_:]*)', 'Event-Conference', 'special'),
                (r'Event-Mute["\s]*[:=]\s*([A-Za-z0-9_:]*)', 'Event-Mute', 'special'),
                (r'Event-Volume["\s]*[:=]\s*([A-Za-z0-9_:]*)', 'Event-Volume', 'special'),
                (r'Event-Display["\s]*[:=]\s*([^\r\n]*)', 'Event-Display', 'display'),
                (r'Event-Status["\s]*[:=]\s*([^\r\n]*)', 'Event-Status', 'status'),
                # Info- patterns (NEC format)
                (r'Info-TermType["\s]*[:=]\s*([^\r\n]*)', 'Info-TermType', 'info'),
                (r'Info-State["\s]*[:=]\s*([^\r\n]*)', 'Info-State', 'info'),
                (r'Info-CallState["\s]*[:=]\s*([^\r\n]*)', 'Info-CallState', 'info'),
                (r'Info-([A-Za-z][A-Za-z0-9]*)["\s]*[:=]\s*([^\r\n]*)', 'Info-Generic', 'info'),
                # Generic Event- pattern (catch-all)
                (r'Event-([A-Za-z][A-Za-z0-9]*)["\s]*[:=]\s*([^\r\n]*)', 'Event-Generic', 'generic')
            ]
            
            for pattern, event_name, key_category in other_event_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if event_name == 'Event-Generic':
                        event_name = f'Event-{match.group(1)}'
                        value = match.group(2)
                    elif event_name == 'Info-Generic':
                        event_name = f'Info-{match.group(1)}'
                        value = match.group(2)
                    else:
                        value = match.group(1)
                        # If there's a second group (description), include it
                        if match.lastindex >= 2 and match.group(2):
                            value = f"{value}:{match.group(2)}"
                    
                    # Skip if we already processed this as a specific event
                    if any(e['raw_line'] == line and e['event_type'] in ['Event-Digitkey', 'Event-Fkey', 'Event-Jkey'] for e in events):
                        continue
                    
                    events.append({
                        'event_type': event_name,
                        'digit': value,
                        'key_type': key_category,
                        'packet': packet_num,
                        'call_id': call_id,
                        'pattern': f'notify_{key_category}',
                        'event_header': event_header,
                        'content_type': content_type,
                        'request_uri': request_uri,
                        'body_line': line_num + 1,
                        'raw_line': line,
                        'display_enabled': False  # Only display specific events by default
                    })
                    break  # Found a match, don't process other patterns for this line
            
            # Track raw message body content for debugging
            if line and not any(e['raw_line'] == line for e in events):
                # This is unrecognized content, track it for debugging
                events.append({
                    'event_type': 'Raw-Content',
                    'digit': line[:50] + '...' if len(line) > 50 else line,
                    'key_type': 'raw',
                    'packet': packet_num,
                    'call_id': call_id,
                    'pattern': 'notify_raw',
                    'event_header': event_header,
                    'content_type': content_type,
                    'request_uri': request_uri,
                    'body_line': line_num + 1,
                    'raw_line': line,
                    'display_enabled': False
                })
    
    except Exception as e:
        # If parsing fails, create an error event
        events.append({
            'event_type': 'Parse-Error',
            'digit': f'Error: {str(e)}',
            'key_type': 'error',
            'packet': packet_num,
            'call_id': call_id,
            'pattern': 'notify_error',
            'event_header': event_header,
            'content_type': content_type,
            'request_uri': request_uri,
            'body_line': 0,
            'raw_line': sip_data[:100] + '...' if len(sip_data) > 100 else sip_data,
            'display_enabled': False
        })
    
    return events


def detect_overlap_dialing(sip_data: str, file_path: str = None) -> Dict[str, Any]:
    """
    Detects SIP overlap dialing patterns in the call signaling.
    
    Overlap dialing indicators:
    - Multiple INVITE messages to the same Call-ID with different Request-URIs
    - Progressive digit collection in Request-URI
    - re-INVITE or INFO messages with additional digits
    - NOTIFY messages with Event-Digitkey for digit collection
    - Time delays between digit sending
    
    Args:
        sip_data: Raw SIP data containing packet information
        file_path: Optional path to pcap file for enhanced digit extraction
        
    Returns:
        Dict containing overlap dialing analysis results
    """
    try:
        data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
        
        if not isinstance(data, dict) or 'sip_packets' not in data:
            return {'overlap_detected': False, 'reason': 'No SIP packet data available'}
            
        sip_packets = data.get('sip_packets', [])
        
        if not sip_packets:
            return {'overlap_detected': False, 'reason': 'No SIP packets found'}
        
        # Group packets by Call-ID
        calls = {}
        for packet in sip_packets:
            call_id = packet.get('call_id', 'Unknown')
            if call_id not in calls:
                calls[call_id] = []
            calls[call_id].append(packet)
        
        overlap_results = {}
        
        # Extract digit keys if we have raw SIP data
        digit_info = extract_digit_keys_from_sip_data(sip_data)
        
        # For NOTIFY-based patterns, try enhanced scapy extraction
        enhanced_digit_info = None
        if file_path and any('notify' in str(packet.get('method', '')).lower() for packets in calls.values() for packet in packets):
            enhanced_digit_info = extract_digit_keys_with_scapy(file_path)
        
        for call_id, packets in calls.items():
            call_analysis = {
                'overlap_detected': False,
                'pattern_type': None,
                'evidence': [],
                'digit_progression': [],
                'timing_analysis': {},
                'invite_count': 0,
                'reinvite_count': 0,
                'info_count': 0,
                'collected_digits': [],  # New: store actual digits
                'digit_sequence': ''     # New: combined digit string
            }
            
            # Sort packets by time or packet number
            packets.sort(key=lambda x: x.get('packet_num', 0))
            
            invites = []
            reinvites = []
            info_messages = []
            
            for packet in packets:
                method = packet.get('method', '')
                request_uri = packet.get('request_uri', '')
                
                if method == 'INVITE':
                    if not invites:  # First INVITE
                        invites.append({
                            'packet_num': packet.get('packet_num'),
                            'request_uri': request_uri,
                            'time': packet.get('time', ''),
                            'type': 'initial'
                        })
                        call_analysis['invite_count'] += 1
                    else:  # re-INVITE
                        reinvites.append({
                            'packet_num': packet.get('packet_num'),
                            'request_uri': request_uri,
                            'time': packet.get('time', ''),
                            'type': 'reinvite'
                        })
                        call_analysis['reinvite_count'] += 1
                
                elif method == 'INFO':
                    info_messages.append({
                        'packet_num': packet.get('packet_num'),
                        'request_uri': request_uri,
                        'time': packet.get('time', ''),
                        'type': 'info'
                    })
                    call_analysis['info_count'] += 1
                
                elif method == 'NOTIFY':
                    # NOTIFY messages can be used for digit collection
                    info_messages.append({
                        'packet_num': packet.get('packet_num'),
                        'request_uri': request_uri,
                        'time': packet.get('time', ''),
                        'type': 'notify'
                    })
                    call_analysis['notify_count'] = call_analysis.get('notify_count', 0) + 1
            
            # Analyze Request-URI progression for digit collection
            all_requests = invites + reinvites + info_messages
            if len(all_requests) > 1:
                uri_progression = []
                for req in all_requests:
                    uri = req['request_uri']
                    # Extract number from SIP URI (sip:number@host)
                    if 'sip:' in uri and '@' in uri:
                        try:
                            number_part = uri.split('sip:')[1].split('@')[0]
                            # Remove ;user=phone or other parameters
                            number_part = number_part.split(';')[0]
                            uri_progression.append({
                                'packet': req['packet_num'],
                                'number': number_part,
                                'time': req['time'],
                                'method': req['type']
                            })
                        except (IndexError, AttributeError):
                            continue
                
                call_analysis['digit_progression'] = uri_progression
                
                # Check for progressive digit collection patterns
                if len(uri_progression) >= 2:
                    numbers = [entry['number'] for entry in uri_progression]
                    
                    # Pattern 1: Numbers getting longer (digit addition)
                    progressive_lengthening = True
                    for i in range(1, len(numbers)):
                        prev_num = numbers[i-1]
                        curr_num = numbers[i]
                        if not (len(curr_num) > len(prev_num) and curr_num.startswith(prev_num)):
                            progressive_lengthening = False
                            break
                    
                    if progressive_lengthening:
                        call_analysis['overlap_detected'] = True
                        call_analysis['pattern_type'] = 'progressive_digits'
                        call_analysis['evidence'].append(
                            f"Progressive digit addition: {' → '.join(numbers)}"
                        )
                    
                    # Pattern 2: Multiple re-INVITEs with different numbers
                    if call_analysis['reinvite_count'] > 0:
                        unique_numbers = list(set(numbers))
                        if len(unique_numbers) > 1:
                            call_analysis['overlap_detected'] = True
                            if not call_analysis['pattern_type']:
                                call_analysis['pattern_type'] = 'reinvite_based'
                            call_analysis['evidence'].append(
                                f"Multiple numbers via re-INVITE: {unique_numbers}"
                            )
                    
                    # Pattern 3: INFO messages for digit collection
                    if call_analysis['info_count'] > 0:
                        call_analysis['overlap_detected'] = True
                        if not call_analysis['pattern_type']:
                            call_analysis['pattern_type'] = 'info_based'
                        call_analysis['evidence'].append(
                            f"INFO messages for additional digits: {call_analysis['info_count']} messages"
                        )
                    
                    # Pattern 4: NOTIFY messages for digit collection (e.g., NEC systems)
                    if call_analysis.get('notify_count', 0) > 0:
                        call_analysis['overlap_detected'] = True
                        if not call_analysis['pattern_type']:
                            call_analysis['pattern_type'] = 'notify_based'
                        call_analysis['evidence'].append(
                            f"NOTIFY messages for digit events: {call_analysis['notify_count']} messages"
                        )
                    
                    # Pattern 5: Check for overlap signaling indicators in URIs
                    overlap_indicators = ['overlap', 'digit', 'collection']
                    for entry in uri_progression:
                        uri_lower = entry['number'].lower()
                        if any(indicator in uri_lower for indicator in overlap_indicators):
                            call_analysis['overlap_detected'] = True
                            if not call_analysis['pattern_type']:
                                call_analysis['pattern_type'] = 'uri_based'
                            call_analysis['evidence'].append(
                                f"Overlap indicator in URI: {entry['number']}"
                            )
            
            # Add collected digits from message bodies
            digits_to_use = enhanced_digit_info if enhanced_digit_info and enhanced_digit_info.get('digit_events') else digit_info
            
            if digits_to_use and digits_to_use.get('digit_events'):
                call_digits = [
                    event for event in digits_to_use.get('digit_events', []) 
                    if event.get('call_id') == call_id
                ]
                
                if call_digits:
                    call_analysis['collected_digits'] = call_digits
                    # Generate digit sequence from DTMF keys only (not function keys)
                    dtmf_digits = [event.get('digit', '') for event in call_digits if event.get('key_type', 'dtmf') == 'dtmf']
                    digit_sequence = ''.join(dtmf_digits)
                    call_analysis['digit_sequence'] = digit_sequence
                    
                    if not call_analysis['overlap_detected']:
                        call_analysis['overlap_detected'] = True
                        call_analysis['pattern_type'] = f"{call_digits[0].get('pattern', 'unknown')}_extracted"
                    
                    # Update evidence to include all keypress types
                    dtmf_count = len([d for d in call_digits if d.get('key_type', 'dtmf') == 'dtmf'])
                    function_count = len([d for d in call_digits if d.get('key_type') == 'function'])
                    special_count = len([d for d in call_digits if d.get('key_type') == 'special'])
                    
                    evidence_parts = []
                    if dtmf_count > 0:
                        evidence_parts.append(f"{dtmf_count} DTMF")
                    if function_count > 0:
                        evidence_parts.append(f"{function_count} function")
                    if special_count > 0:
                        evidence_parts.append(f"{special_count} special")
                    
                    keypress_summary = " + ".join(evidence_parts) + " keys" if evidence_parts else f"{len(call_digits)} keys"
                    
                    if digit_sequence:
                        call_analysis['evidence'].append(f"Dialed number: {digit_sequence} ({keypress_summary})")
                    else:
                        call_analysis['evidence'].append(f"Keypresses detected: {keypress_summary}")
            
            # Add timing analysis if overlap detected
            if call_analysis['overlap_detected'] and len(all_requests) > 1:
                call_analysis['timing_analysis'] = {
                    'first_invite_packet': all_requests[0]['packet_num'],
                    'last_message_packet': all_requests[-1]['packet_num'],
                    'total_messages': len(all_requests),
                    'inter_message_packets': [
                        all_requests[i]['packet_num'] - all_requests[i-1]['packet_num'] 
                        for i in range(1, len(all_requests))
                    ]
                }
            
            overlap_results[call_id] = call_analysis
        
        # Create summary
        total_calls = len(calls)
        overlap_calls = sum(1 for analysis in overlap_results.values() if analysis['overlap_detected'])
        
        summary = {
            'overlap_detected': overlap_calls > 0,
            'total_calls_analyzed': total_calls,
            'overlap_calls_count': overlap_calls,
            'call_details': overlap_results
        }
        
        if overlap_calls > 0:
            summary['overall_pattern'] = 'Multiple overlap dialing patterns detected'
        else:
            summary['overall_pattern'] = 'En-bloc dialing (complete numbers sent at once)'
            
        return summary
        
    except Exception as e:
        return {
            'overlap_detected': False, 
            'reason': f'Analysis error: {e}',
            'total_calls_analyzed': 0,
            'overlap_calls_count': 0
        }


def print_overlap_dialing_analysis(sip_data: str, file_path: str = None) -> None:
    """
    Analyzes and displays SIP overlap dialing detection results.
    
    This function examines SIP signaling patterns to identify overlap dialing,
    where destination numbers are sent incrementally rather than all at once.
    
    Args:
        sip_data: Raw SIP data containing packet information
        file_path: Optional path to pcap file for enhanced analysis
    """
    try:
        print(f"\n📞 Overlap Dialing Analysis")
        print("=" * 60)
        
        overlap_analysis = detect_overlap_dialing(sip_data, file_path)
        
        if not overlap_analysis.get('overlap_detected', False):
            total_calls = overlap_analysis.get('total_calls_analyzed', 0)
            pattern = overlap_analysis.get('overall_pattern', 'Unknown')
            reason = overlap_analysis.get('reason', '')
            
            print(f"✅ En-bloc Dialing Detected")
            print(f"   📊 Calls analyzed: {total_calls}")
            print(f"   📋 Pattern: {pattern}")
            if reason:
                print(f"   ℹ️  Note: {reason}")
            print(f"   🎯 Complete destination numbers sent in single INVITE messages")
            return
        
        # Overlap dialing detected
        total_calls = overlap_analysis.get('total_calls_analyzed', 0)
        overlap_calls = overlap_analysis.get('overlap_calls_count', 0)
        
        print(f"🚨 Overlap Dialing Detected!")
        print(f"   📊 Total calls: {total_calls}")
        print(f"   📞 Overlap calls: {overlap_calls}")
        print(f"   📈 Overlap percentage: {(overlap_calls/total_calls*100):.1f}%" if total_calls > 0 else "")
        
        call_details = overlap_analysis.get('call_details', {})
        
        for i, (call_id, analysis) in enumerate(call_details.items(), 1):
            if not analysis.get('overlap_detected', False):
                continue
                
            print(f"\n📞 Call {i}: {call_id}")
            print("-" * 40)
            
            pattern_type = analysis.get('pattern_type', 'unknown')
            evidence = analysis.get('evidence', [])
            digit_progression = analysis.get('digit_progression', [])
            timing = analysis.get('timing_analysis', {})
            
            # Pattern type
            pattern_icons = {
                'progressive_digits': '🔢',
                'reinvite_based': '🔄',
                'info_based': 'ℹ️',
                'notify_based': '📨',
                'uri_based': '🔗',
                'unknown': '❓'
            }
            
            pattern_descriptions = {
                'progressive_digits': 'Progressive Digit Addition',
                'reinvite_based': 're-INVITE Based Overlap',
                'info_based': 'INFO Message Based',
                'notify_based': 'NOTIFY-based Digit Collection',
                'uri_based': 'URI-based Overlap Signaling',
                'unknown': 'Unknown Pattern'
            }
            
            icon = pattern_icons.get(pattern_type, '❓')
            desc = pattern_descriptions.get(pattern_type, 'Unknown Pattern')
            
            print(f"{icon} Pattern: {desc}")
            
            # Evidence
            if evidence:
                print(f"📋 Evidence:")
                for ev in evidence:
                    print(f"   • {ev}")
            
            # Show collected digits and keypresses
            collected_digits = analysis.get('collected_digits', [])
            digit_sequence = analysis.get('digit_sequence', '')
            
            if collected_digits:
                # Filter events to show only enabled display types
                display_events = [d for d in collected_digits if d.get('display_enabled', True)]
                all_events = collected_digits
                
                # Categorize keypresses by type
                dtmf_keys = [d for d in display_events if d.get('key_type') == 'dtmf']
                function_keys = [d for d in display_events if d.get('key_type') == 'function']
                navigation_keys = [d for d in display_events if d.get('key_type') == 'navigation']
                special_keys = [d for d in display_events if d.get('key_type') == 'special']
                line_keys = [d for d in display_events if d.get('key_type') == 'line']
                speed_dial_keys = [d for d in display_events if d.get('key_type') == 'speed_dial']
                
                # Build digit sequence from DTMF keys only
                dtmf_sequence = ''.join([event.get('digit', '') for event in dtmf_keys])
                if dtmf_sequence:
                    print(f"🔢 Dialed Number: {dtmf_sequence}")
                
                print(f"🎹 Total Events Tracked: {len(all_events)} (Displaying: {len(display_events)})")
                
                # Show DTMF digits (Event-Digitkey)
                if dtmf_keys:
                    print(f"📞 DTMF Digits - Event-Digitkey ({len(dtmf_keys)}):")
                    for j, digit_event in enumerate(dtmf_keys, 1):
                        digit = digit_event.get('digit', '?')
                        event_type = digit_event.get('event_type', 'Unknown')
                        packet_num = digit_event.get('packet', '?')
                        body_line = digit_event.get('body_line', '?')
                        event_header = digit_event.get('event_header', '')
                        context = f" ({event_header})" if event_header else ""
                        print(f"   {j}. '{digit}' via {event_type} (packet #{packet_num}, line {body_line}){context}")
                
                # Show function keys (Event-FKey)
                if function_keys:
                    print(f"🔧 Function Keys - Event-FKey ({len(function_keys)}):")
                    for j, key_event in enumerate(function_keys, 1):
                        key = key_event.get('digit', '?')
                        event_type = key_event.get('event_type', 'Unknown')
                        packet_num = key_event.get('packet', '?')
                        body_line = key_event.get('body_line', '?')
                        event_header = key_event.get('event_header', '')
                        context = f" ({event_header})" if event_header else ""
                        print(f"   {j}. {key} via {event_type} (packet #{packet_num}, line {body_line}){context}")
                
                # Show navigation keys (Event-JKey)
                if navigation_keys:
                    print(f"🕹️ Navigation Keys - Event-JKey ({len(navigation_keys)}):")
                    for j, key_event in enumerate(navigation_keys, 1):
                        key = key_event.get('digit', '?')
                        event_type = key_event.get('event_type', 'Unknown')
                        packet_num = key_event.get('packet', '?')
                        body_line = key_event.get('body_line', '?')
                        event_header = key_event.get('event_header', '')
                        context = f" ({event_header})" if event_header else ""
                        print(f"   {j}. {key} via {event_type} (packet #{packet_num}, line {body_line}){context}")
                
                # Show other categories if they exist in display events
                if special_keys:
                    print(f"⚙️ Special Keys ({len(special_keys)}):")
                    for j, key_event in enumerate(special_keys, 1):
                        key = key_event.get('digit', '?')
                        event_type = key_event.get('event_type', 'Unknown')
                        packet_num = key_event.get('packet', '?')
                        print(f"   {j}. {key} via {event_type} (packet #{packet_num})")
                
                if line_keys:
                    print(f"📱 Line Keys ({len(line_keys)}):")
                    for j, key_event in enumerate(line_keys, 1):
                        key = key_event.get('digit', '?')
                        event_type = key_event.get('event_type', 'Unknown')
                        packet_num = key_event.get('packet', '?')
                        print(f"   {j}. {key} via {event_type} (packet #{packet_num})")
                
                if speed_dial_keys:
                    print(f"⚡ Speed Dial Keys ({len(speed_dial_keys)}):")
                    for j, key_event in enumerate(speed_dial_keys, 1):
                        key = key_event.get('digit', '?')
                        event_type = key_event.get('event_type', 'Unknown')
                        packet_num = key_event.get('packet', '?')
                        print(f"   {j}. {key} via {event_type} (packet #{packet_num})")
                
                # Show chronological call progression for enabled display events
                if len(display_events) > 1:
                    print(f"⏱️ Call Progression Timeline (Enabled Events):")
                    sorted_events = sorted(display_events, key=lambda x: (x.get('packet', 0), x.get('body_line', 0)))
                    for j, event in enumerate(sorted_events, 1):
                        key = event.get('digit', '?')
                        event_type = event.get('event_type', 'Unknown')
                        key_type = event.get('key_type', 'unknown')
                        packet_num = event.get('packet', '?')
                        body_line = event.get('body_line', '?')
                        
                        # Choose appropriate icon
                        type_icons = {
                            'dtmf': '📞',
                            'function': '🔧',
                            'navigation': '🕹️',
                            'special': '⚙️',
                            'line': '📱',
                            'speed_dial': '⚡',
                            'unknown': '❓'
                        }
                        icon = type_icons.get(key_type, '❓')
                        
                        print(f"   {j}. {icon} {event_type}: '{key}' (packet #{packet_num}, line {body_line})")
                
                # Show summary of all tracked events (including hidden ones)
                hidden_events = [d for d in all_events if not d.get('display_enabled', True)]
                if hidden_events:
                    event_type_counts = {}
                    for event in hidden_events:
                        event_type = event.get('event_type', 'Unknown')
                        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
                    
                    print(f"📊 Additional Tracked Events (Hidden): {len(hidden_events)} events")
                    for event_type, count in sorted(event_type_counts.items()):
                        print(f"   • {event_type}: {count} events")
                    print(f"   💡 Use --verbose to display all tracked events")
                
            else:
                # Fallback to old display if no collected digits
                if digit_sequence:
                    print(f"🔢 Collected Digits: {digit_sequence}")
                    print(f"📝 Digit Events ({len(collected_digits)}):")
                    for j, digit_event in enumerate(collected_digits, 1):
                        digit = digit_event.get('digit', '?')
                        pattern = digit_event.get('pattern', 'unknown')
                        msg_idx = digit_event.get('message_index', '?')
                        print(f"   {j}. '{digit}' via {pattern.upper()} (msg #{msg_idx})")
            
            # Show NOTIFY Events or URI progression
            if collected_digits:
                # Show actual NOTIFY events with key presses
                print(f"🔢 NOTIFY Event Progression:")
                notify_events = [d for d in collected_digits if d.get('event_type', '').startswith('Event-')]
                if notify_events:
                    # Sort by packet number
                    sorted_events = sorted(notify_events, key=lambda x: x.get('packet', 0))
                    for j, event in enumerate(sorted_events, 1):
                        event_type = event.get('event_type', 'Unknown')
                        digit = event.get('digit', '?')
                        packet_num = event.get('packet', '?')
                        
                        # Choose appropriate icon based on event type
                        if 'Digitkey' in event_type:
                            icon = "📞"  # DTMF digit
                        elif 'Fkey' in event_type:
                            icon = "🔧"  # Function key
                        elif 'Jkey' in event_type:
                            icon = "🕹️"  # Navigation/Jog key
                        else:
                            icon = "📨"  # Generic NOTIFY
                        
                        print(f"   {icon} Packet #{packet_num}: {event_type} = '{digit}'")
                else:
                    # Fallback to URI progression if no specific events found
                    print(f"🔢 URI Progression (NOTIFY Packets):")
                    for entry in digit_progression:
                        method_icon = "📨" if entry['method'] == 'initial' else "🔄" if entry['method'] == 'reinvite' else "ℹ️"
                        print(f"   {method_icon} Packet #{entry['packet']}: {entry['number']} ({entry['method'].upper()})")
            elif digit_progression:
                # Only show URI progression if we don't have actual digits
                print(f"🔢 URI Progression:")
                for entry in digit_progression:
                    method_icon = "📨" if entry['method'] == 'initial' else "🔄" if entry['method'] == 'reinvite' else "ℹ️"
                    print(f"   {method_icon} Packet #{entry['packet']}: {entry['number']} ({entry['method'].upper()})")
            
            # Timing analysis
            if timing:
                print(f"⏱️  Timing Analysis:")
                print(f"   📦 First packet: #{timing.get('first_invite_packet', 'N/A')}")
                print(f"   📦 Last packet: #{timing.get('last_message_packet', 'N/A')}")
                print(f"   📊 Total messages: {timing.get('total_messages', 0)}")
                
                inter_gaps = timing.get('inter_message_packets', [])
                if inter_gaps:
                    avg_gap = sum(inter_gaps) / len(inter_gaps)
                    print(f"   ⏳ Average packet gap: {avg_gap:.1f} packets")
                    print(f"   🔄 Packet gaps: {inter_gaps}")
                    print(f"   💡 Explanation: Packet gaps show the number of packets between each")
                    print(f"      overlap message. Smaller gaps indicate rapid digit entry, while")
                    print(f"      larger gaps suggest pauses in dialing or inter-digit timeouts.")
            
            # Message counts
            invite_count = analysis.get('invite_count', 0)
            reinvite_count = analysis.get('reinvite_count', 0)
            info_count = analysis.get('info_count', 0)
            notify_count = analysis.get('notify_count', 0)
            
            print(f"📈 Message Summary:")
            print(f"   📨 Initial INVITEs: {invite_count}")
            if reinvite_count > 0:
                print(f"   🔄 re-INVITEs: {reinvite_count}")
            if info_count > 0:
                print(f"   ℹ️  INFO messages: {info_count}")
            if notify_count > 0:
                print(f"   📨 NOTIFY messages: {notify_count}")
        
        # Recommendations for overlap dialing
        print(f"\n💡 Overlap Dialing Recommendations:")
        print(f"   1. 🔍 Monitor inter-digit timeouts to prevent incomplete calls")
        print(f"   2. 📊 Check gateway configuration for overlap vs en-bloc handling")
        print(f"   3. 🌐 Verify ISDN interworking settings if connecting to legacy systems")
        print(f"   4. ⏱️  Review digit collection timeouts (typically 4-15 seconds)")
        print(f"   5. 📞 Consider en-bloc conversion for SIP-only networks for efficiency")
        print(f"   6. 🎹 Monitor function key usage for call control features")
        print(f"   7. 📱 Review line key and speed dial configurations")
        print(f"   8. ⚙️  Check special key handling for call transfer/hold features")
        
        # Enhanced Wireshark filters for overlap dialing investigation
        print(f"\n📋 Wireshark Investigation Filters:")
        print(f"   • All INVITE messages: sip.Method == INVITE")
        print(f"   • re-INVITE messages: sip.Method == INVITE and sip.CSeq.method == INVITE")
        print(f"   • INFO messages: sip.Method == INFO")
        print(f"   • NOTIFY messages: sip.Method == NOTIFY")
        print(f"   • DTMF digit events: sip.Method == NOTIFY and sip contains \"Event-Digitkey\"")
        print(f"   • Function key events: sip.Method == NOTIFY and sip contains \"Event-FKey\"")
        print(f"   • Navigation key events: sip.Method == NOTIFY and sip contains \"Event-JKey\"")
        print(f"   • Line key events: sip.Method == NOTIFY and sip contains \"Event-LineKey\"")
        print(f"   • Speed dial events: sip.Method == NOTIFY and sip contains \"Event-SpeedDial\"")
        print(f"   • Soft key events: sip.Method == NOTIFY and sip contains \"Event-SoftKey\"")
        print(f"   • Hold events: sip.Method == NOTIFY and sip contains \"Event-Hold\"")
        print(f"   • Transfer events: sip.Method == NOTIFY and sip contains \"Event-Transfer\"")
        print(f"   • All keypress events: sip.Method == INFO and sip contains \"Signal=\"")
        print(f"   • All NOTIFY events: sip.Method == NOTIFY and sip contains \"Event-\"")
        print(f"   • Progressive calls: sip and frame.number >= X and frame.number <= Y")
        
        # Call-specific filters
        for call_id in call_details.keys():
            if call_details[call_id].get('overlap_detected'):
                print(f"   • Call {call_id}: sip.Call-ID == \"{call_id}\"")
                
    except Exception as e:
        print(f"   ℹ️  Overlap dialing analysis not available: {e}")
