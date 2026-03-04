#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Authentication Information Extractor

Extracts SIP authentication and registration details from packet captures.
Implements RFC 3261 (SIP), RFC 2617 (Digest Authentication), and RFC 3665 (REGISTER flow).

Author: Raymond A Rizzo | Zombat
Version: 3.1 (Full Implementation with RFC Compliance)
Last Updated: 2025-07-22
"""

import json
import re
from typing import Dict, Any, List, Optional, Tuple


def extract_auth_and_registration_info(file_path: str) -> Dict[str, Any]:
    """
    Extracts comprehensive authentication and registration information from a pcap file.
    
    Parses SIP authentication challenges (401/407), authentication responses, and
    REGISTER request flows to detect:
    - Authentication challenges from SIP servers/proxies
    - Authentication credentials sent by clients
    - Registration success/failure patterns
    - Realm and nonce information for security analysis
    
    RFC Compliance:
    - RFC 3261 §21.4.1: 401 Unauthorized response format
    - RFC 3261 §21.4.3: 407 Proxy-Authenticate response format
    - RFC 2617 §3.2: Digest algorithm parameters (realm, nonce, algorithm, qop, opaque, stale)
    - RFC 3665 §1: REGISTER request lifecycle
    
    Args:
        file_path: Path to the pcap/pcapng file
        
    Returns:
        Dict containing:
            - auth_challenges: List of 401/407 challenges from servers/proxies
            - auth_responses: List of successful Authorization/Proxy-Authorization responses
            - register_attempts: List of REGISTER requests and their outcomes
            - sip_servers: Dict mapping server IPs to their characteristics
            - realms: List of authentication realms detected
            - auth_anomalies: Security issues detected in auth flow
    """
    
    # Extract SIP data using tshark (via submodule)
    from .tshark import extract_sip_data
    
    sip_data_json = extract_sip_data(file_path)
    if not sip_data_json:
        return {
            "auth_challenges": [],
            "auth_responses": [],
            "register_attempts": [],
            "sip_servers": {},
            "realms": [],
            "auth_anomalies": []
        }
    
    # Parse the JSON string to get SIP packets
    try:
        sip_data = json.loads(sip_data_json)
        sip_packets = sip_data.get("sip_packets", [])
    except (json.JSONDecodeError, TypeError):
        sip_packets = []
    
    # Extract authentication components
    auth_challenges = extract_auth_challenges(sip_packets)
    auth_responses = extract_auth_responses(sip_packets)
    register_attempts = extract_register_attempts(sip_packets)
    
    # Aggregate realms and servers
    realms = list(set(challenge.get("realm", "") for challenge in auth_challenges if challenge.get("realm", "")))
    
    sip_servers = {}
    for challenge in auth_challenges:
        server_ip = challenge.get("from_ip", "Unknown")
        if server_ip not in sip_servers:
            sip_servers[server_ip] = {
                "challenge_count": 0,
                "server_challenges": 0,
                "proxy_challenges": 0,
                "realms": set(),
            }
        sip_servers[server_ip]["challenge_count"] += 1
        if challenge.get("challenge_type") == "server":
            sip_servers[server_ip]["server_challenges"] += 1
        else:
            sip_servers[server_ip]["proxy_challenges"] += 1
        if challenge.get("realm"):
            sip_servers[server_ip]["realms"].add(challenge.get("realm"))
    
    # Convert sets to lists for JSON serialization
    for server_ip in sip_servers:
        sip_servers[server_ip]["realms"] = list(sip_servers[server_ip]["realms"])
    
    # Detect authentication anomalies
    auth_anomalies = _detect_auth_anomalies(auth_challenges, register_attempts, auth_responses)
    
    return {
        "auth_challenges": auth_challenges,
        "auth_responses": auth_responses,
        "register_attempts": register_attempts,
        "sip_servers": sip_servers,
        "realms": realms,
        "auth_anomalies": auth_anomalies
    }


def parse_authentication_header(header_value: str, header_type: str = "WWW-Authenticate") -> Dict[str, str]:
    """
    Parses SIP authentication header (WWW-Authenticate or Proxy-Authenticate).
    
    RFC 2617 Format:
        WWW-Authenticate: Digest realm="...", domain="...", nonce="...", 
                          opaque="...", stale=false, algorithm=MD5, qop="auth"
    
    Args:
        header_value: The full header value to parse
        header_type: Type of header ("WWW-Authenticate" or "Proxy-Authenticate")
        
    Returns:
        Dict with parsed parameters: realm, nonce, algorithm, qop, opaque, stale, etc.
    """
    auth_dict = {
        "header_type": header_type,
        "scheme": "",
        "realm": "",
        "domain": "",
        "nonce": "",
        "opaque": "",
        "stale": False,
        "algorithm": "MD5",  # Default per RFC 2617
        "qop": "",  # auth, auth-int, or both
    }
    
    if not header_value:
        return auth_dict
    
    # Extract scheme (Digest/Basic)
    scheme_match = re.match(r"(\w+)\s+(.+)", header_value)
    if scheme_match:
        auth_dict["scheme"] = scheme_match.group(1)
        params_str = scheme_match.group(2)
    else:
        return auth_dict
    
    # Parse quoted parameters
    quoted_params = {
        "realm": r'realm="([^"]*)"',
        "domain": r'domain="([^"]*)"',
        "nonce": r'nonce="([^"]*)"',
        "opaque": r'opaque="([^"]*)"',
    }
    
    for param_name, pattern in quoted_params.items():
        match = re.search(pattern, params_str)
        if match:
            auth_dict[param_name] = match.group(1)
    
    # Parse unquoted parameters
    algorithm_match = re.search(r'algorithm=([^\s,]+)', params_str)
    if algorithm_match:
        auth_dict["algorithm"] = algorithm_match.group(1).strip('"')
    
    qop_match = re.search(r'qop="?([^",\s]+)"?', params_str)
    if qop_match:
        auth_dict["qop"] = qop_match.group(1)
    
    stale_match = re.search(r'stale=(\w+)', params_str)
    if stale_match:
        auth_dict["stale"] = stale_match.group(1).lower() == "true"
    
    return auth_dict


def parse_authorization_header(header_value: str) -> Dict[str, str]:
    """
    Parses Authorization/Proxy-Authorization request header.
    
    RFC 2617 §3.2.1 Digest Response Format:
        Authorization: Digest username="...", realm="...", nonce="...", 
                       uri="...", response="...", opaque="...", algorithm="MD5", qop=auth, nc=00000001, cnonce="..."
    
    Args:
        header_value: The full header value to parse
        
    Returns:
        Dict with parsed digest parameters
    """
    auth_dict = {
        "scheme": "",
        "username": "",
        "realm": "",
        "nonce": "",
        "uri": "",
        "response": "",
        "opaque": "",
        "algorithm": "MD5",
        "qop": "",
        "nc": "",
        "cnonce": "",
    }
    
    if not header_value:
        return auth_dict
    
    # Extract scheme
    scheme_match = re.match(r"(\w+)\s+(.+)", header_value)
    if scheme_match:
        auth_dict["scheme"] = scheme_match.group(1)
        params_str = scheme_match.group(2)
    else:
        return auth_dict
    
    # Parse parameters
    parameters = {
        "username": r'username="([^"]*)"',
        "realm": r'realm="([^"]*)"',
        "nonce": r'nonce="([^"]*)"',
        "uri": r'uri="([^"]*)"',
        "response": r'response="([^"]*)"',
        "opaque": r'opaque="([^"]*)"',
        "cnonce": r'cnonce="([^"]*)"',
    }
    
    for param_name, pattern in parameters.items():
        match = re.search(pattern, params_str)
        if match:
            auth_dict[param_name] = match.group(1)
    
    # Parse unquoted parameters
    algorithm_match = re.search(r'algorithm=([^\s,]+)', params_str)
    if algorithm_match:
        auth_dict["algorithm"] = algorithm_match.group(1).strip('"')
    
    qop_match = re.search(r'qop=(\w+)', params_str)
    if qop_match:
        auth_dict["qop"] = qop_match.group(1)
    
    nc_match = re.search(r'nc=([0-9a-f]+)', params_str)
    if nc_match:
        auth_dict["nc"] = nc_match.group(1)
    
    return auth_dict


def extract_auth_challenges(sip_packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extracts 401/407 authentication challenges from SIP packets.
    
    A 401 Unauthorized response (RFC 3261 §21.4.1) indicates the originating 
    server is challenging authentication.
    A 407 Proxy-Authenticate response (RFC 3261 §21.4.3) indicates a proxy 
    is challenging authentication.
    
    Args:
        sip_packets: List of SIP packet data from tshark extraction
        
    Returns:
        List of auth challenge dicts with packet info, challenge parameters, realms, etc.
    """
    challenges = []
    
    for packet in sip_packets:
        status_code = packet.get("status_code", "")
        
        if status_code == "401":
            www_auth = packet.get("www_authenticate", "")
            if www_auth:
                auth_params = parse_authentication_header(www_auth, "WWW-Authenticate")
                challenges.append({
                    "packet_num": packet.get("packet_num"),
                    "timestamp": packet.get("time"),
                    "status_code": "401",
                    "challenge_type": "server",
                    "from_ip": packet.get("src_ip"),
                    "to_ip": packet.get("dst_ip"),
                    "method": packet.get("method", ""),
                    "call_id": packet.get("call_id"),
                    "realm": auth_params.get("realm", ""),
                    "nonce": auth_params.get("nonce", ""),
                    "algorithm": auth_params.get("algorithm", "MD5"),
                    "qop": auth_params.get("qop", ""),
                    "opaque": auth_params.get("opaque", ""),
                    "stale": auth_params.get("stale", False),
                    "domain": auth_params.get("domain", ""),
                    "full_header": www_auth,
                })
        
        elif status_code == "407":
            proxy_auth = packet.get("proxy_authenticate", "")
            if proxy_auth:
                auth_params = parse_authentication_header(proxy_auth, "Proxy-Authenticate")
                challenges.append({
                    "packet_num": packet.get("packet_num"),
                    "timestamp": packet.get("time"),
                    "status_code": "407",
                    "challenge_type": "proxy",
                    "from_ip": packet.get("src_ip"),
                    "to_ip": packet.get("dst_ip"),
                    "method": packet.get("method", ""),
                    "call_id": packet.get("call_id"),
                    "realm": auth_params.get("realm", ""),
                    "nonce": auth_params.get("nonce", ""),
                    "algorithm": auth_params.get("algorithm", "MD5"),
                    "qop": auth_params.get("qop", ""),
                    "opaque": auth_params.get("opaque", ""),
                    "stale": auth_params.get("stale", False),
                    "domain": auth_params.get("domain", ""),
                    "full_header": proxy_auth,
                })
    
    return challenges


def extract_auth_responses(sip_packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extracts successful authorization responses from SIP packets.
    
    These are packets that include Authorization or Proxy-Authorization headers,
    indicating the client is responding to a previous challenge.
    
    Args:
        sip_packets: List of SIP packet data from tshark extraction
        
    Returns:
        List of auth response dicts with digest parameters and timing info
    """
    responses = []
    
    for packet in sip_packets:
        auth_header = packet.get("authorization", "")
        is_proxy = False
        
        if not auth_header:
            auth_header = packet.get("proxy_authorization", "")
            is_proxy = True
        
        if auth_header:
            auth_params = parse_authorization_header(auth_header)
            responses.append({
                "packet_num": packet.get("packet_num"),
                "timestamp": packet.get("time"),
                "method": packet.get("method", ""),
                "request_uri": packet.get("request_uri", ""),
                "from_ip": packet.get("src_ip"),
                "to_ip": packet.get("dst_ip"),
                "call_id": packet.get("call_id"),
                "is_proxy": is_proxy,
                "username": auth_params.get("username", ""),
                "realm": auth_params.get("realm", ""),
                "nonce": auth_params.get("nonce", ""),
                "uri": auth_params.get("uri", ""),
                "response_hash": auth_params.get("response", "")[:16] + "..." if auth_params.get("response") else "",
                "algorithm": auth_params.get("algorithm", "MD5"),
                "qop": auth_params.get("qop", ""),
                "nc": auth_params.get("nc", ""),
                "cnonce": auth_params.get("cnonce", "")[:8] + "..." if auth_params.get("cnonce") else "",
                "full_header": auth_header[:80] + "..." if len(auth_header) > 80 else auth_header,
            })
    
    return responses


def extract_register_attempts(sip_packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extracts REGISTER request lifecycle information.
    
    RFC 3665 §1 defines the REGISTER flow:
    1. Client sends REGISTER without auth
    2. Server responds with 401 + challenge
    3. Client resends REGISTER with Authorization header
    4. Server responds with 200 OK (success) or error
    
    Args:
        sip_packets: List of SIP packet data from tshark extraction
        
    Returns:
        List of REGISTER attempt sequences showing success/failure
    """
    attempts = []
    register_calls = {}  # Track by call_id to match challenges with responses
    
    for packet in sip_packets:
        method = packet.get("method", "")
        status_code = packet.get("status_code", "")
        call_id = packet.get("call_id", "Unknown")
        
        if method == "REGISTER":
            # Group REGISTER requests by call_id
            if call_id not in register_calls:
                register_calls[call_id] = []
            
            register_calls[call_id].append({
                "packet_num": packet.get("packet_num"),
                "timestamp": packet.get("time"),
                "type": "request",
                "from_ip": packet.get("src_ip"),
                "to_ip": packet.get("dst_ip"),
                "from_addr": packet.get("from_addr", ""),
                "to_addr": packet.get("to_addr", ""),
                "request_uri": packet.get("request_uri", ""),
                "has_auth": bool(packet.get("authorization") or packet.get("proxy_authorization")),
                "expires": packet.get("expires", ""),
                "contact": packet.get("contact", ""),
            })
        
        elif method == "" and (status_code == "401" or status_code == "407") and "REGISTER" in packet.get("cseq_method", ""):
            # This is a challenge response to REGISTER
            if call_id not in register_calls:
                register_calls[call_id] = []
            
            register_calls[call_id].append({
                "packet_num": packet.get("packet_num"),
                "timestamp": packet.get("time"),
                "type": "challenge",
                "status_code": status_code,
                "from_ip": packet.get("src_ip"),
                "to_ip": packet.get("dst_ip"),
                "realm": _extract_realm_from_challenge(packet),
                "nonce": _extract_nonce_from_challenge(packet),
            })
        
        elif status_code == "200" and "REGISTER" in packet.get("cseq_method", ""):
            # This is successful REGISTER response
            if call_id not in register_calls:
                register_calls[call_id] = []
            
            register_calls[call_id].append({
                "packet_num": packet.get("packet_num"),
                "timestamp": packet.get("time"),
                "type": "response",
                "status_code": "200",
                "from_ip": packet.get("src_ip"),
                "to_ip": packet.get("dst_ip"),
                "expires": packet.get("expires", ""),
            })
    
    # Convert grouped data into attempts
    for call_id, packets in register_calls.items():
        if len(packets) > 0:
            attempt = {
                "call_id": call_id,
                "packets": packets,
                "success": any(p.get("status_code") == "200" for p in packets),
                "authenticated": any(p.get("has_auth") for p in packets if p.get("type") == "request"),
                "count": len([p for p in packets if p.get("type") == "request"]),
            }
            attempts.append(attempt)
    
    return attempts


def _extract_realm_from_challenge(packet: Dict[str, Any]) -> str:
    """Helper to extract realm from 401/407 challenge packet."""
    www_auth = packet.get("www_authenticate", "")
    proxy_auth = packet.get("proxy_authenticate", "")
    auth_header = www_auth or proxy_auth
    
    if auth_header:
        realm_match = re.search(r'realm="([^"]*)"', auth_header)
        return realm_match.group(1) if realm_match else ""
    return ""


def _extract_nonce_from_challenge(packet: Dict[str, Any]) -> str:
    """Helper to extract nonce from 401/407 challenge packet."""
    www_auth = packet.get("www_authenticate", "")
    proxy_auth = packet.get("proxy_authenticate", "")
    auth_header = www_auth or proxy_auth
    
    if auth_header:
        nonce_match = re.search(r'nonce="([^"]*)"', auth_header)
        return nonce_match.group(1)[:16] + "..." if nonce_match else ""
    return ""


def _detect_auth_anomalies(
    auth_challenges: List[Dict[str, Any]], 
    register_attempts: List[Dict[str, Any]], 
    auth_responses: List[Dict[str, Any]]
) -> List[str]:
    """
    Detects security and operational anomalies in authentication flows.
    
    Checks for:
    - Excessive 401/407 challenges (>3) indicating credential issues
    - Failed REGISTER attempts (service availability issues)
    - Weak MD5 algorithm usage (security risk)
    - Missing qop parameter (reduced security)
    - Cascading proxy challenges (proxy chain issues)
    
    Args:
        auth_challenges: List of 401/407 challenges
        register_attempts: List of REGISTER attempts
        auth_responses: List of auth response headers
        
    Returns:
        List of anomaly descriptions
    """
    anomalies = []
    
    # Detect excessive challenges (potential brute force or credential issues)
    if len(auth_challenges) > 3:
        anomalies.append(f"⚠️ Excessive authentication challenges detected ({len(auth_challenges)}). May indicate credential issues or replay attacks.")
    
    # Detect failed REGISTER attempts
    failed_attempts = [attempt for attempt in register_attempts if not attempt.get("success")]
    if failed_attempts:
        anomalies.append(f"⚠️ {len(failed_attempts)} REGISTER attempt(s) failed. May indicate registration service issues or credential problems.")
    
    # Detect weak algorithms (MD5)
    weak_algo_challenges = [c for c in auth_challenges if c.get("algorithm", "").upper() in ["MD5", ""]]
    if weak_algo_challenges:
        anomalies.append(f"🔓 Weak authentication algorithm (MD5) detected in {len(weak_algo_challenges)} challenge(s). Consider upgrading to SHA-256.")
    
    # Detect missing qop (lower security)
    no_qop_challenges = [c for c in auth_challenges if not c.get("qop")]
    if no_qop_challenges and len(no_qop_challenges) > len(auth_challenges) / 2:
        anomalies.append(f"🔓 Quality-of-Protection (qop) missing in {len(no_qop_challenges)} challenge(s). Security is reduced without auth-int or replay protection.")
    
    # Detect cascading 407 challenges (proxy chain issues)
    proxy_407_challenges = [c for c in auth_challenges if c.get("status_code") == "407"]
    if len(proxy_407_challenges) > 2:
        anomalies.append(f"⚠️ Cascading proxy challenges detected ({len(proxy_407_challenges)} 407 responses). May indicate proxy chain configuration issues.")
    
    # Detect stale nonce reuse (replay protection issue)
    stale_nonces = [c for c in auth_challenges if c.get("stale")]
    if stale_nonces:
        anomalies.append(f"ℹ️ Stale nonce flag set in {len(stale_nonces)} challenge(s). Server is forcing nonce refresh (normal behavior but affects performance).")
    
    # Detect authentication attempts without successful auth
    if auth_responses and len(auth_responses) > 0 and len(failed_attempts) > 0:
        successful_auths = sum(1 for attempt in register_attempts if attempt.get("authenticated"))
        if successful_auths == 0:
            anomalies.append("⚠️ No successful authenticated REGISTER requests detected. All registration attempts may be failing due to authentication issues.")
    
    return anomalies


def calculate_auth_security_posture(auth_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate overall authentication security posture with letter grade.
    
    Analyzes authentication mechanisms for security best practices and
    assigns a letter grade (A-F) based on algorithm strength, qop usage,
    REGISTER success rates, and other security factors.
    
    Args:
        auth_data: Complete auth data from extract_auth_and_registration_info()
    
    Returns:
        Dictionary with:
            - grade: Letter grade (A+, A, B, C, D, F)
            - score: Numeric score 0-100
            - factors: List of positive security factors
            - risks: List of security risks identified
            - recommendations: List of upgrade suggestions
    """
    score = 100  # Start with perfect score
    factors = []
    risks = []
    recommendations = []
    
    auth_challenges = auth_data.get("auth_challenges", [])
    auth_responses = auth_data.get("auth_responses", [])
    register_attempts = auth_data.get("register_attempts", [])
    
    # No auth data available - neutral score
    if not auth_challenges and not auth_responses:
        return {
            "grade": "N/A",
            "score": 0,
            "factors": ["No authentication activity detected"],
            "risks": [],
            "recommendations": []
        }
    
    # Factor 1: Algorithm strength
    strong_algos = ["SHA-256", "SHA-512"]
    weak_algos = ["MD5", ""]
    
    if auth_challenges:
        strong_count = sum(1 for c in auth_challenges if c.get("algorithm", "").upper() in strong_algos)
        weak_count = sum(1 for c in auth_challenges if c.get("algorithm", "").upper() in weak_algos)
        
        if weak_count > 0:
            penalty = min(25, weak_count * 8)  # Up to 25 points
            score -= penalty
            risks.append(f"Weak algorithm (MD5) in {weak_count} challenge(s)")
            recommendations.append("🔒 Upgrade to SHA-256 or SHA-512 for stronger security")
        else:
            factors.append(f"Strong algorithms ({strong_count} challenge(s) use SHA-256+)")
        
        if strong_count > 0:
            factors.append(f"RFC 3261 best practices: SHA-256+ in {strong_count} challenge(s)")
    
    # Factor 2: QoP (Quality of Protection) usage
    if auth_challenges:
        with_qop = sum(1 for c in auth_challenges if c.get("qop"))
        without_qop = len(auth_challenges) - with_qop
        qop_auth_int = sum(1 for c in auth_challenges if c.get("qop") == "auth-int")
        
        if without_qop > len(auth_challenges) / 2:
            penalty = 15
            score -= penalty
            risks.append(f"Missing qop in {without_qop} challenge(s) - replay protection disabled")
            recommendations.append("🛡️ Enable qop='auth' or 'auth-int' for replay protection")
        elif with_qop > 0:
            if qop_auth_int > 0:
                factors.append(f"Excellent: qop='auth-int' provides message integrity ({qop_auth_int} challenge(s))")
            else:
                factors.append(f"Good: qop='auth' provides replay protection ({with_qop} challenge(s))")
    
    # Factor 3: REGISTER success rate
    if register_attempts:
        successful = sum(1 for r in register_attempts if r.get("success"))
        failed = len(register_attempts) - successful
        success_rate = (successful / len(register_attempts)) * 100 if register_attempts else 0
        
        if failed > 0:
            penalty = min(20, failed * 10)  # Up to 20 points
            score -= penalty
            risks.append(f"{failed} REGISTER attempt(s) failed ({success_rate:.0f}% success rate)")
            recommendations.append(f"⚠️ Investigate failed registrations - verify credentials and service availability")
        else:
            factors.append(f"All REGISTER attempts successful ({successful}/{len(register_attempts)})")
    
    # Factor 4: Challenge/response ratio
    if auth_challenges and auth_responses:
        if len(auth_responses) >= len(auth_challenges):
            factors.append("All challenges received proper authorization responses")
        else:
            unresponded = len(auth_challenges) - len(auth_responses)
            penalty = min(10, unresponded * 5)
            score -= penalty
            risks.append(f"{unresponded} challenge(s) without authorization responses")
    elif auth_challenges and not auth_responses:
        score -= 15
        risks.append("Authentication challenges issued but no responses detected")
        recommendations.append("⚠️ Check client authentication configuration")
    
    # Factor 5: Cascading proxy challenges
    proxy_407_count = sum(1 for c in auth_challenges if c.get("status_code") == "407")
    if proxy_407_count > 2:
        penalty = min(10, (proxy_407_count - 2) * 3)
        score -= penalty
        risks.append(f"Cascading proxy authentication ({proxy_407_count} 407 challenges)")
        recommendations.append("🔧 Review SIP proxy chain configuration - reduce cascading challenges")
    
    # Factor 6: Excessive challenges (potential attack or misconfiguration)
    if len(auth_challenges) > 5:
        penalty = min(10, (len(auth_challenges) - 5) * 2)
        score -= penalty
        risks.append(f"Excessive authentication challenges ({len(auth_challenges)} total)")
        recommendations.append("🔍 Investigate excessive auth challenges - may indicate attack or misconfiguration")
    
    # Ensure score is in valid range
    score = max(0, min(100, score))
    
    # Assign letter grade
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    
    return {
        "grade": grade,
        "score": score,
        "factors": factors,
        "risks": risks,
        "recommendations": recommendations
    }


def generate_auth_upgrade_recommendations(auth_data: Dict[str, Any]) -> List[str]:
    """
    Generate specific upgrade recommendations based on authentication analysis.
    
    Provides actionable recommendations for improving authentication security,
    including algorithm upgrades, qop enablement, and configuration fixes.
    
    Args:
        auth_data: Complete auth data from extract_auth_and_registration_info()
    
    Returns:
        List of recommendation strings with emoji indicators
    """
    recommendations = []
    
    auth_challenges = auth_data.get("auth_challenges", [])
    auth_responses = auth_data.get("auth_responses", [])
    register_attempts = auth_data.get("register_attempts", [])
    
    # No data - no recommendations
    if not auth_challenges and not auth_responses:
        return recommendations
    
    # Recommendation 1: Upgrade from MD5
    weak_algo = [c for c in auth_challenges if c.get("algorithm", "").upper() in ["MD5", ""]]
    if weak_algo:
        recommendations.append(
            f"🔒 **Upgrade Authentication Algorithm**: Replace MD5 with SHA-256 or SHA-512 "
            f"on {len(weak_algo)} challenge(s) for enhanced security (RFC 3261 §22.4)"
        )
    
    # Recommendation 2: Enable qop
    no_qop = [c for c in auth_challenges if not c.get("qop")]
    if no_qop and len(no_qop) > len(auth_challenges) / 2:
        recommendations.append(
            f"🛡️ **Enable Quality-of-Protection**: Add qop='auth' or qop='auth-int' "
            f"to {len(no_qop)} challenge(s) for replay protection (RFC 2617 §3.2.1)"
        )
    
    # Recommendation 3: Fix cascading 407s
    proxy_407 = [c for c in auth_challenges if c.get("status_code") == "407"]
    if len(proxy_407) > 2:
        recommendations.append(
            f"🔧 **Optimize Proxy Chain**: Reduce cascading 407 challenges "
            f"({len(proxy_407)} detected) - consolidate proxy authentication or review topology"
        )
    
    # Recommendation 4: Address failed registrations
    failed_regs = [r for r in register_attempts if not r.get("success")]
    if failed_regs:
        recommendations.append(
            f"⚠️ **Fix REGISTER Failures**: Investigate {len(failed_regs)} failed registration(s) - "
            f"verify credentials, realm configuration, and service availability"
        )
    
    # Recommendation 5: Address missing responses
    if auth_challenges and not auth_responses:
        recommendations.append(
            "🔍 **Client Configuration Issue**: Authentication challenges issued but no responses detected - "
            "verify client is properly configured with credentials"
        )
    elif auth_challenges and auth_responses and len(auth_responses) < len(auth_challenges):
        unresponded = len(auth_challenges) - len(auth_responses)
        recommendations.append(
            f"📋 **Incomplete Auth Flow**: {unresponded} challenge(s) without responses - "
            f"review client logs for authentication errors"
        )
    
    # Recommendation 6: Excessive challenges
    if len(auth_challenges) > 5:
        recommendations.append(
            f"🚨 **Excessive Challenges**: {len(auth_challenges)} authentication challenges detected - "
            f"investigate for credential issues, replay attacks, or clock skew problems"
        )
    
    return recommendations

