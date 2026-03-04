#!/usr/bin/env python3
"""
S.O.N.I.C. Data Models - Pydantic schemas for SIP diagnostic reports

This module defines the structured data models used throughout S.O.N.I.C. for 
representing SIP diagnostic information, call quality metrics, and analysis results.

Models:
- AudioQualityDiagnostic: Audio codec and RTP quality information
- CallFlow: SIP call setup and termination analysis  
- CallDiagnostic: Complete diagnostic data for a single call
- SipDiagnosticReport: Top-level diagnostic report structure

Author: Raymond A Rizzo | Zombat
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class AudioQualityDiagnostic(BaseModel):
    """
    Audio quality indicators for diagnosing choppy audio issues.
    
    This model captures information about audio codecs, RTP configuration,
    and potential quality issues that could affect call audio.
    
    Codec Quality Analysis:
    - G.711 (PCMU/PCMA): High quality (64 kbps), high bandwidth usage
    - G.729: Moderate quality (8 kbps), efficient bandwidth usage  
    - Opus: Adaptive quality (6-510 kbps), excellent modern codec
    - iLBC: Low bitrate (13.3/15.2 kbps), packet loss resistant
    
    Common Issues by Codec:
    - G.711: Network congestion due to high bandwidth
    - G.729: Quality degradation with poor implementations
    - Opus: Configuration mismatches between endpoints
    - iLBC: Limited availability, compatibility issues
    
    Attributes:
        codec_used: Primary audio codec (PCMU, PCMA, G729, Opus, iLBC, etc.)
        payload_types: All RTP payload types negotiated during SDP exchange
        rtp_port: Port number used for RTP audio stream
        potential_issues: List of identified audio quality problems
    """
    codec_used: str = Field(..., description="Primary audio codec used in the call (e.g., PCMU, PCMA, G729, Opus, iLBC)", alias="codecUsed")
    payload_types: List[str] = Field(default=[], description="All RTP payload types negotiated", alias="payloadTypes")
    rtp_port: str = Field(default="Unknown", description="RTP port used for audio stream", alias="rtpPort")
    potential_issues: List[str] = Field(default=[], description="Identified potential audio quality issues", alias="potentialIssues")

    class Config:
        populate_by_name = True


class CallFlow(BaseModel):
    """
    Represents the flow and termination of a SIP call for disconnect analysis.
    
    This model tracks how calls are established, maintained, and terminated,
    helping identify premature disconnects and call setup failures.
    
    Attributes:
        call_setup_method: SIP method used to initiate the call (usually INVITE)
        call_termination: How/why the call ended (BYE, timeout, error response)
        response_codes: All SIP response codes observed during the call
        call_duration_indicators: Analysis of call timing and duration patterns
        initiator_ip: IP address of the party who sent the INVITE
        terminator_ip: IP address of the party who sent the BYE or error response
        disconnect_code: Specific disconnect code (BYE, 486, 487, etc.)
        hangup_pattern: Who hung up relative to who initiated (initiator/recipient)
    """
    call_setup_method: str = Field(..., description="How the call was initiated (INVITE, etc.)", alias="callSetupMethod")
    call_termination: Optional[str] = Field(default="Unknown", description="How/why the call ended (BYE, timeout, error)", alias="callTermination")
    response_codes: List[str] = Field(default=[], description="SIP response codes seen (200 OK, 486 Busy, etc.)", alias="responseCodes")
    call_duration_indicators: str = Field(default="Unknown", description="Indicators of call duration or early termination", alias="callDurationIndicators")
    
    # Enhanced call tracking fields
    initiator_ip: Optional[str] = Field(default=None, description="IP address of the party who initiated the call", alias="initiatorIp")
    terminator_ip: Optional[str] = Field(default=None, description="IP address of the party who terminated the call", alias="terminatorIp")
    disconnect_code: Optional[str] = Field(default=None, description="Specific disconnect code (BYE, 486, 487, etc.)", alias="disconnectCode")
    hangup_pattern: Optional[str] = Field(default=None, description="Who hung up: 'Initiator hung up' or 'Recipient hung up'", alias="hangupPattern")

    @field_validator('call_termination', mode='before')
    @classmethod
    def handle_null_termination(cls, v):
        """Handle null termination values from AI models"""
        return v if v is not None else "Unknown"

    class Config:
        populate_by_name = True


class CallDiagnostic(BaseModel):
    """
    Complete diagnostic information for a single SIP call.
    
    This is the primary data structure containing all diagnostic information
    for an individual call, including endpoints, audio analysis, and call flow.
    
    Attributes:
        call_id: Unique SIP Call-ID header value
        caller_ip: IP address of the calling party (INVITE sender)
        callee_ip: IP address of the called party (INVITE receiver)
        user_agents: User-Agent headers from both endpoints
        audio_quality: Audio-related diagnostic information
        call_flow: Call setup and termination analysis
        diagnostic_summary: Human-readable summary of identified issues
    """
    call_id: str = Field(..., description="The unique Call-ID for the SIP call.", alias="callId")
    caller_ip: str = Field(..., description="IP address of the caller (INVITE sender)", alias="callerIp")
    callee_ip: str = Field(..., description="IP address of the callee (INVITE receiver)", alias="calleeIp")
    user_agents: List[str] = Field(default=[], description="User-Agent headers from both endpoints", alias="userAgents")
    audio_quality: AudioQualityDiagnostic = Field(..., description="Audio quality diagnostic information", alias="audioQuality")
    network_baseline: dict = Field(default={}, description="TCP network baseline analysis for VoIP quality planning", alias="networkBaseline")
    call_flow: CallFlow = Field(..., description="Call setup and termination analysis", alias="callFlow")
    diagnostic_summary: str = Field(..., description="Summary of potential issues found in this call", alias="diagnosticSummary")

    class Config:
        populate_by_name = True


class AuthenticationMetrics(BaseModel):
    """
    SIP Authentication and Registration metrics.
    
    Tracks authentication challenges (401/407), responses, and REGISTER flows
    per RFC 3261 (SIP), RFC 2617 (Digest Authentication), and RFC 3665 (REGISTER).
    
    Security Analysis includes detection of:
    - Excessive authentication challenges (potential credential issues)
    - Failed REGISTER attempts (service outages)
    - Weak algorithms (MD5 vs SHA-256)
    - Missing qop parameters (reduced security)
    - Stale nonce reuse patterns
    
    Attributes:
        total_challenges: Count of 401/407 Unauthorized responses
        total_auth_responses: Count of successful Authorization headers sent
        register_attempts: Count of REGISTER requests sent
        register_success_rate: Percentage of REGISTER requests that succeeded
        unique_realms: List of distinct authentication realms detected
        servers: Dict mapping server IPs to their challenge counts
        weak_algorithms_detected: Whether MD5 or unspecified algorithms present
        qop_usage: Whether quality-of-protection is used in challenges
        anomalies: List of detected authentication anomalies
    """
    total_challenges: int = Field(default=0, description="Count of 401/407 auth challenges", alias="totalChallenges")
    server_challenges: int = Field(default=0, description="Count of 401 Unauthorized (server-side)", alias="serverChallenges")
    proxy_challenges: int = Field(default=0, description="Count of 407 Proxy-Authenticate (proxy-side)", alias="proxyChallenges")
    total_auth_responses: int = Field(default=0, description="Count of Authorization headers sent", alias="totalAuthResponses")
    register_attempts: int = Field(default=0, description="Count of REGISTER requests", alias="registerAttempts")
    register_successes: int = Field(default=0, description="Count of successful 200 OK REGISTER responses", alias="registerSuccesses")
    register_failures: int = Field(default=0, description="Count of failed REGISTER responses (4xx/5xx)", alias="registerFailures")
    
    unique_realms: List[str] = Field(default=[], description="List of authentication realms detected", alias="uniqueRealms")
    servers: Dict[str, int] = Field(default={}, description="Map of server IP to challenge count", alias="servers")
    
    weak_algorithms: List[str] = Field(default=[], description="Weak algorithms detected (MD5, unspecified)", alias="weakAlgorithms")
    qop_usage_count: int = Field(default=0, description="Count of challenges with qop parameter", alias="qopUsageCount")
    
    authentication_anomalies: List[str] = Field(
        default=[], 
        description="Security issues detected in auth flow",
        alias="authenticationAnomalies"
    )
    
    # Detailed lists for analysis
    challenges_detail: List[Dict[str, Any]] = Field(
        default=[], 
        description="Detailed list of auth challenges with realms and algorithms",
        alias="challengesDetail"
    )
    register_detail: List[Dict[str, Any]] = Field(
        default=[],
        description="Detailed REGISTER attempt sequences",
        alias="registerDetail"
    )

    class Config:
        populate_by_name = True



    """
    Comprehensive SIP diagnostic report focused on call quality issues.
    
    This is the top-level report structure that contains analysis for all calls
    found in a packet capture, along with overall assessment and recommendations.
    
    Attributes:
        total_calls_analyzed: Number of unique calls identified in the capture
        calls: List of individual call diagnostics
        overall_assessment: High-level analysis of capture contents
        recommendations: Specific actions to resolve identified issues
    """
    total_calls_analyzed: int = Field(..., description="Number of unique calls found in capture", alias="totalCalls")
    calls: List[CallDiagnostic] = Field(..., description="Detailed diagnostics for each call", alias="calls")
    overall_assessment: str = Field(..., description="Overall assessment of call quality and common issues found", alias="overallAssessment")
    recommendations: List[str] = Field(default=[], description="Specific recommendations to resolve identified issues", alias="recommendations")

    class Config:
        populate_by_name = True
