#!/usr/bin/env python3
"""
S.O.N.I.C. Advanced Call Quality Scoring System

This module provides comprehensive call quality scoring based on multiple VoIP metrics
including network performance, codec efficiency, call setup success, and error patterns.

The scoring system uses a weighted approach combining:
- Network Quality (40%): RTP metrics, QoS, jitter, packet loss
- Protocol Quality (30%): SIP success rates, response times, error patterns  
- Codec Efficiency (20%): Bandwidth usage, compression quality, compatibility
- Call Completion (10%): Setup success, normal termination, duration metrics

Author: Raymond A Rizzo | Zombat
"""

import json
import math
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class QualityGrade(Enum):
    """Call quality grade classifications"""
    EXCELLENT = "A+"  # 90-100
    VERY_GOOD = "A"   # 80-89
    GOOD = "B"        # 70-79
    FAIR = "C"        # 60-69
    POOR = "D"        # 40-59
    FAILED = "F"      # 0-39


@dataclass
class QualityMetrics:
    """Individual quality metric scores"""
    network_score: float = 0.0
    protocol_score: float = 0.0
    codec_score: float = 0.0
    completion_score: float = 0.0
    overall_score: float = 0.0
    grade: QualityGrade = QualityGrade.FAILED
    
    # Detailed breakdowns
    network_details: Dict[str, float] = None
    protocol_details: Dict[str, float] = None
    codec_details: Dict[str, float] = None
    completion_details: Dict[str, float] = None
    
    # Quality factors
    quality_factors: List[str] = None
    degradation_factors: List[str] = None


class CallQualityScorer:
    """Advanced call quality scoring engine"""
    
    # Scoring weights
    WEIGHTS = {
        'network': 0.40,      # Network performance is most critical
        'protocol': 0.30,     # SIP protocol handling
        'codec': 0.20,        # Audio codec efficiency
        'completion': 0.10    # Call completion success
    }
    
    # Quality thresholds for network metrics
    NETWORK_THRESHOLDS = {
        'packet_loss': {'excellent': 0.0, 'good': 1.0, 'fair': 3.0, 'poor': 5.0},
        'jitter': {'excellent': 10, 'good': 20, 'fair': 50, 'poor': 100},  # ms
        'latency': {'excellent': 50, 'good': 100, 'fair': 200, 'poor': 400},  # ms
        'mos_score': {'excellent': 4.5, 'good': 4.0, 'fair': 3.5, 'poor': 2.5}
    }
    
    # Codec quality ratings
    CODEC_RATINGS = {
        'G.711': {'quality': 95, 'efficiency': 60, 'compatibility': 100},
        'G.722': {'quality': 90, 'efficiency': 70, 'compatibility': 85},
        'G.729': {'quality': 85, 'efficiency': 95, 'compatibility': 90},
        'Opus': {'quality': 98, 'efficiency': 90, 'compatibility': 70},
        'iLBC': {'quality': 75, 'efficiency': 85, 'compatibility': 80},
        'Unknown': {'quality': 50, 'efficiency': 50, 'compatibility': 50}
    }
    
    def __init__(self):
        self.quality_factors = []
        self.degradation_factors = []
    
    def score_call_quality(
        self,
        sip_data: str,
        call_sessions: List[Dict],
        network_analysis: Dict = None,
        file_path: str = None,
        auth_data: Dict[str, Any] = None,
    ) -> QualityMetrics:
        """
        Calculate comprehensive call quality score.
        
        Args:
            sip_data: Raw SIP packet data
            call_sessions: List of call session tracking data
            network_analysis: Network quality analysis results
            file_path: Path to packet capture for additional analysis
            auth_data: Extracted authentication diagnostics from extractors/auth_info.py
            
        Returns:
            QualityMetrics: Complete quality assessment with scores and details
        """
        self.quality_factors = []
        self.degradation_factors = []
        
        # Parse SIP data
        try:
            parsed_data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
        except:
            parsed_data = {}
        
        # Calculate individual scores
        network_score, network_details = self._score_network_quality(parsed_data, network_analysis)
        protocol_score, protocol_details = self._score_protocol_quality(parsed_data, call_sessions, auth_data)
        codec_score, codec_details = self._score_codec_quality(parsed_data)
        completion_score, completion_details = self._score_call_completion(call_sessions)
        
        # Calculate weighted overall score
        overall_score = (
            network_score * self.WEIGHTS['network'] +
            protocol_score * self.WEIGHTS['protocol'] +
            codec_score * self.WEIGHTS['codec'] +
            completion_score * self.WEIGHTS['completion']
        )
        
        # Determine quality grade
        grade = self._determine_grade(overall_score)
        
        return QualityMetrics(
            network_score=network_score,
            protocol_score=protocol_score,
            codec_score=codec_score,
            completion_score=completion_score,
            overall_score=overall_score,
            grade=grade,
            network_details=network_details,
            protocol_details=protocol_details,
            codec_details=codec_details,
            completion_details=completion_details,
            quality_factors=self.quality_factors.copy(),
            degradation_factors=self.degradation_factors.copy()
        )
    
    def _score_network_quality(self, parsed_data: Dict, network_analysis: Dict = None) -> Tuple[float, Dict]:
        """Score network performance metrics (40% weight)"""
        details = {
            'qos_markings': 0.0,
            'rtp_streams': 0.0,
            'packet_loss': 100.0,  # Default to perfect if no data
            'jitter': 100.0,
            'baseline_health': 0.0
        }
        
        score = 0.0
        factors_count = 0
        
        # QoS markings analysis
        if network_analysis and 'real_issues_detected' in network_analysis:
            qos_issues = [issue for issue in network_analysis['real_issues_detected'] 
                         if 'QoS' in issue]
            if not qos_issues:
                details['qos_markings'] = 100.0
                self.quality_factors.append("✅ Proper QoS markings detected")
            else:
                details['qos_markings'] = max(0, 100 - len(qos_issues) * 25)
                for issue in qos_issues:
                    self.degradation_factors.append(f"❌ {issue}")
            score += details['qos_markings']
            factors_count += 1
        
        # RTP stream analysis
        rtp_streams = parsed_data.get('rtp_streams', [])
        if rtp_streams:
            details['rtp_streams'] = 90.0  # Good if RTP streams present
            self.quality_factors.append(f"✅ {len(rtp_streams)} RTP streams detected")
            score += details['rtp_streams']
        else:
            details['rtp_streams'] = 30.0  # Lower score if no RTP
            self.degradation_factors.append("⚠️ No RTP streams detected")
            score += details['rtp_streams']
        factors_count += 1
        
        # TCP baseline health (if available)
        if network_analysis and 'tcp_baseline_analysis' in network_analysis:
            tcp_baseline = network_analysis['tcp_baseline_analysis']
            health_score = tcp_baseline.get('health_score', 50)
            details['baseline_health'] = health_score
            
            if health_score >= 90:
                self.quality_factors.append("✅ Excellent network baseline health")
            elif health_score >= 70:
                self.quality_factors.append("👍 Good network baseline health")
            else:
                self.degradation_factors.append(f"⚠️ Network baseline health: {health_score}/100")
            
            score += health_score
            factors_count += 1
        
        # Calculate average score
        if factors_count > 0:
            return score / factors_count, details
        else:
            return 50.0, details  # Default neutral score
    
    def _score_protocol_quality(
        self,
        parsed_data: Dict,
        call_sessions: List[Dict],
        auth_data: Dict[str, Any] = None,
    ) -> Tuple[float, Dict]:
        """Score SIP protocol handling quality (30% weight)"""
        details = {
            'response_success': 100.0,
            'error_rate': 100.0,
            'setup_efficiency': 100.0,
            'authentication': 100.0,
            'auth_penalty': 0.0,
            'auth_challenges_401': 0.0,
            'auth_challenges_407': 0.0,
            'register_failures': 0.0,
            'auth_responses': 0.0,
        }
        
        # Analyze response codes
        total_responses = 0
        success_responses = 0
        error_responses = 0
        auth_challenges = 0
        
        sip_packets = parsed_data.get('sip_packets', parsed_data.get('sip_messages', []))
        
        for msg in sip_packets:
            status_code = msg.get('status_code')
            if status_code:
                total_responses += 1
                status_code_str = str(status_code)
                if status_code_str.startswith('2'):  # 2xx success
                    success_responses += 1
                elif status_code_str in ('401', '407'):
                    auth_challenges += 1
                    error_responses += 1
                elif status_code_str.startswith(('4', '5')):  # 4xx/5xx errors
                    error_responses += 1
        
        # Response success rate
        if total_responses > 0:
            success_rate = (success_responses / total_responses) * 100
            details['response_success'] = success_rate
            
            if success_rate >= 95:
                self.quality_factors.append("✅ Excellent SIP response success rate")
            elif success_rate >= 80:
                self.quality_factors.append("👍 Good SIP response success rate")
            else:
                self.degradation_factors.append(f"⚠️ Low SIP success rate: {success_rate:.1f}%")
        
        # Error rate analysis
        if total_responses > 0:
            error_rate = (error_responses / total_responses) * 100
            details['error_rate'] = max(0, 100 - error_rate * 2)  # Penalty for errors
            
            if error_rate == 0:
                self.quality_factors.append("✅ No SIP protocol errors")
            elif error_rate < 5:
                self.quality_factors.append("👍 Low SIP error rate")
            else:
                self.degradation_factors.append(f"❌ High SIP error rate: {error_rate:.1f}%")
        
        # Authentication diagnostics and penalties (Phase 2)
        auth_score, auth_details = self._analyze_authentication_security(parsed_data, auth_data)
        details['authentication'] = auth_score
        details['auth_penalty'] = auth_details['total_penalty']
        details['auth_challenges_401'] = auth_details['challenges_401']
        details['auth_challenges_407'] = auth_details['challenges_407']
        details['register_failures'] = auth_details['register_failures']
        details['auth_responses'] = auth_details['auth_responses']
        
        # Call setup efficiency (based on session completeness)
        complete_calls = len([s for s in call_sessions if s.get('complete_session', False)])
        total_calls = len(call_sessions)
        
        if total_calls > 0:
            completion_rate = (complete_calls / total_calls) * 100
            details['setup_efficiency'] = completion_rate
            
            if completion_rate >= 90:
                self.quality_factors.append("✅ Excellent call setup efficiency")
            elif completion_rate >= 70:
                self.quality_factors.append("👍 Good call setup efficiency")
            else:
                self.degradation_factors.append(f"⚠️ Poor call setup efficiency: {completion_rate:.1f}%")
        
        # Calculate weighted protocol score
        protocol_score = (
            details['response_success'] * 0.4 +
            details['error_rate'] * 0.3 +
            details['setup_efficiency'] * 0.2 +
            details['authentication'] * 0.1
        )
        
        return protocol_score, details

    def _analyze_authentication_security(
        self,
        parsed_data: Dict[str, Any],
        auth_data: Dict[str, Any] = None,
    ) -> Tuple[float, Dict[str, float]]:
        """Analyze SIP auth behavior and apply Phase 2 security penalties."""
        score = 100.0
        total_penalty = 0.0

        challenges_401 = 0
        challenges_407 = 0
        register_failures = 0
        auth_responses = 0
        weak_algorithm_count = 0
        missing_qop_count = 0

        if auth_data:
            challenges = auth_data.get('auth_challenges', [])
            register_attempts = auth_data.get('register_attempts', [])
            responses = auth_data.get('auth_responses', [])

            challenges_401 = sum(1 for challenge in challenges if str(challenge.get('status_code')) == '401')
            challenges_407 = sum(1 for challenge in challenges if str(challenge.get('status_code')) == '407')
            auth_responses = len(responses)
            register_failures = sum(1 for attempt in register_attempts if not attempt.get('success', False))
            weak_algorithm_count = sum(
                1 for challenge in challenges
                if str(challenge.get('algorithm', '')).upper() in ('', 'MD5')
            )
            missing_qop_count = sum(1 for challenge in challenges if not challenge.get('qop'))
        else:
            sip_packets = parsed_data.get('sip_packets', parsed_data.get('sip_messages', []))
            challenges_401 = sum(1 for packet in sip_packets if str(packet.get('status_code')) == '401')
            challenges_407 = sum(1 for packet in sip_packets if str(packet.get('status_code')) == '407')
            auth_responses = sum(
                1
                for packet in sip_packets
                if packet.get('authorization') or packet.get('proxy_authorization')
            )

        total_challenges = challenges_401 + challenges_407

        if total_challenges > 0:
            self.quality_factors.append("🔐 SIP authentication in use")

        if total_challenges > 3:
            total_penalty += 15.0
            self.degradation_factors.append(f"❌ Excessive auth challenges detected: {total_challenges}")

        if register_failures > 0:
            total_penalty += 20.0
            self.degradation_factors.append(f"❌ Failed REGISTER attempts: {register_failures}")

        if challenges_407 > 2:
            total_penalty += 10.0
            self.degradation_factors.append(f"⚠️ Cascading proxy auth challenges (407): {challenges_407}")

        if weak_algorithm_count > 0:
            total_penalty += 5.0
            self.degradation_factors.append("🔓 Weak digest algorithm detected (MD5/unspecified)")

        if total_challenges > 0 and missing_qop_count > (total_challenges / 2):
            total_penalty += 10.0
            self.degradation_factors.append("🔓 Missing qop in majority of auth challenges")

        if total_challenges > 0 and auth_responses == 0:
            total_penalty += 10.0
            self.degradation_factors.append("❌ Auth challenges present without Authorization responses")

        if total_penalty == 0 and total_challenges > 0:
            self.quality_factors.append("✅ Authentication flow appears healthy")

        score = max(0.0, score - total_penalty)
        return score, {
            'total_penalty': total_penalty,
            'challenges_401': float(challenges_401),
            'challenges_407': float(challenges_407),
            'register_failures': float(register_failures),
            'auth_responses': float(auth_responses),
        }
    
    def _score_codec_quality(self, parsed_data: Dict) -> Tuple[float, Dict]:
        """Score audio codec quality and efficiency (20% weight)"""
        details = {
            'codec_quality': 50.0,
            'bandwidth_efficiency': 50.0,
            'compatibility': 50.0,
            'negotiation': 100.0
        }
        
        # Extract codec information
        codecs_used = set()
        sdp_sessions = parsed_data.get('sdp_sessions', [])
        
        for session in sdp_sessions:
            media_lines = session.get('media', [])
            for media in media_lines:
                if media.get('media_type') == 'audio':
                    payload_types = media.get('payload_types', [])
                    for pt in payload_types:
                        codec_name = self._map_payload_to_codec(pt)
                        if codec_name:
                            codecs_used.add(codec_name)
        
        if not codecs_used:
            # Try alternative extraction
            rtp_streams = parsed_data.get('rtp_streams', [])
            for stream in rtp_streams:
                pt = stream.get('payload_type')
                if pt:
                    codec_name = self._map_payload_to_codec(pt)
                    if codec_name:
                        codecs_used.add(codec_name)
        
        if codecs_used:
            # Calculate weighted codec scores
            total_quality = 0
            total_efficiency = 0
            total_compatibility = 0
            
            for codec in codecs_used:
                rating = self.CODEC_RATINGS.get(codec, self.CODEC_RATINGS['Unknown'])
                total_quality += rating['quality']
                total_efficiency += rating['efficiency']
                total_compatibility += rating['compatibility']
            
            codec_count = len(codecs_used)
            details['codec_quality'] = total_quality / codec_count
            details['bandwidth_efficiency'] = total_efficiency / codec_count
            details['compatibility'] = total_compatibility / codec_count
            
            # Add quality factors
            if len(codecs_used) == 1:
                codec = list(codecs_used)[0]
                if codec in ['G.711', 'Opus']:
                    self.quality_factors.append(f"✅ High-quality codec in use: {codec}")
                elif codec == 'G.729':
                    self.quality_factors.append(f"💪 Bandwidth-efficient codec: {codec}")
            else:
                self.quality_factors.append(f"🔄 Multiple codecs negotiated: {', '.join(codecs_used)}")
                
            # Negotiation penalty for too many codecs
            if len(codecs_used) > 3:
                details['negotiation'] = 80.0
                self.degradation_factors.append("⚠️ Excessive codec diversity may cause issues")
        
        # Calculate weighted codec score
        codec_score = (
            details['codec_quality'] * 0.5 +
            details['bandwidth_efficiency'] * 0.3 +
            details['compatibility'] * 0.15 +
            details['negotiation'] * 0.05
        )
        
        return codec_score, details
    
    def _score_call_completion(self, call_sessions: List[Dict]) -> Tuple[float, Dict]:
        """Score call completion and termination quality (10% weight)"""
        details = {
            'setup_success': 100.0,
            'normal_termination': 100.0,
            'session_completeness': 100.0,
            'duration_quality': 100.0
        }
        
        if not call_sessions:
            return 50.0, details
        
        total_calls = len(call_sessions)
        complete_calls = 0
        normal_terminations = 0
        error_terminations = 0
        
        for session in call_sessions:
            # Check session completeness
            if session.get('complete_session', False):
                complete_calls += 1
                self.quality_factors.append("✅ Complete call session tracked")
            
            # Check termination type
            disconnect_code = session.get('disconnect_code')
            if disconnect_code:
                if str(disconnect_code).startswith('2'):  # 2xx normal
                    normal_terminations += 1
                else:
                    error_terminations += 1
                    self.degradation_factors.append(f"❌ Error termination: {disconnect_code}")
        
        # Calculate completion metrics
        if total_calls > 0:
            details['session_completeness'] = (complete_calls / total_calls) * 100
            
            if complete_calls == total_calls:
                self.quality_factors.append("✅ All call sessions complete")
            elif complete_calls / total_calls >= 0.8:
                self.quality_factors.append("👍 Most call sessions complete")
            else:
                self.degradation_factors.append("⚠️ Many incomplete call sessions")
        
        # Normal termination rate
        if normal_terminations + error_terminations > 0:
            termination_rate = (normal_terminations / (normal_terminations + error_terminations)) * 100
            details['normal_termination'] = termination_rate
            
            if termination_rate >= 95:
                self.quality_factors.append("✅ Excellent call termination success")
            elif termination_rate >= 80:
                self.quality_factors.append("👍 Good call termination rate")
            else:
                self.degradation_factors.append(f"⚠️ High error termination rate: {100-termination_rate:.1f}%")
        
        # Calculate completion score
        completion_score = (
            details['setup_success'] * 0.3 +
            details['normal_termination'] * 0.4 +
            details['session_completeness'] * 0.3
        )
        
        return completion_score, details
    
    def _map_payload_to_codec(self, payload_type: str) -> str:
        """Map RTP payload type to codec name"""
        pt_map = {
            '0': 'G.711',     # PCMU
            '8': 'G.711',     # PCMA
            '9': 'G.722',     # G.722
            '18': 'G.729',    # G.729
        }
        return pt_map.get(str(payload_type), 'Unknown')
    
    def _determine_grade(self, score: float) -> QualityGrade:
        """Convert numeric score to quality grade"""
        if score >= 90:
            return QualityGrade.EXCELLENT
        elif score >= 80:
            return QualityGrade.VERY_GOOD
        elif score >= 70:
            return QualityGrade.GOOD
        elif score >= 60:
            return QualityGrade.FAIR
        elif score >= 40:
            return QualityGrade.POOR
        else:
            return QualityGrade.FAILED


def print_quality_score_analysis(quality_metrics: QualityMetrics, file_path: str = None):
    """
    Print comprehensive call quality score analysis.
    
    Args:
        quality_metrics: Quality assessment results
        file_path: Optional file path for context
    """
    print("\n" + "="*80)
    print("📊 CALL QUALITY SCORE ANALYSIS")
    print("="*80)
    
    # Overall score and grade
    print(f"\n🎯 OVERALL QUALITY SCORE: {quality_metrics.overall_score:.1f}/100")
    print(f"🏆 QUALITY GRADE: {quality_metrics.grade.value}")
    
    # Grade description
    grade_descriptions = {
        QualityGrade.EXCELLENT: "🌟 Outstanding call quality - enterprise grade",
        QualityGrade.VERY_GOOD: "✨ Very good quality - minor optimization opportunities",
        QualityGrade.GOOD: "👍 Good quality - some improvements recommended",
        QualityGrade.FAIR: "⚠️ Fair quality - several issues need attention",
        QualityGrade.POOR: "🔧 Poor quality - significant improvements required",
        QualityGrade.FAILED: "❌ Failed quality - major issues require immediate attention"
    }
    print(f"   {grade_descriptions[quality_metrics.grade]}")
    
    # Individual component scores
    print(f"\n📋 COMPONENT SCORES:")
    print(f"   🌐 Network Quality:     {quality_metrics.network_score:.1f}/100 (40% weight)")
    print(f"   📞 Protocol Quality:    {quality_metrics.protocol_score:.1f}/100 (30% weight)")
    print(f"   🎵 Codec Efficiency:    {quality_metrics.codec_score:.1f}/100 (20% weight)")
    print(f"   ✅ Call Completion:     {quality_metrics.completion_score:.1f}/100 (10% weight)")
    
    # Quality factors (positive aspects)
    if quality_metrics.quality_factors:
        print(f"\n🌟 QUALITY FACTORS:")
        for factor in quality_metrics.quality_factors[:10]:  # Show top 10
            print(f"   {factor}")
        if len(quality_metrics.quality_factors) > 10:
            print(f"   ... and {len(quality_metrics.quality_factors) - 10} more positive factors")
    
    # Degradation factors (issues)
    if quality_metrics.degradation_factors:
        print(f"\n⚠️ DEGRADATION FACTORS:")
        for factor in quality_metrics.degradation_factors[:10]:  # Show top 10
            print(f"   {factor}")
        if len(quality_metrics.degradation_factors) > 10:
            print(f"   ... and {len(quality_metrics.degradation_factors) - 10} more issues")
    
    # Detailed breakdowns
    if quality_metrics.network_details:
        print(f"\n🌐 NETWORK QUALITY BREAKDOWN:")
        for metric, score in quality_metrics.network_details.items():
            print(f"   {metric.replace('_', ' ').title()}: {score:.1f}/100")
    
    if quality_metrics.protocol_details:
        print(f"\n📞 PROTOCOL QUALITY BREAKDOWN:")
        for metric, score in quality_metrics.protocol_details.items():
            print(f"   {metric.replace('_', ' ').title()}: {score:.1f}/100")
    
    if quality_metrics.codec_details:
        print(f"\n🎵 CODEC EFFICIENCY BREAKDOWN:")
        for metric, score in quality_metrics.codec_details.items():
            print(f"   {metric.replace('_', ' ').title()}: {score:.1f}/100")
    
    if quality_metrics.completion_details:
        print(f"\n✅ CALL COMPLETION BREAKDOWN:")
        for metric, score in quality_metrics.completion_details.items():
            print(f"   {metric.replace('_', ' ').title()}: {score:.1f}/100")
    
    # Recommendations based on score
    print(f"\n💡 QUALITY IMPROVEMENT RECOMMENDATIONS:")
    if quality_metrics.overall_score >= 90:
        print("   🎉 Excellent quality! Monitor for consistency and consider:")
        print("   • Regular quality audits to maintain standards")
        print("   • Documentation of successful configuration")
        print("   • Sharing best practices with other systems")
    elif quality_metrics.overall_score >= 70:
        print("   🔧 Good foundation with optimization opportunities:")
        print("   • Address any degradation factors listed above")
        print("   • Fine-tune QoS markings if network score is low")
        print("   • Consider codec optimization for better efficiency")
    else:
        print("   🚨 Significant improvements needed:")
        print("   • Prioritize fixing critical degradation factors")
        print("   • Review network infrastructure and QoS configuration")
        print("   • Validate SIP server configuration and endpoints")
        print("   • Consider professional VoIP consultation")
    
    print("="*80)


def analyze_call_quality_batch(file_paths: List[str]) -> Dict[str, QualityMetrics]:
    """
    Analyze call quality for multiple capture files.
    
    Args:
        file_paths: List of paths to packet capture files
        
    Returns:
        Dict mapping file paths to quality metrics
    """
    from extractors.tshark import extract_sip_data
    from analyzers.call_tracking import extract_and_analyze_call_tracking
    from utils.sip_converter import convert_sip_data_for_tracking
    
    scorer = CallQualityScorer()
    results = {}
    
    print(f"📊 Analyzing call quality for {len(file_paths)} capture files...")
    
    for i, file_path in enumerate(file_paths, 1):
        print(f"\n📂 [{i}/{len(file_paths)}] Processing: {file_path}")
        
        try:
            # Extract SIP data
            sip_data = extract_sip_data(file_path)
            if not sip_data:
                print(f"   ⚠️ No SIP data found in {file_path}")
                continue
            
            # Get call tracking data
            tracking_data = convert_sip_data_for_tracking(sip_data)
            sessions, _ = extract_and_analyze_call_tracking(tracking_data)
            
            # Score call quality
            quality_metrics = scorer.score_call_quality(sip_data, sessions, file_path=file_path)
            results[file_path] = quality_metrics
            
            print(f"   🎯 Quality Score: {quality_metrics.overall_score:.1f}/100 ({quality_metrics.grade.value})")
            
        except Exception as e:
            print(f"   ❌ Error processing {file_path}: {e}")
    
    return results
