#!/usr/bin/env python3
"""
S.O.N.I.C. Advanced RTP MOS Analysis Module

This module provides comprehensive RTP stream analysis and MOS (Mean Opinion Score) calculation
based on ITU-T G.107 E-Model recommendations and real-world VoIP quality metrics.

MOS Scoring Methodology:
- Packet Loss Analysis: ITU-T G.1020 recommendations
- Jitter Analysis: G.114 delay budget considerations  
- Latency Analysis: One-way delay calculations
- Codec Quality Impact: G.711, G.729, Opus quality factors
- Network Impairment Modeling: Burst loss, delay variation

MOS Scale:
5.0 - Excellent (toll quality)
4.0 - Good (high quality)
3.0 - Fair (communication quality)  
2.0 - Poor (barely acceptable)
1.0 - Bad (not recommended)

Author: Raymond A Rizzo | Zombat
"""

import json
import math
import statistics
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class MOSCategory(Enum):
    """MOS quality categories"""
    EXCELLENT = "Excellent"    # 4.5 - 5.0
    GOOD = "Good"             # 3.5 - 4.4  
    FAIR = "Fair"             # 2.5 - 3.4
    POOR = "Poor"             # 1.5 - 2.4
    BAD = "Bad"               # 1.0 - 1.4


@dataclass
class RTPStreamMetrics:
    """Individual RTP stream quality metrics"""
    ssrc: str
    packets_sent: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    packet_loss_rate: float = 0.0
    avg_jitter: float = 0.0
    max_jitter: float = 0.0
    min_jitter: float = 0.0
    jitter_variance: float = 0.0
    avg_latency: float = 0.0  # Estimated from timing analysis
    duplicate_packets: int = 0
    out_of_order_packets: int = 0
    codec: str = "Unknown"
    payload_type: str = "Unknown"
    
    # Calculated quality scores
    packet_loss_mos: float = 5.0
    jitter_mos: float = 5.0
    latency_mos: float = 5.0
    codec_mos: float = 4.0
    overall_mos: float = 4.0
    mos_category: MOSCategory = MOSCategory.GOOD


@dataclass
class MOSAnalysisResult:
    """Complete MOS analysis results"""
    streams: List[RTPStreamMetrics]
    average_mos: float = 0.0
    worst_mos: float = 5.0
    best_mos: float = 5.0
    overall_category: MOSCategory = MOSCategory.GOOD
    
    # Detailed breakdowns
    packet_loss_impact: float = 0.0
    jitter_impact: float = 0.0
    latency_impact: float = 0.0
    codec_impact: float = 0.0
    
    # Quality factors
    quality_factors: List[str] = None
    degradation_factors: List[str] = None
    recommendations: List[str] = None


class AdvancedRTPMOSAnalyzer:
    """Advanced RTP stream analysis with MOS calculation"""
    
    # Codec quality baselines (max MOS without network impairments)
    CODEC_BASELINE_MOS = {
        'G.711': 4.4,    # PCMU/PCMA - toll quality
        'G.722': 4.5,    # Wideband - excellent quality
        'G.729': 4.0,    # Compressed - good quality  
        'Opus': 4.6,     # Modern codec - excellent
        'iLBC': 3.8,     # Internet low bitrate
        'G.723': 3.9,    # Low bitrate
        'GSM': 3.5,      # Mobile codec
        'Unknown': 3.5   # Conservative estimate
    }
    
    # ITU-T G.107 E-Model parameters
    EMODEL_PARAMS = {
        'Ro': 93.2,      # Basic signal-to-noise ratio
        'Is': 1.41,      # Simultaneous impairment factor
        'Id': 0,         # Delay impairment factor (calculated)
        'Ie': 0,         # Equipment impairment factor (calculated)
        'A': 0           # Advantage factor (0 for conventional quality)
    }
    
    def __init__(self):
        self.quality_factors = []
        self.degradation_factors = []
        self.recommendations = []
    
    def analyze_rtp_streams(self, sip_data: str, file_path: str = None) -> MOSAnalysisResult:
        """
        Analyze RTP streams and calculate MOS scores.
        
        Args:
            sip_data: Raw SIP/RTP packet data
            file_path: Path to packet capture for additional analysis
            
        Returns:
            MOSAnalysisResult: Complete MOS analysis with quality metrics
        """
        self.quality_factors = []
        self.degradation_factors = []
        self.recommendations = []
        
        # Parse packet data
        try:
            parsed_data = json.loads(sip_data) if isinstance(sip_data, str) else sip_data
        except:
            parsed_data = {}
        
        # Extract RTP streams
        rtp_streams = self._extract_rtp_streams(parsed_data)
        
        if not rtp_streams:
            # No RTP data available - return default analysis
            return self._create_no_rtp_analysis()
        
        # Analyze each stream
        analyzed_streams = []
        for stream_data in rtp_streams:
            stream_metrics = self._analyze_single_stream(stream_data, parsed_data)
            analyzed_streams.append(stream_metrics)
        
        # Calculate overall results
        return self._calculate_overall_mos(analyzed_streams)
    
    def _extract_rtp_streams(self, parsed_data: Dict) -> List[Dict]:
        """Extract RTP stream information from packet data."""
        rtp_streams = parsed_data.get('rtp_streams', [])
        
        # If no direct RTP streams, try to extract from packet data
        if not rtp_streams:
            rtp_streams = self._extract_rtp_from_packets(parsed_data)
        
        return rtp_streams
    
    def _extract_rtp_from_packets(self, parsed_data: Dict) -> List[Dict]:
        """Extract RTP information from individual packets."""
        streams = {}
        
        # Look through SIP messages for RTP-related information
        sip_messages = parsed_data.get('sip_messages', [])
        for msg in sip_messages:
            # Look for RTP payload type information
            if 'rtp' in str(msg).lower():
                payload_type = msg.get('payload_type')
                ssrc = msg.get('ssrc') or f"stream_{len(streams)}"
                
                if ssrc not in streams:
                    streams[ssrc] = {
                        'ssrc': ssrc,
                        'payload_type': payload_type,
                        'packets': []
                    }
                
                streams[ssrc]['packets'].append(msg)
        
        return list(streams.values())
    
    def _analyze_single_stream(self, stream_data: Dict, full_data: Dict) -> RTPStreamMetrics:
        """Analyze a single RTP stream and calculate MOS."""
        ssrc = stream_data.get('ssrc', 'unknown')
        payload_type = stream_data.get('payload_type', 'unknown')
        packets = stream_data.get('packets', [])
        
        # Initialize metrics
        metrics = RTPStreamMetrics(
            ssrc=ssrc,
            payload_type=str(payload_type),
            codec=self._map_payload_to_codec(payload_type)
        )
        
        # Analyze packet flow
        if packets:
            metrics = self._analyze_packet_flow(metrics, packets)
        else:
            # Estimate from stream metadata
            metrics = self._estimate_from_metadata(metrics, stream_data)
        
        # Calculate MOS components
        metrics.packet_loss_mos = self._calculate_packet_loss_mos(metrics.packet_loss_rate, metrics.codec)
        metrics.jitter_mos = self._calculate_jitter_mos(metrics.avg_jitter, metrics.jitter_variance)
        metrics.latency_mos = self._calculate_latency_mos(metrics.avg_latency)
        metrics.codec_mos = self.CODEC_BASELINE_MOS.get(metrics.codec, 3.5)
        
        # Calculate overall MOS using ITU-T E-Model
        metrics.overall_mos = self._calculate_emodel_mos(metrics)
        metrics.mos_category = self._determine_mos_category(metrics.overall_mos)
        
        # Add quality assessment
        self._assess_stream_quality(metrics)
        
        return metrics
    
    def _analyze_packet_flow(self, metrics: RTPStreamMetrics, packets: List[Dict]) -> RTPStreamMetrics:
        """Analyze packet flow for loss, jitter, and timing."""
        if not packets:
            return metrics
        
        # Sort packets by sequence number if available
        sorted_packets = sorted(packets, key=lambda p: p.get('sequence', 0))
        
        metrics.packets_received = len(sorted_packets)
        
        # Analyze sequence numbers for loss detection
        sequences = [p.get('sequence') for p in sorted_packets if p.get('sequence') is not None]
        if sequences:
            expected_packets = max(sequences) - min(sequences) + 1
            metrics.packets_sent = expected_packets
            metrics.packets_lost = expected_packets - len(sequences)
            metrics.packet_loss_rate = (metrics.packets_lost / expected_packets) * 100 if expected_packets > 0 else 0
            
            # Check for out-of-order packets
            for i in range(1, len(sequences)):
                if sequences[i] < sequences[i-1]:
                    metrics.out_of_order_packets += 1
        
        # Analyze timing for jitter calculation
        timestamps = [p.get('timestamp') for p in sorted_packets if p.get('timestamp') is not None]
        if len(timestamps) >= 2:
            # Calculate inter-arrival jitter
            intervals = []
            for i in range(1, len(timestamps)):
                interval = abs(timestamps[i] - timestamps[i-1])
                intervals.append(interval)
            
            if intervals:
                metrics.avg_jitter = statistics.mean(intervals) * 1000  # Convert to ms
                metrics.max_jitter = max(intervals) * 1000
                metrics.min_jitter = min(intervals) * 1000
                metrics.jitter_variance = statistics.pvariance(intervals) * 1000000  # ms²
        
        return metrics
    
    def _estimate_from_metadata(self, metrics: RTPStreamMetrics, stream_data: Dict) -> RTPStreamMetrics:
        """Estimate metrics from available stream metadata."""
        # Use any available stream statistics
        metrics.packets_sent = stream_data.get('packet_count', 100)  # Conservative estimate
        metrics.packets_received = metrics.packets_sent
        metrics.packet_loss_rate = stream_data.get('loss_rate', 0.0)
        metrics.avg_jitter = stream_data.get('jitter', 20.0)  # Default 20ms
        metrics.avg_latency = stream_data.get('latency', 80.0)  # Default 80ms
        
        return metrics
    
    def _calculate_packet_loss_mos(self, loss_rate: float, codec: str) -> float:
        """Calculate MOS impact from packet loss using ITU-T G.1020."""
        if loss_rate <= 0:
            return 5.0
        
        # Codec-specific loss sensitivity
        loss_sensitivity = {
            'G.711': 1.0,   # Uncompressed - moderate sensitivity
            'G.722': 1.1,   # Wideband - slightly more sensitive
            'G.729': 1.5,   # Compressed - high sensitivity
            'Opus': 0.8,    # Modern - good loss concealment
            'iLBC': 0.9,    # Designed for lossy networks
            'Unknown': 1.2
        }.get(codec, 1.2)
        
        # ITU-T G.1020 packet loss impairment model
        if loss_rate < 1.0:
            impairment = loss_rate * 2.5 * loss_sensitivity
        elif loss_rate < 3.0:
            impairment = (2.5 + (loss_rate - 1.0) * 5.0) * loss_sensitivity
        else:
            impairment = (12.5 + (loss_rate - 3.0) * 8.0) * loss_sensitivity
        
        mos = max(1.0, 5.0 - (impairment / 10.0))
        
        if loss_rate > 0:
            if loss_rate > 5.0:
                self.degradation_factors.append(f"❌ HIGH PACKET LOSS: {loss_rate:.2f}% (severe quality impact)")
            elif loss_rate > 2.0:
                self.degradation_factors.append(f"⚠️ Moderate packet loss: {loss_rate:.2f}%")
            else:
                self.degradation_factors.append(f"📉 Low packet loss: {loss_rate:.2f}%")
        else:
            self.quality_factors.append("✅ No packet loss detected")
        
        return mos
    
    def _calculate_jitter_mos(self, avg_jitter: float, jitter_variance: float) -> float:
        """Calculate MOS impact from jitter using ITU-T G.114."""
        if avg_jitter <= 0:
            return 5.0
        
        # ITU-T G.114 jitter buffer requirements
        if avg_jitter <= 20:
            base_impairment = 0
        elif avg_jitter <= 40:
            base_impairment = 5
        elif avg_jitter <= 60:
            base_impairment = 15
        elif avg_jitter <= 100:
            base_impairment = 25
        else:
            base_impairment = 40
        
        # Add variance penalty (jitter consistency matters)
        variance_penalty = min(10, jitter_variance / 100)
        
        total_impairment = base_impairment + variance_penalty
        mos = max(1.0, 5.0 - (total_impairment / 20.0))
        
        if avg_jitter > 50:
            self.degradation_factors.append(f"❌ HIGH JITTER: {avg_jitter:.1f}ms average")
        elif avg_jitter > 30:
            self.degradation_factors.append(f"⚠️ Moderate jitter: {avg_jitter:.1f}ms average")
        elif avg_jitter > 0:
            self.quality_factors.append(f"📊 Low jitter: {avg_jitter:.1f}ms average")
        else:
            self.quality_factors.append("✅ Minimal jitter detected")
        
        return mos
    
    def _calculate_latency_mos(self, latency: float) -> float:
        """Calculate MOS impact from one-way latency using ITU-T G.114."""
        if latency <= 0:
            return 5.0
        
        # ITU-T G.114 one-way delay recommendations
        if latency <= 50:
            impairment = 0  # Excellent
        elif latency <= 100:
            impairment = 5  # Good
        elif latency <= 150:
            impairment = 10  # Acceptable
        elif latency <= 200:
            impairment = 20  # Poor
        else:
            impairment = 35  # Unacceptable
        
        mos = max(1.0, 5.0 - (impairment / 20.0))
        
        if latency > 200:
            self.degradation_factors.append(f"❌ HIGH LATENCY: {latency:.1f}ms (unacceptable)")
        elif latency > 150:
            self.degradation_factors.append(f"⚠️ High latency: {latency:.1f}ms")
        elif latency > 100:
            self.quality_factors.append(f"📈 Moderate latency: {latency:.1f}ms")
        else:
            self.quality_factors.append(f"✅ Low latency: {latency:.1f}ms")
        
        return mos
    
    def _calculate_emodel_mos(self, metrics: RTPStreamMetrics) -> float:
        """Calculate overall MOS using ITU-T G.107 E-Model."""
        # Start with baseline quality
        R = self.EMODEL_PARAMS['Ro']
        
        # Subtract simultaneous impairments
        R -= self.EMODEL_PARAMS['Is']
        
        # Calculate delay impairment (Id)
        if metrics.avg_latency > 100:
            Id = 0.024 * metrics.avg_latency + 0.11 * (metrics.avg_latency - 177.3) * \
                 max(0, 1)  # Simplified delay impairment
            R -= min(Id, 25)  # Cap delay impairment
        
        # Calculate equipment impairment (Ie) from packet loss and codec
        base_ie = {
            'G.711': 0,
            'G.722': 0,
            'G.729': 11,
            'Opus': 0,
            'iLBC': 5,
            'Unknown': 10
        }.get(metrics.codec, 10)
        
        # Packet loss impairment using Bursty-Loss Model
        if metrics.packet_loss_rate > 0:
            loss_ie = 30 * math.log10(1 + 15 * metrics.packet_loss_rate / 100)
            base_ie += loss_ie
        
        # Jitter impairment
        if metrics.avg_jitter > 20:
            jitter_ie = (metrics.avg_jitter - 20) / 10
            base_ie += jitter_ie
        
        R -= base_ie
        
        # Add advantage factor
        R += self.EMODEL_PARAMS['A']
        
        # Convert R-factor to MOS using ITU-T G.107
        if R < 0:
            mos = 1.0
        elif R > 100:
            mos = 4.5
        else:
            mos = 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R)
        
        return max(1.0, min(5.0, mos))
    
    def _assess_stream_quality(self, metrics: RTPStreamMetrics):
        """Add quality assessment for individual stream."""
        if metrics.overall_mos >= 4.0:
            self.quality_factors.append(f"🌟 Stream {metrics.ssrc}: Excellent quality (MOS {metrics.overall_mos:.2f})")
        elif metrics.overall_mos >= 3.5:
            self.quality_factors.append(f"👍 Stream {metrics.ssrc}: Good quality (MOS {metrics.overall_mos:.2f})")
        elif metrics.overall_mos >= 2.5:
            self.recommendations.append(f"🔧 Stream {metrics.ssrc}: Quality optimization needed (MOS {metrics.overall_mos:.2f})")
        else:
            self.degradation_factors.append(f"🚨 Stream {metrics.ssrc}: Poor quality (MOS {metrics.overall_mos:.2f})")
    
    def _calculate_overall_mos(self, streams: List[RTPStreamMetrics]) -> MOSAnalysisResult:
        """Calculate overall MOS analysis from all streams."""
        if not streams:
            return self._create_no_rtp_analysis()
        
        # Calculate aggregate metrics
        mos_scores = [s.overall_mos for s in streams]
        average_mos = statistics.mean(mos_scores)
        worst_mos = min(mos_scores)
        best_mos = max(mos_scores)
        
        # Calculate impact factors
        packet_loss_impact = statistics.mean([s.packet_loss_mos for s in streams])
        jitter_impact = statistics.mean([s.jitter_mos for s in streams])
        latency_impact = statistics.mean([s.latency_mos for s in streams])
        codec_impact = statistics.mean([s.codec_mos for s in streams])
        
        # Add overall recommendations
        self._add_overall_recommendations(streams, average_mos)
        
        return MOSAnalysisResult(
            streams=streams,
            average_mos=average_mos,
            worst_mos=worst_mos,
            best_mos=best_mos,
            overall_category=self._determine_mos_category(average_mos),
            packet_loss_impact=packet_loss_impact,
            jitter_impact=jitter_impact,
            latency_impact=latency_impact,
            codec_impact=codec_impact,
            quality_factors=self.quality_factors.copy(),
            degradation_factors=self.degradation_factors.copy(),
            recommendations=self.recommendations.copy()
        )
    
    def _add_overall_recommendations(self, streams: List[RTPStreamMetrics], average_mos: float):
        """Add overall quality recommendations."""
        if average_mos >= 4.0:
            self.recommendations.extend([
                "🎉 Excellent voice quality achieved",
                "📊 Monitor consistency over time",
                "📋 Document successful configuration"
            ])
        elif average_mos >= 3.5:
            self.recommendations.extend([
                "🔧 Fine-tune network parameters for optimal quality",
                "📈 Consider QoS optimization",
                "🎯 Target packet loss < 1% and jitter < 30ms"
            ])
        else:
            self.recommendations.extend([
                "🚨 Immediate quality improvement required",
                "🔍 Investigate network infrastructure",
                "⚡ Prioritize packet loss and jitter reduction"
            ])
        
        # Codec-specific recommendations
        codecs_used = set(s.codec for s in streams)
        if 'G.729' in codecs_used and any(s.packet_loss_rate > 1.0 for s in streams):
            self.recommendations.append("🎵 Consider G.711 codec for lossy networks")
        
        if any(s.avg_jitter > 50 for s in streams):
            self.recommendations.append("🌐 Implement adaptive jitter buffers")
    
    def _create_no_rtp_analysis(self) -> MOSAnalysisResult:
        """Create analysis when no RTP data is available."""
        self.degradation_factors.append("⚠️ No RTP streams detected for MOS analysis")
        self.recommendations.extend([
            "📦 Verify RTP traffic is present in capture",
            "🔍 Check if media streams use non-standard ports",
            "📊 Consider extending capture duration"
        ])
        
        return MOSAnalysisResult(
            streams=[],
            average_mos=0.0,
            worst_mos=0.0,
            best_mos=0.0,
            overall_category=MOSCategory.BAD,
            quality_factors=self.quality_factors.copy(),
            degradation_factors=self.degradation_factors.copy(),
            recommendations=self.recommendations.copy()
        )
    
    def _map_payload_to_codec(self, payload_type: str) -> str:
        """Map RTP payload type to codec name."""
        pt_map = {
            '0': 'G.711',     # PCMU
            '8': 'G.711',     # PCMA
            '9': 'G.722',     # G.722
            '18': 'G.729',    # G.729
            '97': 'iLBC',     # Common dynamic PT for iLBC
            '98': 'Opus',     # Common dynamic PT for Opus
            '3': 'GSM',       # GSM
            '4': 'G.723'      # G.723
        }
        return pt_map.get(str(payload_type), 'Unknown')
    
    def _determine_mos_category(self, mos_score: float) -> MOSCategory:
        """Convert MOS score to quality category."""
        if mos_score >= 4.5:
            return MOSCategory.EXCELLENT
        elif mos_score >= 3.5:
            return MOSCategory.GOOD
        elif mos_score >= 2.5:
            return MOSCategory.FAIR
        elif mos_score >= 1.5:
            return MOSCategory.POOR
        else:
            return MOSCategory.BAD


def print_mos_analysis(mos_result: MOSAnalysisResult, file_path: str = None):
    """
    Print comprehensive MOS analysis results.
    
    Args:
        mos_result: MOS analysis results
        file_path: Optional file path for context
    """
    print("\n" + "="*80)
    print("🎵 ADVANCED RTP MOS ANALYSIS")
    print("="*80)
    
    # Overall MOS scoring
    if mos_result.streams:
        print(f"\n📊 OVERALL MOS SCORE: {mos_result.average_mos:.2f}/5.0")
        print(f"🏆 QUALITY CATEGORY: {mos_result.overall_category.value}")
        
        # MOS range
        if len(mos_result.streams) > 1:
            print(f"📈 MOS RANGE: {mos_result.worst_mos:.2f} - {mos_result.best_mos:.2f}")
        
        # Quality description
        category_descriptions = {
            MOSCategory.EXCELLENT: "🌟 Toll-quality voice - exceeds expectations",
            MOSCategory.GOOD: "✨ High-quality voice - business grade",
            MOSCategory.FAIR: "👍 Acceptable voice quality - adequate for communication",
            MOSCategory.POOR: "⚠️ Poor voice quality - improvements needed",
            MOSCategory.BAD: "❌ Unacceptable voice quality - immediate action required"
        }
        print(f"   {category_descriptions[mos_result.overall_category]}")
        
        # Component scores breakdown
        print(f"\n📋 MOS COMPONENT ANALYSIS:")
        print(f"   📦 Packet Loss Impact:  {mos_result.packet_loss_impact:.2f}/5.0")
        print(f"   📊 Jitter Impact:       {mos_result.jitter_impact:.2f}/5.0")
        print(f"   ⏱️  Latency Impact:      {mos_result.latency_impact:.2f}/5.0")
        print(f"   🎵 Codec Quality:       {mos_result.codec_impact:.2f}/5.0")
        
        # Individual stream analysis
        if len(mos_result.streams) > 1:
            print(f"\n🔍 INDIVIDUAL STREAM ANALYSIS:")
            for i, stream in enumerate(mos_result.streams, 1):
                print(f"   Stream {i} (SSRC: {stream.ssrc}):")
                print(f"      🎯 MOS Score: {stream.overall_mos:.2f} ({stream.mos_category.value})")
                print(f"      🎵 Codec: {stream.codec} (PT: {stream.payload_type})")
                print(f"      📦 Packet Loss: {stream.packet_loss_rate:.2f}%")
                print(f"      📊 Avg Jitter: {stream.avg_jitter:.1f}ms")
                if stream.avg_latency > 0:
                    print(f"      ⏱️  Latency: {stream.avg_latency:.1f}ms")
        else:
            stream = mos_result.streams[0]
            print(f"\n🔍 STREAM DETAILS:")
            print(f"   🆔 SSRC: {stream.ssrc}")
            print(f"   🎵 Codec: {stream.codec} (Payload Type: {stream.payload_type})")
            print(f"   📦 Packets: {stream.packets_received} received")
            if stream.packets_lost > 0:
                print(f"   📉 Loss: {stream.packets_lost} packets ({stream.packet_loss_rate:.2f}%)")
            print(f"   📊 Jitter: {stream.avg_jitter:.1f}ms avg, {stream.max_jitter:.1f}ms max")
            if stream.avg_latency > 0:
                print(f"   ⏱️  Latency: {stream.avg_latency:.1f}ms")
    else:
        print(f"\n⚠️ NO RTP STREAMS DETECTED")
        print(f"   Unable to calculate MOS scores without RTP data")
    
    # Quality factors
    if mos_result.quality_factors:
        print(f"\n🌟 QUALITY FACTORS:")
        for factor in mos_result.quality_factors[:8]:  # Show top 8
            print(f"   {factor}")
    
    # Degradation factors
    if mos_result.degradation_factors:
        print(f"\n⚠️ QUALITY DEGRADATION FACTORS:")
        for factor in mos_result.degradation_factors[:8]:  # Show top 8
            print(f"   {factor}")
    
    # Recommendations
    if mos_result.recommendations:
        print(f"\n💡 MOS IMPROVEMENT RECOMMENDATIONS:")
        for rec in mos_result.recommendations[:8]:  # Show top 8
            print(f"   {rec}")
    
    # ITU-T standards reference
    print(f"\n📚 ITU-T STANDARDS REFERENCE:")
    print(f"   📊 MOS Calculation: ITU-T G.107 E-Model")
    print(f"   📦 Packet Loss: ITU-T G.1020 recommendations")
    print(f"   ⏱️  Delay Budget: ITU-T G.114 guidelines")
    print(f"   🎵 Codec Quality: ITU-T codec standards")
    
    print("="*80)
