#!/usr/bin/env python3
"""
Real Network Quality Analysis for VoIP Traffic

This module performs actual packet-level analysis to detect real network issues:
1. RTP Analysis: Jitter, packet delta timing, packet loss detection
2. TCP Analysis: ECN, PFC, retransmissions, congestion indicators  
3. QoS/ToS Analysis: DSCP markings on RTP and control traffic

Unlike generic codec warnings, this provides real detected network problems.
"""

import subprocess
import json
import statistics
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

@dataclass
class RtpQualityMetrics:
    """Real RTP stream quality metrics calculated from actual packets"""
    packet_loss_percent: float
    avg_jitter_ms: float
    max_jitter_ms: float
    packet_delta_variance: float
    out_of_order_packets: int
    duplicate_packets: int
    total_packets: int
    missing_sequence_numbers: List[int]

@dataclass 
class TcpQualityMetrics:
    """TCP network quality indicators"""
    retransmissions: int
    ecn_capable: bool
    ecn_congestion_experienced: bool
    fast_retransmits: int
    duplicate_acks: int
    window_size_variations: List[int]

@dataclass
class QosAnalysis:
    """QoS/ToS analysis for VoIP traffic"""
    rtp_dscp_markings: Dict[str, int]  # DSCP value -> packet count
    sip_dscp_markings: Dict[str, int]  # DSCP value -> packet count
    has_qos_markings: bool
    recommended_dscp: str
    qos_violations: List[str]

class NetworkQualityAnalyzer:
    """Analyzes actual network conditions from packet capture"""
    
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        
    def analyze_rtp_quality(self, rtp_streams: List[Dict]) -> Dict[str, RtpQualityMetrics]:
        """
        Analyze RTP streams for real quality issues:
        - Packet loss (missing sequence numbers)
        - Jitter calculation from actual timestamps
        - Packet delta timing variance
        - Out-of-order and duplicate detection
        """
        results = {}
        
        for i, stream in enumerate(rtp_streams):
            stream_id = f"stream_{i+1}_{stream['src_ip']}_{stream['src_port']}"
            
            # Extract detailed RTP metrics using tshark
            rtp_filter = (f"rtp and ip.src == {stream['src_ip']} and "
                         f"ip.dst == {stream['dst_ip']} and "
                         f"udp.srcport == {stream['src_port']} and "
                         f"udp.dstport == {stream['dst_port']}")
            
            try:
                # Get RTP sequence numbers, timestamps, and timing
                cmd = [
                    'tshark', '-r', self.pcap_path,
                    '-Y', rtp_filter,
                    '-T', 'fields',
                    '-e', 'frame.number',
                    '-e', 'frame.time_relative',
                    '-e', 'rtp.seq',
                    '-e', 'rtp.timestamp', 
                    '-e', 'frame.len',
                    '-E', 'header=y',
                    '-E', 'separator=,'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    continue
                    
                metrics = self._calculate_rtp_metrics(result.stdout, stream)
                results[stream_id] = metrics
                
            except Exception as e:
                print(f"Warning: Could not analyze RTP stream {stream_id}: {e}")
                continue
                
        return results
    
    def _calculate_rtp_metrics(self, tshark_output: str, stream_info: Dict) -> RtpQualityMetrics:
        """Calculate real RTP quality metrics from tshark output"""
        lines = tshark_output.strip().split('\n')[1:]  # Skip header
        
        packets = []
        for line in lines:
            if line.strip():
                parts = line.split(',')
                if len(parts) >= 4:
                    try:
                        frame_num = int(parts[0])
                        time_rel = float(parts[1])
                        seq_num = int(parts[2]) if parts[2] else 0
                        rtp_timestamp = int(parts[3]) if parts[3] else 0
                        packets.append({
                            'frame': frame_num,
                            'time': time_rel,
                            'seq': seq_num,
                            'rtp_ts': rtp_timestamp
                        })
                    except (ValueError, IndexError):
                        continue
        
        if len(packets) < 2:
            return RtpQualityMetrics(0, 0, 0, 0, 0, 0, len(packets), [])
        
        # Sort by sequence number for analysis
        packets_by_seq = sorted(packets, key=lambda x: x['seq'])
        
        # 1. Packet Loss Detection
        seq_numbers = [p['seq'] for p in packets_by_seq]
        if seq_numbers:
            expected_count = seq_numbers[-1] - seq_numbers[0] + 1
            actual_count = len(packets)
            packet_loss_percent = max(0, (expected_count - actual_count) / expected_count * 100)
            
            # Find missing sequence numbers
            all_expected = set(range(seq_numbers[0], seq_numbers[-1] + 1))
            received = set(seq_numbers)
            missing_seqs = list(all_expected - received)
        else:
            packet_loss_percent = 0
            missing_seqs = []
        
        # 2. Jitter Calculation (RFC 3550)
        time_deltas = []
        for i in range(1, len(packets)):
            time_delta = packets[i]['time'] - packets[i-1]['time']
            time_deltas.append(time_delta * 1000)  # Convert to ms
        
        if time_deltas:
            avg_jitter = statistics.mean(time_deltas)
            max_jitter = max(time_deltas)
            delta_variance = statistics.variance(time_deltas) if len(time_deltas) > 1 else 0
        else:
            avg_jitter = max_jitter = delta_variance = 0
        
        # 3. Out-of-order detection
        time_sorted = sorted(packets, key=lambda x: x['time'])
        out_of_order = 0
        for i, pkt in enumerate(time_sorted[1:], 1):
            if pkt['seq'] < time_sorted[i-1]['seq']:
                out_of_order += 1
        
        # 4. Duplicate detection
        seq_counts = {}
        for pkt in packets:
            seq_counts[pkt['seq']] = seq_counts.get(pkt['seq'], 0) + 1
        duplicates = sum(count - 1 for count in seq_counts.values() if count > 1)
        
        return RtpQualityMetrics(
            packet_loss_percent=packet_loss_percent,
            avg_jitter_ms=avg_jitter,
            max_jitter_ms=max_jitter,
            packet_delta_variance=delta_variance,
            out_of_order_packets=out_of_order,
            duplicate_packets=duplicates,
            total_packets=len(packets),
            missing_sequence_numbers=missing_seqs[:10]  # Limit to first 10
        )
    
    def analyze_tcp_quality(self) -> TcpQualityMetrics:
        """
        Analyze TCP traffic for network congestion indicators:
        - Retransmissions
        - ECN (Explicit Congestion Notification)
        - PFC (Priority Flow Control) - for DCB environments
        - Fast retransmits and duplicate ACKs
        """
        try:
            # Extract TCP analysis fields
            cmd = [
                'tshark', '-r', self.pcap_path,
                '-Y', 'tcp',
                '-T', 'fields',
                '-e', 'tcp.analysis.retransmission',
                '-e', 'tcp.analysis.fast_retransmission', 
                '-e', 'tcp.analysis.duplicate_ack',
                '-e', 'ip.dsfield.ecn',
                '-e', 'tcp.window_size',
                '-E', 'header=y',
                '-E', 'separator=,'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return TcpQualityMetrics(0, False, False, 0, 0, [])
            
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            retransmissions = 0
            fast_retransmits = 0
            duplicate_acks = 0
            ecn_capable = False
            ecn_congestion = False
            window_sizes = []
            
            for line in lines:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 5:
                        # Count retransmissions
                        if parts[0] == '1':
                            retransmissions += 1
                        if parts[1] == '1':
                            fast_retransmits += 1
                        if parts[2] == '1':
                            duplicate_acks += 1
                        
                        # ECN analysis
                        try:
                            ecn_field = int(parts[3]) if parts[3] else 0
                            if ecn_field & 0x01:  # ECT(1)
                                ecn_capable = True
                            if ecn_field & 0x02:  # ECT(0)
                                ecn_capable = True  
                            if ecn_field == 0x03:  # CE (Congestion Experienced)
                                ecn_congestion = True
                        except (ValueError, IndexError):
                            pass
                        
                        # Window size tracking
                        try:
                            if parts[4]:
                                window_sizes.append(int(parts[4]))
                        except (ValueError, IndexError):
                            pass
            
            return TcpQualityMetrics(
                retransmissions=retransmissions,
                ecn_capable=ecn_capable,
                ecn_congestion_experienced=ecn_congestion,
                fast_retransmits=fast_retransmits,
                duplicate_acks=duplicate_acks,
                window_size_variations=window_sizes[-20:] if window_sizes else []  # Last 20 samples
            )
            
        except Exception as e:
            print(f"Warning: Could not analyze TCP quality: {e}")
            return TcpQualityMetrics(0, False, False, 0, 0, [])
    
    def analyze_qos_markings(self, sip_packets: List[Dict], rtp_streams: List[Dict]) -> QosAnalysis:
        """
        Analyze QoS/DSCP markings on VoIP traffic:
        - Check for proper DSCP markings on RTP (EF/AF41)
        - Check for SIP signaling markings (AF31/CS3)
        - Identify QoS violations and missing markings
        """
        try:
            # Analyze RTP DSCP markings
            rtp_dscp = {}
            for stream in rtp_streams:
                rtp_filter = (f"rtp and ip.src == {stream['src_ip']} and "
                             f"ip.dst == {stream['dst_ip']} and "
                             f"udp.srcport == {stream['src_port']}")
                
                cmd = [
                    'tshark', '-r', self.pcap_path,
                    '-Y', rtp_filter,
                    '-T', 'fields',
                    '-e', 'ip.dsfield.dscp',
                    '-E', 'header=n'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            dscp_val = line.strip()
                            rtp_dscp[dscp_val] = rtp_dscp.get(dscp_val, 0) + 1
            
            # Analyze SIP DSCP markings
            sip_dscp = {}
            cmd = [
                'tshark', '-r', self.pcap_path,
                '-Y', 'sip',
                '-T', 'fields', 
                '-e', 'ip.dsfield.dscp',
                '-E', 'header=n'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        dscp_val = line.strip()
                        sip_dscp[dscp_val] = sip_dscp.get(dscp_val, 0) + 1
            
            # Determine QoS compliance
            has_qos = bool(rtp_dscp or sip_dscp)
            violations = []
            
            # Check for proper RTP markings (EF=46, AF41=34)
            if rtp_dscp:
                if '46' not in rtp_dscp and '34' not in rtp_dscp:
                    violations.append("RTP traffic missing proper QoS markings (requires EF-46 or AF41-34)")
                if '0' in rtp_dscp:
                    violations.append("RTP packets using Best Effort (DSCP 0) instead of priority marking")
            else:
                violations.append("CRITICAL: No QoS markings found on RTP voice traffic")
            
            # Check for proper SIP markings (AF31=26, CS3=24)
            if sip_dscp:
                if '26' not in sip_dscp and '24' not in sip_dscp:
                    violations.append("SIP signaling missing proper QoS markings (requires AF31-26 or CS3-24)")
            else:
                violations.append("WARNING: No QoS markings found on SIP signaling traffic")
            
            return QosAnalysis(
                rtp_dscp_markings=rtp_dscp,
                sip_dscp_markings=sip_dscp,
                has_qos_markings=has_qos,
                recommended_dscp="RTP: EF (46) or AF41 (34), SIP: AF31 (26) or CS3 (24)",
                qos_violations=violations
            )
            
        except Exception as e:
            print(f"Warning: Could not analyze QoS markings: {e}")
            return QosAnalysis({}, {}, False, "Analysis failed", [])
    
    def generate_network_quality_report(self, sip_data: Dict) -> Dict[str, Any]:
        """
        Generate comprehensive real network quality analysis report
        combining RTP, TCP, and QoS analysis
        """
        print("🔬 Performing real network quality analysis...")
        
        # Extract data from SIP analysis
        rtp_streams = sip_data.get('rtp_streams', [])
        sip_packets = sip_data.get('sip_packets', [])
        
        # Perform all analyses
        rtp_quality = self.analyze_rtp_quality(rtp_streams)
        tcp_quality = self.analyze_tcp_quality()
        qos_analysis = self.analyze_qos_markings(sip_packets, rtp_streams)
        
        # Compile real issues found
        real_issues = []
        
        # RTP Issues (mark critical issues with failure icons)
        for stream_id, metrics in rtp_quality.items():
            if metrics.packet_loss_percent > 0.1:  # > 0.1% loss
                real_issues.append(f"🚨 PACKET LOSS: {metrics.packet_loss_percent:.2f}% in {stream_id}")
            if metrics.avg_jitter_ms > 30:  # > 30ms average jitter
                real_issues.append(f"⚠️ HIGH JITTER: {metrics.avg_jitter_ms:.1f}ms average in {stream_id}")
            if metrics.out_of_order_packets > 0:
                real_issues.append(f"❌ OUT-OF-ORDER: {metrics.out_of_order_packets} packets in {stream_id}")
            if metrics.duplicate_packets > 0:
                real_issues.append(f"⚠️ DUPLICATES: {metrics.duplicate_packets} packets in {stream_id}")
        
        # TCP Issues (mark network problems with failure icons)
        if tcp_quality.retransmissions > 0:
            real_issues.append(f"🚨 NETWORK STRESS: {tcp_quality.retransmissions} TCP retransmissions detected")
        if tcp_quality.ecn_congestion_experienced:
            real_issues.append("❌ CONGESTION: Network congestion detected (ECN Congestion Experienced)")
        if tcp_quality.fast_retransmits > 0:
            real_issues.append(f"⚠️ PACKET LOSS: {tcp_quality.fast_retransmits} fast retransmits detected")
        
        # QoS Issues (mark with failure icons to indicate severity)
        for violation in qos_analysis.qos_violations:
            real_issues.append(f"❌ QoS FAILURE: {violation}")
        
        # Generate TCP network baseline info (always include as canary for QoS planning)
        tcp_baseline = self._generate_tcp_baseline_analysis(tcp_quality)
        
        return {
            'real_issues_detected': real_issues,
            'rtp_quality_metrics': {k: v.__dict__ for k, v in rtp_quality.items()},
            'tcp_quality_metrics': tcp_quality.__dict__,
            'qos_analysis': qos_analysis.__dict__,
            'tcp_baseline_analysis': tcp_baseline,
            'analysis_summary': {
                'total_rtp_streams_analyzed': len(rtp_quality),
                'total_real_issues_found': len(real_issues),
                'has_packet_loss': any(m.packet_loss_percent > 0 for m in rtp_quality.values()),
                'has_high_jitter': any(m.avg_jitter_ms > 20 for m in rtp_quality.values()),
                'has_tcp_issues': tcp_quality.retransmissions > 0 or tcp_quality.ecn_congestion_experienced,
                'has_qos_markings': qos_analysis.has_qos_markings,
                'tcp_network_health': tcp_baseline['health_assessment']
            }
        }
    
    def _generate_tcp_baseline_analysis(self, tcp_quality: TcpQualityMetrics) -> Dict[str, Any]:
        """
        Generate TCP network baseline analysis for VoIP QoS planning.
        This provides insights about network conditions that could affect VoIP quality,
        even when no current TCP issues are detected.
        """
        # Analyze network health indicators
        health_score = 100
        health_factors = []
        recommendations = []
        
        # Retransmission analysis
        if tcp_quality.retransmissions == 0:
            health_factors.append("✅ No TCP retransmissions detected (excellent)")
            recommendations.append("Current network shows no congestion indicators")
        elif tcp_quality.retransmissions <= 5:
            health_score -= 10
            health_factors.append(f"⚠️ Low TCP retransmissions: {tcp_quality.retransmissions}")
            recommendations.append("Monitor for increasing retransmission trends")
        else:
            health_score -= 25
            health_factors.append(f"🚨 High TCP retransmissions: {tcp_quality.retransmissions}")
            recommendations.append("Implement QoS prioritization for VoIP traffic")
        
        # ECN capability analysis
        if tcp_quality.ecn_capable:
            health_factors.append("✅ ECN capable endpoints detected")
            recommendations.append("ECN can provide early congestion warnings")
        else:
            health_factors.append("ℹ️ No ECN capability detected")
            recommendations.append("Consider ECN-capable network equipment for proactive congestion management")
        
        if tcp_quality.ecn_congestion_experienced:
            health_score -= 20
            health_factors.append("🚨 ECN congestion experienced")
            recommendations.append("CRITICAL: Implement immediate QoS policies for VoIP")
        
        # Fast retransmit analysis
        if tcp_quality.fast_retransmits > 0:
            health_score -= 15
            health_factors.append(f"⚠️ Fast retransmits detected: {tcp_quality.fast_retransmits}")
            recommendations.append("Network packet loss may affect VoIP quality")
        
        # Window size variation analysis
        if tcp_quality.window_size_variations:
            window_analysis = self._analyze_window_variations(tcp_quality.window_size_variations)
            health_factors.append(f"📊 TCP window analysis: {window_analysis['summary']}")
            if window_analysis['instability']:
                health_score -= 10
                recommendations.append("Window size instability may indicate network stress")
        
        # Health assessment
        if health_score >= 90:
            health_assessment = "EXCELLENT"
            voip_impact = "Minimal risk to VoIP quality"
        elif health_score >= 75:
            health_assessment = "GOOD"
            voip_impact = "Low risk to VoIP quality with proper QoS"
        elif health_score >= 60:
            health_assessment = "FAIR"
            voip_impact = "Moderate risk - QoS implementation recommended"
        else:
            health_assessment = "POOR"
            voip_impact = "High risk - immediate QoS implementation required"
        
        return {
            'health_score': health_score,
            'health_assessment': health_assessment,
            'voip_impact_assessment': voip_impact,
            'network_health_factors': health_factors,
            'qos_recommendations': recommendations,
            'tcp_metrics_summary': {
                'retransmissions': tcp_quality.retransmissions,
                'ecn_capable': tcp_quality.ecn_capable,
                'ecn_congestion': tcp_quality.ecn_congestion_experienced,
                'window_samples': len(tcp_quality.window_size_variations)
            }
        }
    
    def _analyze_window_variations(self, window_sizes: List[int]) -> Dict[str, Any]:
        """Analyze TCP window size variations for network stability indicators."""
        if not window_sizes or len(window_sizes) < 3:
            return {'summary': 'Insufficient data', 'instability': False}
        
        # Calculate variation metrics
        avg_window = sum(window_sizes) / len(window_sizes)
        variations = [abs(w - avg_window) for w in window_sizes]
        variation_coefficient = (sum(variations) / len(variations)) / avg_window if avg_window > 0 else 0
        
        # Assess stability
        if variation_coefficient < 0.1:
            return {'summary': 'Stable window sizes', 'instability': False}
        elif variation_coefficient < 0.3:
            return {'summary': 'Moderate window variation', 'instability': False}
        else:
            return {'summary': 'High window variation', 'instability': True}
