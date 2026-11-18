// Package sip calculates ITU-T G.1020 loss, G.114 jitter/latency, and G.107 E-Model
// MOS scores for RTP streams matching analyzers/rtp_mos_analysis.py.
package sip

import (
	"fmt"
	"math"
)

const (
	eModelRo = 93.2
	eModelIs = 1.41
	eModelA  = 0.0
)

var codecBaselineMOS = map[string]float64{
	"G.711":   4.4,
	"G.722":   4.5,
	"G.729":   4.0,
	"Opus":    4.6,
	"iLBC":    3.8,
	"G.723":   3.9,
	"GSM":     3.5,
	"Unknown": 3.5,
}

var codecLossSensitivity = map[string]float64{
	"G.711":   1.0,
	"G.722":   1.1,
	"G.729":   1.5,
	"Opus":    0.8,
	"iLBC":    0.9,
	"Unknown": 1.2,
}

var codecBaseIe = map[string]float64{
	"G.711":   0,
	"G.722":   0,
	"G.729":   11,
	"Opus":    0,
	"iLBC":    5,
	"Unknown": 10,
}

func calculatePacketLossMOS(lossRate float64, codec string, qf, df *[]string) float64 {
	if lossRate <= 0 {
		return 5.0
	}
	sens := 1.2
	if v, ok := codecLossSensitivity[codec]; ok {
		sens = v
	}
	var imp float64
	switch {
	case lossRate < 1.0:
		imp = lossRate * 2.5 * sens
	case lossRate < 3.0:
		imp = (2.5 + (lossRate-1.0)*5.0) * sens
	default:
		imp = (12.5 + (lossRate-3.0)*8.0) * sens
	}
	mos := max(1.0, 5.0-(imp/10.0))
	switch {
	case lossRate > 5.0:
		*df = append(*df, fmt.Sprintf("❌ HIGH PACKET LOSS: %.2f%% (severe quality impact)", lossRate))
	case lossRate > 2.0:
		*df = append(*df, fmt.Sprintf("⚠️ Moderate packet loss: %.2f%%", lossRate))
	default:
		*df = append(*df, fmt.Sprintf("📉 Low packet loss: %.2f%%", lossRate))
	}
	return mos
}

func calculateJitterMOS(avgJitter, jitterVar float64, qf, df *[]string) float64 {
	if avgJitter <= 0 {
		return 5.0
	}
	var base float64
	switch {
	case avgJitter <= 20:
		base = 0
	case avgJitter <= 40:
		base = 5
	case avgJitter <= 60:
		base = 15
	case avgJitter <= 100:
		base = 25
	default:
		base = 40
	}
	varPen := min(10.0, jitterVar/100.0)
	mos := max(1.0, 5.0-((base+varPen)/20.0))
	switch {
	case avgJitter > 50:
		*df = append(*df, fmt.Sprintf("❌ HIGH JITTER: %.1fms average", avgJitter))
	case avgJitter > 30:
		*df = append(*df, fmt.Sprintf("⚠️ Moderate jitter: %.1fms average", avgJitter))
	default:
		*qf = append(*qf, fmt.Sprintf("📊 Low jitter: %.1fms average", avgJitter))
	}
	return mos
}

func calculateLatencyMOS(latency float64, qf, df *[]string) float64 {
	if latency <= 0 {
		return 5.0
	}
	var imp float64
	switch {
	case latency <= 50:
		imp = 0
	case latency <= 100:
		imp = 5
	case latency <= 150:
		imp = 10
	case latency <= 200:
		imp = 20
	default:
		imp = 35
	}
	mos := max(1.0, 5.0-(imp/20.0))
	switch {
	case latency > 200:
		*df = append(*df, fmt.Sprintf("❌ HIGH LATENCY: %.1fms (unacceptable)", latency))
	case latency > 150:
		*df = append(*df, fmt.Sprintf("⚠️ High latency: %.1fms", latency))
	case latency > 100:
		*qf = append(*qf, fmt.Sprintf("📈 Moderate latency: %.1fms", latency))
	default:
		*qf = append(*qf, fmt.Sprintf("✅ Low latency: %.1fms", latency))
	}
	return mos
}

func calculateEModelMOS(m RTPStreamMetrics) float64 {
	r := eModelRo - eModelIs
	if m.AvgLatency > 100 {
		id := 0.024*m.AvgLatency + 0.11*(m.AvgLatency-177.3)
		r -= min(id, 25.0)
	}
	ie := 10.0
	if v, ok := codecBaseIe[m.Codec]; ok {
		ie = v
	}
	if m.PacketLossRate > 0 {
		ie += 30.0 * math.Log10(1.0+15.0*m.PacketLossRate/100.0)
	}
	if m.AvgJitter > 20 {
		ie += (m.AvgJitter - 20.0) / 10.0
	}
	r = r - ie + eModelA
	var mos float64
	switch {
	case r < 0:
		mos = 1.0
	case r > 100:
		mos = 4.5
	default:
		mos = 1.0 + 0.035*r + 7e-6*r*(r-60.0)*(100.0-r)
	}
	return max(1.0, min(5.0, mos))
}

func assessStreamQuality(m RTPStreamMetrics, qf, df, recs *[]string) {
	switch {
	case m.OverallMOS >= 4.0:
		*qf = append(*qf, fmt.Sprintf("🌟 Stream %s: Excellent quality (MOS %.2f)", m.SSRC, m.OverallMOS))
	case m.OverallMOS >= 3.5:
		*qf = append(*qf, fmt.Sprintf("👍 Stream %s: Good quality (MOS %.2f)", m.SSRC, m.OverallMOS))
	case m.OverallMOS >= 2.5:
		*recs = append(*recs, fmt.Sprintf("🔧 Stream %s: Quality optimization needed (MOS %.2f)", m.SSRC, m.OverallMOS))
	default:
		*df = append(*df, fmt.Sprintf("🚨 Stream %s: Poor quality (MOS %.2f)", m.SSRC, m.OverallMOS))
	}
}

func calculateOverallMOS(streams []RTPStreamMetrics, qf, df, recs []string) MOSAnalysisResult {
	sumMOS, worst, best := 0.0, streams[0].OverallMOS, streams[0].OverallMOS
	sumLoss, sumJit, sumLat, sumCod := 0.0, 0.0, 0.0, 0.0
	hasG729HighLoss, hasHighJitter := false, false
	for _, s := range streams {
		sumMOS += s.OverallMOS
		if s.OverallMOS < worst {
			worst = s.OverallMOS
		}
		if s.OverallMOS > best {
			best = s.OverallMOS
		}
		sumLoss += s.PacketLossMOS
		sumJit += s.JitterMOS
		sumLat += s.LatencyMOS
		sumCod += s.CodecMOS
		if s.Codec == "G.729" && s.PacketLossRate > 1.0 {
			hasG729HighLoss = true
		}
		if s.AvgJitter > 50 {
			hasHighJitter = true
		}
	}
	n := float64(len(streams))
	avgMOS := sumMOS / n
	switch {
	case avgMOS >= 4.0:
		recs = append(recs, "🎉 Excellent voice quality achieved", "📊 Monitor consistency over time", "📋 Document successful configuration")
	case avgMOS >= 3.5:
		recs = append(recs, "🔧 Fine-tune network parameters for optimal quality", "📈 Consider QoS optimization", "🎯 Target packet loss < 1% and jitter < 30ms")
	default:
		recs = append(recs, "🚨 Immediate quality improvement required", "🔍 Investigate network infrastructure", "⚡ Prioritize packet loss and jitter reduction")
	}
	if hasG729HighLoss {
		recs = append(recs, "🎵 Consider G.711 codec for lossy networks")
	}
	if hasHighJitter {
		recs = append(recs, "🌐 Implement adaptive jitter buffers")
	}
	return MOSAnalysisResult{
		Streams:            streams,
		AverageMOS:         avgMOS,
		WorstMOS:           worst,
		BestMOS:            best,
		OverallCategory:    determineMOSCategory(avgMOS),
		PacketLossImpact:   sumLoss / n,
		JitterImpact:       sumJit / n,
		LatencyImpact:      sumLat / n,
		CodecImpact:        sumCod / n,
		QualityFactors:     qf,
		DegradationFactors: df,
		Recommendations:    recs,
	}
}

func mapMOSPayloadToCodec(pt string) string {
	switch pt {
	case "0", "8":
		return "G.711"
	case "9":
		return "G.722"
	case "18":
		return "G.729"
	case "97":
		return "iLBC"
	case "98":
		return "Opus"
	case "3":
		return "GSM"
	case "4":
		return "G.723"
	default:
		return "Unknown"
	}
}

func determineMOSCategory(mos float64) MOSCategory {
	switch {
	case mos >= 4.5:
		return MOSExcellent
	case mos >= 3.5:
		return MOSGood
	case mos >= 2.5:
		return MOSFair
	case mos >= 1.5:
		return MOSPoor
	default:
		return MOSBad
	}
}
