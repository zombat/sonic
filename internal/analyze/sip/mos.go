// Package sip calculates per-stream RTP packet flow and aggregate Mean Opinion Scores
// matching analyzers/rtp_mos_analysis.py.
package sip

import (
	"encoding/json"
	"math"
	"sort"

	"github.com/zombat/sonic/internal/extract"
)

// RTPPacketSample supplies sequence and arrival timestamps for stream flow analysis.
type RTPPacketSample struct {
	Sequence  *int     `json:"sequence,omitempty"`
	Timestamp *float64 `json:"timestamp,omitempty"`
}

// RTPStreamInput describes an RTP stream either via packet samples or summary metadata.
type RTPStreamInput struct {
	SSRC           string            `json:"ssrc"`
	PayloadType    string            `json:"payload_type"`
	PacketCount    int               `json:"packet_count,omitempty"`
	HasPacketCount bool              `json:"-"`
	LossRate       float64           `json:"loss_rate,omitempty"`
	Jitter         float64           `json:"jitter,omitempty"`
	HasJitter      bool              `json:"-"`
	Latency        float64           `json:"latency,omitempty"`
	HasLatency     bool              `json:"-"`
	Packets        []RTPPacketSample `json:"packets,omitempty"`
}

// AnalyzeRTPStreamsFromJSON decodes SIP/RTP extraction JSON and computes MOS analysis.
func AnalyzeRTPStreamsFromJSON(sipJSON string) MOSAnalysisResult {
	var parsed struct {
		RTPStreams []json.RawMessage `json:"rtp_streams"`
	}
	if sipJSON != "" {
		_ = json.Unmarshal([]byte(sipJSON), &parsed)
	}
	var inputs []RTPStreamInput
	for _, raw := range parsed.RTPStreams {
		inputs = append(inputs, decodeRTPStreamInput(raw))
	}
	return AnalyzeRTPStreams(inputs)
}

func decodeRTPStreamInput(raw json.RawMessage) RTPStreamInput {
	var s RTPStreamInput
	_ = json.Unmarshal(raw, &s)
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) == nil {
		if _, ok := keys["packet_count"]; ok {
			s.HasPacketCount = true
		}
		if _, ok := keys["jitter"]; ok {
			s.HasJitter = true
		}
		if _, ok := keys["latency"]; ok {
			s.HasLatency = true
		}
		if s.SSRC == "" {
			if _, ok := keys["ssrc"]; !ok {
				s.SSRC = "unknown"
			}
		}
		if s.PayloadType == "" {
			if _, ok := keys["payload_type"]; !ok {
				s.PayloadType = "unknown"
			}
		}
	}
	return s
}

// AnalyzeRTPStreamsFromSummary converts extracted RTPStreamSummary records and computes MOS analysis.
func AnalyzeRTPStreamsFromSummary(streams []extract.RTPStreamSummary) MOSAnalysisResult {
	inputs := make([]RTPStreamInput, 0, len(streams))
	for _, s := range streams {
		inputs = append(inputs, RTPStreamInput{
			SSRC:           s.SSRC,
			PayloadType:    s.PayloadType,
			PacketCount:    s.PacketCount,
			HasPacketCount: true,
		})
	}
	return AnalyzeRTPStreams(inputs)
}

// AnalyzeRTPStreams computes per-stream and aggregate MOS scores across streams.
func AnalyzeRTPStreams(streams []RTPStreamInput) MOSAnalysisResult {
	if len(streams) == 0 {
		return createNoRTPAnalysis()
	}
	qf := []string{}
	df := []string{}
	recs := []string{}
	analyzed := make([]RTPStreamMetrics, 0, len(streams))
	for _, st := range streams {
		analyzed = append(analyzed, analyzeSingleStream(st, &qf, &df, &recs))
	}
	return calculateOverallMOS(analyzed, qf, df, recs)
}

func createNoRTPAnalysis() MOSAnalysisResult {
	return MOSAnalysisResult{
		Streams:            []RTPStreamMetrics{},
		AverageMOS:         0.0,
		WorstMOS:           0.0,
		BestMOS:            0.0,
		OverallCategory:    MOSBad,
		QualityFactors:     []string{},
		DegradationFactors: []string{"⚠️ No RTP streams detected for MOS analysis"},
		Recommendations: []string{
			"📦 Verify RTP traffic is present in capture",
			"🔍 Check if media streams use non-standard ports",
			"📊 Consider extending capture duration",
		},
	}
}

func analyzeSingleStream(st RTPStreamInput, qf, df, recs *[]string) RTPStreamMetrics {
	ssrc := defaultStr(st.SSRC, "unknown")
	pt := defaultStr(st.PayloadType, "unknown")
	codec := mapMOSPayloadToCodec(pt)
	m := RTPStreamMetrics{SSRC: ssrc, PayloadType: pt, Codec: codec}
	if len(st.Packets) > 0 {
		analyzePacketFlow(&m, st.Packets)
	} else {
		estimateFromMetadata(&m, st)
	}
	m.PacketLossMOS = calculatePacketLossMOS(m.PacketLossRate, m.Codec, qf, df)
	m.JitterMOS = calculateJitterMOS(m.AvgJitter, m.JitterVariance, qf, df)
	m.LatencyMOS = calculateLatencyMOS(m.AvgLatency, qf, df)
	if base, ok := codecBaselineMOS[m.Codec]; ok {
		m.CodecMOS = base
	} else {
		m.CodecMOS = 3.5
	}
	m.OverallMOS = calculateEModelMOS(m)
	m.MOSCategory = determineMOSCategory(m.OverallMOS)
	assessStreamQuality(m, qf, df, recs)
	return m
}

func analyzePacketFlow(m *RTPStreamMetrics, packets []RTPPacketSample) {
	sorted := append([]RTPPacketSample(nil), packets...)
	sort.SliceStable(sorted, func(i, j int) bool {
		si, sj := 0, 0
		if sorted[i].Sequence != nil {
			si = *sorted[i].Sequence
		}
		if sorted[j].Sequence != nil {
			sj = *sorted[j].Sequence
		}
		return si < sj
	})
	m.PacketsReceived = len(sorted)
	var seqs []int
	var ts []float64
	for _, p := range sorted {
		if p.Sequence != nil {
			seqs = append(seqs, *p.Sequence)
		}
		if p.Timestamp != nil {
			ts = append(ts, *p.Timestamp)
		}
	}
	if len(seqs) > 0 {
		minSeq, maxSeq := seqs[0], seqs[0]
		for i, s := range seqs {
			if s < minSeq {
				minSeq = s
			}
			if s > maxSeq {
				maxSeq = s
			}
			if i > 0 && seqs[i] < seqs[i-1] {
				m.OutOfOrderPackets++
			}
		}
		expected := maxSeq - minSeq + 1
		m.PacketsSent = expected
		m.PacketsLost = expected - len(seqs)
		if expected > 0 {
			m.PacketLossRate = float64(m.PacketsLost) / float64(expected) * 100.0
		}
	}
	if len(ts) >= 2 {
		intervals := make([]float64, 0, len(ts)-1)
		sum, minV, maxV := 0.0, math.Abs(ts[1]-ts[0]), math.Abs(ts[1]-ts[0])
		for i := 1; i < len(ts); i++ {
			iv := math.Abs(ts[i] - ts[i-1])
			intervals = append(intervals, iv)
			sum += iv
			if iv < minV {
				minV = iv
			}
			if iv > maxV {
				maxV = iv
			}
		}
		mean := sum / float64(len(intervals))
		var sq float64
		for _, iv := range intervals {
			d := iv - mean
			sq += d * d
		}
		m.AvgJitter = mean * 1000.0
		m.MaxJitter = maxV * 1000.0
		m.MinJitter = minV * 1000.0
		m.JitterVariance = (sq / float64(len(intervals))) * 1000000.0
	}
}

func estimateFromMetadata(m *RTPStreamMetrics, st RTPStreamInput) {
	m.PacketsSent = 100
	if st.HasPacketCount {
		m.PacketsSent = st.PacketCount
	}
	m.PacketsReceived = m.PacketsSent
	m.PacketLossRate = st.LossRate
	m.AvgJitter = 20.0
	if st.HasJitter {
		m.AvgJitter = st.Jitter
	}
	m.AvgLatency = 80.0
	if st.HasLatency {
		m.AvgLatency = st.Latency
	}
}
