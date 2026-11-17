// Package ai enriches extracted SIP data with codec diagnostic context and
// detects active RTP payload codecs matching utils/codecs.py.
package ai

import (
	"encoding/json"
	"regexp"
	"strings"
)

// RTPGuidance summarizes packet loss and jitter thresholds for one codec profile.
type RTPGuidance struct {
	PacketLossThresholds []string `json:"packet_loss_thresholds"`
	JitterThresholds     []string `json:"jitter_thresholds"`
}

// CodecAnalysisContext holds structured codec properties used to guide LLM diagnostics.
type CodecAnalysisContext struct {
	CodecName       string   `json:"codec_name"`
	StandardPT      int      `json:"standard_payload_type"`
	BandwidthKbps   int      `json:"bandwidth_kbps"`
	QualityRating   string   `json:"quality_rating"`
	CommonIssues    []string `json:"common_issues"`
	DiagnosticFocus []string `json:"diagnostic_focus"`
}

type codecEnvelope struct {
	EnhancedCodecAnalysis map[string]CodecAnalysisContext `json:"enhanced_codec_analysis"`
	RTPGuidance           map[string]RTPGuidance          `json:"rtp_stream_troubleshooting_guidance"`
}

var codecDatabase = map[string]CodecAnalysisContext{
	"pcmu": {
		CodecName:     "G.711 u-law (PCMU)",
		StandardPT:    0,
		BandwidthKbps: 64,
		QualityRating: "Excellent audio quality, toll-quality voice",
		CommonIssues: []string{
			"Network congestion due to high bandwidth usage",
			"Packet loss more noticeable due to no compression",
		},
		DiagnosticFocus: []string{
			"Check for packet loss indicators in RTP streams",
			"Monitor network utilization during calls",
			"Look for jitter buffer issues in high-traffic networks",
			"Verify QoS prioritization for G.711 traffic",
		},
	},
	"pcma": {
		CodecName:     "G.711 A-law (PCMA)",
		StandardPT:    8,
		BandwidthKbps: 64,
		QualityRating: "Excellent audio quality, toll-quality voice",
		CommonIssues: []string{
			"Network congestion due to high bandwidth usage",
			"Packet loss more noticeable due to no compression",
			"A-law/u-law compatibility issues between regions",
		},
		DiagnosticFocus: []string{
			"Check for A-law/u-law compatibility between endpoints",
			"Monitor network utilization during calls",
			"Look for jitter buffer issues in high-traffic networks",
			"Verify QoS prioritization for G.711 traffic",
		},
	},
	"g729": {
		CodecName:     "G.729",
		StandardPT:    18,
		BandwidthKbps: 8,
		QualityRating: "Moderate quality, efficient bandwidth",
		CommonIssues: []string{
			"Quality degradation with poor implementations",
			"High sensitivity to packet loss and transcoding",
		},
		DiagnosticFocus: []string{
			"Check RTP packet loss below 1%",
			"Monitor jitter buffer stability and PLC behavior",
		},
	},
}

// GetCodecContext returns diagnostic guidance for normalized codec names.
func GetCodecContext(name string) CodecAnalysisContext {
	norm := strings.ToLower(name)
	norm = strings.NewReplacer(".", "", "-", "", "_", "", " ", "").Replace(norm)
	switch {
	case strings.Contains(norm, "pcmu") || strings.Contains(norm, "ulaw") || strings.Contains(norm, "g711u"):
		return codecDatabase["pcmu"]
	case strings.Contains(norm, "pcma") || strings.Contains(norm, "alaw") || strings.Contains(norm, "g711a"):
		return codecDatabase["pcma"]
	case strings.Contains(norm, "g729"):
		return codecDatabase["g729"]
	default:
		return codecDatabase["pcmu"]
	}
}

// EnrichSIPDataWithCodecContext appends structured VoIP codec guidance to sipData.
func EnrichSIPDataWithCodecContext(sipData string) string {
	if sipData == "" {
		return ""
	}
	env := codecEnvelope{
		EnhancedCodecAnalysis: map[string]CodecAnalysisContext{
			"g_711_mu_law":            GetCodecContext("PCMU"),
			"g_729_low_bitrate_codec": GetCodecContext("G.729"),
			"g_711_a_law":             GetCodecContext("PCMA"),
		},
		RTPGuidance: map[string]RTPGuidance{
			"g_711_mu_law":            {PacketLossThresholds: []string{"<1%", "1-3%", ">5%"}, JitterThresholds: []string{"<20ms", "20-50ms", ">50ms"}},
			"g_729_low_bitrate_codec": {PacketLossThresholds: []string{"<1%", "1-3%"}, JitterThresholds: []string{"<20ms", "20-50ms"}},
			"g_711_a_law":             {PacketLossThresholds: []string{"<1%", "1-3%"}, JitterThresholds: []string{"<20ms", "20-50ms"}},
		},
	}
	raw, _ := json.MarshalIndent(env, "", "  ")
	return sipData + "\n\n--- CODEC ANALYSIS CONTEXT ---\n" + string(raw)
}

var payloadTypeFieldRe = regexp.MustCompile(`"rtp\.p_type":\s*"(\d+)"`)

var payloadTypeCodecMap = map[string]string{
	"0":  "G.711 u-law (PCMU)",
	"8":  "G.711 A-law (PCMA)",
	"9":  "G.722",
	"18": "G.729",
	"96": "Dynamic (often Opus)",
	"97": "Dynamic (often iLBC)",
	"98": "Dynamic (often Speex)",
	"99": "Dynamic (often H.264)",
}

// ExtractCodecDirectly infers the active RTP voice codec from extracted SIP JSON or text.
func ExtractCodecDirectly(sipData string) string {
	if sipData == "" {
		return "Unknown"
	}
	var parsed struct {
		RTPStreams []struct {
			PayloadType string `json:"payload_type"`
		} `json:"rtp_streams"`
	}
	if json.Unmarshal([]byte(sipData), &parsed) == nil {
		for _, s := range parsed.RTPStreams {
			if name, ok := payloadTypeCodecMap[s.PayloadType]; ok {
				return name
			}
		}
	}
	if m := payloadTypeFieldRe.FindStringSubmatch(sipData); len(m) == 2 {
		if name, ok := payloadTypeCodecMap[m[1]]; ok {
			return name
		}
	}
	lower := strings.ToLower(sipData)
	switch {
	case strings.Contains(lower, "pcmu") || strings.Contains(lower, "u-law"):
		return "G.711 u-law (PCMU)"
	case strings.Contains(lower, "pcma") || strings.Contains(lower, "a-law"):
		return "G.711 A-law (PCMA)"
	case strings.Contains(lower, "g722"):
		return "G.722"
	case strings.Contains(lower, "g729"):
		return "G.729"
	default:
		return "Unknown"
	}
}
