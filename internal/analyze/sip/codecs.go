// Package sip maps RTP payload types and enriches SIP captures with VoIP codec diagnostic
// context matching utils/wireshark.py and utils/codecs.py.
package sip

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

// CodecAnalysisContext holds VoIP diagnostic characteristics for one audio codec.
type CodecAnalysisContext struct {
	CodecName           string            `json:"codec_name"`
	StandardPayloadType int               `json:"standard_payload_type"`
	BandwidthKbps       float64           `json:"bandwidth_kbps"`
	QualityRating       string            `json:"quality_rating"`
	CommonIssues        []string          `json:"common_issues"`
	DiagnosticFocus     []string          `json:"diagnostic_focus"`
	RTPAnalysisGuidance map[string]string `json:"rtp_analysis_guidance"`
	PayloadTypeNote     string            `json:"payload_type_note,omitempty"`
}

var payloadCodecNames = map[string]string{
	"0":   "PCMU (G.711 μ-law)",
	"8":   "PCMA (G.711 A-law)",
	"9":   "G.722",
	"18":  "G.729",
	"96":  "Dynamic (often Opus)",
	"97":  "Dynamic (often iLBC)",
	"98":  "Dynamic (often Speex)",
	"99":  "Dynamic (often H.264)",
	"101": "DTMF/Telephone-Event (RFC 4733)",
}

var codecContextDB = map[string]CodecAnalysisContext{
	"pcmu": {
		CodecName: "G.711 μ-law (PCMU)", StandardPayloadType: 0, BandwidthKbps: 64,
		QualityRating:   "Excellent audio quality, toll-quality voice",
		CommonIssues:    []string{"Network congestion due to high bandwidth usage", "Packet loss more noticeable due to no compression"},
		DiagnosticFocus: []string{"Check for packet loss indicators in RTP streams", "Monitor network utilization during calls", "Look for jitter buffer issues in high-traffic networks", "Verify QoS prioritization for G.711 traffic"},
		RTPAnalysisGuidance: map[string]string{
			"packet_loss_sensitivity": "High - uncompressed audio",
			"jitter_tolerance":        "Moderate - 20-50ms acceptable",
			"bandwidth_monitoring":    "Critical - 64 kbps per call",
		},
	},
	"pcma": {
		CodecName: "G.711 A-law (PCMA)", StandardPayloadType: 8, BandwidthKbps: 64,
		QualityRating:   "Excellent audio quality, toll-quality voice",
		CommonIssues:    []string{"Network congestion due to high bandwidth usage", "Packet loss more noticeable due to no compression", "A-law/μ-law compatibility issues between regions"},
		DiagnosticFocus: []string{"Check for A-law/μ-law compatibility between endpoints", "Monitor network utilization during calls", "Look for jitter buffer issues in high-traffic networks", "Verify QoS prioritization for G.711 traffic"},
		RTPAnalysisGuidance: map[string]string{
			"packet_loss_sensitivity": "High - uncompressed audio",
			"jitter_tolerance":        "Moderate - 20-50ms acceptable",
			"bandwidth_monitoring":    "Critical - 64 kbps per call",
		},
	},
	"g729": {
		CodecName: "G.729 Low Bitrate Codec", StandardPayloadType: 18, BandwidthKbps: 8,
		QualityRating:   "Good quality with proper implementation, may degrade with packet loss",
		CommonIssues:    []string{"Quality degradation with poor G.729 implementations", "Licensing compliance issues on some platforms", "CPU overhead for encoding/decoding"},
		DiagnosticFocus: []string{"Check for G.729 licensing compliance on endpoints", "Monitor CPU usage during calls for codec processing overhead", "Look for transcoding delays in mixed codec environments", "Verify packet loss rates - G.729 is more sensitive than G.711"},
		RTPAnalysisGuidance: map[string]string{
			"packet_loss_sensitivity": "Very High - compressed audio degrades quickly",
			"jitter_tolerance":        "Low - 10-20ms recommended",
			"bandwidth_monitoring":    "Efficient - 8 kbps per call",
		},
	},
	"opus": {
		CodecName: "Opus Modern Adaptive Codec", StandardPayloadType: 96, BandwidthKbps: 32,
		QualityRating:   "Excellent quality at all bitrates, superior packet loss resilience",
		CommonIssues:    []string{"Configuration mismatches between different Opus implementations", "Bandwidth negotiation issues in SDP", "Limited support on legacy systems"},
		DiagnosticFocus: []string{"Verify Opus configuration parameters in SDP", "Check for adaptive bitrate changes during calls", "Monitor for packet loss recovery mechanisms", "Look for compatibility issues with non-Opus endpoints"},
		RTPAnalysisGuidance: map[string]string{
			"packet_loss_sensitivity": "Low - excellent packet loss recovery",
			"jitter_tolerance":        "High - adaptive buffering",
			"bandwidth_monitoring":    "Variable - 6-510 kbps adaptive",
		},
	},
	"ilbc": {
		CodecName: "iLBC Internet Low Bitrate Codec", StandardPayloadType: 97, BandwidthKbps: 15.2,
		QualityRating:   "Moderate quality, excellent packet loss resistance",
		CommonIssues:    []string{"Limited availability on some platforms", "Frame size configuration mismatches", "Quality trade-offs for packet loss resistance"},
		DiagnosticFocus: []string{"Check iLBC frame size configuration (20ms vs 30ms)", "Verify packet loss recovery performance", "Monitor for compatibility issues with other codecs", "Look for quality vs. resilience trade-offs"},
		RTPAnalysisGuidance: map[string]string{
			"packet_loss_sensitivity": "Very Low - designed for poor networks",
			"jitter_tolerance":        "High - robust buffering",
			"bandwidth_monitoring":    "Low - 13.3-15.2 kbps",
		},
	},
}

// GetCodecNameFromPayloadType maps an RTP payload type string to a descriptive codec label.
func GetCodecNameFromPayloadType(payloadType string) string {
	if name, ok := payloadCodecNames[payloadType]; ok {
		return name
	}
	return "Unknown (PT " + payloadType + ")"
}

// GetCodecAnalysisContext returns structured diagnostic guidance for a named codec.
func GetCodecAnalysisContext(codecName, payloadType string) CodecAnalysisContext {
	norm := strings.NewReplacer(".", "", "-", "", "_", "").Replace(strings.ToLower(codecName))
	aliases := map[string]string{
		"g711": "pcmu", "g711u": "pcmu", "g711a": "pcma",
		"ulaw": "pcmu", "alaw": "pcma", "mulaw": "pcmu",
		"g729a": "g729", "g729ab": "g729",
	}
	if mapped, ok := aliases[norm]; ok {
		norm = mapped
	}
	info, ok := codecContextDB[norm]
	if !ok {
		stdPT := 96
		if n, err := strconv.Atoi(payloadType); err == nil {
			stdPT = n
		}
		return CodecAnalysisContext{
			CodecName: fmt.Sprintf("Unknown Codec (%s)", codecName), StandardPayloadType: stdPT,
			BandwidthKbps: 32, QualityRating: "Unknown quality characteristics",
			CommonIssues:        []string{fmt.Sprintf("Unknown codec '%s' may have compatibility issues", codecName), "Verify codec support on all endpoints", "Check for proper SDP negotiation"},
			DiagnosticFocus:     []string{"Identify the specific codec implementation", "Verify codec support across all call participants", "Check SDP media format strings for codec details", "Look for codec negotiation failures"},
			RTPAnalysisGuidance: map[string]string{"packet_loss_sensitivity": "Unknown", "jitter_tolerance": "Unknown", "bandwidth_monitoring": "Unknown"},
		}
	}
	if n, err := strconv.Atoi(payloadType); err == nil && n != info.StandardPayloadType {
		info.PayloadTypeNote = fmt.Sprintf("Using non-standard payload type %d (standard: %d)", n, info.StandardPayloadType)
	}
	return info
}

// EnrichSIPDataWithCodecContext appends VoIP codec diagnostic reference context to SIP data.
func EnrichSIPDataWithCodecContext(sipData string) string {
	if sipData == "" {
		return ""
	}
	ctx := map[string]map[string]CodecAnalysisContext{
		"enhanced_codec_analysis": {
			"g_711_mu_law":            GetCodecAnalysisContext("PCMU", ""),
			"g_729_low_bitrate_codec": GetCodecAnalysisContext("G.729", ""),
			"g_711_a_law":             GetCodecAnalysisContext("PCMA", ""),
		},
	}
	b, _ := json.MarshalIndent(ctx, "", "  ")
	return sipData + "\n\n--- CODEC ANALYSIS CONTEXT ---\n" + string(b)
}

var rtpPayloadTypeFieldRe = regexp.MustCompile(`"rtp\.p_type":\s*"(\d+)"`)

// ExtractCodecDirectly extracts the primary codec directly from RTP payload type data.
func ExtractCodecDirectly(sipData string) string {
	ptNames := map[string]string{
		"0": "G.711 μ-law (PCMU)", "8": "G.711 A-law (PCMA)", "9": "G.722", "18": "G.729",
		"96": "Dynamic (often Opus)", "97": "Dynamic (often iLBC)", "98": "Dynamic (often Speex)", "99": "Dynamic (often H.264)",
	}
	for _, m := range rtpPayloadTypeFieldRe.FindAllStringSubmatch(sipData, -1) {
		if name, ok := ptNames[m[1]]; ok {
			return name
		}
	}
	var parsed extract.SIPExtractionSummary
	if json.Unmarshal([]byte(sipData), &parsed) == nil {
		for _, r := range parsed.RTPStreams {
			if name, ok := ptNames[r.PayloadType]; ok {
				return name
			}
		}
	}
	low := strings.ToLower(sipData)
	switch {
	case strings.Contains(low, "pcmu") || strings.Contains(low, "μ-law"):
		return "G.711 μ-law (PCMU)"
	case strings.Contains(low, "pcma") || strings.Contains(low, "a-law"):
		return "G.711 A-law (PCMA)"
	case strings.Contains(low, "g722"):
		return "G.722"
	case strings.Contains(low, "g729"):
		return "G.729"
	default:
		return "Unknown"
	}
}
