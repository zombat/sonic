// Package sip implements authentication security penalties, codec efficiency scoring,
// and call completion sub-scorers for CallQualityScorer.
package sip

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

type codecRating struct {
	quality       float64
	efficiency    float64
	compatibility float64
}

var codecRatingTable = map[string]codecRating{
	"G.711":   {quality: 95, efficiency: 60, compatibility: 100},
	"G.722":   {quality: 90, efficiency: 70, compatibility: 85},
	"G.729":   {quality: 85, efficiency: 95, compatibility: 90},
	"Opus":    {quality: 98, efficiency: 90, compatibility: 70},
	"iLBC":    {quality: 75, efficiency: 85, compatibility: 80},
	"Unknown": {quality: 50, efficiency: 50, compatibility: 50},
}

func analyzeAuthSecurity(packets []extract.SIPPacket, auth *extract.AuthInfo, qf, df *[]string) (score, penalty float64, c401, c407, regFail, authResp int) {
	weakAlgo, missingQoP := 0, 0
	if auth != nil {
		for _, ch := range auth.AuthChallenges {
			if ch.StatusCode == "401" {
				c401++
			} else if ch.StatusCode == "407" {
				c407++
			}
			up := strings.ToUpper(ch.Algorithm)
			if up == "" || up == "MD5" {
				weakAlgo++
			}
			if ch.QoP == "" {
				missingQoP++
			}
		}
		authResp = len(auth.AuthResponses)
		for _, att := range auth.RegisterAttempts {
			if !att.Success {
				regFail++
			}
		}
	} else {
		for _, p := range packets {
			if p.StatusCode == "401" {
				c401++
			} else if p.StatusCode == "407" {
				c407++
			}
			if p.Authorization != "" || p.ProxyAuthorization != "" {
				authResp++
			}
		}
	}

	totalCh := c401 + c407
	if totalCh > 0 {
		*qf = append(*qf, "🔐 SIP authentication in use")
	}
	if totalCh > 3 {
		penalty += 15.0
		*df = append(*df, fmt.Sprintf("❌ Excessive auth challenges detected: %d", totalCh))
	}
	if regFail > 0 {
		penalty += 20.0
		*df = append(*df, fmt.Sprintf("❌ Failed REGISTER attempts: %d", regFail))
	}
	if c407 > 2 {
		penalty += 10.0
		*df = append(*df, fmt.Sprintf("⚠️ Cascading proxy auth challenges (407): %d", c407))
	}
	if weakAlgo > 0 {
		penalty += 5.0
		*df = append(*df, "🔓 Weak digest algorithm detected (MD5/unspecified)")
	}
	if totalCh > 0 && float64(missingQoP) > float64(totalCh)/2.0 {
		penalty += 10.0
		*df = append(*df, "🔓 Missing qop in majority of auth challenges")
	}
	if totalCh > 0 && authResp == 0 {
		penalty += 10.0
		*df = append(*df, "❌ Auth challenges present without Authorization responses")
	}
	if penalty == 0 && totalCh > 0 {
		*qf = append(*qf, "✅ Authentication flow appears healthy")
	}
	return max(0.0, 100.0-penalty), penalty, c401, c407, regFail, authResp
}

func scoreCodecQuality(sdpSessions []SDPSessionSpec, rtpStreams []extract.RTPStreamSummary, qf, df *[]string) (float64, map[string]float64) {
	details := map[string]float64{
		"codec_quality":        50.0,
		"bandwidth_efficiency": 50.0,
		"compatibility":        50.0,
		"negotiation":          100.0,
	}
	seen := make(map[string]bool)
	for _, s := range sdpSessions {
		for _, m := range s.Media {
			if m.MediaType == "audio" {
				for _, pt := range m.PayloadTypes {
					if c := mapQualityPayloadToCodec(pt); c != "" {
						seen[c] = true
					}
				}
			}
		}
	}
	if len(seen) == 0 {
		for _, r := range rtpStreams {
			if r.PayloadType != "" {
				if c := mapQualityPayloadToCodec(r.PayloadType); c != "" {
					seen[c] = true
				}
			}
		}
	}

	if len(seen) > 0 {
		var codecs []string
		for c := range seen {
			codecs = append(codecs, c)
		}
		slices.Sort(codecs)
		totQ, totE, totC := 0.0, 0.0, 0.0
		for _, c := range codecs {
			r, ok := codecRatingTable[c]
			if !ok {
				r = codecRatingTable["Unknown"]
			}
			totQ += r.quality
			totE += r.efficiency
			totC += r.compatibility
		}
		n := float64(len(codecs))
		details["codec_quality"] = totQ / n
		details["bandwidth_efficiency"] = totE / n
		details["compatibility"] = totC / n
		if len(codecs) == 1 {
			switch codecs[0] {
			case "G.711", "Opus":
				*qf = append(*qf, "✅ High-quality codec in use: "+codecs[0])
			case "G.729":
				*qf = append(*qf, "💪 Bandwidth-efficient codec: "+codecs[0])
			}
		} else {
			*qf = append(*qf, "🔄 Multiple codecs negotiated: "+strings.Join(codecs, ", "))
		}
		if len(codecs) > 3 {
			details["negotiation"] = 80.0
			*df = append(*df, "⚠️ Excessive codec diversity may cause issues")
		}
	}

	score := details["codec_quality"]*0.5 + details["bandwidth_efficiency"]*0.3 + details["compatibility"]*0.15 + details["negotiation"]*0.05
	return score, details
}

func scoreCallCompletion(sessions []CallSessionSummary, qf, df *[]string) (float64, map[string]float64) {
	details := map[string]float64{
		"setup_success":        100.0,
		"normal_termination":   100.0,
		"session_completeness": 100.0,
		"duration_quality":     100.0,
	}
	if len(sessions) == 0 {
		return 50.0, details
	}
	complete, normalTerm, errTerm := 0, 0, 0
	for _, s := range sessions {
		if s.CompleteSession {
			complete++
			*qf = append(*qf, "✅ Complete call session tracked")
		}
		if s.DisconnectCode != nil && *s.DisconnectCode != "" {
			if strings.HasPrefix(*s.DisconnectCode, "2") {
				normalTerm++
			} else {
				errTerm++
				*df = append(*df, "❌ Error termination: "+*s.DisconnectCode)
			}
		}
	}
	total := len(sessions)
	details["session_completeness"] = float64(complete) / float64(total) * 100.0
	switch {
	case complete == total:
		*qf = append(*qf, "✅ All call sessions complete")
	case float64(complete)/float64(total) >= 0.8:
		*qf = append(*qf, "👍 Most call sessions complete")
	default:
		*df = append(*df, "⚠️ Many incomplete call sessions")
	}
	if normalTerm+errTerm > 0 {
		termRate := float64(normalTerm) / float64(normalTerm+errTerm) * 100.0
		details["normal_termination"] = termRate
		switch {
		case termRate >= 95:
			*qf = append(*qf, "✅ Excellent call termination success")
		case termRate >= 80:
			*qf = append(*qf, "👍 Good call termination rate")
		default:
			*df = append(*df, fmt.Sprintf("⚠️ High error termination rate: %.1f%%", 100.0-termRate))
		}
	}
	score := details["setup_success"]*0.3 + details["normal_termination"]*0.4 + details["session_completeness"]*0.3
	return score, details
}

func mapQualityPayloadToCodec(pt string) string {
	switch pt {
	case "0", "8":
		return "G.711"
	case "9":
		return "G.722"
	case "18":
		return "G.729"
	default:
		return "Unknown"
	}
}
