// Package sip implements weighted VoIP call quality scoring matching
// analyzers/call_quality_scoring.py (network 40%, protocol 30%, codec 20%, completion 10%).
package sip

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

const (
	weightNetwork    = 0.40
	weightProtocol   = 0.30
	weightCodec      = 0.20
	weightCompletion = 0.10
)

// ScoreCallQualityFromJSON parses SIP extraction JSON and scores call quality.
func ScoreCallQualityFromJSON(sipJSON string, sessions []CallSessionSummary, net *NetworkQualityInput, auth *extract.AuthInfo) QualityMetrics {
	var parsed struct {
		SIPPackets  []extract.SIPPacket        `json:"sip_packets"`
		SIPMessages []extract.SIPPacket        `json:"sip_messages"`
		RTPStreams  []extract.RTPStreamSummary `json:"rtp_streams"`
		SDPSessions []SDPSessionSpec           `json:"sdp_sessions"`
	}
	if sipJSON != "" {
		_ = json.Unmarshal([]byte(sipJSON), &parsed)
	}
	pkts := parsed.SIPPackets
	if len(pkts) == 0 {
		pkts = parsed.SIPMessages
	}
	return ScoreCallQuality(ScoringInput{
		SIPPackets:   pkts,
		RTPStreams:   parsed.RTPStreams,
		SDPSessions:  parsed.SDPSessions,
		CallSessions: sessions,
		Network:      net,
		Auth:         auth,
	})
}

// ScoreCallQuality computes weighted network, protocol, codec, and completion quality scores.
func ScoreCallQuality(in ScoringInput) QualityMetrics {
	qFactors := []string{}
	dFactors := []string{}

	netScore, netDetails := scoreNetworkQuality(in.RTPStreams, in.Network, &qFactors, &dFactors)
	protoScore, protoDetails := scoreProtocolQuality(in.SIPPackets, in.CallSessions, in.Auth, &qFactors, &dFactors)
	codecScore, codecDetails := scoreCodecQuality(in.SDPSessions, in.RTPStreams, &qFactors, &dFactors)
	compScore, compDetails := scoreCallCompletion(in.CallSessions, &qFactors, &dFactors)

	overall := netScore*weightNetwork + protoScore*weightProtocol + codecScore*weightCodec + compScore*weightCompletion
	return QualityMetrics{
		NetworkScore:       netScore,
		ProtocolScore:      protoScore,
		CodecScore:         codecScore,
		CompletionScore:    compScore,
		OverallScore:       overall,
		Grade:              determineQualityGrade(overall),
		NetworkDetails:     netDetails,
		ProtocolDetails:    protoDetails,
		CodecDetails:       codecDetails,
		CompletionDetails:  compDetails,
		QualityFactors:     qFactors,
		DegradationFactors: dFactors,
	}
}

func scoreNetworkQuality(rtpStreams []extract.RTPStreamSummary, net *NetworkQualityInput, qf, df *[]string) (float64, map[string]float64) {
	details := map[string]float64{
		"qos_markings":    0.0,
		"rtp_streams":     0.0,
		"packet_loss":     100.0,
		"jitter":          100.0,
		"baseline_health": 0.0,
	}
	score := 0.0
	count := 0.0

	if net != nil && (net.HasRealIssues || len(net.RealIssuesDetected) > 0) {
		var qosIssues []string
		for _, issue := range net.RealIssuesDetected {
			if strings.Contains(issue, "QoS") {
				qosIssues = append(qosIssues, issue)
			}
		}
		if len(qosIssues) == 0 {
			details["qos_markings"] = 100.0
			*qf = append(*qf, "✅ Proper QoS markings detected")
		} else {
			details["qos_markings"] = max(0.0, 100.0-float64(len(qosIssues)*25))
			for _, issue := range qosIssues {
				*df = append(*df, "❌ "+issue)
			}
		}
		score += details["qos_markings"]
		count++
	}

	if len(rtpStreams) > 0 {
		details["rtp_streams"] = 90.0
		*qf = append(*qf, fmt.Sprintf("✅ %d RTP streams detected", len(rtpStreams)))
		score += details["rtp_streams"]
	} else {
		details["rtp_streams"] = 30.0
		*df = append(*df, "⚠️ No RTP streams detected")
		score += details["rtp_streams"]
	}
	count++

	if net != nil && net.TCPHealthScore != nil {
		hs := *net.TCPHealthScore
		details["baseline_health"] = hs
		switch {
		case hs >= 90:
			*qf = append(*qf, "✅ Excellent network baseline health")
		case hs >= 70:
			*qf = append(*qf, "👍 Good network baseline health")
		default:
			*df = append(*df, fmt.Sprintf("⚠️ Network baseline health: %v/100", hs))
		}
		score += hs
		count++
	}

	if count > 0 {
		return score / count, details
	}
	return 50.0, details
}

func scoreProtocolQuality(packets []extract.SIPPacket, sessions []CallSessionSummary, auth *extract.AuthInfo, qf, df *[]string) (float64, map[string]float64) {
	details := map[string]float64{
		"response_success":    100.0,
		"error_rate":          100.0,
		"setup_efficiency":    100.0,
		"authentication":      100.0,
		"auth_penalty":        0.0,
		"auth_challenges_401": 0.0,
		"auth_challenges_407": 0.0,
		"register_failures":   0.0,
		"auth_responses":      0.0,
	}

	totalResp, successResp, errorResp := 0, 0, 0
	for _, msg := range packets {
		code := msg.StatusCode
		if code == "" {
			continue
		}
		totalResp++
		switch {
		case strings.HasPrefix(code, "2"):
			successResp++
		case code == "401" || code == "407":
			errorResp++
		case strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5"):
			errorResp++
		}
	}

	if totalResp > 0 {
		succRate := float64(successResp) / float64(totalResp) * 100.0
		details["response_success"] = succRate
		switch {
		case succRate >= 95:
			*qf = append(*qf, "✅ Excellent SIP response success rate")
		case succRate >= 80:
			*qf = append(*qf, "👍 Good SIP response success rate")
		default:
			*df = append(*df, fmt.Sprintf("⚠️ Low SIP success rate: %.1f%%", succRate))
		}

		errRate := float64(errorResp) / float64(totalResp) * 100.0
		details["error_rate"] = max(0.0, 100.0-errRate*2.0)
		switch {
		case errRate == 0:
			*qf = append(*qf, "✅ No SIP protocol errors")
		case errRate < 5:
			*qf = append(*qf, "👍 Low SIP error rate")
		default:
			*df = append(*df, fmt.Sprintf("❌ High SIP error rate: %.1f%%", errRate))
		}
	}

	authScore, authPenalty, c401, c407, regFail, authResp := analyzeAuthSecurity(packets, auth, qf, df)
	details["authentication"] = authScore
	details["auth_penalty"] = authPenalty
	details["auth_challenges_401"] = float64(c401)
	details["auth_challenges_407"] = float64(c407)
	details["register_failures"] = float64(regFail)
	details["auth_responses"] = float64(authResp)

	if totalCalls := len(sessions); totalCalls > 0 {
		complete := 0
		for _, s := range sessions {
			if s.CompleteSession {
				complete++
			}
		}
		compRate := float64(complete) / float64(totalCalls) * 100.0
		details["setup_efficiency"] = compRate
		switch {
		case compRate >= 90:
			*qf = append(*qf, "✅ Excellent call setup efficiency")
		case compRate >= 70:
			*qf = append(*qf, "👍 Good call setup efficiency")
		default:
			*df = append(*df, fmt.Sprintf("⚠️ Poor call setup efficiency: %.1f%%", compRate))
		}
	}

	score := details["response_success"]*0.4 + details["error_rate"]*0.3 + details["setup_efficiency"]*0.2 + details["authentication"]*0.1
	return score, details
}

func determineQualityGrade(score float64) QualityGrade {
	switch {
	case score >= 90:
		return GradeExcellent
	case score >= 80:
		return GradeVeryGood
	case score >= 70:
		return GradeGood
	case score >= 60:
		return GradeFair
	case score >= 40:
		return GradePoor
	default:
		return GradeFailed
	}
}
