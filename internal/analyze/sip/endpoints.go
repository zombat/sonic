// Package sip provides SDP media parsing and SIP endpoint role profiling matching
// analyzers/endpoint_analysis.py.
package sip

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

// SDPMediaAnalysis holds parsed fields and explanations for one SDP m= media line.
type SDPMediaAnalysis struct {
	MediaType       string   `json:"media_type"`
	Port            string   `json:"port"`
	Protocol        string   `json:"protocol"`
	PayloadTypes    []string `json:"payload_types"`
	AudioCodecs     []string `json:"audio_codecs"`
	DTMFSupport     bool     `json:"dtmf_support"`
	DynamicPayloads []string `json:"dynamic_payloads"`
	Explanation     []string `json:"explanation"`
}

// EndpointProfile summarizes observed SIP signaling, roles, codecs, and auth realms per IP.
type EndpointProfile struct {
	IP               string   `json:"ip"`
	SIPAddresses     []string `json:"sip_addresses"`
	MethodsSent      []string `json:"methods_sent"`
	StatusCodesSent  []string `json:"status_codes_sent"`
	UserAgents       []string `json:"user_agents"`
	CodecsOffered    []string `json:"codecs_offered"`
	Role             string   `json:"role"`
	AuthRealms       []string `json:"auth_realms"`
	SDPOfferCount    int      `json:"sdp_offer_count"`
	ChallengeCount   int      `json:"challenge_count"`
	RegisterMsgCount int      `json:"register_msg_count"`
}

// AnalyzeSDPMediaLine parses an SDP "m=" line into codecs, DTMF flag, and explanations.
func AnalyzeSDPMediaLine(mediaLine string) SDPMediaAnalysis {
	out := SDPMediaAnalysis{
		PayloadTypes: []string{}, AudioCodecs: []string{},
		DynamicPayloads: []string{}, Explanation: []string{},
	}
	trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(mediaLine), "m="))
	parts := strings.Fields(trimmed)
	if len(parts) < 4 {
		return out
	}
	out.MediaType, out.Port, out.Protocol = parts[0], parts[1], parts[2]
	out.PayloadTypes = parts[3:]
	for _, pt := range out.PayloadTypes {
		name := GetCodecNameFromPayloadType(pt)
		switch pt {
		case "101":
			out.DTMFSupport = true
			out.Explanation = append(out.Explanation, "Payload type 101: DTMF/Telephone-Event support (RFC 4733). DTMF tones will be sent out-of-band as separate RTP packets, not as in-band audio tones.")
		case "0", "8", "9", "18":
			out.AudioCodecs = append(out.AudioCodecs, name)
			out.Explanation = append(out.Explanation, fmt.Sprintf("Payload type %s: %s audio codec", pt, name))
		default:
			if n, err := strconv.Atoi(pt); err == nil && n >= 96 {
				out.DynamicPayloads = append(out.DynamicPayloads, pt)
				out.Explanation = append(out.Explanation, fmt.Sprintf("Payload type %s: %s (dynamic assignment)", pt, name))
			} else {
				out.Explanation = append(out.Explanation, fmt.Sprintf("Payload type %s: %s", pt, name))
			}
		}
	}
	return out
}

type endpointAccum struct {
	ip               string
	sipAddrs         map[string]bool
	methods          map[string]bool
	statuses         map[string]bool
	userAgents       map[string]bool
	codecs           map[string]bool
	role             string
	realms           map[string]bool
	sdpCount         int
	challengeCount   int
	registerMsgCount int
}

// AnalyzeEndpoints builds deterministic per-IP endpoint role and capability profiles.
func AnalyzeEndpoints(packets []extract.SIPPacket, auth *extract.AuthInfo) map[string]EndpointProfile {
	acc := make(map[string]*endpointAccum)
	get := func(ip string) *endpointAccum {
		if a, ok := acc[ip]; ok {
			return a
		}
		a := &endpointAccum{
			ip: ip, sipAddrs: map[string]bool{}, methods: map[string]bool{},
			statuses: map[string]bool{}, userAgents: map[string]bool{},
			codecs: map[string]bool{}, role: "unknown", realms: map[string]bool{},
		}
		acc[ip] = a
		return a
	}
	if auth != nil {
		for _, ch := range auth.AuthChallenges {
			if ch.ToIP != "" {
				ep := get(ch.ToIP)
				ep.role = "registration_client"
				if ch.Realm != "" {
					ep.realms[ch.Realm] = true
				}
			}
		}
	}
	for _, p := range packets {
		if p.SrcIP == "" || p.SrcIP == "Unknown" {
			continue
		}
		ep := get(p.SrcIP)
		if p.FromAddr != "" && p.Method != "" {
			ep.sipAddrs[p.FromAddr] = true
		}
		if p.Method != "" {
			ep.methods[p.Method] = true
			switch p.Method {
			case "INVITE":
				ep.role = "caller"
			case "REGISTER":
				ep.role = "registration_client"
				ep.registerMsgCount++
			}
		}
		if p.StatusCode != "" {
			ep.statuses[p.StatusCode] = true
			if (p.StatusCode == "100" || p.StatusCode == "180" || p.StatusCode == "183" || p.StatusCode == "200") && ep.role == "unknown" {
				ep.role = "callee"
			}
			if p.StatusCode == "401" || p.StatusCode == "407" {
				ep.role = "sip_server"
				ep.challengeCount++
			}
		}
		if p.UserAgent != "" {
			ep.userAgents[p.UserAgent] = true
		}
		if p.SDPMedia != "" {
			ep.sdpCount++
			for _, codec := range AnalyzeSDPMediaLine(p.SDPMedia).AudioCodecs {
				ep.codecs[codec] = true
			}
		}
	}
	out := make(map[string]EndpointProfile, len(acc))
	for ip, ep := range acc {
		out[ip] = EndpointProfile{
			IP: ip, SIPAddresses: sortedKeys(ep.sipAddrs), MethodsSent: sortedKeys(ep.methods),
			StatusCodesSent: sortedKeys(ep.statuses), UserAgents: sortedKeys(ep.userAgents),
			CodecsOffered: sortedKeys(ep.codecs), Role: ep.role, AuthRealms: sortedKeys(ep.realms),
			SDPOfferCount: ep.sdpCount, ChallengeCount: ep.challengeCount, RegisterMsgCount: ep.registerMsgCount,
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
