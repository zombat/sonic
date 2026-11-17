// Package sip converts raw Scapy "---PACKET---" SIP message blocks into structured JSON
// matching utils/sip_converter.py.
package sip

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// ScapySIPTextPacket describes one SIP frame extracted from raw Scapy text output.
type ScapySIPTextPacket struct {
	FrameNumber  string `json:"frame.number"`
	FrameTime    string `json:"frame.time"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	SrcPort      string `json:"src_port"`
	DstPort      string `json:"dst_port"`
	Method       string `json:"method,omitempty"`
	RequestURI   string `json:"request_uri,omitempty"`
	StatusCode   string `json:"status_code,omitempty"`
	ReasonPhrase string `json:"reason_phrase,omitempty"`
	CallID       string `json:"call_id,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
}

// ScapySIPData holds parsed Scapy SIP packet summaries for tracking conversion.
type ScapySIPData struct {
	SIPPackets   []ScapySIPTextPacket `json:"sip_packets"`
	TotalPackets int                  `json:"total_packets"`
}

var (
	scapyReqLineRe  = regexp.MustCompile(`^(\w+)\s+(.+?)\s+SIP/2\.0`)
	scapyRespLineRe = regexp.MustCompile(`^SIP/2\.0\s+(\d+)\s+(.+)`)
	scapyATIPRe     = regexp.MustCompile(`@(\d+\.\d+\.\d+\.\d+)`)
	scapyIPPortRe   = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+):(\d+)`)
	scapySIPURIIPRe = regexp.MustCompile(`sip:.*?@(\d+\.\d+\.\d+\.\d+)`)
)

// ParseScapySIPText converts "---PACKET---" delimited SIP blocks into structured packet data.
func ParseScapySIPText(sipText string) ScapySIPData {
	out := ScapySIPData{SIPPackets: []ScapySIPTextPacket{}}
	if sipText == "" {
		return out
	}
	blocks := strings.Split(sipText, "---PACKET---")
	num := 1
	for _, blk := range blocks {
		if strings.TrimSpace(blk) == "" {
			continue
		}
		if pkt, ok := extractScapySIPPacket(blk, num); ok {
			out.SIPPackets = append(out.SIPPackets, pkt)
			num++
		}
	}
	out.TotalPackets = len(out.SIPPackets)
	return out
}

func extractScapySIPPacket(text string, frameNum int) (ScapySIPTextPacket, bool) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 0 {
		return ScapySIPTextPacket{}, false
	}
	pkt := ScapySIPTextPacket{
		FrameNumber: strconv.Itoa(frameNum), FrameTime: "Unknown",
		SrcIP: "Unknown", DstIP: "Unknown", SrcPort: "Unknown", DstPort: "Unknown",
	}
	first := strings.TrimSpace(lines[0])
	for _, pfx := range []string{"INVITE", "BYE", "ACK", "CANCEL", "REGISTER", "OPTIONS", "NOTIFY", "SUBSCRIBE"} {
		if strings.HasPrefix(first, pfx) {
			if m := scapyReqLineRe.FindStringSubmatch(first); m != nil {
				pkt.Method, pkt.RequestURI = m[1], m[2]
			}
			break
		}
	}
	if pkt.Method == "" && strings.HasPrefix(first, "SIP/2.0") {
		if m := scapyRespLineRe.FindStringSubmatch(first); m != nil {
			pkt.StatusCode, pkt.ReasonPhrase = m[1], m[2]
		}
	}
	for _, raw := range lines[1:] {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		val := ""
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			val = strings.TrimSpace(line[idx+1:])
		}
		switch {
		case strings.HasPrefix(low, "call-id:"):
			pkt.CallID = val
		case strings.HasPrefix(low, "from:") && pkt.SrcIP == "Unknown":
			if m := scapyATIPRe.FindStringSubmatch(val); m != nil {
				pkt.SrcIP = m[1]
			}
		case strings.HasPrefix(low, "to:") && pkt.DstIP == "Unknown":
			if m := scapyATIPRe.FindStringSubmatch(val); m != nil {
				pkt.DstIP = m[1]
			}
		case strings.HasPrefix(low, "contact:") && (pkt.Method == "INVITE" || pkt.Method == "REGISTER"):
			if m := scapyATIPRe.FindStringSubmatch(val); m != nil {
				pkt.SrcIP = m[1]
			}
		case strings.HasPrefix(low, "via:") && pkt.SrcIP == "Unknown":
			if m := scapyIPPortRe.FindStringSubmatch(val); m != nil {
				pkt.SrcIP, pkt.SrcPort = m[1], m[2]
			}
		case strings.HasPrefix(low, "user-agent:"):
			pkt.UserAgent = val
		}
	}
	if pkt.SrcIP == "Unknown" || pkt.DstIP == "Unknown" {
		for _, line := range lines {
			matches := scapySIPURIIPRe.FindAllStringSubmatch(line, -1)
			if len(matches) > 0 && pkt.DstIP == "Unknown" {
				pkt.DstIP = matches[0][1]
			}
			if len(matches) > 1 && pkt.SrcIP == "Unknown" {
				pkt.SrcIP = matches[1][1]
			}
		}
	}
	if pkt.SrcPort == "Unknown" {
		pkt.SrcPort = "5060"
	}
	if pkt.DstPort == "Unknown" {
		pkt.DstPort = "5060"
	}
	return pkt, true
}

// ConvertSIPDataForTracking normalizes either JSON or raw Scapy SIP text into tracking JSON.
func ConvertSIPDataForTracking(sipData string) string {
	var probe struct {
		SIPPackets []json.RawMessage `json:"sip_packets"`
	}
	if json.Unmarshal([]byte(sipData), &probe) == nil && probe.SIPPackets != nil {
		return sipData
	}
	parsed := ParseScapySIPText(sipData)
	b, _ := json.MarshalIndent(parsed, "", "  ")
	return string(b)
}
