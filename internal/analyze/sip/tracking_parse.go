// Package sip parses tshark JSON and SIP summary JSON into CallEvent values
// matching analyzers/call_tracking.py:parse_sip_events_from_json.
package sip

import (
	"encoding/json"
	"strconv"
)

var terminatingStatusReasons = map[string]string{
	"408": "Request Timeout",
	"480": "Temporarily Unavailable",
	"486": "Busy Here",
	"487": "Request Terminated",
	"504": "Server Time-out",
	"600": "Busy Everywhere",
	"603": "Decline",
}

// ParseSIPEventsFromJSON parses tshark summary or raw layer JSON into INVITE/BYE/error CallEvents.
func ParseSIPEventsFromJSON(jsonData string) []CallEvent {
	if jsonData == "" {
		return []CallEvent{}
	}
	var raw []json.RawMessage
	var obj struct {
		SIPPackets []json.RawMessage `json:"sip_packets"`
		Source     *json.RawMessage  `json:"_source"`
	}
	if err := json.Unmarshal([]byte(jsonData), &raw); err != nil {
		if err := json.Unmarshal([]byte(jsonData), &obj); err != nil {
			return []CallEvent{}
		}
		if len(obj.SIPPackets) > 0 {
			raw = obj.SIPPackets
		} else if obj.Source != nil {
			raw = []json.RawMessage{[]byte(jsonData)}
		}
	}
	events := []CallEvent{}
	for _, item := range raw {
		if ev, ok := parseSingleCallEvent(item); ok {
			events = append(events, ev)
		}
	}
	return events
}

type rawCallPacket struct {
	FrameNumber int    `json:"packet_num"`
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     string `json:"src_port"`
	DstPort     string `json:"dst_port"`
	CallID      string `json:"call_id"`
	Method      string `json:"method"`
	StatusCode  string `json:"status_code"`
	UserAgent   string `json:"user_agent"`
	FrameNumStr string `json:"frame.number"`
	Source      *struct {
		Layers struct {
			Frame struct {
				Number []string `json:"frame.number"`
				Time   []string `json:"frame.time"`
			} `json:"frame"`
			IP struct {
				Src []string `json:"ip.src"`
				Dst []string `json:"ip.dst"`
			} `json:"ip"`
			UDP struct {
				SrcPort []string `json:"udp.srcport"`
				DstPort []string `json:"udp.dstport"`
			} `json:"udp"`
			SIP *struct {
				CallID     []string `json:"sip.Call-ID"`
				Method     []string `json:"sip.Method"`
				StatusCode []string `json:"sip.Status-Code"`
				UserAgent  []string `json:"sip.User-Agent"`
			} `json:"sip"`
		} `json:"layers"`
	} `json:"_source"`
}

func parseSingleCallEvent(raw json.RawMessage) (CallEvent, bool) {
	var p rawCallPacket
	if err := json.Unmarshal(raw, &p); err != nil {
		return CallEvent{}, false
	}
	ts, srcIP, dstIP, srcPort, dstPort, callID, method, code, ua :=
		defaultStr(p.Timestamp, "Unknown"), defaultStr(p.SrcIP, "Unknown"), defaultStr(p.DstIP, "Unknown"),
		defaultStr(p.SrcPort, "Unknown"), defaultStr(p.DstPort, "Unknown"), defaultStr(p.CallID, "Unknown"),
		p.Method, p.StatusCode, p.UserAgent
	frameNum := p.FrameNumber
	if frameNum == 0 && p.FrameNumStr != "" {
		if v, err := strconv.Atoi(p.FrameNumStr); err == nil {
			frameNum = v
		}
	}
	if p.Source != nil {
		if p.Source.Layers.SIP == nil {
			return CallEvent{}, false
		}
		l := p.Source.Layers
		if len(l.Frame.Number) > 0 {
			frameNum, _ = strconv.Atoi(l.Frame.Number[0])
		}
		ts = firstOr(l.Frame.Time, ts)
		srcIP = firstOr(l.IP.Src, srcIP)
		dstIP = firstOr(l.IP.Dst, dstIP)
		srcPort = firstOr(l.UDP.SrcPort, srcPort)
		dstPort = firstOr(l.UDP.DstPort, dstPort)
		callID = firstOr(l.SIP.CallID, callID)
		method = firstOr(l.SIP.Method, "")
		code = firstOr(l.SIP.StatusCode, "")
		ua = firstOr(l.SIP.UserAgent, "")
	} else if callID == "Unknown" && method == "" && p.CallID == "" {
		return CallEvent{}, false
	}
	var uaPtr *string
	if ua != "" {
		uaPtr = &ua
	}
	if method == "INVITE" || method == "BYE" {
		return CallEvent{
			FrameNumber: frameNum, Timestamp: ts, CallID: callID, Method: method,
			SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, UserAgent: uaPtr,
		}, true
	}
	if reason, ok := terminatingStatusReasons[code]; ok {
		return CallEvent{
			FrameNumber: frameNum, Timestamp: ts, CallID: callID, Method: "RESPONSE_" + code,
			SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
			StatusCode: &code, ReasonPhrase: &reason, UserAgent: uaPtr,
		}, true
	}
	return CallEvent{}, false
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func firstOr(vs []string, fallback string) string {
	if len(vs) > 0 && vs[0] != "" {
		return vs[0]
	}
	return fallback
}
