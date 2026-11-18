// Package sip detects SIP overlap dialing patterns (progressive Request-URIs, re-INVITE,
// INFO, NOTIFY) matching analyzers/overlap_dialing.py.
package sip

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

// DigitEvent captures one DTMF, function, special, or progressive digit event.
type DigitEvent struct {
	CallID        string `json:"call_id,omitempty"`
	Digit         string `json:"digit,omitempty"`
	DigitSequence string `json:"digit_sequence,omitempty"`
	Packet        int    `json:"packet"`
	Pattern       string `json:"pattern"`
	KeyType       string `json:"key_type"`
	Legacy        bool   `json:"legacy,omitempty"`
}

// DigitKeysResult holds digit events extracted by ExtractDigitKeysFromSIPData.
type DigitKeysResult struct {
	OverlapDialingDetected bool         `json:"overlap_dialing_detected"`
	DigitEvents            []DigitEvent `json:"digit_events"`
	CallSetupMethod        string       `json:"call_setup_method"`
	TotalEvents            int          `json:"total_events"`
}

// URIProgressionEntry describes one SIP request URI along a call's dialing sequence.
type URIProgressionEntry struct {
	Packet int    `json:"packet"`
	Number string `json:"number"`
	Time   string `json:"time"`
	Method string `json:"method"`
}

// OverlapTimingAnalysis records packet spacing for overlap calls, marshaling as {} when unset.
type OverlapTimingAnalysis struct {
	Populated           bool  `json:"-"`
	FirstInvitePacket   int   `json:"first_invite_packet"`
	LastMessagePacket   int   `json:"last_message_packet"`
	TotalMessages       int   `json:"total_messages"`
	InterMessagePackets []int `json:"inter_message_packets"`
}

// MarshalJSON omits timing fields as `{}` when no overlap timing was recorded.
func (t OverlapTimingAnalysis) MarshalJSON() ([]byte, error) {
	if !t.Populated {
		return []byte("{}"), nil
	}
	type alias struct {
		FirstInvitePacket   int   `json:"first_invite_packet"`
		LastMessagePacket   int   `json:"last_message_packet"`
		TotalMessages       int   `json:"total_messages"`
		InterMessagePackets []int `json:"inter_message_packets"`
	}
	return json.Marshal(alias{
		FirstInvitePacket:   t.FirstInvitePacket,
		LastMessagePacket:   t.LastMessagePacket,
		TotalMessages:       t.TotalMessages,
		InterMessagePackets: t.InterMessagePackets,
	})
}

// CallOverlapDetail summarizes overlap dialing findings for a single Call-ID.
type CallOverlapDetail struct {
	OverlapDetected  bool                  `json:"overlap_detected"`
	PatternType      *string               `json:"pattern_type"`
	Evidence         []string              `json:"evidence"`
	DigitProgression []URIProgressionEntry `json:"digit_progression"`
	TimingAnalysis   OverlapTimingAnalysis `json:"timing_analysis"`
	InviteCount      int                   `json:"invite_count"`
	ReinviteCount    int                   `json:"reinvite_count"`
	InfoCount        int                   `json:"info_count"`
	NotifyCount      int                   `json:"notify_count,omitempty"`
	CollectedDigits  []DigitEvent          `json:"collected_digits"`
	DigitSequence    string                `json:"digit_sequence"`
}

// OverlapAnalysisResult summarizes overlap vs en-bloc dialing across all calls in a capture.
type OverlapAnalysisResult struct {
	OverlapDetected    bool                         `json:"overlap_detected"`
	TotalCallsAnalyzed int                          `json:"total_calls_analyzed"`
	OverlapCallsCount  int                          `json:"overlap_calls_count"`
	CallDetails        map[string]CallOverlapDetail `json:"call_details,omitempty"`
	OverallPattern     string                       `json:"overall_pattern,omitempty"`
	Reason             string                       `json:"reason,omitempty"`
}

type overlapReq struct {
	packetNum  int
	requestURI string
	time       string
	reqType    string
}

// DetectOverlapDialing analyzes SIP extraction JSON for per-Call-ID overlap dialing patterns.
func DetectOverlapDialing(sipData string) OverlapAnalysisResult {
	var parsed struct {
		SIPPackets []extract.SIPPacket `json:"sip_packets"`
	}
	if err := json.Unmarshal([]byte(sipData), &parsed); err != nil || parsed.SIPPackets == nil {
		return OverlapAnalysisResult{OverlapDetected: false, Reason: "No SIP packet data available"}
	}
	if len(parsed.SIPPackets) == 0 {
		return OverlapAnalysisResult{OverlapDetected: false, Reason: "No SIP packets found"}
	}

	calls := make(map[string][]extract.SIPPacket)
	var callOrder []string
	for _, p := range parsed.SIPPackets {
		cid := defaultStr(p.CallID, "Unknown")
		if _, ok := calls[cid]; !ok {
			callOrder = append(callOrder, cid)
		}
		calls[cid] = append(calls[cid], p)
	}

	digitInfo := ExtractDigitKeysFromSIPData(sipData)
	details := make(map[string]CallOverlapDetail, len(calls))
	overlapCalls := 0
	for _, cid := range callOrder {
		d := analyzeCallOverlap(cid, calls[cid], digitInfo.DigitEvents)
		if d.OverlapDetected {
			overlapCalls++
		}
		details[cid] = d
	}

	pattern := "En-bloc dialing (complete numbers sent at once)"
	if overlapCalls > 0 {
		pattern = "Multiple overlap dialing patterns detected"
	}
	return OverlapAnalysisResult{
		OverlapDetected:    overlapCalls > 0,
		TotalCallsAnalyzed: len(calls),
		OverlapCallsCount:  overlapCalls,
		CallDetails:        details,
		OverallPattern:     pattern,
	}
}

func analyzeCallOverlap(callID string, pkts []extract.SIPPacket, digitEvents []DigitEvent) CallOverlapDetail {
	d := CallOverlapDetail{
		Evidence:         []string{},
		DigitProgression: []URIProgressionEntry{},
		CollectedDigits:  []DigitEvent{},
	}
	sorted := append([]extract.SIPPacket(nil), pkts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].PacketNum < sorted[j].PacketNum })

	var invites, reinvites, infoMsgs []overlapReq
	for _, p := range sorted {
		req := overlapReq{packetNum: p.PacketNum, requestURI: p.RequestURI, time: p.Time}
		switch p.Method {
		case "INVITE":
			if len(invites) == 0 {
				req.reqType = "initial"
				invites = append(invites, req)
				d.InviteCount++
			} else {
				req.reqType = "reinvite"
				reinvites = append(reinvites, req)
				d.ReinviteCount++
			}
		case "INFO":
			req.reqType = "info"
			infoMsgs = append(infoMsgs, req)
			d.InfoCount++
		case "NOTIFY":
			req.reqType = "notify"
			infoMsgs = append(infoMsgs, req)
			d.NotifyCount++
		}
	}

	allReqs := make([]overlapReq, 0, len(invites)+len(reinvites)+len(infoMsgs))
	allReqs = append(allReqs, invites...)
	allReqs = append(allReqs, reinvites...)
	allReqs = append(allReqs, infoMsgs...)

	if len(allReqs) > 1 {
		for _, r := range allReqs {
			if strings.Contains(r.requestURI, "sip:") && strings.Contains(r.requestURI, "@") {
				num := strings.SplitN(strings.SplitN(r.requestURI, "sip:", 2)[1], "@", 2)[0]
				num = strings.SplitN(num, ";", 2)[0]
				d.DigitProgression = append(d.DigitProgression, URIProgressionEntry{
					Packet: r.packetNum, Number: num, Time: r.time, Method: r.reqType,
				})
			}
		}
		evalOverlapPatterns(&d)
	}

	var callDigits []DigitEvent
	for _, ev := range digitEvents {
		if ev.CallID != "" && ev.CallID == callID {
			callDigits = append(callDigits, ev)
		}
	}
	if len(callDigits) > 0 {
		applyCallDigits(&d, callDigits)
	}

	if d.OverlapDetected && len(allReqs) > 1 {
		inter := make([]int, 0, len(allReqs)-1)
		for i := 1; i < len(allReqs); i++ {
			inter = append(inter, allReqs[i].packetNum-allReqs[i-1].packetNum)
		}
		d.TimingAnalysis = OverlapTimingAnalysis{
			Populated:           true,
			FirstInvitePacket:   allReqs[0].packetNum,
			LastMessagePacket:   allReqs[len(allReqs)-1].packetNum,
			TotalMessages:       len(allReqs),
			InterMessagePackets: inter,
		}
	}
	return d
}
