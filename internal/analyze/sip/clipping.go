// Package sip detects post-200 OK RTP media start clipping delays and
// SDP offer/answer modes across extracted SIP and RTP streams.
package sip

import (
	"fmt"
	"math"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

const (
	clippingWarnMS     = 500.0
	clippingCriticalMS = 2000.0
)

// CallClippingEvent summarizes post-200 OK media startup timing for one SIP call.
type CallClippingEvent struct {
	CallID         string   `json:"call_id"`
	OfferMode      string   `json:"offer_mode"`
	OKEpoch        float64  `json:"ok_epoch"`
	FirstRTPEpoch  *float64 `json:"first_rtp_epoch,omitempty"`
	DelayMS        float64  `json:"delay_ms"`
	EarlyMedia     bool     `json:"early_media"`
	NoMediaAfterOK bool     `json:"no_media_after_ok"`
	Severity       string   `json:"severity"`
	Direction      string   `json:"direction,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// MediaClippingSummary aggregates post-200 OK media clipping metrics across calls.
type MediaClippingSummary struct {
	AnalyzedCalls     int                 `json:"analyzed_calls"`
	EarlyOfferCalls   int                 `json:"early_offer_calls"`
	DelayedOfferCalls int                 `json:"delayed_offer_calls"`
	EarlyMediaCalls   int                 `json:"early_media_calls"`
	WarningCount      int                 `json:"warning_count"`
	CriticalCount     int                 `json:"critical_count"`
	NoMediaCount      int                 `json:"no_media_count"`
	MaxDelayMS        float64             `json:"max_delay_ms"`
	Verdict           string              `json:"verdict"`
	CallEvents        []CallClippingEvent `json:"call_events"`
}

type trackedCallWindow struct {
	callID      string
	inviteEpoch *float64
	okEpoch     *float64
	inviteSDP   bool
	okSDP       bool
	ips         map[string]bool
	sdpPorts    map[string]bool
}

// AnalyzeMediaClipping computes per-call millisecond delay between SIP INVITE 200 OK
// responses and the first observed RTP packet in either direction.
func AnalyzeMediaClipping(pkts []extract.SIPPacket, streams []extract.RTPStreamSummary) MediaClippingSummary {
	calls := make(map[string]*trackedCallWindow)
	order := []string{}
	for _, p := range pkts {
		if p.CallID == "" {
			continue
		}
		cw, ok := calls[p.CallID]
		if !ok {
			cw = &trackedCallWindow{
				callID:   p.CallID,
				ips:      map[string]bool{},
				sdpPorts: map[string]bool{},
			}
			calls[p.CallID] = cw
			order = append(order, p.CallID)
		}
		if p.SrcIP != "" && p.SrcIP != "Unknown" {
			cw.ips[p.SrcIP] = true
		}
		if p.DstIP != "" && p.DstIP != "Unknown" {
			cw.ips[p.DstIP] = true
		}
		if p.SDPMediaPort != "" {
			cw.sdpPorts[p.SDPMediaPort] = true
		}
		hasSDP := p.SDPMedia != "" || p.SDPMediaPort != "" || p.SDPVersion != ""
		if p.Method == "INVITE" {
			if cw.inviteEpoch == nil && p.Epoch != nil {
				e := *p.Epoch
				cw.inviteEpoch = &e
			}
			if hasSDP {
				cw.inviteSDP = true
			}
		}
		isInviteOK := p.StatusCode == "200" && (p.CSeqMethod == "INVITE" || (p.CSeqMethod == "" && cw.inviteEpoch != nil))
		if isInviteOK {
			if cw.okEpoch == nil && p.Epoch != nil {
				e := *p.Epoch
				cw.okEpoch = &e
			}
			if hasSDP {
				cw.okSDP = true
			}
		}
	}

	out := MediaClippingSummary{CallEvents: []CallClippingEvent{}}
	for _, cid := range order {
		cw := calls[cid]
		if cw.okEpoch == nil {
			continue
		}
		ev := evaluateCallClipping(cw, streams)
		out.AnalyzedCalls++
		switch ev.OfferMode {
		case "early_offer":
			out.EarlyOfferCalls++
		case "delayed_offer":
			out.DelayedOfferCalls++
		}
		if ev.EarlyMedia {
			out.EarlyMediaCalls++
		}
		switch ev.Severity {
		case "warning":
			if ev.NoMediaAfterOK {
				out.NoMediaCount++
			} else {
				out.WarningCount++
			}
		case "critical":
			out.CriticalCount++
		}
		if ev.DelayMS > out.MaxDelayMS {
			out.MaxDelayMS = ev.DelayMS
		}
		out.CallEvents = append(out.CallEvents, ev)
	}
	out.Verdict = formatClippingVerdict(out)
	return out
}

func evaluateCallClipping(cw *trackedCallWindow, streams []extract.RTPStreamSummary) CallClippingEvent {
	offerMode := "unknown"
	switch {
	case cw.inviteSDP:
		offerMode = "early_offer"
	case !cw.inviteSDP && cw.okSDP:
		offerMode = "delayed_offer"
	}
	okEp := *cw.okEpoch
	bestStream, matched := findEarliestCallRTP(cw, okEp, streams)
	if !matched {
		return CallClippingEvent{
			CallID:         cw.callID,
			OfferMode:      offerMode,
			OKEpoch:        okEp,
			NoMediaAfterOK: true,
			Severity:       "warning",
			Note:           "200 OK seen with no matching RTP media packets",
		}
	}

	firstRTP := *bestStream.FirstEpoch
	deltaMS := (firstRTP - okEp) * 1000.0
	dir := fmt.Sprintf("%s:%s -> %s:%s", bestStream.SrcIP, bestStream.SrcPort, bestStream.DstIP, bestStream.DstPort)
	if deltaMS < 0 {
		return CallClippingEvent{
			CallID:        cw.callID,
			OfferMode:     offerMode,
			OKEpoch:       okEp,
			FirstRTPEpoch: &firstRTP,
			DelayMS:       0,
			EarlyMedia:    true,
			Severity:      "ok",
			Direction:     dir,
			Note:          "Early media active before 200 OK",
		}
	}

	rounded := math.Round(deltaMS*100) / 100
	sev := "ok"
	note := "Normal post-200 OK media start"
	if rounded > clippingCriticalMS {
		sev = "critical"
		note = fmt.Sprintf("Severe %.1f ms post-200 OK media clipping (>2000 ms; check firewall pinhole or NAT latch)", rounded)
	} else if rounded > clippingWarnMS {
		sev = "warning"
		note = fmt.Sprintf("Elevated %.1f ms post-200 OK media delay (>500 ms; initial speech clipping risk)", rounded)
	}
	return CallClippingEvent{
		CallID:        cw.callID,
		OfferMode:     offerMode,
		OKEpoch:       okEp,
		FirstRTPEpoch: &firstRTP,
		DelayMS:       rounded,
		Severity:      sev,
		Direction:     dir,
		Note:          note,
	}
}

func findEarliestCallRTP(cw *trackedCallWindow, okEp float64, streams []extract.RTPStreamSummary) (extract.RTPStreamSummary, bool) {
	windowStart := okEp - 30.0
	if cw.inviteEpoch != nil && *cw.inviteEpoch-1.0 < windowStart {
		windowStart = *cw.inviteEpoch - 1.0
	}
	windowEnd := okEp + 120.0

	var best extract.RTPStreamSummary
	found := false
	for _, st := range streams {
		if st.FirstEpoch == nil {
			continue
		}
		if *st.FirstEpoch < windowStart || *st.FirstEpoch > windowEnd {
			continue
		}
		portMatch := cw.sdpPorts[st.SrcPort] || cw.sdpPorts[st.DstPort]
		ipMatch := cw.ips[st.SrcIP] || cw.ips[st.DstIP]
		if len(cw.sdpPorts) > 0 && !portMatch && !ipMatch {
			continue
		}
		if !found || *st.FirstEpoch < *best.FirstEpoch {
			best = st
			found = true
		}
	}
	return best, found
}

func formatClippingVerdict(s MediaClippingSummary) string {
	if s.AnalyzedCalls == 0 {
		return "No INVITE 200 OK calls with timestamps found for clipping analysis."
	}
	parts := []string{fmt.Sprintf("%d call(s) analyzed (max post-200 OK delay %.1f ms)", s.AnalyzedCalls, s.MaxDelayMS)}
	if s.CriticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical clipping", s.CriticalCount))
	}
	if s.WarningCount > 0 {
		parts = append(parts, fmt.Sprintf("%d warning delay", s.WarningCount))
	}
	if s.NoMediaCount > 0 {
		parts = append(parts, fmt.Sprintf("%d missing media after 200 OK", s.NoMediaCount))
	}
	if s.EarlyMediaCalls > 0 {
		parts = append(parts, fmt.Sprintf("%d early media", s.EarlyMediaCalls))
	}
	return strings.Join(parts, "; ") + "."
}
