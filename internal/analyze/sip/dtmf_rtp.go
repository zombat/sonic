// Package sip extracts and validates RFC 4733 / RFC 2833 RTP telephone-event
// (DTMF) digit sequences against SDP dynamic payload type negotiation.
package sip

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

var rtpmapTelEventRe = regexp.MustCompile(`(?i)\brtpmap:(\d+)\s+telephone-event/(\d+)`)

// DTMFDigitEvent captures one logical RFC 4733 DTMF key press per RTP stream.
type DTMFDigitEvent struct {
	Digit       string  `json:"digit"`
	EventID     int     `json:"event_id"`
	DurationMS  int     `json:"duration_ms"`
	Complete    bool    `json:"complete"`
	StartPacket int     `json:"start_packet"`
	EndPacket   int     `json:"end_packet"`
	Epoch       float64 `json:"epoch"`
}

// DTMFStreamDigits holds decoded telephone-event digits for a single RTP stream.
type DTMFStreamDigits struct {
	SSRC        string           `json:"ssrc"`
	SrcIP       string           `json:"src_ip"`
	DstIP       string           `json:"dst_ip"`
	PayloadType string           `json:"payload_type"`
	Digits      string           `json:"digits"`
	Events      []DTMFDigitEvent `json:"events"`
}

// DTMFEventsSummary summarizes negotiated telephone-event payload types and DTMF events.
type DTMFEventsSummary struct {
	NegotiatedPTs    []int              `json:"negotiated_payload_types"`
	TotalPackets     int                `json:"total_packets"`
	CompletedEvents  int                `json:"completed_events"`
	IncompleteEvents int                `json:"incomplete_events"`
	PTMismatchCount  int                `json:"pt_mismatch_count"`
	Digits           string             `json:"digits"`
	Streams          []DTMFStreamDigits `json:"streams"`
	Warnings         []string           `json:"warnings,omitempty"`
}

// AnalyzeDTMFEvents maps SDP telephone-event payload types and decodes RFC 4733 digits.
func AnalyzeDTMFEvents(pkts []extract.SIPPacket, rtpEvents []extract.RTPEventPacket) DTMFEventsSummary {
	ptClocks := parseNegotiatedDTMFPayloadTypes(pkts)
	negotiatedPTs := make([]int, 0, len(ptClocks))
	for pt := range ptClocks {
		negotiatedPTs = append(negotiatedPTs, pt)
	}
	slices.Sort(negotiatedPTs)

	out := DTMFEventsSummary{
		NegotiatedPTs: negotiatedPTs,
		TotalPackets:  len(rtpEvents),
		Streams:       []DTMFStreamDigits{},
	}
	if len(rtpEvents) == 0 {
		return out
	}

	type streamKey struct{ ssrc, src, dst, pt string }
	byStream := make(map[streamKey][]extract.RTPEventPacket)
	order := []streamKey{}
	for _, ev := range rtpEvents {
		ptNum, err := strconv.Atoi(strings.TrimSpace(ev.PayloadType))
		if err == nil && len(ptClocks) > 0 {
			if _, ok := ptClocks[ptNum]; !ok {
				out.PTMismatchCount++
			}
		}
		k := streamKey{ssrc: ev.SSRC, src: ev.SrcIP, dst: ev.DstIP, pt: ev.PayloadType}
		if _, ok := byStream[k]; !ok {
			order = append(order, k)
		}
		byStream[k] = append(byStream[k], ev)
	}

	var allDigits strings.Builder
	for _, k := range order {
		clock := 8000
		if ptNum, err := strconv.Atoi(strings.TrimSpace(k.pt)); err == nil {
			if c, ok := ptClocks[ptNum]; ok && c > 0 {
				clock = c
			}
		}
		events := collapseRTPEventPackets(byStream[k], clock)
		var legDigits strings.Builder
		for _, ev := range events {
			legDigits.WriteString(ev.Digit)
			allDigits.WriteString(ev.Digit)
			if ev.Complete {
				out.CompletedEvents++
			} else {
				out.IncompleteEvents++
			}
		}
		out.Streams = append(out.Streams, DTMFStreamDigits{
			SSRC:        k.ssrc,
			SrcIP:       k.src,
			DstIP:       k.dst,
			PayloadType: k.pt,
			Digits:      legDigits.String(),
			Events:      events,
		})
	}
	out.Digits = allDigits.String()

	if out.PTMismatchCount > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d RFC 4733 packet(s) arrived on payload type not listed in SDP telephone-event rtpmap", out.PTMismatchCount))
	}
	if out.IncompleteEvents > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d DTMF digit event(s) lacked end_of_event=1 marker", out.IncompleteEvents))
	}
	return out
}

func parseNegotiatedDTMFPayloadTypes(pkts []extract.SIPPacket) map[int]int {
	pts := make(map[int]int)
	for _, p := range pkts {
		for _, attr := range p.SDPMediaAttrs {
			for _, m := range rtpmapTelEventRe.FindAllStringSubmatch(attr, -1) {
				pt, err1 := strconv.Atoi(m[1])
				clk, err2 := strconv.Atoi(m[2])
				if err1 == nil && err2 == nil && pt >= 96 && pt <= 127 {
					pts[pt] = clk
				}
			}
		}
		if p.SDPMedia != "" && len(p.SDPMediaAttrs) == 0 {
			for _, tok := range strings.Fields(p.SDPMedia) {
				if tok == "101" {
					if _, exists := pts[101]; !exists {
						pts[101] = 8000
					}
				}
			}
		}
	}
	return pts
}

func collapseRTPEventPackets(pkts []extract.RTPEventPacket, clock int) []DTMFDigitEvent {
	var events []DTMFDigitEvent
	for _, p := range pkts {
		durMS := (p.Duration * 1000) / max(clock, 1)
		n := len(events)
		if n > 0 && !events[n-1].Complete && events[n-1].EventID == p.EventID && (p.Epoch-events[n-1].Epoch) < 0.25 {
			last := &events[n-1]
			last.DurationMS = durMS
			last.EndPacket = p.PacketNum
			if p.EndOfEvent {
				last.Complete = true
			}
			continue
		}
		events = append(events, DTMFDigitEvent{
			Digit:       rfc4733EventLabel(p.EventID),
			EventID:     p.EventID,
			DurationMS:  durMS,
			Complete:    p.EndOfEvent,
			StartPacket: p.PacketNum,
			EndPacket:   p.PacketNum,
			Epoch:       p.Epoch,
		})
	}
	return events
}

func rfc4733EventLabel(id int) string {
	switch {
	case id >= 0 && id <= 9:
		return strconv.Itoa(id)
	case id == 10:
		return "*"
	case id == 11:
		return "#"
	case id >= 12 && id <= 15:
		return string(rune('A' + (id - 12)))
	default:
		return fmt.Sprintf("[%d]", id)
	}
}
