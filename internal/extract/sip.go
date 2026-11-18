// Package extract extracts masked SIP signaling, SDP media hints, RTP stream
// summaries, and RFC 4733 RTP telephone-event frames from packet captures.
package extract

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/zombat/sonic/internal/tshark"
)

var sipTsharkFields = []string{
	"frame.number", "frame.time", "frame.time_epoch",
	"ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
	"sip.Call-ID", "sip.Method", "sip.Status-Code",
	"sip.r-uri", "sip.from.addr", "sip.to.addr",
	"sip.User-Agent",
	"sip.Authorization", "sip.Proxy-Authorization",
	"sip.WWW-Authenticate", "sip.Proxy-Authenticate",
	"sip.Status-Line", "sip.Reason", "sip.Request-Line",
	"sip.contact.uri", "sip.from.tag", "sip.to.tag",
	"sip.CSeq.method", "sip.CSeq.seq", "sip.Expires",
	"sdp.version", "sdp.media", "sdp.media.port",
	"sdp.media.proto", "sdp.media_attr", "sdp.owner.username", "sdp.session_name",
	"rtp.ssrc", "rtp.seq", "rtp.p_type",
	"rtpevent.event_id", "rtpevent.duration", "rtpevent.end_of_event",
	"udp.srcport", "udp.dstport", "udp.length",
	"frame.protocols",
}

// SIPPacket holds masked SIP signaling and SDP metadata for a single captured frame.
type SIPPacket struct {
	PacketNum          int      `json:"packet_num"`
	Time               string   `json:"time"`
	Epoch              *float64 `json:"epoch,omitempty"`
	SrcIP              string   `json:"src_ip"`
	DstIP              string   `json:"dst_ip"`
	SrcPort            string   `json:"src_port"`
	DstPort            string   `json:"dst_port"`
	CallID             string   `json:"call_id"`
	Method             string   `json:"method"`
	StatusCode         string   `json:"status_code"`
	RequestURI         string   `json:"request_uri"`
	FromAddr           string   `json:"from_addr"`
	ToAddr             string   `json:"to_addr"`
	UserAgent          string   `json:"user_agent"`
	Contact            string   `json:"contact"`
	CSeqMethod         string   `json:"cseq_method"`
	CSeqSeq            string   `json:"cseq_seq"`
	Expires            string   `json:"expires"`
	Authorization      string   `json:"authorization"`
	ProxyAuthorization string   `json:"proxy_authorization"`
	WWWAuthenticate    string   `json:"www_authenticate"`
	ProxyAuthenticate  string   `json:"proxy_authenticate"`
	SDPVersion         string   `json:"sdp_version"`
	SDPMedia           string   `json:"sdp_media"`
	SDPMediaPort       string   `json:"sdp_media_port"`
	SDPMediaProto      string   `json:"sdp_media_proto"`
	SDPMediaAttrs      []string `json:"sdp_media_attr,omitempty"`
	SDPOwnerUsername   string   `json:"sdp_owner_username"`
	SDPSessionName     string   `json:"sdp_session_name"`
}

// RTPStreamSummary aggregates packet count, payload type, epochs, and frame numbers per RTP flow.
type RTPStreamSummary struct {
	SSRC          string   `json:"ssrc"`
	SrcIP         string   `json:"src_ip"`
	DstIP         string   `json:"dst_ip"`
	SrcPort       string   `json:"src_port"`
	DstPort       string   `json:"dst_port"`
	PacketCount   int      `json:"packet_count"`
	PayloadType   string   `json:"payload_type"`
	PacketNumbers []int    `json:"packet_numbers"`
	FirstEpoch    *float64 `json:"first_epoch,omitempty"`
	LastEpoch     *float64 `json:"last_epoch,omitempty"`
}

// RTPEventPacket holds one decoded RFC 4733 / RFC 2833 telephone-event frame.
type RTPEventPacket struct {
	PacketNum   int     `json:"packet_num"`
	Epoch       float64 `json:"epoch"`
	SrcIP       string  `json:"src_ip"`
	DstIP       string  `json:"dst_ip"`
	SrcPort     string  `json:"src_port"`
	DstPort     string  `json:"dst_port"`
	SSRC        string  `json:"ssrc"`
	PayloadType string  `json:"payload_type"`
	EventID     int     `json:"event_id"`
	EndOfEvent  bool    `json:"end_of_event"`
	Duration    int     `json:"duration"`
}

// SIPExtractionSummary matches the JSON payload consumed by S.O.N.I.C. SIP analyzers.
type SIPExtractionSummary struct {
	SIPPackets     []SIPPacket        `json:"sip_packets"`
	RTPStreams     []RTPStreamSummary `json:"rtp_streams"`
	RTPEvents      []RTPEventPacket   `json:"rtpevents,omitempty"`
	TotalPackets   int                `json:"total_packets"`
	SIPCount       int                `json:"sip_count"`
	RTPStreamCount int                `json:"rtp_stream_count"`
}

// ExtractSIPData runs streaming tshark SIP/RTP extraction, falling back to raw PCAP UDP scan when needed.
func ExtractSIPData(ctx context.Context, filePath string) (*SIPExtractionSummary, string, error) {
	fmt.Fprintf(os.Stderr, "Extracting SIP data from %s...\n", filePath)
	if tshark.Available("") {
		summary, jsonText, err := extractSIPWithTShark(ctx, filePath)
		if err == nil && (summary != nil || jsonText != "") {
			return summary, jsonText, nil
		}
	}
	rawText, err := readSIPRawPCAP(filePath)
	if err != nil || rawText == "" {
		return nil, "", err
	}
	return nil, rawText, nil
}

// extractSIPWithTShark streams SIP, SDP, RTP, and RTPEvent packets via tshark -T ek,
// running a dynamic -d udp.port==<port>,rtp pass for non-standard SDP media ports.
func extractSIPWithTShark(ctx context.Context, filePath string) (*SIPExtractionSummary, string, error) {
	const flt = "sip or rtp or rtpevent or (udp and (udp.port >= 10000 and udp.port <= 20000))"
	rows := make([]map[string][]string, 0, 32)
	_, err := tshark.StreamEKFields(ctx, tshark.CustomStreamOptions{
		FilePath:      filePath,
		DisplayFilter: flt,
		Fields:        sipTsharkFields,
	}, func(row tshark.Row) error {
		rows = append(rows, ekRowMap(row))
		return nil
	})
	if err != nil {
		return nil, "", err
	}

	if extraDecode := collectDynamicRTPDecodeSpecs(rows); len(extraDecode) > 0 {
		rows = appendDynamicRTPPass(ctx, filePath, extraDecode, rows)
	}

	summary := buildSIPSummary(len(rows), func(yield func(map[string][]string)) {
		for _, layers := range rows {
			yield(layers)
		}
	})
	encoded, merr := json.MarshalIndent(summary, "", "  ")
	if merr != nil {
		return nil, "", merr
	}
	return summary, string(encoded), nil
}

// buildSIPSummary transforms extracted layer maps into a masked SIPExtractionSummary.
func buildSIPSummary(total int, iter func(func(map[string][]string))) *SIPExtractionSummary {
	sipPackets := []SIPPacket{}
	rtpStreams := make(map[string]*RTPStreamSummary)
	streamOrder := []string{}
	var rtpEvents []RTPEventPacket

	iter(func(layers map[string][]string) {
		pnum, _ := strconv.Atoi(firstOr(layers, "frame.number", "0"))
		srcIP := firstAddr(layers, "ip.src", "ipv6.src")
		dstIP := firstAddr(layers, "ip.dst", "ipv6.dst")
		srcPort := firstOr(layers, "udp.srcport", "Unknown")
		dstPort := firstOr(layers, "udp.dstport", "Unknown")
		epoch, hasEpoch := parseEpochValue(firstOr(layers, "frame.time_epoch", ""))

		if pkt, ok := parseSIPPacketRow(layers, pnum, srcIP, dstIP, srcPort, dstPort, epoch, hasEpoch); ok {
			sipPackets = append(sipPackets, pkt)
		}

		if ssrcs := layers["rtp.ssrc"]; len(ssrcs) > 0 {
			key := fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, dstIP, dstPort)
			st, ok := rtpStreams[key]
			if !ok {
				st = &RTPStreamSummary{
					SSRC:          ssrcs[0],
					SrcIP:         srcIP,
					DstIP:         dstIP,
					SrcPort:       srcPort,
					DstPort:       dstPort,
					PayloadType:   firstOr(layers, "rtp.p_type", "Unknown"),
					PacketNumbers: []int{},
				}
				rtpStreams[key] = st
				streamOrder = append(streamOrder, key)
			}
			st.PacketCount++
			if pnum > 0 {
				st.PacketNumbers = append(st.PacketNumbers, pnum)
			}
			if hasEpoch {
				updateStreamEpochs(st, epoch)
			}
			if ev, ok := parseRTPEventRow(layers, pnum, epoch, srcIP, dstIP, srcPort, dstPort, ssrcs[0]); ok {
				rtpEvents = append(rtpEvents, ev)
			}
		}
	})

	ordered := make([]RTPStreamSummary, 0, len(streamOrder))
	for _, k := range streamOrder {
		ordered = append(ordered, *rtpStreams[k])
	}
	return &SIPExtractionSummary{
		SIPPackets:     sipPackets,
		RTPStreams:     ordered,
		RTPEvents:      rtpEvents,
		TotalPackets:   total,
		SIPCount:       len(sipPackets),
		RTPStreamCount: len(ordered),
	}
}
