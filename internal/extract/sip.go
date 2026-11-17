// Package extract extracts masked SIP signaling and RTP stream summaries from packet captures.
package extract

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/zombat/sonic/internal/tshark"
)

var sipTsharkFields = []string{
	"frame.number", "frame.time", "ip.src", "ip.dst",
	"sip.Call-ID", "sip.Method", "sip.Status-Code",
	"sip.r-uri", "sip.from.addr", "sip.to.addr",
	"sip.User-Agent",
	"sip.Authorization", "sip.Proxy-Authorization",
	"sip.WWW-Authenticate", "sip.Proxy-Authenticate",
	"sip.Status-Line", "sip.Reason", "sip.Request-Line",
	"sip.contact.uri", "sip.from.tag", "sip.to.tag",
	"sip.CSeq.method", "sip.CSeq.seq", "sip.Expires",
	"sdp.version", "sdp.media", "sdp.media.port",
	"sdp.media.proto", "sdp.owner.username", "sdp.session_name",
	"rtp.ssrc", "rtp.seq", "rtp.p_type",
	"udp.srcport", "udp.dstport", "udp.length",
	"frame.protocols",
}

// SIPPacket holds masked SIP signaling and SDP metadata for a single captured frame.
type SIPPacket struct {
	PacketNum          int    `json:"packet_num"`
	Time               string `json:"time"`
	SrcIP              string `json:"src_ip"`
	DstIP              string `json:"dst_ip"`
	SrcPort            string `json:"src_port"`
	DstPort            string `json:"dst_port"`
	CallID             string `json:"call_id"`
	Method             string `json:"method"`
	StatusCode         string `json:"status_code"`
	RequestURI         string `json:"request_uri"`
	FromAddr           string `json:"from_addr"`
	ToAddr             string `json:"to_addr"`
	UserAgent          string `json:"user_agent"`
	Contact            string `json:"contact"`
	CSeqMethod         string `json:"cseq_method"`
	CSeqSeq            string `json:"cseq_seq"`
	Expires            string `json:"expires"`
	Authorization      string `json:"authorization"`
	ProxyAuthorization string `json:"proxy_authorization"`
	WWWAuthenticate    string `json:"www_authenticate"`
	ProxyAuthenticate  string `json:"proxy_authenticate"`
	SDPVersion         string `json:"sdp_version"`
	SDPMedia           string `json:"sdp_media"`
	SDPMediaPort       string `json:"sdp_media_port"`
	SDPMediaProto      string `json:"sdp_media_proto"`
	SDPOwnerUsername   string `json:"sdp_owner_username"`
	SDPSessionName     string `json:"sdp_session_name"`
}

// RTPStreamSummary aggregates packet count, payload type, and frame numbers per RTP flow.
type RTPStreamSummary struct {
	SSRC          string `json:"ssrc"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       string `json:"src_port"`
	DstPort       string `json:"dst_port"`
	PacketCount   int    `json:"packet_count"`
	PayloadType   string `json:"payload_type"`
	PacketNumbers []int  `json:"packet_numbers"`
}

// SIPExtractionSummary matches the JSON payload returned by extractors/tshark.py.
type SIPExtractionSummary struct {
	SIPPackets     []SIPPacket        `json:"sip_packets"`
	RTPStreams     []RTPStreamSummary `json:"rtp_streams"`
	TotalPackets   int                `json:"total_packets"`
	SIPCount       int                `json:"sip_count"`
	RTPStreamCount int                `json:"rtp_stream_count"`
}

// ExtractSIPData runs tshark SIP/RTP extraction, falling back to raw PCAP UDP scan when needed.
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

// extractSIPWithTShark invokes tshark -T json across sip/rtp filters and summarizes results.
func extractSIPWithTShark(ctx context.Context, filePath string) (*SIPExtractionSummary, string, error) {
	const flt = "sip or rtp or (udp and (udp.port >= 10000 and udp.port <= 20000))"
	args := make([]string, 0, 8+len(sipTsharkFields)*2)
	args = append(args, "-r", tshark.SafeCapturePath(filePath), "-Y", flt, "-T", "json")
	for _, f := range sipTsharkFields {
		args = append(args, "-e", f)
	}
	out, err := exec.CommandContext(ctx, tshark.DefaultBinary, args...).Output()
	if err != nil || len(out) == 0 {
		return nil, "", err
	}
	var rawPackets []struct {
		Source struct {
			Layers map[string][]string `json:"layers"`
		} `json:"_source"`
	}
	if err := json.Unmarshal(out, &rawPackets); err != nil {
		return nil, MaskSIPText(string(out)), nil
	}
	summary := buildSIPSummary(len(rawPackets), func(yield func(map[string][]string)) {
		for _, pkt := range rawPackets {
			yield(pkt.Source.Layers)
		}
	})
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return summary, string(encoded), nil
}

// buildSIPSummary transforms raw tshark _source.layers maps into a bounded SIPExtractionSummary.
func buildSIPSummary(total int, iter func(func(map[string][]string))) *SIPExtractionSummary {
	sipPackets := []SIPPacket{}
	rtpStreams := make(map[string]*RTPStreamSummary)
	streamOrder := []string{}

	firstOr := func(m map[string][]string, key, def string) string {
		if vals := m[key]; len(vals) > 0 {
			return vals[0]
		}
		return def
	}

	iter(func(layers map[string][]string) {
		callID := firstOr(layers, "sip.Call-ID", "")
		method := firstOr(layers, "sip.Method", "")
		status := firstOr(layers, "sip.Status-Code", "")
		if callID != "" || method != "" || status != "" {
			if callID == "" {
				callID = "Unknown"
			}
			pnum, _ := strconv.Atoi(firstOr(layers, "frame.number", "0"))
			auth := firstOr(layers, "sip.Authorization", "")
			if auth != "" {
				auth = MaskSIPCredentials(auth)
			}
			proxyAuth := firstOr(layers, "sip.Proxy-Authorization", "")
			if proxyAuth != "" {
				proxyAuth = MaskSIPCredentials(proxyAuth)
			}
			sipPackets = append(sipPackets, SIPPacket{
				PacketNum:          pnum,
				Time:               firstOr(layers, "frame.time", "Unknown"),
				SrcIP:              firstOr(layers, "ip.src", "Unknown"),
				DstIP:              firstOr(layers, "ip.dst", "Unknown"),
				SrcPort:            firstOr(layers, "udp.srcport", "Unknown"),
				DstPort:            firstOr(layers, "udp.dstport", "Unknown"),
				CallID:             callID,
				Method:             method,
				StatusCode:         status,
				RequestURI:         firstOr(layers, "sip.r-uri", ""),
				FromAddr:           firstOr(layers, "sip.from.addr", ""),
				ToAddr:             firstOr(layers, "sip.to.addr", ""),
				UserAgent:          firstOr(layers, "sip.User-Agent", ""),
				Contact:            firstOr(layers, "sip.contact.uri", ""),
				CSeqMethod:         firstOr(layers, "sip.CSeq.method", ""),
				CSeqSeq:            firstOr(layers, "sip.CSeq.seq", ""),
				Expires:            firstOr(layers, "sip.Expires", ""),
				Authorization:      auth,
				ProxyAuthorization: proxyAuth,
				WWWAuthenticate:    firstOr(layers, "sip.WWW-Authenticate", ""),
				ProxyAuthenticate:  firstOr(layers, "sip.Proxy-Authenticate", ""),
				SDPVersion:         firstOr(layers, "sdp.version", ""),
				SDPMedia:           firstOr(layers, "sdp.media", ""),
				SDPMediaPort:       firstOr(layers, "sdp.media.port", ""),
				SDPMediaProto:      firstOr(layers, "sdp.media.proto", ""),
				SDPOwnerUsername:   firstOr(layers, "sdp.owner.username", ""),
				SDPSessionName:     firstOr(layers, "sdp.session_name", ""),
			})
		}

		if ssrcs := layers["rtp.ssrc"]; len(ssrcs) > 0 {
			srcIP := firstOr(layers, "ip.src", "Unknown")
			dstIP := firstOr(layers, "ip.dst", "Unknown")
			srcPort := firstOr(layers, "udp.srcport", "Unknown")
			dstPort := firstOr(layers, "udp.dstport", "Unknown")
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
			if pnum, err := strconv.Atoi(firstOr(layers, "frame.number", "0")); err == nil && pnum > 0 {
				st.PacketNumbers = append(st.PacketNumbers, pnum)
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
		TotalPackets:   total,
		SIPCount:       len(sipPackets),
		RTPStreamCount: len(ordered),
	}
}
