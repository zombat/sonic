// Package extract provides SDP port discovery, masking, and row parsing helpers
// supporting streaming SIP, RTP, and RFC 4733 extraction in sip.go.
package extract

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/tshark"
)

const maxDynamicRTPDecodePorts = 32

var sdpKeyMgmtBareRe = regexp.MustCompile(`(?i)\bkey-mgmt:[ \t]*[A-Za-z0-9._\-]+[ \t]+([^\r\n"]+)`)

func ekRowMap(row tshark.Row) map[string][]string {
	m := make(map[string][]string, len(sipTsharkFields))
	for _, f := range sipTsharkFields {
		if vals := row.All(f); len(vals) > 0 {
			copied := make([]string, len(vals))
			copy(copied, vals)
			m[f] = copied
		}
	}
	return m
}

func firstOr(m map[string][]string, key, def string) string {
	if vals := m[key]; len(vals) > 0 {
		return vals[0]
	}
	return def
}

func firstAddr(m map[string][]string, primary, secondary string) string {
	if vals := m[primary]; len(vals) > 0 && vals[0] != "" {
		return vals[0]
	}
	if vals := m[secondary]; len(vals) > 0 && vals[0] != "" {
		return vals[0]
	}
	return "Unknown"
}

func parseEpochValue(raw string) (float64, bool) {
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func maskSDPMediaAttr(raw string) string {
	masked := redact.MaskSDPKeys(raw, SIPCredentialMask)
	return sdpKeyMgmtBareRe.ReplaceAllStringFunc(masked, func(full string) string {
		loc := sdpKeyMgmtBareRe.FindStringSubmatchIndex(full)
		if len(loc) < 4 {
			return full
		}
		return full[:loc[2]] + SIPCredentialMask
	})
}

func parseSIPPacketRow(
	layers map[string][]string,
	pnum int,
	srcIP, dstIP, srcPort, dstPort string,
	epoch float64,
	hasEpoch bool,
) (SIPPacket, bool) {
	callID := firstOr(layers, "sip.Call-ID", "")
	method := firstOr(layers, "sip.Method", "")
	status := firstOr(layers, "sip.Status-Code", "")
	if callID == "" && method == "" && status == "" {
		return SIPPacket{}, false
	}
	if callID == "" {
		callID = "Unknown"
	}
	auth := firstOr(layers, "sip.Authorization", "")
	if auth != "" {
		auth = MaskSIPCredentials(auth)
	}
	proxyAuth := firstOr(layers, "sip.Proxy-Authorization", "")
	if proxyAuth != "" {
		proxyAuth = MaskSIPCredentials(proxyAuth)
	}
	var epochPtr *float64
	if hasEpoch {
		e := epoch
		epochPtr = &e
	}
	var attrs []string
	if rawAttrs := layers["sdp.media_attr"]; len(rawAttrs) > 0 {
		attrs = make([]string, 0, len(rawAttrs))
		for _, a := range rawAttrs {
			attrs = append(attrs, maskSDPMediaAttr(a))
		}
	}
	return SIPPacket{
		PacketNum:          pnum,
		Time:               firstOr(layers, "frame.time", "Unknown"),
		Epoch:              epochPtr,
		SrcIP:              srcIP,
		DstIP:              dstIP,
		SrcPort:            srcPort,
		DstPort:            dstPort,
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
		SDPMediaAttrs:      attrs,
		SDPOwnerUsername:   firstOr(layers, "sdp.owner.username", ""),
		SDPSessionName:     firstOr(layers, "sdp.session_name", ""),
	}, true
}

func updateStreamEpochs(st *RTPStreamSummary, epoch float64) {
	if st.FirstEpoch == nil || epoch < *st.FirstEpoch {
		e := epoch
		st.FirstEpoch = &e
	}
	if st.LastEpoch == nil || epoch > *st.LastEpoch {
		e := epoch
		st.LastEpoch = &e
	}
}

func parseRTPEventRow(
	layers map[string][]string,
	pnum int,
	epoch float64,
	srcIP, dstIP, srcPort, dstPort, ssrc string,
) (RTPEventPacket, bool) {
	rawID, ok := layers["rtpevent.event_id"]
	if !ok || len(rawID) == 0 {
		return RTPEventPacket{}, false
	}
	idVal, okID := tshark.ParseInt64(rawID[0])
	if !okID {
		return RTPEventPacket{}, false
	}
	endFlag := false
	if rawEnd := firstOr(layers, "rtpevent.end_of_event", ""); rawEnd != "" {
		if b, ok := tshark.ParseInt64(rawEnd); ok {
			endFlag = b != 0
		}
	}
	dur := 0
	if rawDur := firstOr(layers, "rtpevent.duration", ""); rawDur != "" {
		if d, ok := tshark.ParseInt64(rawDur); ok {
			dur = int(d)
		}
	}
	return RTPEventPacket{
		PacketNum:   pnum,
		Epoch:       epoch,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		SSRC:        ssrc,
		PayloadType: firstOr(layers, "rtp.p_type", "Unknown"),
		EventID:     int(idVal),
		EndOfEvent:  endFlag,
		Duration:    dur,
	}, true
}

func collectDynamicRTPDecodeSpecs(rows []map[string][]string) []string {
	decodedRTPPorts := make(map[int]bool)
	for _, r := range rows {
		if len(r["rtp.ssrc"]) == 0 {
			continue
		}
		if p, err := strconv.Atoi(firstOr(r, "udp.srcport", "")); err == nil {
			decodedRTPPorts[p] = true
		}
		if p, err := strconv.Atoi(firstOr(r, "udp.dstport", "")); err == nil {
			decodedRTPPorts[p] = true
		}
	}

	candidates := make(map[int]bool)
	for _, r := range rows {
		protos := r["sdp.media.proto"]
		ports := r["sdp.media.port"]
		for idx, rawPort := range ports {
			p, err := strconv.Atoi(strings.TrimSpace(rawPort))
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			proto := ""
			if idx < len(protos) {
				proto = strings.ToUpper(protos[idx])
			} else if len(protos) > 0 {
				proto = strings.ToUpper(protos[0])
			}
			if proto != "" && !strings.Contains(proto, "RTP") {
				continue
			}
			if (p >= 10000 && p <= 20000) || decodedRTPPorts[p] {
				continue
			}
			candidates[p] = true
		}
	}

	if len(candidates) == 0 {
		return nil
	}
	ordered := make([]int, 0, len(candidates))
	for p := range candidates {
		ordered = append(ordered, p)
	}
	slices.Sort(ordered)
	if len(ordered) > maxDynamicRTPDecodePorts {
		ordered = ordered[:maxDynamicRTPDecodePorts]
	}
	specs := make([]string, 0, len(ordered))
	for _, p := range ordered {
		specs = append(specs, fmt.Sprintf("udp.port==%d,rtp", p))
	}
	return specs
}

func appendDynamicRTPPass(
	ctx context.Context,
	filePath string,
	decodeSpecs []string,
	existing []map[string][]string,
) []map[string][]string {
	seenRTPFrames := make(map[int]bool, len(existing))
	for _, r := range existing {
		if len(r["rtp.ssrc"]) > 0 {
			if n, err := strconv.Atoi(firstOr(r, "frame.number", "0")); err == nil && n > 0 {
				seenRTPFrames[n] = true
			}
		}
	}
	var extra []map[string][]string
	_, err := tshark.StreamEKFields(ctx, tshark.CustomStreamOptions{
		FilePath:      filePath,
		DisplayFilter: "rtp or rtpevent",
		DecodeAs:      decodeSpecs,
		Fields:        sipTsharkFields,
	}, func(row tshark.Row) error {
		n, _ := row.Int64("frame.number")
		if n > 0 && seenRTPFrames[int(n)] {
			return nil
		}
		if len(row.All("rtp.ssrc")) > 0 {
			extra = append(extra, ekRowMap(row))
		}
		return nil
	})
	if err != nil || len(extra) == 0 {
		return existing
	}
	return append(existing, extra...)
}
