// Package grpc diagnoses RPC failures, gNMI capability/encoding mismatches, and deadlines.
package grpc

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

func (a *grpcAnalysis) diagnose(conn *connTrack, rpc *rpcTrack, row *RPCRow, timeout *float64) string {
	text := a.diagnoseStatus(conn, rpc, row, timeout)
	if row.HeadersDecoded != nil && !*row.HeadersDecoded && row.Method != nil && *row.Method != "" {
		text += "; some headers could not be decoded (HPACK state missing: the capture started after the connection opened), so metadata and status may be incomplete"
	}
	return text
}

func (a *grpcAnalysis) diagnoseStatus(conn *connTrack, rpc *rpcTrack, row *RPCRow, timeout *float64) string {
	method := fmt.Sprintf("stream %d", rpc.streamID)
	if row.Method != nil && *row.Method != "" {
		method = *row.Method
	}
	fam := ""
	if row.Family != nil {
		fam = *row.Family
	}
	if row.HeadersDecoded != nil && !*row.HeadersDecoded && (row.Method == nil || *row.Method == "") {
		return "headers could not be decoded (HPACK state missing: the capture probably started after the connection opened), so the method and status are unknown"
	}
	if row.ContentType != nil && *row.ContentType != "" && !strings.HasPrefix(*row.ContentType, "application/grpc") {
		return fmt.Sprintf("HTTP/2 request with content-type %s: not gRPC", *row.ContentType)
	}
	if rpc.reset != nil && !row.ResetAfterEnd {
		hint := ""
		if rpc.reset.ErrorCode != nil {
			hint = H2ErrorHints[*rpc.reset.ErrorCode]
		}
		text := fmt.Sprintf("%s: stream reset by the %s with %s (%s)", method, rpc.reset.From, rpc.reset.Error, hint)
		if timeout != nil && row.Timing.ToEndMS != nil && *row.Timing.ToEndMS/1000 >= *timeout*0.95 && rpc.reset.From == "client" {
			text += fmt.Sprintf("; the reset came at the deadline (%s s): the client gave up waiting", formatPyFloat(*timeout))
		}
		if fam == "gNMI" && strings.HasSuffix(method, "/Set") {
			text += "; whether the target applied the Set is unknown (it may have committed before the cancel): read the paths back with Get"
		}
		return text
	}
	if row.GrpcStatus == nil {
		if rpc.tFirstResponse == nil {
			return fmt.Sprintf("%s: no response from the server before the capture ended", method)
		}
		if isLongLived(rpc, row.Decoded) {
			mode := "streaming"
			if row.Decoded != nil && row.Decoded.Request != nil && row.Decoded.Request.Subscribe != nil && row.Decoded.Request.Subscribe.Mode != "" {
				mode = row.Decoded.Request.Subscribe.Mode
			}
			return fmt.Sprintf("%s: a long-lived stream (%s) still open when the capture ended, %d response message(s) so far (normal)",
				method, mode, row.Response.Messages)
		}
		return fmt.Sprintf("%s: no trailers (grpc-status) before the capture ended; the RPC was still open", method)
	}

	prefix := fmt.Sprintf("%s: %s", method, *row.GrpcStatusName)
	if row.GrpcMessage != nil && *row.GrpcMessage != "" {
		prefix += " (" + *row.GrpcMessage + ")"
	}
	if row.GrpcStatusFromHTTP && row.HTTPStatus != nil {
		prefix += fmt.Sprintf(", mapped from HTTP %d (a proxy or a non-gRPC server answered)", *row.HTTPStatus)
	}
	status := *row.GrpcStatus
	if status == 0 {
		return diagnoseOK(prefix, fam, method, row.Decoded)
	}
	hint := GrpcStatusHints[status]
	text := prefix
	if hint != "" {
		text += ": " + hint
	}
	if fam == "gNMI" && (status == 3 || status == 12) && row.Decoded != nil && row.Decoded.Request != nil {
		enc, present := reqEncoding(row.Decoded.Request)
		if enc != "" {
			var supported []string
			if conn.capabilities != nil && conn.capabilities.Capabilities != nil {
				for _, se := range conn.capabilities.Capabilities.SupportedEncodings {
					if se != nil {
						supported = append(supported, *se)
					}
				}
			}
			if len(supported) > 0 && !slices.Contains(supported, enc) {
				absNote := ""
				if !present {
					absNote = " (the field was absent, which means JSON)"
				}
				text += fmt.Sprintf(". The request asked for encoding %s%s; Capabilities on this connection lists only %s",
					enc, absNote, strings.Join(supported, ", "))
			} else {
				absNote := ""
				if !present {
					absNote = " (absent field: the proto3 default JSON)"
				}
				text += fmt.Sprintf(". The request asked for encoding %s%s", enc, absNote)
			}
		}
	}
	if status == 4 && timeout != nil {
		text += fmt.Sprintf(" (deadline %s s)", formatPyFloat(*timeout))
	}
	if status == 8 {
		maxMsg := 0
		if row.Request.Largest != nil && *row.Request.Largest > maxMsg {
			maxMsg = *row.Request.Largest
		}
		if row.Response.Largest != nil && *row.Response.Largest > maxMsg {
			maxMsg = *row.Response.Largest
		}
		if maxMsg > grpcDefaultMaxRecv {
			text += fmt.Sprintf("; a message of %d bytes exceeds the 4 MiB default: raise the receiver's max receive message size or ask for less (a narrower path, or Subscribe instead of Get)", maxMsg)
		}
	}
	if fam == "gNMI" && strings.HasSuffix(method, "/Set") {
		text += ". gNMI Set is all or none: none of its operations were applied"
	}
	return text
}

func diagnoseOK(prefix, fam, method string, decoded *DecodedBlock) string {
	var resp *DecodedResponse
	var req *DecodedRequest
	if decoded != nil {
		resp = decoded.Response
		req = decoded.Request
	}
	if fam == "gNMI" && strings.HasSuffix(method, "/Get") && resp != nil && resp.Get != nil {
		if resp.Get.Notifications > 0 && resp.Get.Updates == 0 {
			return fmt.Sprintf("%s: answered with %d notification(s) and no updates: the path exists but holds nothing, or the target returns an empty notification for an absent path (measured on SR Linux)",
				prefix, resp.Get.Notifications)
		}
		return fmt.Sprintf("%s: %d notification(s), %d update(s)", prefix, resp.Get.Notifications, resp.Get.Updates)
	}
	if fam == "gNMI" && strings.HasSuffix(method, "/Subscribe") && resp != nil && resp.SubscribeSum != nil {
		s := resp.SubscribeSum
		if len(s.Errors) > 0 {
			first := s.Errors[0]
			msgStr := "None"
			if first.Message != nil {
				msgStr = *first.Message
			}
			return fmt.Sprintf("%s, but the target answered in-band with an error (code %d: %s) in the deprecated SubscribeResponse.error field: the subscription did not deliver data",
				prefix, first.Code, msgStr)
		}
		mode := "?"
		if req != nil && req.Subscribe != nil && req.Subscribe.Mode != "" {
			mode = req.Subscribe.Mode
		}
		syncWord := "without"
		if s.SyncResponse {
			syncWord = "with"
		}
		tail := ""
		if mode == "ONCE" && !s.SyncResponse {
			tail = "; a ONCE subscription should end with sync_response"
		}
		return fmt.Sprintf("%s: %s subscription, %d notification(s), %s sync_response%s",
			prefix, mode, s.Notifications, syncWord, tail)
	}
	if fam == "gNMI" && strings.HasSuffix(method, "/Capabilities") && resp != nil && resp.Capabilities != nil {
		c := resp.Capabilities
		ver := "None"
		if c.GnmiVersion != nil {
			ver = *c.GnmiVersion
		}
		var encs []string
		for _, se := range c.SupportedEncodings {
			if se != nil {
				encs = append(encs, *se)
			}
		}
		encStr := "none listed"
		if len(encs) > 0 {
			encStr = strings.Join(encs, ", ")
		}
		return fmt.Sprintf("%s: gNMI %s, encodings %s, %d model(s)", prefix, ver, encStr, c.Models)
	}
	if resp != nil && resp.Health != nil && resp.Health.ServingStatus != "" {
		tail := ""
		if resp.Health.ServingStatus != "SERVING" {
			tail = ": the server is up but says it cannot serve"
		}
		return fmt.Sprintf("%s: the service reports %s%s", prefix, resp.Health.ServingStatus, tail)
	}
	if resp != nil && resp.Time != nil && resp.Time.SkewS != nil {
		skew := *resp.Time.SkewS
		if math.Abs(skew) < 0.001 {
			return fmt.Sprintf("%s: the target's clock matches the capture's clock", prefix)
		}
		dir := "ahead of"
		if skew <= 0 {
			dir = "behind"
		}
		tail := ""
		if math.Abs(skew) > 1 {
			tail = " (check NTP on the target)"
		}
		return fmt.Sprintf("%s: the target's clock is %s s %s the capture's clock%s",
			prefix, formatPyFloat(math.Abs(skew)), dir, tail)
	}
	return prefix + ": succeeded"
}

func isLongLived(rpc *rpcTrack, decoded *DecodedBlock) bool {
	m := rpc.method()
	if m == nil || !strings.HasSuffix(*m, "/gnmi.gNMI/Subscribe") || decoded == nil || decoded.Request == nil || decoded.Request.Subscribe == nil {
		return false
	}
	mode := decoded.Request.Subscribe.Mode
	return mode == "STREAM" || mode == "POLL"
}

func reqEncoding(r *DecodedRequest) (string, bool) {
	if r.Get != nil && r.Get.Encoding != nil {
		return *r.Get.Encoding, r.Get.EncodingFieldPresent
	}
	if r.Subscribe != nil && r.Subscribe.Encoding != nil {
		return *r.Subscribe.Encoding, r.Subscribe.EncodingFieldPresent
	}
	return "", false
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func formatPyFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.ContainsRune(s, '.') && !strings.ContainsRune(s, 'e') && !strings.ContainsRune(s, 'E') {
		s += ".0"
	}
	return s
}
