// Package grpc emits HTTP/2 transport, flow-control, TCP reset, and TLS connection issues.
package grpc

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func appendHTTP2Issues(conn *connTrack, reportConn *ConnectionRow, label string, ctx model.Context, issues *[]model.Issue, events *[]model.Event) {
	for _, rst := range conn.rstStreams {
		sev := model.SeverityError
		if rst.ErrorCode != nil && (*rst.ErrorCode == 0 || *rst.ErrorCode == 8) {
			sev = model.SeverityWarning
		}
		methNote := ""
		if rst.Method != nil && *rst.Method != "" {
			methNote = " (" + *rst.Method + ")"
		}
		text := fmt.Sprintf("%s: RST_STREAM %s from the %s on stream %d%s: ", label, rst.Error, rst.From, rst.StreamID, methNote)
		if rst.AfterEnd != nil && *rst.AfterEnd && rst.From == "client" {
			sev = model.SeverityInfo
			text += "after the server had already ended the stream with its status: the client closing its half (normal cleanup)"
		} else if rst.AfterEnd != nil && *rst.AfterEnd && rst.ErrorCode != nil && *rst.ErrorCode == 0 {
			sev = model.SeverityInfo
			text += "right after the server's own status: asks the client to stop sending on a stream whose response is complete (RFC 9113 8.1; normal for a ONCE or server-streaming call)"
		} else if rst.ErrorCode != nil {
			text += H2ErrorHints[*rst.ErrorCode]
		}
		iss := model.MakeIssue(sev, "HTTP2_RST_STREAM", text, []int{rst.Frame})
		iss.Error = rst.Error
		*issues = append(*issues, iss)
		fr := rst.Frame
		*events = append(*events, model.MakeEvent(ctx, rst.t, "http2", "rst_stream", text, &fr))
	}

	for _, ga := range conn.goaways {
		dbg := ""
		if ga.DebugData != nil {
			dbg = *ga.DebugData
		}
		var unproc []string
		for _, r := range conn.rpcs {
			if ga.LastStreamID != nil && r.streamID > *ga.LastStreamID && r.streamID%2 == 1 {
				unproc = append(unproc, strconv.Itoa(r.streamID))
			}
		}
		slices.Sort(unproc)
		var text string
		if ga.ErrorCode != nil && *ga.ErrorCode == 11 && strings.Contains(dbg, "too_many_pings") {
			text = fmt.Sprintf("%s: GOAWAY ENHANCE_YOUR_CALM 'too_many_pings' from the %s: the client's keepalive is more frequent than the server allows (grpc-go servers refuse pings more often than every 5 minutes by default); raise the client's keepalive time or the server's keepalive enforcement policy", label, ga.From)
			*issues = append(*issues, model.MakeIssue(model.SeverityError, "HTTP2_TOO_MANY_PINGS", text, []int{ga.Frame}))
		} else {
			lastStr := "None"
			if ga.LastStreamID != nil {
				lastStr = strconv.Itoa(*ga.LastStreamID)
			}
			text = fmt.Sprintf("%s: GOAWAY %s from the %s, last stream %s", label, ga.Error, ga.From, lastStr)
			if dbg != "" {
				text += fmt.Sprintf(", debug data '%s'", dbg)
			}
			sev := model.SeverityError
			if ga.ErrorCode != nil && *ga.ErrorCode == 0 && ga.From == "client" {
				text += ": the client closed the channel"
				sev = model.SeverityInfo
			} else if ga.ErrorCode != nil && *ga.ErrorCode == 0 {
				text += ": the server is closing the connection gracefully (shutdown, restart or max connection age); streams above the last stream id were not processed and may be retried"
				sev = model.SeverityWarning
			} else {
				hint := "connection error"
				if ga.ErrorCode != nil {
					if h := H2ErrorHints[*ga.ErrorCode]; h != "" {
						hint = h
					}
				}
				text += ": " + hint
			}
			if len(unproc) > 0 {
				if len(unproc) > 10 {
					unproc = unproc[:10]
				}
				text += "; streams [" + strings.Join(unproc, ", ") + "] were not processed"
			}
			iss := model.MakeIssue(sev, "HTTP2_GOAWAY", text, []int{ga.Frame})
			iss.Error = ga.Error
			*issues = append(*issues, iss)
		}
		fr := ga.Frame
		*events = append(*events, model.MakeEvent(ctx, ga.t, "http2", "goaway", text, &fr))
	}

	for _, stall := range reportConn.FlowControl.Stalls {
		waiting := "while its stream was still open"
		if stall.DataWaiting {
			waiting = "with data waiting"
		}
		methNote := ""
		if stall.Method != nil && *stall.Method != "" {
			methNote = " (" + *stall.Method + ")"
		}
		var text string
		sev := model.SeverityError
		if stall.Resolved {
			reop := 0
			if stall.ReopenedFrame != nil {
				reop = *stall.ReopenedFrame
			}
			text = fmt.Sprintf("%s: the %s's %s flow-control window reached 0 on stream %d%s %s, for %s s until a WINDOW_UPDATE (frame %d): the receiver reads slower than the sender writes",
				label, stall.Sender, stall.Window, stall.StreamID, methNote, waiting, formatPyFloat(stall.DurationS), reop)
			if stall.DurationS >= stallWarnS {
				sev = model.SeverityWarning
			} else {
				sev = model.SeverityInfo
			}
		} else {
			ended := "until the capture ended"
			if stall.EndedBy != nil && *stall.EndedBy != "" {
				ended = *stall.EndedBy
			}
			text = fmt.Sprintf("%s: the %s's %s flow-control window reached 0 on stream %d%s and never reopened (%s, %s s): the receiver stopped reading (a stuck or overloaded consumer)",
				label, stall.Sender, stall.Window, stall.StreamID, methNote, ended, formatPyFloat(stall.DurationS))
		}
		*issues = append(*issues, model.MakeIssue(sev, "HTTP2_FLOW_CONTROL_STALL", text, []int{stall.Frame}))
		if ctx.Start != nil || stall.T != nil {
			base, rel := 0.0, 0.0
			if ctx.Start != nil {
				base = *ctx.Start
			}
			if stall.T != nil {
				rel = *stall.T
			}
			fr := stall.Frame
			*events = append(*events, model.MakeEvent(ctx, base+rel, "http2", "flow_control_stall", text, &fr))
		}
	}

	for _, big := range conn.oversizeFrames {
		*issues = append(*issues, model.MakeIssue(model.SeverityError, "HTTP2_FRAME_TOO_LARGE",
			fmt.Sprintf("%s: the %s sent a %s frame of %d bytes, over the peer's SETTINGS_MAX_FRAME_SIZE %d: the peer must fail the connection with FRAME_SIZE_ERROR",
				label, big.From, big.Type, big.Length, big.PeerMaxFrameSize), []int{big.Frame}))
	}
	for _, big := range conn.oversizeHeaders {
		*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "HTTP2_HEADER_LIST_TOO_LARGE",
			fmt.Sprintf("%s: the %s sent a header list of %d bytes on stream %d, over the peer's SETTINGS_MAX_HEADER_LIST_SIZE %d (large metadata): expect RESOURCE_EXHAUSTED or INTERNAL",
				label, big.From, big.HeaderListSize, big.StreamID, big.PeerLimit), []int{big.Frame}))
	}
	if limit := conn.settingsServer["max_concurrent_streams"]; limit != nil && conn.maxOpen > *limit {
		frames := []int{}
		if conn.maxOpenFrame != nil {
			frames = []int{*conn.maxOpenFrame}
		}
		*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "HTTP2_MAX_CONCURRENT_STREAMS_EXCEEDED",
			fmt.Sprintf("%s: %d streams open at once, over the server's SETTINGS_MAX_CONCURRENT_STREAMS %d: the excess is refused (REFUSED_STREAM, gRPC UNAVAILABLE) or queued by the client",
				label, conn.maxOpen, *limit), frames))
	}
	if conn.disc != nil && conn.disc.PrefaceFrame != nil && conn.packetsServer == 0 {
		*issues = append(*issues, model.MakeIssue(model.SeverityError, "HTTP2_PREFACE_UNANSWERED",
			fmt.Sprintf("%s: the client sent the HTTP/2 preface in cleartext and the server never answered with HTTP/2: the port may expect TLS (the client used an insecure channel), or it is not a gRPC server",
				label), []int{*conn.disc.PrefaceFrame}))
	}
	if len(conn.hpackFailures) > 0 {
		*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "HTTP2_HPACK_DECODE_FAILED",
			fmt.Sprintf("%s: %d header block(s) could not be decoded (HPACK state missing: the capture started after the connection opened)",
				label, len(conn.hpackFailures)), conn.hpackFailures))
	}
	if conn.disc != nil {
		var openRPCs []*rpcTrack
		for _, r := range conn.rpcs {
			if r.isOpen() {
				openRPCs = append(openRPCs, r)
			}
		}
		for _, reset := range conn.disc.Resets {
			var inFlight []string
			for _, r := range openRPCs {
				if r.tRequest != nil && *r.tRequest <= reset.T {
					if m := r.method(); m != nil && *m != "" {
						inFlight = append(inFlight, *m)
					}
				}
			}
			text := fmt.Sprintf("%s: TCP reset from %s", label, endpointStr(&reset.From))
			if len(inFlight) > 0 {
				sample := inFlight
				if len(sample) > 5 {
					sample = sample[:5]
				}
				text += fmt.Sprintf(" with %d RPC(s) still open (%s): the client sees UNAVAILABLE",
					len(inFlight), strings.Join(sample, ", "))
				*issues = append(*issues, model.MakeIssue(model.SeverityError, "TCP_RESET_DURING_RPC", text, []int{reset.Frame}))
			}
			fr := reset.Frame
			*events = append(*events, model.MakeEvent(ctx, reset.T, "tcp", "reset", text, &fr))
		}
	}
}

func appendTLSConnIssues(dconn *extract.TCPConnection, tlsInfo *TLSView, label string, issues *[]model.Issue) {
	if tlsInfo == nil {
		return
	}
	for _, alert := range tlsInfo.Alerts {
		if (alert.Level == "fatal" || alert.Level == "warning") && alert.Description != "close_notify" {
			sev := model.SeverityWarning
			if alert.Level == "fatal" {
				sev = model.SeverityError
			}
			hint := ""
			if alert.Hint != nil && *alert.Hint != "" {
				hint = ": " + *alert.Hint
			}
			*issues = append(*issues, model.MakeIssue(sev, "TLS_ALERT",
				fmt.Sprintf("%s: TLS %s alert %s from %s%s", label, alert.Level, alert.Description, alert.From, hint),
				[]int{alert.Frame}))
		}
	}
	hello := []int{}
	if dconn != nil && dconn.TLSClientHello != nil {
		hello = []int{*dconn.TLSClientHello}
	}
	for _, hint := range tlsInfo.Hints {
		text := fmt.Sprintf("%s: %s", label, hint.Text)
		switch hint.Code {
		case "TLS_CERT_NO_IP_SAN":
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "TLS_CERT_NO_IP_SAN", text, hello))
		case "TLS_NO_SERVER_HELLO":
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "TLS_NO_SERVER_HELLO", text, hello))
		case "TLS_NO_SNI":
			*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "TLS_NO_SNI", text, hello))
		default:
			*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "GRPC_TLS_NOT_DECRYPTED", text, hello))
		}
	}
}
