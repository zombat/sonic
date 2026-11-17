// Package sip tracks SIP INVITE/BYE call sessions and hangup/termination patterns
// matching analyzers/call_tracking.py.
package sip

import (
	"fmt"
	"strings"
)

// CallEvent represents one signaling event (INVITE, BYE, or terminating error response).
type CallEvent struct {
	FrameNumber  int     `json:"frame_number"`
	Timestamp    string  `json:"timestamp"`
	CallID       string  `json:"call_id"`
	Method       string  `json:"method"`
	SrcIP        string  `json:"src_ip"`
	DstIP        string  `json:"dst_ip"`
	SrcPort      string  `json:"src_port"`
	DstPort      string  `json:"dst_port"`
	StatusCode   *string `json:"status_code,omitempty"`
	ReasonPhrase *string `json:"reason_phrase,omitempty"`
	UserAgent    *string `json:"user_agent,omitempty"`
}

// CallSession tracks correlated INVITE and BYE events for a single Call-ID.
type CallSession struct {
	CallID           string
	InviteEvent      *CallEvent
	ByeEvent         *CallEvent
	InitiatorIP      *string
	TerminatorIP     *string
	DisconnectCode   *string
	DisconnectReason *string
	CallDirection    *string
}

// CallSessionSummary holds the JSON representation returned by CallSession.get_call_summary().
type CallSessionSummary struct {
	CallID           string  `json:"call_id"`
	InitiatorIP      *string `json:"initiator_ip"`
	TerminatorIP     *string `json:"terminator_ip"`
	DisconnectCode   *string `json:"disconnect_code"`
	DisconnectReason *string `json:"disconnect_reason"`
	CallDirection    *string `json:"call_direction"`
	InviteTimestamp  *string `json:"invite_timestamp"`
	ByeTimestamp     *string `json:"bye_timestamp"`
	CompleteSession  bool    `json:"complete_session"`
	SessionType      string  `json:"session_type"`
	CaptureContext   string  `json:"capture_context"`
	HangupPattern    *string `json:"hangup_pattern,omitempty"`
}

// CaptureWindowAnalysis summarizes calls starting or ending within the capture window.
type CaptureWindowAnalysis struct {
	CallsStartedInCapture      int `json:"calls_started_in_capture"`
	CallsEndedInCapture        int `json:"calls_ended_in_capture"`
	CallsSpanningCaptureWindow int `json:"calls_spanning_capture_window"`
}

// CallPatternAnalysis aggregates completion, termination, and hangup pattern counts.
type CallPatternAnalysis struct {
	TotalCalls         int                   `json:"total_calls"`
	CompleteCalls      int                   `json:"complete_calls"`
	IncompleteCalls    int                   `json:"incomplete_calls"`
	InviteOnlyCalls    int                   `json:"invite_only_calls"`
	ByeOnlyCalls       int                   `json:"bye_only_calls"`
	NormalTerminations int                   `json:"normal_terminations"`
	ErrorTerminations  int                   `json:"error_terminations"`
	InitiatorHangups   int                   `json:"initiator_hangups"`
	RecipientHangups   int                   `json:"recipient_hangups"`
	DisconnectCodes    map[string]int        `json:"disconnect_codes"`
	CallPatterns       []string              `json:"call_patterns"`
	CaptureAnalysis    CaptureWindowAnalysis `json:"capture_analysis"`
}

// CallTrackingReport bundles aggregate pattern metrics and per-Call-ID session summaries.
type CallTrackingReport struct {
	Analysis CallPatternAnalysis           `json:"analysis"`
	Sessions map[string]CallSessionSummary `json:"sessions"`
}

// IsComplete returns true when both INVITE and BYE events were seen for the call.
func (s *CallSession) IsComplete() bool {
	return s != nil && s.InviteEvent != nil && s.ByeEvent != nil
}

// SessionType classifies whether the session is complete, invite_only, bye_only, or unknown.
func (s *CallSession) SessionType() string {
	switch {
	case s.InviteEvent != nil && s.ByeEvent != nil:
		return "complete"
	case s.InviteEvent != nil:
		return "invite_only"
	case s.ByeEvent != nil:
		return "bye_only"
	default:
		return "unknown"
	}
}

// CaptureContext describes what lifecycle boundaries fell inside the capture window.
func (s *CallSession) CaptureContext() string {
	switch s.SessionType() {
	case "complete":
		return "Complete call session captured"
	case "invite_only":
		return "Call start captured, but termination occurred outside capture window"
	case "bye_only":
		return "Call termination captured, but initiation occurred before capture started"
	default:
		return "Partial session data"
	}
}

// Summary returns the serialized session summary matching Python get_call_summary().
func (s *CallSession) Summary() CallSessionSummary {
	out := CallSessionSummary{
		CallID: s.CallID, InitiatorIP: s.InitiatorIP, TerminatorIP: s.TerminatorIP,
		DisconnectCode: s.DisconnectCode, DisconnectReason: s.DisconnectReason,
		CallDirection: s.CallDirection, CompleteSession: s.IsComplete(),
		SessionType: s.SessionType(), CaptureContext: s.CaptureContext(),
	}
	if s.InviteEvent != nil {
		ts := s.InviteEvent.Timestamp
		out.InviteTimestamp = &ts
	}
	if s.ByeEvent != nil {
		ts := s.ByeEvent.Timestamp
		out.ByeTimestamp = &ts
	}
	if s.InviteEvent != nil && s.ByeEvent != nil {
		pat := "Recipient hung up"
		if s.InitiatorIP != nil && s.ByeEvent.SrcIP == *s.InitiatorIP {
			pat = "Initiator hung up"
		}
		out.HangupPattern = &pat
	}
	return out
}

// ExtractAndAnalyzeCallTracking parses SIP JSON, correlates sessions, and analyzes patterns.
func ExtractAndAnalyzeCallTracking(sipJSON string) CallTrackingReport {
	events := ParseSIPEventsFromJSON(sipJSON)
	sessions := TrackCallSessions(events)
	analysis := AnalyzeCallPatterns(sessions)
	summaries := make(map[string]CallSessionSummary, len(sessions))
	for cid, sess := range sessions {
		summaries[cid] = sess.Summary()
	}
	return CallTrackingReport{Analysis: analysis, Sessions: summaries}
}

// TrackCallSessions correlates INVITE, BYE, and error response events by Call-ID.
func TrackCallSessions(events []CallEvent) map[string]*CallSession {
	sessions := make(map[string]*CallSession)
	for i := range events {
		ev := events[i]
		sess, ok := sessions[ev.CallID]
		if !ok {
			sess = &CallSession{CallID: ev.CallID}
			sessions[ev.CallID] = sess
		}
		evCopy := ev
		switch {
		case ev.Method == "INVITE":
			sess.InviteEvent = &evCopy
			src, dir := ev.SrcIP, "outbound"
			sess.InitiatorIP = &src
			sess.CallDirection = &dir
		case ev.Method == "BYE":
			sess.ByeEvent = &evCopy
			src, code, reason := ev.SrcIP, "BYE", "Normal call termination"
			sess.TerminatorIP = &src
			sess.DisconnectCode = &code
			sess.DisconnectReason = &reason
			if sess.InviteEvent == nil {
				dst := ev.DstIP
				sess.InitiatorIP = &dst
			}
		case strings.HasPrefix(ev.Method, "RESPONSE_"):
			sess.DisconnectCode = ev.StatusCode
			sess.DisconnectReason = ev.ReasonPhrase
			src := ev.SrcIP
			sess.TerminatorIP = &src
			if sess.InviteEvent == nil {
				dst := ev.DstIP
				sess.InitiatorIP = &dst
			}
		}
	}
	return sessions
}

// AnalyzeCallPatterns computes session completion, hangup, and disconnect statistics.
func AnalyzeCallPatterns(sessions map[string]*CallSession) CallPatternAnalysis {
	out := CallPatternAnalysis{
		TotalCalls:      len(sessions),
		DisconnectCodes: map[string]int{},
		CallPatterns:    []string{},
	}
	for _, sess := range sessions {
		sType := sess.SessionType()
		if sess.IsComplete() {
			out.CompleteCalls++
			out.CaptureAnalysis.CallsStartedInCapture++
			out.CaptureAnalysis.CallsEndedInCapture++
			if sess.DisconnectCode != nil && *sess.DisconnectCode == "BYE" {
				out.NormalTerminations++
			} else {
				out.ErrorTerminations++
			}
			if sess.ByeEvent != nil && sess.InitiatorIP != nil {
				if sess.ByeEvent.SrcIP == *sess.InitiatorIP {
					out.InitiatorHangups++
				} else {
					out.RecipientHangups++
				}
			}
		} else {
			out.IncompleteCalls++
			switch sType {
			case "invite_only":
				out.InviteOnlyCalls++
				out.CaptureAnalysis.CallsStartedInCapture++
				if sess.DisconnectCode != nil && *sess.DisconnectCode != "" {
					out.CaptureAnalysis.CallsEndedInCapture++
					countTermType(sess, &out)
				}
			case "bye_only":
				out.ByeOnlyCalls++
				out.CaptureAnalysis.CallsEndedInCapture++
				countTermType(sess, &out)
			}
		}
		if sess.DisconnectCode != nil && *sess.DisconnectCode != "" {
			out.DisconnectCodes[*sess.DisconnectCode]++
		}
	}
	if out.TotalCalls > 0 {
		out.CallPatterns = buildCallPatterns(out)
	}
	return out
}

func countTermType(sess *CallSession, out *CallPatternAnalysis) {
	if sess.DisconnectCode != nil && *sess.DisconnectCode == "BYE" {
		out.NormalTerminations++
	} else {
		out.ErrorTerminations++
	}
}

func buildCallPatterns(out CallPatternAnalysis) []string {
	var patterns []string
	switch {
	case out.InitiatorHangups > out.RecipientHangups:
		patterns = append(patterns, "📞 Callers tend to hang up more often than recipients")
	case out.RecipientHangups > out.InitiatorHangups:
		patterns = append(patterns, "📞 Recipients tend to hang up more often than callers")
	case out.CompleteCalls > 0:
		patterns = append(patterns, "📞 Balanced hangup pattern between callers and recipients")
	}
	if out.ErrorTerminations > out.NormalTerminations {
		patterns = append(patterns, "⚠️ More calls end with errors than normal termination")
	}
	if out.InviteOnlyCalls > 0 {
		patterns = append(patterns, fmt.Sprintf("📤 %d call(s) started during capture but continued beyond", out.InviteOnlyCalls))
	}
	if out.ByeOnlyCalls > 0 {
		patterns = append(patterns, fmt.Sprintf("📥 %d call(s) ended during capture but started before", out.ByeOnlyCalls))
	}
	if out.CompleteCalls == 0 && out.TotalCalls > 0 {
		patterns = append(patterns, "🔄 No complete call sessions - all calls span beyond capture window")
	}
	totalEvents := out.CaptureAnalysis.CallsStartedInCapture + out.CaptureAnalysis.CallsEndedInCapture
	if totalEvents > out.TotalCalls {
		patterns = append(patterns, "📊 Good capture coverage - multiple call events captured")
	}
	return patterns
}
