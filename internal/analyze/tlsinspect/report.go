// Package tlsinspect session aggregation, verdict formatting, and report building.
package tlsinspect

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report compiles the complete JSON report matching TlsDetector.report().
func (d *Detector) Report(ctx model.Context) Report {
	ordered := make([]*sessionState, 0, len(d.order))
	for _, k := range d.order {
		ordered = append(ordered, d.sessions[k])
	}
	slices.SortStableFunc(ordered, func(a, b *sessionState) int {
		return cmp.Compare(a.firstT, b.firstT)
	})

	issues := []model.Issue{}
	events := []model.Event{}
	sessions := make([]Session, 0, len(ordered))
	baseActive := d.baseline.active()

	for _, sess := range ordered {
		sh := sess.serverHello
		var version string
		if sh != nil {
			version = sh.Version
		}
		cert := resolveSessionCertificate(sess, version)
		violations := d.checkSession(sess)
		clientEnd := sess.client.format()
		serverEnd := sess.server.format()
		label := clientEnd + " -> " + serverEnd
		var sni *string
		if sess.clientHello != nil {
			sni = sess.clientHello.SNI
		}
		frames := sortedFrameValues(sess.frames)

		var alertsOut []AlertRecord
		alertsOut, issues, events = collectSessionAlerts(ctx, sess, clientEnd, label, issues, events)

		if sess.clientHello != nil && sh == nil && len(alertsOut) == 0 {
			text := fmt.Sprintf("TLS %s: ClientHello (SNI %s) with no ServerHello seen", label, optStrOrNone(sni))
			issues = append(issues, model.MakeIssue(model.SeverityWarning, "TLS_NO_SERVER_HELLO", text, frames))
			var firstFrame *int
			if len(frames) > 0 {
				fCopy := frames[0]
				firstFrame = &fCopy
			}
			events = append(events, model.MakeEvent(ctx, sess.firstT, "tls", "no_server_hello", text, firstFrame))
		}

		for _, v := range violations {
			issues = append(issues, model.MakeIssue(v.Severity, v.Code,
				fmt.Sprintf("TLS %s (SNI %s): %s", label, optStrOrNone(sni), v.Message), frames))
		}

		hints := SessionHints(sess.server.addr, sni, version, cert)
		for _, h := range hints {
			if h.Code == "TLS_CERT_NO_IP_SAN" {
				issues = append(issues, model.MakeIssue(model.SeverityWarning, "TLS_CERT_NO_IP_SAN",
					fmt.Sprintf("TLS %s: %s", label, h.Text), frames))
			}
		}

		if sh != nil {
			tEvt := sess.firstT
			if sess.serverHelloT != nil {
				tEvt = *sess.serverHelloT
			}
			var shFrame *int
			if f, ok := sess.frames["server_hello"]; ok {
				fCopy := f
				shFrame = &fCopy
			}
			events = append(events, model.MakeEvent(ctx, tEvt, "tls", "handshake",
				fmt.Sprintf("TLS %s SNI %s: %s %s", label, optStrOrNone(sni), version, sh.CipherSuite), shFrame))
		}

		var basePass *bool
		if baseActive {
			pass := true
			for _, v := range violations {
				if v.Severity == model.SeverityError {
					pass = false
					break
				}
			}
			basePass = &pass
		}

		framesOut := make(map[string]int, len(sess.frames))
		for k, v := range sess.frames {
			framesOut[k] = v
		}
		sessions = append(sessions, Session{
			Client:            clientEnd,
			Server:            serverEnd,
			SNI:               sni,
			ClientOffered:     sess.clientHello,
			ServerChose:       sh,
			HelloRetryRequest: sess.helloRetryRequest,
			Certificate:       cert,
			Hints:             hints,
			Alerts:            alertsOut,
			BaselinePass:      basePass,
			Findings:          violations,
			Frames:            framesOut,
			FirstT:            ctx.Rel(&sess.firstT),
		})
	}

	present := d.Present()
	status := model.StatusFromIssues(issues, present)
	verdict := buildVerdict(sessions, present, baseActive)
	listed, omitted := model.Cap(sessions, ctx.MaxItems)

	var baselineOut *Baseline
	if baseActive {
		baselineOut = d.baseline
	}

	failures := 0
	for _, s := range sessions {
		if s.BaselinePass != nil && !*s.BaselinePass {
			failures++
		}
	}

	return Report{
		Detector: "tls",
		Status:   status,
		Verdict:  verdict,
		Baseline: baselineOut,
		Summary: Summary{
			Handshakes:          len(sessions),
			StreamsDroppedAtCap: d.dropped,
			BaselineFailures:    failures,
		},
		Sessions:        listed,
		SessionsOmitted: omitted,
		Limits:          Limits,
		Issues:          model.SortIssues(issues),
		Events:          events,
	}
}

// resolveSessionCertificate determines the certificate state or invisibility reason for sess.
func resolveSessionCertificate(sess *sessionState, version string) CertificateInfo {
	if sess.serverHello == nil {
		return CertificateInfo{Visible: false, Reason: "no ServerHello seen"}
	}
	if version == "TLS1.3" {
		return CertificateInfo{Visible: false, Reason: "TLS 1.3 encrypts the certificate; not visible"}
	}
	if sess.certificate != nil {
		return *sess.certificate
	}
	return CertificateInfo{Visible: false, Reason: "Certificate message not captured (resumed session, or segments missing)"}
}

// collectSessionAlerts enriches raw alerts with sender role/hint and appends non-close-notify issues and events.
func collectSessionAlerts(ctx model.Context, sess *sessionState, clientEnd, label string, issues []model.Issue, events []model.Event) ([]AlertRecord, []model.Issue, []model.Event) {
	alertsOut := make([]AlertRecord, 0, len(sess.alerts))
	for _, a := range sess.alerts {
		sender := "server"
		if a.From == clientEnd {
			sender = "client"
		}
		var hint *string
		if a.Level != "encrypted" {
			hint = AlertHint(a.Description, sender)
		}
		alertsOut = append(alertsOut, AlertRecord{
			From:        a.From,
			Level:       a.Level,
			Description: a.Description,
			Frame:       a.Frame,
			Sender:      sender,
			Hint:        hint,
		})
		if a.Level == "encrypted" {
			continue
		}
		if a.Level == "fatal" || a.Description != "close_notify" {
			text := fmt.Sprintf("TLS %s: %s alert %s from %s", label, a.Level, a.Description, a.From)
			if hint != nil {
				text += fmt.Sprintf(" (%s)", *hint)
			}
			sev := model.SeverityWarning
			if a.Level == "fatal" {
				sev = model.SeverityError
			}
			issues = append(issues, model.MakeIssue(sev, "TLS_ALERT", text, []int{a.Frame}))
			fCopy := a.Frame
			events = append(events, model.MakeEvent(ctx, a.t, "tls", "alert", text, &fCopy))
		}
	}
	return alertsOut, issues, events
}

// buildVerdict formats the single-sentence summary matching TlsDetector.report().
func buildVerdict(sessions []Session, present, baseActive bool) string {
	if !present {
		return "No TLS handshake in this capture."
	}
	versions := make(map[string]int)
	unanswered := 0
	failing := 0
	for _, s := range sessions {
		if s.ServerChose != nil {
			versions[s.ServerChose.Version]++
		}
		if s.ClientOffered != nil && s.ServerChose == nil {
			unanswered++
		}
		if s.BaselinePass != nil && !*s.BaselinePass {
			failing++
		}
	}
	verdict := fmt.Sprintf("%d TLS handshake(s)", len(sessions))
	if len(versions) > 0 {
		keys := make([]string, 0, len(versions))
		for v := range versions {
			keys = append(keys, v)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(keys))
		for _, v := range keys {
			parts = append(parts, fmt.Sprintf("%d %s", versions[v], v))
		}
		verdict += ": " + strings.Join(parts, ", ")
	}
	if unanswered > 0 {
		verdict += fmt.Sprintf("; %d without ServerHello", unanswered)
	}
	if baseActive {
		if failing > 0 {
			verdict += fmt.Sprintf("; %d fail the baseline", failing)
		} else {
			verdict += "; all meet the baseline"
		}
	}
	return verdict + "."
}

// sortedFrameValues returns deduplicated sorted frame numbers from a frame map.
func sortedFrameValues(frames map[string]int) []int {
	seen := make(map[int]bool, len(frames))
	out := make([]int, 0, len(frames))
	for _, f := range frames {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

// optStrOrNone returns *s when non-nil, or Python's "None" representation otherwise.
func optStrOrNone(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}
