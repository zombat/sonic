// Package audit computes SSH/TLS encryption findings and builds audit verdict text.
package audit

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// encryptionFindings summarizes SSH/TLS session states and emits WEAK_ENCRYPTION,
// ENCRYPTION_UNVERIFIED, and ENCRYPTED_OUTSIDE_TUNNEL issues in golden order.
func encryptionFindings(sessions []model.TCPSession, issues *[]model.Issue) (model.EncryptionSummary, int) {
	var judged []model.TCPSession
	for _, s := range sessions {
		if s.Encryption != nil {
			judged = append(judged, s)
		}
	}
	summary := model.EncryptionSummary{Sessions: len(judged)}
	for _, s := range judged {
		switch s.Encryption.State {
		case "encrypted":
			summary.Encrypted++
		case "weak":
			summary.Weak++
		case "unverified":
			summary.Unverified++
		case "cleartext":
			summary.Cleartext++
		case "not_started":
			summary.NotStarted++
		}
	}

	warningSpecs := []struct {
		state string
		code  string
		what  string
	}{
		{"weak", "WEAK_ENCRYPTION", "passed with weak encryption"},
		{"unverified", "ENCRYPTION_UNVERIFIED", "passed as encrypted, unverified"},
	}
	for _, spec := range warningSpecs {
		var protoOrder []string
		groups := make(map[string][]model.TCPSession)
		for _, s := range judged {
			if s.Encryption.State == spec.state {
				if _, exists := groups[s.Protocol]; !exists {
					protoOrder = append(protoOrder, s.Protocol)
				}
				groups[s.Protocol] = append(groups[s.Protocol], s)
			}
		}
		for _, protocol := range protoOrder {
			members := groups[protocol]
			var reasons []string
			seenReason := make(map[string]bool)
			for _, m := range members {
				if m.Encryption.Reason != nil && *m.Encryption.Reason != "" && !seenReason[*m.Encryption.Reason] {
					seenReason[*m.Encryption.Reason] = true
					reasons = append(reasons, *m.Encryption.Reason)
				}
			}
			first := members[0]
			limitReasons := reasons[:min(len(reasons), 3)]
			msg := fmt.Sprintf("%d %s session(s) %s: %s (first %s -> %s)",
				len(members), protocol, spec.what, strings.Join(limitReasons, "; "), first.Client, first.Server)

			frames := make([]int, len(members))
			for i, m := range members {
				frames[i] = m.FirstFrame
			}
			slices.Sort(frames)
			issue := model.MakeIssue(model.SeverityWarning, spec.code, msg, frames)
			issue.Protocol = protocol
			*issues = append(*issues, issue)
		}
	}

	var outside []model.TCPSession
	for _, s := range judged {
		if s.AllowedAsEncrypted != nil && *s.AllowedAsEncrypted {
			outside = append(outside, s)
		}
	}
	if len(outside) > 0 {
		var nameOrder []string
		counts := make(map[string]int)
		frames := make([]int, len(outside))
		for i, s := range outside {
			if _, ok := counts[s.Protocol]; !ok {
				nameOrder = append(nameOrder, s.Protocol)
			}
			counts[s.Protocol]++
			frames[i] = s.FirstFrame
		}
		parts := make([]string, 0, len(nameOrder))
		for _, name := range nameOrder {
			parts = append(parts, fmt.Sprintf("%d %s", counts[name], name))
		}
		slices.Sort(frames)
		msg := fmt.Sprintf("%d SSH or TLS session(s) passed as encrypted by their own transport, not inside IPsec (%s); allow crypto alone to require the tunnel",
			len(outside), strings.Join(parts, ", "))
		*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "ENCRYPTED_OUTSIDE_TUNNEL", msg, frames))
	}

	return summary, len(outside)
}

func formatProtectionBreakdown(protection map[string]int) string {
	order := []string{"encrypted", "key_exchange", "authenticated_only", "layer2", "cleartext"}
	var parts []string
	for _, k := range order {
		if n := protection[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(k, "_", " ")))
		}
	}
	return strings.Join(parts, ", ")
}

func buildVerdict(
	frames int,
	passed bool,
	clean bool,
	allowText []string,
	protection map[string]int,
	cleartext int,
	enc model.EncryptionSummary,
	outsideTunnel int,
	rows []*violationAgg,
	byProto []model.ByProtocol,
	issues *[]model.Issue,
) string {
	if frames == 0 {
		verdict := "FAIL: the capture is empty, so nothing proves the link carried only allowed traffic"
		*issues = append(*issues, model.MakeIssue(model.SeverityError, "AUDIT_EMPTY_CAPTURE", verdict, nil))
		return verdict
	}
	protected := formatProtectionBreakdown(protection)
	if passed {
		prefix := "PASS"
		if !clean {
			prefix = "PASS with warnings"
		}
		verdict := fmt.Sprintf("%s: all %d frames match the allowlist (%s); no cleartext outside it (%s)",
			prefix, frames, strings.Join(allowText, ", "), protected)
		var doubts []string
		if enc.Unverified > 0 {
			doubts = append(doubts, fmt.Sprintf("%d encrypted, unverified (see ENCRYPTION_UNVERIFIED)", enc.Unverified))
		}
		if enc.Weak > 0 {
			doubts = append(doubts, fmt.Sprintf("%d weakly encrypted (see WEAK_ENCRYPTION)", enc.Weak))
		}
		if len(doubts) > 0 {
			verdict += "; but of the SSH and TLS sessions " + strings.Join(doubts, " and ")
		}
		if outsideTunnel > 0 {
			verdict += fmt.Sprintf("; %d SSH or TLS session(s) protected by their own encryption, not by IPsec (allow crypto alone to require the tunnel)",
				outsideTunnel)
		}
		return verdict
	}

	violating := 0
	for _, r := range rows {
		violating += r.packets
	}
	parts := make([]string, 0, len(byProto))
	for _, agg := range byProto {
		parts = append(parts, fmt.Sprintf("%d %s", agg.Packets, agg.Protocol))
	}
	verdict := fmt.Sprintf("FAIL: %d of %d frames outside the allowlist (%s); first at frame %d",
		violating, frames, strings.Join(parts, ", "), rows[0].firstFrame)

	outsideClear := 0
	var unencReason string
	hasUnenc := false
	for _, r := range rows {
		outsideClear += r.protection["cleartext"]
		if !hasUnenc && r.category == "unencrypted_session" {
			hasUnenc = true
			if len(r.reasons) > 0 {
				unencReason = r.reasons[0]
			} else {
				unencReason = "see violations"
			}
		}
	}
	if outsideClear == 0 {
		verdict += fmt.Sprintf("; none of them is cleartext (%s): allow ssh, tls, netconf or encrypted (the default) to accept transport encryption",
			protected)
	} else {
		verdict += fmt.Sprintf("; %d of them cleartext", outsideClear)
		if protected != fmt.Sprintf("%d cleartext", cleartext) {
			verdict += fmt.Sprintf(" (all frames: %s)", protected)
		}
	}
	if hasUnenc {
		verdict += fmt.Sprintf("; %d SSH or TLS session(s) negotiated no encryption (%s)", enc.Cleartext, unencReason)
	}
	return verdict
}
