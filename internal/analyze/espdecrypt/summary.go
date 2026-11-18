// Package espdecrypt formats per-SA decryption diagnostics, nested inner summaries,
// and verdict prose for sonic.esp_decrypt_report/1 outputs.
package espdecrypt

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/model"
)

// saReason explains why an SA decrypted none or only some of its matched ESP packets.
func saReason(sa SARow) *string {
	if sa.Packets == 0 {
		msg := "no ESP packet in the capture matched this SA: wrong addresses or SPI, the other direction's SA, or the traffic is not in this capture"
		return &msg
	}
	if sa.Decrypted == sa.Packets {
		return nil
	}
	failed := sa.Packets - sa.Decrypted
	aead := sa.Encryption != nil && strings.Contains(strings.ToLower(*sa.Encryption), "gcm")
	if sa.ICVBad > 0 {
		what := "the integrity key or algorithm"
		if aead {
			what = "the key (for AES-GCM the key and its 4-byte salt)"
		}
		msg := fmt.Sprintf("%d of %d packet(s) failed the integrity check: %s is wrong, or the packets were altered",
			sa.ICVBad, sa.Packets, what)
		return &msg
	}
	if sa.ICVGood >= failed && !aead {
		msg := fmt.Sprintf("%d of %d packet(s) did not decrypt although their integrity check passed: the integrity key is right, so the encryption key or algorithm is wrong",
			failed, sa.Packets)
		return &msg
	}
	msg := fmt.Sprintf("%d of %d packet(s) did not decrypt: the key or algorithm is wrong (or the sender pads with something other than the RFC 4303 default, which S.O.N.I.C. uses to prove a decryption)",
		failed, sa.Packets)
	return &msg
}

// buildInnerSummary condenses a nested NetworkReport into bounded verdicts and issues.
func buildInnerSummary(rep netorch.NetworkReport) *InnerSummary {
	if rep.Status != "success" {
		return &InnerSummary{Status: rep.Status, Error: rep.Error}
	}
	verdicts := make(map[string]string, len(rep.Verdicts))
	for k, v := range rep.Verdicts {
		verdicts[k] = v
	}
	protos := []string{}
	if len(rep.ProtocolsPresent) > 0 {
		protos = slices.Clone(rep.ProtocolsPresent)
	}

	type detectorSection struct {
		name string
		raw  json.RawMessage
	}
	sections := []detectorSection{
		{"ipsec", rep.IPsec},
		{"gre_nhrp", rep.GreNHRP},
		{"dmvpn_phase3", rep.DMVPNPhase3},
		{"routing", rep.Routing},
		{"reachability", rep.Reachability},
		{"path_mtu", rep.PathMTU},
		{"esp_overhead", rep.ESPOverhead},
		{"tcp", rep.TCP},
		{"tls", rep.TLS},
		{"qos", rep.QoS},
		{"conversations", rep.Conversations},
		{"cleartext_audit", rep.CleartextAudit},
		{"convergence", rep.Convergence},
	}

	type issueEnvelope struct {
		Issues []model.Issue `json:"issues"`
	}
	issues := []InnerIssue{}
	for _, sec := range sections {
		if len(sec.raw) == 0 || string(sec.raw) == "null" {
			continue
		}
		var env issueEnvelope
		if err := json.Unmarshal(sec.raw, &env); err != nil {
			continue
		}
		limit := min(10, len(env.Issues))
		for _, iss := range env.Issues[:limit] {
			issues = append(issues, InnerIssue{
				Detector: sec.name,
				Severity: iss.Severity,
				Code:     iss.Code,
				Message:  iss.Message,
			})
			if len(issues) >= 40 {
				return &InnerSummary{
					Status:           "success",
					ProtocolsPresent: protos,
					OverallStatus:    rep.OverallStatus,
					Verdicts:         verdicts,
					Issues:           issues,
				}
			}
		}
	}
	return &InnerSummary{
		Status:           "success",
		ProtocolsPresent: protos,
		OverallStatus:    rep.OverallStatus,
		Verdicts:         verdicts,
		Issues:           issues,
	}
}

// buildVerdict formats the single-sentence ESP decryption summary matching analyzers/esp_decrypt.py.
func buildVerdict(saRows []SARow, totalPkts, totalDec, innerWritten int, inner *InnerSummary) string {
	if len(saRows) == 0 {
		return "No Security Association given."
	}
	decrypting := 0
	for _, s := range saRows {
		if s.Decrypted > 0 {
			decrypting++
		}
	}
	parts := []string{
		fmt.Sprintf("%d SA(s), %d decrypting", len(saRows), decrypting),
		fmt.Sprintf("%d of %d ESP packet(s) decrypted", totalDec, totalPkts),
	}
	if innerWritten > 0 {
		protos := []string{}
		if inner != nil && len(inner.ProtocolsPresent) > 0 {
			protos = inner.ProtocolsPresent
		}
		tail := fmt.Sprintf("%d inner packet(s) reconstructed", innerWritten)
		if len(protos) > 0 {
			tail += "; inner traffic: " + strings.Join(protos, ", ")
		}
		parts = append(parts, tail)
	} else if totalDec > 0 {
		parts = append(parts, "no inner packet could be reconstructed")
	}
	return strings.Join(parts, ". ") + "."
}
