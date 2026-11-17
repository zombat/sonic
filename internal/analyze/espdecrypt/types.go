// Package espdecrypt defines options, SA status rows, and report schemas for
// S.O.N.I.C. ESP decryption and inner-traffic analysis.
package espdecrypt

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/model"
)

// ReportSchema identifies the JSON output contract for esp_decrypt reports.
const ReportSchema = "sonic.esp_decrypt_report/1"

// Limits documents the protocol and cryptographic boundaries of ESP decryption.
var Limits = []string{
	"Only ESP packets whose (src, dst, SPI) matches an SA, and whose keys and algorithms are correct, decrypt; a wrong key, a missing SA or NULL-but-undeclared encryption leaves the packet encrypted.",
	"Cisco IOS and IOS XE do not expose ESP session keys, so a capture of a Cisco IOS tunnel cannot be decrypted this way. This feature is for SAs whose keys an operator can read (a Linux/strongSwan endpoint's ip xfrm state, a lab).",
	"A packet counts as decrypted only when its decrypted ESP trailer is real: the RFC 4303 default padding (1, 2, 3, ...), a real next header, and in tunnel mode an inner IP packet whose own length is the payload's. tshark fills its decrypted-data field under a wrong key too, so its presence proves nothing.",
	"Tunnel-mode inner packets are analysed as sent; a transport-mode payload is given back its outer IP header (the SA's addresses), so ports and payload are the sender's but the IP header is rebuilt.",
	"The inner analysis sees only what the ESP packets carried; a one-way capture shows one direction of the inner conversation.",
	"SA keys are secrets: read by path, kept off the tshark command line, and never written to a record, a log or a report.",
}

// Options configures SA loading, tshark capture filters, and inner detector selection.
type Options struct {
	SAFile        string
	Detectors     []string
	DisplayFilter string
	MaxPackets    *int
	MaxItems      int
}

// CaptureInfo records capture execution metadata without exposing secret key values.
type CaptureInfo struct {
	Tshark                    *string  `json:"tshark"`
	SACount                   int      `json:"sa_count"`
	ESPPackets                int      `json:"esp_packets"`
	ESPDecrypted              int      `json:"esp_decrypted"`
	InnerPacketsReconstructed int      `json:"inner_packets_reconstructed"`
	Warnings                  []string `json:"warnings"`
	DisplayFilter             *string  `json:"display_filter"`
	MaxPackets                *int     `json:"max_packets"`
}

// Summary aggregates SA counts and decrypted ESP packet totals.
type Summary struct {
	SecurityAssociations int `json:"security_associations"`
	ESPPackets           int `json:"esp_packets"`
	ESPDecrypted         int `json:"esp_decrypted"`
	SAsDecrypting        int `json:"sas_decrypting"`
}

// SARow summarizes decryption counts and failure rationale for a single Security Association.
type SARow struct {
	Src        string  `json:"src"`
	Dst        string  `json:"dst"`
	SPI        string  `json:"spi"`
	Encryption *string `json:"encryption"`
	Integrity  *string `json:"integrity"`
	Packets    int     `json:"packets"`
	Decrypted  int     `json:"decrypted"`
	Tunnel     int     `json:"tunnel"`
	Transport  int     `json:"transport"`
	ICVGood    int     `json:"icv_good"`
	ICVBad     int     `json:"icv_bad"`
	Reason     *string `json:"reason"`
}

// InnerIssue holds a compact nested detector issue inside InnerSummary.
type InnerIssue struct {
	Detector string         `json:"detector"`
	Severity model.Severity `json:"severity"`
	Code     string         `json:"code"`
	Message  string         `json:"message"`
}

// InnerSummary holds a bounded summary of network detectors executed over decrypted inner packets.
type InnerSummary struct {
	Status           string            `json:"status"`
	Error            string            `json:"error,omitempty"`
	ProtocolsPresent []string          `json:"protocols_present"`
	OverallStatus    model.Status      `json:"overall_status"`
	Verdicts         map[string]string `json:"verdicts"`
	Issues           []InnerIssue      `json:"issues"`
}

// MarshalJSON emits error fields only on failed inner analysis, or full summary fields on success.
func (s InnerSummary) MarshalJSON() ([]byte, error) {
	if s.Status != "success" {
		type errSummary struct {
			Status string `json:"status"`
			Error  string `json:"error,omitempty"`
		}
		return json.Marshal(errSummary{Status: s.Status, Error: s.Error})
	}
	type okSummary struct {
		Status           string            `json:"status"`
		ProtocolsPresent []string          `json:"protocols_present"`
		OverallStatus    model.Status      `json:"overall_status"`
		Verdicts         map[string]string `json:"verdicts"`
		Issues           []InnerIssue      `json:"issues"`
	}
	protos := s.ProtocolsPresent
	if protos == nil {
		protos = []string{}
	}
	verdicts := s.Verdicts
	if verdicts == nil {
		verdicts = map[string]string{}
	}
	issues := s.Issues
	if issues == nil {
		issues = []InnerIssue{}
	}
	return json.Marshal(okSummary{
		Status:           s.Status,
		ProtocolsPresent: protos,
		OverallStatus:    s.OverallStatus,
		Verdicts:         verdicts,
		Issues:           issues,
	})
}

// Report represents the top-level sonic.esp_decrypt_report/1 JSON payload or error response.
type Report struct {
	Status                      string        `json:"status"`
	Error                       string        `json:"error,omitempty"`
	Schema                      string        `json:"schema"`
	File                        string        `json:"file"`
	OverallStatus               model.Status  `json:"overall_status"`
	Verdict                     string        `json:"verdict"`
	Capture                     CaptureInfo   `json:"capture"`
	Summary                     Summary       `json:"summary"`
	SecurityAssociations        []SARow       `json:"security_associations"`
	SecurityAssociationsOmitted int           `json:"security_associations_omitted"`
	InnerAnalysis               *InnerSummary `json:"inner_analysis"`
	Issues                      []model.Issue `json:"issues"`
	Limits                      []string      `json:"limits"`
}

// MarshalJSON emits {"status":"error","error":...} on error or the full Report on success.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		type errPayload struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		return json.Marshal(errPayload{Status: r.Status, Error: r.Error})
	}
	type fullReport Report
	return json.Marshal(fullReport(r))
}
