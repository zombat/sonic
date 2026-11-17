// Package snmpinspect implements SNMP v1/v2c/v3 troubleshooting and SNMPv3 USM decryption
// matching analyzers/snmp_inspect.py.
package snmpinspect

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/model"
)

// ReportSchema identifies the JSON output contract version.
const ReportSchema = "sonic.snmp_report/1"

// Options configures AnalyzeCapture execution parameters.
type Options struct {
	UsersFile     string
	DisplayFilter string
	MaxPackets    *int
	MaxItems      int
}

// CaptureInfo summarizes capture timestamps, tshark version, and USM user table status.
type CaptureInfo struct {
	Start          *string  `json:"start"`
	End            *string  `json:"end"`
	Tshark         *string  `json:"tshark"`
	UsersFileGiven bool     `json:"users_file_given"`
	UsersCount     int      `json:"users_count"`
	DisplayFilter  *string  `json:"display_filter"`
	MaxPackets     *int     `json:"max_packets"`
	Warnings       []string `json:"warnings"`
}

// Summary aggregates protocol versions, v3 security levels, and decryption outcomes.
type Summary struct {
	Messages             int            `json:"messages"`
	Versions             map[string]int `json:"versions"`
	V3SecurityLevels     map[string]int `json:"v3_security_levels"`
	V3Outcomes           map[string]int `json:"v3_outcomes"`
	AuthPrivDecrypted    int            `json:"authpriv_decrypted"`
	AuthPrivNotDecrypted int            `json:"authpriv_not_decrypted"`
	CleartextCommunities int            `json:"cleartext_communities"`
}

// V3UserSummary counts authenticated SNMPv3 messages and outcomes per securityName.
type V3UserSummary struct {
	User     *string        `json:"user"`
	Messages int            `json:"messages"`
	Outcomes map[string]int `json:"outcomes"`
}

// CredentialRow records a cleartext SNMP v1/v2c community observation with its value masked.
type CredentialRow struct {
	Protocol string `json:"protocol"`
	Flow     string `json:"flow"`
	Kind     string `json:"kind"`
	Value    string `json:"value"`
}

// MessageRow represents a single decoded SNMP message.
type MessageRow struct {
	Frame         *int
	Version       string
	Src           string
	Dst           string
	PDU           *string
	SecurityLevel string
	Credential    string
	User          *string
	EngineID      *string
	Role          string
	Report        string
	ReportMeaning string
	Outcome       string
	Reason        *string
	isV3          bool
	hasAuth       bool
}

// MarshalJSON serializes v1/v2c vs v3 fields matching Python's dynamic message dicts.
func (m MessageRow) MarshalJSON() ([]byte, error) {
	if !m.isV3 {
		return json.Marshal(struct {
			Frame         *int    `json:"frame"`
			Version       string  `json:"version"`
			Src           string  `json:"src"`
			Dst           string  `json:"dst"`
			PDU           *string `json:"pdu"`
			SecurityLevel string  `json:"security_level"`
			Credential    string  `json:"credential,omitempty"`
		}{
			Frame: m.Frame, Version: m.Version, Src: m.Src, Dst: m.Dst,
			PDU: m.PDU, SecurityLevel: m.SecurityLevel, Credential: m.Credential,
		})
	}
	type v3Base struct {
		Frame         *int    `json:"frame"`
		Version       string  `json:"version"`
		Src           string  `json:"src"`
		Dst           string  `json:"dst"`
		PDU           *string `json:"pdu"`
		SecurityLevel string  `json:"security_level"`
		User          *string `json:"user"`
		EngineID      *string `json:"engine_id"`
		Role          string  `json:"role,omitempty"`
		Report        string  `json:"report,omitempty"`
		ReportMeaning string  `json:"report_meaning,omitempty"`
	}
	if !m.hasAuth {
		return json.Marshal(v3Base{
			Frame: m.Frame, Version: m.Version, Src: m.Src, Dst: m.Dst,
			PDU: m.PDU, SecurityLevel: m.SecurityLevel, User: m.User, EngineID: m.EngineID,
			Role: m.Role, Report: m.Report, ReportMeaning: m.ReportMeaning,
		})
	}
	return json.Marshal(struct {
		v3Base
		Outcome string  `json:"outcome"`
		Reason  *string `json:"reason"`
	}{
		v3Base: v3Base{
			Frame: m.Frame, Version: m.Version, Src: m.Src, Dst: m.Dst,
			PDU: m.PDU, SecurityLevel: m.SecurityLevel, User: m.User, EngineID: m.EngineID,
			Role: m.Role, Report: m.Report, ReportMeaning: m.ReportMeaning,
		},
		Outcome: m.Outcome,
		Reason:  m.Reason,
	})
}

// Report is the top-level JSON structure returned by AnalyzeCapture.
type Report struct {
	Status          string
	Error           string
	Schema          string
	File            string
	OverallStatus   model.Status
	Verdict         string
	Capture         CaptureInfo
	Summary         Summary
	V3Users         []V3UserSummary
	Messages        []MessageRow
	MessagesOmitted int
	Credentials     []CredentialRow
	Issues          []model.Issue
	Limits          []string
}

// MarshalJSON encodes either {"status":"error","error":...} or the full SNMP report.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		return json.Marshal(struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}{Status: r.Status, Error: r.Error})
	}
	return json.Marshal(struct {
		Status          string          `json:"status"`
		Schema          string          `json:"schema"`
		File            string          `json:"file"`
		OverallStatus   model.Status    `json:"overall_status"`
		Verdict         string          `json:"verdict"`
		Capture         CaptureInfo     `json:"capture"`
		Summary         Summary         `json:"summary"`
		V3Users         []V3UserSummary `json:"v3_users"`
		Messages        []MessageRow    `json:"messages"`
		MessagesOmitted int             `json:"messages_omitted"`
		Credentials     []CredentialRow `json:"credentials"`
		Issues          []model.Issue   `json:"issues"`
		Limits          []string        `json:"limits"`
	}{
		Status: r.Status, Schema: r.Schema, File: r.File, OverallStatus: r.OverallStatus,
		Verdict: r.Verdict, Capture: r.Capture, Summary: r.Summary, V3Users: r.V3Users,
		Messages: r.Messages, MessagesOmitted: r.MessagesOmitted,
		Credentials: r.Credentials, Issues: r.Issues, Limits: r.Limits,
	})
}
