// Package aaainspect implements TACACS+ and RADIUS troubleshooting, HMAC verification,
// and secret scrubbing matching analyzers/aaa_inspect.py.
package aaainspect

import (
	"encoding/json"

	"github.com/zombat/sonic/internal/model"
)

// ReportSchema identifies the JSON schema version of AAA reports.
const ReportSchema = "sonic.aaa_report/1"

// Options configures AnalyzeCapture execution parameters.
type Options struct {
	KeysFile      string
	DisplayFilter string
	MaxPackets    *int
	MaxItems      int
}

// CaptureInfo summarizes capture timestamps, tshark version, and key presence flags.
type CaptureInfo struct {
	Start             *string `json:"start"`
	End               *string `json:"end"`
	Tshark            *string `json:"tshark"`
	TacacsKeyGiven    bool    `json:"tacacs_key_given"`
	RadiusSecretGiven bool    `json:"radius_secret_given"`
	DisplayFilter     *string `json:"display_filter"`
	MaxPackets        *int    `json:"max_packets"`
}

// Summary aggregates AAA transaction/session counts, accepts, rejects, and recovered credentials.
type Summary struct {
	RadiusTransactions      int `json:"radius_transactions"`
	TacacsSessions          int `json:"tacacs_sessions"`
	Accepts                 int `json:"accepts"`
	Rejects                 int `json:"rejects"`
	CleartextTacacsSessions int `json:"cleartext_tacacs_sessions"`
	CredentialsRecovered    int `json:"credentials_recovered"`
}

// MessageAuthState holds RADIUS Message-Authenticator verification states per side.
type MessageAuthState struct {
	Request  *string `json:"request"`
	Response *string `json:"response"`
}

// RadiusView is the redacted report view of one RADIUS transaction.
type RadiusView struct {
	Client               string           `json:"client"`
	Server               string           `json:"server"`
	ID                   *int             `json:"id"`
	Kind                 string           `json:"kind"`
	RequestCode          *string          `json:"request_code"`
	ResponseCode         *string          `json:"response_code"`
	Username             *string          `json:"username"`
	NAS                  *string          `json:"nas"`
	CallingStation       *string          `json:"calling_station"`
	AcctStatus           *string          `json:"acct_status"`
	AuthenticatorValid   *bool            `json:"authenticator_valid"`
	MessageAuthenticator MessageAuthState `json:"message_authenticator"`
	CredentialRecovered  bool             `json:"credential_recovered"`
	Credential           *string          `json:"credential"`
	Frames               []int            `json:"frames"`
	Result               string           `json:"result"`
}

// TacacsView is the redacted report view of one TACACS+ session.
type TacacsView struct {
	SessionID           int64    `json:"session_id"`
	Client              *string  `json:"client"`
	Server              *string  `json:"server"`
	User                *string  `json:"user"`
	Action              *string  `json:"action"`
	Service             *string  `json:"service"`
	PrivLvl             *int     `json:"priv_lvl"`
	Cleartext           bool     `json:"cleartext"`
	Types               []string `json:"types"`
	Authentication      *string  `json:"authentication"`
	Authorization       *string  `json:"authorization"`
	Accounting          *string  `json:"accounting"`
	CredentialRecovered bool     `json:"credential_recovered"`
	Credential          *string  `json:"credential"`
	Frames              []int    `json:"frames"`
}

// CredentialRow records a recovered or observed AAA credential with its secret masked.
type CredentialRow struct {
	Protocol string  `json:"protocol"`
	Flow     string  `json:"flow"`
	Username *string `json:"username"`
	Kind     string  `json:"kind"`
	Value    string  `json:"value"`
}

// Report is the top-level JSON structure emitted by AnalyzeCapture.
type Report struct {
	Status        string
	Error         string
	Schema        string
	File          string
	OverallStatus model.Status
	Verdict       string
	Capture       CaptureInfo
	Summary       Summary
	Radius        []RadiusView
	RadiusOmitted int
	Tacacs        []TacacsView
	TacacsOmitted int
	Credentials   []CredentialRow
	Issues        []model.Issue
	Limits        []string
}

// MarshalJSON encodes either {"status":"error","error":...} or the full AAA report.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.Status == "error" {
		return json.Marshal(struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}{Status: r.Status, Error: r.Error})
	}
	return json.Marshal(struct {
		Status        string          `json:"status"`
		Schema        string          `json:"schema"`
		File          string          `json:"file"`
		OverallStatus model.Status    `json:"overall_status"`
		Verdict       string          `json:"verdict"`
		Capture       CaptureInfo     `json:"capture"`
		Summary       Summary         `json:"summary"`
		Radius        []RadiusView    `json:"radius"`
		RadiusOmitted int             `json:"radius_omitted"`
		Tacacs        []TacacsView    `json:"tacacs"`
		TacacsOmitted int             `json:"tacacs_omitted"`
		Credentials   []CredentialRow `json:"credentials"`
		Issues        []model.Issue   `json:"issues"`
		Limits        []string        `json:"limits"`
	}{
		Status: r.Status, Schema: r.Schema, File: r.File, OverallStatus: r.OverallStatus,
		Verdict: r.Verdict, Capture: r.Capture, Summary: r.Summary,
		Radius: r.Radius, RadiusOmitted: r.RadiusOmitted,
		Tacacs: r.Tacacs, TacacsOmitted: r.TacacsOmitted,
		Credentials: r.Credentials, Issues: r.Issues, Limits: r.Limits,
	})
}
