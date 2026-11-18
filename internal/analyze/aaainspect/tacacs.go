// Package aaainspect TACACS+ session aggregation and cleartext/auth-failure issue reporting.
package aaainspect

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/zombat/sonic/internal/model"
)

// TacacsTypes maps TACACS+ header type values to protocol labels.
var TacacsTypes = map[int]string{1: "Authentication", 2: "Authorization", 3: "Accounting"}

// TacacsAuthenStatus maps TACACS+ authentication reply status bytes to names.
var TacacsAuthenStatus = map[int]string{
	1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER", 5: "GETPASS", 6: "RESTART", 7: "ERROR", 0x21: "FOLLOW",
}

// TacacsAuthorStatus maps TACACS+ authorization reply status bytes to names.
var TacacsAuthorStatus = map[int]string{
	1: "PASS_ADD", 2: "PASS_REPL", 0x10: "FAIL", 0x11: "ERROR", 0x21: "FOLLOW",
}

// TacacsAcctStatus maps TACACS+ accounting reply status bytes to names.
var TacacsAcctStatus = map[int]string{1: "SUCCESS", 2: "ERROR", 0x21: "FOLLOW"}

// TacacsActions maps TACACS+ authentication action values to names.
var TacacsActions = map[int]string{1: "login", 2: "chpass", 3: "sendpass", 4: "sendauth"}

// TacacsServices maps TACACS+ authentication service values to names.
var TacacsServices = map[int]string{
	0: "none", 1: "login", 2: "enable", 3: "ppp", 4: "arap", 5: "pt", 6: "rcmd", 7: "x25", 8: "nasi", 9: "fwproxy",
}

// TacacsUnencryptedFlag marks a TACACS+ packet sent without body obfuscation.
const TacacsUnencryptedFlag = 0x01

// tacacsTrack accumulates TACACS+ session state prior to building TacacsView.
type tacacsTrack struct {
	TacacsView
	t       *float64
	typeSet map[string]bool
}

// tacacsSessions groups extracted TACACS+ frames by session ID.
func tacacsSessions(rows []map[string]string) []tacacsTrack {
	sessMap := make(map[int64]*tacacsTrack)
	var order []int64

	for _, row := range rows {
		sidVal, ok := parseInt64(firstVal(row, "tacplus.session_id"))
		if !ok {
			continue
		}
		sess, exists := sessMap[sidVal]
		if !exists {
			sess = &tacacsTrack{
				TacacsView: TacacsView{SessionID: sidVal, Frames: []int{}},
				typeSet:    make(map[string]bool),
			}
			sessMap[sidVal] = sess
			order = append(order, sidVal)
		}
		if fr, ok := parseInt(firstVal(row, "frame.number")); ok && fr != 0 {
			sess.Frames = append(sess.Frames, fr)
		}
		if sess.t == nil {
			tv, _ := strconv.ParseFloat(firstVal(row, "frame.time_epoch"), 64)
			sess.t = &tv
		}
		if ptype, ok := parseInt(firstVal(row, "tacplus.type")); ok {
			lbl := TacacsTypes[ptype]
			if lbl == "" {
				lbl = strconv.Itoa(ptype)
			}
			sess.typeSet[lbl] = true
		}

		sport, hasSport := parseInt(firstVal(row, "tcp.srcport"))
		dport, hasDport := parseInt(firstVal(row, "tcp.dstport"))
		if hasDport && dport == 49 && sess.Client == nil {
			c := endpoint(row, "src", "tcp.srcport")
			s := endpoint(row, "dst", "tcp.dstport")
			sess.Client = &c
			sess.Server = &s
		} else if hasSport && sport == 49 && sess.Server == nil {
			s := endpoint(row, "src", "tcp.srcport")
			c := endpoint(row, "dst", "tcp.dstport")
			sess.Server = &s
			sess.Client = &c
		}

		if flags, ok := parseInt(firstVal(row, "tacplus.flags")); ok && (flags&TacacsUnencryptedFlag) != 0 {
			sess.Cleartext = true
		}
		if user := firstVal(row, "tacplus.user"); user != "" && sess.User == nil {
			sess.User = &user
		}
		if action, ok := parseInt(firstVal(row, "tacplus.authen_action")); ok && sess.Action == nil {
			lbl := TacacsActions[action]
			if lbl == "" {
				lbl = strconv.Itoa(action)
			}
			sess.Action = &lbl
		}
		if svc, ok := parseInt(firstVal(row, "tacplus.service")); ok && sess.Service == nil {
			lbl := TacacsServices[svc]
			if lbl == "" {
				lbl = strconv.Itoa(svc)
			}
			sess.Service = &lbl
		}
		if priv, ok := parseInt(firstVal(row, "tacplus.privilege_level")); ok && sess.PrivLvl == nil {
			sess.PrivLvl = &priv
		}
		if authen, ok := parseInt(firstVal(row, "tacplus.body_authen_rep.status")); ok {
			lbl := TacacsAuthenStatus[authen]
			if lbl == "" {
				lbl = fmt.Sprintf("0x%x", authen)
			}
			sess.Authentication = &lbl
		}
		if author, ok := parseInt(firstVal(row, "tacplus.body_author_rep.auth_status")); ok {
			lbl := TacacsAuthorStatus[author]
			if lbl == "" {
				lbl = fmt.Sprintf("0x%x", author)
			}
			sess.Authorization = &lbl
		}
		if acct, ok := parseInt(firstVal(row, "tacplus.body_acct.status")); ok {
			lbl := TacacsAcctStatus[acct]
			if lbl == "" {
				lbl = fmt.Sprintf("0x%x", acct)
			}
			sess.Accounting = &lbl
		}
		if firstVal(row, "tacplus.auth_password") != "" || firstVal(row, "tacplus.body_authen_req_cont.user") != "" {
			sess.CredentialRecovered = true
		}
	}

	out := make([]tacacsTrack, 0, len(order))
	for _, sid := range order {
		sess := sessMap[sid]
		types := make([]string, 0, len(sess.typeSet))
		for k := range sess.typeSet {
			types = append(types, k)
		}
		slices.Sort(types)
		sess.Types = types
		if sess.CredentialRecovered {
			m := "masked"
			sess.Credential = &m
		}
		out = append(out, *sess)
	}
	return out
}

// appendTacacsIssues records cleartext TACACS+, failed auth/author, and obfuscation-recovery issues.
func appendTacacsIssues(tacacs []tacacsTrack, issues *[]model.Issue, creds *[]CredentialRow) {
	for _, s := range tacacs {
		clientStr, serverStr := "None", "None"
		if s.Client != nil {
			clientStr = *s.Client
		}
		if s.Server != nil {
			serverStr = *s.Server
		}
		label := fmt.Sprintf("session 0x%08x %s -> %s", uint64(s.SessionID), clientStr, serverStr)
		var frames []int
		if len(s.Frames) > 0 {
			frames = s.Frames[:1]
		}
		userLabel := "a user"
		if s.User != nil && *s.User != "" {
			userLabel = *s.User
		}
		if s.Cleartext {
			iss := model.MakeIssue(model.SeverityError, "AAA_CLEARTEXT_TACACS",
				label+": the TACACS+ body is sent unobfuscated (the unencrypted flag is set): the user name, password and authorization cross the network readable", frames)
			iss.User = s.User
			*issues = append(*issues, iss)
		}
		if s.Authentication != nil && *s.Authentication == "FAIL" {
			iss := model.MakeIssue(model.SeverityWarning, "AAA_AUTH_FAIL",
				fmt.Sprintf("%s: authentication FAILed for %s", label, userLabel), frames)
			iss.User = s.User
			*issues = append(*issues, iss)
		}
		if s.Authorization != nil && (*s.Authorization == "FAIL" || *s.Authorization == "ERROR") {
			iss := model.MakeIssue(model.SeverityWarning, "AAA_AUTHORIZATION_FAIL",
				fmt.Sprintf("%s: authorization %s for %s", label, *s.Authorization, userLabel), frames)
			iss.User = s.User
			*issues = append(*issues, iss)
		}
		if s.CredentialRecovered && !s.Cleartext {
			*creds = append(*creds, CredentialRow{
				Protocol: "tacacs+", Flow: clientStr + " -> " + serverStr, Username: s.User, Kind: "password", Value: "masked",
			})
			iss := model.MakeIssue(model.SeverityInfo, "AAA_CREDENTIAL_RECOVERED",
				fmt.Sprintf("%s: the password for %s was de-obfuscated with the shared key (value masked): anyone with the key and the capture can read it", label, userLabel), frames)
			iss.User = s.User
			*issues = append(*issues, iss)
		}
	}
}
