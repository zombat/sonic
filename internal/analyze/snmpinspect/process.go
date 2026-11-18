// Package snmpinspect decodes extracted SNMP field rows into normalized report structures.
package snmpinspect

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// buildSNMPReport transforms raw extracted SNMP rows, communities, and warnings into a scrubbed Report.
func buildSNMPReport(
	ctx context.Context,
	filePath string,
	opts Options,
	users []extract.SnmpUser,
	usersGiven bool,
	rows []map[string]string,
	communities map[string]bool,
	tableWarnings []string,
) Report {
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}

	byUser := make(map[string]extract.SnmpUser, len(users))
	var userOrder []string
	for _, u := range users {
		if _, exists := byUser[u.User]; !exists {
			userOrder = append(userOrder, u.User)
		}
		byUser[u.User] = u
	}

	messages := []MessageRow{}
	versionCounts := make(map[string]int)
	levelCounts := make(map[string]int)
	outcomeCounts := make(map[string]int)
	perUser := make(map[string]*V3UserSummary)
	issues := []model.Issue{}
	credentials := []CredentialRow{}
	type commFlowKey struct{ vname, a, b string }
	commFlows := make(map[commFlowKey]bool)
	var startPtr, endPtr *float64

	for _, row := range rows {
		ver, ok := parseInt(firstVal(row, "snmp.msgVersion"))
		if !ok {
			ver, ok = parseInt(firstVal(row, "snmp.version"))
		}
		if !ok {
			continue
		}
		vname, knownVer := VersionNames[ver]
		if !knownVer {
			vname = fmt.Sprintf("v%d", ver)
		}
		versionCounts[vname]++

		var framePtr *int
		var frames []int
		if fr, ok := parseInt(firstVal(row, "frame.number")); ok && fr != 0 {
			framePtr = &fr
			frames = []int{fr}
		}
		if tv, err := strconv.ParseFloat(firstVal(row, "frame.time_epoch"), 64); err == nil && !math.IsNaN(tv) && !math.IsInf(tv, 0) {
			if startPtr == nil || tv < *startPtr {
				v := tv
				startPtr = &v
			}
			if endPtr == nil || tv > *endPtr {
				v := tv
				endPtr = &v
			}
		}

		src, dst := endpoint(row, "src"), endpoint(row, "dst")
		var pduPtr *string
		if pduCode, ok := parseInt(firstVal(row, "snmp.data")); ok {
			if name, ok := PDUNames[pduCode]; ok {
				p := name
				pduPtr = &p
			}
		}

		if ver == 0 || ver == 1 {
			msg := MessageRow{
				Frame: framePtr, Version: vname, Src: src, Dst: dst, PDU: pduPtr, SecurityLevel: "community",
			}
			if firstVal(row, "snmp.community") != "" {
				msg.Credential = "masked"
				pk := model.PairKey(hostOnly(src), hostOnly(dst))
				fk := commFlowKey{vname: vname, a: pk[0], b: pk[1]}
				if !commFlows[fk] {
					commFlows[fk] = true
					credentials = append(credentials, CredentialRow{
						Protocol: vname, Flow: pk[0] + " -> " + pk[1], Kind: "community string", Value: "masked",
					})
					iss := model.MakeIssue(
						model.SeverityError, "SNMP_CLEARTEXT_COMMUNITY",
						fmt.Sprintf("%s -> %s: an SNMP %s community string crosses the network in cleartext (value masked): anyone on the path can read it and use it; move to SNMPv3 authPriv", src, dst, vname),
						frames,
					)
					iss.Version = vname
					issues = append(issues, iss)
				}
			}
			messages = append(messages, msg)
			continue
		}

		auth := flagSet(row, "snmp.v3.flags.auth")
		crypt := flagSet(row, "snmp.v3.flags.crypt")
		level := "noAuthNoPriv"
		if crypt {
			level = "authPriv"
		} else if auth {
			level = "authNoPriv"
		}
		levelCounts[level]++

		userName := firstVal(row, "snmp.msgUserName")
		var userPtr *string
		if userName != "" {
			u := userName
			userPtr = &u
		}
		eng := strings.ToLower(strings.ReplaceAll(firstVal(row, "snmp.msgAuthoritativeEngineID"), ":", ""))
		var engPtr *string
		if eng != "" {
			engPtr = &eng
		}

		msg := MessageRow{
			Frame: framePtr, Version: vname, Src: src, Dst: dst, PDU: pduPtr,
			SecurityLevel: level, User: userPtr, EngineID: engPtr, isV3: true,
		}
		if pduPtr != nil && *pduPtr == "report" {
			if stat, ok := reportCounter(row); ok {
				msg.Report = stat.Name
				msg.ReportMeaning = stat.Meaning
				if stat.Name != "usmStatsUnknownEngineIDs" {
					userClause := ""
					if userName != "" {
						userClause = " for user " + pyRepr(userName)
					}
					iss := model.MakeIssue(
						model.SeverityWarning, "SNMP_AGENT_REPORT",
						fmt.Sprintf("%s -> %s: the agent answered with a Report %s%s: %s", src, dst, stat.Name, userClause, stat.Meaning),
						frames,
					)
					iss.Counter = stat.Name
					issues = append(issues, iss)
				}
			}
		}
		if userName == "" && level == "noAuthNoPriv" {
			msg.Role = "engine discovery"
		}
		if auth {
			outcome, reason := v3Outcome(row, crypt, userName, eng, byUser, usersGiven)
			msg.hasAuth = true
			msg.Outcome = outcome
			msg.Reason = reason
			outcomeCounts[outcome]++
			key := userName
			if key == "" {
				key = "?"
			}
			tally, ok := perUser[key]
			if !ok {
				tally = &V3UserSummary{User: userPtr, Outcomes: make(map[string]int)}
				perUser[key] = tally
			}
			tally.Messages++
			tally.Outcomes[outcome]++
			appendV3Issue(msg, outcome, reason, src, dst, frames, &issues)
		}
		messages = append(messages, msg)
	}

	for _, line := range tableWarnings {
		issues = append(issues, model.MakeIssue(model.SeverityError, "SNMP_USERS_TABLE_REFUSED", "tshark refused a line of the users table: "+line, nil))
	}
	for _, name := range userOrder {
		if u := byUser[name]; u.Auth != "" {
			if _, seen := perUser[name]; !seen {
				issues = append(issues, model.MakeIssue(model.SeverityInfo, "SNMP_USER_NOT_SEEN",
					fmt.Sprintf("user %s from the users file sent no authenticated message in this capture", pyRepr(name)), nil))
			}
		}
	}

	notDecrypted := 0
	for _, k := range []string{"decrypt_failed", "auth_failed", "unknown_user", "unknown_engine", "no_keys", "not_attempted"} {
		notDecrypted += outcomeCounts[k]
	}
	v3Users := make([]V3UserSummary, 0, len(perUser))
	for _, entry := range perUser {
		v3Users = append(v3Users, *entry)
	}
	slices.SortStableFunc(v3Users, func(a, b V3UserSummary) int {
		au, bu := "", ""
		if a.User != nil {
			au = *a.User
		}
		if b.User != nil {
			bu = *b.User
		}
		return cmp.Compare(au, bu)
	})

	if tableWarnings == nil {
		tableWarnings = []string{}
	}
	var dfPtr *string
	if opts.DisplayFilter != "" {
		df := opts.DisplayFilter
		dfPtr = &df
	}
	verdict := buildVerdict(versionCounts, levelCounts, outcomeCounts, credentials, usersGiven)
	listed, omitted := model.Cap(messages, maxItems*4)

	rep := Report{
		Status:        "success",
		Schema:        ReportSchema,
		File:          filePath,
		OverallStatus: model.StatusFromIssues(issues, len(messages) > 0),
		Verdict:       verdict,
		Capture: CaptureInfo{
			Start: model.ISOTime(startPtr), End: model.ISOTime(endPtr),
			Tshark: tshark.VersionString(ctx, ""), UsersFileGiven: usersGiven,
			UsersCount: len(users), DisplayFilter: dfPtr, MaxPackets: opts.MaxPackets,
			Warnings: tableWarnings,
		},
		Summary: Summary{
			Messages: len(messages), Versions: versionCounts,
			V3SecurityLevels: levelCounts, V3Outcomes: outcomeCounts,
			AuthPrivDecrypted: outcomeCounts["decrypted"], AuthPrivNotDecrypted: notDecrypted,
			CleartextCommunities: len(credentials),
		},
		V3Users: v3Users, Messages: listed, MessagesOmitted: omitted,
		Credentials: credentials, Issues: model.SortIssues(issues), Limits: Limits,
	}

	secretSet := make(map[string]bool)
	for c := range communities {
		if len(c) >= 3 {
			secretSet[c] = true
		}
	}
	for _, u := range users {
		for _, v := range []string{u.AuthPass, u.PrivPass} {
			if len(v) >= 3 {
				secretSet[v] = true
			}
		}
	}
	if len(secretSet) > 0 {
		secrets := make([]string, 0, len(secretSet))
		for s := range secretSet {
			secrets = append(secrets, s)
		}
		slices.SortFunc(secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
		scrubReport(&rep, secrets)
	}
	return rep
}
