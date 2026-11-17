// Package snmpinspect SNMPv3 outcome diagnosis, USM report counters, and verdict formatting.
package snmpinspect

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

// USMStat pairs an SNMPv3 usmStats OID with its symbolic name and explanation.
type USMStat struct {
	Name    string
	Meaning string
}

// USMStats maps usmStats MIB OIDs to counter names and explanations.
var USMStats = map[string]USMStat{
	"1.3.6.1.6.3.15.1.1.1.0": {Name: "usmStatsUnsupportedSecLevels", Meaning: "the agent does not support the security level asked"},
	"1.3.6.1.6.3.15.1.1.2.0": {Name: "usmStatsNotInTimeWindows", Meaning: "the request fell outside the agent's time window (engine boots/time out of sync)"},
	"1.3.6.1.6.3.15.1.1.3.0": {Name: "usmStatsUnknownUserNames", Meaning: "the agent has no such user"},
	"1.3.6.1.6.3.15.1.1.4.0": {Name: "usmStatsUnknownEngineIDs", Meaning: "the request named another engine id (normal in engine discovery)"},
	"1.3.6.1.6.3.15.1.1.5.0": {Name: "usmStatsWrongDigests", Meaning: "the request failed authentication at the agent: wrong auth passphrase or protocol"},
	"1.3.6.1.6.3.15.1.1.6.0": {Name: "usmStatsDecryptionErrors", Meaning: "the agent could not decrypt the request: wrong privacy passphrase or protocol"},
}

// reportCounter looks up any usmStats OID in the extracted snmp.name values of row.
func reportCounter(row map[string]string) (USMStat, bool) {
	for _, oid := range splitField(row, "snmp.name") {
		if stat, ok := USMStats[oid]; ok {
			return stat, true
		}
	}
	return USMStat{}, false
}

// v3Outcome determines why an authenticated SNMPv3 message succeeded or failed decryption/auth.
func v3Outcome(row map[string]string, crypt bool, userName, engine string, byUser map[string]extract.SnmpUser, usersGiven bool) (string, *string) {
	attempted := firstVal(row, "snmp.authentication_ok") != "" ||
		firstVal(row, "snmp.authentication_error") != "" ||
		firstVal(row, "snmp.decrypted_pdu") != "" ||
		firstVal(row, "_ws.malformed") != "" ||
		firstVal(row, "snmp.decrypted_data_bad_formatted") != "" ||
		firstVal(row, "snmp.failed_decrypted_data_pdu") != ""
	dissected := firstVal(row, "snmp.data") != ""
	user, hasUser := byUser[userName]

	if firstVal(row, "snmp.authentication_error") != "" || firstVal(row, "snmp.verify_authentication_error") != "" {
		tail := ""
		if crypt && dissected {
			tail = " (the privacy key still decrypted it)"
		}
		reason := fmt.Sprintf("authentication failed: the auth passphrase or protocol in the users file does not match the one this message was sent with%s", tail)
		return "auth_failed", &reason
	}
	if crypt && dissected {
		return "decrypted", nil
	}
	if !crypt && firstVal(row, "snmp.authentication_ok") != "" {
		return "authenticated", nil
	}
	if attempted && crypt {
		if hasUser && extract.SnmpNeedsKeyExtension(user) {
			reason := fmt.Sprintf(
				"decryption failed. This user's %s key (%d bits) is longer than its %s hash (%d bits), so tshark 3.6.2 extends it the Reeder (Cisco) way: an agent that extends it the Blumenthal-draft way (net-snmp, among others) cannot be decrypted with tshark 3.6.2; a wrong privacy passphrase looks the same",
				user.Priv, extract.SnmpPrivKeyBytes[user.Priv]*8, user.Auth, extract.SnmpAuthHashBytes[user.Auth]*8,
			)
			return "decrypt_failed", &reason
		}
		reason := "decryption failed: the privacy passphrase or protocol is wrong"
		if firstVal(row, "snmp.authentication_ok") != "" {
			reason = "decryption failed: authentication passed, so the user and engine match, and the privacy passphrase or protocol is wrong"
		}
		return "decrypt_failed", &reason
	}
	if !usersGiven {
		reason := "no users file was given, so the message's keys are unknown"
		return "no_keys", &reason
	}
	if !hasUser {
		reason := fmt.Sprintf("unknown user: the users file has no entry for user %s", pyRepr(userName))
		return "unknown_user", &reason
	}
	if user.EngineID != "" && engine != "" && user.EngineID != engine {
		reason := fmt.Sprintf("unknown engine: the users file gives user %s only for engine %s, and this message is from engine %s", pyRepr(userName), user.EngineID, engine)
		return "unknown_engine", &reason
	}
	if user.Auth == "" {
		reason := fmt.Sprintf("the users file gives user %s no auth protocol", pyRepr(userName))
		return "not_attempted", &reason
	}
	reason := "tshark did not apply this user's keys to the message (check the protocols)"
	return "not_attempted", &reason
}

// appendV3Issue adds an SNMPv3 warning or info issue for a failed or unkeyed message.
func appendV3Issue(msg MessageRow, outcome string, reason *string, src, dst string, frames []int, issues *[]model.Issue) {
	spec := map[string]struct {
		sev  model.Severity
		code string
	}{
		"auth_failed":    {model.SeverityWarning, "SNMP_AUTH_FAILED"},
		"decrypt_failed": {model.SeverityWarning, "SNMP_DECRYPT_FAILED"},
		"unknown_user":   {model.SeverityWarning, "SNMP_UNKNOWN_USER"},
		"unknown_engine": {model.SeverityWarning, "SNMP_UNKNOWN_ENGINE"},
		"no_keys":        {model.SeverityInfo, "SNMP_NOT_DECRYPTED"},
		"not_attempted":  {model.SeverityWarning, "SNMP_NOT_DECRYPTED"},
	}
	entry, ok := spec[outcome]
	if !ok {
		return
	}
	uShow := "?"
	if msg.User != nil && *msg.User != "" {
		uShow = *msg.User
	}
	reasonText := ""
	if reason != nil {
		reasonText = *reason
	}
	iss := model.MakeIssue(
		entry.sev, entry.code,
		fmt.Sprintf("%s -> %s: SNMPv3 %s message from user %s: %s", src, dst, msg.SecurityLevel, pyRepr(uShow), reasonText),
		frames,
	)
	iss.User = msg.User
	*issues = append(*issues, iss)
}

// buildVerdict formats the single-sentence SNMP summary matching Python's _verdict().
func buildVerdict(versions, levels, outcomes map[string]int, creds []CredentialRow, usersGiven bool) string {
	if len(versions) == 0 {
		return "No SNMP found in this capture."
	}
	vKeys := make([]string, 0, len(versions))
	for k := range versions {
		vKeys = append(vKeys, k)
	}
	slices.Sort(vKeys)
	vParts := make([]string, 0, len(vKeys))
	for _, k := range vKeys {
		vParts = append(vParts, fmt.Sprintf("%d %s", versions[k], k))
	}
	parts := []string{strings.Join(vParts, ", ") + " message(s)"}

	if len(levels) > 0 {
		lKeys := make([]string, 0, len(levels))
		for k := range levels {
			lKeys = append(lKeys, k)
		}
		slices.Sort(lKeys)
		lParts := make([]string, 0, len(lKeys))
		for _, k := range lKeys {
			lParts = append(lParts, fmt.Sprintf("%d %s", levels[k], k))
		}
		parts = append(parts, "v3 security levels: "+strings.Join(lParts, ", "))
	}

	if total := levels["authPriv"]; total > 0 {
		if usersGiven {
			done := outcomes["decrypted"]
			oKeys := make([]string, 0, len(outcomes))
			for k := range outcomes {
				if k != "decrypted" && k != "authenticated" {
					oKeys = append(oKeys, k)
				}
			}
			slices.Sort(oKeys)
			var oParts []string
			for _, k := range oKeys {
				oParts = append(oParts, fmt.Sprintf("%d %s", outcomes[k], strings.ReplaceAll(k, "_", " ")))
			}
			s := fmt.Sprintf("%d of %d authPriv message(s) decrypted", done, total)
			if len(oParts) > 0 {
				s += " (" + strings.Join(oParts, ", ") + ")"
			}
			parts = append(parts, s)
		} else {
			parts = append(parts, fmt.Sprintf("%d authPriv message(s) left encrypted: no users file given", total))
		}
	}

	if len(creds) > 0 {
		parts = append(parts, fmt.Sprintf("%d cleartext community credential flow(s) (values masked)", len(creds)))
	}
	return strings.Join(parts, ". ") + "."
}
