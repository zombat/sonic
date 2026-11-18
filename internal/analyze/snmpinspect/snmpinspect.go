// Package snmpinspect capture validation and entry-point orchestration for SNMP analysis.
package snmpinspect

import (
	"context"
	"os"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/tshark"
)

// VersionNames maps SNMP integer version fields to display labels.
var VersionNames = map[int]string{0: "v1", 1: "v2c", 3: "v3"}

// PDUNames maps ASN.1 context tag PDU integers to SNMP operation names.
var PDUNames = map[int]string{
	0: "get-request", 1: "get-next-request", 2: "response", 3: "set-request", 4: "trap",
	5: "get-bulk-request", 6: "inform-request", 7: "snmpV2-trap", 8: "report",
}

// Limits lists capture-vantage and decryption caveats attached to every SNMP report.
var Limits = []string{
	"Only what crossed the capture point is read. A v3 message whose user is not in the users file, or is given for another engine id, is reported as not decrypted with that reason, never skipped silently.",
	"SNMPv3 decryption needs the right USM passphrases; a wrong auth passphrase fails authentication and a wrong privacy passphrase leaves the scoped PDU unreadable.",
	"TShark 3.6.2 offers auth MD5, SHA1, SHA2-224/256/384/512 and priv DES, AES-128, AES-192, AES-256. For AES-192/256 over an SHA1 or MD5 user it extends the key the Reeder (Cisco) way; an agent that extends it the Blumenthal-draft way, net-snmp among them, cannot be decrypted then (with SHA2-256 or SHA2-512 no extension is needed and it can).",
	"A v1 or v2c community string is a cleartext credential: anyone on the path reads it. It is flagged and masked.",
	"The USM passphrases are secrets: read by path, kept off the tshark command line (a temporary snmp_users table), and never written to a record, a log or a report. A decrypted PDU's contents are never emitted.",
}

// errReport builds a standardized {"status":"error","error":msg} Report.
func errReport(msg string) Report {
	return Report{Status: "error", Error: msg}
}

// AnalyzeCapture runs Wireshark SNMP dissection (with optional USM decryption) over filePath.
func AnalyzeCapture(ctx context.Context, filePath string, opts Options) Report {
	if filePath == "" {
		return errReport("File not found: " + filePath)
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return errReport("File not found: " + filePath)
	}
	if info.IsDir() {
		return errReport("File not readable: " + filePath)
	}
	if f, err := os.Open(filePath); err != nil {
		return errReport("File not readable: " + filePath)
	} else {
		_ = f.Close()
	}
	if !tshark.Available("") {
		return errReport("SNMP analysis needs tshark (Wireshark's SNMP dissector); install it")
	}
	if opts.MaxPackets != nil && *opts.MaxPackets <= 0 {
		return errReport("max_packets must be a positive number")
	}

	var users []extract.SnmpUser
	usersGiven := opts.UsersFile != ""
	if usersGiven {
		uInfo, err := os.Stat(opts.UsersFile)
		if err != nil || !uInfo.Mode().IsRegular() {
			return errReport("users_file is not a readable file")
		}
		raw, err := os.ReadFile(opts.UsersFile)
		if err != nil {
			return errReport("cannot read the users file: " + err.Error())
		}
		parsed, err := extract.ParseSnmpUsersFile(string(raw))
		if err != nil {
			return errReport("cannot read the users file: " + err.Error())
		}
		users = parsed
	}

	rows, communities, tableWarnings, err := extract.ExtractSNMP(ctx, filePath, users, opts.DisplayFilter, opts.MaxPackets)
	if err != nil {
		return errReport(err.Error())
	}
	return buildSNMPReport(ctx, filePath, opts, users, usersGiven, rows, communities, tableWarnings)
}
