package snmpinspect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
)

func TestGoldenSNMPParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	got := AnalyzeCapture(context.Background(), filepath.Join("testdata", "fixtures", "snmp_v1v2c.pcap"), Options{})
	parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "snmp", "snmp_v1v2c.json"))

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{"public-v1-not-real", "private-v2c-not-real"} {
		if strings.Contains(text, secret) {
			t.Fatalf("community string %q leaked into report JSON", secret)
		}
	}
}

func TestSnmpErrorsAndV3Helpers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmp := t.TempDir()

	// Missing and directory paths.
	if rep := AnalyzeCapture(ctx, filepath.Join(tmp, "missing.pcap"), Options{}); rep.Status != "error" {
		t.Fatalf("expected error on missing capture: %+v", rep)
	}
	if rep := AnalyzeCapture(ctx, tmp, Options{}); rep.Status != "error" {
		t.Fatalf("expected error on dir capture: %+v", rep)
	}

	// Non-positive max_packets and bad users file.
	dummyPcap := filepath.Join(tmp, "empty.pcap")
	if err := os.WriteFile(dummyPcap, []byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	zero := 0
	if rep := AnalyzeCapture(ctx, dummyPcap, Options{MaxPackets: &zero}); rep.Status != "error" {
		t.Fatalf("expected error on max_packets=0: %+v", rep)
	}
	if rep := AnalyzeCapture(ctx, dummyPcap, Options{UsersFile: filepath.Join(tmp, "no-users.txt")}); rep.Status != "error" {
		t.Fatalf("expected error on missing users file: %+v", rep)
	}
	badUsers := filepath.Join(tmp, "bad.txt")
	if err := os.WriteFile(badUsers, []byte("# only comments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repBadUsers := AnalyzeCapture(ctx, dummyPcap, Options{UsersFile: badUsers})
	rawErr, err := json.Marshal(repBadUsers)
	if err != nil || !strings.Contains(string(rawErr), `"status":"error"`) {
		t.Fatalf("unexpected error JSON: %s (%v)", rawErr, err)
	}

	// Exercise V3 outcomes and MessageRow JSON serialization across states.
	byUser := map[string]extract.SnmpUser{
		"alice": {User: "alice", Auth: "SHA1", AuthPass: "authsec1", Priv: "AES192", PrivPass: "privsec1", EngineID: "8000aa"},
		"noa":   {User: "noa"},
	}
	if out, _ := v3Outcome(map[string]string{"snmp.authentication_error": "1", "snmp.data": "1"}, true, "alice", "8000aa", byUser, true); out != "auth_failed" {
		t.Fatalf("got %s want auth_failed", out)
	}
	if out, _ := v3Outcome(map[string]string{"snmp.data": "2"}, true, "alice", "8000aa", byUser, true); out != "decrypted" {
		t.Fatalf("got %s want decrypted", out)
	}
	if out, _ := v3Outcome(map[string]string{"snmp.authentication_ok": "1"}, false, "alice", "8000aa", byUser, true); out != "authenticated" {
		t.Fatalf("got %s want authenticated", out)
	}
	if out, reason := v3Outcome(map[string]string{"snmp.decrypted_pdu": "1"}, true, "alice", "8000aa", byUser, true); out != "decrypt_failed" || reason == nil || !strings.Contains(*reason, "Reeder") {
		t.Fatalf("expected Reeder decrypt_failed, got (%s, %v)", out, reason)
	}
	if out, _ := v3Outcome(map[string]string{}, true, "alice", "8000aa", byUser, false); out != "no_keys" {
		t.Fatalf("got %s want no_keys", out)
	}
	if out, _ := v3Outcome(map[string]string{}, true, "bob", "8000aa", byUser, true); out != "unknown_user" {
		t.Fatalf("got %s want unknown_user", out)
	}
	if out, _ := v3Outcome(map[string]string{}, true, "alice", "8000bb", byUser, true); out != "unknown_engine" {
		t.Fatalf("got %s want unknown_engine", out)
	}
	if out, _ := v3Outcome(map[string]string{}, true, "noa", "", byUser, true); out != "not_attempted" {
		t.Fatalf("got %s want not_attempted", out)
	}
	if stat, ok := reportCounter(map[string]string{"snmp.name": "1.3.6.1.6.3.15.1.1.5.0"}); !ok || stat.Name != "usmStatsWrongDigests" {
		t.Fatalf("reportCounter = (%+v, %v)", stat, ok)
	}

	var issues []model.Issue
	u := "alice"
	reason := "bad"
	appendV3Issue(MessageRow{SecurityLevel: "authPriv", User: &u}, "auth_failed", &reason, "a", "b", []int{1}, &issues)
	if len(issues) != 1 || issues[0].Code != "SNMP_AUTH_FAILED" {
		t.Fatalf("unexpected v3 issue: %+v", issues)
	}

	msgNoAuth := MessageRow{Version: "v3", Src: "a", Dst: "b", SecurityLevel: "noAuthNoPriv", isV3: true}
	bNoAuth, _ := json.Marshal(msgNoAuth)
	if strings.Contains(string(bNoAuth), `"reason"`) {
		t.Fatalf("noAuthNoPriv should omit reason: %s", bNoAuth)
	}
	msgAuthOK := MessageRow{Version: "v3", Src: "a", Dst: "b", SecurityLevel: "authPriv", Outcome: "decrypted", isV3: true, hasAuth: true}
	bAuthOK, _ := json.Marshal(msgAuthOK)
	if !strings.Contains(string(bAuthOK), `"reason":null`) {
		t.Fatalf("authenticated v3 message should emit reason:null: %s", bAuthOK)
	}

	verdictV3 := buildVerdict(
		map[string]int{"v3": 4},
		map[string]int{"authPriv": 3, "noAuthNoPriv": 1},
		map[string]int{"decrypted": 2, "auth_failed": 1},
		nil,
		true,
	)
	if !strings.Contains(verdictV3, "2 of 3 authPriv message(s) decrypted (1 auth failed)") {
		t.Fatalf("unexpected v3 verdict: %s", verdictV3)
	}
	if emptyV := buildVerdict(nil, nil, nil, nil, false); emptyV != "No SNMP found in this capture." {
		t.Fatalf("empty verdict = %q", emptyV)
	}

	// Scrubbing pass test.
	rep := Report{Verdict: "leak authsec1 here", Messages: []MessageRow{{User: &u, Reason: &reason}}, Issues: []model.Issue{{Message: "authsec1"}}, Capture: CaptureInfo{Warnings: []string{"authsec1"}}}
	scrubReport(&rep, []string{"authsec1"})
	if strings.Contains(rep.Verdict+rep.Issues[0].Message+rep.Capture.Warnings[0], "authsec1") {
		t.Fatalf("secret leaked after scrubReport: %+v", rep)
	}

	// Synthetic v3 row processing covering engine discovery, USM reports, warnings, and unseen users.
	rows := []map[string]string{
		{"frame.number": "1", "frame.time_epoch": "100.0", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "udp.srcport": "40000", "udp.dstport": "161", "snmp.msgVersion": "3", "snmp.v3.flags.auth": "0", "snmp.v3.flags.crypt": "0", "snmp.data": "0"},
		{"frame.number": "2", "frame.time_epoch": "100.1", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.1", "udp.srcport": "161", "udp.dstport": "40000", "snmp.msgVersion": "3", "snmp.data": "8", "snmp.name": "1.3.6.1.6.3.15.1.1.5.0", "snmp.msgUserName": "alice"},
		{"frame.number": "3", "frame.time_epoch": "100.2", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "udp.srcport": "40001", "udp.dstport": "161", "snmp.msgVersion": "3", "snmp.v3.flags.auth": "1", "snmp.v3.flags.crypt": "1", "snmp.msgUserName": "alice", "snmp.msgAuthoritativeEngineID": "80:00:AA", "snmp.authentication_error": "1"},
		{"frame.number": "4", "frame.time_epoch": "100.3", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "udp.srcport": "40002", "udp.dstport": "161", "snmp.msgVersion": "3", "snmp.v3.flags.auth": "1", "snmp.v3.flags.crypt": "0", "snmp.msgUserName": "alice", "snmp.msgAuthoritativeEngineID": "80:00:AA", "snmp.authentication_ok": "1", "snmp.data": "0"},
		{"frame.number": "5", "frame.time_epoch": "100.4", "snmp.msgVersion": ""},
	}
	v3Users := []extract.SnmpUser{
		{User: "alice", Auth: "SHA1", AuthPass: "authsec1", Priv: "AES192", PrivPass: "privsec1", EngineID: "8000aa"},
		{User: "unused", Auth: "SHA1", AuthPass: "unusedpw1"},
	}
	v3Rep := buildSNMPReport(ctx, "synth.pcap", Options{DisplayFilter: "snmp"}, v3Users, true, rows, nil, []string{"snmp_users: bad row"})
	if v3Rep.Summary.Messages != 4 || v3Rep.OverallStatus != model.StatusProblem || len(v3Rep.V3Users) != 1 {
		t.Fatalf("unexpected v3 report: %+v", v3Rep)
	}
}
