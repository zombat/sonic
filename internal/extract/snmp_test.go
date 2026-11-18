package extract

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSnmpUsersFileAndHelpers(t *testing.T) {
	t.Parallel()

	block := strings.Join([]string{
		"# comment",
		"---",
		"user: alice",
		"auth: SHA-256",
		"auth_pass: pass1234",
		"priv: AES-192",
		"priv_pass: priv1234",
		"engine_id: 0x80:00 AB",
		"",
		"- user: bob",
		"auth = SHA",
		"auth_pass = pass5678",
	}, "\n")
	users, err := ParseSnmpUsersFile(block)
	if err != nil {
		t.Fatalf("ParseSnmpUsersFile(block): %v", err)
	}
	if len(users) != 2 || users[0].Auth != "SHA2-256" || users[0].Priv != "AES192" || users[0].EngineID != "8000ab" {
		t.Fatalf("unexpected block parse: %+v", users)
	}
	if users[1].Auth != "SHA1" || users[1].Priv != "" {
		t.Fatalf("unexpected second user: %+v", users[1])
	}
	if row := SnmpUserUATRow(users[0]); row != `"8000ab","alice","SHA2-256","pass1234","AES192","priv1234"` {
		t.Fatalf("SnmpUserUATRow = %s", row)
	}

	csvText := "user,auth,auth_pass,priv,priv_pass,engine_id\ncarol,MD5,aaaa,AES-256,bbbb,0x8000FF\n"
	csvUsers, err := ParseSnmpUsersFile(csvText)
	if err != nil || len(csvUsers) != 1 || !SnmpNeedsKeyExtension(csvUsers[0]) {
		t.Fatalf("CSV parse / key extension unexpected: (%+v, %v)", csvUsers, err)
	}
	if SnmpNeedsKeyExtension(users[0]) {
		t.Fatal("SHA2-256 + AES192 should not need key extension")
	}

	// Validation refusals must never echo passphrases.
	for _, bad := range []string{
		"# empty\n",
		"user: u\nauth: SHA3\nauth_pass: secret-1\n",
		"user: u\nauth: SHA\nauth_pass: secret-1\npriv: 3DES\npriv_pass: secret-2\n",
		"user: u\nauth: SHA\nauth_pass: has\"quote-secret\n",
	} {
		if _, err := ParseSnmpUsersFile(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatalf("error echoed secret: %v", err)
		}
	}
}

func TestExtractSNMPFixture(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	rows, communities, warnings, err := ExtractSNMP(context.Background(), filepath.Join("testdata", "fixtures", "snmp_v1v2c.pcap"), []SnmpUser{
		{User: "u1", Auth: "SHA1", AuthPass: "authpass1", Priv: "AES", PrivPass: "privpass1"},
	}, "", nil)
	if err != nil {
		t.Fatalf("ExtractSNMP: %v", err)
	}
	if len(rows) != 5 || len(communities) != 2 || len(warnings) != 0 {
		t.Fatalf("unexpected ExtractSNMP results: rows=%d comms=%v warn=%v", len(rows), communities, warnings)
	}
}
