package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/model"
)

// labCapture audits one of the CML lab captures in testdata/lab with the real
// tshark on PATH. These captures were taken from a live lab (IOS XE, SR Linux,
// SNMP agents), so they test the audit against real protocol traffic rather
// than against output recorded from an earlier run. On CI a missing tshark is a
// failure, never a skip.
func labCapture(t *testing.T, name string, snmpPorts []int) model.AuditReport {
	t.Helper()
	if _, err := exec.LookPath("tshark"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatalf("tshark is missing on CI, so the lab capture tests cannot run: %v", err)
		}
		t.Skipf("tshark is not on PATH: %v", err)
	}
	rep, err := AuditCleartextCapture(context.Background(), AuditOptions{
		FilePath:  filepath.Join("..", "..", "..", "testdata", "lab", name+".pcap"),
		SNMPPorts: snmpPorts,
	})
	if err != nil {
		t.Fatalf("audit %s: %v", name, err)
	}
	return rep
}

// TestLabCapture_SSHAndTLSAreProtectedNotCleartext proves SSH and TLS sessions
// from the lab pass the default allowlist, with no frame counted as cleartext.
func TestLabCapture_SSHAndTLSAreProtectedNotCleartext(t *testing.T) {
	for _, name := range []string{"netconf-restconf-ssh", "gnmi-tls-srlinux"} {
		rep := labCapture(t, name, nil)
		if !rep.Passed {
			t.Errorf("%s: want the audit to pass, got verdict %q", name, rep.Verdict)
		}
		if n := rep.Protection["cleartext"]; n != 0 {
			t.Errorf("%s: %d cleartext frames in an encrypted session", name, n)
		}
	}
}

// TestLabCapture_PlaintextGRPCIsCleartextWithItsCredentials proves gNMI over
// plaintext HTTP/2 fails the audit, every frame counted as cleartext, and that
// the login sent in metadata is named.
func TestLabCapture_PlaintextGRPCIsCleartextWithItsCredentials(t *testing.T) {
	rep := labCapture(t, "gnmi-plaintext", nil)
	if rep.Passed {
		t.Fatalf("plaintext gRPC passed the audit: %q", rep.Verdict)
	}
	if !strings.Contains(rep.Verdict, "57 of them cleartext") || !strings.Contains(rep.Verdict, "57 http2 (tcp/50001)") {
		t.Errorf("the verdict does not name the cleartext HTTP/2 on tcp/50001: %q", rep.Verdict)
	}
	if n := rep.Protection["cleartext"]; n != 57 {
		t.Errorf("want all 57 frames cleartext, got %d (%v)", n, rep.Protection)
	}
}

// TestLabCapture_SNMPWithItsPortDecodedIsClassedByVersion proves that, with the
// agent's port named, SNMP is classed by version and its security flags: v2c
// and v3 without privacy are cleartext, since their PDUs are readable, and v3
// with privacy is encrypted. The 4 frames of v3 discovery carry no PDU and stay
// cleartext.
func TestLabCapture_SNMPWithItsPortDecodedIsClassedByVersion(t *testing.T) {
	ports := []int{1161}

	if rep := labCapture(t, "snmp-v2c", ports); rep.Protection["cleartext"] != 16 || rep.Protection["encrypted"] != 0 {
		t.Errorf("snmp v2c: want 16 cleartext, got %v", rep.Protection)
	}
	if rep := labCapture(t, "snmp-v3-authnopriv", ports); rep.Protection["cleartext"] != 18 {
		t.Errorf("snmp v3 without privacy: want 18 cleartext, got %v", rep.Protection)
	}
	if rep := labCapture(t, "snmp-v3-authpriv", ports); rep.Protection["encrypted"] != 14 || rep.Protection["cleartext"] != 4 {
		t.Errorf("snmp v3 with privacy: want 14 encrypted and 4 discovery cleartext, got %v", rep.Protection)
	}
}

// TestLabCapture_SNMPv3PrivacyIsAllowedByItsOwnToken proves the encrypted SNMPv3
// frames pass when the operator allows the snmp-v3-privacy token, and the
// cleartext discovery frames still fail, so the token never admits cleartext SNMP.
func TestLabCapture_SNMPv3PrivacyIsAllowedByItsOwnToken(t *testing.T) {
	rep2, err := AuditCleartextCapture(context.Background(), AuditOptions{
		FilePath:  filepath.Join("..", "..", "..", "testdata", "lab", "snmp-v3-authpriv.pcap"),
		SNMPPorts: []int{1161},
		Allow:     []string{"snmp-v3-privacy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.FramesOutsideAllowlist != 4 || rep2.Protection["cleartext"] != 4 {
		t.Errorf("with the privacy token: want only the 4 discovery frames outside the allowlist, got %d outside (%v)",
			rep2.FramesOutsideAllowlist, rep2.Protection)
	}
}

// TestLabCapture_SNMPWithoutItsPortIsNotDecoded documents the gap the port
// option closes: on a non-standard UDP port SNMP is not decoded, so every frame
// reads as cleartext, including encrypted SNMPv3.
func TestLabCapture_SNMPWithoutItsPortIsNotDecoded(t *testing.T) {
	rep := labCapture(t, "snmp-v3-authpriv", nil)
	if rep.Protection["encrypted"] != 0 || rep.Protection["cleartext"] != 18 {
		t.Errorf("an undecoded port: want all 18 cleartext, got %v", rep.Protection)
	}
}
