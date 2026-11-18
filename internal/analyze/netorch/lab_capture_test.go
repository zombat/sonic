package netorch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLabCapture_PlaintextGRPCNamesItsLoginWithoutItsValue runs the network
// path over the lab's plaintext gNMI capture with real tshark, and proves the
// login sent in cleartext metadata is named as a finding, with its value masked.
// It is the path the CLI's --network-only mode takes. On CI a missing tshark is
// a failure, never a skip.
func TestLabCapture_PlaintextGRPCNamesItsLoginWithoutItsValue(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatalf("tshark is missing on CI, so the lab capture test cannot run: %v", err)
		}
		t.Skipf("tshark is not on PATH: %v", err)
	}
	path := filepath.Join("..", "..", "..", "testdata", "lab", "gnmi-plaintext.pcap")
	rep := AnalyzeNetworkCapture(context.Background(), path, Options{Detectors: []string{"cleartext_audit"}})
	if rep.Status != "success" {
		t.Fatalf("analysis failed: %s", rep.Error)
	}
	var named bool
	for _, issue := range rep.Issues {
		if issue.Code == "CLEARTEXT_CREDENTIAL" && containsAll(issue.Message, "username", "value masked") {
			named = true
		}
		if containsAll(issue.Message, "Gx-fixture") {
			t.Errorf("the password value leaked into a finding: %q", issue.Message)
		}
	}
	if !named {
		t.Errorf("no CLEARTEXT_CREDENTIAL finding names the username with its value masked; issues: %+v", rep.Issues)
	}
}

// containsAll reports whether s contains every part.
func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
