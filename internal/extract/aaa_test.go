package extract

import (
	"context"
	"path/filepath"
	"testing"
)

func TestExtractAAAFixtures(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	rSec := "radius-shared-secret-not-real"
	tKey := "tacacs-shared-key-not-real"

	radRows, _, radSecrets, err := ExtractAAA(context.Background(), filepath.Join("tests", "fixtures", "aaa_radius.pcap"), &tKey, &rSec, "", nil)
	if err != nil {
		t.Fatalf("ExtractAAA(radius): %v", err)
	}
	if len(radRows) == 0 || !radSecrets["user-password-not-real"] {
		t.Fatalf("unexpected RADIUS extract: rows=%d secrets=%v", len(radRows), radSecrets)
	}

	_, tacRows, tacSecrets, err := ExtractAAA(context.Background(), filepath.Join("tests", "fixtures", "aaa_tacacs.pcap"), &tKey, &rSec, "tcp.port==49", nil)
	if err != nil {
		t.Fatalf("ExtractAAA(tacacs): %v", err)
	}
	if len(tacRows) == 0 || !tacSecrets["enable-password-not-real"] {
		t.Fatalf("unexpected TACACS extract: rows=%d secrets=%v", len(tacRows), tacSecrets)
	}
}
