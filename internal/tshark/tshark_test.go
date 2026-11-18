package tshark

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRowAndScalars(t *testing.T) {
	t.Parallel()

	row := NewRow(map[string][]string{
		"hex":   {"0xdeadbeef"},
		"bools": {"True", "false"},
		"float": {"12.75"},
		"bad":   {"nope"},
		"bytes": {"AA:BB:CC"},
	})
	if v, ok := row.First("hex"); !ok || v != "0xdeadbeef" {
		t.Fatalf("First(hex) = (%q, %v)", v, ok)
	}
	if row.FirstPtr("missing") != nil || row.FirstPtr("hex") == nil {
		t.Fatal("FirstPtr behavior unexpected")
	}
	if !row.Has("hex") || row.Has("missing") {
		t.Fatal("Has behavior unexpected")
	}
	if v := row.Uint32("hex"); v == nil || *v != 0xdeadbeef {
		t.Fatalf("Uint32(hex) = %v, want 0xdeadbeef", v)
	}
	if v := row.Int("bools", 0); v == nil || *v != 1 {
		t.Fatalf("Int(bools, 0) = %v, want 1", v)
	}
	if v := row.Int("bools", 1); v == nil || *v != 0 {
		t.Fatalf("Int(bools, 1) = %v, want 0", v)
	}
	if v := row.Int("float"); v == nil || *v != 12 {
		t.Fatalf("Int(float) = %v, want 12", v)
	}
	if f, ok := row.Float64("float"); !ok || f != 12.75 {
		t.Fatalf("Float64(float) = (%v, %v)", f, ok)
	}
	if _, ok := row.Float64("bad"); ok {
		t.Fatal("Float64(bad) should be false")
	}
	if ints := row.Ints("bools"); len(ints) != 2 || ints[0] != 1 || ints[1] != 0 {
		t.Fatalf("Ints(bools) = %v", ints)
	}
	if row.Int("bad") != nil || row.Int("bools", 5) != nil {
		t.Fatal("expected nil for bad/out-of-range Int")
	}
	if hx, ok := HexBytes("AA:BB:CC"); !ok || hx != "aabbcc" {
		t.Fatalf("HexBytes = (%q, %v)", hx, ok)
	}
	if _, ok := HexBytes(""); ok {
		t.Fatal("HexBytes empty should be false")
	}
}

func TestSafePathAndFragOffset(t *testing.T) {
	t.Parallel()

	if SafeCapturePath("-bad.pcap") != "./-bad.pcap" {
		t.Fatalf("SafeCapturePath(-bad) = %q", SafeCapturePath("-bad.pcap"))
	}
	if SafeCapturePath("ok.pcap") != "ok.pcap" {
		t.Fatalf("SafeCapturePath(ok) = %q", SafeCapturePath("ok.pcap"))
	}
	if FragOffsetBytes(185, 4) != 1480 || FragOffsetBytes(1480, 3) != 1480 {
		t.Fatal("FragOffsetBytes mismatch")
	}
	if len(AllFields()) != len(NetworkFields)+len(DataplaneFields) {
		t.Fatal("AllFields length mismatch")
	}
}

func TestRealTsharkStreamAndErrorPaths(t *testing.T) {
	ctx := context.Background()
	resolved := ResolveFields(ctx, DefaultBinary)
	if len(resolved) == 0 {
		t.Fatal("ResolveFields returned empty map")
	}
	if maj := VersionMajor(ctx, DefaultBinary); maj < 3 {
		t.Fatalf("VersionMajor = %d, want >= 3", maj)
	}
	if !Available(DefaultBinary) || !Available("") || Available("definitely-missing-tshark-bin") {
		t.Fatal("Available check failed")
	}
	v1 := VersionString(ctx, "")
	v2 := VersionString(ctx, DefaultBinary)
	if v1 == nil || v2 == nil || *v1 != *v2 || !strings.Contains(*v1, "TShark") {
		t.Fatalf("VersionString unexpected: %v, %v", v1, v2)
	}
	if got := VersionString(ctx, "definitely-missing-tshark-bin"); got != nil {
		t.Fatalf("VersionString(missing) = %v, want nil", got)
	}

	// Bad capture path checks.
	if _, err := StreamFields(ctx, StreamOptions{}, nil); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := StreamFields(ctx, StreamOptions{FilePath: "/nonexistent/nope.pcap"}, nil); err == nil {
		t.Fatal("expected error for missing file")
	}
	dir := t.TempDir()
	if _, err := StreamFields(ctx, StreamOptions{FilePath: dir}, nil); err == nil {
		t.Fatal("expected error for directory path")
	}
	if got := VersionMajor(ctx, "definitely-missing-tshark-bin"); got != 0 {
		t.Fatalf("VersionMajor(missing) = %d, want 0", got)
	}

	fixture := filepath.Join("..", "..", "testdata", "fixtures", "audit_one_leak.pcap")
	if _, err := os.Stat(fixture); err != nil {
		t.Fatalf("fixture stat: %v", err)
	}

	// Verify streaming all packets, display filter, max packets, and early abort.
	max3 := 3
	count := 0
	res, err := StreamFields(ctx, StreamOptions{
		FilePath:      fixture,
		MaxPackets:    &max3,
		DisplayFilter: "ip",
	}, func(r Row) error {
		count++
		if r.Int("frame.number") == nil {
			t.Fatal("missing frame.number")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamFields failed: %v (stderr: %s)", err, res.Stderr)
	}
	if count != 3 {
		t.Fatalf("streamed %d filtered packets, want 3", count)
	}

	// Verify early abort from callback terminates tshark cleanly.
	stopErr := errors.New("stop early")
	abortCount := 0
	_, err = StreamFields(ctx, StreamOptions{FilePath: fixture}, func(Row) error {
		abortCount++
		return stopErr
	})
	if !errors.Is(err, stopErr) || abortCount != 1 {
		t.Fatalf("early abort = (%v, count=%d), want (stopErr, 1)", err, abortCount)
	}

	// Verify invalid pcap yields tshark failure when 0 rows produced.
	badPcap := filepath.Join(dir, "-corrupt.pcap")
	if err := os.WriteFile(badPcap, []byte("not a pcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if _, err := StreamFields(ctx, StreamOptions{FilePath: "-corrupt.pcap"}, func(Row) error { return nil }); err == nil {
		t.Fatal("expected error for corrupt -corrupt.pcap")
	} else if !strings.Contains(err.Error(), "tshark failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
