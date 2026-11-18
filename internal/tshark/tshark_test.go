package tshark

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
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

func TestStreamEKFieldsAndDecodeEdgeCases(t *testing.T) {
	ctx := context.Background()
	sipFix, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "sip_minimal.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sipFix); err != nil {
		t.Fatalf("stat sip fixture: %v", err)
	}

	if _, err := StreamEKFields(ctx, CustomStreamOptions{}, nil); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := StreamEKFields(ctx, CustomStreamOptions{FilePath: "/nonexistent/nope.pcap", Fields: []string{"frame.number"}}, nil); err == nil {
		t.Fatal("expected error for missing path")
	}
	dir := t.TempDir()
	if _, err := StreamEKFields(ctx, CustomStreamOptions{FilePath: dir, Fields: []string{"frame.number"}}, nil); err == nil {
		t.Fatal("expected error for directory")
	}
	if _, err := StreamEKFields(ctx, CustomStreamOptions{FilePath: sipFix}, nil); err == nil {
		t.Fatal("expected error for empty fields")
	}
	if _, err := StreamEKFields(ctx, CustomStreamOptions{Binary: "missing-tshark", FilePath: sipFix, Fields: []string{"frame.number"}}, nil); err == nil {
		t.Fatal("expected error for missing binary")
	}

	max2 := 2
	seen := 0
	var attrs []string
	_, err = StreamEKFields(ctx, CustomStreamOptions{
		FilePath:      sipFix,
		DisplayFilter: "sip",
		MaxPackets:    &max2,
		Fields:        []string{"frame.number", "sip.Method", "sdp.media_attr"},
		DecodeAs:      []string{"udp.port==5060,sip", ""},
	}, func(r Row) error {
		seen++
		attrs = append(attrs, r.All("sdp.media_attr")...)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamEKFields failed: %v", err)
	}
	if seen != 2 || len(attrs) == 0 {
		t.Fatalf("unexpected ek stream: seen=%d attrs=%v", seen, attrs)
	}

	stopErr := errors.New("abort ek")
	if _, err := StreamEKFields(ctx, CustomStreamOptions{FilePath: sipFix, Fields: []string{"frame.number"}}, func(Row) error { return stopErr }); !errors.Is(err, stopErr) {
		t.Fatalf("expected abort error, got %v", err)
	}

	badPcap := filepath.Join(dir, "bad.pcap")
	if err := os.WriteFile(badPcap, []byte("not a pcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StreamEKFields(ctx, CustomStreamOptions{FilePath: badPcap, Fields: []string{"frame.number"}}, func(Row) error { return nil }); err == nil {
		t.Fatal("expected error on bad pcap")
	}

	decoded := decodeEKLayers(map[string]json.RawMessage{
		"frame_number": []byte(`["1"]`),
		"flag_true":    []byte(`true`),
		"flag_false":   []byte(`false`),
		"count":        []byte(`42`),
		"scalar_str":   []byte(`"hello"`),
		"empty":        []byte(`null`),
		"blank":        []byte(`   `),
		"obj_skip":     []byte(`{"x":1}`),
		"bad_arr":      []byte(`[invalid`),
		"arr_mix":      []byte(`["a", true, 5, {}]`),
	}, map[string]string{"frame_number": "frame.number"})
	if decoded["frame.number"][0] != "1" || decoded["flag_true"][0] != "1" || decoded["flag_false"][0] != "0" || decoded["count"][0] != "42" || decoded["scalar_str"][0] != "hello" || len(decoded["arr_mix"]) != 3 {
		t.Fatalf("unexpected decodeEKLayers: %+v", decoded)
	}
	if EKFieldKey("sip.Call-ID") != "sip_Call-ID" {
		t.Fatalf("EKFieldKey unexpected: %s", EKFieldKey("sip.Call-ID"))
	}
}

func FuzzParseEKLine(f *testing.F) {
	ekToField := map[string]string{
		"frame_number":   "frame.number",
		"sip_Call-ID":    "sip.Call-ID",
		"sdp_media_attr": "sdp.media_attr",
	}
	for _, seed := range []string{
		`{"timestamp":"1700000000","layers":{"frame_number":["1"],"sip_Call-ID":"abc@1.2.3.4","sdp_media_attr":["rtpmap:101 telephone-event/8000","crypto:1 AES_CM_128_HMAC_SHA1_80 inline:topsecret"]}}`,
		`{"layers":{"flag":true,"count":42,"nullf":null}}`,
		`{"index":{"_index":"packets"}}`,
		`{invalid`,
		``,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseEKLine(line, ekToField)
	})
}

// TestPrepareCapturePathStagesWhenTsharkConfinedToTemp verifies that captures
// outside os.TempDir are transparently staged to os.TempDir and cleaned up
// when tshark fails with a permission-denied error on workspace paths.
func TestPrepareCapturePathStagesWhenTsharkConfinedToTemp(t *testing.T) {
	realTshark, err := exec.LookPath(Binary())
	if err != nil {
		t.Fatalf("locate %s: %v", Binary(), err)
	}
	tmpRoot, err := filepath.Abs(os.TempDir())
	if err != nil {
		t.Fatalf("abs TempDir: %v", err)
	}
	tmpRoot = strings.TrimRight(tmpRoot, string(filepath.Separator))

	fakeBinDir := t.TempDir()
	traceFile := filepath.Join(t.TempDir(), "staged-paths.log")
	wrapper := "#!/bin/sh\n" +
		"prev=\"\"\n" +
		"rpath=\"\"\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = \"-r\" ]; then\n" +
		"    rpath=\"$arg\"\n" +
		"    break\n" +
		"  fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"if [ -n \"$rpath\" ]; then\n" +
		"  case \"$rpath\" in\n" +
		"    '" + tmpRoot + "'/*)\n" +
		"      printf '%s\\n' \"$rpath\" >> '" + traceFile + "'\n" +
		"      ;;\n" +
		"    *)\n" +
		"      printf 'tshark: You don'\\''t have permission to read the file \"%s\".\\n' \"$rpath\" >&2\n" +
		"      exit 3\n" +
		"      ;;\n" +
		"  esac\n" +
		"fi\n" +
		"exec '" + realTshark + "' \"$@\"\n"

	fakeTshark := filepath.Join(fakeBinDir, Binary())
	if err := os.WriteFile(fakeTshark, []byte(wrapper), 0o755); err != nil {
		t.Fatalf("write fake tshark: %v", err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+origPath)

	sipFix := filepath.Join("..", "..", "testdata", "fixtures", "sip_minimal.pcap")
	ctx := context.Background()

	fieldRows := 0
	if _, err := StreamFields(ctx, StreamOptions{FilePath: sipFix}, func(Row) error {
		fieldRows++
		return nil
	}); err != nil {
		t.Fatalf("StreamFields with confined tshark failed: %v", err)
	}
	if fieldRows == 0 {
		t.Fatal("StreamFields produced 0 rows through staged capture")
	}

	ekRows := 0
	if _, err := StreamEKFields(ctx, CustomStreamOptions{
		FilePath: sipFix,
		Fields:   []string{"frame.number"},
	}, func(Row) error {
		ekRows++
		return nil
	}); err != nil {
		t.Fatalf("StreamEKFields with confined tshark failed: %v", err)
	}
	if ekRows == 0 {
		t.Fatal("StreamEKFields produced 0 rows through staged capture")
	}

	traceBytes, err := os.ReadFile(traceFile)
	if err != nil {
		t.Fatalf("read trace log: %v", err)
	}
	lines := strings.Fields(strings.TrimSpace(string(traceBytes)))
	if len(lines) < 2 {
		t.Fatalf("expected >= 2 staged invocations, got %d (%q)", len(lines), string(traceBytes))
	}
	for _, p := range lines {
		if !strings.HasPrefix(p, tmpRoot+string(filepath.Separator)) {
			t.Fatalf("staged path %q not inside %s", p, tmpRoot)
		}
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Fatalf("staged capture %q was not cleaned up (stat err=%v)", p, statErr)
		}
	}

	// Cover edge inputs: blank, missing, directory, already under os.TempDir, and missing PATH binary.
	p, clean := PrepareCapturePath("   ")
	clean()
	if p != "   " {
		t.Fatalf("unexpected PrepareCapturePath for blank: %q", p)
	}
	p, clean = PrepareCapturePath("/nonexistent/nope.pcap")
	clean()
	if p != "/nonexistent/nope.pcap" {
		t.Fatalf("unexpected PrepareCapturePath for missing file: %q", p)
	}
	tmpDir := t.TempDir()
	p, clean = PrepareCapturePath(tmpDir)
	clean()
	if p != tmpDir {
		t.Fatalf("unexpected PrepareCapturePath for dir: %q", p)
	}
	inTmp := filepath.Join(tmpDir, "local.pcap")
	if err := os.WriteFile(inTmp, []byte("pcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, clean = PrepareCapturePath(inTmp)
	clean()
	if p != inTmp {
		t.Fatalf("expected tmp file %q to pass through unchanged, got %q", inTmp, p)
	}

	t.Setenv("PATH", t.TempDir())
	p, clean = PrepareCapturePath(sipFix)
	clean()
	if p != sipFix {
		t.Fatalf("expected original path %q when tshark absent from PATH, got %q", sipFix, p)
	}
}
