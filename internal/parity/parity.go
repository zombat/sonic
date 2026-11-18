// Package parity provides JSON comparison helpers for verifying Go outputs
// against the golden baseline in testdata/golden/.
package parity

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

const floatTolerance = 1e-6

var updateGolden = flag.Bool("update", false, "update golden JSON files instead of comparing")

// CompareJSON unmarshals gotBytes and wantBytes into generic JSON values and
// returns a descriptive error naming the first mismatched JSON path.
func CompareJSON(gotBytes, wantBytes []byte) error {
	var gotVal any
	if err := json.Unmarshal(gotBytes, &gotVal); err != nil {
		return fmt.Errorf("unmarshal got json: %w", err)
	}
	var wantVal any
	if err := json.Unmarshal(wantBytes, &wantVal); err != nil {
		return fmt.Errorf("unmarshal want json: %w", err)
	}
	normalizeInstalledTool(gotVal, onTShark4())
	normalizeInstalledTool(wantVal, false)
	return compareValues("$", gotVal, wantVal)
}

// knownAbsentOn4 names the fields tshark 4 no longer decodes, which a golden
// made on tshark 3 lists as present. Only these are forgiven, and only when the
// tshark that produced the output is 4.x. Any other field a build fails to
// decode still fails the comparison.
var knownAbsentOn4 = map[string]bool{
	"bgp.minor_capability": true,
}

var (
	tshark4Once sync.Once
	tshark4     bool
)

// onTShark4 reports whether the tshark on PATH is 4.x, the version CI runs.
func onTShark4() bool {
	tshark4Once.Do(func() {
		out, err := exec.Command("tshark", "--version").Output()
		tshark4 = err == nil && strings.HasPrefix(string(out), "TShark (Wireshark) 4.")
	})
	return tshark4
}

// normalizeInstalledTool removes what describes the installed tshark, not the
// analysis: its version string. The fields it did not decode stay compared,
// except the known tshark 4 gaps on a tshark 4 run (knownAbsentOn4). Goldens
// were made with tshark 3.6.2 and CI runs 4.6.4, so the comparison is
// otherwise the same on both.
func normalizeInstalledTool(v any, tshark4Run bool) {
	root, ok := v.(map[string]any)
	if !ok {
		return
	}
	forgiveOn4(root, "missing_fields", tshark4Run)
	capture, ok := root["capture"].(map[string]any)
	if !ok {
		return
	}
	delete(capture, "tshark")
	forgiveOn4(capture, "missing_tshark_fields", tshark4Run)
}

// forgiveOn4 drops the knownAbsentOn4 names from m[key] on a tshark 4 run.
func forgiveOn4(m map[string]any, key string, tshark4Run bool) {
	if !tshark4Run {
		return
	}
	list, ok := m[key].([]any)
	if !ok {
		return
	}
	kept := make([]any, 0, len(list))
	for _, f := range list {
		if s, ok := f.(string); ok && knownAbsentOn4[s] {
			continue
		}
		kept = append(kept, f)
	}
	m[key] = kept
}

// CompareGolden marshals got to JSON, reads the golden file at goldenPath, and
// fails the test if their decoded JSON structures differ beyond floatTolerance.
// When -update is passed to go test, goldenPath is overwritten cleanly instead.
func CompareGolden(t *testing.T, got any, goldenPath string) {
	t.Helper()
	gotBytes, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got value: %v", err)
	}
	CompareOrUpdateJSON(t, gotBytes, goldenPath)
}

// CompareOrUpdateJSON compares pre-serialized JSON bytes against goldenPath, or
// rewrites goldenPath cleanly when the -update flag is enabled.
func CompareOrUpdateJSON(t *testing.T, gotBytes []byte, goldenPath string) {
	t.Helper()
	if *updateGolden {
		if err := writeGolden(goldenPath, gotBytes); err != nil {
			t.Fatalf("update golden file %s: %v", goldenPath, err)
		}
		return
	}
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file %s: %v", goldenPath, err)
	}
	if err := CompareJSON(gotBytes, wantBytes); err != nil {
		t.Fatalf("golden parity mismatch for %s: %v", goldenPath, err)
	}
}

func writeGolden(goldenPath string, raw []byte) error {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("unmarshal generated json: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(decoded); err != nil {
		return fmt.Errorf("encode sorted golden json: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(goldenPath, buf.Bytes(), 0o644)
}

// compareValues recursively compares two unmarshaled JSON values at path.
func compareValues(path string, got, want any) error {
	if got == nil || want == nil {
		if got == nil && want == nil {
			return nil
		}
		return fmt.Errorf("%s: got %#v, want %#v", path, got, want)
	}

	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: got type %T, want object", path, got)
		}
		return compareMaps(path, g, w)
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Errorf("%s: got type %T, want array", path, got)
		}
		return compareSlices(path, g, w)
	case float64:
		g, ok := got.(float64)
		if !ok {
			return fmt.Errorf("%s: got type %T, want number", path, got)
		}
		if math.Abs(g-w) > floatTolerance {
			return fmt.Errorf("%s: got %v, want %v", path, g, w)
		}
		return nil
	case string:
		g, ok := got.(string)
		if !ok {
			return fmt.Errorf("%s: got type %T, want string", path, got)
		}
		if g != w {
			return fmt.Errorf("%s: got %q, want %q", path, g, w)
		}
		return nil
	case bool:
		g, ok := got.(bool)
		if !ok {
			return fmt.Errorf("%s: got type %T, want bool", path, got)
		}
		if g != w {
			return fmt.Errorf("%s: got %v, want %v", path, g, w)
		}
		return nil
	default:
		return fmt.Errorf("%s: unsupported golden type %T", path, want)
	}
}

// compareMaps compares two JSON objects by sorted key order so mismatches are deterministic.
func compareMaps(path string, got, want map[string]any) error {
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		gv, exists := got[k]
		if !exists {
			return fmt.Errorf("%s.%s: missing key in got (want %#v)", path, k, want[k])
		}
		if err := compareValues(path+"."+k, gv, want[k]); err != nil {
			return err
		}
	}

	extra := make([]string, 0)
	for k := range got {
		if _, exists := want[k]; !exists {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("%s.%s: unexpected extra key in got (%#v)", path, extra[0], got[extra[0]])
	}
	return nil
}

// compareSlices compares two JSON arrays element by element.
func compareSlices(path string, got, want []any) error {
	if len(got) != len(want) {
		return fmt.Errorf("%s: array length got %d, want %d", path, len(got), len(want))
	}
	for i := range want {
		elemPath := fmt.Sprintf("%s[%d]", path, i)
		if err := compareValues(elemPath, got[i], want[i]); err != nil {
			return err
		}
	}
	return nil
}
