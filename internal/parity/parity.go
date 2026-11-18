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
	"path/filepath"
	"sort"
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
	dropInstalledTool(gotVal)
	dropInstalledTool(wantVal)
	return compareValues("$", gotVal, wantVal)
}

// dropInstalledTool removes what describes the installed tshark, not the
// analysis: its version string, and the fields that build did not decode.
// Goldens were made with tshark 3.6.2 and CI runs 4.6.4, which renamed a BGP
// field, so comparing these would fail on the tool's version rather than on a
// change to the analysis. The analysis itself is still compared in full.
func dropInstalledTool(v any) {
	root, ok := v.(map[string]any)
	if !ok {
		return
	}
	// The record extractor reports the same thing at the top level.
	delete(root, "missing_fields")
	capture, ok := root["capture"].(map[string]any)
	if !ok {
		return
	}
	delete(capture, "tshark")
	delete(capture, "missing_tshark_fields")
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
