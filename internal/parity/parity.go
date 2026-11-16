// Package parity provides JSON comparison helpers for verifying Go outputs
// against the Python golden baseline in testdata/golden/.
package parity

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"testing"
)

const floatTolerance = 1e-6

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
	return compareValues("$", gotVal, wantVal)
}

// CompareGolden marshals got to JSON, reads the golden file at goldenPath, and
// fails the test if their decoded JSON structures differ beyond floatTolerance.
func CompareGolden(t *testing.T, got any, goldenPath string) {
	t.Helper()
	gotBytes, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got value: %v", err)
	}
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file %s: %v", goldenPath, err)
	}
	if err := CompareJSON(gotBytes, wantBytes); err != nil {
		t.Fatalf("golden parity mismatch for %s: %v", goldenPath, err)
	}
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
