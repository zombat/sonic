package parity

import (
	"encoding/json"
	"testing"
)

// comparedMissing normalizes a got output listing missing, against a golden
// listing none, the way CompareJSON does, and returns the comparison error.
func comparedMissing(t *testing.T, missing []string, tshark4Run bool) error {
	t.Helper()
	raw := `{"capture":{"tshark":"TShark (Wireshark) 4.6.4.","missing_tshark_fields":[]}}`
	var got, want map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &want); err != nil {
		t.Fatal(err)
	}
	list := make([]any, 0, len(missing))
	for _, m := range missing {
		list = append(list, m)
	}
	got["capture"].(map[string]any)["missing_tshark_fields"] = list
	normalizeInstalledTool(got, tshark4Run)
	normalizeInstalledTool(want, false)
	return compareValues("$", got, want)
}

// TestParity_AMissingFieldStillFails proves the comparison still catches a
// field the build failed to decode, on a tshark 4 run as on a tshark 3 run.
// Only the known tshark 4 gap is forgiven.
func TestParity_AMissingFieldStillFails(t *testing.T) {
	if err := comparedMissing(t, []string{"udp.port"}, true); err == nil {
		t.Error("an unexpected missing field on tshark 4 passed the comparison")
	}
	if err := comparedMissing(t, []string{"udp.port"}, false); err == nil {
		t.Error("an unexpected missing field on tshark 3 passed the comparison")
	}
}

// TestParity_TheKnownTShark4GapIsForgivenOnlyOnTShark4 proves the BGP
// capability sub-code that tshark 4 dropped is forgiven on a tshark 4 run, and
// is still a difference on a tshark 3 run, where the field exists.
func TestParity_TheKnownTShark4GapIsForgivenOnlyOnTShark4(t *testing.T) {
	if err := comparedMissing(t, []string{"bgp.minor_capability"}, true); err != nil {
		t.Errorf("the known tshark 4 gap was not forgiven on a tshark 4 run: %v", err)
	}
	if err := comparedMissing(t, []string{"bgp.minor_capability"}, false); err == nil {
		t.Error("the known tshark 4 gap was forgiven on a tshark 3 run")
	}
}
