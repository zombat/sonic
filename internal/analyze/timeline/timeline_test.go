package timeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/parity"
)

func strPtr(s string) *string  { return &s }
func f64Ptr(f float64) *float6 { return &f }

type float6 = float64

func TestGoldenTimelineParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	captures := []CaptureInput{
		{Path: filepath.Join("tests", "fixtures", "ospf_failover.pcap"), Label: "core"},
		{Path: filepath.Join("tests", "fixtures", "icmp_loss.pcap"), Label: "lan"},
	}

	t.Run("ospf_icmp_auto", func(t *testing.T) {
		got := MergeTimelines(ctx, captures, Options{})
		parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "timeline", "ospf_icmp_auto.json"))
	})

	t.Run("ospf_icmp_measured", func(t *testing.T) {
		got := MergeTimelines(ctx, captures, Options{
			Measurements: []MeasurementSpec{{
				Name: "ospf failover",
				From: &Selector{Capture: strPtr("core"), Event: strPtr("neighbor_down")},
				To:   &Selector{Event: strPtr("neighbor_up"), Contains: strPtr("3.3.3.3")},
				MaxS: f64Ptr(15),
			}},
		})
		parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "timeline", "ospf_icmp_measured.json"))
	})

	t.Run("ospf_icmp_threshold5", func(t *testing.T) {
		got := MergeTimelines(ctx, captures, Options{FailoverMaxS: f64Ptr(5)})
		parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "timeline", "ospf_icmp_threshold5.json"))
	})
}

func TestTimelineOptionsSelectorsAndErrors(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	captures := []CaptureInput{
		{Path: filepath.Join("tests", "fixtures", "ospf_failover.pcap"), Label: "core"},
		{Path: filepath.Join("tests", "fixtures", "icmp_loss.pcap"), Label: "lan"},
	}

	assertErr := func(r Report, substr string) {
		t.Helper()
		if r.Status != "error" || !strings.Contains(r.Error, substr) {
			t.Fatalf("expected error containing %q, got status=%q err=%q", substr, r.Status, r.Error)
		}
		raw, err := json.Marshal(r)
		if err != nil || !strings.Contains(string(raw), `"status":"error"`) || strings.Contains(string(raw), `"schema"`) {
			t.Fatalf("unexpected error marshal: %s err=%v", raw, err)
		}
	}

	assertErr(MergeTimelines(ctx, nil, Options{}), "one or more entries")
	assertErr(MergeTimelines(ctx, []CaptureInput{{Path: ""}}, Options{}), "needs a")
	assertErr(MergeTimelines(ctx, []CaptureInput{captures[0], {Path: captures[1].Path, Label: "core"}}, Options{}), "duplicate capture label")
	assertErr(MergeTimelines(ctx, captures, Options{ClockOffsetsS: map[string]float64{"zz": 1}}), "unknown label")
	assertErr(MergeTimelines(ctx, captures, Options{Measurements: []MeasurementSpec{{Name: "bad"}}}), `needs "from" and "to"`)
	assertErr(MergeTimelines(ctx, captures, Options{Measurements: []MeasurementSpec{{
		Name: "unk",
		From: &Selector{UnknownKeys: []string{"evnt"}},
		To:   &Selector{},
	}}}), "unknown selector key")
	assertErr(MergeTimelines(ctx, captures, Options{Measurements: []MeasurementSpec{{
		Name: "cap",
		From: &Selector{Capture: strPtr("nope")},
		To:   &Selector{},
	}}}), "unknown capture")
	assertErr(MergeTimelines(ctx, []CaptureInput{captures[0], {Path: filepath.Join("tests", "fixtures", "missing.pcap"), Label: "bad"}}, Options{}), "bad:")

	// JSON unmarshaling of Selector (string/int occurrence, unknown keys).
	var sel Selector
	if err := json.Unmarshal([]byte(`{"capture":"core","detector":"routing","protocol":"ospf","event":"neighbor_up","contains":"3.3.3.3","occurrence":2,"extra":true}`), &sel); err != nil {
		t.Fatal(err)
	}
	if sel.Occurrence != "2" || len(sel.UnknownKeys) != 1 || sel.UnknownKeys[0] != "extra" {
		t.Fatalf("unexpected selector unmarshal: %+v", sel)
	}

	// below_min, exceeded, not_found, last, numeric occurrence, and output file write/overwrite behavior.
	specExceeded := MeasurementSpec{
		Name: "fast",
		From: &Selector{Capture: strPtr("core"), Event: strPtr("neighbor_down"), Occurrence: "1"},
		To:   &Selector{Event: strPtr("neighbor_up"), Occurrence: "last"},
		MaxS: f64Ptr(5),
	}
	specBelowMin := MeasurementSpec{
		Name: "slow",
		From: &Selector{Capture: strPtr("core"), Event: strPtr("neighbor_down")},
		To:   &Selector{Event: strPtr("neighbor_up")},
		MinS: f64Ptr(30),
	}
	specMissing := MeasurementSpec{
		Name: "missing",
		From: &Selector{Event: strPtr("established")},
		To:   &Selector{Event: strPtr("established")},
	}
	specBadOcc := MeasurementSpec{
		Name: "oob",
		From: &Selector{Event: strPtr("neighbor_down"), Occurrence: "99"},
		To:   &Selector{Event: strPtr("neighbor_up")},
	}
	res := MergeTimelines(ctx, captures, Options{Measurements: []MeasurementSpec{specExceeded, specBelowMin, specMissing, specBadOcc}})
	if res.Status != "success" || res.Measurements[0].Verdict != "exceeded" || res.Measurements[1].Verdict != "below_min" || res.Measurements[2].Verdict != "not_found" || res.Measurements[3].Verdict != "not_found" {
		t.Fatalf("unexpected measurement verdicts: %+v", res.Measurements)
	}

	outDir := t.TempDir()
	outJSON := filepath.Join(outDir, "timing.json")
	writtenRep := MergeTimelines(ctx, captures, Options{OutputPath: outJSON})
	if writtenRep.Status != "success" || writtenRep.WrittenTo != outJSON {
		t.Fatalf("expected written_to=%q, got %+v", outJSON, writtenRep)
	}
	rawFile, err := os.ReadFile(outJSON)
	if err != nil || !strings.Contains(string(rawFile), ReportSchema) {
		t.Fatalf("written JSON file missing schema: err=%v", err)
	}
	assertErr(MergeTimelines(ctx, captures, Options{OutputPath: outJSON}), "output_path exists")
	overwritten := MergeTimelines(ctx, captures, Options{OutputPath: outJSON, Overwrite: true})
	if overwritten.Status != "success" {
		t.Fatalf("overwrite=true failed: %+v", overwritten)
	}
	assertErr(MergeTimelines(ctx, captures, Options{OutputPath: filepath.Join(outDir, "bad.txt")}), "must end in .json")
	assertErr(MergeTimelines(ctx, captures, Options{OutputPath: filepath.Join(outDir, "no_such_dir", "x.json")}), "directory does not exist")
}
