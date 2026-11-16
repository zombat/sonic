package espoverhead

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenESPOverheadParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	intp := func(v int) *int { return &v }
	cases := []struct {
		name   string
		pcap   string
		golden string
		opts   Options
	}{
		{"dp_esp_sizes", "dp_esp_sizes", "dp_esp_sizes", Options{}},
		{"dp_esp_sizes_mtu1400", "dp_esp_sizes", "dp_esp_sizes_mtu1400", Options{TunnelMTU: intp(1400)}},
		{"dp_esp_sizes_mtu1476", "dp_esp_sizes", "dp_esp_sizes_mtu1476", Options{TunnelMTU: intp(1476)}},
		{"ipsec_ikev2_esp", "ipsec_ikev2_esp", "ipsec_ikev2_esp", Options{}},
		{"dp_fragments", "dp_fragments", "dp_fragments", Options{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", tc.pcap+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewDetector(tc.opts)
			var startPtr, endPtr *float64
			for i := range out.Records {
				rec := &out.Records[i]
				if rec.T != 0 {
					tv := rec.T
					if startPtr == nil || tv < *startPtr {
						v := tv
						startPtr = &v
					}
					if endPtr == nil || tv > *endPtr {
						v := tv
						endPtr = &v
					}
				}
				det.Feed(rec)
			}
			got := det.Report(model.Context{Start: startPtr, End: endPtr, MaxItems: 25})
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "esp_overhead", tc.golden+".json"))
		})
	}
}

func TestESPOverheadUnitsAndUnexplainedSizes(t *testing.T) {
	t.Parallel()

	if empty := NewDetector(Options{}).Report(model.Context{MaxItems: 25}); empty.Status != model.StatusNotPresent {
		t.Fatalf("empty status = %v, want not_present", empty.Status)
	}

	if fams := FamiliesFor([]int{76, 96, 108, 136}); len(fams) == 0 || fams[0].Family[:7] != "AES-GCM" {
		t.Fatalf("unexpected FamiliesFor result: %+v", fams)
	}
	if BestFamily(nil) != nil || len(FamiliesFor(nil)) != 7 {
		t.Fatal("empty sizes/families mismatch")
	}

	// Unexplained payload size (too small for any known family -> ESP_SIZES_UNEXPLAINED) + medium pooled match + IPv6 outer.
	greBytes := 4
	det := NewDetector(Options{GREHeaderBytes: &greBytes})
	proto50 := 50
	id1 := 1
	df1 := 1
	det.Feed(&model.Record{
		N: 1, T: 1.0, Len: 40,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: &proto50},
		ESP: &model.ESPHeader{SPI: 0x01020304, Seq: 1},
		DP:  &model.DataPlane{HL: 20, TL: 35, DF: &df1},
	})
	det.Feed(&model.Record{
		N: 2, T: 1.1, Len: 120,
		IP:  &model.IPHeader{V: 6, Src: "2001:db8::1", Dst: "2001:db8::2", Proto: &proto50},
		ESP: &model.ESPHeader{SPI: 0x0a0b0c0d, Seq: 1},
		DP:  &model.DataPlane{HL: 40, TL: 140, ID: &id1},
	})

	start, end := 1.0, 1.1
	rep := det.Report(model.Context{Start: &start, End: &end, MaxItems: 25})
	if rep.Flows[0].Confidence != "none" || rep.Issues[0].Code != "ESP_SIZES_UNEXPLAINED" {
		t.Fatalf("expected unexplained flow issue, got flow=%+v issues=%+v", rep.Flows, rep.Issues)
	}
}
