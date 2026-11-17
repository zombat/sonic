package convergence

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenConvergenceParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	floatp := func(v float64) *float64 { return &v }
	cases := []struct {
		name   string
		pcap   string
		golden string
		opts   Options
	}{
		{name: "convergence_dpd", pcap: "convergence_dpd", golden: "convergence_dpd"},
		{
			name:   "convergence_dpd_event30",
			pcap:   "convergence_dpd",
			golden: "convergence_dpd_event30",
			opts:   Options{EventTime: "+30.0", HoldTime: floatp(30.0)},
		},
		{name: "bgp_failover", pcap: "bgp_failover", golden: "bgp_failover"},
		{name: "ospf_failover", pcap: "ospf_failover", golden: "ospf_failover"},
		{name: "icmp_loss", pcap: "icmp_loss", golden: "icmp_loss"},
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
			got, err := det.Report(model.Context{Start: startPtr, End: endPtr, MaxItems: 25})
			if err != nil {
				t.Fatalf("Report: %v", err)
			}
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "convergence", tc.golden+".json"))
		})
	}
}

func TestParseEventTime(t *testing.T) {
	t.Parallel()
	start := 1767225600.0

	if v, err := ParseEventTime("", &start); err != nil || v != nil {
		t.Fatalf("empty: got (%v, %v), want (nil, nil)", v, err)
	}
	if v, err := ParseEventTime("+30.0", &start); err != nil || v == nil || *v != 1767225630.0 {
		t.Fatalf("+30.0: got (%v, %v)", v, err)
	}
	if v, err := ParseEventTime("15.5", &start); err != nil || v == nil || *v != 1767225615.5 {
		t.Fatalf("15.5: got (%v, %v)", v, err)
	}
	if v, err := ParseEventTime("1767225640", &start); err != nil || v == nil || *v != 1767225640.0 {
		t.Fatalf("epoch: got (%v, %v)", v, err)
	}
	if v, err := ParseEventTime("2026-01-01T00:00:30Z", &start); err != nil || v == nil || *v != 1767225630.0 {
		t.Fatalf("iso Z: got (%v, %v)", v, err)
	}
	if v, err := ParseEventTime("2026-01-01T01:00:30+01:00", &start); err != nil || v == nil || *v != 1767225630.0 {
		t.Fatalf("iso offset: got (%v, %v)", v, err)
	}
	if _, err := ParseEventTime("2026-01-01T00:00:30", &start); err == nil || !strings.Contains(err.Error(), "no time zone") {
		t.Fatalf("naive iso: expected timezone error, got %v", err)
	}
	if _, err := ParseEventTime("not-a-timestamp", &start); err == nil || !strings.Contains(err.Error(), "not epoch seconds") {
		t.Fatalf("bad input: expected parse error, got %v", err)
	}
}

func TestConvergenceSyntheticDriversAndBranches(t *testing.T) {
	t.Parallel()
	intp := func(v int) *int { return &v }
	floatp := func(v float64) *float64 { return &v }

	// Empty capture.
	empty, err := NewDetector(Options{}).Report(model.Context{MaxItems: 25})
	if err != nil || empty.Status != model.StatusNotPresent {
		t.Fatalf("empty capture: got (%+v, %v)", empty, err)
	}

	// BFD down driver + surviving BGP UPDATE + CONVERGENCE_NOT_SEEN when only outage starts without recovery.
	bfdDet := NewDetector(Options{SilenceS: floatp(2.0)})
	sp1, dp, sp2 := 40000, 179, 40001
	bfdDet.Feed(nil)
	// Establish session 10.0.0.1 <-> 10.0.0.2 and session 10.0.0.2 <-> 10.0.0.3.
	for _, pair := range []struct {
		a, b string
		sp   int
		n    int
		t    float64
	}{
		{"10.0.0.1", "10.0.0.2", sp1, 1, 100.0},
		{"10.0.0.2", "10.0.0.3", sp2, 10, 100.0},
	} {
		h := 30
		bfdDet.Feed(&model.Record{
			N: pair.n, T: pair.t,
			IP:  &model.IPHeader{V: 4, Src: pair.a, Dst: pair.b, Proto: intp(6)},
			TCP: &model.TCPHeader{Sport: &pair.sp, Dport: &dp, Flags: 0x02},
			BGP: []model.BGPMessage{{Type: 1, Hold: &h}},
		})
		bfdDet.Feed(&model.Record{
			N: pair.n + 1, T: pair.t + 0.1,
			IP:  &model.IPHeader{V: 4, Src: pair.b, Dst: pair.a, Proto: intp(6)},
			TCP: &model.TCPHeader{Sport: &dp, Dport: &pair.sp, Flags: 0x12},
			BGP: []model.BGPMessage{{Type: 1, Hold: &h}},
		})
		bfdDet.Feed(&model.Record{
			N: pair.n + 2, T: pair.t + 0.2,
			IP:  &model.IPHeader{V: 4, Src: pair.a, Dst: pair.b, Proto: intp(6)},
			TCP: &model.TCPHeader{Sport: &pair.sp, Dport: &dp, Flags: 0x10},
			BGP: []model.BGPMessage{{Type: 4}},
		})
		bfdDet.Feed(&model.Record{
			N: pair.n + 3, T: pair.t + 0.3,
			IP:  &model.IPHeader{V: 4, Src: pair.b, Dst: pair.a, Proto: intp(6)},
			TCP: &model.TCPHeader{Sport: &dp, Dport: &pair.sp, Flags: 0x10},
			BGP: []model.BGPMessage{{Type: 4}},
		})
	}
	// BFD Cease notification on 10.0.0.1 <-> 10.0.0.2 and UPDATE on surviving 10.0.0.2 <-> 10.0.0.3.
	bfdDet.Feed(&model.Record{
		N: 20, T: 105.0,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.2", Dst: "10.0.0.1", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &dp, Dport: &sp1, Flags: 0x10},
		BGP: []model.BGPMessage{{Type: 3, Major: intp(6), Minor: intp(10)}},
	})
	bfdDet.Feed(&model.Record{
		N: 21, T: 105.2,
		IP:           &model.IPHeader{V: 4, Src: "10.0.0.3", Dst: "10.0.0.2", Proto: intp(6)},
		TCP:          &model.TCPHeader{Sport: &dp, Dport: &sp2, Flags: 0x10},
		BGP:          []model.BGPMessage{{Type: 2}},
		BGPWithdrawn: intp(1),
	})
	rep, err := bfdDet.Report(model.Context{Start: floatp(100.0), End: floatp(110.0), MaxItems: 25})
	if err != nil {
		t.Fatalf("bfd report: %v", err)
	}
	if rep.Driver.Mechanism != "bfd" || rep.Status != model.StatusWarning || len(rep.Issues) == 0 || rep.Issues[0].Code != "CONVERGENCE_NOT_SEEN" {
		t.Fatalf("unexpected bfd report: driver=%+v status=%v issues=%+v", rep.Driver, rep.Status, rep.Issues)
	}

	// Hold-time inferred driver via HoldTime option + explicit ESP resumed + bad EventTime error.
	infDet := NewDetector(Options{FailedPeer: "192.0.2.1", HoldTime: floatp(10.0)})
	infDet.Feed(&model.Record{N: 1, T: 200.0, IP: &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.2", Proto: intp(50)}, ESP: &model.ESPHeader{SPI: 1, Seq: 1}})
	infDet.Feed(&model.Record{N: 2, T: 201.0, IP: &model.IPHeader{V: 4, Src: "198.51.100.2", Dst: "192.0.2.1", Proto: intp(50)}, ESP: &model.ESPHeader{SPI: 2, Seq: 1}})
	infDet.Feed(&model.Record{N: 3, T: 205.0, IP: &model.IPHeader{V: 4, Src: "198.51.100.2", Dst: "192.0.2.1", Proto: intp(50)}, ESP: &model.ESPHeader{SPI: 2, Seq: 2}})
	infDet.Feed(&model.Record{N: 4, T: 209.5, IP: &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.2", Proto: intp(50)}, ESP: &model.ESPHeader{SPI: 1, Seq: 2}})
	repInf, err := infDet.Report(model.Context{Start: floatp(200.0), End: floatp(210.0), MaxItems: 25})
	if err != nil {
		t.Fatalf("inf report: %v", err)
	}
	if repInf.Driver.Mechanism != "bgp_hold_timer" {
		t.Fatalf("expected inferred bgp_hold_timer driver, got %+v", repInf.Driver)
	}
}
