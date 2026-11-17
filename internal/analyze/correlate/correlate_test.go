package correlate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
)

func intPtr(i int) *int        { return &i }
func strPtr(s string) *string  { return &s }
func f64Ptr(f float64) *float6 { return &f }

type float6 = float64

func TestGoldenCorrelateParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	fix := func(name string) string {
		return filepath.Join("tests", "fixtures", name)
	}
	golden := func(name string) string {
		return filepath.Join("testdata", "golden", "correlate", name)
	}

	t.Run("nat_inside_outside", func(t *testing.T) {
		got := CorrelateCaptures(ctx, []CaptureInput{
			{Path: fix("dp_corr_inside.pcap"), Label: "inside"},
			{Path: fix("dp_corr_outside.pcap"), Label: "outside"},
		}, Options{})
		parity.CompareGolden(t, got, golden("nat_inside_outside.json"))
	})

	t.Run("asymmetric_lan_wan1_wan2", func(t *testing.T) {
		got := CorrelateCaptures(ctx, []CaptureInput{
			{Path: fix("dp_corr_lan.pcap"), Label: "lan"},
			{Path: fix("dp_corr_wan1.pcap"), Label: "wan1"},
			{Path: fix("dp_corr_wan2.pcap"), Label: "wan2"},
		}, Options{})
		parity.CompareGolden(t, got, golden("asymmetric_lan_wan1_wan2.json"))
	})

	t.Run("clock_offset_unmatched", func(t *testing.T) {
		got := CorrelateCaptures(ctx, []CaptureInput{
			{Path: fix("dp_corr_inside.pcap"), Label: "inside"},
			{Path: fix("dp_corr_outside.pcap"), Label: "outside"},
		}, Options{ClockOffsetsS: map[string]float64{"outside": 100.0}})
		parity.CompareGolden(t, got, golden("clock_offset_unmatched.json"))
	})
}

func TestCorrelateIdentitiesBranchesAndErrors(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	in := filepath.Join("tests", "fixtures", "dp_corr_inside.pcap")
	out := filepath.Join("tests", "fixtures", "dp_corr_outside.pcap")

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

	assertErr(CorrelateCaptures(ctx, []CaptureInput{{Path: in, Label: "a"}}, Options{}), "two or more")
	assertErr(CorrelateCaptures(ctx, []CaptureInput{{Path: ""}, {Path: out}}, Options{}), `needs a "path"`)
	assertErr(CorrelateCaptures(ctx, []CaptureInput{{Path: in, Label: "a"}, {Path: out, Label: "a"}}, Options{}), "duplicate capture label")
	assertErr(CorrelateCaptures(ctx, []CaptureInput{{Path: in}, {Path: filepath.Join("tests", "fixtures", "missing.pcap")}}, Options{}), "File not found")
	assertErr(CorrelateCaptures(ctx, []CaptureInput{{Path: in, Label: "a"}, {Path: out, Label: "b"}}, Options{ClockOffsetsS: map[string]float64{"zz": 1}}), "unknown label")
	assertErr(CorrelateCaptures(ctx, []CaptureInput{{Path: in}, {Path: out}}, Options{WindowS: f64Ptr(0)}), "window_s must be")
	assertErr(CorrelateCaptures(ctx, []CaptureInput{{Path: in}, {Path: out}}, Options{MaxPacketsHeld: 10}), "max_packets_held must be at least 100")

	// Small held cap still runs cleanly on inside/outside fixtures.
	smallCap := CorrelateCaptures(ctx, []CaptureInput{
		{Path: in, Label: "inside"},
		{Path: out, Label: "outside"},
	}, Options{MaxPacketsHeld: 100})
	if smallCap.Status != "success" || smallCap.Matching.MaxPacketsHeld != 100 {
		t.Fatalf("unexpected small MaxPacketsHeld run: %+v", smallCap)
	}

	// PacketIdentity covers ESP, IKE, TCP NAT-invariance, UDP (ph + id), ICMP, generic IP, and non-IP.
	if _, _, ok := PacketIdentity(&model.Record{N: 1}); ok {
		t.Fatal("expected false for non-IP PacketIdentity")
	}
	tcpRecA := &model.Record{
		N: 1, IP: &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "192.0.2.1", Proto: intPtr(6), TTL: intPtr(64)},
		TCP: &model.TCPHeader{Sport: intPtr(1000), Dport: intPtr(443), Flags: 0x18, Len: 20},
		DP:  &model.DataPlane{HL: 20, TL: 60, ID: intPtr(7), TCP: &model.DPTCP{Seq: 10, Ack: 20, Win: 100, HL: 20}, PH: "abc"},
	}
	tcpRecB := &model.Record{
		N: 1, IP: &model.IPHeader{V: 4, Src: "203.0.113.5", Dst: "192.0.2.1", Proto: intPtr(6), TTL: intPtr(63)},
		TCP: &model.TCPHeader{Sport: intPtr(61000), Dport: intPtr(443), Flags: 0x18, Len: 20},
		DP:  &model.DataPlane{HL: 20, TL: 60, ID: intPtr(7), TCP: &model.DPTCP{Seq: 10, Ack: 20, Win: 100, HL: 20}, PH: "abc"},
	}
	kA, tA, okA := PacketIdentity(tcpRecA)
	kB, tB, okB := PacketIdentity(tcpRecB)
	if !okA || !okB || kA != kB || tA == tB {
		t.Fatalf("TCP NAT invariance mismatch: kA=%v kB=%v", kA, kB)
	}
	for _, rec := range []*model.Record{
		{N: 2, IP: &model.IPHeader{V: 4, Src: "1.1.1.1", Dst: "2.2.2.2", Proto: intPtr(50), TTL: intPtr(64)}, ESP: &model.ESPHeader{SPI: 1, Seq: 2}, DP: &model.DataPlane{}},
		{N: 3, IP: &model.IPHeader{V: 4, Src: "1.1.1.1", Dst: "2.2.2.2", Proto: intPtr(17), TTL: intPtr(64)}, UDP: &model.UDPHeader{Sport: intPtr(500), Dport: intPtr(500), Len: 100}, IKE: &model.IKEHeader{ISPI: strPtr("aa"), RSPI: strPtr("bb"), MsgID: 0, Flags: 8, Length: 100}, DP: &model.DataPlane{}},
		{N: 4, IP: &model.IPHeader{V: 4, Src: "1.1.1.1", Dst: "2.2.2.2", Proto: intPtr(17), TTL: intPtr(64)}, UDP: &model.UDPHeader{Sport: intPtr(53), Dport: intPtr(1053), Len: 12}, DP: &model.DataPlane{ID: intPtr(9), TL: 40}},
		{N: 5, IP: &model.IPHeader{V: 4, Src: "1.1.1.1", Dst: "2.2.2.2", Proto: intPtr(1), TTL: intPtr(64)}, ICMP: &model.ICMPPacket{Type: intPtr(8), ID: intPtr(3), Seq: intPtr(4)}, DP: &model.DataPlane{ID: intPtr(11), TL: 64}},
		{N: 6, IP: &model.IPHeader{V: 4, Src: "1.1.1.1", Dst: "2.2.2.2", Proto: intPtr(47), TTL: intPtr(64)}, DP: &model.DataPlane{ID: intPtr(12), TL: 80}},
	} {
		if _, _, ok := PacketIdentity(rec); !ok {
			t.Fatalf("expected valid identity on record %d", rec.N)
		}
	}
	if !isMulticast("224.0.0.5") || !isMulticast("10.0.0.255") || isMulticast("bad") {
		t.Fatal("isMulticast edge mismatch")
	}

	// Synthetic partial_loss, not_on_other_paths, and eviction test via feed/flush.
	t0, t1, t2 := 0.0, 1.0, 2.0
	infos := []*streamInfo{
		{label: "c1", start: &t0, end: &t2, done: true},
		{label: "c2", start: &t0, end: &t2, done: true},
		{label: "c3", start: &t0, end: &t2, done: true},
	}
	synth := newCorrelator([]string{"c1", "c2", "c3"}, 2.0, 2, infos)
	mkUDP := func(n int, src, dst string, id int) *model.Record {
		return &model.Record{N: n, IP: &model.IPHeader{V: 4, Src: src, Dst: dst, Proto: intPtr(17), TTL: intPtr(64)}, UDP: &model.UDPHeader{Sport: intPtr(5000), Dport: intPtr(5001), Len: 10}, DP: &model.DataPlane{ID: intPtr(id), TL: 38}}
	}
	// Flow crossing c1+c2 on pkt1 and c1 only on pkt2 -> partial_loss.
	synth.feed(0, 0.1, mkUDP(1, "10.0.0.1", "10.0.0.2", 101))
	synth.feed(1, 0.2, mkUDP(1, "10.0.0.1", "10.0.0.2", 101))
	synth.feed(0, 0.5, mkUDP(2, "10.0.0.1", "10.0.0.2", 102))
	// Isolated c3 flow -> not_on_other_paths (with evictedEarly triggered by maxHeld=2).
	synth.feed(2, 0.6, mkUDP(1, "172.16.0.1", "172.16.0.2", 201))
	synth.feed(0, t1+5.0, &model.Record{N: 3})
	synth.flush()
	synthRep := buildReport(synth, synth.labels, infos, 2.0, 2, 25)
	if synthRep.Summary.ByVerdict["partial_loss"] != 1 || synthRep.Summary.ByVerdict["not_on_other_paths"] != 1 || synthRep.Matching.EvictedEarly == 0 {
		t.Fatalf("unexpected synthetic correlation summary: %+v matching=%+v", synthRep.Summary, synthRep.Matching)
	}
}
