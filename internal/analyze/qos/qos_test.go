package qos

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenQosParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	for _, stem := range []string{"dp_qos_rtp", "dp_esp_sizes", "ipsec_ikev2_esp"} {
		t.Run(stem, func(t *testing.T) {
			pcapPath := filepath.Join("testdata", "fixtures", stem+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewQosDetector()
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
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "qos", stem+".json"))
		})
	}
}

func TestQosSyntheticBranchesAndMOS(t *testing.T) {
	t.Parallel()

	if empty := NewQosDetector().Report(model.Context{MaxItems: 25}); empty.Status != model.StatusNotPresent {
		t.Fatalf("empty status = %v, want not_present", empty.Status)
	}

	if mos := CalculateEModelMOS("G.729", 6.0, 45.0); mos <= 1.0 || mos >= 4.5 {
		t.Fatalf("unexpected MOS: %v", mos)
	}
	if CalculateEModelMOS("Unknown", 99.0, 600.0) != 1.0 {
		t.Fatal("extreme loss/jitter MOS should floor at 1.0")
	}
	if CalculateEModelMOS("GSM", 0.0, 0.0) <= 4.0 {
		t.Fatal("zero-loss GSM baseline should produce good MOS")
	}

	// Build a dynamic-PT RTP stream with < 20 packets ("assumed" 8000 Hz clock), duplicate, OOO, high jitter, >5% loss.
	det := NewQosDetector()
	makeRTP := func(seq uint16, ts uint32) string {
		pkt := make([]byte, 12)
		pkt[0] = 0x80
		pkt[1] = 98 // Opus dynamic PT
		binary.BigEndian.PutUint16(pkt[2:4], seq)
		binary.BigEndian.PutUint32(pkt[4:8], ts)
		binary.BigEndian.PutUint32(pkt[8:12], 0xdeadbeef)
		return hex.EncodeToString(pkt)
	}
	intp := func(v int) *int { return &v }
	sp, dp := 16000, 20000
	// Seq 1..8, skip 9..10 (loss > 5%), 11, duplicate 11, out-of-order 10, huge jitter on seq 12.
	events := []struct {
		n   int
		t   float64
		seq uint16
		ts  uint32
	}{
		{1, 1.00, 1, 160},
		{2, 1.02, 2, 320},
		{3, 1.04, 3, 480},
		{4, 1.06, 4, 640},
		{5, 1.08, 5, 800},
		{6, 1.10, 6, 960},
		{7, 1.12, 7, 1120},
		{8, 1.14, 8, 1280},
		{9, 1.20, 11, 1760},
		{10, 1.21, 11, 1760},
		{11, 1.22, 10, 1600},
		{12, 2.50, 12, 1920},
	}
	for _, ev := range events {
		det.Feed(&model.Record{
			N: ev.n, T: ev.t, Len: 80,
			IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(17)},
			UDP: &model.UDPHeader{Sport: &sp, Dport: &dp, Len: 20},
			DP:  &model.DataPlane{HL: 20, TL: 60, DSCP: 10, PL: makeRTP(ev.seq, ev.ts)},
		})
	}
	// GRE rewritten DSCP (inner=46, outer=10) + ESP fixed single non-zero marking (CS6).
	det.Feed(&model.Record{
		N: 13, T: 2.6, Len: 100,
		IP:    &model.IPHeader{V: 4, Src: "198.51.100.1", Dst: "198.51.100.2", Proto: intp(47)},
		GRE:   &model.GREHeader{Ptype: intp(0x0800)},
		Inner: &model.InnerPacket{Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(17)},
		DP:    &model.DataPlane{HL: 20, TL: 80, DSCP: 10, Inner: &model.DPInner{TL: 56, DSCP: 46}},
	})
	det.Feed(&model.Record{
		N: 14, T: 2.7, Len: 120,
		IP:  &model.IPHeader{V: 4, Src: "198.51.100.1", Dst: "198.51.100.2", Proto: intp(50)},
		ESP: &model.ESPHeader{SPI: 0x11223344, Seq: 1},
		DP:  &model.DataPlane{HL: 20, TL: 100, DSCP: 48},
	})

	// RTCP packet (PT 72) and low port (500) ignored by RTP detector; sequence wrap-around branch.
	lowPort := 500
	rtcpHex := hex.EncodeToString([]byte{0x80, 72, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	det.Feed(&model.Record{N: 15, T: 2.8, Len: 50, IP: &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(17)}, UDP: &model.UDPHeader{Sport: &sp, Dport: &dp}, DP: &model.DataPlane{HL: 20, TL: 30, PL: rtcpHex}})
	det.Feed(&model.Record{N: 16, T: 2.81, Len: 50, IP: &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(17)}, UDP: &model.UDPHeader{Sport: &lowPort, Dport: &dp}, DP: &model.DataPlane{HL: 20, TL: 30, PL: makeRTP(1, 10)}})

	start, end := 1.0, 2.81
	rep := det.Report(model.Context{Start: &start, End: &end, MaxItems: 25})
	if len(rep.RTPStreams) != 1 || rep.RTPStreams[0].ClockRateSource != "assumed" || rep.RTPStreams[0].Duplicates != 1 || rep.RTPStreams[0].OutOfOrder != 1 {
		t.Fatalf("unexpected synthetic RTP stream: %+v", rep.RTPStreams)
	}
	if len(rep.GRETunnels) != 1 || rep.GRETunnels[0].Rewritten != 1 {
		t.Fatalf("unexpected GRE rewrite stats: %+v", rep.GRETunnels)
	}
}
