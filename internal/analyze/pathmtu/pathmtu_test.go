package pathmtu

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenPathMtuParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	for _, stem := range []string{"dp_pmtu_frag_needed", "dp_pmtu_black_hole", "dp_fragments", "icmp_loss"} {
		t.Run(stem, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", stem+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewPathMtuDetector()
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
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "path_mtu", stem+".json"))
		})
	}
}

func TestPathMtuEdgeBranches(t *testing.T) {
	t.Parallel()

	if empty := NewPathMtuDetector().Report(model.Context{MaxItems: 25}); empty.Status != model.StatusNotPresent {
		t.Fatalf("empty status = %v", empty.Status)
	}

	intp := func(v int) *int { return &v }
	strp := func(v string) *string { return &v }
	floatp := func(v float64) *float64 { return &v }

	det := NewPathMtuDetector()
	// DF probe without black hole / PTB, plus pre-RFC1191 PTB without MTU, plus IPv6 PTB, plus missing-first fragment.
	det.Feed(&model.Record{
		N: 1, T: 1.0, Len: 1500,
		IP: &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 1480, ID: intp(77), DF: intp(1), MF: intp(0)},
	})
	det.Feed(&model.Record{
		N: 2, T: 1.1, Len: 90,
		IP:   &model.IPHeader{V: 6, Src: "2001:db8::ff", Dst: "2001:db8::1", Proto: intp(58)},
		ICMP: &model.ICMPPacket{V6: true, Type: intp(2), Code: intp(0), Src: strp("2001:db8::ff"), Dst: strp("2001:db8::1"), Orig: &model.ICMPOrig{Src: "2001:db8::1", Dst: "2001:db8::2", Proto: intp(6)}},
		DP:   &model.DataPlane{HL: 40, TL: 50, ICMP: &model.DPICMP{OrigLen: intp(1500)}},
	})
	det.Feed(&model.Record{
		N: 3, T: 1.2, Len: 100,
		IP: &model.IPHeader{V: 4, Src: "10.0.0.5", Dst: "10.0.0.6", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 100, ID: intp(88), DF: intp(0), MF: intp(0), Off: 100},
	})

	rep := det.Report(model.Context{Start: floatp(1.0), End: floatp(2.0), MaxItems: 25})
	if rep.Summary.DFPacketsOver576 != 1 || rep.Summary.FragNeededMessages != 1 || rep.Fragments.IncompleteCount != 1 {
		t.Fatalf("unexpected edge summary: %+v frags=%+v", rep.Summary, rep.Fragments)
	}
	if rep.Fragments.Incomplete[0].Missing[0] != "first" {
		t.Fatalf("expected missing 'first' fragment, got %v", rep.Fragments.Incomplete[0].Missing)
	}

	// Second scenario: TCP PMTU black hole + stale PTB MTU + overlapping + complete fragmentation.
	det2 := NewPathMtuDetector()
	sp, dp := 52000, 443
	// Small DF segment (600B) gets ACKed.
	det2.Feed(&model.Record{
		N: 1, T: 1.0, Len: 614,
		IP:  &model.IPHeader{V: 4, Src: "10.1.0.1", Dst: "10.1.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sp, Dport: &dp, Flags: 0x18, Len: 560},
		DP:  &model.DataPlane{HL: 20, TL: 600, ID: intp(1), DF: intp(1), TCP: &model.DPTCP{Seq: 1000, Ack: 1}},
	})
	det2.Feed(&model.Record{
		N: 2, T: 1.05, Len: 54,
		IP:  &model.IPHeader{V: 4, Src: "10.1.0.2", Dst: "10.1.0.1", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &dp, Dport: &sp, Flags: 0x10, Len: 0},
		DP:  &model.DataPlane{HL: 20, TL: 40, DF: intp(1), TCP: &model.DPTCP{Seq: 1, Ack: 1560}},
	})
	// Large DF segment (1500B) retransmitted twice without ACK.
	det2.Feed(&model.Record{
		N: 3, T: 1.1, Len: 1514,
		IP:  &model.IPHeader{V: 4, Src: "10.1.0.1", Dst: "10.1.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sp, Dport: &dp, Flags: 0x18, Len: 1460},
		DP:  &model.DataPlane{HL: 20, TL: 1500, ID: intp(2), DF: intp(1), TCP: &model.DPTCP{Seq: 1560, Ack: 1}},
	})
	det2.Feed(&model.Record{
		N: 4, T: 1.3, Len: 1514,
		IP:  &model.IPHeader{V: 4, Src: "10.1.0.1", Dst: "10.1.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sp, Dport: &dp, Flags: 0x18, Len: 1460},
		DP:  &model.DataPlane{HL: 20, TL: 1500, ID: intp(3), DF: intp(1), TCP: &model.DPTCP{Seq: 1560, Ack: 1}},
	})
	// Complete fragmented datagram for a different pair + overlapping datagram for another pair + stale PTB MTU.
	det2.Feed(&model.Record{
		N: 5, T: 1.4, Len: 600,
		IP: &model.IPHeader{V: 4, Src: "10.2.0.1", Dst: "10.2.0.2", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 580, ID: intp(10), MF: intp(1), Off: 0},
	})
	det2.Feed(&model.Record{
		N: 6, T: 1.41, Len: 200,
		IP: &model.IPHeader{V: 4, Src: "10.2.0.1", Dst: "10.2.0.2", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 180, ID: intp(10), MF: intp(0), Off: 560},
	})
	det2.Feed(&model.Record{
		N: 7, T: 1.5, Len: 200,
		IP: &model.IPHeader{V: 4, Src: "10.3.0.1", Dst: "10.3.0.2", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 120, ID: intp(11), MF: intp(1), Off: 0},
	})
	det2.Feed(&model.Record{
		N: 8, T: 1.51, Len: 200,
		IP: &model.IPHeader{V: 4, Src: "10.3.0.1", Dst: "10.3.0.2", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 120, ID: intp(11), MF: intp(0), Off: 50},
	})
	det2.Feed(&model.Record{
		N: 9, T: 1.6, Len: 90,
		IP:   &model.IPHeader{V: 4, Src: "10.9.9.1", Dst: "10.4.0.1", Proto: intp(1)},
		ICMP: &model.ICMPPacket{Type: intp(3), Code: intp(4), Src: strp("10.9.9.1"), Dst: strp("10.4.0.1"), Orig: &model.ICMPOrig{Src: "10.4.0.1", Dst: "10.4.0.2", Proto: intp(17)}},
		DP:   &model.DataPlane{HL: 20, TL: 70, ICMP: &model.DPICMP{MTU: intp(1500), OrigLen: intp(1400)}},
	})
	rep2 := det2.Report(model.Context{Start: floatp(1.0), End: floatp(2.0), MaxItems: 25})
	if rep2.Summary.BlackHoles != 1 || rep2.Summary.FragmentedDatagrams != 2 || len(rep2.Fragments.Overlapping) != 1 {
		t.Fatalf("unexpected rep2 summary/frags: summary=%+v frags=%+v", rep2.Summary, rep2.Fragments)
	}

	// Complete-only fragmentation info report.
	det3 := NewPathMtuDetector()
	det3.Feed(&model.Record{
		N: 1, T: 1.0, Len: 600,
		IP: &model.IPHeader{V: 4, Src: "10.5.0.1", Dst: "10.5.0.2", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 580, ID: intp(20), MF: intp(1), Off: 0},
	})
	det3.Feed(&model.Record{
		N: 2, T: 1.01, Len: 200,
		IP: &model.IPHeader{V: 4, Src: "10.5.0.1", Dst: "10.5.0.2", Proto: intp(17)},
		DP: &model.DataPlane{HL: 20, TL: 180, ID: intp(20), MF: intp(0), Off: 560},
	})
	rep3 := det3.Report(model.Context{Start: floatp(1.0), End: floatp(1.1), MaxItems: 25})
	if len(rep3.Issues) != 1 || rep3.Issues[0].Code != "IP_FRAGMENTATION" {
		t.Fatalf("expected IP_FRAGMENTATION info issue, got %+v", rep3.Issues)
	}
}
