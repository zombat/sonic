package grenhrp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenGreNhrpParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	for _, stem := range []string{"gre_nhrp", "nhrp_phase3_broken", "routing_over_gre", "audit_one_leak"} {
		t.Run(stem, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", stem+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewDetector()
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
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "gre_nhrp", stem+".json"))
		})
	}
}

func TestGreNhrpSyntheticEdgeCases(t *testing.T) {
	t.Parallel()

	empty := NewDetector().Report(model.Context{MaxItems: 25})
	if empty.Status != model.StatusNotPresent || empty.Verdict != "No GRE traffic in this capture." {
		t.Fatalf("empty report mismatch: %+v", empty)
	}

	intp := func(v int) *int { return &v }
	u32p := func(v uint32) *uint32 { return &v }
	strp := func(v string) *string { return &v }
	floatp := func(v float64) *float64 { return &v }

	det := NewDetector()
	// Direction 1 uses key 100; reverse uses keyless GRE -> GRE_KEY_MISMATCH; unanswered registration; negative reply; purge req/rep.
	det.Feed(&model.Record{
		N: 1, T: 1.0, Len: 90,
		IP:   &model.IPHeader{V: 4, Src: "198.51.100.1", Dst: "192.0.2.1"},
		GRE:  &model.GREHeader{Key: u32p(100), Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(3), SrcNBMA: strp("198.51.100.1"), SrcProto: strp("10.0.0.10"), DstProto: strp("10.0.0.1")},
	})
	det.Feed(&model.Record{
		N: 2, T: 1.1, Len: 80,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.1"},
		GRE: &model.GREHeader{Key: nil, Ptype: intp(0x0800)},
	})
	// Negative resolution reply + duplicate reply + purge req/rep + unknown op.
	det.Feed(&model.Record{
		N: 3, T: 1.2, Len: 80,
		IP:   &model.IPHeader{V: 4, Src: "198.51.100.1", Dst: "192.0.2.1"},
		GRE:  &model.GREHeader{Key: u32p(100), Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(1), SrcNBMA: strp("198.51.100.1"), SrcProto: strp("10.0.0.10"), DstProto: strp("10.9.9.1"), ReqID: u32p(77)},
	})
	det.Feed(&model.Record{
		N: 4, T: 1.3, Len: 80,
		IP:   &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.1"},
		GRE:  &model.GREHeader{Key: nil, Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(2), SrcProto: strp("10.0.0.10"), DstProto: strp("10.9.9.1"), ReqID: u32p(77), Code: intp(12)},
	})
	det.Feed(&model.Record{
		N: 5, T: 1.4, Len: 80,
		IP:   &model.IPHeader{V: 4, Src: "198.51.100.1", Dst: "192.0.2.1"},
		GRE:  &model.GREHeader{Key: u32p(100), Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(5)},
	})
	det.Feed(&model.Record{
		N: 6, T: 1.5, Len: 80,
		IP:   &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.1"},
		GRE:  &model.GREHeader{Key: nil, Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(6)},
	})

	rep := det.Report(model.Context{Start: floatp(1.0), End: floatp(2.0), MaxItems: 25})
	if rep.Status != model.StatusProblem || rep.Purges["requests"] != 1 || rep.Purges["replies"] != 1 {
		t.Fatalf("unexpected synthetic report: %+v", rep)
	}
	if RegResult(99).String() != "unknown" || ResResult(99).String() != "unknown" {
		t.Fatal("enum fallback mismatch")
	}
}
