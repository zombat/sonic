package dmvpn

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenDmvpnPhase3Parity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	cases := []struct {
		name   string
		pcap   string
		golden string
		hubs   []string
	}{
		{name: "gre_nhrp", pcap: "gre_nhrp", golden: "gre_nhrp"},
		{name: "nhrp_phase3_broken", pcap: "nhrp_phase3_broken", golden: "nhrp_phase3_broken"},
		{name: "phase3_encrypted_no_hubs", pcap: "phase3_encrypted", golden: "phase3_encrypted_no_hubs"},
		{name: "phase3_encrypted_with_hubs", pcap: "phase3_encrypted", golden: "phase3_encrypted_with_hubs", hubs: []string{"192.0.2.1", "192.0.2.2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join("testdata", "fixtures", tc.pcap+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewDetector(tc.hubs)
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
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "dmvpn_phase3", tc.golden+".json"))
		})
	}
}

func TestDmvpnSyntheticThrashingAndErrors(t *testing.T) {
	t.Parallel()

	empty := NewDetector(nil).Report(model.Context{MaxItems: 25})
	if empty.Status != model.StatusNotPresent || empty.Verdict != "No GRE/NHRP and no spoke-to-spoke IKE in this capture." {
		t.Fatalf("empty report mismatch: %+v", empty)
	}

	intp := func(v int) *int { return &v }
	u32p := func(v uint32) *uint32 { return &v }
	strp := func(v string) *string { return &v }
	floatp := func(v float64) *float64 { return &v }

	det := NewDetector(nil)
	// Trigger relayed-without-redirect + thrashing + negative resolution reply + error indication.
	det.Feed(&model.Record{
		N: 1, T: 1.0,
		IP:    &model.IPHeader{V: 4, Src: "198.51.100.2", Dst: "192.0.2.1"},
		GRE:   &model.GREHeader{Ptype: intp(0x0800)},
		Inner: &model.InnerPacket{Src: "10.9.1.1", Dst: "10.9.2.1"},
	})
	det.Feed(&model.Record{
		N: 2, T: 1.01,
		IP:    &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "203.0.113.3"},
		GRE:   &model.GREHeader{Ptype: intp(0x0800)},
		Inner: &model.InnerPacket{Src: "10.9.1.1", Dst: "10.9.2.1"},
	})
	det.Feed(&model.Record{
		N: 3, T: 1.02,
		IP:   &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.2"},
		GRE:  &model.GREHeader{Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(8), OrigSrc: strp("10.9.3.1"), OrigDst: strp("10.9.4.1")},
	})
	// 5 resolution requests within 1s from 198.51.100.2 to trigger NHRP_RESOLUTION_THRASHING + 1 negative reply.
	for i := 0; i < 5; i++ {
		det.Feed(&model.Record{
			N: 4 + i, T: 1.1 + float64(i)*0.05,
			IP:   &model.IPHeader{V: 4, Src: "198.51.100.2", Dst: "192.0.2.1"},
			GRE:  &model.GREHeader{Ptype: intp(0x2001)},
			NHRP: &model.NHRPPacket{Op: intp(1), SrcNBMA: strp("198.51.100.2"), SrcProto: strp("10.0.0.2"), DstProto: strp("10.9.4.1"), ReqID: u32p(uint32(100 + i))},
		})
	}
	det.Feed(&model.Record{
		N: 10, T: 1.4,
		IP:   &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.2"},
		GRE:  &model.GREHeader{Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(2), ReqID: u32p(100), Code: intp(12)},
	})
	det.Feed(&model.Record{
		N: 11, T: 1.41,
		IP:   &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "198.51.100.2"},
		GRE:  &model.GREHeader{Ptype: intp(0x2001)},
		NHRP: &model.NHRPPacket{Op: intp(7), ReqID: u32p(101), ErrCode: intp(6)},
	})

	rep := det.Report(model.Context{Start: floatp(1.0), End: floatp(2.0), MaxItems: 25})
	if !rep.ResolutionThrashing.Thrashing || len(rep.HubRelayedWithoutRedir) != 1 || len(rep.ErrorIndications) != 1 {
		t.Fatalf("unexpected synthetic thrashing report: %+v", rep)
	}
	if !inPrefix("10.1.2.5", strp("10.1.2.0"), intp(24)) || inPrefix("bad", strp("10.1.2.0"), intp(24)) {
		t.Fatal("inPrefix mismatch")
	}
}
