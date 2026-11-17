package routing

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenRoutingParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	intp := func(v int) *int { return &v }
	cases := []struct {
		name        string
		pcap        string
		golden      string
		expectedMSS *int
	}{
		{name: "bgp_session", pcap: "bgp_session", golden: "bgp_session"},
		{name: "bgp_failover", pcap: "bgp_failover", golden: "bgp_failover"},
		{name: "bgp_failover_mss1360", pcap: "bgp_failover", golden: "bgp_failover_mss1360", expectedMSS: intp(1360)},
		{name: "ospf_hello_mismatch", pcap: "ospf_hello_mismatch", golden: "ospf_hello_mismatch"},
		{name: "ospf_failover", pcap: "ospf_failover", golden: "ospf_failover"},
		{name: "ospf_stuck", pcap: "ospf_stuck", golden: "ospf_stuck"},
		{name: "eigrp_mismatch", pcap: "eigrp_mismatch", golden: "eigrp_mismatch"},
		{name: "routing_over_gre", pcap: "routing_over_gre", golden: "routing_over_gre"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", tc.pcap+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewDetector(tc.expectedMSS)
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
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "routing", tc.golden+".json"))
		})
	}
}

func TestRoutingSyntheticEdgeBranches(t *testing.T) {
	t.Parallel()

	empty := NewDetector(nil).Report(model.Context{MaxItems: 25})
	if empty.Status != model.StatusNotPresent || empty.Verdict != "No BGP, OSPF or EIGRP in this capture." {
		t.Fatalf("empty report mismatch: %+v", empty)
	}

	intp := func(v int) *int { return &v }
	u32p := func(v uint32) *uint32 { return &v }
	strp := func(v string) *string { return &v }
	floatp := func(v float64) *float64 { return &v }

	det := NewDetector(intp(1360))
	sp, dp := 40000, 179
	// BGP connection refused with RST + silent peer + flap + End-of-RIB.
	det.Feed(&model.Record{
		N: 1, T: 1.0,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sp, Dport: &dp, Flags: 0x02},
	})
	det.Feed(&model.Record{
		N: 2, T: 1.01,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.2", Dst: "10.0.0.1", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &dp, Dport: &sp, Flags: 0x14},
	})
	// Second peer pair: SYN unanswered (no_answer).
	sp2 := 40001
	det.Feed(&model.Record{
		N: 3, T: 1.2,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.3", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sp2, Dport: &dp, Flags: 0x02},
	})

	// OSPF duplicate RID + stub area mismatch + one-way neighbor + EIGRP AS mismatch + SIA-Query + goodbye TLV.
	det.Feed(&model.Record{
		N: 4, T: 2.0,
		IP:   &model.IPHeader{V: 4, Src: "10.1.0.1", Dst: "224.0.0.5", Proto: intp(89)},
		OSPF: &model.OSPFPacket{Type: intp(1), RID: strp("1.1.1.1"), Area: strp("0.0.0.0"), Mask: strp("255.255.255.0"), Hello: intp(10), Dead: intp(40), Options: intp(0x02), DR: strp("10.1.0.1"), Neighbors: []string{"2.2.2.2"}},
	})
	det.Feed(&model.Record{
		N: 5, T: 2.1,
		IP:   &model.IPHeader{V: 4, Src: "10.1.0.2", Dst: "224.0.0.5", Proto: intp(89)},
		OSPF: &model.OSPFPacket{Type: intp(1), RID: strp("1.1.1.1"), Area: strp("0.0.0.0"), Mask: strp("255.255.255.0"), Hello: intp(10), Dead: intp(40), Options: intp(0x00), DR: strp("10.1.0.1")},
	})

	det.Feed(&model.Record{
		N: 6, T: 3.0,
		IP:    &model.IPHeader{V: 4, Src: "10.2.0.1", Dst: "224.0.0.10", Proto: intp(88)},
		EIGRP: &model.EIGRPPacket{Opcode: intp(5), AS: intp(10), K: []int{1, 0, 1, 0, 0, 0}, Hold: intp(15)},
	})
	det.Feed(&model.Record{
		N: 7, T: 3.1,
		IP:    &model.IPHeader{V: 4, Src: "10.2.0.2", Dst: "224.0.0.10", Proto: intp(88)},
		EIGRP: &model.EIGRPPacket{Opcode: intp(10), AS: intp(20), Seq: 1, TLVs: []int{0x0007, 0x0102}},
	})

	_ = u32p(1)
	rep := det.Report(model.Context{Start: floatp(1.0), End: floatp(4.0), MaxItems: 25})
	if rep.Status != model.StatusProblem || !rep.BGP.Present || !rep.OSPF.Present || !rep.EIGRP.Present {
		t.Fatalf("unexpected multi-protocol report: status=%v", rep.Status)
	}
	if ups := det.BGPAllUpdates([2]string{"10.0.0.1", "10.0.0.2"}); len(ups) != 0 {
		t.Fatalf("expected empty updates on refused session, got %v", ups)
	}
	if ups := det.BGPAllUpdates([2]string{"192.0.2.1", "192.0.2.2"}); ups != nil {
		t.Fatalf("expected nil updates on unknown session, got %v", ups)
	}
}
