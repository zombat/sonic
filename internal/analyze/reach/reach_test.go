package reach

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func feedFixtureRecords(t *testing.T, relPcap string, feed func(*model.Record)) model.Context {
	t.Helper()
	out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: relPcap})
	if err != nil {
		t.Fatalf("OpenNetworkRecords(%s): %v", relPcap, err)
	}
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
		feed(rec)
	}
	return model.Context{Start: startPtr, End: endPtr, MaxItems: 25}
}

func TestGoldenReachabilityAndConversationsParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	reachCases := []string{
		"icmp_loss",
		"audit_one_leak",
		"ipsec_cleartext_icmp",
		"dp_pmtu_frag_needed",
	}
	for _, stem := range reachCases {
		t.Run("reachability/"+stem, func(t *testing.T) {
			det := NewReachabilityDetector()
			ctx := feedFixtureRecords(t, filepath.Join("tests", "fixtures", stem+".pcap"), det.Feed)
			got := det.Report(ctx)
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "reachability", stem+".json"))
		})
	}

	convCases := []string{
		"ipsec_ikev2_esp",
		"audit_one_leak",
		"icmp_loss",
		"dp_tcp_health",
	}
	for _, stem := range convCases {
		t.Run("conversations/"+stem, func(t *testing.T) {
			det := NewConversationDetector()
			ctx := feedFixtureRecords(t, filepath.Join("tests", "fixtures", stem+".pcap"), det.Feed)
			got := det.Report(ctx)
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "conversations", stem+".json"))
		})
	}
}

func TestReachabilityEdgeCasesAndDuplicates(t *testing.T) {
	t.Parallel()

	intp := func(v int) *int { return &v }
	strp := func(v string) *string { return &v }
	floatp := func(v float64) *float64 { return &v }

	// Empty detectors report not_present cleanly.
	if emptyR := NewReachabilityDetector().Report(model.Context{MaxItems: 25}); emptyR.Status != model.StatusNotPresent {
		t.Fatalf("empty reach status = %v", emptyR.Status)
	}
	if emptyC := NewConversationDetector().Report(model.Context{MaxItems: 25}); emptyC.Status != model.StatusNotPresent {
		t.Fatalf("empty conv status = %v", emptyC.Status)
	}

	det := NewReachabilityDetector()
	// Duplicate echo request, unmatched reply, pending echo at end, IPv6 time exceeded, gratuitous + dup ARP.
	det.Feed(&model.Record{N: 1, T: 10.0, ICMP: &model.ICMPPacket{Type: intp(8), ID: intp(1), Seq: intp(1), Src: strp("10.0.0.1"), Dst: strp("10.0.0.2")}})
	det.Feed(&model.Record{N: 2, T: 10.1, ICMP: &model.ICMPPacket{Type: intp(8), ID: intp(1), Seq: intp(1), Src: strp("10.0.0.1"), Dst: strp("10.0.0.2")}})
	det.Feed(&model.Record{N: 3, T: 10.2, ICMP: &model.ICMPPacket{Type: intp(0), ID: intp(99), Seq: intp(9), Src: strp("10.0.0.9"), Dst: strp("10.0.0.1")}})
	det.Feed(&model.Record{N: 4, T: 14.5, ICMP: &model.ICMPPacket{Type: intp(8), ID: intp(1), Seq: intp(2), Src: strp("10.0.0.1"), Dst: strp("10.0.0.2")}})
	det.Feed(&model.Record{N: 5, T: 11.0, ICMP: &model.ICMPPacket{V6: true, Type: intp(3), Code: intp(0), Src: strp("2001:db8::1"), Dst: strp("2001:db8::2"), Orig: &model.ICMPOrig{Src: "2001:db8::2", Dst: "2001:db8::3", Proto: intp(58)}}})
	det.Feed(&model.Record{N: 6, T: 12.0, ARP: &model.ARPPacket{Op: intp(1), SPA: strp("10.0.0.5"), TPA: strp("10.0.0.5")}})
	det.Feed(&model.Record{N: 7, T: 12.1, ARP: &model.ARPPacket{Op: intp(2), SPA: strp("10.0.0.5"), TPA: strp("10.0.0.5"), SHA: strp("aa:bb:cc:00:00:01")}})
	det.Feed(&model.Record{N: 8, T: 12.2, ARP: &model.ARPPacket{Op: intp(2), SPA: strp("10.0.0.5"), TPA: strp("10.0.0.5"), SHA: strp("aa:bb:cc:00:00:02")}})

	rep := det.Report(model.Context{Start: floatp(10.0), End: floatp(15.0), MaxItems: 25})
	if rep.Summary.UnmatchedReplies != 1 || rep.Summary.GratuitousARP != 3 || len(rep.ARPDuplicateIPs) != 1 {
		t.Fatalf("unexpected reach edge summary: %+v dups=%v", rep.Summary, rep.ARPDuplicateIPs)
	}
	if rep.Echo[0].DuplicateRequestsSeen != 1 || rep.Echo[0].PendingAtCaptureEnd != 1 {
		t.Fatalf("unexpected echo pair edge counts: %+v", rep.Echo[0])
	}
}
