package tcphealth

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenTCPHealthParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	for _, stem := range []string{"dp_tcp_health", "dp_tls", "bgp_session", "enc_ssh_cbc"} {
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
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "tcp", stem+".json"))
		})
	}
}

func TestTCPHealthEdgeCasesAndMidstream(t *testing.T) {
	t.Parallel()

	if empty := NewDetector().Report(model.Context{MaxItems: 25}); empty.Status != model.StatusNotPresent {
		t.Fatalf("empty status = %v, want not_present", empty.Status)
	}

	intp := func(v int) *int { return &v }
	floatp := func(v float64) *float64 { return &v }
	sp, dp := 55000, 443

	det := NewDetector()
	// Midstream data without SYN + FIN + RST + duplicate SYN-ACK + zero window left open at end.
	det.Feed(&model.Record{
		N: 1, T: 1.0,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sp, Dport: &dp, Flags: flagACK, Len: 100},
		DP:  &model.DataPlane{HL: 20, TL: 140, TCP: &model.DPTCP{Seq: 1000, Ack: 2000, Win: 0}},
	})
	det.Feed(&model.Record{
		N: 2, T: 1.5,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intp(6)},
		TCP: &model.TCPHeader{Sport: &sp, Dport: &dp, Flags: flagACK | flagFIN | flagRST, Len: 0},
		DP:  &model.DataPlane{HL: 20, TL: 40, TCP: &model.DPTCP{Seq: 1100, Ack: 2000, Win: 0}},
	})
	rep := det.Report(model.Context{Start: floatp(1.0), End: floatp(2.5), MaxItems: 25})
	if len(rep.Connections) != 1 || rep.Connections[0].Verdict != "receiver_buffer_exhausted" ||
		!rep.Connections[0].Directions["client_to_server"].ZeroWindowOpenAtEnd {
		t.Fatalf("unexpected midstream zero-window connection: %+v", rep.Connections)
	}
}
