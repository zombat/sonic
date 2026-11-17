package ipsec

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestGoldenIPsecParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	fixtures := []string{
		"ipsec_ikev2_esp",
		"ipsec_cleartext_icmp",
		"ipsec_natt",
		"ikev1",
		"ikev2_failures",
		"ikev2_negotiation",
		"ikev2_no_proposal",
		"ikev2_no_response",
		"esp_stale_spi",
		"phase3_encrypted",
		"convergence_dpd",
	}

	for _, stem := range fixtures {
		t.Run(stem, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", stem+".pcap")
			out, err := extract.OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			det := NewDetector(nil)
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
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "ipsec", stem+".json"))
		})
	}
}

func TestIPsecSyntheticPeersCollisionsAndEdgeCases(t *testing.T) {
	t.Parallel()

	empty := NewDetector([]string{"10.0.0.1", "10.0.0.2"}).Report(model.Context{MaxItems: 25})
	if empty.Status != model.StatusNotPresent || empty.Verdict != "No IPsec (IKE/ESP) or GRE tunnel traffic in this capture." {
		t.Fatalf("empty report mismatch: %+v", empty)
	}
	if EncryptionVerdict(99).String() != "not_present" {
		t.Fatal("unknown EncryptionVerdict string mismatch")
	}

	intp := func(v int) *int { return &v }
	strp := func(v string) *string { return &v }
	floatp := func(v float64) *float64 { return &v }

	// Explicit peer filter + GRE cleartext leak + ESP gaps/duplicates + IKE SA collision.
	det := NewDetector([]string{"192.0.2.1", "192.0.2.2"})
	det.Feed(&model.Record{
		N: 1, T: 1.0, Len: 120,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "192.0.2.2", Proto: intp(47)},
		GRE: &model.GREHeader{Ptype: intp(0x0800)},
	})
	det.Feed(&model.Record{
		N: 2, T: 1.1, Len: 120,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "192.0.2.2", Proto: intp(50)},
		ESP: &model.ESPHeader{SPI: 0x11111111, Seq: 1},
	})
	det.Feed(&model.Record{
		N: 3, T: 1.2, Len: 120,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "192.0.2.2", Proto: intp(50)},
		ESP: &model.ESPHeader{SPI: 0x11111111, Seq: 5},
	})
	det.Feed(&model.Record{
		N: 4, T: 1.3, Len: 120,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "192.0.2.2", Proto: intp(50)},
		ESP: &model.ESPHeader{SPI: 0x11111111, Seq: 3},
	})
	det.Feed(&model.Record{
		N: 5, T: 1.4, Len: 120,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "192.0.2.2", Proto: intp(50)},
		ESP: &model.ESPHeader{SPI: 0x11111111, Seq: 5},
	})

	// Simultaneous IKEv2 SAs in opposing directions (collision) + peer lost SA notify (INVALID_IKE_SPI).
	ispi1, ispi2 := "1111111111111111", "2222222222222222"
	sp500 := 500
	det.Feed(&model.Record{
		N: 6, T: 2.0, Len: 200,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.1", Dst: "192.0.2.2", Proto: intp(17)},
		UDP: &model.UDPHeader{Sport: &sp500, Dport: &sp500},
		IKE: &model.IKEHeader{Version: 2, ISPI: &ispi1, RSPI: strp("0000000000000000"), Exch: intp(34), Flags: 0x08, MsgID: 0, Length: 200, Proposals: []model.IKEProposal{{Num: 1, Protocol: 1}}},
	})
	det.Feed(&model.Record{
		N: 7, T: 2.05, Len: 200,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.2", Dst: "192.0.2.1", Proto: intp(17)},
		UDP: &model.UDPHeader{Sport: &sp500, Dport: &sp500},
		IKE: &model.IKEHeader{Version: 2, ISPI: &ispi2, RSPI: strp("0000000000000000"), Exch: intp(34), Flags: 0x08, MsgID: 0, Length: 200, Proposals: []model.IKEProposal{{Num: 1, Protocol: 1}}},
	})
	det.Feed(&model.Record{
		N: 8, T: 2.1, Len: 80,
		IP:  &model.IPHeader{V: 4, Src: "192.0.2.2", Dst: "192.0.2.1", Proto: intp(17)},
		UDP: &model.UDPHeader{Sport: &sp500, Dport: &sp500},
		IKE: &model.IKEHeader{Version: 2, ISPI: &ispi1, RSPI: strp("aaaaaaaaaaaaaaaa"), Exch: intp(34), Flags: 0x20, MsgID: 0, Length: 80, Notify: []int{4}},
	})

	rep := det.Report(model.Context{Start: floatp(1.0), End: floatp(3.0), MaxItems: 25})
	if rep.EncryptionVerdict != "cleartext_seen" || len(rep.IKESAs) != 2 || rep.IKESAs[0].CollidedWith == "" {
		t.Fatalf("unexpected synthetic collision/cleartext report: enc=%s sas=%+v", rep.EncryptionVerdict, rep.IKESAs)
	}
	if _, ok := natdHash(ispi1, ispi2, "192.0.2.1", 500); !ok {
		t.Fatal("valid natdHash returned false")
	}
	if _, ok := natdHash("zz", ispi2, "bad-ip", 500); ok {
		t.Fatal("invalid natdHash should return false")
	}
}
