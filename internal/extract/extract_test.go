package extract

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
	"github.com/zombat/sonic/internal/tshark"
)

func TestPayloadHashBLAKE2b64(t *testing.T) {
	t.Parallel()

	// Verified against Python hashlib.blake2b(x, digest_size=8).hexdigest().
	cases := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte(""), "e4a6a0577479b2b4"},
		{"abc", []byte("abc"), "d8bb14d833d59559"},
		{"hello", []byte("hello world"), "878633aa32a3b150"},
		{"multiblock", []byte(strings.Repeat("ABCD1234", 40)), "faff5236bc46ad95"},
	}
	for _, tc := range cases {
		if got := PayloadHash(tc.input); got != tc.want {
			t.Fatalf("%s: PayloadHash = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestGoldenRecordsParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	fixtures := []string{
		"audit_one_leak",
		"ipsec_cleartext_icmp",
		"ipsec_ikev2_esp",
		"ipsec_natt",
		"ikev2_negotiation",
		"gre_nhrp",
		"bgp_session",
		"ospf_hello_mismatch",
		"eigrp_mismatch",
		"icmp_loss",
		"dp_fragments",
		"dp_tcp_health",
		"dp_tls",
		"dp_esp_sizes",
		"dp_pmtu_black_hole",
		"dp_pmtu_frag_needed",
		"dp_qos_rtp",
		"grpc_tls12_alert",
		"grpc_tls13_hrr",
		"enc_midstream",
		"enc_port22_text",
		"enc_ssh_cbc",
		"enc_ssh_none",
		"enc_tls10",
		"enc_tls12_null",
		"enc_tls13_integrity_only",
	}

	ctx := context.Background()
	for _, stem := range fixtures {
		t.Run(stem, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", stem+".pcap")
			goldenPath := filepath.Join("testdata", "golden", "records", stem+".json")
			got, err := OpenNetworkRecords(ctx, tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords(%s): %v", pcapPath, err)
			}
			parity.CompareGolden(t, got, goldenPath)
		})
	}
}

func TestSyntheticRowsAndFamilies(t *testing.T) {
	t.Parallel()

	// IPv6 + ICMPv6 Packet Too Big + HTTP/2 preface service port inference.
	v6Row := tshark.NewRow(map[string][]string{
		"frame.number":  {"1"},
		"frame.len":     {"120"},
		"ipv6.src":      {"2001:db8::1", "2001:db8::2"},
		"ipv6.dst":      {"2001:db8::2", "2001:db8::1"},
		"ipv6.nxt":      {"58", "6"},
		"ipv6.hlim":     {"64"},
		"icmpv6.type":   {"2"},
		"icmpv6.code":   {"0"},
		"dp.icmpv6.mtu": {"1280"},
		"dp.ip6.plen":   {"80", "40"},
		"tcp.dstport":   {"443"},
	})
	v6Rec := RecordFromTShark(v6Row, 4)
	if v6Rec.ICMP == nil || !v6Rec.ICMP.V6 || v6Rec.DP == nil || v6Rec.DP.ICMP == nil || *v6Rec.DP.ICMP.MTU != 1280 {
		t.Fatalf("unexpected v6 ICMP record: %+v", v6Rec)
	}

	// IKE fallback (no udp payload) + SIP + STP LLC + TLS/HTTP2 family coverage.
	ikeRow := tshark.NewRow(map[string][]string{
		"frame.number":       {"2"},
		"frame.protocols":    {"eth:llc:stp"},
		"isakmp.exchtype":    {"2"},
		"isakmp.version":     {"0x20"},
		"isakmp.flags":       {"8"},
		"isakmp.typepayload": {"46"},
	})
	ikeRec := RecordFromTShark(ikeRow, 4)
	if ikeRec.LLC != "stp" || ikeRec.IKE == nil || !ikeRec.IKE.Encrypted {
		t.Fatalf("unexpected IKE/LLC record: %+v", ikeRec)
	}

	http2Hex := hex.EncodeToString(http2Preface)
	sport, dport := 55000, 50051
	six := 6
	recs := []model.Record{
		{
			IP:  &model.IPHeader{V: 6, Proto: &six, Src: "2001:db8::2", Dst: "2001:db8::1"},
			TCP: &model.TCPHeader{Sport: &sport, Dport: &dport},
			DP:  &model.DataPlane{PL: http2Hex},
		},
		{
			IP:    &model.IPHeader{V: 4},
			TCP:   &model.TCPHeader{},
			SIP:   new(true),
			DP:    &model.DataPlane{PL: "5353482d322e300d0a"},
			Inner: &model.InnerPacket{NATKeepalive: new(true), OSPF: &model.OSPFPacket{}, EIGRP: &model.EIGRPPacket{}, BGP: []model.BGPMessage{{}}},
		},
		{
			ICMP: &model.ICMPPacket{V6: true},
		},
	}
	AnnotateServicePorts(recs)
	if recs[0].TCP.Svc == nil || *recs[0].TCP.Svc != 50051 {
		t.Fatalf("HTTP/2 service annotation = %v, want 50051", recs[0].TCP.Svc)
	}
	fams := DetectFamilies(recs)
	for _, need := range []string{"bgp", "eigrp", "http2", "icmpv6", "ipv6", "nat-t", "ospf", "sip", "ssh", "tcp"} {
		found := false
		for _, f := range fams {
			if f == need {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing family %q in %v", need, fams)
		}
	}

	if _, err := OpenNetworkRecords(context.Background(), tshark.StreamOptions{FilePath: "/nonexistent/nope.pcap"}); err == nil {
		t.Fatal("expected error for missing pcap")
	}
}

func FuzzParseIKE(f *testing.F) {
	f.Add(make([]byte, 32), false)
	f.Add([]byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
		33, 0x20, 34, 8, 0, 0, 0, 0, 0, 0, 0, 48,
		0, 0, 0, 20, 0, 0, 0, 16, 1, 1, 0, 1, 0, 3, 0, 8, 1, 0, 0, 12,
	}, true)
	f.Fuzz(func(t *testing.T, data []byte, natt bool) {
		_ = ParseIKE(data, natt)
	})
}
