package extract

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

func TestFastPathMatchesTSharkOnRepoFixtures(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	fixtures := []string{
		"dp_tcp_health",
		"dp_pmtu_black_hole",
		"dp_pmtu_frag_needed",
		"dp_qos_rtp",
		"dp_esp_sizes",
		"icmp_loss",
		"dp_fragments",
		"routing_over_gre",
		"ipsec_natt",
	}

	ctx := context.Background()
	for _, stem := range fixtures {
		t.Run(stem, func(t *testing.T) {
			pcapPath := filepath.Join("testdata", "fixtures", stem+".pcap")
			wantOut, err := OpenNetworkRecords(ctx, tshark.StreamOptions{FilePath: pcapPath})
			if err != nil {
				t.Fatalf("OpenNetworkRecords: %v", err)
			}
			gotOut, err := OpenFastPathRecords(pcapPath, FastPathOptions{})
			if err != nil {
				t.Fatalf("OpenFastPathRecords: %v", err)
			}
			if gotOut.Backend != "go-fast" {
				t.Fatalf("backend = %q, want go-fast", gotOut.Backend)
			}
			if len(gotOut.Records) != len(wantOut.Records) {
				t.Fatalf("record count = %d, want %d", len(gotOut.Records), len(wantOut.Records))
			}
			for i := range wantOut.Records {
				g := gotOut.Records[i]
				w := wantOut.Records[i]
				if g.N != w.N || g.Len != w.Len || math.Abs(g.T-w.T) > 1e-4 {
					t.Fatalf("frame %d meta mismatch: got=(N=%d,T=%f,Len=%d) want=(N=%d,T=%f,Len=%d)", i+1, g.N, g.T, g.Len, w.N, w.T, w.Len)
				}
				if !reflect.DeepEqual(g.IP, w.IP) {
					t.Fatalf("frame %d IP mismatch: got=%+v want=%+v", i+1, g.IP, w.IP)
				}
				if !reflect.DeepEqual(g.TCP, w.TCP) {
					t.Fatalf("frame %d TCP mismatch: got=%+v want=%+v", i+1, g.TCP, w.TCP)
				}
				if !reflect.DeepEqual(g.UDP, w.UDP) {
					t.Fatalf("frame %d UDP mismatch: got=%+v want=%+v", i+1, g.UDP, w.UDP)
				}
				if !reflect.DeepEqual(g.ESP, w.ESP) {
					t.Fatalf("frame %d ESP mismatch: got=%+v want=%+v", i+1, g.ESP, w.ESP)
				}
				if !reflect.DeepEqual(g.NATKeepalive, w.NATKeepalive) {
					t.Fatalf("frame %d NATKeepalive mismatch: got=%v want=%v", i+1, g.NATKeepalive, w.NATKeepalive)
				}
				if !reflect.DeepEqual(g.ICMP, w.ICMP) {
					t.Fatalf("frame %d ICMP mismatch: got=%+v want=%+v", i+1, g.ICMP, w.ICMP)
				}
				if !reflect.DeepEqual(g.ARP, w.ARP) {
					t.Fatalf("frame %d ARP mismatch: got=%+v want=%+v", i+1, g.ARP, w.ARP)
				}
				if !reflect.DeepEqual(g.DP, w.DP) {
					t.Fatalf("frame %d DP mismatch: got=%+v want=%+v", i+1, g.DP, w.DP)
				}
			}
		})
	}
}

func TestFastPathPCAPNGSpecialLinksWindowAndErrors(t *testing.T) {
	t.Parallel()

	if !CanUseFastPath([]string{"tcp", "qos", "path_mtu", "esp_overhead", "reachability", "conversations"}, "") {
		t.Fatal("CanUseFastPath returned false for pure L2-L4 detectors")
	}
	if CanUseFastPath([]string{"routing"}, "") || CanUseFastPath([]string{"tcp"}, "ip") || CanUseFastPath(nil, "") {
		t.Fatal("CanUseFastPath accepted disallowed config")
	}
	if got := appendUniqueInt([]int{1, 2}, 2); len(got) != 2 {
		t.Fatalf("appendUniqueInt duplicated value: %v", got)
	}
	if got := appendUniqueInt([]int{1, 2}, 3); len(got) != 3 {
		t.Fatalf("appendUniqueInt failed to append: %v", got)
	}

	dir := t.TempDir()
	ngPath := filepath.Join(dir, "mixed.pcapng")
	writeSyntheticPCAPNG(t, ngPath)

	out, err := OpenFastPathRecords(ngPath, FastPathOptions{})
	if err != nil {
		t.Fatalf("OpenFastPathRecords(pcapng): %v", err)
	}
	if len(out.Records) != 5 {
		t.Fatalf("pcapng records = %d, want 5", len(out.Records))
	}
	// Frame 1: VLAN + IPv4 + ARP reply? Frame 1 is VLAN-tagged ARP, Frame 2 is IPv6 ICMPv6 PTB,
	// Frame 3 is STP LLC, Frame 4 is CDP LLC, Frame 5 is SPB IPv4 UDP.
	if out.Records[0].ARP == nil || *out.Records[0].ARP.Op != 2 {
		t.Fatalf("expected VLAN ARP in frame 1: %+v", out.Records[0])
	}
	if out.Records[1].ICMP == nil || !out.Records[1].ICMP.V6 || out.Records[1].DP == nil || out.Records[1].DP.ICMP == nil || *out.Records[1].DP.ICMP.MTU != 1280 {
		t.Fatalf("expected ICMPv6 PTB MTU 1280 in frame 2: %+v", out.Records[1])
	}
	if out.Records[2].LLC != "stp" || out.Records[3].LLC != "cdp" {
		t.Fatalf("expected STP and CDP LLC frames: f3=%q f4=%q", out.Records[2].LLC, out.Records[3].LLC)
	}
	if out.Records[4].UDP == nil || *out.Records[4].UDP.Dport != 9999 {
		t.Fatalf("expected SPB UDP/9999 in frame 5: %+v", out.Records[4])
	}

	// Window filtering and MaxPackets.
	since, until := 0.5, 1.5
	winOut, err := OpenFastPathRecords(ngPath, FastPathOptions{Since: &since, Until: &until})
	if err != nil || len(winOut.Records) != 1 || winOut.Records[0].N != 2 {
		t.Fatalf("window slice unexpected: err=%v recs=%+v", err, winOut.Records)
	}
	max2 := 2
	maxOut, err := OpenFastPathRecords(ngPath, FastPathOptions{MaxPackets: &max2})
	if err != nil || len(maxOut.Records) != 2 {
		t.Fatalf("max packets unexpected: err=%v len=%d", err, len(maxOut.Records))
	}

	// Special linktypes unit coverage: DLT_NULL (v4/v6), DLT_RAW, SLL, SLL2, unknown ethertype, LLC, IPv6 extensions, big-endian/ns PCAP.
	nullV4 := make([]byte, 4+28)
	binary.LittleEndian.PutUint32(nullV4[0:4], 2)
	copy(nullV4[4:], transportIPPacket("10.0.0.1", "10.0.0.2", 50, []byte{0, 0, 0, 1, 0, 0, 0, 2}))
	if rec := decodeFastFrame(1, 0, len(nullV4), nullV4, 0); rec.ESP == nil || rec.ESP.SPI != 1 {
		t.Fatalf("DLT_NULL v4 ESP failed: %+v", rec)
	}
	v6HopFrag := make([]byte, 40+8+8+8)
	v6HopFrag[0], v6HopFrag[4], v6HopFrag[5], v6HopFrag[6], v6HopFrag[7] = 0x60, 0, 24, 0, 64
	copy(v6HopFrag[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(v6HopFrag[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	v6HopFrag[40] = 44 // Hop-by-Hop -> Fragment (len=8 bytes, hdrlen field=0)
	v6HopFrag[48] = 58 // Fragment -> ICMPv6
	v6HopFrag[50], v6HopFrag[51] = 0, 0
	v6HopFrag[56], v6HopFrag[57] = 128, 0 // ICMPv6 echo req
	nullV6 := append([]byte{24, 0, 0, 0}, v6HopFrag...)
	if rec := decodeFastFrame(1, 0, len(nullV6), nullV6, 0); rec.ICMP == nil || !rec.ICMP.V6 || *rec.ICMP.Type != 128 {
		t.Fatalf("DLT_NULL v6 hop+icmpv6 failed: %+v", rec)
	}
	v6FragDrop := append([]byte(nil), v6HopFrag...)
	v6FragDrop[50] = 0x10 // non-zero fragment offset
	if rec := decodeFastFrame(1, 0, len(v6FragDrop), v6FragDrop, 101); rec.IP == nil || rec.ICMP != nil {
		t.Fatalf("DLT_RAW fragmented IPv6 should skip L4: %+v", rec)
	}
	if rec := decodeFastFrame(1, 0, 14, make([]byte, 14), 1); rec.EthType != nil {
		t.Fatalf("zero ethertype frame: %+v", rec)
	}
	unkEth := make([]byte, 18)
	binary.BigEndian.PutUint16(unkEth[12:14], 0x88cc) // LLDP
	if rec := decodeFastFrame(1, 0, 18, unkEth, 1); rec.EthType == nil || *rec.EthType != 0x88cc {
		t.Fatalf("unknown ethertype mismatch: %+v", rec)
	}
	if rec := decodeFastFrame(1, 0, 8, make([]byte, 8), 999); rec.IP != nil {
		t.Fatalf("unknown linktype should leave IP nil: %+v", rec)
	}
	// Big-endian nanosecond PCAP + FilterRecordWindow + tsresol binary unit.
	bePcap := filepath.Join(dir, "be_ns.pcap")
	var beBuf bytes.Buffer
	_ = binary.Write(&beBuf, binary.BigEndian, uint32(0xa1b23c4d))
	_ = binary.Write(&beBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(&beBuf, binary.BigEndian, uint16(4))
	beBuf.Write(make([]byte, 8))
	_ = binary.Write(&beBuf, binary.BigEndian, uint32(65535))
	_ = binary.Write(&beBuf, binary.BigEndian, uint32(101)) // DLT_RAW
	raw4 := transportIPPacket("10.0.0.1", "10.0.0.2", 17, []byte{0, 10, 0, 20, 0, 10, 0, 0, 1, 2})
	_ = binary.Write(&beBuf, binary.BigEndian, uint32(100))
	_ = binary.Write(&beBuf, binary.BigEndian, uint32(500_000_000))
	_ = binary.Write(&beBuf, binary.BigEndian, uint32(len(raw4)))
	_ = binary.Write(&beBuf, binary.BigEndian, uint32(len(raw4)))
	beBuf.Write(raw4)
	_ = os.WriteFile(bePcap, beBuf.Bytes(), 0o600)
	if beOut, err := OpenFastPathRecords(bePcap, FastPathOptions{}); err != nil || len(beOut.Records) != 1 || math.Abs(beOut.Records[0].T-100.5) > 1e-6 {
		t.Fatalf("big-endian ns PCAP failed: err=%v out=%+v", err, beOut)
	}
	if w := FilterRecordWindow([]model.Record{{N: 1, T: 1}, {N: 2, T: 2}, {N: 3, T: 3}}, &since, &until); len(w) != 1 || w[0].N != 1 {
		t.Fatalf("FilterRecordWindow failed: %+v", w)
	}
	if w := FilterRecordWindow([]model.Record{{N: 1, T: 1}}, nil, nil); len(w) != 1 {
		t.Fatalf("FilterRecordWindow nil bounds failed: %+v", w)
	}
	greICMP := make([]byte, 8+28)
	binary.BigEndian.PutUint16(greICMP[0:2], 0xb000) // C+K+S flags
	binary.BigEndian.PutUint16(greICMP[2:4], 0x0800)
	// Offset: 4 + 4(C) + 4(K) + 4(S) = 16 bytes GRE header -> resize buffer!
	greFull := make([]byte, 16+28)
	binary.BigEndian.PutUint16(greFull[0:2], 0xb000)
	binary.BigEndian.PutUint16(greFull[2:4], 0x0800)
	binary.BigEndian.PutUint32(greFull[8:12], 0x12345678)
	icmpInner := transportIPPacket("10.10.0.1", "10.10.0.2", 1, []byte{8, 0, 0, 0, 0, 1, 0, 2})
	copy(greFull[16:], icmpInner)
	_ = greICMP
	outerGRE := transportIPPacket("192.0.2.1", "192.0.2.2", 47, greFull)
	if rec := decodeFastFrame(1, 0, len(outerGRE), outerGRE, 101); rec.GRE == nil || *rec.GRE.Key != 0x12345678 || rec.ICMP == nil || !rec.ICMP.Tunneled {
		t.Fatalf("GRE C+K+S ICMP failed: %+v", rec)
	}
	if u := parseIDBTSResol([]byte{9, 0, 1, 0, 0x82, 0, 0, 0}, binary.LittleEndian); math.Abs(u-0.25) > 1e-9 {
		t.Fatalf("parseIDBTSResol binary exponent failed: %v", u)
	}
	if got := firstAddr(map[string][]string{"ipv6.src": {"2001:db8::1"}}, "ip.src", "ipv6.src"); got != "2001:db8::1" {
		t.Fatalf("firstAddr v6 fallback failed: %s", got)
	}
	if mask := maskSDPMediaAttr("key-mgmt:mikey SECRET_MIKEY_VAL"); !strings.Contains(mask, SIPCredentialMask) || strings.Contains(mask, "SECRET_MIKEY_VAL") {
		t.Fatalf("maskSDPMediaAttr leaked key-mgmt: %q", mask)
	}
	syn1 := buildSYNTCP("10.0.0.1", "10.0.0.2")
	sll := make([]byte, 16+len(syn1))
	binary.BigEndian.PutUint16(sll[14:16], 0x0800)
	copy(sll[16:], syn1)
	if rec := decodeFastFrame(1, 0, len(sll), sll, 113); rec.TCP == nil || rec.TCP.MSS == nil || *rec.TCP.MSS != 1460 {
		t.Fatalf("SLL TCP MSS failed: %+v", rec)
	}
	syn2 := buildSYNTCP("10.0.0.3", "10.0.0.4")
	sll2 := make([]byte, 20+len(syn2))
	binary.BigEndian.PutUint16(sll2[0:2], 0x0800)
	copy(sll2[20:], syn2)
	if rec := decodeFastFrame(1, 0, len(sll2), sll2, 276); rec.TCP == nil || rec.DP.TCP == nil || !rec.DP.TCP.SACK || !rec.DP.TCP.TS {
		t.Fatalf("SLL2 TCP options failed: %+v", rec)
	}

	// Error paths.
	if _, err := OpenFastPathRecords("", FastPathOptions{}); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := OpenFastPathRecords("/nonexistent/missing.pcap", FastPathOptions{}); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := OpenFastPathRecords(dir, FastPathOptions{}); err == nil {
		t.Fatal("expected error for directory")
	}
	badMagic := filepath.Join(dir, "bad.bin")
	_ = os.WriteFile(badMagic, []byte("BAD!"), 0o600)
	if _, err := OpenFastPathRecords(badMagic, FastPathOptions{}); err == nil {
		t.Fatal("expected error for invalid magic")
	}
	if rec := decodeFastFrame(1, 0, 10, []byte{0x40}, 101); rec.IP != nil {
		t.Fatalf("truncated IPv4 should leave IP nil: %+v", rec)
	}
	if rec := decodeFastFrame(1, 0, 10, []byte{0x60}, 101); rec.IP != nil {
		t.Fatalf("truncated IPv6 should leave IP nil: %+v", rec)
	}
	arp28 := make([]byte, 28)
	arp28[4], arp28[5], arp28[7] = 1, 1, 1
	if arp := decodeFastARP(arp28); arp == nil || *arp.Op != 1 {
		t.Fatalf("non-eth/ipv4 ARP fallback mismatch: %+v", arp)
	}
	if d := collectDynamicRTPDecodeSpecs([]map[string][]string{
		{"rtp.ssrc": {"0x1"}, "udp.srcport": {"12000"}, "udp.dstport": {"42000"}},
		{"sdp.media.proto": {"RTP/AVP", "TCP"}, "sdp.media.port": {"42000", "9", "99999"}},
	}); len(d) != 0 {
		t.Fatalf("already-decoded dynamic port should not trigger pass2: %v", d)
	}
	_ = appendDynamicRTPPass(context.Background(), "/nonexistent.pcap", []string{"udp.port==42000,rtp"}, nil)
}

func buildSYNTCP(src, dst string) []byte {
	tcp := make([]byte, 32)
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x80 // 32-byte header
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	// MSS(4) + SACKPerm(2) + WS(3) + NOP(1) + TS(10) -> check fits in 12 bytes: MSS(4)+SACKPerm(2)+TS(10)? Needs 16 -> use 36 bytes!
	tcp36 := make([]byte, 36)
	copy(tcp36, tcp[:20])
	tcp36[12] = 0x90 // 36 bytes
	opts := tcp36[20:]
	opts[0], opts[1] = 2, 4
	binary.BigEndian.PutUint16(opts[2:4], 1460)
	opts[4], opts[5] = 4, 2 // SACK permitted
	opts[6], opts[7] = 8, 10
	return transportIPPacket(src, dst, 6, tcp36)
}

func writeSyntheticPCAPNG(t *testing.T, outPath string) {
	t.Helper()
	var buf bytes.Buffer
	appendBlock := func(bType uint32, body []byte) {
		pad := (4 - (len(body) % 4)) % 4
		totalLen := uint32(12 + len(body) + pad)
		_ = binary.Write(&buf, binary.LittleEndian, bType)
		_ = binary.Write(&buf, binary.LittleEndian, totalLen)
		buf.Write(body)
		for range pad {
			buf.WriteByte(0)
		}
		_ = binary.Write(&buf, binary.LittleEndian, totalLen)
	}

	// SHB
	var shb bytes.Buffer
	_ = binary.Write(&shb, binary.LittleEndian, uint32(0x1a2b3c4d))
	_ = binary.Write(&shb, binary.LittleEndian, uint16(1))
	_ = binary.Write(&shb, binary.LittleEndian, uint16(0))
	_ = binary.Write(&shb, binary.LittleEndian, int64(-1))
	appendBlock(0x0a0d0d0a, shb.Bytes())

	// IDB: linkType=1, ts_resol=1e-6 (option 9 -> value 6)
	var idb bytes.Buffer
	_ = binary.Write(&idb, binary.LittleEndian, uint16(1))
	_ = binary.Write(&idb, binary.LittleEndian, uint16(0))
	_ = binary.Write(&idb, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&idb, binary.LittleEndian, uint16(9))
	_ = binary.Write(&idb, binary.LittleEndian, uint16(1))
	idb.Write([]byte{6, 0, 0, 0})
	_ = binary.Write(&idb, binary.LittleEndian, uint32(0)) // opt_endofopt
	appendBlock(0x00000001, idb.Bytes())

	appendEPB := func(tsUS uint64, frame []byte) {
		var epb bytes.Buffer
		_ = binary.Write(&epb, binary.LittleEndian, uint32(0))
		_ = binary.Write(&epb, binary.LittleEndian, uint32(tsUS>>32))
		_ = binary.Write(&epb, binary.LittleEndian, uint32(tsUS&0xffffffff))
		_ = binary.Write(&epb, binary.LittleEndian, uint32(len(frame)))
		_ = binary.Write(&epb, binary.LittleEndian, uint32(len(frame)))
		epb.Write(frame)
		appendBlock(0x00000006, epb.Bytes())
	}

	// 1. VLAN 802.1Q ARP Reply at t=0.1s.
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 2)
	s4 := netip.MustParseAddr("192.0.2.1").As4()
	d4 := netip.MustParseAddr("192.0.2.2").As4()
	copy(arp[14:18], s4[:])
	copy(arp[24:28], d4[:])
	f1 := make([]byte, 18+len(arp))
	binary.BigEndian.PutUint16(f1[12:14], 0x8100)
	binary.BigEndian.PutUint16(f1[16:18], 0x0806)
	copy(f1[18:], arp)
	appendEPB(100_000, f1)

	// 2. IPv6 ICMPv6 Packet Too Big (MTU 1280) at t=1.0s.
	v6ptb := make([]byte, 40+48)
	v6ptb[0] = 0x60
	binary.BigEndian.PutUint16(v6ptb[4:6], 48)
	v6ptb[6], v6ptb[7] = 58, 64
	copy(v6ptb[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(v6ptb[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	icmp6 := v6ptb[40:]
	icmp6[0] = 2
	binary.BigEndian.PutUint32(icmp6[4:8], 1280)
	emb := icmp6[8:]
	emb[0] = 0x60
	binary.BigEndian.PutUint16(emb[4:6], 20)
	emb[6] = 6
	copy(emb[8:24], netip.MustParseAddr("2001:db8::2").AsSlice())
	copy(emb[24:40], netip.MustParseAddr("2001:db8::9").AsSlice())
	f2 := make([]byte, 14+len(v6ptb))
	binary.BigEndian.PutUint16(f2[12:14], 0x86dd)
	copy(f2[14:], v6ptb)
	appendEPB(1_000_000, f2)

	// 3. STP LLC at t=2.0s.
	f3 := make([]byte, 20)
	binary.BigEndian.PutUint16(f3[12:14], 6)
	f3[14], f3[15] = 0x42, 0x42
	appendEPB(2_000_000, f3)

	// 4. CDP LLC/SNAP at t=3.0s.
	f4 := make([]byte, 24)
	binary.BigEndian.PutUint16(f4[12:14], 10)
	f4[14], f4[15], f4[16] = 0xaa, 0xaa, 0x03
	binary.BigEndian.PutUint16(f4[20:22], 0x2000)
	appendEPB(3_000_000, f4)

	// 5. Simple Packet Block: IPv4 UDP port 9999.
	udpPkt := transportIPPacket("10.1.1.1", "10.1.1.2", 17, func() []byte {
		u := make([]byte, 12)
		binary.BigEndian.PutUint16(u[0:2], 12345)
		binary.BigEndian.PutUint16(u[2:4], 9999)
		binary.BigEndian.PutUint16(u[4:6], 12)
		return u
	}())
	f5 := make([]byte, 14+len(udpPkt))
	binary.BigEndian.PutUint16(f5[12:14], 0x0800)
	copy(f5[14:], udpPkt)
	var spb bytes.Buffer
	_ = binary.Write(&spb, binary.LittleEndian, uint32(len(f5)))
	spb.Write(f5)
	appendBlock(0x00000003, spb.Bytes())

	if err := os.WriteFile(outPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
