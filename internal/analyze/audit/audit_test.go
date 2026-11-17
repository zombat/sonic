package audit

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
)

func TestGoldenCleartextAuditParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	cases := []struct {
		name   string
		pcap   string
		golden string
		allow  []string
	}{
		{"audit_one_leak", "audit_one_leak", "audit_one_leak", nil},
		{"ipsec_cleartext_icmp", "ipsec_cleartext_icmp", "ipsec_cleartext_icmp", nil},
		{"ipsec_ikev2_esp", "ipsec_ikev2_esp", "ipsec_ikev2_esp", nil},
		{"ipsec_natt", "ipsec_natt", "ipsec_natt", nil},
		{"enc_midstream", "enc_midstream", "enc_midstream", nil},
		{"enc_port22_text", "enc_port22_text", "enc_port22_text", nil},
		{"enc_ssh_cbc", "enc_ssh_cbc", "enc_ssh_cbc", nil},
		{"enc_ssh_none", "enc_ssh_none", "enc_ssh_none", nil},
		{"enc_tls10", "enc_tls10", "enc_tls10", nil},
		{"enc_tls12_null", "enc_tls12_null", "enc_tls12_null", nil},
		{"enc_tls13_integrity_only", "enc_tls13_integrity_only", "enc_tls13_integrity_only", nil},
		{"audit_one_leak_allow_crypto", "audit_one_leak", "audit_one_leak_allow_crypto", []string{"crypto"}},
		{"enc_tls10_allow_crypto", "enc_tls10", "enc_tls10_allow_crypto", []string{"crypto"}},
	}

	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join("tests", "fixtures", tc.pcap+".pcap")
			goldenPath := filepath.Join("testdata", "golden", "cleartext_audit", tc.golden+".json")
			got, err := AuditCleartextCapture(ctx, AuditOptions{
				FilePath: pcapPath,
				Allow:    tc.allow,
			})
			if err != nil {
				t.Fatalf("AuditCleartextCapture(%s): %v", pcapPath, err)
			}
			parity.CompareGolden(t, got, goldenPath)
		})
	}
}

func TestAllowlistParsingAndMatching(t *testing.T) {
	t.Parallel()

	texts, rules, err := ParseAllowlist([]string{
		"routing",
		"tcp:8080@10.0.0.0/8",
		"udp:5000@2001:db8::1",
		"proto:89",
		"ethertype:0x9000",
	})
	if err != nil || len(texts) != 5 || len(rules) != 5 {
		t.Fatalf("ParseAllowlist failed: texts=%v rules=%d err=%v", texts, len(rules), err)
	}
	if !rules[1].Matches(map[string]bool{"tcp:8080": true}, []string{"10.1.2.3"}) {
		t.Fatal("scoped tcp rule should match 10.1.2.3")
	}
	if rules[1].Matches(map[string]bool{"tcp:8080": true}, []string{"192.0.2.1"}) {
		t.Fatal("scoped tcp rule should not match 192.0.2.1")
	}
	if !rules[4].Matches(map[string]bool{"ethertype:0x9000": true}, nil) {
		t.Fatal("ethertype rule should match 0x9000")
	}

	badTokens := []string{"bogus", "tcp:abc", "ethertype:xyz", "ethertype:", "icmp@not-ip", "proto:"}
	for _, bad := range badTokens {
		if _, _, err := ParseAllowlist([]string{bad}); err == nil {
			t.Fatalf("expected error for invalid token %q", bad)
		}
	}
}

func TestSSHCipherEmptyCaptureAndFragments(t *testing.T) {
	t.Parallel()

	// Empty detector emits AUDIT_EMPTY_CAPTURE failure.
	det, err := NewDetector(nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyRep := det.Report(model.Context{MaxItems: 25}, "empty.pcap", model.CaptureInfo{Backend: "tshark"}, nil)
	if emptyRep.Passed || len(emptyRep.Issues) != 1 || emptyRep.Issues[0].Code != "AUDIT_EMPTY_CAPTURE" {
		t.Fatalf("unexpected empty capture report: %+v", emptyRep)
	}

	// Verify SSHCipher covers weak/unverified/cleartext/strong families.
	str := func(s string) *string { return &s }
	if st, _ := SSHCipher(nil); st != tlsinspect.StateUnverified {
		t.Fatalf("SSHCipher(nil) = %v, want unverified", st)
	}
	if st, _ := SSHCipher(str("none")); st != tlsinspect.StateCleartext {
		t.Fatalf("SSHCipher(none) = %v, want cleartext", st)
	}
	if st, _ := SSHCipher(str("arcfour128")); st != tlsinspect.StateWeak {
		t.Fatalf("SSHCipher(arcfour128) = %v, want weak", st)
	}
	if st, _ := SSHCipher(str("blowfish-cbc")); st != tlsinspect.StateWeak {
		t.Fatalf("SSHCipher(blowfish-cbc) = %v, want weak", st)
	}
	if st, _ := SSHCipher(str("blowfish")); st != tlsinspect.StateWeak {
		t.Fatalf("SSHCipher(blowfish) = %v, want weak", st)
	}
	if st, _ := SSHCipher(str("chacha20-poly1305@openssh.com")); st != tlsinspect.StateEncrypted {
		t.Fatalf("SSHCipher(chacha20) = %v, want encrypted", st)
	}
	if st, _ := SSHCipher(str("custom-cipher")); st != tlsinspect.StateUnverified {
		t.Fatalf("SSHCipher(custom) = %v, want unverified", st)
	}

	// Non-first IP fragment follows allowed first fragment with matching IP id.
	fragDet, err := NewDetector([]string{"udp:5002"})
	if err != nil {
		t.Fatal(err)
	}
	proto17 := 17
	idVal := 4242
	mf1, mf0 := 1, 0
	p1, p2 := 5001, 5002
	fragDet.Feed(&model.Record{
		N: 1, T: 1.0, Len: 1500,
		IP:  &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: &proto17},
		UDP: &model.UDPHeader{Sport: &p1, Dport: &p2, Len: 3000},
		DP:  &model.DataPlane{ID: &idVal, MF: &mf1, Off: 0},
	})
	fragDet.Feed(&model.Record{
		N: 2, T: 1.01, Len: 1500,
		IP: &model.IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2", Proto: &proto17},
		DP: &model.DataPlane{ID: &idVal, MF: &mf0, Off: 1480},
	})
	fragRep := fragDet.Report(model.Context{MaxItems: 25}, "frag.pcap", model.CaptureInfo{Backend: "tshark"}, nil)
	if !fragRep.Passed || fragRep.FramesAllowed != 2 {
		t.Fatalf("fragment datagram tracking failed: %+v", fragRep)
	}

	if _, err := AuditCleartextCapture(context.Background(), AuditOptions{FilePath: "no-such.pcap"}); err == nil {
		t.Fatal("expected error for missing pcap")
	}
}

func FuzzParseAllowlist(f *testing.F) {
	f.Add("encrypted")
	f.Add("tcp:443@10.0.0.0/8,192.168.1.1")
	f.Add("ethertype:0x9000")
	f.Add("bad:token")
	f.Fuzz(func(t *testing.T, token string) {
		_, _, _ = ParseAllowlist([]string{token})
	})
}

func FuzzParseKexInit(f *testing.F) {
	var seed []byte
	seed = append(seed, 20)
	seed = append(seed, make([]byte, 16)...)
	for i := 0; i < 8; i++ {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, 3)
		seed = append(seed, lenBuf...)
		seed = append(seed, 'a', ',', 'b')
	}
	f.Add(seed)
	f.Add([]byte{20, 1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseKexInit(data)
	})
}

func TestProtocolTokensHTTP2AHAndTLSContinuation(t *testing.T) {
	t.Parallel()

	det, err := NewDetector([]string{"encrypted"})
	if err != nil {
		t.Fatal(err)
	}
	intp := func(v int) *int { return &v }
	strp := func(v string) *string { return &v }

	// HTTP/2 cleartext management session.
	p1, p2 := 55000, 50051
	proto6 := 6
	det.Feed(&model.Record{
		N: 1, T: 1.0, Len: 80,
		IP:  &model.IPHeader{V: 4, Src: "10.1.0.1", Dst: "10.1.0.2", Proto: &proto6},
		TCP: &model.TCPHeader{Sport: &p1, Dport: &p2, Flags: 2, Len: 24},
		DP:  &model.DataPlane{TCP: &model.DPTCP{Seq: 100}, PL: "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"},
	})

	// AH frame (proto 51) + unknown EtherType + GRE wrapping OSPF + NETCONF port 830 midstream ciphertext.
	det.Feed(&model.Record{N: 2, T: 1.1, Len: 64, IP: &model.IPHeader{V: 4, Src: "10.1.0.1", Dst: "10.1.0.2", Proto: intp(51)}})
	det.Feed(&model.Record{N: 3, T: 1.2, Len: 60, EthType: intp(0x9001)})
	det.Feed(&model.Record{
		N: 4, T: 1.3, Len: 90,
		IP:    &model.IPHeader{V: 4, Src: "10.1.0.1", Dst: "10.1.0.2", Proto: intp(47)},
		GRE:   &model.GREHeader{Ptype: intp(0x0800)},
		Inner: &model.InnerPacket{Src: "172.16.0.1", Dst: "224.0.0.5", OSPF: &model.OSPFPacket{}},
	})

	// Multi-segment TLS record spanning two TCP segments cleanly (hello continuing without new header).
	p443 := 443
	det.Feed(&model.Record{
		N: 5, T: 1.4, Len: 120,
		IP:  &model.IPHeader{V: 4, Src: "10.2.0.1", Dst: "10.2.0.2", Proto: &proto6},
		TCP: &model.TCPHeader{Sport: &p1, Dport: &p443, Flags: 0x18, Len: 40},
		DP:  &model.DataPlane{TCP: &model.DPTCP{Seq: 1000}, PL: "16030300230100001f"},
	})
	det.Feed(&model.Record{
		N: 6, T: 1.5, Len: 100,
		IP:  &model.IPHeader{V: 4, Src: "10.2.0.1", Dst: "10.2.0.2", Proto: &proto6},
		TCP: &model.TCPHeader{Sport: &p1, Dport: &p443, Flags: 0x18, Len: 20},
		DP:  &model.DataPlane{TCP: &model.DPTCP{Seq: 1020}, PL: "aabbccdd"},
	})

	// Missing one-side KEXINIT + MAC=none evaluation branches.
	sess := newTCPSession(true)
	c := endpointAddr{"10.0.0.1", 50000}
	s := endpointAddr{"10.0.0.2", 830}
	dc := newDirection(1, false)
	dc.kexinit = map[string][]string{
		"cipher_client_to_server": {"aes128-ctr"},
		"cipher_server_to_client": {"aes128-ctr"},
		"mac_client_to_server":    {"none"},
		"mac_server_to_client":    {"hmac-sha2-256"},
	}
	sess.dirs[c] = dc
	missingEnc, _ := evaluateSSHEncryption(sess, c, s)
	if missingEnc.State != "unverified" {
		t.Fatalf("missing server KEXINIT state = %s, want unverified", missingEnc.State)
	}
	ds := newDirection(1, false)
	ds.kexinit = map[string][]string{
		"cipher_client_to_server": {"aes128-ctr"},
		"cipher_server_to_client": {"aes128-ctr"},
		"mac_client_to_server":    {"none"},
		"mac_server_to_client":    {"hmac-sha2-256"},
	}
	sess.dirs[s] = ds
	weakMacEnc, _ := evaluateSSHEncryption(sess, c, s)
	if weakMacEnc.State != "weak" {
		t.Fatalf("MAC none SSH state = %s, want weak", weakMacEnc.State)
	}

	if lbl, cat, _ := SessionLabel("ssh", intp(830)); lbl != "netconf over ssh (tcp/830)" || cat != "encrypted" {
		t.Fatalf("SessionLabel(830) = (%q, %q)", lbl, cat)
	}
	if tok, name, cat := TokensFor(&model.Record{}); len(tok) == 0 || name != "other" || cat != "layer2" {
		t.Fatal("TokensFor empty fallback should return other")
	}

	rep := det.Report(model.Context{Start: new(1.0), End: new(1.5), MaxItems: 25}, "mix.pcap", model.CaptureInfo{Backend: "tshark"}, nil)
	if rep.Passed || rep.Protection["authenticated_only"] != 1 {
		t.Fatalf("unexpected mixed report: passed=%v prot=%v", rep.Passed, rep.Protection)
	}
	_ = strp
}

func TestAddGrpcFindingsAndGoldenMix(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	pcap := filepath.Join("tests", "fixtures", "grpc_mgmt_mix.pcap")
	rep, err := AuditCleartextCapture(ctx, AuditOptions{FilePath: pcap})
	if err != nil {
		t.Fatalf("AuditCleartextCapture: %v", err)
	}
	AddGrpcFindings(ctx, &rep, pcap, "", nil)
	parity.CompareGolden(t, rep, filepath.Join("testdata", "golden", "network_orchestrator", "audit_grpc_mgmt_mix.json"))

	// Error and no-op branches.
	AddGrpcFindings(ctx, nil, pcap, "", nil)
	noH2 := model.AuditReport{Status: "success"}
	AddGrpcFindings(ctx, &noH2, pcap, "", nil)
	if noH2.Grpc != nil {
		t.Fatalf("expected no Grpc summary when no HTTP/2 sessions exist")
	}
	errRep := model.AuditReport{
		Status:      "success",
		TCPSessions: []model.TCPSession{{Protocol: "http2 (tcp/50001)"}},
	}
	AddGrpcFindings(ctx, &errRep, filepath.Join("tests", "fixtures", "missing.pcap"), "", nil)
	if errRep.Grpc == nil || errRep.Grpc.Checked || errRep.Grpc.Error == "" {
		t.Fatalf("expected checked=false error on missing capture: %+v", errRep.Grpc)
	}
}
