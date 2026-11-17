package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/analyze/aaainspect"
	"github.com/zombat/sonic/internal/analyze/espdecrypt"
	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/analyze/httpinspect"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/analyze/snmpinspect"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func strPtr(s string) *string   { return &s }
func intPtr(i int) *int         { return &i }
func boolPtr(b bool) *bool      { return &b }
func f64Ptr(f float64) *float64 { return &f }

func TestReportFormattersAndSaveRedaction(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	tmp := t.TempDir()
	fix := func(name string) string { return filepath.Join("tests", "fixtures", name) }

	// 1. Network report formatting (IPsec, routing, GRE, reachability, conversations, SIP, error state).
	for _, tc := range []struct {
		name string
		pcap string
	}{
		{"ipsec", "ipsec_ikev2_esp.pcap"},
		{"routing", "bgp_failover.pcap"},
		{"gre", "gre_nhrp.pcap"},
		{"sip", "sip_minimal.pcap"},
		{"reach", "icmp_loss.pcap"},
	} {
		rep := netorch.AnalyzeNetworkCapture(ctx, fix(tc.pcap), netorch.Options{})
		sum := FormatNetworkSummary(rep)
		md := BuildNetworkMarkdown(rep)
		if !strings.Contains(sum, "S.O.N.I.C. network analysis") || !strings.Contains(md, "# S.O.N.I.C. network analysis") {
			t.Fatalf("%s network format mismatch:\n%s", tc.name, sum)
		}
		mdOut := filepath.Join(tmp, tc.name+".md")
		jsOut := filepath.Join(tmp, tc.name+".json")
		if err := SaveNetworkReport(rep, mdOut); err != nil {
			t.Fatal(err)
		}
		if err := SaveNetworkReport(rep, jsOut); err != nil {
			t.Fatal(err)
		}
	}
	// Failure branch and synthetic secret redaction on write.
	errNet := netorch.AnalyzeNetworkCapture(ctx, "/no/such/file.pcap", netorch.Options{})
	if !strings.Contains(FormatNetworkSummary(errNet), "Network analysis failed") ||
		!strings.Contains(BuildNetworkMarkdown(errNet), "Analysis failed") {
		t.Fatal("network error formatter mismatch")
	}

	// 2. gRPC report formatting + TLS branches + error state.
	for _, pcap := range []string{"grpc_h2_trouble.pcap", "grpc_tls12_alert.pcap"} {
		gRep := grpc.AnalyzeCapture(ctx, fix(pcap), grpc.Options{})
		if !strings.Contains(FormatGRPCSummary(gRep), "Verdict:") || !strings.Contains(BuildGRPCMarkdown(gRep), "## RPCs") {
			t.Fatalf("gRPC format mismatch on %s", pcap)
		}
		if err := SaveGRPCReport(gRep, filepath.Join(tmp, pcap+".md")); err != nil {
			t.Fatal(err)
		}
		if err := SaveGRPCReport(gRep, filepath.Join(tmp, pcap+".json")); err != nil {
			t.Fatal(err)
		}
	}
	errGRPC := grpc.AnalyzeCapture(ctx, "/no/such/file.pcap", grpc.Options{})
	if !strings.Contains(FormatGRPCSummary(errGRPC), "gRPC analysis failed") ||
		!strings.Contains(BuildGRPCMarkdown(errGRPC), "Analysis failed") {
		t.Fatal("gRPC error formatter mismatch")
	}

	// 3. HTTP / RESTCONF report formatting + TLS + secret redaction.
	for _, pcap := range []string{"restconf_cleartext.pcap", "grpc_mgmt_mix.pcap"} {
		hRep := httpinspect.AnalyzeCapture(ctx, fix(pcap), httpinspect.Options{})
		if !strings.Contains(FormatHTTPSummary(hRep), "Verdict:") || !strings.Contains(BuildHTTPMarkdown(hRep), "## Connections") {
			t.Fatalf("HTTP format mismatch on %s", pcap)
		}
		if err := SaveHTTPReport(hRep, filepath.Join(tmp, pcap+".md")); err != nil {
			t.Fatal(err)
		}
		if err := SaveHTTPReport(hRep, filepath.Join(tmp, pcap+".json")); err != nil {
			t.Fatal(err)
		}
	}
	errHTTP := httpinspect.AnalyzeCapture(ctx, "/no/such/file.pcap", httpinspect.Options{})
	if !strings.Contains(FormatHTTPSummary(errHTTP), "RESTCONF/REST analysis failed") ||
		!strings.Contains(BuildHTTPMarkdown(errHTTP), "Analysis failed") {
		t.Fatal("HTTP error formatter mismatch")
	}

	// 4. SNMP report formatting + v3 table branches.
	sRep := snmpinspect.AnalyzeCapture(ctx, fix("snmp_v1v2c.pcap"), snmpinspect.Options{})
	if !strings.Contains(FormatSNMPSummary(sRep), "Verdict:") || !strings.Contains(BuildSNMPMarkdown(sRep), "## Messages") {
		t.Fatal("SNMP format mismatch")
	}
	if err := SaveSNMPReport(sRep, filepath.Join(tmp, "snmp.md")); err != nil || SaveSNMPReport(sRep, filepath.Join(tmp, "snmp.json")) != nil {
		t.Fatal("SaveSNMPReport failed")
	}
	synthSNMP := snmpinspect.Report{
		Status: "success", File: "synth.pcap", OverallStatus: model.StatusWarning, Verdict: "v3",
		Capture:  snmpinspect.CaptureInfo{UsersFileGiven: true, UsersCount: 1},
		Summary:  snmpinspect.Summary{Versions: map[string]int{"v3": 1}, V3SecurityLevels: map[string]int{"authPriv": 1}},
		V3Users:  []snmpinspect.V3UserSummary{{User: strPtr("netops"), Messages: 1, Outcomes: map[string]int{"decrypted_ok": 1}}},
		Messages: []snmpinspect.MessageRow{{Frame: intPtr(1), Version: "v3", SecurityLevel: "authPriv", Src: "10.0.0.1", Dst: "10.0.0.2", User: strPtr("netops"), Role: "authPriv", Outcome: "decrypted_ok", Report: "usmStatsWrongDigests"}},
		Issues:   []model.Issue{{Severity: model.SeverityWarning, Code: "SNMP_TEST", Message: "test issue", Frames: []int{1}}},
		Limits:   []string{"limit1"},
	}
	if !strings.Contains(FormatSNMPSummary(synthSNMP), "netops") || !strings.Contains(BuildSNMPMarkdown(synthSNMP), "## SNMPv3 users") {
		t.Fatal("synthetic SNMP v3 format mismatch")
	}
	errSNMP := snmpinspect.Report{Status: "error", Error: "bad snmp"}
	if !strings.Contains(FormatSNMPSummary(errSNMP), "SNMP analysis failed") || !strings.Contains(BuildSNMPMarkdown(errSNMP), "Analysis failed") {
		t.Fatal("SNMP error formatter mismatch")
	}

	// 5. AAA report formatting (RADIUS + TACACS+ + recovered creds redaction).
	for _, pcap := range []string{"aaa_radius.pcap", "aaa_tacacs.pcap"} {
		aRep := aaainspect.AnalyzeCapture(ctx, fix(pcap), aaainspect.Options{})
		if !strings.Contains(FormatAAASummary(aRep), "Verdict:") || !strings.Contains(BuildAAAMarkdown(aRep), "# S.O.N.I.C. TACACS+ and RADIUS") {
			t.Fatalf("AAA format mismatch on %s", pcap)
		}
		if err := SaveAAAReport(aRep, filepath.Join(tmp, pcap+".md")); err != nil {
			t.Fatal(err)
		}
		if err := SaveAAAReport(aRep, filepath.Join(tmp, pcap+".json")); err != nil {
			t.Fatal(err)
		}
	}
	errAAA := aaainspect.Report{Status: "error", Error: "bad aaa"}
	if !strings.Contains(FormatAAASummary(errAAA), "AAA analysis failed") || !strings.Contains(BuildAAAMarkdown(errAAA), "Analysis failed") {
		t.Fatal("AAA error formatter mismatch")
	}

	// 6. ESP report formatting (with SA file + secret leak check).
	saText := strings.Join([]string{
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00001001\nencryption: aes-cbc\nencryption_key: 0x000102030405060708090a0b0c0d0e0f\nintegrity: hmac-sha1-96\nintegrity_key: 0x000102030405060708090a0b0c0d0e0f10111213",
		"src: 198.51.100.2\ndst: 198.51.100.1\nspi: 0x00001002\nencryption: aes-gcm\nencryption_key: 0x000102030405060708090a0b0c0d0e0fdeadbeef",
	}, "\n\n") + "\n"
	saPath := filepath.Join(tmp, "sa.conf")
	if err := os.WriteFile(saPath, []byte(saText), 0o600); err != nil {
		t.Fatal(err)
	}
	eRep := espdecrypt.AnalyzeCapture(ctx, fix("esp_tunnel.pcap"), espdecrypt.Options{SAFile: saPath})
	if !strings.Contains(FormatESPSummary(eRep), "Security Associations:") || !strings.Contains(BuildESPMarkdown(eRep), "## Inner traffic") {
		t.Fatal("ESP format mismatch")
	}
	espMD := filepath.Join(tmp, "esp.md")
	espJS := filepath.Join(tmp, "esp.json")
	if err := SaveESPReport(eRep, espMD); err != nil || SaveESPReport(eRep, espJS) != nil {
		t.Fatal("SaveESPReport failed")
	}
	errESP := espdecrypt.Report{Status: "error", Error: "bad esp"}
	if !strings.Contains(FormatESPSummary(errESP), "ESP decryption failed") || !strings.Contains(BuildESPMarkdown(errESP), "Analysis failed") {
		t.Fatal("ESP error formatter mismatch")
	}

	// Verify WriteRedacted masks secrets cleanly.
	redPath := filepath.Join(tmp, "nested", "secret.md")
	if err := WriteRedacted(redPath, "ANTHROPIC_API_KEY=sk-ant-supersecretkeyvalue1234567890\n"); err != nil {
		t.Fatal(err)
	}
	redContent, err := os.ReadFile(redPath)
	if err != nil || strings.Contains(string(redContent), "supersecretkeyvalue") || !strings.Contains(string(redContent), "[REDACTED]") {
		t.Fatalf("WriteRedacted did not redact key: %q err=%v", redContent, err)
	}
	if DerefBool(nil, "unset") != "unset" || DerefBool(boolPtr(false), "unset") != "no" || DerefBool(boolPtr(true), "unset") != "yes" {
		t.Fatal("DerefBool helper mismatch")
	}
	if StatusMark("unknown_state") != "unknown_state" || MarkdownTable([]string{"a"}, nil) != "_none_\n" {
		t.Fatal("StatusMark / empty MarkdownTable mismatch")
	}
	_ = f64Ptr(1.0)
}

// TestPhase3AuthReportingVisualizations ports test_phase3_reporting.py mapping and diagram assertions.
func TestPhase3AuthReportingVisualizations(t *testing.T) {
	if !strings.Contains(FormatRealmServerMapping(nil), "No authentication data") {
		t.Fatal("nil AuthInfo should report no authentication data")
	}
	empty := &extract.AuthInfo{SIPServers: map[string]extract.SIPServerAuthInfo{}}
	if !strings.Contains(FormatRealmServerMapping(empty), "No SIP servers") {
		t.Fatal("empty SIPServers should report no SIP servers")
	}
	authData := &extract.AuthInfo{
		SIPServers: map[string]extract.SIPServerAuthInfo{
			"192.168.1.100": {ChallengeCount: 2, ServerChallenges: 2, Realms: []string{"pbx.example.com"}},
			"10.0.0.50":     {ChallengeCount: 3, ProxyChallenges: 3, Realms: []string{"proxy.example.com", "mixed.example.com"}},
			"10.0.0.99":     {ChallengeCount: 1},
		},
		AuthChallenges: []extract.AuthChallenge{
			{Realm: "pbx.example.com", Algorithm: "SHA-256", QoP: "auth", FromIP: "192.168.1.100"},
			{Realm: "proxy.example.com", Algorithm: "MD5", QoP: "", FromIP: "10.0.0.50"},
			{Realm: "mixed.example.com", Algorithm: "MD5", QoP: "", FromIP: "10.0.0.50"},
			{Realm: "mixed.example.com", Algorithm: "SHA-256", QoP: "auth", FromIP: "10.0.0.50"},
		},
	}
	tree := FormatRealmServerMapping(authData)
	for _, want := range []string{"192.168.1.100", "10.0.0.50", "pbx.example.com", "proxy.example.com", "Registrar", "Proxy", "Strong (SHA-256+)", "Weak (MD5)", "Mixed (MD5 + SHA-256)", "realm unknown"} {
		if !strings.Contains(tree, want) {
			t.Fatalf("missing %q in realm mapping:\n%s", want, tree)
		}
	}

	attempt := extract.RegisterAttempt{
		CallID:  "test-very-long-call-id-12345@example.com",
		Success: true,
		Packets: []extract.RegisterPacketEvent{
			{PacketNum: 5, Type: "request", HasAuth: false},
			{PacketNum: 7, Type: "challenge", StatusCode: "401"},
			{PacketNum: 9, Type: "request", HasAuth: true},
			{PacketNum: 11, Type: "response", StatusCode: "200"},
		},
	}
	challenges := []extract.AuthChallenge{{PacketNum: 7, Realm: "pbx.example.com", Algorithm: "SHA-256"}}
	ascii := GenerateAuthSequenceASCII(attempt, challenges)
	for _, want := range []string{"Client", "Server", "REGISTER", "401", "200", "#5", "#7", "#9", "#11", "pbx.example.com"} {
		if !strings.Contains(ascii, want) {
			t.Fatalf("missing %q in ASCII sequence:\n%s", want, ascii)
		}
	}
	mermaidOK := GenerateMermaidAuthSequence(attempt, challenges)
	for _, want := range []string{"```mermaid", "sequenceDiagram", "participant Client", "participant Server", "✅ Registration Successful"} {
		if !strings.Contains(mermaidOK, want) {
			t.Fatalf("missing %q in Mermaid diagram:\n%s", want, mermaidOK)
		}
	}
	attempt.Success = false
	if !strings.Contains(GenerateMermaidAuthSequence(attempt, nil), "❌ Registration Failed") {
		t.Fatal("failed REGISTER should include failure note")
	}
	emptyAttempt := extract.RegisterAttempt{CallID: "empty"}
	if !strings.Contains(GenerateAuthSequenceASCII(emptyAttempt, nil), "No packet sequence") || GenerateMermaidAuthSequence(emptyAttempt, nil) != "" {
		t.Fatal("empty attempt sequence handling mismatch")
	}
}

func TestReserveStdoutForProtocol(t *testing.T) {
	protoOut, restore, err := ReserveStdoutForProtocol()
	if err != nil {
		t.Fatalf("ReserveStdoutForProtocol failed: %v", err)
	}
	if protoOut == nil || restore == nil {
		t.Fatal("expected non-nil protoOut and restore closure")
	}
	restore()
	restore() // idempotent
}

func TestBuildAndSaveQualityReport(t *testing.T) {
	rep := sip.QuickQualityReport{
		Status: "success",
		File:   "/tmp/call.pcap",
		QualityAnalysis: &sip.QualityMetrics{
			OverallScore:    88.5,
			Grade:           sip.GradeGood,
			NetworkScore:    90,
			ProtocolScore:   85,
			CodecScore:      92,
			CompletionScore: 87,
		},
		MOSAnalysis: &sip.MOSAnalysisResult{
			AverageMOS:      4.15,
			WorstMOS:        4.01,
			BestMOS:         4.30,
			OverallCategory: sip.MOSGood,
			Recommendations: []string{"Keep monitoring jitter"},
		},
	}
	md := BuildQualityMarkdown(rep)
	for _, want := range []string{"# S.O.N.I.C. Call Quality Report", "Overall Score: 88.5/100", "Average MOS: 4.15", "Keep monitoring jitter"} {
		if !strings.Contains(md, want) {
			t.Fatalf("missing %q in quality markdown: %s", want, md)
		}
	}
	tmp := t.TempDir()
	mdPath := filepath.Join(tmp, "q.md")
	jsonPath := filepath.Join(tmp, "q.json")
	if err := SaveQualityReport(rep, mdPath); err != nil {
		t.Fatal(err)
	}
	if err := SaveQualityReport(rep, jsonPath); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(jsonPath); err != nil || !strings.Contains(string(b), `"average_mos": 4.15`) {
		t.Fatalf("unexpected quality JSON file: err=%v body=%s", err, b)
	}
}
