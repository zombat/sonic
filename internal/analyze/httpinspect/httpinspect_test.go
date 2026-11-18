package httpinspect

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
)

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }

func TestGoldenHTTPInspectParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	cases := []struct {
		name   string
		pcap   string
		golden string
	}{
		{name: "restconf_cleartext", pcap: "restconf_cleartext.pcap", golden: "restconf_cleartext.json"},
		{name: "dp_tls", pcap: "dp_tls.pcap", golden: "dp_tls.json"},
		{name: "grpc_mgmt_mix", pcap: "grpc_mgmt_mix.pcap", golden: "grpc_mgmt_mix.json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeCapture(context.Background(), filepath.Join("testdata", "fixtures", tc.pcap), Options{})
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "http_inspect", tc.golden))

			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			for _, secret := range []string{
				"restconf-pass-not-real",
				"restconf-token-0000-not-real",
				"gnmi-bearer-token-not-real",
			} {
				if strings.Contains(text, secret) {
					t.Fatalf("secret %q leaked into report JSON", secret)
				}
			}
		})
	}
}

func TestParseRestconfErrors(t *testing.T) {
	if got := ParseRestconfErrors(nil, ""); len(got) != 0 {
		t.Fatalf("expected empty on nil body: %v", got)
	}
	jsonSingle := []byte(`{"ietf-restconf:errors":{"error":{"error-type":"protocol","error-tag":"invalid-value","error-app-tag":"bad-leaf","error-message":"bad","extra":true}}}`)
	errs := ParseRestconfErrors(jsonSingle, "application/yang-data+json")
	if len(errs) != 1 || errs[0]["error-tag"] != "invalid-value" || errs[0]["error-app-tag"] != "bad-leaf" {
		t.Fatalf("unexpected JSON single error: %v", errs)
	}
	jsonNoCT := []byte(`{"errors":{"error":[{"error-type":"application","error-tag":"operation-failed"}]}}`)
	errs = ParseRestconfErrors(jsonNoCT, "")
	if len(errs) != 1 || errs[0]["error-type"] != "application" {
		t.Fatalf("unexpected fallback JSON error: %v", errs)
	}
	if got := ParseRestconfErrors([]byte(`not-json`), "application/json"); len(got) != 0 {
		t.Fatalf("expected empty on invalid JSON: %v", got)
	}
	if got := ParseRestconfErrors([]byte(`["list"]`), "application/json"); len(got) != 0 {
		t.Fatalf("expected empty on JSON array: %v", got)
	}

	xmlErr := []byte(`<errors xmlns="urn:ietf:params:xml:ns:yang:ietf-restconf"><error><error-type>protocol</error-type><error-tag>data-missing</error-tag><error-message> missing leaf </error-message></error></errors>`)
	errs = ParseRestconfErrors(xmlErr, "application/yang-data+xml")
	if len(errs) != 1 || errs[0]["error-tag"] != "data-missing" || errs[0]["error-message"] != "missing leaf" {
		t.Fatalf("unexpected XML error: %v", errs)
	}
	if got := ParseRestconfErrors([]byte(`<broken`), "application/xml"); len(got) != 0 {
		t.Fatalf("expected empty on malformed XML: %v", got)
	}
}

func TestValidationAndCoverage(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	rcPcap := filepath.Join("testdata", "fixtures", "restconf_cleartext.pcap")
	dpTLS := filepath.Join("testdata", "fixtures", "dp_tls.pcap")

	assertErr := func(r Report, substr string) {
		t.Helper()
		if r.Status != "error" || !strings.Contains(r.Error, substr) {
			t.Fatalf("expected error containing %q, got status=%q err=%q", substr, r.Status, r.Error)
		}
		raw, err := json.Marshal(r)
		if err != nil || !strings.Contains(string(raw), `"status":"error"`) || strings.Contains(string(raw), `"schema"`) {
			t.Fatalf("unexpected error JSON: %s err=%v", raw, err)
		}
	}

	assertErr(AnalyzeCapture(ctx, "", Options{}), "File not found")
	assertErr(AnalyzeCapture(ctx, filepath.Join("testdata", "fixtures", "no_such.pcap"), Options{}), "File not found")
	assertErr(AnalyzeCapture(ctx, t.TempDir(), Options{}), "File not readable")
	assertErr(AnalyzeCapture(ctx, rcPcap, Options{KeylogFile: t.TempDir()}), "keylog_file is not a readable file")
	assertErr(AnalyzeCapture(ctx, rcPcap, Options{MaxPackets: intPtr(0)}), "max_packets must be a positive number")
	assertErr(AnalyzeCapture(ctx, rcPcap, Options{Ports: []int{70000}}), "Not a TCP port")

	// Empty filtered run tests "no HTTP found" verdict.
	empty := AnalyzeCapture(ctx, rcPcap, Options{DisplayFilter: "tcp.port==65530"})
	if empty.Status != "success" || !strings.Contains(empty.Verdict, "No HTTP, RESTCONF or REST found") {
		t.Fatalf("unexpected empty verdict: %+v", empty)
	}

	// Wrong-session keylog on dp_tls triggers TLS_SESSION_NOT_DECRYPTED and keylog coverage reason.
	kl := filepath.Join(t.TempDir(), "other.keylog")
	line := "CLIENT_RANDOM " + strings.Repeat("aa", 32) + " " + strings.Repeat("bb", 48) + "\n"
	if err := os.WriteFile(kl, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongKL := AnalyzeCapture(ctx, dpTLS, Options{KeylogFile: kl, Ports: []int{8443}, MaxItems: 5})
	if wrongKL.Status != "success" || wrongKL.TLSDecryption == nil || wrongKL.TLSDecryption.Decrypted >= wrongKL.TLSDecryption.Total {
		t.Fatalf("expected partial/un-decrypted TLS report, got %+v", wrongKL.TLSDecryption)
	}
	foundTLSIssue := false
	for _, iss := range wrongKL.Issues {
		if iss.Code == "TLS_SESSION_NOT_DECRYPTED" {
			foundTLSIssue = true
			break
		}
	}
	if !foundTLSIssue || len(wrongKL.TLSDecryption.Sessions) == 0 {
		t.Fatalf("expected TLS_SESSION_NOT_DECRYPTED issue in %+v", wrongKL.Issues)
	}

	// PCAPNG with minimal DSB exercises secretsView DSB branch and TLS_SECRETS_IN_CAPTURE alert.
	pcapngPath := writeMinimalPCAPNGWithDSB(t, line)
	sv := secretsView(pcapngPath, kl)
	if sv.PCAPNGBlocks != 1 || sv.Source == nil || !strings.Contains(*sv.Source, "and") {
		t.Fatalf("unexpected secretsView for DSB+keylog: %+v", sv)
	}
	var dsbIssues []model.Issue
	appendTLSDecryptIssues(&TLSDecryptionSummary{Sessions: []TLSSessionRow{{Flow: "f", Service: "tcp/443", Decrypted: false, ClientHelloFrame: intPtr(1), Reason: strPtr("mismatch")}}}, sv, true, &dsbIssues)
	if len(dsbIssues) != 2 || dsbIssues[1].Code != "TLS_SECRETS_IN_CAPTURE" {
		t.Fatalf("unexpected DSB/decrypt issues: %+v", dsbIssues)
	}

	// Synthetic buildHTTP, mergeTLSDecryption, verdict, and pairStream edge coverage.
	cov := decryptionCoverage(ctx, map[int]*extract.TCPConnection{
		0: {Index: 0, FirstFrame: 1, A: extract.Endpoint{IP: "10.0.0.1", Port: 1}, B: extract.Endpoint{IP: "10.0.0.2", Port: 443}, TLSClientHello: intPtr(1)},
	}, dpTLS, nil, "", secretsInfo{}, "", nil, 10)
	if cov.Total != 1 {
		t.Fatalf("unexpected synthetic coverage: %+v", cov)
	}
	dstMap := map[int]*extract.TLSDecryptionInfo{
		0: {ApplicationData: []string{"http"}},
	}
	mergeTLSDecryption(dstMap, 0, &extract.TLSDecryptionInfo{Handshake: true, ClientRandom: strPtr("dead"), ApplicationData: []string{"h2", "http"}})
	mergeTLSDecryption(dstMap, 2, &extract.TLSDecryptionInfo{Handshake: true})
	if !dstMap[0].Handshake || len(dstMap[0].ApplicationData) != 2 || dstMap[0].ClientRandom == nil || !dstMap[2].Handshake {
		t.Fatalf("unexpected mergeTLSDecryption: %+v", dstMap)
	}
	if v := tlsCoverageVerdict(nil, 0, nil, nil); !strings.Contains(v, "No TLS session") {
		t.Fatalf("unexpected empty TLS verdict: %s", v)
	}
	if hv := httpVerdict([]ConnectionRow{{Transport: "tls (no key log)"}}, nil, nil, false); !strings.Contains(hv, "no request decoded") {
		t.Fatalf("unexpected un-decoded HTTP verdict: %s", hv)
	}
	assertErr(AnalyzeCapture(ctx, rcPcap, Options{DisplayFilter: "bad=="}), "tshark")

	_, _, _ = buildHTTP(map[int]*extract.TCPConnection{
		0: {Index: 0, FirstFrame: 1, A: extract.Endpoint{IP: "10.0.0.1", Port: 1}, B: extract.Endpoint{IP: "10.0.0.2", Port: 80}},
	}, []extract.HTTPMessage{
		{TCPStream: 0, Frame: 5, IsRequest: true, Method: strPtr("GET"), URI: strPtr("/restconf/data/x"), ContentType: strPtr("application/yang-data+json"), HasCookie: true},
		{TCPStream: 0, Frame: 6, IsRequest: false, Status: intPtr(500), ContentType: strPtr("application/yang-data+json"), RequestFrame: intPtr(5), Body: []byte(`{"ietf-restconf:errors":{"error":[{"error-tag":"invalid-value","error-message":true,"error-path":null,"error-app-tag":false,"error-type":42}]}}`)},
		{TCPStream: 0, Frame: 7, IsRequest: false, Status: intPtr(102)},
	}, false, nil)
	if v := httpOutcome(&extract.HTTPMessage{Status: intPtr(102)}); v != "other" {
		t.Fatalf("expected other outcome, got %s", v)
	}
	if lbl := transportLabel(&extract.TCPConnection{TLSClientHello: intPtr(1)}, true, true); lbl != "tls (decrypted)" {
		t.Fatalf("unexpected transportLabel: %s", lbl)
	}

	// Synthetic unit tests for error paths, IPv6 flow formatting, verdicts, and scrubbing.
	v6Conn := &extract.TCPConnection{
		Index:  1,
		Client: &extract.Endpoint{IP: "2001:db8::1", Port: 50000},
		Server: &extract.Endpoint{IP: "2001:db8::2", Port: 443},
	}
	if got := connectionFlow(v6Conn); got != "[2001:db8::1]:50000 -> [2001:db8::2]:443" {
		t.Fatalf("unexpected IPv6 flow: %s", got)
	}

	reqNoResp := RequestRow{
		Flow: "10.0.0.1:1 -> 10.0.0.2:443", Service: "tcp/443", Transport: "tls (decrypted)",
		Method: strPtr("GET"), Path: strPtr("/secret-token/data"), Outcome: "no_response",
		Credentials: []extract.HTTPCredentialFlag{{Header: "Authorization", Kind: "authorization", Scheme: strPtr("Bearer"), Value: "masked"}},
		Frames:      FramesRef{Request: intPtr(10)},
	}
	req500 := RequestRow{
		Flow: "10.0.0.1:2 -> 10.0.0.2:80", Service: "tcp/80", Transport: "cleartext",
		Method: strPtr("POST"), Path: strPtr("/api"), Status: intPtr(503), Phrase: strPtr("Unavailable"), Outcome: "server_error",
		Frames: FramesRef{Request: intPtr(20), Response: intPtr(21)},
	}
	req401 := RequestRow{
		Flow: "10.0.0.1:2 -> 10.0.0.2:80", Service: "tcp/80", Transport: "cleartext",
		Method: strPtr("GET"), Path: strPtr("/api"), Status: intPtr(418), Phrase: strPtr("Teapot"), Outcome: "client_error",
		Frames: FramesRef{Request: intPtr(22), Response: intPtr(23)},
	}
	req505 := RequestRow{
		Flow: "10.0.0.1:2 -> 10.0.0.2:80", Service: "tcp/80", Transport: "cleartext",
		Status: intPtr(505), Outcome: "server_error",
	}
	var issues []model.Issue
	appendRequestIssues(reqNoResp, "f1", &issues)
	appendRequestIssues(req500, "f2", &issues)
	appendRequestIssues(req401, "f2", &issues)
	appendRequestIssues(req505, "f2", &issues)
	if len(issues) != 5 {
		t.Fatalf("expected 5 synthetic request issues, got %d", len(issues))
	}

	rep := Report{
		Verdict: "leak secret-token",
		Capture: CaptureInfo{Warnings: []string{"warn secret-token"}},
		Connections: []ConnectionRow{{
			Transport: "tls (decrypted)",
			SNI:       strPtr("host.secret-token.local"),
			Decrypted: new(bool),
		}},
		Requests: []RequestRow{reqNoResp},
		Issues:   issues,
	}
	rep.Requests[0].RestconfErrors = []map[string]string{{"error-message": "bad secret-token"}}
	*rep.Connections[0].Decrypted = true
	scrubReport(&rep, []string{"secret-token"})
	if strings.Contains(rep.Verdict+*rep.Connections[0].SNI+*rep.Requests[0].Path+rep.Requests[0].RestconfErrors[0]["error-message"], "secret-token") {
		t.Fatal("scrubReport did not redact secret-token")
	}

	if r := tlsFailureReason(nil, nil, nil, "the key log"); r == nil || !strings.Contains(*r, "no ClientHello") {
		t.Fatalf("unexpected missing-CH reason: %v", r)
	}
	if r := tlsFailureReason(nil, intPtr(5), nil, "the key log"); r == nil || !strings.Contains(*r, "reassembled") {
		t.Fatalf("unexpected unreassembled reason: %v", r)
	}
	if r := tlsFailureReason(strPtr("ab"), intPtr(5), &randomSecretInfo{labels: map[string]bool{"CLIENT_RANDOM": true}}, "the key log"); r == nil || !strings.Contains(*r, "tshark did not decrypt") {
		t.Fatalf("unexpected fallback reason: %v", r)
	}
}

func writeMinimalPCAPNGWithDSB(t *testing.T, keylog string) string {
	t.Helper()
	// SHB (type 0x0a0d0d0a, len 28, byte-order magic 0x1a2b3c4d) + TLS DSB (type 0x0000000a, secrets type 0x544c534b).
	var buf []byte
	shb := make([]byte, 28)
	binary.LittleEndian.PutUint32(shb[0:4], 0x0a0d0d0a)
	binary.LittleEndian.PutUint32(shb[4:8], 28)
	binary.LittleEndian.PutUint32(shb[8:12], 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(shb[12:14], 1)
	binary.LittleEndian.PutUint32(shb[24:28], 28)
	buf = append(buf, shb...)

	pad := (4 - (len(keylog) % 4)) % 4
	dsbLen := 12 + 8 + len(keylog) + pad
	dsb := make([]byte, dsbLen)
	binary.LittleEndian.PutUint32(dsb[0:4], 0x0000000a)
	binary.LittleEndian.PutUint32(dsb[4:8], uint32(dsbLen))
	binary.LittleEndian.PutUint32(dsb[8:12], 0x544c534b)
	binary.LittleEndian.PutUint32(dsb[12:16], uint32(len(keylog)))
	copy(dsb[16:], keylog)
	binary.LittleEndian.PutUint32(dsb[dsbLen-4:], uint32(dsbLen))
	buf = append(buf, dsb...)

	p := filepath.Join(t.TempDir(), "dsb.pcapng")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
