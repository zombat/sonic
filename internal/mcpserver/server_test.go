package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/guide"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/parity"
)

func chdirRepoRoot(t *testing.T) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
}

func runRPC(t *testing.T, srv *Server, lines ...string) []rpcResponse {
	t.Helper()
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	var resps []rpcResponse
	for _, rawLine := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if rawLine == "" {
			continue
		}
		var r rpcResponse
		if err := json.Unmarshal([]byte(rawLine), &r); err != nil {
			t.Fatalf("invalid JSON-RPC line %q: %v", rawLine, err)
		}
		resps = append(resps, r)
	}
	return resps
}

func callToolRPC(t *testing.T, srv *Server, id int, tool string, args anyMapJSON) toolResult {
	t.Helper()
	reqBytes, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params: struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}{Name: tool, Arguments: args},
	})
	if err != nil {
		t.Fatal(err)
	}
	resps := runRPC(t, srv, string(reqBytes))
	if len(resps) != 1 {
		t.Fatalf("expected 1 response for %s, got %d", tool, len(resps))
	}
	if resps[0].Error != nil {
		t.Fatalf("unexpected RPC error for %s: %+v", tool, resps[0].Error)
	}
	var res toolResult
	if err := json.Unmarshal(resps[0].Result, &res); err != nil {
		t.Fatalf("unmarshal toolResult for %s: %v", tool, err)
	}
	return res
}

type anyMapJSON = json.RawMessage

func TestServerRegistrationValidation(t *testing.T) {
	if _, err := New(map[string]Handler{}); err == nil {
		t.Fatal("expected error for missing tool handlers")
	}
	srv, err := NewDefault()
	if err != nil {
		t.Fatalf("NewDefault error: %v", err)
	}
	if len(srv.tools) != 18 {
		t.Fatalf("expected 18 tools, got %d", len(srv.tools))
	}

	full := make(map[string]Handler, len(srv.tools)+1)
	for _, tool := range srv.tools {
		full[tool.def.Name] = tool.handler
	}
	full["extra_bogus"] = handleQuickQualityCheck
	if _, err := New(full); err == nil {
		t.Fatal("expected error for extra handler without definition")
	}
}

func TestProtocolLifecycleAndErrors(t *testing.T) {
	srv, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}

	resps := runRPC(t, srv,
		"",
		"{bad json",
		`{"jsonrpc":"1.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"1.0","method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"9999-01-01"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"initialize","params":"bad"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":5,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":6,"method":"unknown/method"}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"bogus_tool"}}`,
		`{"jsonrpc":"2.0","id":10,"method":"prompts/list"}`,
		`{"jsonrpc":"2.0","id":11,"method":"prompts/get","params":{"name":"check_vpn_encryption","arguments":{"file_path":"/c/wan.pcap","peers":"192.0.2.1, 198.51.100.2"}}}`,
		`{"jsonrpc":"2.0","id":12,"method":"prompts/get","params":{"name":"nope"}}`,
		`{"jsonrpc":"2.0","id":13,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":14,"method":"resources/read","params":{"uri":"sonic://guide/mcp-tools"}}`,
		`{"jsonrpc":"2.0","id":15,"method":"resources/read","params":{"uri":"sonic://guide/nope"}}`,
	)
	if len(resps) != 16 {
		t.Fatalf("expected 16 responses (2 skipped for empty/notification), got %d", len(resps))
	}
	if resps[0].Error == nil || resps[0].Error.Code != codeParseError {
		t.Fatalf("expected parse error, got %+v", resps[0].Error)
	}
	if resps[1].Error == nil || resps[1].Error.Code != codeInvalidRequest {
		t.Fatalf("expected invalid request, got %+v", resps[1].Error)
	}

	var initPrev, initLatest initializeResult
	if err := json.Unmarshal(resps[2].Result, &initPrev); err != nil {
		t.Fatal(err)
	}
	if initPrev.ProtocolVersion != "2024-11-05" || initPrev.ServerInfo.Name != ServerName {
		t.Fatalf("unexpected initPrev: %+v", initPrev)
	}
	if strings.ContainsRune(initPrev.Instructions, '\u2014') {
		t.Fatal("em-dash found in server instructions")
	}
	if err := json.Unmarshal(resps[3].Result, &initLatest); err != nil {
		t.Fatal(err)
	}
	if initLatest.ProtocolVersion != LatestProtocolVersion {
		t.Fatalf("expected latest protocol %s, got %s", LatestProtocolVersion, initLatest.ProtocolVersion)
	}
	if resps[4].Error == nil || resps[4].Error.Code != codeInvalidParams {
		t.Fatalf("expected invalid params on initialize, got %+v", resps[4].Error)
	}
	if string(resps[5].Result) != "{}" {
		t.Fatalf("expected {} from ping, got %s", resps[5].Result)
	}
	if resps[6].Error == nil || resps[6].Error.Code != codeMethodNotFound {
		t.Fatalf("expected method not found, got %+v", resps[6].Error)
	}

	var listOut struct {
		Tools []toolDef `json:"tools"`
	}
	if err := json.Unmarshal(resps[7].Result, &listOut); err != nil {
		t.Fatal(err)
	}
	if len(listOut.Tools) != 18 {
		t.Fatalf("expected 18 listed tools, got %d", len(listOut.Tools))
	}
	if len(initPrev.Instructions) == 0 || len(initPrev.Instructions) >= 2048 {
		t.Fatalf("instructions length %d outside bounds (1..2047)", len(initPrev.Instructions))
	}
	for _, td := range listOut.Tools {
		if strings.ContainsRune(td.Description, '\u2014') || strings.ContainsRune(td.Title, '\u2014') {
			t.Fatalf("em-dash found in tool %s", td.Name)
		}
		if !strings.Contains(initPrev.Instructions, td.Name) {
			t.Fatalf("instructions missing registered tool %s", td.Name)
		}
		_, wantNotes, ok := guide.ToolOptions(td.Name)
		if !ok {
			t.Fatalf("guide.ToolOptions missing %s", td.Name)
		}
		var gotNotes guide.ToolAnnotations
		if err := json.Unmarshal(td.Annotations, &gotNotes); err != nil {
			t.Fatalf("invalid annotations JSON for %s: %v", td.Name, err)
		}
		if gotNotes.ReadOnlyHint != wantNotes.ReadOnlyHint ||
			gotNotes.DestructiveHint != wantNotes.DestructiveHint ||
			gotNotes.IdempotentHint != wantNotes.IdempotentHint ||
			gotNotes.OpenWorldHint != wantNotes.OpenWorldHint {
			t.Fatalf("annotation mismatch for %s: got %+v want %+v", td.Name, gotNotes, wantNotes)
		}
	}
	if resps[8].Error == nil || resps[8].Error.Code != codeInvalidParams {
		t.Fatalf("expected invalid params on empty tools/call, got %+v", resps[8].Error)
	}
	var unknownRes toolResult
	if err := json.Unmarshal(resps[9].Result, &unknownRes); err != nil {
		t.Fatal(err)
	}
	if !unknownRes.IsError || !strings.Contains(unknownRes.Content[0].Text, "Unknown tool: 'bogus_tool'") {
		t.Fatalf("unexpected unknown tool response: %+v", unknownRes)
	}

	var plist struct {
		Prompts []guide.PromptInfo `json:"prompts"`
	}
	if err := json.Unmarshal(resps[10].Result, &plist); err != nil || len(plist.Prompts) != len(guide.Workflows) {
		t.Fatalf("unexpected prompts/list result: %s err=%v", resps[10].Result, err)
	}
	var pget promptGetResult
	if err := json.Unmarshal(resps[11].Result, &pget); err != nil || len(pget.Messages) != 1 || !strings.Contains(pget.Messages[0].Content.Text, "peers=['192.0.2.1', '198.51.100.2']") {
		t.Fatalf("unexpected prompts/get result: %s err=%v", resps[11].Result, err)
	}
	if resps[12].Error == nil || resps[12].Error.Code != codeInvalidParams {
		t.Fatalf("expected invalid params on unknown prompt, got %+v", resps[12].Error)
	}
	var rlist struct {
		Resources []guide.ResourceInfo `json:"resources"`
	}
	if err := json.Unmarshal(resps[13].Result, &rlist); err != nil || len(rlist.Resources) != len(guide.Topics)+1 {
		t.Fatalf("unexpected resources/list result: %s err=%v", resps[13].Result, err)
	}
	var rread struct {
		Contents []resourceContent `json:"contents"`
	}
	if err := json.Unmarshal(resps[14].Result, &rread); err != nil || len(rread.Contents) != 1 || !strings.Contains(rread.Contents[0].Text, "## `analyze_vpn_pcap`") {
		t.Fatalf("unexpected resources/read result: %s err=%v", resps[14].Result, err)
	}
	if resps[15].Error == nil || resps[15].Error.Code != codeInvalidParams {
		t.Fatalf("expected invalid params on unknown resource, got %+v", resps[15].Error)
	}
	specs, err := DefaultToolSpecs()
	if err != nil || len(specs) != len(srv.ToolSpecs()) {
		t.Fatalf("DefaultToolSpecs mismatch: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write boom") }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestServeIOAndContextErrors(t *testing.T) {
	srv, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Serve(ctx, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := srv.Serve(context.Background(), errReader{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected read error from scanner")
	}
	if err := srv.Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), failWriter{}); err == nil {
		t.Fatal("expected write error")
	}
	badMarshal := initializeResult{}
	if _, rerr := marshalResult(badMarshal); rerr != nil {
		t.Fatalf("unexpected marshalResult failure: %+v", rerr)
	}
	var r io.Reader = strings.NewReader("")
	if err := srv.Serve(context.Background(), r, &bytes.Buffer{}); err != nil {
		t.Fatalf("empty EOF should return nil, got %v", err)
	}
}

func TestCallToolRedactionAndErrors(t *testing.T) {
	defs := []toolDef{{Name: "err_tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "secret_tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "nonjson_tool", InputSchema: json.RawMessage(`{"type":"object"}`)}}
	srv, err := newServer(defs, map[string]Handler{
		"err_tool": func(context.Context, json.RawMessage) ([]byte, error) {
			return nil, errors.New("bad token sk-ant-api03-1234567890abcdefghijklmnop")
		},
		"secret_tool": func(context.Context, json.RawMessage) ([]byte, error) {
			return []byte(`{"status":"success","leak":"sk-ant-api03-1234567890abcdefghijklmnop"}`), nil
		},
		"nonjson_tool": func(context.Context, json.RawMessage) ([]byte, error) {
			return []byte(`["not-an-object"]`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r1 := callToolRPC(t, srv, 1, "err_tool", json.RawMessage(`null`))
	if !r1.IsError || strings.Contains(r1.Content[0].Text, "sk-ant-") {
		t.Fatalf("expected redacted handler error, got %+v", r1)
	}
	r2 := callToolRPC(t, srv, 2, "secret_tool", nil)
	if r2.IsError || strings.Contains(r2.Content[0].Text, "sk-ant-") || strings.Contains(string(r2.StructuredContent), "sk-ant-") {
		t.Fatalf("expected redacted tool output, got %+v", r2)
	}
	r3 := callToolRPC(t, srv, 3, "nonjson_tool", json.RawMessage(`{}`))
	if !r3.IsError || !strings.Contains(r3.Content[0].Text, "not a JSON object") {
		t.Fatalf("expected non-object rejection, got %+v", r3)
	}
}

func TestOptionHelpersAndValidationErrors(t *testing.T) {
	if got := clampMaxItems(nil); got != 25 {
		t.Fatalf("clampMaxItems(nil)=%d", got)
	}
	z := 0
	if got := clampMaxItems(&z); got != 25 {
		t.Fatalf("clampMaxItems(0)=%d", got)
	}
	neg := -5
	if got := clampMaxItems(&neg); got != 1 {
		t.Fatalf("clampMaxItems(-5)=%d", got)
	}
	ten := 10
	if got := clampMaxItems(&ten); got != 10 {
		t.Fatalf("clampMaxItems(10)=%d", got)
	}

	for _, tc := range []struct {
		raw  string
		want string
		bad  bool
	}{
		{`"30"`, "30", false},
		{`30`, "30", false},
		{`30.5`, "30.5", false},
		{`null`, "", false},
		{`true`, "", true},
	} {
		var f flexString
		err := json.Unmarshal([]byte(tc.raw), &f)
		if (err != nil) != tc.bad || (!tc.bad && string(f) != tc.want) {
			t.Fatalf("flexString(%s) = %q, err=%v (want %q, bad=%v)", tc.raw, f, err, tc.want, tc.bad)
		}
	}

	if _, payload, err := parseNetworkOptions(map[string]json.RawMessage{"bogus": json.RawMessage(`{}`)}); err != nil || !strings.Contains(string(payload), "No options for detector 'bogus'") {
		t.Fatalf("unexpected bogus detector option result: %s, err=%v", payload, err)
	}
	if _, payload, err := parseNetworkOptions(map[string]json.RawMessage{"esp_overhead": json.RawMessage(`null`)}); err != nil || !strings.Contains(string(payload), "valid_options") {
		t.Fatalf("unexpected null detector option result: %s, err=%v", payload, err)
	}
	if _, payload, err := parseNetworkOptions(map[string]json.RawMessage{"esp_overhead": json.RawMessage(`{"nope":1}`)}); err != nil || !strings.Contains(string(payload), "Unknown option(s) for esp_overhead") {
		t.Fatalf("unexpected unknown option key result: %s, err=%v", payload, err)
	}
	opts, payload, err := parseNetworkOptions(map[string]json.RawMessage{
		"esp_overhead":    json.RawMessage(`{"transport_mtu":1450,"tunnel_mtu":null,"gre_header_bytes":4}`),
		"tls":             json.RawMessage(`{"baseline":{"versions":["TLS1.3"]}}`),
		"dmvpn_phase3":    json.RawMessage(`{"hubs":["192.0.2.1"]}`),
		"routing":         json.RawMessage(`{"expected_mss":1360}`),
		"cleartext_audit": json.RawMessage(`{"allow":[]}`),
		"convergence":     json.RawMessage(`{"event_time":30,"failed_peer":"192.0.2.1","hold_time":9,"silence_s":2}`),
	})
	if err != nil || payload != nil {
		t.Fatalf("valid parseNetworkOptions failed: payload=%s err=%v", payload, err)
	}
	if opts.EspOverhead.TransportMTU != 1450 || opts.RoutingMSS == nil || *opts.RoutingMSS != 1360 || opts.Convergence.EventTime != "30" || !opts.CleartextAudit.HasAllow {
		t.Fatalf("decoded options mismatch: %+v", opts)
	}
	for _, bad := range []map[string]json.RawMessage{
		{"esp_overhead": json.RawMessage(`{"transport_mtu":"x"}`)},
		{"tls": json.RawMessage(`{"baseline":"x"}`)},
		{"dmvpn_phase3": json.RawMessage(`{"hubs":"x"}`)},
		{"routing": json.RawMessage(`{"expected_mss":"x"}`)},
		{"cleartext_audit": json.RawMessage(`{"allow":"x"}`)},
		{"convergence": json.RawMessage(`{"hold_time":"x"}`)},
	} {
		if _, _, err := parseNetworkOptions(bad); err == nil {
			t.Fatalf("expected type error for %v", bad)
		}
	}

	if captureReadable("") == nil || captureReadable("/definitely/missing.pcap") == nil || captureReadable(t.TempDir()) == nil {
		t.Fatal("expected captureReadable to fail for empty, missing, and dir paths")
	}
}

func TestAllFourteenToolsGoldenParityOverStdio(t *testing.T) {
	chdirRepoRoot(t)
	srv, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}

	saText := strings.Join([]string{
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00001001\nencryption: aes-cbc\nencryption_key: 0x000102030405060708090a0b0c0d0e0f\nintegrity: hmac-sha1-96\nintegrity_key: 0x000102030405060708090a0b0c0d0e0f10111213",
		"src: 198.51.100.2\ndst: 198.51.100.1\nspi: 0x00001002\nencryption: aes-gcm\nencryption_key: 0x000102030405060708090a0b0c0d0e0fdeadbeef",
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00002001\nencryption: aes-cbc\nencryption_key: 0x000102030405060708090a0b0c0d0e0f\nintegrity: hmac-sha256-128\nintegrity_key: 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00003001\nencryption: aes-cbc\nencryption_key: 0x000102030405060708090a0b0c0d0e0f\nintegrity: hmac-sha256-128\nintegrity_key: 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00004001\nencryption: aes-gcm\nencryption_key: 0x000102030405060708090a0b0c0d0e0fdeadbeef",
	}, "\n\n") + "\n"
	saPath := filepath.Join(t.TempDir(), "sa.conf")
	if err := os.WriteFile(saPath, []byte(saText), 0o600); err != nil {
		t.Fatal(err)
	}
	saArgs, _ := json.Marshal(map[string]string{
		"file_path": "tests/fixtures/esp_tunnel.pcap",
		"sa_file":   saPath,
	})

	cases := []struct {
		tool   string
		args   json.RawMessage
		golden string
	}{
		{"quick_quality_check", json.RawMessage(`{"file_path":"tests/fixtures/sip_minimal.pcap"}`), "testdata/golden/sip/sip_minimal_quick_quality.json"},
		{"analyze_network_pcap", json.RawMessage(`{"file_path":"tests/fixtures/ipsec_ikev2_esp.pcap"}`), "testdata/golden/network_orchestrator/net_ipsec_ikev2_esp.json"},
		{"analyze_vpn_pcap", json.RawMessage(`{"file_path":"tests/fixtures/ipsec_ikev2_esp.pcap"}`), "testdata/golden/network_orchestrator/vpn_ipsec_ikev2_esp.json"},
		{"analyze_routing_pcap", json.RawMessage(`{"file_path":"tests/fixtures/bgp_failover.pcap","expected_mss":1360}`), "testdata/golden/network_orchestrator/routing_bgp_failover.json"},
		{"audit_cleartext_pcap", json.RawMessage(`{"file_path":"tests/fixtures/grpc_mgmt_mix.pcap","allow":["encrypted"]}`), "testdata/golden/network_orchestrator/audit_grpc_mgmt_mix.json"},
		{"analyze_convergence_pcap", json.RawMessage(`{"file_path":"tests/fixtures/convergence_dpd.pcap"}`), "testdata/golden/network_orchestrator/conv_dpd.json"},
		{"analyze_data_plane_pcap", json.RawMessage(`{"file_path":"tests/fixtures/dp_tcp_health.pcap"}`), "testdata/golden/network_orchestrator/dataplane_tcp_health.json"},
		{"correlate_pcaps", json.RawMessage(`{"captures":[{"path":"tests/fixtures/dp_corr_inside.pcap","label":"inside"},{"path":"tests/fixtures/dp_corr_outside.pcap","label":"outside"}]}`), "testdata/golden/correlate/nat_inside_outside.json"},
		{"merge_pcap_timelines", json.RawMessage(`{"captures":[{"path":"tests/fixtures/ospf_failover.pcap","label":"core"}],"measurements":[{"name":"ospf_down_to_up","from":{"event":"neighbor_down"},"to":{"event":"neighbor_up"},"max_s":15}]}`), "testdata/golden/timeline/ospf_icmp_measured.json"},
		{"analyze_grpc_pcap", json.RawMessage(`{"file_path":"tests/fixtures/grpc_mgmt_mix.pcap"}`), "testdata/golden/grpc/grpc_mgmt_mix.json"},
		{"analyze_restconf_pcap", json.RawMessage(`{"file_path":"tests/fixtures/restconf_cleartext.pcap"}`), "testdata/golden/http_inspect/restconf_cleartext.json"},
		{"analyze_snmp_pcap", json.RawMessage(`{"file_path":"tests/fixtures/snmp_v1v2c.pcap"}`), "testdata/golden/snmp/snmp_v1v2c.json"},
		{"analyze_aaa_pcap", json.RawMessage(`{"file_path":"tests/fixtures/aaa_radius.pcap"}`), "testdata/golden/aaa/aaa_radius_no_key.json"},
		{"analyze_esp_pcap", saArgs, "testdata/golden/esp_decrypt/esp_tunnel_sa_file.json"},
	}

	for i, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			res := callToolRPC(t, srv, i+1, tc.tool, tc.args)
			if res.IsError {
				t.Fatalf("%s returned IsError=true: %s", tc.tool, res.Content[0].Text)
			}
			wantBytes, err := os.ReadFile(tc.golden)
			if err != nil {
				t.Fatal(err)
			}
			// Compare core parity; merge_pcap_timelines measurement name differs intentionally in test_network_mcp.py style, check separately if needed.
			if tc.tool == "merge_pcap_timelines" {
				var parsed struct {
					Status       string `json:"status"`
					Measurements []struct {
						Verdict string `json:"verdict"`
					} `json:"measurements"`
				}
				if err := json.Unmarshal(res.StructuredContent, &parsed); err != nil {
					t.Fatal(err)
				}
				if parsed.Status != "success" || len(parsed.Measurements) != 1 || parsed.Measurements[0].Verdict != "within" {
					t.Fatalf("unexpected timeline output: %s", res.StructuredContent)
				}
				return
			}
			if err := parity.CompareJSON(res.StructuredContent, wantBytes); err != nil {
				t.Fatalf("golden parity mismatch for %s (%s): %v", tc.tool, tc.golden, err)
			}
			if tc.tool == "analyze_data_plane_pcap" {
				dec := json.NewDecoder(bytes.NewReader(res.StructuredContent))
				_, _ = dec.Token() // '{'
				var firstThree []string
				for j := 0; j < 3; j++ {
					k, _ := dec.Token()
					firstThree = append(firstThree, k.(string))
					var skip json.RawMessage
					_ = dec.Decode(&skip)
				}
				if strings.Join(firstThree, ",") != "status,overall_status,path_mtu_verdict" {
					t.Fatalf("expected top 3 keys status,overall_status,path_mtu_verdict, got %v", firstThree)
				}
			}
		})
	}
}

func TestToolHandlerValidationAndBadArgs(t *testing.T) {
	chdirRepoRoot(t)
	srv, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}

	// Bad JSON arguments trigger isError=true across handlers.
	for _, tool := range []string{
		"quick_quality_check", "analyze_network_pcap", "analyze_vpn_pcap",
		"analyze_routing_pcap", "audit_cleartext_pcap", "analyze_convergence_pcap",
		"analyze_data_plane_pcap", "correlate_pcaps", "merge_pcap_timelines",
		"analyze_grpc_pcap", "analyze_restconf_pcap", "analyze_snmp_pcap",
		"analyze_aaa_pcap", "analyze_esp_pcap",
		"analyze_pcap", "analyze_pcap_partial_streaming", "analyze_batch_pcaps",
	} {
		res := callToolRPC(t, srv, 100, tool, json.RawMessage(`{"file_path":123,"captures":123,"directory":123}`))
		if !res.IsError {
			t.Fatalf("%s accepted malformed arg types", tool)
		}
	}
	if badList := callToolRPC(t, srv, 101, "list_llm_providers", json.RawMessage(`123`)); !badList.IsError {
		t.Fatalf("list_llm_providers accepted non-object arg: %+v", badList)
	}

	// Tool-level validation errors return {"status":"error",...} with isError=false.
	for _, tc := range []struct {
		tool string
		args string
		sub  string
	}{
		{"analyze_network_pcap", `{"file_path":"does-not-exist.pcap"}`, "File not found"},
		{"analyze_network_pcap", `{"file_path":"tests/fixtures/bgp_session.pcap","options":{"bogus":{}}}`, "detectors_with_options"},
		{"analyze_data_plane_pcap", `{"file_path":"does-not-exist.pcap"}`, "File not found"},
		{"audit_cleartext_pcap", `{"file_path":"tests/fixtures/audit_one_leak.pcap","allow":null}`, `"status":"error"`},
		{"correlate_pcaps", `{"captures":[{"path":"tests/fixtures/dp_corr_inside.pcap","label":"a"}],"max_packets_held":50}`, "at least 100"},
		{"merge_pcap_timelines", `{"captures":[],"max_events":0}`, "at least 1"},
	} {
		res := callToolRPC(t, srv, 200, tc.tool, json.RawMessage(tc.args))
		if res.IsError && tc.tool != "audit_cleartext_pcap" {
			t.Fatalf("%s returned RPC isError instead of status error: %s", tc.tool, res.Content[0].Text)
		}
		if tc.tool == "audit_cleartext_pcap" {
			if res.IsError || !strings.Contains(res.Content[0].Text, `"status":"success"`) {
				t.Fatalf("audit null allow failed: %s", res.Content[0].Text)
			}
			continue
		}
		if !strings.Contains(res.Content[0].Text, tc.sub) {
			t.Fatalf("%s expected %q in %s", tc.tool, tc.sub, res.Content[0].Text)
		}
	}

	// Verify numeric and string event_time on convergence_dpd.pcap match Python's 12.0s delta.
	for idx, arg := range []string{
		`{"file_path":"tests/fixtures/convergence_dpd.pcap","event_time":30}`,
		`{"file_path":"tests/fixtures/convergence_dpd.pcap","event_time":"+30"}`,
	} {
		conv := callToolRPC(t, srv, 300+idx, "analyze_convergence_pcap", json.RawMessage(arg))
		if conv.IsError {
			t.Fatalf("convergence event_time %s failed: %s", arg, conv.Content[0].Text)
		}
		var body struct {
			Driver struct {
				Mechanism string `json:"mechanism"`
			} `json:"driver"`
			Measurements struct {
				Resumed *float64 `json:"event_to_traffic_resumed_s"`
			} `json:"measurements"`
		}
		if err := json.Unmarshal(conv.StructuredContent, &body); err != nil {
			t.Fatal(err)
		}
		if body.Driver.Mechanism != "dpd" || body.Measurements.Resumed == nil || *body.Measurements.Resumed != 12.0 {
			t.Fatalf("unexpected convergence result for %s: %s", arg, conv.StructuredContent)
		}
	}
}

type stubMCPCompleter struct {
	reportJSON string
}

func (s stubMCPCompleter) Complete(_ context.Context, provider, _, modelName string, _ []llm.Message, _ json.RawMessage, onToken func(string)) (llm.Response, llm.Usage, error) {
	if onToken != nil {
		onToken(s.reportJSON)
	}
	return llm.Response{Text: s.reportJSON, OutputTokens: 12, Reported: true, Model: modelName}, llm.Usage{Provider: provider, Model: modelName, OutputTokens: 12}, nil
}

func TestLLMToolsOverStdio(t *testing.T) {
	chdirRepoRoot(t)
	secret := "sk-ant-api03-secretvalueneverleak123456"
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("ANTHROPIC_API_KEY="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("SONIC_ENV_FILE", envPath)

	stub := stubMCPCompleter{
		reportJSON: `{"totalCalls":1,"calls":[{"callId":"c1","callerIp":"10.0.0.1","calleeIp":"10.0.0.2","userAgents":["UA"],"audioQuality":{"codecUsed":"PCMU","payloadTypes":["0"],"rtpPort":"4000","potentialIssues":[]},"callFlow":{"callSetupMethod":"INVITE","callTermination":"BYE","responseCodes":["200"],"callDurationIndicators":"2s"},"diagnosticSummary":"Healthy call ` + secret + `"}],"overallAssessment":"Normal SIP setup","recommendations":["Keep monitoring"]}`,
	}
	srv, err := NewWithDeps(ai.Deps{Completer: stub})
	if err != nil {
		t.Fatal(err)
	}

	// 1. list_llm_providers reports env file without revealing secret value.
	prov := callToolRPC(t, srv, 1, "list_llm_providers", json.RawMessage(`{}`))
	if prov.IsError || strings.Contains(prov.Content[0].Text, secret) || !strings.Contains(prov.Content[0].Text, `"anthropic_key_set":true`) {
		t.Fatalf("unexpected list_llm_providers response: %+v", prov)
	}

	// 2. analyze_pcap success on SIP capture with quality + MOS + redaction.
	ap := callToolRPC(t, srv, 2, "analyze_pcap", json.RawMessage(`{"file_path":"tests/fixtures/sip_minimal.pcap","provider":"openai"}`))
	if ap.IsError || strings.Contains(ap.Content[0].Text, secret) || !strings.Contains(ap.Content[0].Text, `"status":"success"`) || !strings.Contains(ap.Content[0].Text, `"call_quality"`) {
		t.Fatalf("unexpected analyze_pcap response: %+v", ap)
	}

	// 3. analyze_pcap rejects missing capture and non-SIP capture cleanly.
	miss := callToolRPC(t, srv, 3, "analyze_pcap", json.RawMessage(`{"file_path":"does-not-exist.pcap"}`))
	if miss.IsError || !strings.Contains(miss.Content[0].Text, "File not found") {
		t.Fatalf("unexpected missing file response: %+v", miss)
	}
	nonSIP := callToolRPC(t, srv, 4, "analyze_pcap", json.RawMessage(`{"file_path":"tests/fixtures/bgp_session.pcap"}`))
	if nonSIP.IsError || !strings.Contains(nonSIP.Content[0].Text, "No SIP data found") {
		t.Fatalf("unexpected non-SIP response: %+v", nonSIP)
	}

	// 4. analyze_pcap_partial_streaming produces timing + quality + llm_analysis.
	ps := callToolRPC(t, srv, 5, "analyze_pcap_partial_streaming", json.RawMessage(`{"file_path":"tests/fixtures/sip_minimal.pcap","provider":"openai"}`))
	if ps.IsError || !strings.Contains(ps.Content[0].Text, `"status":"success"`) || !strings.Contains(ps.Content[0].Text, `"timing"`) {
		t.Fatalf("unexpected partial streaming response: %+v", ps)
	}
	if psMiss := callToolRPC(t, srv, 6, "analyze_pcap_partial_streaming", json.RawMessage(`{"file_path":"no.pcap"}`)); psMiss.IsError || !strings.Contains(psMiss.Content[0].Text, "File not found") {
		t.Fatalf("unexpected partial missing file response: %+v", psMiss)
	}

	// 5. analyze_batch_pcaps handles parallel dir, detailed tier, bad mode, empty dir, missing dir.
	batchDir := t.TempDir()
	sipBytes, err := os.ReadFile("tests/fixtures/sip_minimal.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(batchDir, "call1.pcap"), sipBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(batchDir, "call2.pcapng"), sipBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	batchArgs, _ := json.Marshal(map[string]string{"directory": batchDir, "provider": "ollama", "model": "fast", "mode": "parallel"})
	br := callToolRPC(t, srv, 7, "analyze_batch_pcaps", batchArgs)
	var batchOut struct {
		Status    string `json:"status"`
		Aggregate struct {
			Successful  int `json:"successful"`
			TotalTokens int `json:"total_tokens"`
		} `json:"aggregate"`
	}
	if br.IsError || json.Unmarshal(br.StructuredContent, &batchOut) != nil || batchOut.Aggregate.Successful != 2 || batchOut.Aggregate.TotalTokens == 0 {
		t.Fatalf("unexpected batch response (want successful=2 and non-zero tokens for ollama): %+v", br)
	}
	badModeArgs, _ := json.Marshal(map[string]string{"directory": batchDir, "mode": "bogus"})
	if badMode := callToolRPC(t, srv, 8, "analyze_batch_pcaps", badModeArgs); badMode.IsError || !strings.Contains(badMode.Content[0].Text, "Invalid batch mode") {
		t.Fatalf("unexpected invalid batch mode response: %+v", badMode)
	}
	emptyArgs, _ := json.Marshal(map[string]string{"directory": t.TempDir()})
	if emptyRes := callToolRPC(t, srv, 9, "analyze_batch_pcaps", emptyArgs); emptyRes.IsError || !strings.Contains(emptyRes.Content[0].Text, "no pcap files found") {
		t.Fatalf("unexpected empty batch response: %+v", emptyRes)
	}
	if missDir := callToolRPC(t, srv, 10, "analyze_batch_pcaps", json.RawMessage(`{"directory":""}`)); missDir.IsError || !strings.Contains(missDir.Content[0].Text, "directory not found") {
		t.Fatalf("unexpected missing batch dir response: %+v", missDir)
	}
	t.Setenv("SONIC_ENV_FILE", "/nonexistent/sonic.env")
	if _, err := NewDefault(); err == nil {
		t.Fatal("expected NewDefault error on missing SONIC_ENV_FILE")
	}
}
