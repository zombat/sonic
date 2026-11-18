package extract

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestHTTP2AndHTTPMessagesExtraction(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	if HeaderKind(":path") != "shown" || HeaderKind("x-api-key") != "credential" || HeaderKind("x-custom") != "masked" {
		t.Fatal("HeaderKind classification mismatch")
	}
	if !IsRestconf("/restconf/data/x") || !IsRestconf("/api", "application/yang-data+json") || IsRestconf("/api/status", "application/json") {
		t.Fatal("IsRestconf mismatch")
	}
	if len(ProtobufOptions([]string{"/tmp/protos"})) == 0 {
		t.Fatal("expected non-empty ProtobufOptions")
	}

	ctx := context.Background()
	rcPcap := filepath.Join("testdata", "fixtures", "restconf_cleartext.pcap")
	conns, err := Discover(ctx, rcPcap, "", nil, nil, nil)
	if err != nil || len(conns) != 3 {
		t.Fatalf("Discover(restconf_cleartext): len=%d err=%v", len(conns), err)
	}
	decOpts, reasons := PlanHTTPDecodeAs(conns, nil)
	if len(decOpts) == 0 || reasons[8081] != "h2c" {
		t.Fatalf("PlanHTTPDecodeAs: opts=%v reasons=%v", decOpts, reasons)
	}
	if _, h2Reasons := PlanDecodeAs(conns, []int{9999}); h2Reasons[9999] != "requested" {
		t.Fatalf("PlanDecodeAs extra port: %v", h2Reasons)
	}

	http1, h1Secrets, err := HTTP1Messages(ctx, rcPcap, decOpts, "", "", nil, true)
	if err != nil || len(http1) == 0 || !h1Secrets["restconf-pass-not-real"] && len(h1Secrets) == 0 {
		t.Fatalf("HTTP1Messages: len=%d secrets=%v err=%v", len(http1), h1Secrets, err)
	}
	wanted := map[int]bool{}
	for idx := range conns {
		wanted[idx] = true
	}
	http2, h2Secrets, pktCnt, _, err := HTTP2Messages(ctx, rcPcap, decOpts, wanted, "", "", nil, true)
	if err != nil || pktCnt == 0 || len(http2) == 0 || !h2Secrets["restconf-token-0000-not-real"] {
		t.Fatalf("HTTP2Messages: len=%d pkts=%d secrets=%v err=%v", len(http2), pktCnt, h2Secrets, err)
	}

	dpTLS := filepath.Join("testdata", "fixtures", "dp_tls.pcap")
	tlsConns, err := Discover(ctx, dpTLS, "", nil, nil, nil)
	if err != nil || len(tlsConns) == 0 {
		t.Fatalf("Discover(dp_tls): len=%d err=%v", len(tlsConns), err)
	}
	tlsDec, _ := PlanHTTPDecodeAs(tlsConns, nil)
	decInfo, err := TLSDecryption(ctx, dpTLS, tlsDec, "", "", nil, true)
	if err != nil || len(decInfo) == 0 {
		t.Fatalf("TLSDecryption(dp_tls): len=%d err=%v", len(decInfo), err)
	}

	maxPkt := 20
	fltConns, err := Discover(ctx, rcPcap, "tcp", &maxPkt, nil, []int{8081})
	if err != nil || len(fltConns) == 0 {
		t.Fatalf("Discover filtered: len=%d err=%v", len(fltConns), err)
	}
	pre := FindPrefaces(ctx, rcPcap, "tcp", nil)
	if len(pre) == 0 {
		t.Fatal("expected prefaces in restconf_cleartext.pcap")
	}
	grpcPcap := filepath.Join("testdata", "fixtures", "grpc_mgmt_mix.pcap")
	if grpcConns, gErr := Discover(ctx, grpcPcap, "", nil, nil, nil); gErr == nil {
		if opts, r := PlanDecodeAs(grpcConns, []int{443}); len(opts) == 0 || r[443] == "" {
			t.Fatalf("PlanDecodeAs grpc_mgmt_mix: opts=%v reasons=%v", opts, r)
		}
		if _, r := PlanHTTPDecodeAs(grpcConns, []int{50001}); r[50001] == "" {
			t.Fatalf("PlanHTTPDecodeAs grpc_mgmt_mix: reasons=%v", r)
		}
	}
}

func strPtr(s string) *string { return &s }

func TestHTTPCredentialFlagJSONAndUnitEdges(t *testing.T) {
	bAuth, err := json.Marshal(HTTPCredentialFlag{Header: "Authorization", Kind: "authorization", Value: "masked"})
	if err != nil || string(bAuth) != `{"header":"Authorization","kind":"authorization","scheme":null,"value":"masked"}` {
		t.Fatalf("auth json mismatch: %s err=%v", bAuth, err)
	}
	bTok, err := json.Marshal(HTTPCredentialFlag{Header: "x-auth-token", Kind: "token", Value: "masked"})
	if err != nil || string(bTok) != `{"header":"x-auth-token","kind":"token","value":"masked"}` {
		t.Fatalf("token json mismatch: %s err=%v", bTok, err)
	}

	var buf limitedTailBuffer
	if _, err := buf.Write(make([]byte, 5000)); err != nil {
		t.Fatal(err)
	}
	if len(buf.rawTail()) != maxCmdStderrBytes {
		t.Fatalf("expected truncated limitedTailBuffer length %d, got %d", maxCmdStderrBytes, len(buf.rawTail()))
	}
	_ = buf.String()

	c1 := &TCPConnection{A: Endpoint{Port: 50051}, B: Endpoint{Port: 40000}, TLSClientHello: new(int), ALPN: []string{"h2"}}
	if c1.ServicePort() != 50051 || !c1.CarriesHTTP2() {
		t.Fatalf("expected ServicePort=50051 and CarriesHTTP2=true")
	}
	c2 := &TCPConnection{A: Endpoint{Port: 18080}, B: Endpoint{Port: 9000}}
	if c2.ServicePort() != 9000 || !c2.CarriesHTTP2(9000) {
		t.Fatalf("expected fallback ServicePort=9000")
	}

	if got := string(decodeHTTPFileData("68:69")); got != "hi" {
		t.Fatalf("expected colon-hex 'hi', got %q", got)
	}
	if got := string(decodeHTTPFileData("plain")); got != "plain" || decodeHTTPFileData("") != nil {
		t.Fatalf("decodeHTTPFileData fallback mismatch: %q", got)
	}

	ext := &HTTP2Extraction{
		SecretValues:   map[string]bool{},
		IdentityValues: map[string]bool{},
	}
	magic := frameFromPDML(&pdmlField{Fields: []pdmlField{{Name: "http2.magic"}}}, ext)
	if magic == nil || magic.Type != "MAGIC" {
		t.Fatalf("expected MAGIC frame, got %+v", magic)
	}
	if got := frameFromPDML(&pdmlField{Fields: []pdmlField{{Name: "http2.type", Show: strPtr("bad")}}}, ext); got != nil {
		t.Fatalf("expected nil on invalid type")
	}
	dataHex := hex.EncodeToString([]byte("payload"))
	dfr := frameFromPDML(&pdmlField{Fields: []pdmlField{
		{Name: "http2.type", Show: strPtr("0")},
		{Name: "http2.streamid", Show: strPtr("1")},
		{Name: "http2.flags", Show: strPtr("1")},
		{Name: "http2.data.data", Value: &dataHex},
	}}, ext)
	if dfr == nil || dfr.Type != "DATA" || !dfr.EndStream || string(dfr.Data) != "payload" {
		t.Fatalf("unexpected DATA frame: %+v", dfr)
	}
	rst := frameFromPDML(&pdmlField{Fields: []pdmlField{
		{Name: "http2.type", Show: strPtr("3")},
		{Name: "http2.rst_stream.error", Show: strPtr("8")},
	}}, ext)
	if rst == nil || rst.ErrorCode == nil || *rst.ErrorCode != 8 {
		t.Fatalf("unexpected RST_STREAM frame: %+v", rst)
	}
	set := frameFromPDML(&pdmlField{Fields: []pdmlField{
		{Name: "http2.type", Show: strPtr("4")},
		{Name: "http2.flags", Show: strPtr("0")},
		{Name: "http2.settings", Fields: []pdmlField{
			{Name: "http2.settings.id", Show: strPtr("3")},
			{Name: "http2.settings.max_concurrent_streams", Show: strPtr("100")},
		}},
	}}, ext)
	if set == nil || set.Settings["max_concurrent_streams"] == nil || *set.Settings["max_concurrent_streams"] != 100 {
		t.Fatalf("unexpected SETTINGS frame: %+v", set)
	}
	pong := frameFromPDML(&pdmlField{Fields: []pdmlField{
		{Name: "http2.type", Show: strPtr("6")},
		{Name: "http2.flags", Show: strPtr("1")},
		{Name: "http2.pong", Show: strPtr("01020304")},
	}}, ext)
	if pong == nil || !pong.Ack || pong.Opaque != "01020304" {
		t.Fatalf("unexpected PONG frame: %+v", pong)
	}
	goawayHex := hex.EncodeToString([]byte("closing\x00"))
	goaway := frameFromPDML(&pdmlField{Fields: []pdmlField{
		{Name: "http2.type", Show: strPtr("7")},
		{Name: "http2.goaway.last_stream_id", Show: strPtr("5")},
		{Name: "http2.goaway.error", Show: strPtr("2")},
		{Name: "http2.goaway.addata", Value: &goawayHex},
	}}, ext)
	if goaway == nil || goaway.DebugData == nil || *goaway.DebugData != "closing" {
		t.Fatalf("unexpected GOAWAY frame: %+v", goaway)
	}
	win := frameFromPDML(&pdmlField{Fields: []pdmlField{
		{Name: "http2.type", Show: strPtr("8")},
		{Name: "http2.window_update.window_size_increment", Show: strPtr("65535")},
	}}, ext)
	if win == nil || win.Increment != 65535 {
		t.Fatalf("unexpected WINDOW_UPDATE frame: %+v", win)
	}
	hdr := frameFromPDML(&pdmlField{Fields: []pdmlField{
		{Name: "http2.type", Show: strPtr("1")},
		{Name: "http2.flags", Show: strPtr("4")},
		{Name: "http2.headers"},
		{Name: "http2.header", Fields: []pdmlField{
			{Name: "http2.header.name", Show: strPtr("<unknown>")},
		}},
		{Name: "http2.header", Fields: []pdmlField{
			{Name: "http2.header.name", Show: strPtr("grpc-message")},
			{Name: "http2.header.value", Show: strPtr("bad%20input")},
		}},
		{Name: "http2.header", Fields: []pdmlField{
			{Name: "http2.header.name", Show: strPtr("x-api-key")},
			{Name: "http2.header.value", Show: strPtr("Bearer super-secret-tok")},
		}},
	}}, ext)
	if hdr == nil || !hdr.DecodeFailed || !ext.SecretValues["super-secret-tok"] || *hdr.Headers[0].Value != "bad input" {
		t.Fatalf("unexpected HEADERS frame: %+v secrets=%v", hdr, ext.SecretValues)
	}
	pb := protobufFromPDML(&pdmlProto{
		Showname: "Protocol Buffers: /gnmi.gNMI/Get,response (Message: gnmi.GetResponse)",
		Fields: []pdmlField{{
			Name:     "pbf.gnmi.PathElem.name",
			Showname: "name: interfaces",
			Show:     strPtr("interfaces"),
		}},
	})
	if pb.MessageType == nil || *pb.MessageType != "gnmi.GetResponse" || pb.Path == nil || *pb.Path != "/gnmi.gNMI/Get" || pb.Direction == nil || *pb.Direction != "response" || len(pb.Fields) != 1 || pb.Fields[0].Value != "interfaces" {
		t.Fatalf("unexpected ProtobufMsg: %+v", pb)
	}
}
