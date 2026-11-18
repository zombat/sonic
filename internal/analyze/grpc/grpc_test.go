package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/parity"
)

func strPtr(s string) *string  { return &s }
func intPtr(i int) *int        { return &i }
func f64Ptr(f float64) *float6 { return &f }

type float6 = float64

func TestGoldenGrpcParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	cases := []string{
		"grpc_connection_trouble",
		"grpc_h2_trouble",
		"grpc_mgmt_mix",
		"grpc_tls12_alert",
		"grpc_tls13_hrr",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			got := AnalyzeCapture(
				context.Background(),
				filepath.Join("testdata", "fixtures", name+".pcap"),
				Options{IgnoreDefaultProtoDir: true},
			)
			parity.CompareGolden(t, got, filepath.Join("testdata", "golden", "grpc", name+".json"))

			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			for _, sec := range []string{
				"gnmi-bearer-token-not-real",
				"lab-pass-not-real",
				"grpc-api-key-not-real",
			} {
				if strings.Contains(text, sec) {
					t.Fatalf("secret %q leaked into report JSON", sec)
				}
			}
		})
	}
}

func pbVarint(num uint64, val uint64) []byte {
	var b []byte
	b = binary.AppendUvarint(b, num<<3)
	b = binary.AppendUvarint(b, val)
	return b
}

func pbBytes(num uint64, data []byte) []byte {
	var b []byte
	b = binary.AppendUvarint(b, (num<<3)|2)
	b = binary.AppendUvarint(b, uint64(len(data)))
	b = append(b, data...)
	return b
}

func TestGnmiWireAndDecodeUnit(t *testing.T) {
	if p := EncodingName(nil); p != nil {
		t.Fatalf("expected nil EncodingName(nil)")
	}
	if p := EncodingName(intPtr(99)); p == nil || *p != "vendor encoding 99" {
		t.Fatalf("unexpected vendor encoding: %v", p)
	}

	// Build Path with target, origin, PathElem+key, and test deprecated elements fallback.
	kv := append(pbBytes(1, []byte("name")), pbBytes(2, []byte("eth0"))...)
	elem := append(pbBytes(1, []byte("interface")), pbBytes(2, kv)...)
	pathMsg := append(pbBytes(2, []byte("openconfig")), pbBytes(3, elem)...)
	pathMsg = append(pathMsg, pbBytes(4, []byte("leaf1"))...)
	rendered, err := RenderPath(pathMsg)
	if err != nil || rendered == nil || *rendered != "<leaf1>openconfig:/interface[name=eth0]" {
		t.Fatalf("unexpected RenderPath: %v err=%v", rendered, err)
	}
	depPath, err := RenderPath(pbBytes(1, []byte("legacy")))
	if err != nil || depPath == nil || *depPath != "/legacy" {
		t.Fatalf("unexpected deprecated RenderPath: %v err=%v", depPath, err)
	}
	if rp, _ := RenderPath(nil); rp != nil {
		t.Fatalf("expected nil RenderPath(nil)")
	}
	if jp := JoinPaths(strPtr("/"), strPtr("/a")); jp == nil || *jp != "/a" {
		t.Fatalf("unexpected JoinPaths: %v", jp)
	}
	if jp := JoinPaths(strPtr("/pre"), strPtr("/")); jp == nil || *jp != "/pre" {
		t.Fatalf("unexpected JoinPaths prefix fallback: %v", jp)
	}

	// GetRequest, SetRequest, SubscribeRequest (poll + list).
	getBytes := append(pbBytes(1, pbBytes(1, []byte("sys"))), pbBytes(2, pbBytes(1, []byte("ver")))...)
	getBytes = append(getBytes, pbVarint(3, 2)...)
	getBytes = append(getBytes, pbVarint(5, 4)...)
	dGet, err := DecodeRequest("/gnmi.gNMI/Get", getBytes)
	if err != nil || dGet.Get == nil || dGet.Get.Type != "STATE" || !dGet.Get.EncodingFieldPresent {
		t.Fatalf("DecodeRequest(Get) failed: %+v err=%v", dGet, err)
	}

	updMsg := pbBytes(1, pbBytes(1, []byte("cfg")))
	setBytes := append(pbBytes(2, pbBytes(1, []byte("old"))), pbBytes(3, updMsg)...)
	setBytes = append(setBytes, pbBytes(4, updMsg)...)
	setBytes = append(setBytes, pbBytes(6, updMsg)...)
	dSet, err := DecodeRequest("/gnmi.gNMI/Set", setBytes)
	if err != nil || dSet.Set == nil || dSet.Set.Delete.Count != 1 || dSet.Set.UnionReplace.Count != 1 {
		t.Fatalf("DecodeRequest(Set) failed: %+v err=%v", dSet, err)
	}

	subItem := append(pbBytes(1, pbBytes(1, []byte("if"))), pbVarint(2, 2)...)
	subItem = append(subItem, pbVarint(3, 1_000_000_000)...)
	subItem = append(subItem, pbVarint(5, 5_000_000_000)...)
	subList := append(pbBytes(2, subItem), pbVarint(5, 1)...)
	subList = append(subList, pbVarint(8, 2)...)
	subList = append(subList, pbVarint(9, 1)...)
	dSub, err := DecodeRequest("/gnmi.gNMI/Subscribe", pbBytes(1, subList))
	if err != nil || dSub.Subscribe == nil || dSub.Subscribe.Mode != "ONCE" || *dSub.Subscribe.Subscriptions[0].SampleIntervalS != 1 {
		t.Fatalf("DecodeRequest(Subscribe) failed: %+v err=%v", dSub, err)
	}
	dPoll, err := DecodeRequest("/gnmi.gNMI/Subscribe", pbBytes(3, []byte{}))
	if err != nil || !dPoll.Poll {
		t.Fatalf("DecodeRequest(Poll) failed: %+v err=%v", dPoll, err)
	}

	// Responses: Set, Get with Error, Subscribe notification+sync+error, Health, Time.
	errBytes := append(pbVarint(1, 7), pbBytes(2, []byte("denied"))...)
	getRespBytes := append(pbBytes(1, pbBytes(4, []byte{})), pbBytes(2, errBytes)...)
	rGet, err := DecodeResponse("/gnmi.gNMI/Get", getRespBytes, nil)
	if err != nil || rGet.Get == nil || rGet.Get.Notifications != 1 || rGet.Get.Error.Code != 7 {
		t.Fatalf("DecodeResponse(Get) failed: %+v err=%v", rGet, err)
	}

	setRespBytes := append(pbBytes(2, pbVarint(4, 3)), pbBytes(3, errBytes)...)
	rSet, err := DecodeResponse("/gnmi.gNMI/Set", setRespBytes, nil)
	if err != nil || rSet.Set == nil || rSet.Set.Ops["UPDATE"] != 1 || rSet.Set.Error == nil {
		t.Fatalf("DecodeResponse(Set) failed: %+v err=%v", rSet, err)
	}

	subRespBytes := append(pbBytes(1, pbBytes(5, []byte{})), pbVarint(3, 1)...)
	subRespBytes = append(subRespBytes, pbBytes(4, errBytes)...)
	rSub, err := DecodeResponse("/gnmi.gNMI/Subscribe", subRespBytes, nil)
	if err != nil || rSub.SubscribeMsg == nil || rSub.SubscribeMsg.SyncResponse == nil || rSub.SubscribeMsg.Error == nil {
		t.Fatalf("DecodeResponse(Subscribe) failed: %+v err=%v", rSub, err)
	}

	rTime, err := DecodeResponse("/gnoi.system.System/Time", pbVarint(1, 1_767_225_605_000_000_000), f64Ptr(1767225600.0))
	if err != nil || rTime.Time == nil || rTime.Time.SkewS == nil || *rTime.Time.SkewS != 5.0 {
		t.Fatalf("DecodeResponse(Time) failed: %+v err=%v", rTime, err)
	}

	// Error cases for ParseFields (wire=3, wire=1/5 truncated, field 0).
	for _, bad := range [][]byte{{0x03}, {0x09, 0x01}, {0x0d, 0x01}, {0x00}} {
		if _, err := ParseFields(bad); err == nil {
			t.Fatalf("expected error parsing bad protobuf bytes %x", bad)
		}
	}
	var fixedPayload []byte
	fixedPayload = append(fixedPayload, 0x09, 1, 2, 3, 4, 5, 6, 7, 8)
	fixedPayload = append(fixedPayload, 0x15, 1, 2, 3, 4)
	if fs, err := ParseFields(fixedPayload); err != nil || len(fs) != 2 {
		t.Fatalf("expected fixed64+fixed32 parse, got len=%d err=%v", len(fs), err)
	}
}

func TestProtosValidationAndScrubbing(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	assertErr := func(r Report, substr string) {
		t.Helper()
		if r.Status != "error" || !strings.Contains(r.Error, substr) {
			t.Fatalf("expected error containing %q, got status=%q err=%q", substr, r.Status, r.Error)
		}
		raw, err := json.Marshal(r)
		if err != nil || !strings.Contains(string(raw), `"status":"error"`) || strings.Contains(string(raw), `"schema"`) {
			t.Fatalf("unexpected error marshal: %s err=%v", raw, err)
		}
	}

	sample := filepath.Join("testdata", "fixtures", "grpc_mgmt_mix.pcap")
	assertErr(AnalyzeCapture(ctx, "", Options{}), "File not found")
	assertErr(AnalyzeCapture(ctx, filepath.Join("testdata", "fixtures", "missing.pcap"), Options{}), "File not found")
	assertErr(AnalyzeCapture(ctx, t.TempDir(), Options{}), "File not readable")
	assertErr(AnalyzeCapture(ctx, sample, Options{KeylogFile: t.TempDir()}), "keylog_file is not a readable file")
	assertErr(AnalyzeCapture(ctx, sample, Options{MaxPackets: intPtr(0)}), "max_packets must be a positive number")
	assertErr(AnalyzeCapture(ctx, sample, Options{Ports: []int{99999}}), "Not a TCP port")
	assertErr(AnalyzeCapture(ctx, sample, Options{ProtoPaths: []string{sample}}), "proto path is not a directory")

	// Mock FetchProtos success & digest mismatch.
	dest := filepath.Join(t.TempDir(), "protos")
	zeroPins := map[string]string{}
	okRes := FetchProtos(ctx, dest, func(context.Context, string) ([]byte, error) {
		return []byte("syntax = \"proto3\";"), nil
	}, zeroPins)
	if okRes.Status != "success" || len(okRes.Files) != len(pinnedProtoFiles) {
		t.Fatalf("FetchProtos mock failed: %+v", okRes)
	}
	badRes := FetchProtos(ctx, dest, func(context.Context, string) ([]byte, error) {
		return []byte("tampered"), nil
	}, Pins())
	if badRes.Status != "error" || !strings.Contains(badRes.Error, "SHA-256 mismatch") {
		t.Fatalf("expected SHA-256 mismatch error: %+v", badRes)
	}
	netErrRes := FetchProtos(ctx, dest, func(context.Context, string) ([]byte, error) {
		return nil, errors.New("offline")
	}, zeroPins)
	if netErrRes.Status != "error" || !strings.Contains(netErrRes.Error, "download failed") {
		t.Fatalf("expected download failed error: %+v", netErrRes)
	}
	t.Setenv(ProtoPathVariable, dest)
	if gotPaths := ResolveProtoPaths(nil, true); len(gotPaths) != 1 || gotPaths[0] != dest {
		t.Fatalf("unexpected ResolveProtoPaths env: %v", gotPaths)
	}

	// Scrubbing: identity preserves compound tokens ("admin-state") while redacting standalone words ("admin").
	rules := buildScrubRules(map[string]bool{"tok-1234": true}, map[string]bool{"admin": true, "tok-1234": true})
	if scrubbed := applyScrubRules("admin-state user admin tok-1234!", rules); scrubbed != "admin-state user [REDACTED] [REDACTED]!" {
		t.Fatalf("unexpected scrub result: %q", scrubbed)
	}

	// Wrong-session keylog on grpc_tls13_hrr hits probeTLSDetails, retry, and TLS_SESSION_NOT_DECRYPTED.
	kl := filepath.Join(t.TempDir(), "other.keylog")
	klLine := "CLIENT_RANDOM " + strings.Repeat("aa", 32) + " " + strings.Repeat("bb", 48) + "\n"
	if err := os.WriteFile(kl, []byte(klLine), 0o600); err != nil {
		t.Fatal(err)
	}
	tlsPcap := filepath.Join("testdata", "fixtures", "grpc_tls13_hrr.pcap")
	klRep := AnalyzeCapture(ctx, tlsPcap, Options{KeylogFile: kl, IgnoreDefaultProtoDir: true, MaxItems: 5})
	if klRep.Status != "success" || klRep.TLSDecryption == nil || klRep.TLSDecryption.Decrypted >= klRep.TLSDecryption.Total {
		t.Fatalf("expected un-decrypted TLS summary: %+v", klRep.TLSDecryption)
	}
	emptyRep := AnalyzeCapture(ctx, sample, Options{DisplayFilter: "tcp.port==65530", IgnoreDefaultProtoDir: true})
	if emptyRep.Status != "success" || !strings.Contains(emptyRep.Verdict, "No gRPC or HTTP/2 found") {
		t.Fatalf("unexpected empty verdict: %q", emptyRep.Verdict)
	}

	// PCAPNG DSB + coverageFailureReason + mergeTLSState + tlsView decrypted DER.
	dsbPath := writeMinimalDSBPCAPNG(t, klLine)
	sv := secretsView(dsbPath, kl)
	if sv.PCAPNGBlocks != 1 || sv.Source == nil || !strings.Contains(*sv.Source, "and") {
		t.Fatalf("unexpected DSB secretsView: %+v", sv)
	}
	var tlsIssues []model.Issue
	appendCaptureTLSAlerts(klRep.TLSDecryption, sv, true, map[int]*extract.TCPConnection{0: {A: extract.Endpoint{IP: "1.1.1.1", Port: 1}, B: extract.Endpoint{IP: "2.2.2.2", Port: 443}}}, []RereadRow{{TCPStream: 0}}, &tlsIssues)
	if len(tlsIssues) == 0 {
		t.Fatal("expected TLS alerts from appendCaptureTLSAlerts")
	}
	if r := coverageFailureReason(nil, false, nil, nil, nil, nil, nil); r == nil || !strings.Contains(*r, "no key log") {
		t.Fatalf("unexpected coverageFailureReason: %v", r)
	}
	if r := coverageFailureReason(strPtr("the key log"), true, nil, []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET"}, nil, nil, nil); r == nil || !strings.Contains(*r, "only the handshake") {
		t.Fatalf("unexpected handshake-only reason: %v", r)
	}
	if r := coverageFailureReason(strPtr("the key log"), false, nil, nil, nil, nil, nil); r == nil || !strings.Contains(*r, "no ClientHello") {
		t.Fatalf("unexpected no-CH reason: %v", r)
	}
	if r := coverageFailureReason(strPtr("the key log"), false, nil, nil, nil, intPtr(1), nil); r == nil || !strings.Contains(*r, "reassembled") {
		t.Fatalf("unexpected unreassembled reason: %v", r)
	}
	if r := coverageFailureReason(strPtr("the key log"), false, nil, []string{"CLIENT_RANDOM"}, strPtr("aa"), intPtr(1), &randomSecretInfo{}); r == nil || !strings.Contains(*r, "tshark did not decrypt") {
		t.Fatalf("unexpected fallback reason: %v", r)
	}
	merged := mergeTLSState(&extract.TLSDecryptionInfo{ApplicationData: []string{"http2"}}, &extract.TLSDecryptionInfo{Handshake: true, ClientRandom: strPtr("dead"), ClientHelloFrame: intPtr(2), ApplicationData: []string{"grpc"}, Certificate: []byte{1, 2}})
	if !merged.Handshake || len(merged.ApplicationData) != 2 || merged.ClientRandom == nil {
		t.Fatalf("unexpected mergeTLSState: %+v", merged)
	}
	if mergeTLSState(nil, merged) != merged || mergeTLSState(merged, nil) != merged {
		t.Fatal("mergeTLSState nil handling mismatch")
	}

	// tlsView with decrypted X.509 leaf DER.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-grpc.local"},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1800000000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	tv := tlsView(&extract.TCPConnection{B: extract.Endpoint{IP: "10.0.0.1", Port: 9339}}, &tlsinspect.Session{ServerChose: &tlsinspect.ServerHello{Version: "TLS1.3"}}, true, true, der, f64Ptr(1750000000), nil)
	if tv.Certificate == nil || tv.Certificate.DecryptedWithKeyLog == nil || !*tv.Certificate.DecryptedWithKeyLog {
		t.Fatalf("expected DecryptedWithKeyLog cert: %+v", tv.Certificate)
	}

	// Synthetic feed, inferSide, diagnoseOK, parseTimeout, and protobufWarnings coverage.
	a := newGrpcAnalysis(map[int]*extract.TCPConnection{}, "")
	a.feed(&extract.HTTP2Packet{
		N: 1, T: 1.0, TCPStream: 0, Src: "10.0.0.1", Dst: "10.0.0.2", Sport: intPtr(10000), Dport: intPtr(9339),
		Frames: []extract.HTTP2Frame{
			{Type: "MAGIC"},
			{Type: "SETTINGS", Settings: map[string]*int{"initial_window_size": intPtr(1024)}},
			{Type: "HEADERS", StreamID: 1, Headers: []extract.HTTP2Header{{Name: ":method", Value: strPtr("POST")}, {Name: ":path", Value: strPtr("/gnmi.gNMI/Get")}}},
			{Type: "DATA", StreamID: 1, Length: 70000, DataLen: 0},
		},
	})
	a.feed(&extract.HTTP2Packet{
		N: 2, T: 2.0, TCPStream: 0, Src: "10.0.0.2", Dst: "10.0.0.1", Sport: intPtr(9339), Dport: intPtr(10000),
		Frames: []extract.HTTP2Frame{
			{Type: "HEADERS", StreamID: 1, EndStream: true, Headers: []extract.HTTP2Header{{Name: ":status", Value: strPtr("200")}}},
		},
	})
	a.feed(&extract.HTTP2Packet{
		N: 3, T: 3.0, TCPStream: 1, Src: "10.0.0.2", Dst: "10.0.0.1", Sport: intPtr(9339), Dport: intPtr(10000),
		Frames: []extract.HTTP2Frame{
			{Type: "HEADERS", StreamID: 1, EndStream: true, DecodeFailed: true, Headers: []extract.HTTP2Header{{Name: ":status", Value: strPtr("500")}}},
		},
	})
	if a.conns[0] == nil || len(a.conns[0].stalls) == 0 {
		t.Fatalf("expected inferSide + flow control stall close on EndStream")
	}
	for _, s := range []string{"1H", "2M", "3S", "4m", "5u", "6n", "bad"} {
		_ = parseTimeout(&s)
	}
	_ = DefaultProtoDir()
	_ = endpointStr(nil)
	if pw := protobufWarnings("Protobuf: file /bad.proto does not exist\nok\nProtobuf: failed\n"); len(pw) != 2 {
		t.Fatalf("expected 2 protobuf warnings, got %v", pw)
	}
	_ = diagnoseOK("p", "gNMI", "/gnmi.gNMI/Get", &DecodedBlock{Response: &DecodedResponse{Get: &GetResponse{Notifications: 1, Updates: 0}}})
	_ = diagnoseOK("p", "gNMI", "/gnmi.gNMI/Subscribe", &DecodedBlock{Response: &DecodedResponse{SubscribeSum: &SubscribeResponseSummary{Errors: []GnmiError{{Code: 3}}}}})
	_ = diagnoseOK("p", "gNMI", "/gnmi.gNMI/Subscribe", &DecodedBlock{Request: &DecodedRequest{Subscribe: &SubscribeRequestDecoded{Mode: "ONCE"}}, Response: &DecodedResponse{SubscribeSum: &SubscribeResponseSummary{Notifications: 1}}})
	_ = diagnoseOK("p", "gNOI", "/gnoi.system.System/Time", &DecodedBlock{Response: &DecodedResponse{Time: &TimeResponse{SkewS: f64Ptr(5.0)}}})
	_ = diagnoseOK("p", "gRPC health", "/grpc.health.v1.Health/Check", &DecodedBlock{Response: &DecodedResponse{Health: &HealthResponse{ServingStatus: "NOT_SERVING"}}})
	_, _ = DecodedRequest{Poll: true}.MarshalJSON()
	_, _ = DecodedRequest{}.MarshalJSON()
	for _, dr := range []DecodedResponse{
		{Get: &GetResponse{}}, {Set: &SetResponse{Ops: map[string]int{}}},
		{Health: &HealthResponse{ServingStatus: "SERVING"}}, {Time: &TimeResponse{TargetTimeEpochS: 1}}, {},
	} {
		_, _ = dr.MarshalJSON()
	}
	_, _ = TLSView{ALPNOffered: []string{}, Hints: []tlsinspect.HintRecord{}}.MarshalJSON()
	_, _ = reqEncoding(&DecodedRequest{Get: &GetRequestDecoded{Encoding: strPtr("JSON")}})
	_, _ = reqEncoding(&DecodedRequest{Subscribe: &SubscribeRequestDecoded{Encoding: strPtr("PROTO")}})
	_, _ = reqEncoding(&DecodedRequest{})
	if b, _ := packedVarints([]ProtoField{{Wire: 2, Bytes: []byte{1, 2, 4}}}); len(b) != 3 {
		t.Fatalf("unexpected packedVarints: %v", b)
	}
	_ = a.rpcReport(a.conns[1], a.conns[1].rpcs[1], model.Context{})
	_ = endpointPtr(&extract.Endpoint{IP: "2001:db8::1", Port: 9339})
	_ = serviceFamily(strPtr("/custom.Svc/Call"))

	// Exercise remaining diagnoseStatus (status 3/4/8, Capabilities mismatch), GOAWAY, preface, HPACK, and verdict paths.
	capConn := newConnTrack(2, &extract.TCPConnection{
		PrefaceFrame: intPtr(1),
		A:            extract.Endpoint{IP: "10.0.0.1", Port: 1000},
		B:            extract.Endpoint{IP: "10.0.0.2", Port: 9339},
	})
	capConn.capabilities = &DecodedResponse{Capabilities: &CapabilitiesResponse{SupportedEncodings: []*string{strPtr("PROTO")}}}
	r3 := &rpcTrack{
		conn: capConn, streamID: 3, frames: map[string]int{"request": 2, "trailers": 3},
		requestHeaders: []extract.HTTP2Header{{Name: ":path", Value: strPtr("/gnmi.gNMI/Get")}, {Name: "content-type", Value: strPtr("application/grpc")}, {Name: "grpc-timeout", Value: strPtr("5S")}},
		trailers:       []extract.HTTP2Header{{Name: "grpc-status", Value: strPtr("3")}, {Name: "grpc-message", Value: strPtr("enc")}},
	}
	a.onHeaders(capConn, "client", &extract.HTTP2Frame{StreamID: 3, DecodeFailed: true, Headers: r3.requestHeaders}, 2, 1.0)
	a.onGoaway(capConn, "client", &extract.HTTP2Frame{ErrorCode: intPtr(0), LastStreamID: intPtr(3)}, 5, 1.5)
	bigSz := grpcDefaultMaxRecv + 100
	row3 := RPCRow{StreamID: 3, Method: strPtr("/gnmi.gNMI/Get"), Family: strPtr("gNMI"), ContentType: strPtr("application/grpc"),
		GrpcStatus: intPtr(3), GrpcStatusName: strPtr("INVALID_ARGUMENT"), Request: FramerSummary{Largest: &bigSz},
		Decoded: &DecodedBlock{Request: &DecodedRequest{Get: &GetRequestDecoded{Encoding: strPtr("JSON")}}}}
	_ = a.diagnoseStatus(capConn, r3, &row3, f64Ptr(5.0))
	row4 := row3
	row4.GrpcStatus = intPtr(4)
	row4.GrpcStatusName = strPtr("DEADLINE_EXCEEDED")
	_ = a.diagnoseStatus(capConn, r3, &row4, f64Ptr(5.0))
	row8 := row3
	row8.GrpcStatus = intPtr(8)
	row8.GrpcStatusName = strPtr("RESOURCE_EXHAUSTED")
	_ = a.diagnoseStatus(capConn, r3, &row8, nil)
	var dIssues []model.Issue
	var dEvents []model.Event
	rerep := a.connectionReport(capConn, model.Context{}, nil)
	appendConnectionDiagnostics(capConn, &rerep, []RPCRow{row3}, nil, model.Context{}, "the key log", map[string]int{}, &[]string{}, &[]CredentialFinding{}, &dIssues, &dEvents)
	_ = grpcVerdict([]ConnectionRow{{Transport: "tls", Service: strPtr("tcp/443")}}, nil, nil, nil, nil, "the key log", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proto"))
	}))
	defer srv.Close()
	if got, err := defaultProtoOpener(ctx, srv.URL); err != nil || string(got) != "proto" {
		t.Fatalf("defaultProtoOpener failed: %q err=%v", got, err)
	}
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer badSrv.Close()
	if _, err := defaultProtoOpener(ctx, badSrv.URL); err == nil {
		t.Fatal("expected error on HTTP 404 from defaultProtoOpener")
	}
	if got := ResolveProtoPaths([]string{dest}, true); len(got) != 1 {
		t.Fatalf("unexpected explicit ResolveProtoPaths: %v", got)
	}

	// Final coverage edges for malformed gNMI requests/responses, TLSSession alerts/hints, and warnings cap.
	for _, m := range []string{"/gnmi.gNMI/Get", "/gnmi.gNMI/Set", "/gnmi.gNMI/Subscribe", "/other.Svc/Call"} {
		_, _ = DecodeRequest(m, pbVarint(2, 1))
		_, _ = DecodeResponse(m, pbVarint(1, 1), nil)
	}
	_, _ = DecodeResponse("/gnmi.gNMI/Capabilities", pbVarint(1, 1), nil)
	_, _ = DecodeRequest("/gnmi.gNMI/Subscribe", []byte{})
	_ = DecodedRequest{Get: &GetRequestDecoded{Paths: []*string{}}}
	var hIssues []model.Issue
	appendTLSConnIssues(&extract.TCPConnection{TLSClientHello: intPtr(4)}, &TLSView{
		Alerts: []tlsinspect.AlertRecord{{Level: "warning", Description: "unknown_ca", From: "client", Frame: 5, Hint: strPtr("ca")}},
		Hints: []tlsinspect.HintRecord{
			{Code: "TLS_CERT_NO_IP_SAN", Text: "ip"},
			{Code: "TLS_NO_SERVER_HELLO", Text: "sh"},
			{Code: "TLS_NO_SNI", Text: "sni"},
			{Code: "OTHER", Text: "other"},
		},
	}, "lbl", &hIssues)
	if len(hIssues) != 5 {
		t.Fatalf("expected 5 TLS hint/alert issues, got %d", len(hIssues))
	}
	longErr := strings.Repeat("Protobuf: failed at line\n", 12)
	if pw := protobufWarnings(longErr); len(pw) != 10 {
		t.Fatalf("expected 10 capped protobuf warnings, got %d", len(pw))
	}
	var dummyH2 extract.HTTP2Extraction
	_ = dummyH2
}

func TestGrpcExtraCoverage(t *testing.T) {
	// RenderPath with origin, target, and multiple PathElem keys, plus packedVarints.
	kv1 := append(pbBytes(1, []byte("name")), pbBytes(2, []byte("eth0"))...)
	kv2 := append(pbBytes(1, []byte("a")), pbBytes(2, []byte("1"))...)
	elem := append(pbBytes(1, []byte("interface")), pbBytes(2, kv1)...)
	elem = append(elem, pbBytes(2, kv2)...)
	pathBytes := append(pbBytes(2, []byte("openconfig")), pbBytes(4, []byte("dut1"))...)
	pathBytes = append(pathBytes, pbBytes(3, elem)...)
	rendered, err := RenderPath(pathBytes)
	if err != nil || rendered == nil || !strings.Contains(*rendered, "openconfig:") || !strings.Contains(*rendered, "[a=1]") {
		t.Fatalf("RenderPath failed: %v err=%v", rendered, err)
	}
	if pNil, err := RenderPath(nil); err != nil || pNil != nil {
		t.Fatalf("RenderPath(nil) mismatch: %v err=%v", pNil, err)
	}
	if _, err := RenderPath(pbVarint(3, 1)); err == nil {
		t.Fatal("expected error for non-bytes PathElem")
	}
	packed := []ProtoField{{Wire: 0, Varint: 2}, {Wire: 2, Bytes: []byte{0x00, 0x01}}}
	if vs, err := packedVarints(packed); err != nil || len(vs) != 3 {
		t.Fatalf("packedVarints mismatch: %v err=%v", vs, err)
	}
	if _, err := packedVarints([]ProtoField{{Wire: 2, Bytes: []byte{0x80}}}); err == nil {
		t.Fatal("expected truncated packedVarints error")
	}

	// DefaultProtoDir fallback + ResolveProtoPaths with existing default dir.
	fakeHome := t.TempDir()
	defCache := filepath.Join(fakeHome, ".cache", "sonic", "grpc-protos")
	if err := os.MkdirAll(defCache, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fakeHome)
	t.Setenv(ProtoPathVariable, "")
	if got := ResolveProtoPaths(nil, false); len(got) != 1 || got[0] != defCache {
		t.Fatalf("ResolveProtoPaths default dir mismatch: %v", got)
	}
	t.Setenv("HOME", "")
	if !strings.HasSuffix(DefaultProtoDir(), filepath.Join(".cache", "sonic", "grpc-protos")) {
		t.Fatalf("DefaultProtoDir empty HOME fallback unexpected: %s", DefaultProtoDir())
	}

	// DecodeRequest Set (delete/replace/update), CapabilitiesResponse, isASCIIDigits, isLongLived.
	setReq := append(pbBytes(2, pathBytes), pbBytes(3, pbBytes(1, pathBytes))...)
	setReq = append(setReq, pbBytes(4, pbBytes(1, pathBytes))...)
	dSetReq, err := DecodeRequest("/gnmi.gNMI/Set", setReq)
	if err != nil || dSetReq.Set == nil || dSetReq.Set.Delete.Count != 1 || dSetReq.Set.Replace.Count != 1 || dSetReq.Set.Update.Count != 1 {
		t.Fatalf("DecodeRequest(Set) mismatch: %+v err=%v", dSetReq, err)
	}
	capResp := append(pbBytes(1, pbBytes(1, []byte("openconfig-interfaces"))), pbBytes(3, []byte("0.10.0"))...)
	dCap, err := DecodeResponse("/gnmi.gNMI/Capabilities", capResp, nil)
	if err != nil || dCap.Capabilities == nil || *dCap.Capabilities.GnmiVersion != "0.10.0" {
		t.Fatalf("DecodeResponse(Capabilities) mismatch: %+v err=%v", dCap, err)
	}
	if isASCIIDigits("") || !isASCIIDigits("42") {
		t.Fatal("isASCIIDigits edge failure")
	}
	subRPC := &rpcTrack{requestHeaders: []extract.HTTP2Header{{Name: ":path", Value: strPtr("/gnmi.gNMI/Subscribe")}}}
	if !isLongLived(subRPC, &DecodedBlock{Request: &DecodedRequest{Subscribe: &SubscribeRequestDecoded{Mode: "STREAM"}}}) {
		t.Fatal("expected Subscribe RPC to be long-lived")
	}
}

func writeMinimalDSBPCAPNG(t *testing.T, keylog string) string {
	t.Helper()
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
