package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func intPtr(v int) *int           { return &v }
func floatPtr(v float64) *float64 { return &v }
func boolPtr(v bool) *bool        { return &v }
func strPtr(v string) *string     { return &v }

func TestStatusAndSeverityEnums(t *testing.T) {
	t.Parallel()

	statuses := []struct {
		status Status
		want   string
		order  int
	}{
		{StatusNotPresent, "not_present", 0},
		{StatusOK, "ok", 1},
		{StatusWarning, "warning", 2},
		{StatusProblem, "problem", 3},
	}
	for _, tc := range statuses {
		data, err := json.Marshal(tc.status)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", tc.status, err)
		}
		if string(data) != `"`+tc.want+`"` {
			t.Fatalf("Marshal(%v) = %s, want %q", tc.status, data, tc.want)
		}
		var got Status
		if err := json.Unmarshal(data, &got); err != nil || got != tc.status {
			t.Fatalf("Unmarshal(%s) = (%v, %v), want %v", data, got, err, tc.status)
		}
		if StatusOrder(tc.status) != tc.order {
			t.Fatalf("StatusOrder(%v) = %d, want %d", tc.status, StatusOrder(tc.status), tc.order)
		}
	}

	var badStatus Status
	if err := json.Unmarshal([]byte(`"bogus"`), &badStatus); err == nil {
		t.Fatal("expected error for unknown status")
	}

	severities := []struct {
		sev   Severity
		want  string
		order int
	}{
		{SeverityError, "error", 0},
		{SeverityWarning, "warning", 1},
		{SeverityInfo, "info", 2},
	}
	for _, tc := range severities {
		data, err := json.Marshal(tc.sev)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", tc.sev, err)
		}
		if string(data) != `"`+tc.want+`"` {
			t.Fatalf("Marshal(%v) = %s, want %q", tc.sev, data, tc.want)
		}
		var got Severity
		if err := json.Unmarshal(data, &got); err != nil || got != tc.sev {
			t.Fatalf("Unmarshal(%s) = (%v, %v), want %v", data, got, err, tc.sev)
		}
		if SeverityOrder(tc.sev) != tc.order {
			t.Fatalf("SeverityOrder(%v) = %d, want %d", tc.sev, SeverityOrder(tc.sev), tc.order)
		}
	}

	var badSev Severity
	if err := json.Unmarshal([]byte(`"fatal"`), &badSev); err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestWorstStatusAndSortIssues(t *testing.T) {
	t.Parallel()

	if got := WorstStatus(nil); got != StatusNotPresent {
		t.Fatalf("WorstStatus(nil) = %v, want not_present", got)
	}
	if got := WorstStatus([]Status{StatusOK, StatusProblem, StatusWarning}); got != StatusProblem {
		t.Fatalf("WorstStatus = %v, want problem", got)
	}

	if got := StatusFromIssues(nil, false); got != StatusNotPresent {
		t.Fatalf("StatusFromIssues(false) = %v, want not_present", got)
	}
	if got := StatusFromIssues([]Issue{{Severity: SeverityInfo}}, true); got != StatusOK {
		t.Fatalf("StatusFromIssues(info) = %v, want ok", got)
	}
	if got := StatusFromIssues([]Issue{{Severity: SeverityWarning}}, true); got != StatusWarning {
		t.Fatalf("StatusFromIssues(warning) = %v, want warning", got)
	}
	if got := StatusFromIssues([]Issue{{Severity: SeverityWarning}, {Severity: SeverityError}}, true); got != StatusProblem {
		t.Fatalf("StatusFromIssues(error) = %v, want problem", got)
	}

	sorted := SortIssues([]Issue{
		{Severity: SeverityInfo, Code: "I1"},
		{Severity: SeverityError, Code: "E1"},
		{Severity: SeverityWarning, Code: "W1"},
		{Severity: SeverityInfo, Code: "I2"},
	})
	wantOrder := []string{"E1", "W1", "I1", "I2"}
	for i, code := range wantOrder {
		if sorted[i].Code != code {
			t.Fatalf("SortIssues[%d] = %s, want %s", i, sorted[i].Code, code)
		}
	}
}

func TestTimeAndContextHelpers(t *testing.T) {
	t.Parallel()

	ctx := Context{Start: floatPtr(1767225600.0), MaxItems: 25}
	if got := ctx.Rel(nil); got != nil {
		t.Fatalf("Rel(nil) = %v, want nil", *got)
	}
	if got := ctx.Rel(floatPtr(1767225605.5024)); got == nil || *got != 5.502 {
		t.Fatalf("Rel = %v, want 5.502", got)
	}
	if got := (Context{}).Rel(floatPtr(1.0)); got != nil {
		t.Fatalf("Context{}.Rel = %v, want nil", got)
	}

	if got := ISOTime(nil); got != nil {
		t.Fatalf("ISOTime(nil) = %v, want nil", *got)
	}
	if got := ISOTime(floatPtr(1767225600.01)); got == nil || *got != "2026-01-01T00:00:00.010Z" {
		t.Fatalf("ISOTime = %v, want 2026-01-01T00:00:00.010Z", got)
	}

	issue := MakeIssue(SeverityError, "TEST", "bad", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	if len(issue.Frames) != MaxFrames || issue.Frames[9] != 10 {
		t.Fatalf("MakeIssue frames = %v, want first 10", issue.Frames)
	}
	ev := MakeEvent(ctx, 1767225601.25, "bgp", "open", "peer up", intPtr(4))
	if ev.T == nil || *ev.T != 1.25 || ev.Time == nil || *ev.Time != "2026-01-01T00:00:01.250Z" {
		t.Fatalf("MakeEvent unexpected: %+v", ev)
	}
}

func TestServicePortAndProtocolLabel(t *testing.T) {
	t.Parallel()

	portCases := []struct {
		sport, dport *int
		want         *int
	}{
		{nil, intPtr(443), intPtr(443)},
		{intPtr(51200), nil, intPtr(51200)},
		{intPtr(443), intPtr(51200), intPtr(443)},
		{intPtr(51200), intPtr(179), intPtr(179)},
		{intPtr(8000), intPtr(50000), intPtr(8000)},
		{intPtr(55000), intPtr(60000), intPtr(60000)},
		{intPtr(900), intPtr(2000), intPtr(900)},
	}
	for _, tc := range portCases {
		got := ServicePort(tc.sport, tc.dport)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Fatalf("ServicePort(%v, %v) = %v, want %v", tc.sport, tc.dport, got, tc.want)
		}
	}

	protoCases := []struct {
		name string
		rec  Record
		want string
	}{
		{"esp", Record{ESP: &ESPHeader{UDP: false}}, "esp"},
		{"esp_udp", Record{ESP: &ESPHeader{UDP: true}}, "esp-in-udp"},
		{"ike", Record{IKE: &IKEHeader{}}, "ike"},
		{"natk", Record{NATKeepalive: boolPtr(true)}, "nat-keepalive"},
		{"gre_nhrp", Record{GRE: &GREHeader{Ptype: intPtr(0x2001)}}, "gre/nhrp"},
		{"gre_ipv4", Record{GRE: &GREHeader{Ptype: intPtr(0x0800)}}, "gre/ipv4"},
		{"gre_ipv6", Record{GRE: &GREHeader{Ptype: intPtr(0x86DD)}}, "gre/ipv6"},
		{"gre_other", Record{GRE: &GREHeader{}}, "gre"},
		{"arp", Record{ARP: &ARPPacket{}}, "arp"},
		{"llc", Record{LLC: "cdp"}, "cdp"},
		{"eth_known", Record{EthType: intPtr(0x88CC)}, "lldp"},
		{"eth_unknown", Record{EthType: intPtr(0x9001)}, "ethertype-0x9001"},
		{"other", Record{}, "other"},
		{"tcp_svc", Record{IP: &IPHeader{Proto: intPtr(6)}, TCP: &TCPHeader{Sport: intPtr(50000), Dport: intPtr(60000), Svc: intPtr(8080)}}, "tcp/8080"},
		{"udp_port", Record{IP: &IPHeader{Proto: intPtr(17)}, UDP: &UDPHeader{Sport: intPtr(55000), Dport: intPtr(161)}}, "udp/161"},
		{"ospf", Record{IP: &IPHeader{Proto: intPtr(89)}}, "ospf"},
		{"ip_unknown", Record{IP: &IPHeader{Proto: intPtr(99)}}, "ip-proto-99"},
	}
	for _, tc := range protoCases {
		if got := ProtocolLabel(&tc.rec); got != tc.want {
			t.Fatalf("%s: ProtocolLabel = %q, want %q", tc.name, got, tc.want)
		}
	}

	if svc, ok := LabelService("tcp/443"); !ok || svc != "https" {
		t.Fatalf("LabelService(tcp/443) = (%q, %v), want (https, true)", svc, ok)
	}
	if _, ok := LabelService("icmp"); ok {
		t.Fatal("LabelService(icmp) should be false")
	}
}

func TestSeqDeltaEndpointTransportAndJSONNulls(t *testing.T) {
	t.Parallel()

	if got := SeqDelta(5, 0xFFFFFFFF); got != 6 {
		t.Fatalf("SeqDelta wrap forward = %d, want 6", got)
	}
	if got := SeqDelta(0xFFFFFFFF, 5); got != -6 {
		t.Fatalf("SeqDelta wrap backward = %d, want -6", got)
	}
	if got := Endpoint("10.0.0.1", intPtr(443)); got != "10.0.0.1:443" {
		t.Fatalf("Endpoint v4 = %q", got)
	}
	if got := Endpoint("2001:db8::1", intPtr(22)); got != "[2001:db8::1]:22" {
		t.Fatalf("Endpoint v6 = %q", got)
	}
	if got := Endpoint("10.0.0.1", nil); got != "10.0.0.1" {
		t.Fatalf("Endpoint nil port = %q", got)
	}
	if got := PairKey("10.0.0.2", "10.0.0.1"); got != [2]string{"10.0.0.1", "10.0.0.2"} {
		t.Fatalf("PairKey v4 = %v", got)
	}
	if got := PairKey("2001:db8::1", "10.0.0.1"); got != [2]string{"10.0.0.1", "2001:db8::1"} {
		t.Fatalf("PairKey v4/v6 = %v", got)
	}

	if DSCPName(intPtr(46)) != "EF" || DSCPName(intPtr(42)) != "DSCP 42" || DSCPName(nil) != "unknown" {
		t.Fatal("DSCPName mismatch")
	}

	// Verify Transport prefers inner GRE IPv4 packet when dp.inner is present.
	rec := Record{
		IP:    &IPHeader{V: 4, Src: "198.51.100.1", Dst: "198.51.100.2", Proto: intPtr(47)},
		Inner: &InnerPacket{Src: "10.0.0.1", Dst: "10.0.0.2", Proto: intPtr(6)},
		DP: &DataPlane{
			HL: 20, TL: 100, DSCP: 0, ECN: 0,
			Inner: &DPInner{TL: 76, ID: intPtr(5), DF: 1, DSCP: 46, ECN: 0},
		},
	}
	tv := Transport(&rec)
	if tv == nil || !tv.Tunneled || tv.Src != "10.0.0.1" || tv.DSCP != 46 || !tv.HasOuter {
		t.Fatalf("Transport GRE inner = %+v", tv)
	}
	if IsFragment(&rec) {
		t.Fatal("IsFragment should be false")
	}
	rec.DP.MF = intPtr(1)
	if !IsFragment(&rec) {
		t.Fatal("IsFragment should be true when mf=1")
	}

	// Verify explicit null vs omitempty JSON encoding required by golden parity.
	raw, err := json.Marshal(struct {
		ICMP ICMPPacket        `json:"icmp"`
		BGP  BGPMessage        `json:"bgp"`
		Enc  SessionEncryption `json:"enc"`
		TCP  TCPHeader         `json:"tcp"`
	}{
		ICMP: ICMPPacket{V6: false, Orig: nil},
		BGP:  BGPMessage{Type: 4, Caps: nil},
		Enc:  SessionEncryption{State: "encrypted", HandshakeCaptured: true, Reason: nil},
		TCP:  TCPHeader{Sport: intPtr(1000), Dport: intPtr(443), Flags: 2, Len: 0},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(raw)
	for _, want := range []string{`"orig":null`, `"caps":null`, `"reason":null`} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %s in %s", want, text)
		}
	}
	for _, forbid := range []string{`"mss"`, `"svc"`, `"version"`} {
		if strings.Contains(text, forbid) {
			t.Fatalf("did not expect omitted field %s in %s", forbid, text)
		}
	}
}

func TestCapAddFrameAndEdgeFallbacks(t *testing.T) {
	t.Parallel()

	items := []int{1, 2, 3, 4}
	capped, omitted := Cap(items, 2)
	if len(capped) != 2 || omitted != 2 {
		t.Fatalf("Cap = (%v, %d), want ([1 2], 2)", capped, omitted)
	}
	allItems, zero := Cap(items, -1)
	if len(allItems) != 4 || zero != 0 {
		t.Fatalf("Cap(-1) = (%v, %d)", allItems, zero)
	}

	var frames []int
	for i := 1; i <= 15; i++ {
		AddFrame(&frames, i)
	}
	if len(frames) != MaxFrames {
		t.Fatalf("AddFrame length = %d, want %d", len(frames), MaxFrames)
	}

	if Transport(nil) != nil || IsFragment(nil) {
		t.Fatal("nil Transport/IsFragment mismatch")
	}
	outerOnly := Record{
		IP: &IPHeader{V: 4, Src: "10.0.0.1", Dst: "10.0.0.2"},
		DP: &DataPlane{DSCP: 10},
	}
	if tv := Transport(&outerOnly); tv == nil || tv.Tunneled || tv.DSCP != 10 {
		t.Fatalf("outer Transport = %+v", tv)
	}
	if CompareIP("not-an-ip", "also-bad") != 0 || CompareIP("10.0.0.1", "not-an-ip") >= 0 {
		t.Fatal("CompareIP invalid fallback mismatch")
	}
	if Status(99).String() != "not_present" || StatusOrder(Status(99)) != 0 || Severity(99).String() != "info" || SeverityOrder(Severity(99)) != 9 {
		t.Fatal("unknown enum defaults mismatch")
	}
}

func TestMathAndICMPDescribe(t *testing.T) {
	t.Parallel()

	if got := Round(2.5, 0); got != 2.0 {
		t.Fatalf("Round(2.5, 0) = %v, want 2.0 (half-to-even)", got)
	}
	if got := Round(3.5, 0); got != 4.0 {
		t.Fatalf("Round(3.5, 0) = %v, want 4.0 (half-to-even)", got)
	}
	if got := Round(-0.0001, 2); got != 0 {
		t.Fatalf("Round(-0.0001, 2) = %v, want 0", got)
	}

	if Median(nil) != nil || Percentile(nil, 0.95) != nil {
		t.Fatal("empty Median/Percentile should return nil")
	}
	mOdd := Median([]float64{5, 1, 3})
	if mOdd == nil || *mOdd != 3 {
		t.Fatalf("Median(odd) = %v, want 3", mOdd)
	}
	mEven := Median([]float64{4, 1, 2, 3})
	if mEven == nil || *mEven != 2.5 {
		t.Fatalf("Median(even) = %v, want 2.5", mEven)
	}
	p95 := Percentile([]float64{10, 20, 30, 40}, 0.95)
	if p95 == nil || *p95 != 40 {
		t.Fatalf("Percentile(0.95) = %v, want 40", p95)
	}

	cases := []struct {
		v6           bool
		typ, code    int
		wantName     string
		wantCodeText string
	}{
		{false, 3, 4, "destination_unreachable", "fragmentation needed and DF set"},
		{false, 11, 1, "time_exceeded", "fragment reassembly time exceeded"},
		{false, 5, 1, "redirect", "redirect for host"},
		{false, 99, 7, "type_99", "code 7"},
		{true, 1, 4, "destination_unreachable", "port unreachable"},
		{true, 3, 0, "time_exceeded", "hop limit exceeded in transit"},
		{true, 3, 1, "time_exceeded", "fragment reassembly time exceeded"},
		{true, 2, 0, "packet_too_big", "code 0"},
	}
	for _, tc := range cases {
		name, codeText := ICMPDescribe(tc.v6, tc.typ, tc.code)
		if name != tc.wantName || codeText != tc.wantCodeText {
			t.Fatalf("ICMPDescribe(%v,%d,%d) = (%q,%q), want (%q,%q)",
				tc.v6, tc.typ, tc.code, name, codeText, tc.wantName, tc.wantCodeText)
		}
	}
}
