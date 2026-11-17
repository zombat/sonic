package netorch

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/analyze/convergence"
	"github.com/zombat/sonic/internal/analyze/espoverhead"
	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/parity"
)

func intPtr(i int) *int         { return &i }
func f64Ptr(f float64) *float64 { return &f }

func TestGoldenNetorchParity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	golden := func(name string) string {
		return filepath.Join("testdata", "golden", "network_orchestrator", name)
	}
	fix := func(name string) string {
		return filepath.Join("tests", "fixtures", name)
	}

	t.Run("net_ipsec_ikev2_esp", func(t *testing.T) {
		got := AnalyzeNetworkCapture(ctx, fix("ipsec_ikev2_esp.pcap"), Options{})
		parity.CompareGolden(t, got, golden("net_ipsec_ikev2_esp.json"))
	})
	t.Run("net_dp_qos_rtp", func(t *testing.T) {
		got := AnalyzeNetworkCapture(ctx, fix("dp_qos_rtp.pcap"), Options{})
		parity.CompareGolden(t, got, golden("net_dp_qos_rtp.json"))
	})
	t.Run("vpn_ipsec_ikev2_esp", func(t *testing.T) {
		got := AnalyzeVPNCapture(ctx, fix("ipsec_ikev2_esp.pcap"), Options{})
		parity.CompareGolden(t, got, golden("vpn_ipsec_ikev2_esp.json"))
	})
	t.Run("routing_bgp_failover", func(t *testing.T) {
		got := AnalyzeRoutingCapture(ctx, fix("bgp_failover.pcap"), Options{
			DetectorOpts: DetectorOptions{RoutingMSS: intPtr(1360)},
		})
		parity.CompareGolden(t, got, golden("routing_bgp_failover.json"))
	})
	t.Run("audit_grpc_mgmt_mix", func(t *testing.T) {
		got := AuditCleartextCapture(ctx, fix("grpc_mgmt_mix.pcap"), Options{})
		parity.CompareGolden(t, got, golden("audit_grpc_mgmt_mix.json"))
	})
	t.Run("conv_dpd", func(t *testing.T) {
		got := AnalyzeConvergenceCapture(ctx, fix("convergence_dpd.pcap"), Options{})
		parity.CompareGolden(t, got, golden("conv_dpd.json"))
	})
	t.Run("dataplane_tcp_health", func(t *testing.T) {
		got := AnalyzeDataPlaneCapture(ctx, fix("dp_tcp_health.pcap"), Options{})
		parity.CompareGolden(t, got, golden("dataplane_tcp_health.json"))
	})
}

func TestNetorchValidationAndEdges(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	sample := filepath.Join("tests", "fixtures", "icmp_loss.pcap")

	assertNetErr := func(r NetworkReport, substr string) {
		t.Helper()
		if r.Status != "error" || !strings.Contains(r.Error, substr) {
			t.Fatalf("expected error containing %q, got status=%q err=%q", substr, r.Status, r.Error)
		}
		raw, err := json.Marshal(r)
		if err != nil || !strings.Contains(string(raw), `"status":"error"`) || strings.Contains(string(raw), `"schema"`) {
			t.Fatalf("unexpected error JSON: %s err=%v", raw, err)
		}
	}

	assertNetErr(AnalyzeNetworkCapture(ctx, "", Options{}), "File not found")
	assertNetErr(AnalyzeNetworkCapture(ctx, filepath.Join("tests", "fixtures", "missing.pcap"), Options{}), "File not found")
	assertNetErr(AnalyzeNetworkCapture(ctx, t.TempDir(), Options{}), "File not readable")
	unknownRep := AnalyzeNetworkCapture(ctx, sample, Options{Detectors: []string{"not_a_detector"}})
	assertNetErr(unknownRep, "Unknown detector(s)")
	if len(unknownRep.ValidDetectors) != len(AllDetectors) {
		t.Fatalf("expected valid_detectors list, got %v", unknownRep.ValidDetectors)
	}
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{Peers: []string{"bad-ip"}}), "Not an IP address in peers")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{MaxPackets: intPtr(0)}), "max_packets must be a positive number")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{DetectorOpts: DetectorOptions{DMVPNHubs: []string{"bad"}}}), "Not an IP address in hubs")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{DetectorOpts: DetectorOptions{RoutingMSS: intPtr(0)}}), "expected_mss must be a positive number")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{DetectorOpts: DetectorOptions{CleartextAudit: &AuditOption{HasAllow: true, Allow: []string{"bogus"}}}}), "unknown allowlist token")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{DetectorOpts: DetectorOptions{Convergence: &convergence.Options{FailedPeer: "bad"}}}), "failed_peer is not an IP address")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{DetectorOpts: DetectorOptions{Convergence: &convergence.Options{HoldTime: f64Ptr(0)}}}), "hold_time must be a positive number")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{DetectorOpts: DetectorOptions{Convergence: &convergence.Options{SilenceS: f64Ptr(-1)}}}), "silence_s must be a positive number")
	assertNetErr(AnalyzeNetworkCapture(ctx, sample, Options{DetectorOpts: DetectorOptions{Convergence: &convergence.Options{EventTime: "not-a-time"}}}), "event_time")

	// Wrapper error marshaling paths.
	missing := filepath.Join("tests", "fixtures", "missing.pcap")
	if b, err := json.Marshal(AnalyzeVPNCapture(ctx, missing, Options{})); err != nil || !strings.Contains(string(b), `"status":"error"`) {
		t.Fatalf("VPN error marshal mismatch: %s err=%v", b, err)
	}
	if b, err := json.Marshal(AnalyzeRoutingCapture(ctx, missing, Options{})); err != nil || !strings.Contains(string(b), `"status":"error"`) {
		t.Fatalf("Routing error marshal mismatch: %s err=%v", b, err)
	}
	if b, err := json.Marshal(AnalyzeConvergenceCapture(ctx, missing, Options{})); err != nil || !strings.Contains(string(b), `"status":"error"`) {
		t.Fatalf("Convergence error marshal mismatch: %s err=%v", b, err)
	}
	if b, err := json.Marshal(AnalyzeDataPlaneCapture(ctx, missing, Options{})); err != nil || !strings.Contains(string(b), `"status":"error"`) {
		t.Fatalf("DataPlane error marshal mismatch: %s err=%v", b, err)
	}
	if r := AuditCleartextCapture(ctx, missing, Options{}); r.Status != "error" {
		t.Fatalf("expected audit error status, got %+v", r)
	}

	// SIP present flag + custom detector options (tls baseline, esp_overhead options, cleartext_audit pass/warning).
	sipRep := AnalyzeNetworkCapture(ctx, filepath.Join("tests", "fixtures", "sip_minimal.pcap"), Options{
		Detectors: []string{"tls", "esp_overhead", "conversations", "cleartext_audit"},
		MaxItems:  2,
		DetectorOpts: DetectorOptions{
			TLSBaseline:    &tlsinspect.Baseline{Versions: []string{"TLS1.3"}},
			EspOverhead:    &espoverhead.Options{TransportMTU: 1500},
			CleartextAudit: &AuditOption{HasAllow: true, Allow: []string{"encrypted", "udp:5060"}},
		},
	})
	if sipRep.Status != "success" || !sipRep.SIP.Present {
		t.Fatalf("expected SIP present in sip_minimal report: %+v", sipRep.SIP)
	}
}
