package diff

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
)

func TestCompareCapturesAndHelpers(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()
	good := filepath.Join("testdata", "fixtures", "bgp_session.pcap")
	bad := filepath.Join("testdata", "fixtures", "bgp_failover.pcap")

	// Identical capture yields zero changes.
	same := CompareCaptures(ctx, good, good, Options{})
	if same.Status != "success" || len(same.Highlights) != 0 || !strings.Contains(same.Verdict, "No behavioral differences") {
		t.Fatalf("expected clean identical diff, got %+v", same)
	}

	// Cross-capture diff highlights issues, MSS/TLS/QoS, and error branches.
	diffRep := CompareCaptures(ctx, good, bad, Options{})
	if diffRep.Status != "success" || len(diffRep.Highlights) == 0 {
		t.Fatalf("expected behavioral highlights in diff, got %+v", diffRep)
	}
	txt := FormatDiffSummary(diffRep)
	if !strings.Contains(txt, "Diff:") || !strings.Contains(txt, "Verdict:") {
		t.Fatalf("unexpected diff summary text: %q", txt)
	}

	// TLS + MSS + QoS + SIP delta comparison across real/synthetic fixtures.
	tlsGood := filepath.Join("testdata", "fixtures", "grpc_tls13_hrr.pcap")
	tlsOld := filepath.Join("testdata", "fixtures", "enc_tls10.pcap")
	tlsDiff := CompareCaptures(ctx, tlsGood, tlsOld, Options{})
	if tlsDiff.Status != "success" || !tlsDiff.TLSDeltas.Changed {
		t.Fatalf("expected TLS deltas between tls13 and tls10: %+v", tlsDiff)
	}
	mssDiff := CompareCaptures(ctx, tlsGood, good, Options{})
	if mssDiff.Status != "success" || !mssDiff.TCPAndMTUDeltas.Changed {
		t.Fatalf("expected TCP MSS delta between tls13 and bgp_session: %+v", mssDiff)
	}

	qosCap := filepath.Join("testdata", "fixtures", "dp_qos_rtp.pcap")
	qosDiff := CompareCaptures(ctx, good, qosCap, Options{})
	if qosDiff.Status != "success" || !qosDiff.QoSDSCPDeltas.Changed {
		t.Fatalf("expected QoS DSCP delta when comparing against dp_qos_rtp: %+v", qosDiff)
	}

	// Error cases.
	if r := CompareCaptures(ctx, "/nonexistent/a.pcap", bad, Options{}); r.Status != "error" || !strings.Contains(r.Error, "baseline error") {
		t.Fatalf("expected baseline error, got %+v", r)
	}
	if r := CompareCaptures(ctx, good, "/nonexistent/b.pcap", Options{}); r.Status != "error" || !strings.Contains(r.Error, "target error") {
		t.Fatalf("expected target error, got %+v", r)
	}

	// SIP delta calculation unit check.
	sd := diffSIP(
		netorch.SIPSummary{
			Present:         true,
			QualityAnalysis: &sip.QualityMetrics{OverallScore: 95},
			MOSAnalysis:     &sip.MOSAnalysisResult{AverageMOS: 4.3},
			MediaClipping:   &sip.MediaClippingSummary{MaxDelayMS: 50},
			DTMFEvents:      &sip.DTMFEventsSummary{Digits: "123"},
		},
		netorch.SIPSummary{
			Present:         true,
			QualityAnalysis: &sip.QualityMetrics{OverallScore: 70},
			MOSAnalysis:     &sip.MOSAnalysisResult{AverageMOS: 3.1},
			MediaClipping:   &sip.MediaClippingSummary{MaxDelayMS: 950},
			DTMFEvents:      &sip.DTMFEventsSummary{Digits: "12"},
		},
	)
	if sd == nil || !sd.Changed || sd.ClippingDelayDeltaMS != 900 || sd.MOSDelta >= 0 {
		t.Fatalf("unexpected SIP diff: %+v", sd)
	}
	_ = json.RawMessage{}
}
