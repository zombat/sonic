package gate

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
)

func TestGateEvaluationFormatsAndThresholds(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	ctx := context.Background()

	// Invalid policy syntax -> ExitCode 2.
	for _, badPol := range [][]string{{"bogus"}, {"mos-min=9"}, {"mos-min=abc"}, {"max-clipping-ms=-5"}} {
		if r := Evaluate(ctx, filepath.Join("testdata", "fixtures", "sip_minimal.pcap"), Options{Policies: badPol}); r.Status != "error" || r.ExitCode != 2 {
			t.Fatalf("expected exit 2 for policy %v, got %+v", badPol, r)
		}
	}
	if _, err := ParsePolicies([]string{" , "}); err != nil {
		t.Fatalf("ParsePolicies whitespace should fall back to defaults, got %v", err)
	}

	// Missing capture -> ExitCode 1.
	if r := Evaluate(ctx, "/nonexistent/missing.pcap", Options{}); r.Status != "error" || r.ExitCode != 1 {
		t.Fatalf("expected exit 1 for missing capture, got %+v", r)
	}

	// Healthy IPsec/TLS capture passes zero-cleartext + no-weak-crypto -> ExitCode 0.
	cleanCap := filepath.Join("testdata", "fixtures", "phase3_encrypted.pcap")
	cryptoOK := Evaluate(ctx, cleanCap, Options{Policies: []string{"zero-cleartext", "no-weak-crypto"}})
	if cryptoOK.Status != "success" || !cryptoOK.Passed || cryptoOK.ExitCode != 0 {
		t.Fatalf("expected crypto PASS on phase3_encrypted.pcap, got %+v", cryptoOK)
	}
	healthyCap := filepath.Join("testdata", "fixtures", "grpc_tls13_hrr.pcap")
	if healthyRep := Evaluate(ctx, healthyCap, Options{Policies: []string{"no-weak-crypto", "no-critical-issues"}}); !healthyRep.Passed || healthyRep.ExitCode != 0 {
		t.Fatalf("expected PASS on grpc_tls13_hrr.pcap, got %+v", healthyRep)
	}
	// phase3_encrypted carries an unanswered spoke peer (IKE_NO_RESPONSE) so default gate catches it cleanly.
	if critRep := Evaluate(ctx, cleanCap, Options{}); critRep.Passed || critRep.ExitCode != 3 {
		t.Fatalf("expected no-critical-issues failure on phase3_encrypted.pcap, got %+v", critRep)
	}

	// Cleartext leak capture fails default zero-cleartext -> ExitCode 3; passes with allow token.
	leakCap := filepath.Join("testdata", "fixtures", "audit_one_leak.pcap")
	failRep := Evaluate(ctx, leakCap, Options{Policies: []string{"zero-cleartext,no-critical-issues"}})
	if failRep.Status != "success" || failRep.Passed || failRep.ExitCode != 3 || failRep.ViolationCount == 0 {
		t.Fatalf("expected FAIL exit 3 on audit_one_leak.pcap, got %+v", failRep)
	}
	sarifBytes, err := FormatSARIF(failRep)
	if err != nil || !json.Valid(sarifBytes) || !strings.Contains(string(sarifBytes), `"version": "2.1.0"`) {
		t.Fatalf("invalid SARIF output: err=%v out=%s", err, sarifBytes)
	}
	junitBytes, err := FormatJUnit(failRep)
	if err != nil || xml.Unmarshal(junitBytes, &junitSuites{}) != nil || !strings.Contains(string(junitBytes), "<failure") {
		t.Fatalf("invalid JUnit XML output: err=%v out=%s", err, junitBytes)
	}
	if txt := FormatText(failRep); !strings.Contains(txt, "[FAIL]") {
		t.Fatalf("unexpected text output: %s", txt)
	}

	// Weak TLS and IKEv1 captures fail no-weak-crypto -> ExitCode 3.
	weakTLS := filepath.Join("testdata", "fixtures", "enc_tls10.pcap")
	if tlsFail := Evaluate(ctx, weakTLS, Options{Policies: []string{"no-weak-crypto"}}); tlsFail.Passed || tlsFail.ExitCode != 3 {
		t.Fatalf("expected weak TLS failure, got %+v", tlsFail)
	}
	ikev1Cap := filepath.Join("testdata", "fixtures", "ikev1.pcap")
	if ikeFail := Evaluate(ctx, ikev1Cap, Options{Policies: []string{"no-weak-crypto"}}); ikeFail.Passed || ikeFail.ExitCode != 3 {
		t.Fatalf("expected IKEv1 weak crypto failure, got %+v", ikeFail)
	}

	// Allowlist lets ipsec_ikev2_esp pass zero-cleartext cleanly, plus format zero-violation SARIF/JUnit/Text.
	allowPass := Evaluate(ctx, filepath.Join("testdata", "fixtures", "ipsec_ikev2_esp.pcap"), Options{
		Policies: []string{"zero-cleartext", "mos-min=3.5", "max-clipping-ms=500"},
		Allow:    []string{"crypto", "l2-control"},
	})
	if !allowPass.Passed || allowPass.ExitCode != 0 {
		t.Fatalf("expected allowlisted pass, got %+v", allowPass)
	}
	if _, err := FormatSARIF(allowPass); err != nil {
		t.Fatalf("FormatSARIF pass failed: %v", err)
	}
	if _, err := FormatJUnit(allowPass); err != nil {
		t.Fatalf("FormatJUnit pass failed: %v", err)
	}
	if !strings.Contains(FormatText(allowPass), "[PASS]") {
		t.Fatalf("FormatText pass missing [PASS]: %s", FormatText(allowPass))
	}

	// Threshold evaluators for MOS and clipping boundaries.
	mosFail := evalMOSRule("mos-min=4.0", 4.0, &netorch.NetworkReport{}, &sip.QuickQualityReport{
		MOSAnalysis: &sip.MOSAnalysisResult{Streams: []sip.RTPStreamMetrics{{SSRC: "0x1"}}, WorstMOS: 3.1},
	})
	mosOK := evalMOSRule("mos-min=3.0", 3.0, &netorch.NetworkReport{}, &sip.QuickQualityReport{
		MOSAnalysis: &sip.MOSAnalysisResult{Streams: []sip.RTPStreamMetrics{{SSRC: "0x1"}}, WorstMOS: 4.1},
	})
	clipFail := evalClippingRule("max-clipping-ms=500", 500, &netorch.NetworkReport{}, &sip.QuickQualityReport{
		MediaClipping: &sip.MediaClippingSummary{AnalyzedCalls: 1, MaxDelayMS: 1200},
	})
	clipOK := evalClippingRule("max-clipping-ms=500", 500, &netorch.NetworkReport{}, &sip.QuickQualityReport{
		MediaClipping: &sip.MediaClippingSummary{AnalyzedCalls: 1, MaxDelayMS: 80},
	})
	weakSIP := evalWeakCryptoRule("no-weak-crypto", &netorch.NetworkReport{
		NetworkBody: netorch.NetworkBody{
			SIP: netorch.SIPSummary{
				Present:         true,
				QualityAnalysis: &sip.QualityMetrics{DegradationFactors: []string{"Weak digest algorithm detected (MD5)"}},
			},
		},
	})
	if mosFail.Passed || !mosOK.Passed || clipFail.Passed || !clipOK.Passed || weakSIP.Passed {
		t.Fatalf("threshold unit checks failed: mos=(%v,%v) clip=(%v,%v) sip=%v",
			mosFail.Passed, mosOK.Passed, clipFail.Passed, clipOK.Passed, weakSIP.Passed)
	}
}
