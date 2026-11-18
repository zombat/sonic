// Package gate implements individual policy rule evaluators for gate.go.
package gate

import (
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/model"
)

func evaluateRule(sp PolicySpec, netRep *netorch.NetworkReport, voipRep *sip.QuickQualityReport) RuleResult {
	switch sp.Kind {
	case RuleZeroCleartext:
		return evalCleartextRule(sp.Name, netRep)
	case RuleNoWeakCrypto:
		return evalWeakCryptoRule(sp.Name, netRep)
	case RuleMOSMin:
		return evalMOSRule(sp.Name, sp.Threshold, netRep, voipRep)
	case RuleMaxClippingMS:
		return evalClippingRule(sp.Name, sp.Threshold, netRep, voipRep)
	case RuleNoCriticalIssues:
		return evalCriticalIssuesRule(sp.Name, netRep)
	default:
		return RuleResult{Name: sp.Name, Passed: true, Violations: []Violation{}}
	}
}

func evalCleartextRule(name string, netRep *netorch.NetworkReport) RuleResult {
	var viols []Violation
	for _, iss := range netRep.Issues {
		if iss.Detector == "cleartext_audit" && (iss.Severity == model.SeverityError || iss.Severity == model.SeverityWarning) {
			viols = append(viols, Violation{
				Rule: name, Code: iss.Code, Detector: iss.Detector,
				Severity: iss.Severity, Message: iss.Message, Frames: nonNilFrames(iss.Frames),
			})
		}
	}
	if len(viols) == 0 {
		return RuleResult{Name: name, Passed: true, Summary: "No prohibited cleartext flows found.", Violations: []Violation{}}
	}
	return RuleResult{Name: name, Passed: false, Summary: fmt.Sprintf("%d cleartext violation(s) found.", len(viols)), Violations: viols}
}

func evalWeakCryptoRule(name string, netRep *netorch.NetworkReport) RuleResult {
	var viols []Violation
	for _, iss := range netRep.Issues {
		if isWeakCryptoCode(iss.Code) || (iss.Detector == "tls" && iss.Severity == model.SeverityError) {
			viols = append(viols, Violation{
				Rule: name, Code: iss.Code, Detector: iss.Detector,
				Severity: iss.Severity, Message: iss.Message, Frames: nonNilFrames(iss.Frames),
			})
		}
	}
	if netRep.SIP.Present && netRep.SIP.QualityAnalysis != nil {
		for _, df := range netRep.SIP.QualityAnalysis.DegradationFactors {
			if strings.Contains(strings.ToLower(df), "weak digest") {
				viols = append(viols, Violation{
					Rule: name, Code: "SIP_WEAK_DIGEST", Detector: "sip",
					Severity: model.SeverityWarning, Message: df, Frames: []int{},
				})
			}
		}
	}
	if len(viols) == 0 {
		return RuleResult{Name: name, Passed: true, Summary: "No weak cryptographic negotiations found.", Violations: []Violation{}}
	}
	return RuleResult{Name: name, Passed: false, Summary: fmt.Sprintf("%d weak cryptography finding(s).", len(viols)), Violations: viols}
}

func isWeakCryptoCode(code string) bool {
	if strings.HasPrefix(code, "IKEV1_") {
		return true
	}
	switch code {
	case "IKE_WEAK_CRYPTO", "WEAK_ENCRYPTION",
		"TLS_OLD_VERSION", "TLS_WEAK_CIPHER_CHOSEN", "TLS_NO_FORWARD_SECRECY",
		"TLS_BASELINE_VERSION", "TLS_BASELINE_CIPHER":
		return true
	default:
		return false
	}
}

func evalMOSRule(name string, minMOS float64, netRep *netorch.NetworkReport, voipRep *sip.QuickQualityReport) RuleResult {
	var mosRes *sip.MOSAnalysisResult
	if voipRep != nil && voipRep.MOSAnalysis != nil {
		mosRes = voipRep.MOSAnalysis
	} else if netRep.SIP.MOSAnalysis != nil {
		mosRes = netRep.SIP.MOSAnalysis
	}
	if mosRes == nil || len(mosRes.Streams) == 0 {
		return RuleResult{Name: name, Passed: true, Summary: "No RTP streams present to score against MOS threshold.", Violations: []Violation{}}
	}
	if mosRes.WorstMOS < minMOS {
		msg := fmt.Sprintf("Worst RTP stream MOS %.2f is below required minimum %.2f", mosRes.WorstMOS, minMOS)
		return RuleResult{
			Name:    name,
			Passed:  false,
			Summary: msg,
			Violations: []Violation{{
				Rule: name, Code: "VOIP_MOS_BELOW_THRESHOLD", Detector: "sip",
				Severity: model.SeverityError, Message: msg, Frames: []int{},
			}},
		}
	}
	return RuleResult{Name: name, Passed: true, Summary: fmt.Sprintf("Worst RTP MOS %.2f meets >= %.2f.", mosRes.WorstMOS, minMOS), Violations: []Violation{}}
}

func evalClippingRule(name string, maxMS float64, netRep *netorch.NetworkReport, voipRep *sip.QuickQualityReport) RuleResult {
	var clip *sip.MediaClippingSummary
	if voipRep != nil && voipRep.MediaClipping != nil {
		clip = voipRep.MediaClipping
	} else if netRep.SIP.MediaClipping != nil {
		clip = netRep.SIP.MediaClipping
	}
	if clip == nil || clip.AnalyzedCalls == 0 {
		return RuleResult{Name: name, Passed: true, Summary: "No INVITE 200 OK media calls present to measure clipping.", Violations: []Violation{}}
	}
	if clip.MaxDelayMS > maxMS {
		msg := fmt.Sprintf("Post-200 OK media delay %.1f ms exceeds limit %.1f ms", clip.MaxDelayMS, maxMS)
		return RuleResult{
			Name:    name,
			Passed:  false,
			Summary: msg,
			Violations: []Violation{{
				Rule: name, Code: "VOIP_MEDIA_CLIPPING", Detector: "sip",
				Severity: model.SeverityError, Message: msg, Frames: []int{},
			}},
		}
	}
	return RuleResult{Name: name, Passed: true, Summary: fmt.Sprintf("Max post-200 OK delay %.1f ms <= %.1f ms.", clip.MaxDelayMS, maxMS), Violations: []Violation{}}
}

func evalCriticalIssuesRule(name string, netRep *netorch.NetworkReport) RuleResult {
	var viols []Violation
	for _, iss := range netRep.Issues {
		if iss.Severity == model.SeverityError {
			viols = append(viols, Violation{
				Rule: name, Code: iss.Code, Detector: iss.Detector,
				Severity: iss.Severity, Message: iss.Message, Frames: nonNilFrames(iss.Frames),
			})
		}
	}
	if len(viols) == 0 {
		return RuleResult{Name: name, Passed: true, Summary: "No error-severity detector issues found.", Violations: []Violation{}}
	}
	return RuleResult{Name: name, Passed: false, Summary: fmt.Sprintf("%d error-severity issue(s) reported.", len(viols)), Violations: viols}
}

func nonNilFrames(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}
