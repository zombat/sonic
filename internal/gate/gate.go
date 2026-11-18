// Package gate evaluates deterministic CI/CD network and security policy gates
// over packet captures and renders JSON, text, SARIF v2.1.0, and JUnit XML reports.
package gate

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/model"
)

// RuleKind identifies one built-in CI policy check using a closed enum.
type RuleKind int

const (
	// RuleZeroCleartext fails when cleartext traffic violates the audit allowlist.
	RuleZeroCleartext RuleKind = iota
	// RuleNoWeakCrypto fails on IKEv1, weak TLS/SSH ciphers, or weak SIP Digest auth.
	RuleNoWeakCrypto
	// RuleMOSMin fails when measured RTP MOS falls below Threshold.
	RuleMOSMin
	// RuleMaxClippingMS fails when post-200 OK media start delay exceeds Threshold ms.
	RuleMaxClippingMS
	// RuleNoCriticalIssues fails when any detector reports error-level issues.
	RuleNoCriticalIssues
)

// PolicySpec defines a single parsed CI policy rule and its optional numeric threshold.
type PolicySpec struct {
	Kind      RuleKind `json:"-"`
	Name      string   `json:"name"`
	Threshold float64  `json:"threshold,omitempty"`
}

// Options configures policy gate execution against one capture file.
type Options struct {
	Policies      []string
	Allow         []string
	Peers         []string
	DisplayFilter string
	MaxPackets    *int
}

// Violation captures one failing condition encountered during a gate evaluation.
type Violation struct {
	Rule     string         `json:"rule"`
	Code     string         `json:"code"`
	Detector string         `json:"detector"`
	Severity model.Severity `json:"severity"`
	Message  string         `json:"message"`
	Frames   []int          `json:"frames"`
}

// RuleResult records pass/fail status and any violations for one policy rule.
type RuleResult struct {
	Name       string      `json:"name"`
	Passed     bool        `json:"passed"`
	Summary    string      `json:"summary"`
	Violations []Violation `json:"violations"`
}

// Report is the structured result returned by Evaluate.
type Report struct {
	Status          string       `json:"status"`
	Error           string       `json:"error,omitempty"`
	File            string       `json:"file"`
	Passed          bool         `json:"passed"`
	ExitCode        int          `json:"exit_code"`
	PoliciesApplied []string     `json:"policies_applied"`
	Results         []RuleResult `json:"results"`
	ViolationCount  int          `json:"violation_count"`
	Verdict         string       `json:"verdict"`
}

// DefaultPolicies defines the default CI gate checks when --policy is omitted.
var DefaultPolicies = []string{"zero-cleartext", "no-weak-crypto", "no-critical-issues"}

// ParsePolicies parses comma-separated or slice policy specs into typed PolicySpec items.
func ParsePolicies(specs []string) ([]PolicySpec, error) {
	if len(specs) == 0 {
		specs = DefaultPolicies
	}
	var out []PolicySpec
	for _, raw := range specs {
		for _, tok := range strings.Split(raw, ",") {
			name := strings.TrimSpace(strings.ToLower(tok))
			if name == "" {
				continue
			}
			spec, err := parseOnePolicy(name)
			if err != nil {
				return nil, err
			}
			out = append(out, spec)
		}
	}
	if len(out) == 0 {
		return ParsePolicies(DefaultPolicies)
	}
	return out, nil
}

func parseOnePolicy(tok string) (PolicySpec, error) {
	switch {
	case tok == "zero-cleartext":
		return PolicySpec{Kind: RuleZeroCleartext, Name: tok}, nil
	case tok == "no-weak-crypto":
		return PolicySpec{Kind: RuleNoWeakCrypto, Name: tok}, nil
	case tok == "no-critical-issues" || tok == "no-errors":
		return PolicySpec{Kind: RuleNoCriticalIssues, Name: tok}, nil
	case strings.HasPrefix(tok, "mos-min="):
		v, err := strconv.ParseFloat(strings.TrimPrefix(tok, "mos-min="), 64)
		if err != nil || v <= 0 || v > 5 {
			return PolicySpec{}, fmt.Errorf("invalid mos-min threshold in %q (want 0..5)", tok)
		}
		return PolicySpec{Kind: RuleMOSMin, Name: tok, Threshold: v}, nil
	case strings.HasPrefix(tok, "max-clipping-ms="):
		v, err := strconv.ParseFloat(strings.TrimPrefix(tok, "max-clipping-ms="), 64)
		if err != nil || v < 0 {
			return PolicySpec{}, fmt.Errorf("invalid max-clipping-ms threshold in %q", tok)
		}
		return PolicySpec{Kind: RuleMaxClippingMS, Name: tok, Threshold: v}, nil
	default:
		return PolicySpec{}, fmt.Errorf("unknown gate policy: %q", tok)
	}
}

// Evaluate checks all configured policy rules against a capture and sets ExitCode
// (0 pass, 3 policy violation, 1 capture error, 2 invalid policy syntax).
func Evaluate(ctx context.Context, filePath string, opts Options) Report {
	specs, err := ParsePolicies(opts.Policies)
	if err != nil {
		return Report{Status: "error", Error: err.Error(), File: filePath, ExitCode: 2, Results: []RuleResult{}}
	}

	needAudit := false
	needSIP := false
	applied := make([]string, 0, len(specs))
	for _, sp := range specs {
		applied = append(applied, sp.Name)
		switch sp.Kind {
		case RuleZeroCleartext:
			needAudit = true
		case RuleMOSMin, RuleMaxClippingMS, RuleNoWeakCrypto:
			needSIP = true
		case RuleNoCriticalIssues:
		}
	}

	detectors := append([]string{}, netorch.DetectorNames...)
	var detOpts netorch.DetectorOptions
	if needAudit {
		detectors = append(detectors, "cleartext_audit")
		if len(opts.Allow) > 0 {
			detOpts.CleartextAudit = &netorch.AuditOption{HasAllow: true, Allow: opts.Allow}
		}
	}

	netRep := netorch.AnalyzeNetworkCapture(ctx, filePath, netorch.Options{
		Detectors:     detectors,
		Peers:         opts.Peers,
		DisplayFilter: opts.DisplayFilter,
		MaxPackets:    opts.MaxPackets,
		IncludeSIP:    &needSIP,
		DetectorOpts:  detOpts,
	})
	if netRep.Status != "success" {
		return Report{
			Status:          "error",
			Error:           netRep.Error,
			File:            filePath,
			ExitCode:        1,
			PoliciesApplied: applied,
			Results:         []RuleResult{},
		}
	}

	var voipRep sip.QuickQualityReport
	if needSIP && netRep.SIP.Present {
		voipRep = sip.QuickQualityCheck(ctx, filePath)
	}

	results := make([]RuleResult, 0, len(specs))
	totalViolations := 0
	allPassed := true
	for _, sp := range specs {
		res := evaluateRule(sp, &netRep, &voipRep)
		if !res.Passed {
			allPassed = false
		}
		totalViolations += len(res.Violations)
		results = append(results, res)
	}

	exitCode := 0
	verdict := fmt.Sprintf("PASS: %d/%d gate rule(s) satisfied.", len(results), len(results))
	if !allPassed {
		exitCode = 3
		verdict = fmt.Sprintf("FAIL: %d violation(s) across %d gate rule(s).", totalViolations, len(results))
	}
	return Report{
		Status:          "success",
		File:            filePath,
		Passed:          allPassed,
		ExitCode:        exitCode,
		PoliciesApplied: applied,
		Results:         results,
		ViolationCount:  totalViolations,
		Verdict:         verdict,
	}
}
