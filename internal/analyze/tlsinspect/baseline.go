// Package tlsinspect policy baseline checking and weak-primitive classification helpers.
package tlsinspect

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// suiteCodeByName maps known IANA cipher suite names deterministically back to their lowest 16-bit code.
var suiteCodeByName = buildSuiteCodeByName()

// buildSuiteCodeByName precomputes the reverse cipher suite name table sorted by ascending numeric code.
func buildSuiteCodeByName() map[string]uint16 {
	codes := make([]int, 0, len(CipherSuites))
	for code := range CipherSuites {
		codes = append(codes, int(code))
	}
	slices.Sort(codes)
	out := make(map[string]uint16, len(CipherSuites))
	for _, code := range codes {
		name := CipherSuites[uint16(code)]
		if _, exists := out[name]; !exists {
			out[name] = uint16(code)
		}
	}
	return out
}

// checkSession evaluates one TLS session against built-in security rules and the configured Baseline.
func (d *Detector) checkSession(sess *sessionState) []model.Issue {
	violations := []model.Issue{}
	base := d.baseline
	ch := sess.clientHello
	sh := sess.serverHello

	var chosenVersion, chosenSuite string
	if sh != nil {
		chosenVersion = sh.Version
		chosenSuite = sh.CipherSuite
	}

	var allowedVersions []string
	var minVersion string
	var hasMinVersion bool
	if base != nil {
		for _, v := range base.Versions {
			if norm, ok := NormalizeVersion(v); ok {
				allowedVersions = append(allowedVersions, norm)
			}
		}
		if base.MinVersion != "" {
			minVersion, hasMinVersion = NormalizeVersion(base.MinVersion)
		}
	}

	if rank, ok := VersionRank[chosenVersion]; chosenVersion != "" && ok {
		switch {
		case len(allowedVersions) > 0 && !slices.Contains(allowedVersions, chosenVersion):
			violations = append(violations, model.MakeIssue(model.SeverityError, "TLS_BASELINE_VERSION",
				fmt.Sprintf("negotiated %s, baseline allows %s", chosenVersion, strings.Join(allowedVersions, ", ")), nil))
		case hasMinVersion && rank < VersionRank[minVersion]:
			violations = append(violations, model.MakeIssue(model.SeverityError, "TLS_BASELINE_VERSION",
				fmt.Sprintf("negotiated %s, below the baseline minimum %s", chosenVersion, minVersion), nil))
		case len(allowedVersions) == 0 && !hasMinVersion && rank < VersionRank["TLS1.2"]:
			violations = append(violations, model.MakeIssue(model.SeverityWarning, "TLS_OLD_VERSION",
				fmt.Sprintf("negotiated %s (deprecated by RFC 8996)", chosenVersion), nil))
		}
	}

	if chosenSuite != "" {
		if base != nil && len(base.CipherSuites) > 0 {
			allowedSuites := make([]string, 0, len(base.CipherSuites))
			for _, s := range base.CipherSuites {
				allowedSuites = append(allowedSuites, strings.ToUpper(NormalizeSuite(s)))
			}
			if !slices.Contains(allowedSuites, strings.ToUpper(chosenSuite)) {
				violations = append(violations, model.MakeIssue(model.SeverityError, "TLS_BASELINE_CIPHER",
					fmt.Sprintf("chose %s, not in the baseline list", chosenSuite), nil))
			}
		}
		if SuiteIsWeak(chosenSuite) {
			kind := StateWeak
			why := ""
			if code, ok := suiteCodeByName[chosenSuite]; ok {
				kind, why = SuiteEncryption(code)
			}
			text := fmt.Sprintf("chose a weak cipher suite %s", chosenSuite)
			if kind == StateCleartext {
				text = fmt.Sprintf("chose a suite that does not encrypt: %s", why)
			}
			violations = append(violations, model.MakeIssue(model.SeverityError, "TLS_WEAK_CIPHER_CHOSEN", text, nil))
		}
		if base != nil && base.RequireForwardSecrecy != nil && *base.RequireForwardSecrecy && !SuiteHasForwardSecrecy(chosenSuite) {
			violations = append(violations, model.MakeIssue(model.SeverityError, "TLS_NO_FORWARD_SECRECY",
				fmt.Sprintf("chose %s: static RSA key exchange, no forward secrecy", chosenSuite), nil))
		}
	}

	if base != nil && base.RequireSNI != nil && *base.RequireSNI && ch != nil && (ch.SNI == nil || *ch.SNI == "") {
		violations = append(violations, model.MakeIssue(model.SeverityWarning, "TLS_BASELINE_SNI", "ClientHello carries no SNI", nil))
	}

	if base != nil && len(base.ALPN) > 0 && sh != nil && chosenVersion != "TLS1.3" {
		if sh.ALPN == nil || !slices.Contains(base.ALPN, *sh.ALPN) {
			violations = append(violations, model.MakeIssue(model.SeverityWarning, "TLS_BASELINE_ALPN",
				fmt.Sprintf("ALPN %s not in %s", pyReprOptString(sh.ALPN), pyReprStringSlice(base.ALPN)), nil))
		}
	}

	if ch != nil {
		violations = appendOfferedWeakness(violations, ch, base)
	}

	if cert := sess.certificate; cert != nil && cert.Parsed != nil && *cert.Parsed &&
		cert.ValidAtCaptureTime != nil && !*cert.ValidAtCaptureTime {
		violations = append(violations, model.MakeIssue(model.SeverityError, "TLS_CERT_NOT_VALID",
			fmt.Sprintf("server certificate valid %s to %s, not at capture time", *cert.NotBefore, *cert.NotAfter), nil))
	}

	return violations
}

// appendOfferedWeakness appends a TLS_WEAK_OFFERED violation if ClientHello advertises weak ciphers or old TLS versions.
func appendOfferedWeakness(violations []model.Issue, ch *ClientHello, base *Baseline) []model.Issue {
	var weak []string
	for _, s := range ch.CipherSuites {
		if SuiteIsWeak(s) {
			weak = append(weak, s)
		}
	}
	var old []string
	for _, v := range ch.Versions {
		if rank, ok := VersionRank[v]; ok && rank < VersionRank["TLS1.2"] {
			old = append(old, v)
		}
	}
	if len(weak) == 0 && len(old) == 0 {
		return violations
	}
	sev := model.SeverityInfo
	if base != nil && base.ForbidWeakOffers != nil && *base.ForbidWeakOffers {
		sev = model.SeverityWarning
	}
	text := "client offered"
	if len(weak) > 0 {
		text += " weak suites " + strings.Join(weak[:min(5, len(weak))], ", ")
	}
	if len(old) > 0 {
		if len(weak) > 0 {
			text += " and"
		}
		text += " versions " + strings.Join(old, ", ")
	}
	return append(violations, model.MakeIssue(sev, "TLS_WEAK_OFFERED", text, nil))
}

// pyReprOptString formats an optional string like Python repr(str | None).
func pyReprOptString(s *string) string {
	if s == nil {
		return "None"
	}
	return "'" + strings.ReplaceAll(*s, "'", "\\'") + "'"
}

// pyReprStringSlice formats a string slice like Python repr(list[str]).
func pyReprStringSlice(items []string) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, "'"+strings.ReplaceAll(item, "'", "\\'")+"'")
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
