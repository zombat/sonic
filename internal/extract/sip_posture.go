// Package extract evaluates overall SIP authentication security posture and
// upgrade recommendations matching extractors/auth_info.py.
package extract

import (
	"fmt"
	"strings"
)

// AuthSecurityPosture holds a letter grade, numeric score, factors, risks, and upgrade actions.
type AuthSecurityPosture struct {
	Grade           string   `json:"grade"`
	Score           int      `json:"score"`
	Factors         []string `json:"factors"`
	Risks           []string `json:"risks"`
	Recommendations []string `json:"recommendations"`
}

// CalculateAuthSecurityPosture computes security posture grade and score for SIP auth traffic.
func CalculateAuthSecurityPosture(auth AuthInfo) AuthSecurityPosture {
	challenges := auth.AuthChallenges
	responses := auth.AuthResponses
	attempts := auth.RegisterAttempts

	if len(challenges) == 0 && len(responses) == 0 {
		return AuthSecurityPosture{
			Grade:           "N/A",
			Score:           0,
			Factors:         []string{"No authentication activity detected"},
			Risks:           []string{},
			Recommendations: []string{},
		}
	}

	score := 100
	factors := []string{}
	risks := []string{}
	recs := []string{}

	if len(challenges) > 0 {
		strongCount, weakCount, withQoP, authInt, proxy407 := 0, 0, 0, 0, 0
		for _, ch := range challenges {
			up := strings.ToUpper(ch.Algorithm)
			switch up {
			case "SHA-256", "SHA-512":
				strongCount++
			case "", "MD5":
				weakCount++
			}
			if ch.QoP != "" {
				withQoP++
				if ch.QoP == "auth-int" {
					authInt++
				}
			}
			if ch.StatusCode == "407" {
				proxy407++
			}
		}
		if weakCount > 0 {
			score -= min(25, weakCount*8)
			risks = append(risks, fmt.Sprintf("Weak algorithm (MD5) in %d challenge(s)", weakCount))
			recs = append(recs, "🔒 Upgrade to SHA-256 or SHA-512 for stronger security")
		} else {
			factors = append(factors, fmt.Sprintf("Strong algorithms (%d challenge(s) use SHA-256+)", strongCount))
		}
		if strongCount > 0 {
			factors = append(factors, fmt.Sprintf("RFC 3261 best practices: SHA-256+ in %d challenge(s)", strongCount))
		}

		withoutQoP := len(challenges) - withQoP
		if float64(withoutQoP) > float64(len(challenges))/2.0 {
			score -= 15
			risks = append(risks, fmt.Sprintf("Missing qop in %d challenge(s) - replay protection disabled", withoutQoP))
			recs = append(recs, "🛡️ Enable qop='auth' or 'auth-int' for replay protection")
		} else if withQoP > 0 {
			if authInt > 0 {
				factors = append(factors, fmt.Sprintf("Excellent: qop='auth-int' provides message integrity (%d challenge(s))", authInt))
			} else {
				factors = append(factors, fmt.Sprintf("Good: qop='auth' provides replay protection (%d challenge(s))", withQoP))
			}
		}
		if proxy407 > 2 {
			score -= min(10, (proxy407-2)*3)
			risks = append(risks, fmt.Sprintf("Cascading proxy authentication (%d 407 challenges)", proxy407))
			recs = append(recs, "🔧 Review SIP proxy chain configuration - reduce cascading challenges")
		}
		if len(challenges) > 5 {
			score -= min(10, (len(challenges)-5)*2)
			risks = append(risks, fmt.Sprintf("Excessive authentication challenges (%d total)", len(challenges)))
			recs = append(recs, "🔍 Investigate excessive auth challenges - may indicate attack or misconfiguration")
		}
	}

	if len(attempts) > 0 {
		successful := 0
		for _, a := range attempts {
			if a.Success {
				successful++
			}
		}
		failed := len(attempts) - successful
		rate := float64(successful) / float64(len(attempts)) * 100
		if failed > 0 {
			score -= min(20, failed*10)
			risks = append(risks, fmt.Sprintf("%d REGISTER attempt(s) failed (%.0f%% success rate)", failed, rate))
			recs = append(recs, "⚠️ Investigate failed registrations - verify credentials and service availability")
		} else {
			factors = append(factors, fmt.Sprintf("All REGISTER attempts successful (%d/%d)", successful, len(attempts)))
		}
	}

	if len(challenges) > 0 && len(responses) > 0 {
		if len(responses) >= len(challenges) {
			factors = append(factors, "All challenges received proper authorization responses")
		} else {
			unresp := len(challenges) - len(responses)
			score -= min(10, unresp*5)
			risks = append(risks, fmt.Sprintf("%d challenge(s) without authorization responses", unresp))
		}
	} else if len(challenges) > 0 {
		score -= 15
		risks = append(risks, "Authentication challenges issued but no responses detected")
		recs = append(recs, "⚠️ Check client authentication configuration")
	}

	score = max(0, min(100, score))
	grade := "F"
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	}
	return AuthSecurityPosture{
		Grade: grade, Score: score, Factors: factors, Risks: risks, Recommendations: recs,
	}
}

// GenerateAuthUpgradeRecommendations returns actionable markdown bullet strings for SIP auth hardening.
func GenerateAuthUpgradeRecommendations(auth AuthInfo) []string {
	recs := []string{}
	challenges := auth.AuthChallenges
	responses := auth.AuthResponses
	attempts := auth.RegisterAttempts
	if len(challenges) == 0 && len(responses) == 0 {
		return recs
	}
	weak, noQoP, proxy407 := 0, 0, 0
	for _, c := range challenges {
		up := strings.ToUpper(c.Algorithm)
		if up == "" || up == "MD5" {
			weak++
		}
		if c.QoP == "" {
			noQoP++
		}
		if c.StatusCode == "407" {
			proxy407++
		}
	}
	if weak > 0 {
		recs = append(recs, fmt.Sprintf("🔒 **Upgrade Authentication Algorithm**: Replace MD5 with SHA-256 or SHA-512 on %d challenge(s) for enhanced security (RFC 3261 §22.4)", weak))
	}
	if noQoP > 0 && float64(noQoP) > float64(len(challenges))/2.0 {
		recs = append(recs, fmt.Sprintf("🛡️ **Enable Quality-of-Protection**: Add qop='auth' or qop='auth-int' to %d challenge(s) for replay protection (RFC 2617 §3.2.1)", noQoP))
	}
	if proxy407 > 2 {
		recs = append(recs, fmt.Sprintf("🔧 **Optimize Proxy Chain**: Reduce cascading 407 challenges (%d detected) - consolidate proxy authentication or review topology", proxy407))
	}
	failed := 0
	for _, r := range attempts {
		if !r.Success {
			failed++
		}
	}
	if failed > 0 {
		recs = append(recs, fmt.Sprintf("⚠️ **Fix REGISTER Failures**: Investigate %d failed registration(s) - verify credentials, realm configuration, and service availability", failed))
	}
	if len(challenges) > 0 && len(responses) == 0 {
		recs = append(recs, "🔍 **Client Configuration Issue**: Authentication challenges issued but no responses detected - verify client is properly configured with credentials")
	} else if len(challenges) > 0 && len(responses) > 0 && len(responses) < len(challenges) {
		recs = append(recs, fmt.Sprintf("📋 **Incomplete Auth Flow**: %d challenge(s) without responses - review client logs for authentication errors", len(challenges)-len(responses)))
	}
	if len(challenges) > 5 {
		recs = append(recs, fmt.Sprintf("🚨 **Excessive Challenges**: %d authentication challenges detected - investigate for credential issues, replay attacks, or clock skew problems", len(challenges)))
	}
	return recs
}
