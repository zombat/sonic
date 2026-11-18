// Package gate renders policy evaluation results in text, SARIF v2.1.0, and JUnit XML.
package gate

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	ShortDescription sarifTextMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifTextMessage `json:"message"`
	Locations []sarifLocation  `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifTextMessage struct {
	Text string `json:"text"`
}

// FormatSARIF encodes a gate Report as SARIF v2.1.0 JSON for CI code-scanning workflows.
func FormatSARIF(rep Report) ([]byte, error) {
	ruleSeen := make(map[string]bool)
	rules := []sarifRule{}
	results := []sarifResult{}

	for _, rr := range rep.Results {
		for _, v := range rr.Violations {
			if !ruleSeen[v.Code] {
				ruleSeen[v.Code] = true
				rules = append(rules, sarifRule{
					ID:               v.Code,
					ShortDescription: sarifTextMessage{Text: fmt.Sprintf("[%s] policy %s violation", v.Detector, v.Rule)},
				})
			}
			lvl := "warning"
			if v.Severity == model.SeverityError {
				lvl = "error"
			}
			msg := v.Message
			if len(v.Frames) > 0 {
				msg = fmt.Sprintf("%s (frames: %v)", msg, v.Frames)
			}
			results = append(results, sarifResult{
				RuleID:  v.Code,
				Level:   lvl,
				Message: sarifTextMessage{Text: msg},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: rep.File},
					},
				}},
			})
		}
	}

	logDoc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "S.O.N.I.C.", Rules: rules}},
			Results: results,
		}},
	}
	return json.MarshalIndent(logDoc, "", "  ")
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// FormatJUnit encodes a gate Report as JUnit XML for CI test reporters.
func FormatJUnit(rep Report) ([]byte, error) {
	failures := 0
	cases := make([]junitTestCase, 0, len(rep.Results))
	for _, rr := range rep.Results {
		tc := junitTestCase{Name: rr.Name, ClassName: "sonic.gate." + rep.File}
		if !rr.Passed {
			failures++
			var body strings.Builder
			for _, v := range rr.Violations {
				fmt.Fprintf(&body, "[%s/%s] %s\n", v.Detector, v.Code, v.Message)
			}
			tc.Failure = &junitFailure{
				Type:    "PolicyViolation",
				Message: rr.Summary,
				Body:    strings.TrimSpace(body.String()),
			}
		}
		cases = append(cases, tc)
	}
	doc := junitSuites{
		Tests:    len(cases),
		Failures: failures,
		Suites: []junitSuite{{
			Name:     "S.O.N.I.C. Policy Gate",
			Tests:    len(cases),
			Failures: failures,
			Cases:    cases,
		}},
	}
	raw, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), raw...), nil
}

// FormatText renders a concise terminal summary of policy gate results.
func FormatText(rep Report) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Gate: %s | %s\n", rep.File, rep.Verdict)
	for _, rr := range rep.Results {
		mark := "PASS"
		if !rr.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(&sb, "[%s] %s: %s\n", mark, rr.Name, rr.Summary)
		for _, v := range rr.Violations {
			fmt.Fprintf(&sb, "  - %s (%s): %s\n", v.Code, v.Detector, v.Message)
		}
	}
	return sb.String()
}
