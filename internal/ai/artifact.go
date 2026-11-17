// Package ai implements the Artifact interface and registered ArtifactFactory
// guaranteeing schema normalization, invariant validation, and secret redaction.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/zombat/sonic/internal/redact"
)

// ArtifactKind identifies concrete artifact types constructed by ArtifactFactory.
type ArtifactKind string

const (
	// KindDiagnosticReport produces a validated, redacted DiagnosticArtifact.
	KindDiagnosticReport ArtifactKind = "diagnostic_report"
)

// Artifact is a validated, redacted diagnostic output produced by ArtifactFactory.
type Artifact interface {
	Kind() ArtifactKind
	Validate() error
	Redact(knownSecrets []string)
	JSONBytes() ([]byte, error)
	Markdown() string
}

// BuildContext supplies raw LLM output and capture context to ArtifactFactory builders.
type BuildContext struct {
	Kind         ArtifactKind
	RawText      string
	ModelName    string
	SIPData      string
	FilePath     string
	KnownSecrets []string
}

// ResponseAdapter converts one recognized LLM JSON shape into a DiagnosticReport.
type ResponseAdapter interface {
	Name() string
	Matches(keys map[string]json.RawMessage) bool
	Build(ctx context.Context, buildCtx BuildContext, keys map[string]json.RawMessage) (DiagnosticReport, error)
}

// ArtifactBuilder constructs an Artifact of a registered ArtifactKind from BuildContext.
type ArtifactBuilder func(ctx context.Context, buildCtx BuildContext) (Artifact, error)

// DiagnosticArtifact implements Artifact around a validated DiagnosticReport.
type DiagnosticArtifact struct {
	Report  DiagnosticReport
	RawJSON json.RawMessage
}

// Kind returns KindDiagnosticReport.
func (a *DiagnosticArtifact) Kind() ArtifactKind { return KindDiagnosticReport }

// Validate normalizes required non-nil slices and verifies diagnostic invariants.
func (a *DiagnosticArtifact) Validate() error {
	if a.Report.Calls == nil {
		a.Report.Calls = []CallDiagnostic{}
	}
	if a.Report.Recommendations == nil {
		a.Report.Recommendations = []string{}
	}
	for i := range a.Report.Calls {
		c := &a.Report.Calls[i]
		if c.CallID == "" {
			c.CallID = fmt.Sprintf("call-%d", i+1)
		}
		if c.CallerIP == "" {
			c.CallerIP = "unknown"
		}
		if c.CalleeIP == "" {
			c.CalleeIP = "unknown"
		}
		if c.UserAgents == nil {
			c.UserAgents = []string{}
		}
		if c.AudioQuality.CodecUsed == "" {
			c.AudioQuality.CodecUsed = "Unknown"
		}
		if c.AudioQuality.RTPPort == "" {
			c.AudioQuality.RTPPort = "Unknown"
		}
		if c.AudioQuality.PayloadTypes == nil {
			c.AudioQuality.PayloadTypes = []string{}
		}
		if c.AudioQuality.PotentialIssues == nil {
			c.AudioQuality.PotentialIssues = []string{}
		}
		if c.CallFlow.CallSetupMethod == "" {
			c.CallFlow.CallSetupMethod = "Unknown"
		}
		if c.CallFlow.CallTermination == "" {
			c.CallFlow.CallTermination = "Unknown"
		}
		if c.CallFlow.CallDurationIndicators == "" {
			c.CallFlow.CallDurationIndicators = "Unknown"
		}
		if c.CallFlow.ResponseCodes == nil {
			c.CallFlow.ResponseCodes = []string{}
		}
		if c.DiagnosticSummary == "" {
			c.DiagnosticSummary = "No summary available"
		}
	}
	if a.Report.TotalCallsAnalyzed < 0 {
		return fmt.Errorf("invalid negative total_calls_analyzed: %d", a.Report.TotalCallsAnalyzed)
	}
	return nil
}

// Redact masks knownSecrets and secret shapes from every string in DiagnosticArtifact.
func (a *DiagnosticArtifact) Redact(knownSecrets []string) {
	scrub := func(s string) string { return redact.RedactText(s, knownSecrets...) }
	a.Report.OverallAssessment = scrub(a.Report.OverallAssessment)
	a.Report.AnalysisMethod = scrub(a.Report.AnalysisMethod)
	for i, r := range a.Report.Recommendations {
		a.Report.Recommendations[i] = scrub(r)
	}
	for i := range a.Report.Calls {
		c := &a.Report.Calls[i]
		c.CallID = scrub(c.CallID)
		c.CallerIP = scrub(c.CallerIP)
		c.CalleeIP = scrub(c.CalleeIP)
		c.DiagnosticSummary = scrub(c.DiagnosticSummary)
		for j, ua := range c.UserAgents {
			c.UserAgents[j] = scrub(ua)
		}
		for j, issue := range c.AudioQuality.PotentialIssues {
			c.AudioQuality.PotentialIssues[j] = scrub(issue)
		}
		c.CallFlow.CallDurationIndicators = scrub(c.CallFlow.CallDurationIndicators)
	}
	if len(a.RawJSON) > 0 {
		cleaned := scrub(string(a.RawJSON))
		if json.Valid([]byte(cleaned)) {
			a.RawJSON = json.RawMessage(cleaned)
		}
	}
}

// JSONBytes serializes the validated DiagnosticReport as indented JSON.
func (a *DiagnosticArtifact) JSONBytes() ([]byte, error) {
	return json.MarshalIndent(a.Report, "", "  ")
}

// Markdown renders a concise human-readable markdown report without leaking secrets.
func (a *DiagnosticArtifact) Markdown() string {
	var sb strings.Builder
	sb.WriteString("# S.O.N.I.C. SIP Diagnostic Report\n\n")
	fmt.Fprintf(&sb, "- Total Calls Analyzed: %d\n", a.Report.TotalCallsAnalyzed)
	if a.Report.AnalysisMethod != "" {
		fmt.Fprintf(&sb, "- Analysis Method: %s\n", a.Report.AnalysisMethod)
	}
	fmt.Fprintf(&sb, "- Overall Assessment: %s\n\n", a.Report.OverallAssessment)
	for i, call := range a.Report.Calls {
		fmt.Fprintf(&sb, "## Call %d: %s\n\n", i+1, call.CallID)
		fmt.Fprintf(&sb, "- Endpoints: %s -> %s\n", call.CallerIP, call.CalleeIP)
		fmt.Fprintf(&sb, "- Codec: %s (RTP Port: %s)\n", call.AudioQuality.CodecUsed, call.AudioQuality.RTPPort)
		fmt.Fprintf(&sb, "- Call Flow: %s -> %s\n", call.CallFlow.CallSetupMethod, call.CallFlow.CallTermination)
		fmt.Fprintf(&sb, "- Summary: %s\n\n", call.DiagnosticSummary)
	}
	if len(a.Report.Recommendations) > 0 {
		sb.WriteString("## Recommendations\n\n")
		for _, rec := range a.Report.Recommendations {
			fmt.Fprintf(&sb, "- %s\n", rec)
		}
	}
	return sb.String()
}

// ArtifactFactory constructs validated, redacted Artifacts through registered builders
// and prioritized ResponseAdapters (following ~/auto-roboto factory discipline).
type ArtifactFactory struct {
	builders map[ArtifactKind]ArtifactBuilder
	adapters []ResponseAdapter
}

// NewArtifactFactory builds the default factory pre-loaded with all SIP response adapters.
func NewArtifactFactory() *ArtifactFactory {
	f := NewArtifactFactoryWithBuilders(nil, defaultAdapters())
	f.RegisterBuilder(KindDiagnosticReport, f.buildDiagnosticArtifact)
	return f
}

// NewArtifactFactoryWithBuilders creates an isolated factory with explicit builders and adapters.
func NewArtifactFactoryWithBuilders(builders map[ArtifactKind]ArtifactBuilder, adapters []ResponseAdapter) *ArtifactFactory {
	cloned := make(map[ArtifactKind]ArtifactBuilder, len(builders))
	maps.Copy(cloned, builders)
	clonedAdapters := make([]ResponseAdapter, len(adapters))
	copy(clonedAdapters, adapters)
	return &ArtifactFactory{builders: cloned, adapters: clonedAdapters}
}

// RegisterBuilder adds or replaces an ArtifactBuilder for kind.
func (f *ArtifactFactory) RegisterBuilder(kind ArtifactKind, b ArtifactBuilder) {
	if f.builders == nil {
		f.builders = make(map[ArtifactKind]ArtifactBuilder)
	}
	f.builders[kind] = b
}

// AdapterNames returns the ordered names of registered response adapters.
func (f *ArtifactFactory) AdapterNames() []string {
	out := make([]string, len(f.adapters))
	for i, a := range f.adapters {
		out[i] = a.Name()
	}
	return out
}

// Build constructs, validates, and redacts an Artifact of buildCtx.Kind.
func (f *ArtifactFactory) Build(ctx context.Context, buildCtx BuildContext) (Artifact, error) {
	if buildCtx.Kind == "" {
		return nil, fmt.Errorf("artifact kind must not be empty")
	}
	builder, ok := f.builders[buildCtx.Kind]
	if !ok {
		return nil, fmt.Errorf("unsupported artifact kind: %s", buildCtx.Kind)
	}
	art, err := builder(ctx, buildCtx)
	if err != nil {
		return nil, err
	}
	if err := art.Validate(); err != nil {
		return nil, fmt.Errorf("artifact %s validation failed: %w", buildCtx.Kind, err)
	}
	art.Redact(buildCtx.KnownSecrets)
	return art, nil
}

// BuildDiagnostic is a typed convenience wrapper invoking Build for KindDiagnosticReport.
func (f *ArtifactFactory) BuildDiagnostic(ctx context.Context, buildCtx BuildContext) (*DiagnosticArtifact, error) {
	buildCtx.Kind = KindDiagnosticReport
	art, err := f.Build(ctx, buildCtx)
	if err != nil {
		return nil, err
	}
	diag, ok := art.(*DiagnosticArtifact)
	if !ok {
		return nil, fmt.Errorf("unexpected artifact implementation for %s", buildCtx.Kind)
	}
	return diag, nil
}

func (f *ArtifactFactory) buildDiagnosticArtifact(ctx context.Context, buildCtx BuildContext) (Artifact, error) {
	rawObj, ok := ExtractBalancedJSON(buildCtx.RawText)
	if ok {
		var keys map[string]json.RawMessage
		if json.Unmarshal(rawObj, &keys) == nil && len(keys) > 0 {
			for _, adapter := range f.adapters {
				if adapter.Matches(keys) {
					rep, err := adapter.Build(ctx, buildCtx, keys)
					if err == nil {
						return &DiagnosticArtifact{Report: rep, RawJSON: rawObj}, nil
					}
				}
			}
		}
	}
	if recovered, ok := RecoverLMResponseError(buildCtx.RawText); ok {
		retryCtx := buildCtx
		retryCtx.RawText = recovered
		if subObj, subOK := ExtractBalancedJSON(recovered); subOK {
			var keys map[string]json.RawMessage
			if json.Unmarshal(subObj, &keys) == nil && len(keys) > 0 {
				for _, adapter := range f.adapters {
					if adapter.Matches(keys) {
						rep, err := adapter.Build(ctx, retryCtx, keys)
						if err == nil {
							return &DiagnosticArtifact{Report: rep, RawJSON: subObj}, nil
						}
					}
				}
			}
		}
	}
	rep := buildNaturalLanguageReport(buildCtx.RawText, buildCtx.ModelName)
	return &DiagnosticArtifact{Report: rep}, nil
}
