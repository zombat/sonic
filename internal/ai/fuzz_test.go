package ai

import (
	"context"
	"testing"
)

func FuzzExtractBalancedJSON(f *testing.F) {
	f.Add(`prefix {"totalCalls":1,"calls":[],"overallAssessment":"ok"} suffix`)
	f.Add(`{"nested":{"text":"} brace in string"}}`)
	f.Add(`unclosed { "a": `)
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = ExtractBalancedJSON(raw)
		_, _ = RecoverLMResponseError(raw)
	})
}

func FuzzArtifactFactoryBuild(f *testing.F) {
	f.Add(`{"totalCalls":1,"calls":[],"overallAssessment":"fine"}`)
	f.Add(`192.0.2.1 -> 192.0.2.2 INVITE BYE timeout`)
	f.Add(`{"messages":[{"source_ip":"10.0.0.1","destination_ip":"10.0.0.2","status_code":503}]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		factory := NewArtifactFactory()
		_, _ = factory.BuildDiagnostic(context.Background(), BuildContext{
			RawText:      raw,
			ModelName:    "fuzz",
			KnownSecrets: []string{"sk-ant-api03-fuzzsecret999"},
		})
	})
}
