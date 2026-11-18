// Package llm provides redacting formatters, JSON marshalers, and slog
// LogValuer methods for Config and Endpoint so API credentials never serialize
// into logs, %v/%+v/%#v formatting, or JSON output.
package llm

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

const redactedMarker = "[REDACTED]"

func redactFlag(secret string) string {
	if secret == "" {
		return ""
	}
	return redactedMarker
}

// String formats Config for %v/%+v while masking APIKey.
func (c Config) String() string {
	return fmt.Sprintf("{Provider:%s ModelName:%s APIKey:%s Temperature:%g MaxTokens:%d AllowPlaintextCredentials:%t}",
		c.Provider, c.ModelName, redactFlag(c.APIKey), c.Temperature, c.MaxTokens, c.AllowPlaintextCredentials)
}

// GoString formats Config for %#v while masking APIKey.
func (c Config) GoString() string {
	return fmt.Sprintf("llm.Config{Provider:%q, ModelName:%q, APIKey:%q, Temperature:%g, MaxTokens:%d, AllowPlaintextCredentials:%t}",
		c.Provider, c.ModelName, redactFlag(c.APIKey), c.Temperature, c.MaxTokens, c.AllowPlaintextCredentials)
}

// MarshalJSON serializes non-sensitive Config fields while omitting APIKey.
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Provider                  string  `json:"provider"`
		ModelName                 string  `json:"model_name"`
		Temperature               float64 `json:"temperature"`
		MaxTokens                 int     `json:"max_tokens"`
		AllowPlaintextCredentials bool    `json:"allow_plaintext_credentials,omitempty"`
	}{
		Provider:                  c.Provider,
		ModelName:                 c.ModelName,
		Temperature:               c.Temperature,
		MaxTokens:                 c.MaxTokens,
		AllowPlaintextCredentials: c.AllowPlaintextCredentials,
	})
}

// LogValue emits Config attributes to slog while masking APIKey.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", c.Provider),
		slog.String("model_name", c.ModelName),
		slog.String("api_key", redactFlag(c.APIKey)),
		slog.Float64("temperature", c.Temperature),
		slog.Int("max_tokens", c.MaxTokens),
	)
}

// String formats Endpoint for %v/%+v while masking Key.
func (e Endpoint) String() string {
	base := ""
	if e.Base != nil {
		base = e.Base.Redacted()
	}
	return fmt.Sprintf("{Base:%s Key:%s APIVersion:%s}", base, redactFlag(e.Key), e.APIVersion)
}

// GoString formats Endpoint for %#v while masking Key.
func (e Endpoint) GoString() string {
	base := ""
	if e.Base != nil {
		base = e.Base.Redacted()
	}
	return fmt.Sprintf("llm.Endpoint{Base:%q, Key:%q, APIVersion:%q}", base, redactFlag(e.Key), e.APIVersion)
}

// MarshalJSON serializes non-sensitive Endpoint fields while omitting Key.
func (e Endpoint) MarshalJSON() ([]byte, error) {
	base := ""
	if e.Base != nil {
		base = e.Base.Redacted()
	}
	return json.Marshal(struct {
		Base       string `json:"base"`
		APIVersion string `json:"api_version,omitempty"`
	}{
		Base:       base,
		APIVersion: e.APIVersion,
	})
}

// LogValue emits Endpoint attributes to slog while masking Key.
func (e Endpoint) LogValue() slog.Value {
	base := ""
	if e.Base != nil {
		base = e.Base.Redacted()
	}
	return slog.GroupValue(
		slog.String("base", base),
		slog.String("key", redactFlag(e.Key)),
		slog.String("api_version", e.APIVersion),
	)
}
