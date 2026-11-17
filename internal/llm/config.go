// Package llm configures provider model tables, sampling defaults, and
// list_llm_providers status snapshots matching llm_config.py.
package llm

import (
	"os"
	"slices"
	"strconv"
)

// ProviderModels defines fast, detailed, and deep model defaults per provider.
var ProviderModels = map[string]map[string]string{
	"ollama": {
		ProfileFast:     "qwen2.5:0.5b",
		ProfileDetailed: "mistral:7b",
	},
	"anthropic": {
		ProfileFast:     "claude-haiku-5-5",
		ProfileDetailed: "claude-sonnet-5-5",
		ProfileDeep:     "claude-opus-5-5",
	},
	"openai": {
		ProfileFast:     "gpt-4o-mini",
		ProfileDetailed: "gpt-4o",
	},
	"azure": {
		ProfileFast:     "gpt-4o-mini",
		ProfileDetailed: "gpt-4o",
	},
}

// GetModelName resolves the concrete model identifier for provider, profile, and override.
func GetModelName(providerName, profile, override string) string {
	if override != "" {
		return override
	}
	if !slices.Contains(Profiles, profile) {
		profile = ProfileFast
	}
	models := ProviderModels[providerName]
	if profile == ProfileDeep {
		if _, ok := models[ProfileDeep]; !ok {
			profile = ProfileDetailed
		}
	}
	if m := models[profile]; m != "" {
		return m
	}
	return models[ProfileFast]
}

// NewConfig builds Config from env defaults (SONIC_LLM_TEMPERATURE, SONIC_LLM_MAX_TOKENS).
func NewConfig(provider, modelName, apiKey string, creds *CredentialStore) Config {
	temp := 0.7
	if raw := os.Getenv("SONIC_LLM_TEMPERATURE"); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			temp = parsed
		}
	}
	maxTok := 4000
	if raw := os.Getenv("SONIC_LLM_MAX_TOKENS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			maxTok = parsed
		}
	}
	resolved := ResolveProvider(provider)
	key := apiKey
	if key == "" {
		if envName := providerEnvKey[resolved]; envName != "" {
			key = creds.APIKeyFor(envName)
		}
	}
	return Config{
		Provider:    resolved,
		ModelName:   modelName,
		APIKey:      key,
		Temperature: temp,
		MaxTokens:   maxTok,
	}
}

// ProvidersListing matches MCP list_llm_providers and llm_config.list_available_providers().
type ProvidersListing struct {
	Providers     []string                     `json:"providers"`
	Models        map[string]map[string]string `json:"models"`
	Default       string                       `json:"default"`
	CurrentConfig CurrentLLMConfig             `json:"current_config"`
}

// CurrentLLMConfig summarizes resolved provider and configured key presence (never key values).
type CurrentLLMConfig struct {
	Provider        string               `json:"provider"`
	Credentials     map[string]KeyStatus `json:"credentials"`
	AnthropicKeySet bool                 `json:"anthropic_key_set"`
	OpenAIKeySet    bool                 `json:"openai_key_set"`
}

// ListProviders constructs the redacted provider/model/credential status payload.
func ListProviders(creds *CredentialStore) ProvidersListing {
	status := creds.CredentialStatus()
	return ProvidersListing{
		Providers: []string{"ollama", "anthropic", "openai", "azure"},
		Models:    ProviderModels,
		Default:   DefaultProvider,
		CurrentConfig: CurrentLLMConfig{
			Provider:        ResolveProvider(""),
			Credentials:     status,
			AnthropicKeySet: status["ANTHROPIC_API_KEY"].Configured,
			OpenAIKeySet:    status["OPENAI_API_KEY"].Configured,
		},
	}
}
