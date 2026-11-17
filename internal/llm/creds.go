// Package llm manages process environment and dotenv API credentials without
// exposing secret values to subprocesses, logs, reports, or outbound prompts.
package llm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/zombat/sonic/internal/redact"
)

// EnvFileError reports an unreadable or invalid dotenv file without leaking values.
type EnvFileError struct {
	msg string
}

// Error implements error for EnvFileError.
func (e *EnvFileError) Error() string { return e.msg }

// KeyStatus describes whether an API key is configured and where it originated.
type KeyStatus struct {
	Configured bool    `json:"configured"`
	Source     *string `json:"source"`
}

// CredentialStore resolves API keys from process environment first, then an isolated dotenv map.
type CredentialStore struct {
	fileValues map[string]string
	filePath   string
}

// NewCredentialStore loads envFile (or $SONIC_ENV_FILE when empty) as literal data.
func NewCredentialStore(envFile string) (*CredentialStore, error) {
	store := &CredentialStore{fileValues: make(map[string]string)}
	path := envFile
	if path == "" {
		path = os.Getenv(redact.EnvFileVariable)
	}
	if path == "" {
		return store, nil
	}
	expanded, err := expandTilde(path)
	if err != nil {
		return nil, err
	}
	absPath, err := filepath.Abs(expanded)
	if err != nil {
		return nil, &EnvFileError{msg: fmt.Sprintf("cannot resolve env file %s: %s", path, err)}
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return nil, &EnvFileError{msg: fmt.Sprintf("cannot read env file %s: %s", absPath, err)}
	}
	if !utf8.Valid(raw) {
		return nil, &EnvFileError{msg: fmt.Sprintf("env file %s is not UTF-8 text", absPath)}
	}
	parsed, perr := redact.ParseDotenv(string(raw), redact.APIKeyNames, absPath)
	if perr != nil {
		return nil, &EnvFileError{msg: perr.Error()}
	}
	for k, v := range parsed {
		if v != "" {
			store.fileValues[k] = v
		}
	}
	store.filePath = absPath
	return store, nil
}

func expandTilde(p string) (string, error) {
	if p == "~" || len(p) >= 2 && (p[:2] == "~/" || p[:2] == `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", &EnvFileError{msg: fmt.Sprintf("cannot resolve home for %s: %s", p, err)}
		}
		if p == "~" {
			return home, nil
		}
		return filepath.Join(home, p[2:]), nil
	}
	return p, nil
}

// ResolveProvider selects explicit provider, else $SONIC_LLM_PROVIDER, else DefaultProvider.
func ResolveProvider(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv(ProviderVariable); env != "" {
		return env
	}
	return DefaultProvider
}

// APIKeyFor looks up name in process environment first, then loaded dotenv values.
func (s *CredentialStore) APIKeyFor(name string) string {
	if val := os.Getenv(name); val != "" {
		return val
	}
	if s == nil {
		return ""
	}
	return s.fileValues[name]
}

// CredentialStatus returns configuration presence and source per recognized API key.
func (s *CredentialStore) CredentialStatus() map[string]KeyStatus {
	out := make(map[string]KeyStatus, len(redact.APIKeyNames))
	for _, name := range redact.APIKeyNames {
		if os.Getenv(name) != "" {
			src := "environment"
			out[name] = KeyStatus{Configured: true, Source: &src}
			continue
		}
		if s != nil && s.fileValues[name] != "" && s.filePath != "" {
			src := "env file " + s.filePath
			out[name] = KeyStatus{Configured: true, Source: &src}
			continue
		}
		out[name] = KeyStatus{Configured: false, Source: nil}
	}
	return out
}

// KnownSecrets returns active configured secrets of length >= redact.MinSecretLength, longest first.
func (s *CredentialStore) KnownSecrets() []string {
	seen := make(map[string]struct{}, len(redact.APIKeyNames)*2)
	var out []string
	for _, name := range redact.APIKeyNames {
		for _, val := range []string{os.Getenv(name), s.fileKey(name)} {
			if len(val) < redact.MinSecretLength {
				continue
			}
			if _, ok := seen[val]; ok {
				continue
			}
			seen[val] = struct{}{}
			out = append(out, val)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func (s *CredentialStore) fileKey(name string) string {
	if s == nil {
		return ""
	}
	return s.fileValues[name]
}

// Redact scrubs all known API keys and secret patterns from text.
func (s *CredentialStore) Redact(text string) string {
	if text == "" {
		return text
	}
	return redact.RedactText(text, s.KnownSecrets()...)
}

var providerEnvKey = map[string]string{
	"anthropic": "ANTHROPIC_API_KEY",
	"openai":    "OPENAI_API_KEY",
	"azure":     "AZURE_OPENAI_KEY",
}
