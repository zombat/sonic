// Package redact provides dotenv key parsing and secret-shape redaction
// mirroring utils/credentials.py so secrets never reach reports, logs, or output.
package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// APIKeyNames lists the environment variable names recognized by S.O.N.I.C.
var APIKeyNames = []string{
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"AZURE_OPENAI_KEY",
}

// EnvFileVariable is the environment variable naming a dotenv file.
const EnvFileVariable = "SONIC_ENV_FILE"

var (
	dotenvLineRe   = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)
	inlineCommentR = regexp.MustCompile(`\s#`)
)

// ParseDotenv parses literal dotenv text (KEY=VALUE, optional "export ",
// single or double quotes, # comments) and returns only the requested keys.
// Errors name only path and the 1-based line number, never any file content.
func ParseDotenv(text string, wanted []string, path string) (map[string]string, error) {
	if path == "" {
		path = "env file"
	}
	if len(wanted) == 0 {
		wanted = APIKeyNames
	}
	wantedSet := make(map[string]struct{}, len(wanted))
	for _, k := range wanted {
		wantedSet[k] = struct{}{}
	}

	found := make(map[string]string)
	lines := splitLines(text)
	for i, raw := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := dotenvLineRe.FindStringSubmatch(raw)
		if m == nil {
			return nil, fmt.Errorf("%s: line %d is not KEY=VALUE", path, lineNum)
		}
		name, value := m[1], m[2]
		if _, keep := wantedSet[name]; !keep {
			continue
		}
		if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
			quote := value[0]
			end := strings.IndexByte(value[1:], quote)
			if end < 0 {
				return nil, fmt.Errorf("%s: line %d has an unterminated quote", path, lineNum)
			}
			end++
			rest := strings.TrimSpace(value[end+1:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return nil, fmt.Errorf("%s: line %d has text after the closing quote", path, lineNum)
			}
			value = value[1:end]
		} else if loc := inlineCommentR.FindStringIndex(value); loc != nil {
			value = strings.TrimRight(value[:loc[0]], " \t\r\n")
		}
		found[name] = value
	}
	return found, nil
}

// splitLines splits text into lines identically to Python str.splitlines().
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	norm := strings.ReplaceAll(text, "\r\n", "\n")
	norm = strings.ReplaceAll(norm, "\r", "\n")
	if strings.HasSuffix(norm, "\n") {
		norm = norm[:len(norm)-1]
	}
	return strings.Split(norm, "\n")
}
