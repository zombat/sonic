// Package aaainspect key-file parsing for TACACS+ and RADIUS shared secrets.
package aaainspect

import (
	"errors"
	"os"
	"strings"
)

var (
	tacacsKeyAliases = map[string]bool{
		"tacacs_key": true, "tacacs-key": true, "tacplus.key": true, "tacplus_key": true, "tacacs": true,
	}
	radiusSecretAliases = map[string]bool{
		"radius_secret": true, "radius-secret": true, "radius.shared_secret": true, "radius_shared_secret": true, "radius": true,
	}
)

// ReadKeysFile loads (tacacsKey, radiusSecret) from a key=value, YAML-like, or single-line bare key file.
// Secret values are never included in returned error messages.
func ReadKeysFile(path string) (*string, *string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var tacacs, radius, bare *string
	recognised := false
	for _, lineRaw := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(lineRaw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, ":=") {
			sep := "="
			cIdx := strings.IndexByte(line, ':')
			eIdx := strings.IndexByte(line, '=')
			if cIdx >= 0 && (eIdx < 0 || cIdx < eIdx) {
				sep = ":"
			}
			idx := strings.Index(line, sep)
			name := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.Trim(strings.Trim(strings.TrimSpace(line[idx+len(sep):]), `"`), `'`)
			if val == "" {
				continue
			}
			if tacacsKeyAliases[name] {
				v := val
				tacacs = &v
				recognised = true
			} else if radiusSecretAliases[name] {
				v := val
				radius = &v
				recognised = true
			}
		} else if bare == nil {
			v := line
			bare = &v
		}
	}
	if !recognised {
		if bare != nil {
			v1, v2 := *bare, *bare
			return &v1, &v2, nil
		}
		return nil, nil, errors.New("no tacacs_key or radius_secret found in the key file")
	}
	return tacacs, radius, nil
}
