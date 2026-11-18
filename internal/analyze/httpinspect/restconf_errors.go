// Package httpinspect implements RFC 8040 RESTCONF JSON and XML error document parsing.
package httpinspect

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"slices"
	"strings"
)

// errorFields lists the canonical RFC 8040 section 3.9 error object members.
var errorFields = []string{"error-type", "error-tag", "error-app-tag", "error-path", "error-message"}

// ParseRestconfErrors decodes RFC 8040 JSON or XML ietf-restconf:errors payloads.
func ParseRestconfErrors(body []byte, contentType string) []map[string]string {
	if len(body) == 0 {
		return []map[string]string{}
	}
	text := strings.TrimSpace(strings.ToValidUTF8(string(body), "\ufffd"))
	lowCT := strings.ToLower(contentType)
	looksJSON := strings.HasPrefix(text, "{") || strings.Contains(lowCT, "json")
	looksXML := strings.HasPrefix(text, "<") || strings.Contains(lowCT, "xml")

	if looksJSON {
		if errs := restconfErrorsJSON(text); len(errs) > 0 {
			return errs
		}
	}
	if looksXML {
		return restconfErrorsXML(text)
	}
	if errs := restconfErrorsJSON(text); len(errs) > 0 {
		return errs
	}
	return restconfErrorsXML(text)
}

// restconfErrorsJSON parses RFC 8040 JSON error objects from "ietf-restconf:errors" or "errors".
func restconfErrorsJSON(text string) []map[string]string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &top); err != nil || top == nil {
		return []map[string]string{}
	}
	var containerRaw json.RawMessage
	for _, key := range []string{"ietf-restconf:errors", "errors"} {
		if raw, ok := top[key]; ok {
			trimmed := bytes.TrimSpace(raw)
			if len(trimmed) > 0 && trimmed[0] == '{' {
				containerRaw = trimmed
				break
			}
		}
	}
	if len(containerRaw) == 0 {
		return []map[string]string{}
	}

	var container map[string]json.RawMessage
	if err := json.Unmarshal(containerRaw, &container); err != nil || container == nil {
		return []map[string]string{}
	}
	rawErr := bytes.TrimSpace(container["error"])
	if len(rawErr) == 0 {
		return []map[string]string{}
	}

	var entries []map[string]json.RawMessage
	switch rawErr[0] {
	case '[':
		if err := json.Unmarshal(rawErr, &entries); err != nil {
			return []map[string]string{}
		}
	case '{':
		var single map[string]json.RawMessage
		if err := json.Unmarshal(rawErr, &single); err != nil {
			return []map[string]string{}
		}
		entries = []map[string]json.RawMessage{single}
	default:
		return []map[string]string{}
	}

	out := make([]map[string]string, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		parsed := make(map[string]string)
		for _, k := range errorFields {
			rawVal, ok := entry[k]
			if !ok {
				continue
			}
			if val, valid := decodeJSONScalar(rawVal); valid {
				parsed[k] = val
			}
		}
		if len(parsed) > 0 {
			out = append(out, parsed)
		}
	}
	return out
}

// decodeJSONScalar converts a JSON scalar value into its string representation matching Python str().
func decodeJSONScalar(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", false
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return s, true
	}
	switch {
	case bytes.Equal(trimmed, []byte("true")):
		return "True", true
	case bytes.Equal(trimmed, []byte("false")):
		return "False", true
	default:
		return string(trimmed), true
	}
}

// restconfErrorsXML parses RFC 8040 XML <error> elements ignoring namespace prefixes.
func restconfErrorsXML(text string) []map[string]string {
	dec := xml.NewDecoder(strings.NewReader(text))
	out := []map[string]string{}
	var stack []string
	errDepth := 0
	var cur map[string]string
	var childField string
	var childText strings.Builder

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return []map[string]string{}
		}
		switch v := tok.(type) {
		case xml.StartElement:
			stack = append(stack, v.Name.Local)
			if v.Name.Local == "error" && cur == nil {
				errDepth = len(stack)
				cur = make(map[string]string)
			} else if cur != nil && len(stack) == errDepth+1 && slices.Contains(errorFields, v.Name.Local) {
				childField = v.Name.Local
				childText.Reset()
			}
		case xml.CharData:
			if cur != nil && childField != "" && len(stack) == errDepth+1 {
				childText.Write(v)
			}
		case xml.EndElement:
			if cur != nil && len(stack) == errDepth+1 && childField != "" && v.Name.Local == childField {
				if raw := childText.String(); raw != "" {
					cur[childField] = strings.TrimSpace(raw)
				}
				childField = ""
				childText.Reset()
			} else if cur != nil && len(stack) == errDepth && v.Name.Local == "error" {
				if len(cur) > 0 {
					out = append(out, cur)
				}
				cur = nil
				errDepth = 0
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return out
}
