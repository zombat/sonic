package llm

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzSSEEvents(f *testing.F) {
	f.Add("event: message\ndata: {\"a\":1}\n\ndata: [DONE]\n\n")
	f.Add(": keepalive\ndata: line1\ndata: line2\n\n")
	f.Fuzz(func(t *testing.T, input string) {
		_ = sseEvents(strings.NewReader(input), func(string, []byte) error {
			return nil
		})
	})
}

func FuzzNDJSON(f *testing.F) {
	f.Add([]byte("{\"done\":true}\n{\"message\":{\"content\":\"hi\"}}\n"))
	f.Add([]byte("\n  \nnot-json\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ndjson(bytes.NewReader(data), func([]byte) error {
			return nil
		})
	})
}

func FuzzValidateBaseURL(f *testing.F) {
	f.Add("https://api.openai.com/v1", true, false)
	f.Add("http://127.0.0.1:11434", true, false)
	f.Add("http://user:pass@localhost", false, true)
	f.Fuzz(func(t *testing.T, raw string, hasKey, allowPlain bool) {
		_, _ = validateBaseURL(raw, hasKey, allowPlain)
	})
}
