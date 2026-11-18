package tui

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
)

func TestInteractiveTUINavigationFilterAndQuit(t *testing.T) {
	t.Parallel()

	sampleJSON := `{
		"status": "success",
		"overall_status": "warning",
		"file": "voip_wan.pcap",
		"verdict": "Media clipping detected during IKE rekey",
		"protocols_present": ["sip", "ike", "esp"],
		"verdicts": {"ipsec": "Stale SPI 0x100", "qos": "DSCP EF preserved"},
		"issues": [
			{"severity": "error", "detector": "ipsec", "code": "ESP_STALE_SPI", "message": "ESP packets missed active SA", "frames": [4, 5]},
			{"severity": "warning", "detector": "sip", "code": "MEDIA_CLIPPING", "message": "Post-200 OK delay 900 ms", "frames": [8]}
		],
		"timeline": [{"t": 1.25, "protocol": "ike", "event": "rekey", "detail": "Child SA replaced"}],
		"highlights": ["VOIP degraded by ESP_STALE_SPI"]
	}`
	digest, err := report.ParseReportDigest("S.O.N.I.C. TUI Test", []byte(sampleJSON), &redact.AuditCounts{BearerTokens: 1, Total: 1})
	if err != nil {
		t.Fatalf("ParseReportDigest: %v", err)
	}

	// Simulate single-keystroke interactive input across all 5 tabs, scrolling, filter, and quit.
	keys := "2j\x1b[B\x1b[Aknp3/rekey\n45c1q"
	var out bytes.Buffer
	if err := Run(digest, iotest.OneByteReader(strings.NewReader(keys)), &out); err != nil {
		t.Fatalf("tui Run failed: %v", err)
	}
	rendered := out.String()
	for _, want := range []string{"ESP_STALE_SPI", "Child SA replaced", "VOIP degraded", "Redaction Audit: total=1", "1:Overview", "Media clipping detected"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("TUI output missing %q", want)
		}
	}

	// Test empty sections, filter-no-match, backspace/Esc in filter, non-TTY os.File check, and EOF exit.
	emptyDigest, err := report.ParseReportDigest("Empty", []byte(`{"status":"ok"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out2 bytes.Buffer
	if err := Run(emptyDigest, iotest.OneByteReader(strings.NewReader("234/nomatch\x7fa\r5")), &out2); err != nil {
		t.Fatalf("empty tui Run failed: %v", err)
	}
	if !strings.Contains(out2.String(), "No issues reported.") || !strings.Contains(out2.String(), "No timeline events recorded.") || !strings.Contains(out2.String(), "no rows match filter") {
		t.Fatalf("missing empty/filter messages in TUI output: %s", out2.String())
	}
	if f, ferr := os.Open(os.DevNull); ferr == nil {
		defer f.Close()
		enableRawInput(f)()
	}
	if toks := parseInputTokens([]byte{0x1b, '[', 'A', 0x1b, '[', 'B', 0x1b, 'x'}); len(toks) != 4 {
		t.Fatalf("parseInputTokens unexpected: %v", toks)
	}
}

func TestTUISanitizesANSIEscapesAndControlChars(t *testing.T) {
	t.Parallel()

	payload := "\x1b[2J\x1b[H\x1b]0;spoof\x07evil\r\ninjected\x1b\\next"
	digest := report.ReportDigest{
		Title: payload,
		File:  "cap\x1b[31m.pcap",
		Issues: []report.DigestIssue{{
			Severity: "warning",
			Detector: "sip",
			Code:     "CODE",
			Message:  payload,
		}},
		PrettyJSON: `{"verdict":"` + payload + `"}`,
	}
	var out bytes.Buffer
	if err := Run(digest, strings.NewReader("25q"), &out); err != nil {
		t.Fatalf("tui Run failed: %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "evil injected") {
		t.Fatalf("expected sanitized text 'evil injected', got %q", rendered)
	}
	if strings.Contains(rendered, "\x1b]0;spoof") || strings.Contains(rendered, "\x1b[31m") {
		t.Fatalf("terminal escape injection leaked into TUI output: %q", rendered)
	}
	if got := SanitizeTerminalText("ok\u009b31m\x7f\x01\tdone\x1b"); got != "ok31m\tdone" {
		t.Fatalf("SanitizeTerminalText = %q", got)
	}
}

func FuzzSanitizeTerminalText(f *testing.F) {
	for _, seed := range []string{
		"",
		"plain ascii",
		"\x1b[2J\x1b[H\x1b]0;spoof\x07evil\r\ninjected",
		"\x1bPdevice\x1b\\\u009b1m\x7f\x00test",
		"\x1b",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := SanitizeTerminalText(s)
		for _, r := range out {
			if r == 0x1b || r == '\r' || r == '\n' || (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("unsanitized rune %#x in output %q", r, out)
			}
		}
	})
}
