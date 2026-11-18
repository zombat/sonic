package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/redact"
)

func TestOfflineHTMLReportRenderingAndXSSRedactionSafety(t *testing.T) {
	t.Parallel()

	sampleJSON := `{
		"status": "success",
		"overall_status": "warning",
		"file": "cap<script>alert(1)</script>.pcap",
		"verdict": "Warning found",
		"protocols_present": ["tls", "http2"],
		"verdicts": {"tls": "Weak cipher chosen"},
		"issues": [{"severity": "warning", "detector": "tls", "code": "TLS_OLD_VERSION", "message": "Authorization: Bearer tok_1234567890abcdef <img src=x onerror=alert(1)>", "frames": [1, 2]}],
		"timeline": [{"t": 0.125, "protocol": "tls", "event": "handshake", "detail": "ClientHello"}],
		"highlights": ["TLS 1.0 negotiated"],
		"results": [{"name": "no-weak-crypto", "passed": false, "summary": "TLS 1.0 found"}],
		"cross_layer_links": [{"underlay_area": "ipsec", "severity": "error", "summary": "ESP stale SPI"}]
	}`

	audit := &redact.AuditCounts{KnownSecrets: 1, Total: 1}
	htmlOut, err := RenderHTMLReport("S.O.N.I.C. Audit", []byte(sampleJSON), audit)
	if err != nil {
		t.Fatalf("RenderHTMLReport failed: %v", err)
	}
	if strings.Contains(htmlOut, "tok_1234567890abcdef") {
		t.Fatal("secret leaked into HTML report")
	}
	if strings.Contains(htmlOut, "<script>alert(1)</script>") || strings.Contains(htmlOut, "<img src=x") {
		t.Fatal("raw unescaped HTML script/tag leaked into HTML report")
	}
	if strings.Contains(htmlOut, "https://") || strings.Contains(htmlOut, "http://") {
		t.Fatal("offline HTML report must contain zero external network URLs")
	}
	if !strings.Contains(htmlOut, "TLS_OLD_VERSION") || !strings.Contains(htmlOut, "Redaction Audit") {
		t.Fatalf("missing expected HTML sections")
	}

	outPath := filepath.Join(t.TempDir(), "nested", "report.html")
	if err := SaveHTMLReport(outPath, "S.O.N.I.C. Ticket", []byte(sampleJSON), nil); err != nil {
		t.Fatalf("SaveHTMLReport failed: %v", err)
	}
	saved, err := os.ReadFile(outPath)
	if err != nil || !strings.Contains(string(saved), "<!DOCTYPE html>") {
		t.Fatalf("saved HTML missing doctype: err=%v", err)
	}

	if _, err := RenderHTMLReport("", []byte("not json"), nil); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}
