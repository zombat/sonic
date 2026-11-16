// Package main provides the thin S.O.N.I.C. CLI composition root wiring
// extractor and analyzer packages without embedded business logic.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/audit"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/tshark"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "dump" {
		return runDump(ctx, args[1:], stdout, stderr)
	}
	return runAudit(ctx, args, stdout, stderr)
}

func runDump(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	filePath := fs.String("file", "", "pcap/pcapng file path")
	displayFilter := fs.String("display-filter", "", "wireshark display filter")
	maxPackets := fs.Int("max-packets", 0, "maximum frames to read")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *filePath == "" {
		fmt.Fprintln(stderr, "missing required --file flag")
		return 1
	}

	var maxPtr *int
	if *maxPackets > 0 {
		v := *maxPackets
		maxPtr = &v
	}
	out, err := extract.OpenNetworkRecords(ctx, tshark.StreamOptions{
		FilePath:      *filePath,
		DisplayFilter: *displayFilter,
		MaxPackets:    maxPtr,
	})
	if err != nil {
		fmt.Fprintln(stderr, redact.RedactText(err.Error()))
		return 1
	}
	return writeJSON(stdout, stderr, out)
}

func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sonic", flag.ContinueOnError)
	fs.SetOutput(stderr)
	filePath := fs.String("file", "", "pcap/pcapng file path")
	_ = fs.Bool("network-only", true, "run deterministic network detectors")
	detectorsCSV := fs.String("detectors", "cleartext_audit", "comma-separated detector list")
	allowCSV := fs.String("allow", "", "comma-separated allowlist tokens for cleartext_audit")
	displayFilter := fs.String("display-filter", "", "wireshark display filter")
	maxPackets := fs.Int("max-packets", 0, "maximum frames to read")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *filePath == "" {
		fmt.Fprintln(stderr, "missing required --file flag")
		return 1
	}

	detectors := splitCSV(*detectorsCSV)
	if len(detectors) == 0 {
		detectors = []string{"cleartext_audit"}
	}
	if !slices.Contains(detectors, "cleartext_audit") {
		if *allowCSV != "" {
			fmt.Fprintln(stderr, "--allow needs --detectors cleartext_audit")
			return 1
		}
		fmt.Fprintf(stderr, "unsupported stage 1 detector(s): %s\n", strings.Join(detectors, ","))
		return 1
	}

	var maxPtr *int
	if *maxPackets > 0 {
		v := *maxPackets
		maxPtr = &v
	}
	report, err := audit.AuditCleartextCapture(ctx, audit.AuditOptions{
		FilePath:      *filePath,
		Allow:         splitCSV(*allowCSV),
		DisplayFilter: *displayFilter,
		MaxPackets:    maxPtr,
	})
	if err != nil {
		report.Error = redact.RedactText(report.Error)
		if *asJSON {
			_ = writeJSON(stdout, stderr, report)
		} else {
			fmt.Fprintln(stderr, redact.RedactText(err.Error()))
		}
		return 1
	}

	if *asJSON {
		return writeJSON(stdout, stderr, report)
	}
	fmt.Fprintln(stdout, report.Verdict)
	return 0
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	return 0
}
