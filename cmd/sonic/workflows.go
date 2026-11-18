// Package main implements v4.0 workflow commands and flags (gate, diff, tui,
// correlate-media, window bounds, redaction audit, and offline HTML export).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/diff"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/gate"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
	"github.com/zombat/sonic/internal/tui"
)

func runCorrelateMedia(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	sincePtr, untilPtr, ok := parseWindowBounds(o.sinceStr, o.untilStr, stderr)
	if !ok {
		return 2
	}
	rep := netorch.AnalyzeMediaUnderlay(ctx, o.file, netorch.UnderlayCorrelationOptions{
		Peers:         splitCSV(o.peersCSV),
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
		Since:         sincePtr,
		Until:         untilPtr,
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Media/Underlay Diagnosis: %s\nVerdict: %s\n", rep.File, rep.Verdict)
	for _, link := range rep.CrossLayerLinks {
		fmt.Fprintf(&sb, "  - [%s/%s] %s (frames: %v)\n", link.Severity, link.UnderlayArea, link.Summary, link.Frames)
	}
	var saveErr error
	if o.saveFile != "" && !isHTMLPath(o.saveFile) {
		saveErr = report.SaveRawReport(raw, merr, sb.String(), o.saveFile)
	}
	return deliverArtifacts(raw, merr, o.saveFile, saveErr, "S.O.N.I.C. Media-Underlay Diagnosis", o.file, sb.String(), o, stdin, stdout, stderr)
}

func runDiffPairFlag(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	parts := splitCSV(o.diffPair)
	if len(parts) != 2 {
		fmt.Fprintln(stderr, "--diff expects BASE,TARGET capture paths")
		return 2
	}
	return executeDiff(ctx, parts[0], parts[1], splitCSV(o.detectorsCSV), o, stdin, stdout, stderr)
}

func runDiffSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("baseline", "", "baseline (working) pcap/pcapng path")
	target := fs.String("target", "", "target (broken) pcap/pcapng path")
	var o cliOptions
	fs.StringVar(&o.detectorsCSV, "detectors", "", "comma-separated detector list")
	fs.StringVar(&o.peersCSV, "peers", "", "comma-separated VPN peer IPs")
	fs.StringVar(&o.displayFilter, "display-filter", "", "wireshark display filter")
	fs.IntVar(&o.maxPackets, "max-packets", 0, "maximum frames to read")
	fs.StringVar(&o.saveFile, "save_file", "", "path to save markdown, JSON, or HTML diff report")
	fs.StringVar(&o.htmlPath, "html", "", "write offline HTML5 report to FILE")
	fs.BoolVar(&o.tuiMode, "tui", false, "open interactive TUI viewer")
	fs.BoolVar(&o.redactAudit, "redact-audit", false, "include secret redaction counts")
	fs.BoolVar(&o.asJSON, "json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *base == "" || *target == "" {
		fmt.Fprintln(stderr, "diff requires --baseline and --target")
		return 2
	}
	return executeDiff(ctx, *base, *target, splitCSV(o.detectorsCSV), o, stdin, stdout, stderr)
}

func executeDiff(ctx context.Context, base, target string, detectors []string, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	rep := diff.CompareCaptures(ctx, base, target, diff.Options{
		Peers:         splitCSV(o.peersCSV),
		Detectors:     detectors,
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	summary := diff.FormatDiffSummary(rep)
	var saveErr error
	if o.saveFile != "" && !isHTMLPath(o.saveFile) {
		saveErr = report.SaveRawReport(raw, merr, summary, o.saveFile)
	}
	label := fmt.Sprintf("%s vs %s", base, target)
	return deliverArtifacts(raw, merr, o.saveFile, saveErr, "S.O.N.I.C. Capture Diff", label, summary, o, stdin, stdout, stderr)
}

func runGateSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o cliOptions
	policyCSV := fs.String("policy", "", "comma-separated policy rules (zero-cleartext,no-weak-crypto,mos-min=3.8,max-clipping-ms=500,no-critical-issues)")
	format := fs.String("format", "text", "output format: text, json, sarif, or junit")
	fs.StringVar(&o.file, "file", "", "pcap/pcapng file path")
	fs.StringVar(&o.allowCSV, "allow", "", "comma-separated allowlist tokens for zero-cleartext")
	fs.StringVar(&o.peersCSV, "peers", "", "comma-separated VPN peer IPs")
	fs.StringVar(&o.displayFilter, "display-filter", "", "wireshark display filter")
	fs.IntVar(&o.maxPackets, "max-packets", 0, "maximum frames to read")
	fs.StringVar(&o.saveFile, "save_file", "", "optional path to write output payload")
	fs.StringVar(&o.htmlPath, "html", "", "write offline HTML5 report to FILE")
	fs.BoolVar(&o.redactAudit, "redact-audit", false, "include secret redaction counts")
	fs.BoolVar(&o.asJSON, "json", false, "shorthand for --format json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if o.file == "" {
		fmt.Fprintln(stderr, "gate requires --file")
		return 2
	}
	outFmt := strings.ToLower(strings.TrimSpace(*format))
	if o.asJSON {
		outFmt = "json"
	}

	rep := gate.Evaluate(ctx, o.file, gate.Options{
		Policies:      splitCSV(*policyCSV),
		Allow:         splitCSV(o.allowCSV),
		Peers:         splitCSV(o.peersCSV),
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	rawJSON, merr := json.MarshalIndent(rep, "", "  ")
	if rep.ExitCode == 1 || rep.ExitCode == 2 {
		if outFmt == "json" {
			_ = writeJSONBytes(stdout, stderr, rawJSON, merr)
		} else {
			fmt.Fprintln(stderr, redact.RedactText(rep.Error))
		}
		return rep.ExitCode
	}

	var auditPtr *redact.AuditCounts
	rawJSON, auditPtr = maybeApplyRedactAudit(rawJSON, o.redactAudit, stderr)
	if o.htmlPath != "" {
		if err := report.SaveHTMLReport(o.htmlPath, "S.O.N.I.C. Policy Gate", rawJSON, auditPtr); err != nil {
			fmt.Fprintf(stderr, "failed to save HTML report: %s\n", redact.RedactText(err.Error()))
		}
	}

	var payload string
	switch outFmt {
	case "text":
		payload = gate.FormatText(rep)
	case "json":
		payload = string(rawJSON) + "\n"
	case "sarif":
		b, err := gate.FormatSARIF(rep)
		if err != nil {
			fmt.Fprintln(stderr, redact.RedactText(err.Error()))
			return 1
		}
		payload = redact.RedactText(string(b)) + "\n"
	case "junit":
		b, err := gate.FormatJUnit(rep)
		if err != nil {
			fmt.Fprintln(stderr, redact.RedactText(err.Error()))
			return 1
		}
		payload = redact.RedactText(string(b)) + "\n"
	default:
		fmt.Fprintf(stderr, "unsupported gate --format %q (want text, json, sarif, or junit)\n", *format)
		return 2
	}
	if o.saveFile != "" {
		if isHTMLPath(o.saveFile) {
			_ = report.SaveHTMLReport(o.saveFile, "S.O.N.I.C. Policy Gate", rawJSON, auditPtr)
		} else {
			_ = report.WriteRedacted(o.saveFile, payload)
		}
	}
	_, _ = io.WriteString(stdout, payload)
	return rep.ExitCode
}

func runTUISubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runCommandWithDepsIO(ctx, append([]string{"--tui"}, args...), stdin, stdout, stderr, defaultLLMRuntimeDeps())
}

func deliverArtifacts(
	raw []byte,
	merr error,
	savePath string,
	saveErr error,
	title, fileLabel, summary string,
	o cliOptions,
	stdin io.Reader,
	stdout, stderr io.Writer,
) int {
	if saveErr != nil {
		fmt.Fprintf(stderr, "failed to save report: %s\n", redact.RedactText(saveErr.Error()))
	}
	var auditPtr *redact.AuditCounts
	raw, auditPtr = maybeApplyRedactAudit(raw, o.redactAudit, stderr)
	if savePath != "" && isHTMLPath(savePath) {
		if herr := report.SaveHTMLReport(savePath, title, raw, auditPtr); herr != nil {
			fmt.Fprintf(stderr, "failed to save HTML report: %s\n", redact.RedactText(herr.Error()))
		}
	}
	if o.htmlPath != "" {
		if herr := report.SaveHTMLReport(o.htmlPath, title, raw, auditPtr); herr != nil {
			fmt.Fprintf(stderr, "failed to save HTML report: %s\n", redact.RedactText(herr.Error()))
		}
	}
	if o.tuiMode {
		digest, derr := report.ParseReportDigest(title, raw, auditPtr)
		if derr != nil {
			fmt.Fprintln(stderr, redact.RedactText(derr.Error()))
			return 1
		}
		if digest.File == "" {
			digest.File = fileLabel
		}
		if terr := tui.Run(digest, stdin, stdout); terr != nil {
			fmt.Fprintln(stderr, redact.RedactText(terr.Error()))
			return 1
		}
		return 0
	}
	if o.asJSON {
		return writeJSONBytes(stdout, stderr, raw, merr)
	}
	fmt.Fprint(stdout, summary)
	return 0
}

func maybeApplyRedactAudit(raw []byte, enabled bool, stderr io.Writer) ([]byte, *redact.AuditCounts) {
	if !enabled || len(raw) == 0 {
		return raw, nil
	}
	redacted, counts := redact.RedactTextWithAudit(string(raw))
	fmt.Fprintf(stderr, "Redaction audit: total=%d known=%d auth=%d pem=%d jwt=%d tokens=%d bearer=%d basic=%d assign=%d sdp=%d\n",
		counts.Total, counts.KnownSecrets, counts.AuthHeaders, counts.PEMBlocks,
		counts.JWTs, counts.ProviderTokens, counts.BearerTokens, counts.BasicAuth,
		counts.Assignments, counts.SDPKeys)
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(redacted), &obj) == nil && obj != nil {
		if cb, err := json.Marshal(counts); err == nil {
			obj["redact_audit"] = cb
			if merged, err := json.MarshalIndent(obj, "", "  "); err == nil {
				return merged, &counts
			}
		}
	}
	return []byte(redacted), &counts
}

func isHTMLPath(p string) bool {
	low := strings.ToLower(strings.TrimSpace(p))
	return strings.HasSuffix(low, ".html") || strings.HasSuffix(low, ".htm")
}

func parseWindowBounds(sinceRaw, untilRaw string, stderr io.Writer) (*float64, *float64, bool) {
	var sincePtr, untilPtr *float64
	if strings.TrimSpace(sinceRaw) != "" {
		v, err := strconv.ParseFloat(strings.TrimSpace(sinceRaw), 64)
		if err != nil {
			fmt.Fprintf(stderr, "invalid --since value %q: %v\n", sinceRaw, err)
			return nil, nil, false
		}
		sincePtr = &v
	}
	if strings.TrimSpace(untilRaw) != "" {
		v, err := strconv.ParseFloat(strings.TrimSpace(untilRaw), 64)
		if err != nil {
			fmt.Fprintf(stderr, "invalid --until value %q: %v\n", untilRaw, err)
			return nil, nil, false
		}
		untilPtr = &v
	}
	return sincePtr, untilPtr, true
}
