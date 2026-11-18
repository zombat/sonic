// Package main provides the thin S.O.N.I.C. CLI composition root wiring
// extractor, analyzer, and report packages without embedded business logic.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/guide"
	"github.com/zombat/sonic/internal/mcpserver"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/tshark"
)

var version, commit = "dev", "none"

type cliOptions struct {
	file           string
	saveFile       string
	htmlPath       string
	networkOnly    bool
	correlateMedia bool
	tuiMode        bool
	redactAudit    bool
	diffPair       string
	detectorsCSV   string
	peersCSV       string
	allowCSV       string
	displayFilter  string
	maxPackets     int
	sinceStr       string
	untilStr       string
	fastPath       string
	asJSON         bool
	grpcMode       bool
	restconfMode   bool
	snmpMode       bool
	aaaMode        bool
	espDecrypt     bool
	qualityOnly    bool
	tlsSecretsLog  string
	protoPaths     stringListFlag
	grpcPorts      string
	snmpPorts      string
	httpPorts      string
	snmpUsers      string
	aaaSecrets     string
	espSA          string
	envFile        string
}

type stringListFlag []string

// String implements flag.Value.String.
func (s *stringListFlag) String() string { return strings.Join(*s, ",") }

// Set appends one flag occurrence (splitting comma-separated paths when needed).
func (s *stringListFlag) Set(val string) error {
	for _, p := range splitCSV(val) {
		*s = append(*s, p)
	}
	return nil
}

func main() {
	os.Exit(runWithIO(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, defaultLLMRuntimeDeps()))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithIO(ctx, args, strings.NewReader("q"), stdout, stderr, defaultLLMRuntimeDeps())
}

func runWithIO(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, deps llmRuntimeDeps) int {
	if len(args) > 0 {
		switch args[0] {
		case "dump":
			return runDump(ctx, args[1:], stdout, stderr)
		case "gate":
			return runGateSubcommand(ctx, args[1:], stdout, stderr)
		case "diff":
			return runDiffSubcommand(ctx, args[1:], stdin, stdout, stderr)
		case "tui":
			return runTUISubcommand(ctx, args[1:], stdin, stdout, stderr)
		}
	}
	return runCommandWithDepsIO(ctx, args, stdin, stdout, stderr, deps)
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
	out, err := extract.OpenNetworkRecords(ctx, tshark.StreamOptions{
		FilePath:      *filePath,
		DisplayFilter: *displayFilter,
		MaxPackets:    positiveIntPtr(*maxPackets),
	})
	if err != nil {
		fmt.Fprintln(stderr, redact.RedactText(err.Error()))
		return 1
	}
	b, merr := json.MarshalIndent(out, "", "  ")
	return writeJSONBytes(stdout, stderr, b, merr)
}

func runCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runCommandWithDepsIO(ctx, args, strings.NewReader("q"), stdout, stderr, defaultLLMRuntimeDeps())
}

func runCommandWithDeps(ctx context.Context, args []string, stdout, stderr io.Writer, deps llmRuntimeDeps) int {
	return runCommandWithDepsIO(ctx, args, strings.NewReader("q"), stdout, stderr, deps)
}

func runCommandWithDepsIO(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, deps llmRuntimeDeps) int {
	skillDir, createSkill, cleanArgs := guide.ExtractCreateSkillFlag(args)
	protoDir, fetchProtos, cleanArgs := extractFetchProtosFlag(cleanArgs)
	var o cliOptions
	var lo llmCLIOptions
	fs := flag.NewFlagSet("sonic", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.file, "file", "", "pcap/pcapng file path")
	fs.StringVar(&o.saveFile, "save_file", "", "path to save markdown, JSON, or HTML report")
	fs.StringVar(&o.htmlPath, "html", "", "write self-contained offline HTML5 report to FILE")
	netOnlyFlag := fs.Bool("network-only", false, "run deterministic network detectors")
	fs.BoolVar(&o.correlateMedia, "correlate-media", false, "correlate SIP/RTP quality, clipping, and DTMF with underlay faults")
	fs.BoolVar(&o.tuiMode, "tui", false, "open interactive ANSI terminal report viewer")
	fs.BoolVar(&o.redactAudit, "redact-audit", false, "include per-category redaction counts in JSON/HTML/stderr output")
	fs.StringVar(&o.diffPair, "diff", "", "compare baseline and target captures (BASE,TARGET)")
	detectorsSet := fs.String("detectors", "cleartext_audit", "comma-separated detector list")
	fs.StringVar(&o.peersCSV, "peers", "", "comma-separated VPN peer IPs")
	fs.StringVar(&o.allowCSV, "allow", "", "comma-separated allowlist tokens for cleartext_audit")
	fs.StringVar(&o.displayFilter, "display-filter", "", "wireshark display filter")
	fs.IntVar(&o.maxPackets, "max-packets", 0, "maximum frames to read")
	fs.StringVar(&o.sinceStr, "since", "", "filter packets at or after Unix epoch seconds")
	fs.StringVar(&o.untilStr, "until", "", "filter packets at or before Unix epoch seconds")
	fs.StringVar(&o.fastPath, "fast-path", "auto", "pure-Go L2-L4 decoder mode: auto, always, or never")
	fs.BoolVar(&o.asJSON, "json", false, "emit machine-readable JSON")
	fs.BoolVar(&o.grpcMode, "grpc", false, "run gRPC/gNMI/gNOI inspection")
	fs.BoolVar(&o.restconfMode, "restconf", false, "run RESTCONF/REST HTTP inspection")
	fs.BoolVar(&o.snmpMode, "snmp", false, "run SNMP inspection")
	fs.BoolVar(&o.aaaMode, "aaa", false, "run TACACS+/RADIUS AAA inspection")
	fs.BoolVar(&o.espDecrypt, "esp-decrypt", false, "decrypt IPsec ESP and inspect inner traffic")
	fs.BoolVar(&o.qualityOnly, "quality-only", false, "run deterministic SIP quality and RTP MOS scoring")
	fs.StringVar(&o.tlsSecretsLog, "tls-secrets-log", "", "SSLKEYLOGFILE path for TLS decryption")
	fs.Var(&o.protoPaths, "proto-path", "directory containing .proto files (repeatable)")
	fs.StringVar(&o.grpcPorts, "grpc-ports", "", "comma-separated TCP ports to decode as HTTP/2")
	fs.StringVar(&o.snmpPorts, "snmp-ports", "", "comma-separated UDP ports to decode as SNMP (for a non-standard port such as 1161)")
	fs.StringVar(&o.httpPorts, "http-ports", "", "comma-separated TCP ports to decode as HTTP")
	fs.StringVar(&o.snmpUsers, "snmp-users", "", "USM users file path for SNMPv3 decryption")
	fs.StringVar(&o.aaaSecrets, "aaa-secrets", "", "AAA shared secret file path")
	fs.StringVar(&o.espSA, "esp-sa", "", "IPsec SA file path for ESP decryption")
	fs.StringVar(&o.envFile, "env-file", "", "dotenv file to read API keys from when unset in process env ($SONIC_ENV_FILE)")
	showVersion := fs.Bool("version", false, "print sonic version and commit and exit")
	registerLLMFlags(fs, &lo)
	configureCLIUsage(fs, stderr)

	if err := fs.Parse(cleanArgs); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "sonic %s (%s)\n", version, commit)
		return 0
	}
	if createSkill {
		specs, err := mcpserver.DefaultToolSpecs()
		if err != nil {
			fmt.Fprintln(stderr, redact.RedactText(err.Error()))
			return 1
		}
		return guide.CreateSkillCommand(skillDir, specs, "sonic", guide.DefaultCLIFlags(), stdout, stderr)
	}
	if !validateLLMOptions(lo, stderr) {
		return 2
	}
	creds, credCode := loadCredentialsForCLI(o.envFile, stderr)
	if credCode != 0 {
		return credCode
	}
	if fetchProtos {
		return runFetchProtos(ctx, protoDir, o.asJSON, deps, stdout, stderr)
	}
	if lo.batchDir != "" {
		return runBatchLLM(ctx, o, lo, creds, deps, stdout, stderr)
	}
	if o.diffPair != "" {
		return runDiffPairFlag(ctx, o, stdin, stdout, stderr)
	}
	if o.file == "" {
		fmt.Fprintln(stderr, "missing required --file flag")
		return 2
	}
	o.networkOnly = *netOnlyFlag
	o.detectorsCSV = *detectorsSet

	if !isDeterministicMode(o, fs) {
		if lo.stream || lo.partial {
			return runStreamLLM(ctx, o, lo, creds, deps, stdout, stderr)
		}
		return runSIPAnalysisLLM(ctx, o, lo, creds, deps, stdout, stderr)
	}

	detectorsExplicit := hasVisitedFlag(fs, "detectors")
	switch {
	case o.grpcMode:
		return runGRPC(ctx, o, stdin, stdout, stderr)
	case o.restconfMode:
		return runHTTP(ctx, o, stdin, stdout, stderr)
	case o.snmpMode:
		return runSNMP(ctx, o, stdin, stdout, stderr)
	case o.aaaMode:
		return runAAA(ctx, o, stdin, stdout, stderr)
	case o.espDecrypt:
		var espDetectors []string
		if detectorsExplicit {
			espDetectors = splitCSV(o.detectorsCSV)
		}
		return runESP(ctx, o, espDetectors, stdin, stdout, stderr)
	case o.correlateMedia:
		return runCorrelateMedia(ctx, o, stdin, stdout, stderr)
	case o.qualityOnly:
		return runQualityOnly(ctx, o, stdin, stdout, stderr)
	case o.networkOnly || o.tuiMode:
		var reqDetectors []string
		if detectorsExplicit {
			reqDetectors = splitCSV(o.detectorsCSV)
		}
		return runNetwork(ctx, o, reqDetectors, stdin, stdout, stderr)
	default:
		return runAudit(ctx, o, stdin, stdout, stderr)
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parsePortCSV(value string) []int {
	var out []int
	for _, tok := range splitCSV(value) {
		if p, err := strconv.Atoi(tok); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func positiveIntPtr(v int) *int {
	if v <= 0 {
		return nil
	}
	c := v
	return &c
}

func writeJSONBytes(stdout, stderr io.Writer, raw []byte, err error) int {
	if err != nil {
		fmt.Fprintln(stderr, redact.RedactText(err.Error()))
		return 1
	}
	if _, werr := stdout.Write(append(raw, '\n')); werr != nil {
		fmt.Fprintln(stderr, redact.RedactText(werr.Error()))
		return 1
	}
	return 0
}
