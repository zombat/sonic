// Package guide defines the canonical CLI flag metadata shared across sonic
// and sonic-mcp when rendering reference/cli.md.
package guide

import (
	"strings"

	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/llm"
)

// DefaultCLIFlags lists every CLI option supported by cmd/sonic in display order.
func DefaultCLIFlags() []CLIOptionSpec {
	return []CLIOptionSpec{
		{Flags: "--file", Values: "FILE", Help: "pcap/pcapng file path"},
		{Flags: "--save_file", Values: "FILE", Help: "path to save markdown or JSON report"},
		{Flags: "--model", Values: "MODE", Default: "combined", Help: "SIP LLM mode: fast, detailed, deep, combined, or all"},
		{Flags: "--provider", Values: "NAME", Default: "$" + llm.ProviderVariable + " else " + llm.DefaultProvider, Help: "LLM provider: ollama, anthropic, openai, or azure"},
		{Flags: "--model-name", Values: "MODEL", Help: "override concrete LLM model name (incompatible with --model all)"},
		{Flags: "--quality", Values: "flag", Help: "include deterministic call quality scoring in SIP LLM mode"},
		{Flags: "--mos", Values: "flag", Help: "include RTP MOS estimation in SIP LLM mode"},
		{Flags: "--stream", Values: "flag", Help: "stream combined SIP LLM diagnosis output"},
		{Flags: "--partial", Values: "flag", Help: "emit deterministic quality and MOS before streaming LLM diagnosis"},
		{Flags: "--batch-dir", Values: "DIR", Help: "analyze every *.pcap* file in DIR in batch mode"},
		{Flags: "--batch-mode", Values: "MODE", Default: "sequential", Help: "batch execution mode: sequential or parallel"},
		{Flags: "--batch-workers", Values: "N", Default: "3", Help: "concurrent workers when --batch-mode parallel is selected"},
		{Flags: "--network-only", Values: "flag", Help: "run deterministic network detectors"},
		{Flags: "--detectors", Values: "LIST", Default: "cleartext_audit", Help: "comma-separated detector list"},
		{Flags: "--peers", Values: "IPS", Help: "comma-separated VPN peer IPs"},
		{Flags: "--allow", Values: "RULES", Help: "comma-separated allowlist tokens for cleartext_audit"},
		{Flags: "--display-filter", Values: "FILTER", Help: "wireshark display filter"},
		{Flags: "--max-packets", Values: "N", Help: "maximum frames to read"},
		{Flags: "--since", Values: "EPOCH", Help: "filter packets at or after Unix epoch seconds"},
		{Flags: "--until", Values: "EPOCH", Help: "filter packets at or before Unix epoch seconds"},
		{Flags: "--fast-path", Values: "MODE", Default: "auto", Help: "pure-Go L2-L4 decoder mode: auto, always, or never"},
		{Flags: "--json", Values: "flag", Help: "emit machine-readable JSON"},
		{Flags: "--html", Values: "FILE", Help: "write self-contained offline HTML5 report to FILE"},
		{Flags: "--tui", Values: "flag", Help: "open interactive ANSI terminal report viewer"},
		{Flags: "--redact-audit", Values: "flag", Help: "include per-category secret redaction counts"},
		{Flags: "--verbose", Values: "flag", Help: "emit detailed progress to stderr"},
		{Flags: "--correlate-media", Values: "flag", Help: "correlate SIP/RTP quality, clipping, and DTMF with underlay faults"},
		{Flags: "--diff", Values: "BASE,TARGET", Help: "compare baseline capture against target capture (or `sonic diff`)"},
		{Flags: "--version", Values: "flag", Help: "print sonic version and commit and exit"},
		{Flags: "--grpc", Values: "flag", Help: "run gRPC/gNMI/gNOI inspection"},
		{Flags: "--restconf", Values: "flag", Help: "run RESTCONF/REST HTTP inspection"},
		{Flags: "--snmp", Values: "flag", Help: "run SNMP inspection"},
		{Flags: "--aaa", Values: "flag", Help: "run TACACS+/RADIUS AAA inspection"},
		{Flags: "--esp-decrypt", Values: "flag", Help: "decrypt IPsec ESP and inspect inner traffic"},
		{Flags: "--quality-only", Values: "flag", Help: "run deterministic SIP quality and RTP MOS scoring"},
		{Flags: "--tls-secrets-log", Values: "FILE", Help: "SSLKEYLOGFILE path for TLS decryption"},
		{Flags: "--proto-path", Values: "DIR", Help: "directory containing .proto files (repeatable)"},
		{Flags: "--grpc-ports", Values: "PORTS", Help: "comma-separated TCP ports to decode as HTTP/2"},
		{Flags: "--http-ports", Values: "PORTS", Help: "comma-separated TCP ports to decode as HTTP"},
		{Flags: "--snmp-users", Values: "FILE", Help: "USM users file path for SNMPv3 decryption"},
		{Flags: "--aaa-secrets", Values: "FILE", Help: "AAA shared secret file path"},
		{Flags: "--esp-sa", Values: "FILE", Help: "IPsec SA file path for ESP decryption"},
		{Flags: "--fetch-grpc-protos", Values: "[DIR]", Default: grpc.DefaultProtoDir(), Help: "download standard gRPC/gNMI .proto files into DIR and exit"},
		{Flags: "--create-skill", Values: "[DIR]", Help: "write the S.O.N.I.C. Agent Skill into DIR (default .claude/skills/sonic) and exit"},
		{Flags: "--env-file", Values: "PATH", Help: "dotenv file to read API keys from when unset in process env ($SONIC_ENV_FILE)"},
	}
}

// CLIFlagsExampleBlock provides concise command-line examples for reference/cli.md.
const CLIFlagsExampleBlock = `SIP call diagnosis (LLM):
  sonic --file call.pcap --provider ollama --model combined --quality --mos
  sonic --file call.pcap --provider openai --stream --partial
  sonic --batch-dir /captures/branch-a --batch-mode parallel --batch-workers 3

Network and VPN checks:
  sonic --file hub-wan.pcap --network-only --peers 192.0.2.1,198.51.100.2
  sonic --file hub-wan.pcap --detectors cleartext_audit --allow encrypted --json

Protocol deep inspection:
  sonic --fetch-grpc-protos
  sonic --file gnmi.pcap --grpc --tls-secrets-log /path/to/keys.log
  sonic --file rest.pcap --restconf --json
  sonic --file snmp.pcap --snmp --snmp-users /path/to/users.conf
  sonic --file aaa.pcap --aaa --aaa-secrets /path/to/aaa-keys.txt
  sonic --file tunnel.pcap --esp-decrypt --esp-sa /path/to/xfrm.txt

SIP quality and workflows (deterministic):
  sonic --file call.pcap --quality-only --json
  sonic --file call.pcap --correlate-media --html report.html
  sonic diff --baseline good.pcap --target broken.pcap
  sonic gate --file hub-wan.pcap --policy zero-cleartext,no-weak-crypto --format sarif
  sonic tui --file hub-wan.pcap`

// ExtractOptionalFlag strips optional-argument flagName [VALUE] occurrences before Go's
// flag.FlagSet parses remaining options, matching argparse nargs='?'.
func ExtractOptionalFlag(args []string, flagName, defaultVal string) (value string, enabled bool, remaining []string) {
	remaining = make([]string, 0, len(args))
	eqPrefix := flagName + "="
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			remaining = append(remaining, args[i:]...)
			break
		}
		if strings.HasPrefix(arg, eqPrefix) {
			enabled = true
			value = strings.TrimPrefix(arg, eqPrefix)
			continue
		}
		if arg == flagName {
			enabled = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				value = args[i]
			}
			continue
		}
		remaining = append(remaining, arg)
	}
	if enabled && value == "" {
		value = defaultVal
	}
	return value, enabled, remaining
}

// ExtractCreateSkillFlag strips optional-argument --create-skill [DIR] occurrences
// before Go's flag.FlagSet parses remaining options.
func ExtractCreateSkillFlag(args []string) (targetDir string, enabled bool, remaining []string) {
	return ExtractOptionalFlag(args, "--create-skill", DefaultSkillDir())
}
