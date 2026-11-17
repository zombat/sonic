// Package guide defines the canonical CLI flag metadata shared across sonic
// and sonic-mcp when rendering reference/cli.md.
package guide

import "strings"

// DefaultCLIFlags lists every CLI option supported by cmd/sonic in display order.
func DefaultCLIFlags() []CLIOptionSpec {
	return []CLIOptionSpec{
		{Flags: "--file", Values: "FILE", Help: "pcap/pcapng file path"},
		{Flags: "--save_file", Values: "FILE", Help: "path to save markdown or JSON report"},
		{Flags: "--network-only", Values: "flag", Help: "run deterministic network detectors"},
		{Flags: "--detectors", Values: "LIST", Default: "cleartext_audit", Help: "comma-separated detector list"},
		{Flags: "--peers", Values: "IPS", Help: "comma-separated VPN peer IPs"},
		{Flags: "--allow", Values: "RULES", Help: "comma-separated allowlist tokens for cleartext_audit"},
		{Flags: "--display-filter", Values: "FILTER", Help: "wireshark display filter"},
		{Flags: "--max-packets", Values: "N", Help: "maximum frames to read"},
		{Flags: "--json", Values: "flag", Help: "emit machine-readable JSON"},
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
		{Flags: "--create-skill", Values: "[DIR]", Help: "write the S.O.N.I.C. Agent Skill into DIR (default .claude/skills/sonic) and exit"},
		{Flags: "--env-file", Values: "PATH", Help: "dotenv file to read API keys from when unset in process env ($SONIC_ENV_FILE)"},
	}
}

// CLIFlagsExampleBlock provides concise command-line examples for reference/cli.md.
const CLIFlagsExampleBlock = `Network and VPN checks:
  sonic --file hub-wan.pcap --network-only --peers 192.0.2.1,198.51.100.2
  sonic --file hub-wan.pcap --detectors cleartext_audit --allow encrypted --json

Protocol deep inspection:
  sonic --file gnmi.pcap --grpc --tls-secrets-log /path/to/keys.log
  sonic --file rest.pcap --restconf --json
  sonic --file snmp.pcap --snmp --snmp-users /path/to/users.conf
  sonic --file aaa.pcap --aaa --aaa-secrets /path/to/aaa-keys.txt
  sonic --file tunnel.pcap --esp-decrypt --esp-sa /path/to/xfrm.txt

SIP quality (deterministic):
  sonic --file call.pcap --quality-only --json`

// ExtractCreateSkillFlag strips optional-argument --create-skill [DIR] occurrences
// before Go's flag.FlagSet parses remaining options, matching argparse nargs='?'.
func ExtractCreateSkillFlag(args []string) (targetDir string, enabled bool, remaining []string) {
	remaining = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			remaining = append(remaining, args[i:]...)
			break
		}
		if strings.HasPrefix(arg, "--create-skill=") {
			enabled = true
			targetDir = strings.TrimPrefix(arg, "--create-skill=")
			continue
		}
		if arg == "--create-skill" {
			enabled = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				targetDir = args[i]
			}
			continue
		}
		remaining = append(remaining, arg)
	}
	if enabled && targetDir == "" {
		targetDir = DefaultSkillDir()
	}
	return targetDir, enabled, remaining
}
