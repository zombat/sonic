// Package guide renders the detector, gRPC, SIP/RTP, CLI, and result-interpretation
// markdown topic pages from live Go types and AST-extracted metadata.
package guide

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/extract"
)

func renderNetworkDetectors() (string, error) {
	metas, err := DetectorMeta()
	if err != nil {
		return "", err
	}
	metaByKey := make(map[string]PackageMeta, len(metas))
	for _, m := range metas {
		metaByKey[m.Key] = m
	}

	lines := []string{
		"# Network and VPN detectors",
		"",
		"Deterministic, no LLM. Read from the live Go detector registry (`internal/analyze/netorch`) and analyzer packages.",
		"",
		"| Detector | MCP tools that run it | CLI |",
		"|---|---|---|",
	}

	dedicated := map[string]string{
		"cleartext_audit": "audit_cleartext_pcap",
		"convergence":     "analyze_convergence_pcap",
	}
	for _, name := range netorch.AllDetectors {
		var tools []string
		if dTool, isDedicated := dedicated[name]; isDedicated {
			tools = append(tools, dTool, "analyze_network_pcap (only when named in detectors)")
		} else {
			tools = append(tools, "analyze_network_pcap")
		}
		if slices.Contains(netorch.VPNDetectors, name) {
			tools = append(tools, "analyze_vpn_pcap")
		}
		if slices.Contains(netorch.RoutingDetectors, name) {
			tools = append(tools, "analyze_routing_pcap")
		}
		if slices.Contains(netorch.DataPlaneDetectors, name) {
			tools = append(tools, "analyze_data_plane_pcap")
		}
		formattedTools := make([]string, len(tools))
		for i, t := range tools {
			formattedTools[i] = "`" + t + "`"
		}
		lines = append(lines, fmt.Sprintf("| `%s` | %s | `--network-only --detectors %s` |",
			name, strings.Join(formattedTools, ", "), name))
	}

	lines = append(lines,
		"",
		"Each detector section has `status` (`not_present`, `ok`, `warning`, `problem`), a one-sentence `verdict`, and `issues`, each with `severity` (`error`, `warning`, `info`), a stable `code`, a `message` and `frames` (Wireshark frame numbers).",
		"",
	)

	for _, name := range netorch.AllDetectors {
		meta := metaByKey[name]
		codeList := "none"
		if len(meta.Codes) > 0 {
			bt := make([]string, len(meta.Codes))
			for i, c := range meta.Codes {
				bt[i] = "`" + c + "`"
			}
			codeList = strings.Join(bt, ", ")
		}
		lines = append(lines,
			fmt.Sprintf("## `%s`", name),
			"",
			meta.Doc,
			"",
			"Issue codes (`<...>` is filled in from the packet, for example a NOTIFY or ICMP type name):",
			"",
			codeList,
			"",
		)
	}
	return strings.Join(lines, "\n"), nil
}

func renderGRPC() (string, error) {
	metas, err := DetectorMeta()
	if err != nil {
		return "", err
	}
	var grpcMeta PackageMeta
	for _, m := range metas {
		if m.Key == "grpc_inspect" {
			grpcMeta = m
			break
		}
	}

	lines := []string{
		"# gRPC, gNMI and gNOI troubleshooting",
		"",
		"Deterministic, no LLM; needs tshark. MCP `analyze_grpc_pcap`, CLI `--grpc`. The cleartext audit (`audit_cleartext_pcap`) uses the same decoding to name cleartext HTTP/2 as gRPC and to flag credentials in its metadata.",
		"",
		grpcMeta.Doc,
		"",
		"## Ports decoded as HTTP/2 without a preface",
		"",
		"| Port | Service |",
		"|---|---|",
	}
	ports := make([]int, 0, len(extract.GrpcPorts))
	for p := range extract.GrpcPorts {
		ports = append(ports, p)
	}
	slices.Sort(ports)
	for _, p := range ports {
		lines = append(lines, fmt.Sprintf("| %d | %s |", p, extract.GrpcPorts[p]))
	}

	shown := make([]string, 0, len(extract.ShownHeaders))
	for h := range extract.ShownHeaders {
		shown = append(shown, h)
	}
	slices.Sort(shown)
	shownBT := make([]string, len(shown))
	for i, h := range shown {
		shownBT[i] = "`" + h + "`"
	}

	codesBT := make([]string, len(grpcMeta.Codes))
	for i, c := range grpcMeta.Codes {
		codesBT[i] = "`" + c + "`"
	}

	lines = append(lines,
		"",
		"## Header values shown",
		"",
		"Only these header values appear in a report; every other value is masked, and a credential-like name (username, password, authorization, x-api-key, token, cookie, ...) is flagged: "+strings.Join(shownBT, ", ")+".",
		"",
		"## Decryption and .proto files",
		"",
		"- `keylog_file` (CLI `--tls-secrets-log`): a TLS key log (SSLKEYLOGFILE format) the client wrote while it ran: gnmic with `--log-tls-secret`, Python clients and curl with SSLKEYLOGFILE set, a Go program through tls.Config.KeyLogWriter. It is handed to tshark by path and never read into or copied to a report.",
		fmt.Sprintf("- `proto_paths` (CLI `--proto-path`), else `%s`, else `%s` when it exists: .proto files for Wireshark's protobuf dissector, which then names each message type (`wireshark_protobuf` on an RPC).",
			grpc.ProtoPathVariable, grpc.DefaultProtoDir()),
		"",
		"Issue codes (`<...>` is the grpc-status name, for example `GRPC_UNAUTHENTICATED`):",
		"",
		strings.Join(codesBT, ", "),
		"",
	)
	return strings.Join(lines, "\n"), nil
}

func renderSIPRTP() string {
	qFields := structJSONFields(reflect.TypeFor[sip.QualityMetrics]())
	mFields := structJSONFields(reflect.TypeFor[sip.MOSAnalysisResult]())
	grades := []string{
		string(sip.GradeExcellent), string(sip.GradeVeryGood), string(sip.GradeGood),
		string(sip.GradeFair), string(sip.GradePoor), string(sip.GradeFailed),
	}
	cats := []string{
		string(sip.MOSExcellent), string(sip.MOSGood), string(sip.MOSFair),
		string(sip.MOSPoor), string(sip.MOSBad),
	}

	lines := []string{
		"# SIP and RTP analysis",
		"",
		"Two paths. The quality path is deterministic: `quick_quality_check` (CLI `--quality-only`) scores the calls and computes MOS per RTP stream (ITU-T G.107 E-model) in seconds, with no LLM. The diagnosis path (`analyze_pcap`, `analyze_pcap_partial_streaming`, `analyze_batch_pcaps`; CLI default mode) sends the extracted SIP/SDP data to an LLM for a written diagnosis of each call.",
		"",
		"Run the quality path first. It answers \"how bad\"; the LLM answers \"why\" in prose and is slower, costs tokens, and with a cloud provider sends SIP data (including authentication headers, credentials masked) off the machine.",
		"",
		"## Quality result (`quality_analysis`)",
		"",
		"Fields: " + backtickJoin(qFields) + ".",
		"Grades: " + backtickJoin(grades) + ".",
		"",
		"## MOS result (`mos_analysis`)",
		"",
		"Fields: " + backtickJoin(mFields) + ".",
		"Categories: " + backtickJoin(cats) + ".",
		"",
		"## LLM providers and models",
		"",
		fmt.Sprintf("Every LLM tool takes `provider`; a call without it uses the server's `%s`, else `%s`, and `list_llm_providers` reports that choice as `current_config.provider`. Analysis modes: `fast` (small model), `detailed` (the provider's default model), `deep` (its most capable model), `combined` (fast and detailed, recommended), `all` (CLI only). The CLI's `--model-name` runs one pass on a model you name instead.",
			ProviderVariable, DefaultProvider),
		"",
		"API keys come from the server's environment (an MCP client's `env` block passes them through), then from the dotenv file named by `--env-file` or `SONIC_ENV_FILE`. `list_llm_providers` says whether each key is configured and where it came from; no tool ever returns a key, and keys are redacted from results, logs, reports and prompts. Never ask the user to paste a key into the conversation.",
		"",
		"| Provider | Fast model | Detailed (default) model | Deep model |",
		"|---|---|---|---|",
	}
	for _, row := range ProviderModels() {
		deep := row.Deep
		if deep == "" {
			deep = row.Detailed
		}
		lines = append(lines, fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` |", row.Provider, row.Fast, row.Detailed, deep))
	}
	lines = append(lines,
		"",
		"## What the SIP path covers",
		"",
		`Call setup and teardown, failed and dropped calls, one-way or no audio (SDP versus RTP), codec negotiation, RTP loss, jitter and latency, NAT and firewall symptoms, REGISTER and digest authentication posture. A capture with no SIP returns '{"status": "error", "error": "No SIP data found ..."}'; use 'analyze_network_pcap' for anything else.`,
		"",
	)
	return strings.Join(lines, "\n")
}

func renderCLI(cliCommand string, flags []CLIOptionSpec) string {
	if cliCommand == "" {
		cliCommand = "sonic"
	}
	if len(flags) == 0 {
		flags = DefaultCLIFlags()
	}
	lines := []string{
		fmt.Sprintf("# Command line (`%s`)", cliCommand),
		"",
		fmt.Sprintf("Run it as `%s`.", cliCommand),
		"",
		"Read from the CLI's live option specifications.",
		"",
		"| Option | Values | Default | Meaning |",
		"|---|---|---|---|",
	}
	for _, f := range flags {
		lines = append(lines, fmt.Sprintf("| `%s` | %s | %s | %s |",
			f.Flags, mdCell(f.Values), mdCell(f.Default), mdCell(f.Help)))
	}
	lines = append(lines, "", "## Examples and providers", "", "```text", CLIFlagsExampleBlock, "```", "")
	return strings.Join(lines, "\n")
}

func structJSONFields(t reflect.Type) []string {
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			name = f.Name
		}
		out = append(out, name)
	}
	return out
}

func backtickJoin(items []string) string {
	bt := make([]string, len(items))
	for i, s := range items {
		bt[i] = "`" + s + "`"
	}
	return strings.Join(bt, ", ")
}
