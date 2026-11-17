// Package guide serves MCP instructions, prompt workflows, sonic://guide/*
// resources, and embedded Go AST detector metadata.
package guide

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/llm"
)

//go:embed detector_meta.json
var detectorMetaJSON []byte

// Workflows lists the 5 guided investigation prompts exposed by the MCP server.
var Workflows = []WorkflowSpec{
	{
		Name:        "diagnose_capture",
		Title:       "Diagnose an unknown capture",
		Description: "Walk through an unknown capture: protocols present, then VPN, routing and SIP as they apply.",
		Args:        []WorkflowArgSpec{{Name: "file_path", Required: true}},
		Steps: []string{
			"Call analyze_network_pcap(file_path={file_path}). Read protocols_present, overall_status, verdicts and the first issues.",
			"If ike, esp or gre is present, call analyze_vpn_pcap with peers set to the VPN endpoints' WAN addresses when you know them.",
			"If bgp, ospf or eigrp is present, or overall_status is not ok, call analyze_routing_pcap to read the failover_timeline and ping_outages.",
			"If sip is present, call quick_quality_check for the grade and MOS. Use analyze_pcap only if the user wants a written SIP diagnosis and accepts an LLM call.",
			"If http2 is present, or tls on a gRPC port (9339, 57400, 6030, 50051), call analyze_grpc_pcap for each RPC's status, HTTP/2 trouble and credentials in cleartext metadata.",
			"If HTTPS or RESTCONF is present, call analyze_restconf_pcap; if snmp, tacacs or radius is present, analyze_snmp_pcap or analyze_aaa_pcap. Each decrypts when the user has the keys: pass the key file's path (keylog_file, users_file, keys_file), never its contents. If esp is present and the user has SA keys from a Linux or strongSwan endpoint, call analyze_esp_pcap with sa_file (Cisco IOS does not expose ESP keys).",
			"Answer with the verdict sentences, issue codes and Wireshark frame numbers, and say what the capture point could not show.",
		},
	},
	{
		Name:        "check_vpn_encryption",
		Title:       "Is the VPN traffic encrypted?",
		Description: "Prove from a WAN capture whether inter-site traffic is encrypted and the IPsec/DMVPN overlay formed.",
		Args:        []WorkflowArgSpec{{Name: "file_path", Required: true}, {Name: "peers", Required: false}},
		Steps: []string{
			"Call analyze_vpn_pcap(file_path={file_path}, peers={peers}). Leave peers out if none are known.",
			"Report encryption_verdict and verdict word for word. cleartext_seen names the protocol, direction and packet count of what crossed in the clear.",
			"Report negotiation_verdict (IKE outcome per SA) and overlay_verdict (NHRP registrations).",
			"If the verdict is not_present or no_esp, check where the capture was taken: only the underlay (WAN) link proves encryption; a tunnel interface shows decrypted traffic.",
			"To pass or fail on it, call audit_cleartext_pcap(file_path={file_path}, allow=[\"crypto\"]) (IPsec only; the default also passes SSH and TLS); add \"l2-control\" to accept Cisco loopback keepalives and CDP. Report ike_diagnoses codes for failed SAs.",
		},
	},
	{
		Name:        "investigate_failover",
		Title:       "Read a routing failover from a capture",
		Description: "Order BGP/OSPF/EIGRP events and ping outages to measure convergence.",
		Args:        []WorkflowArgSpec{{Name: "file_path", Required: true}},
		Steps: []string{
			"Call analyze_routing_pcap(file_path={file_path}).",
			"Read verdict per protocol, then failover_timeline in order (t is seconds from the first frame).",
			"Line ping_outages up with the timeline: convergence time is from the first down or hello_gap event to the outage's recovery. When the event time is known (a runbook stopped a link), call analyze_convergence_pcap with event_time for the deltas and the driver.",
			"Explain any mismatch issue (for example OSPF_HELLO_INTERVAL_MISMATCH, EIGRP_K_VALUE_MISMATCH, BGP_TCP_REFUSED) with the values the issue carries.",
		},
	},
	{
		Name:        "diagnose_sip_call",
		Title:       "Diagnose SIP call quality",
		Description: "Quality and MOS first without an LLM, then an LLM diagnosis only if wanted.",
		Args:        []WorkflowArgSpec{{Name: "file_path", Required: true}},
		Steps: []string{
			"Call quick_quality_check(file_path={file_path}) first: no LLM, a few seconds.",
			"Report quality_analysis.grade and overall_score, mos_analysis.average_mos and worst_mos, and the degradation_factors.",
			"Only if the user wants a written diagnosis, call analyze_pcap. Ask before choosing a cloud provider: the SIP data (addresses, users, authentication headers with credentials masked) leaves this machine.",
		},
	},
	{
		Name:        "troubleshoot_grpc",
		Title:       "Troubleshoot gRPC, gNMI or gNOI",
		Description: "Read every RPC's status and message, HTTP/2 trouble, TLS problems and cleartext credentials.",
		Args:        []WorkflowArgSpec{{Name: "file_path", Required: true}, {Name: "keylog_file", Required: false}},
		Steps: []string{
			"Call analyze_grpc_pcap(file_path={file_path}, keylog_file={keylog_file}). Leave keylog_file out if there is none.",
			"Read verdict and summary.rpc_status, then for each failing RPC quote method, grpc_status_name, grpc_message and diagnosis, with its frames.",
			"Report HTTP/2 trouble from issues (HTTP2_RST_STREAM, HTTP2_GOAWAY, HTTP2_TOO_MANY_PINGS, HTTP2_FLOW_CONTROL_STALL, HTTP2_FRAME_TOO_LARGE) and TCP_RESET_DURING_RPC.",
			"For TLS connections read connections[].tls: alerts with their hint, the certificate, and TLS_CERT_NO_IP_SAN. Without a key log the RPCs are encrypted: ask for one captured with SSLKEYLOGFILE on the client (a pcapng with the secrets embedded needs none). tls_decryption names each session the secrets did not decrypt, and why.",
			"Report every CLEARTEXT_CREDENTIAL by key and flow; never ask for or repeat a value. To gate on encryption, call audit_cleartext_pcap: its default passes TLS only when the handshake shows real encryption.",
		},
	},
}

// ToolOptions returns the canonical title and annotations for a known tool name.
func ToolOptions(name string) (string, ToolAnnotations, bool) {
	for _, entry := range AllToolGuide {
		if entry.Name == name {
			return entry.Title, ToolAnnotations{
				Title:           entry.Title,
				ReadOnlyHint:    true,
				DestructiveHint: false,
				IdempotentHint:  !entry.LLM,
				OpenWorldHint:   entry.LLM,
			}, true
		}
	}
	return "", ToolAnnotations{}, false
}

// GuideEntryByName looks up one ToolGuideEntry by tool name.
func GuideEntryByName(name string) (ToolGuideEntry, bool) {
	for _, entry := range AllToolGuide {
		if entry.Name == name {
			return entry, true
		}
	}
	return ToolGuideEntry{}, false
}

// Instructions builds concise MCP server instructions under 2 KB naming every registered tool.
func Instructions(tools []ToolSpec) string {
	registered := make(map[string]bool, len(tools))
	for _, t := range tools {
		registered[t.Name] = true
	}

	var sb strings.Builder
	sb.WriteString("S.O.N.I.C. reads pcap/pcapng files on the server's machine. Pass absolute paths.\n\n")
	sb.WriteString("Tools (no LLM unless marked):\n")
	seen := make(map[string]bool, len(tools))
	for _, row := range AllToolGuide {
		if !registered[row.Name] {
			continue
		}
		seen[row.Name] = true
		tag := ""
		if row.LLM {
			tag = " [LLM]"
		}
		fmt.Fprintf(&sb, "- %s%s: %s\n", row.Name, tag, row.Short)
	}
	for _, t := range tools {
		if !seen[t.Name] {
			fmt.Fprintf(&sb, "- %s: %s\n", t.Name, t.Title)
		}
	}

	topicSlugs := make([]string, 0, len(Topics)+1)
	topicSlugs = append(topicSlugs, OverviewTopic)
	for _, top := range Topics {
		topicSlugs = append(topicSlugs, top.Slug)
	}
	wfNames := make([]string, 0, len(Workflows))
	for _, wf := range Workflows {
		wfNames = append(wfNames, wf.Name)
	}

	sb.WriteString("\nOrder: analyze_network_pcap first, then the tool for the protocol found; audit_cleartext_pcap to gate a link; SIP: quick_quality_check before analyze_pcap. Quote codes and frames.\n\n")
	sb.WriteString("Decryption keys (keylog_file, users_file, keys_file, sa_file) are paths on the server, never returned; never paste a key.\n\n")
	sb.WriteString("[LLM] tools: provider SONIC_LLM_PROVIDER, else ollama; a cloud one sends SIP data (auth headers masked) off this machine: ask first.\n\n")
	sb.WriteString("Tools return JSON; check status (errors are data). Lists stop at max_items (default 25), *_omitted counts the rest; narrow: display_filter, max_packets.\n\n")
	sb.WriteString("Limits: only what crossed the capture point (capture the WAN to prove encryption); IKEv2 auth failure is a heuristic; NULL ESP looks encrypted.\n\n")
	fmt.Fprintf(&sb, "More: resources sonic://guide/<topic> (%s); prompts %s.",
		strings.Join(topicSlugs, ", "), strings.Join(wfNames, ", "))
	return sb.String()
}

// Prompts returns the MCP prompts/list entries matching Workflows.
func Prompts() []PromptInfo {
	out := make([]PromptInfo, len(Workflows))
	for i, wf := range Workflows {
		out[i] = PromptInfo{
			Name:        wf.Name,
			Title:       wf.Title,
			Description: wf.Description,
			Arguments:   wf.Args,
		}
	}
	return out
}

// WorkflowText renders one named workflow with placeholder or argument substitution.
func WorkflowText(name string, values map[string]string) (string, error) {
	var flow *WorkflowSpec
	for i := range Workflows {
		if Workflows[i].Name == name {
			flow = &Workflows[i]
			break
		}
	}
	if flow == nil {
		return "", fmt.Errorf("unknown prompt: %s", name)
	}
	shown := make(map[string]string, len(flow.Args))
	for _, arg := range flow.Args {
		val, ok := values[arg.Name]
		switch {
		case !ok:
			shown[arg.Name] = "<" + arg.Name + ">"
		case arg.Name == "peers":
			shown[arg.Name] = formatPeersList(val)
		case val == "":
			shown[arg.Name] = "None"
		default:
			shown[arg.Name] = pySingleQuote(val)
		}
	}
	lines := make([]string, 0, len(flow.Steps)+2)
	lines = append(lines, flow.Title+" with S.O.N.I.C.", "")
	for i, step := range flow.Steps {
		rendered := step
		for k, v := range shown {
			rendered = strings.ReplaceAll(rendered, "{"+k+"}", v)
		}
		lines = append(lines, fmt.Sprintf("%d. %s", i+1, rendered))
	}
	return strings.Join(lines, "\n"), nil
}

func formatPeersList(raw string) string {
	var parts []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, pySingleQuote(p))
		}
	}
	if len(parts) == 0 {
		return "None"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pySingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

// Resources returns the MCP resources/list entries matching utils/agent_guide.py.
func Resources() []ResourceInfo {
	out := make([]ResourceInfo, 0, len(Topics)+1)
	out = append(out, ResourceInfo{
		URI:         "sonic://guide/" + OverviewTopic,
		Name:        "guide-" + OverviewTopic,
		Title:       "S.O.N.I.C. overview",
		Description: "What S.O.N.I.C. answers, which tool for which question, and the guide topics.",
		MimeType:    "text/markdown",
	})
	for _, top := range Topics {
		out = append(out, ResourceInfo{
			URI:         "sonic://guide/" + top.Slug,
			Name:        "guide-" + top.Slug,
			Title:       top.Title,
			Description: fmt.Sprintf("S.O.N.I.C. guide: %s. Read it when you need this area in depth.", top.Title),
			MimeType:    "text/markdown",
		})
	}
	return out
}

// ReadResource renders the markdown body for a sonic://guide/<topic> URI.
func ReadResource(uri string, tools []ToolSpec, cliCommand string, flags []CLIOptionSpec) (string, error) {
	const prefix = "sonic://guide/"
	if !strings.HasPrefix(uri, prefix) {
		return "", fmt.Errorf("unknown resource uri: %s", uri)
	}
	slug := strings.TrimPrefix(uri, prefix)
	if slug == OverviewTopic {
		return RenderSkillMD(cliCommand, tools), nil
	}
	return RenderTopic(slug, tools, cliCommand, flags)
}

// DetectorMeta returns a copy of the embedded Go AST analyzer docstrings and issue codes.
func DetectorMeta() ([]PackageMeta, error) {
	var items []PackageMeta
	if err := json.Unmarshal(detectorMetaJSON, &items); err != nil {
		return nil, fmt.Errorf("decode detector metadata: %w", err)
	}
	return items, nil
}

// ProviderModels returns the supported provider profiles and model names from internal/llm.
func ProviderModels() []ProviderModelRow {
	order := []string{"ollama", "anthropic", "openai", "azure"}
	rows := make([]ProviderModelRow, 0, len(order))
	for _, p := range order {
		tiers := llm.ProviderModels[p]
		rows = append(rows, ProviderModelRow{
			Provider: p,
			Fast:     tiers[llm.ProfileFast],
			Detailed: tiers[llm.ProfileDetailed],
			Deep:     tiers[llm.ProfileDeep],
		})
	}
	return rows
}
