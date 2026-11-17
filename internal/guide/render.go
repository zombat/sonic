// Package guide renders SKILL.md, the reference/mcp-tools.md table, and the
// complete Agent Skill file map.
package guide

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type schemaNode struct {
	Type        string                `json:"type"`
	Description string                `json:"description"`
	Default     json.RawMessage       `json:"default"`
	Items       *schemaNode           `json:"items"`
	Properties  map[string]schemaNode `json:"properties"`
	Required    []string              `json:"required"`
	AnyOf       []schemaNode          `json:"anyOf"`
}

func schemaTypeName(s schemaNode) string {
	if len(s.AnyOf) > 0 {
		var parts []string
		for _, sub := range s.AnyOf {
			if sub.Type == "null" {
				continue
			}
			parts = append(parts, schemaTypeName(sub))
		}
		if len(parts) > 0 {
			return strings.Join(parts, " or ")
		}
		return "null"
	}
	if s.Type == "" {
		return "any"
	}
	if s.Type == "array" && s.Items != nil {
		return "array of " + schemaTypeName(*s.Items)
	}
	return s.Type
}

func mdCell(text string) string {
	return strings.ReplaceAll(strings.Join(strings.Fields(text), " "), "|", `\|`)
}

func toolCostText(llm, known bool) string {
	if !known {
		return "unknown"
	}
	if llm {
		return "LLM, tens of seconds to minutes"
	}
	return "no LLM, seconds"
}

var cliHintByTool = map[string]string{
	"analyze_network_pcap":           "`--file F --network-only`",
	"analyze_vpn_pcap":               "`--file F --network-only --detectors ipsec,gre_nhrp --peers A,B`",
	"analyze_routing_pcap":           "`--file F --network-only --detectors routing,reachability`",
	"analyze_data_plane_pcap":        "`--file F --network-only --detectors path_mtu,esp_overhead,tcp,tls,qos`",
	"analyze_grpc_pcap":              "`--file F --grpc [--tls-secrets-log K]`",
	"analyze_restconf_pcap":          "`--file F --restconf [--tls-secrets-log K]`",
	"analyze_snmp_pcap":              "`--file F --snmp [--snmp-users U]`",
	"analyze_aaa_pcap":               "`--file F --aaa [--aaa-secrets K]`",
	"analyze_esp_pcap":               "`--file F --esp-decrypt --esp-sa S`",
	"audit_cleartext_pcap":           "`--file F --detectors cleartext_audit [--allow encrypted]`",
	"analyze_convergence_pcap":       "MCP only",
	"correlate_pcaps":                "MCP only",
	"merge_pcap_timelines":           "MCP only",
	"quick_quality_check":            "`--file F --quality-only`",
	"analyze_pcap":                   "`--file F --provider P --model combined`",
	"analyze_pcap_partial_streaming": "`--file F --stream --partial`",
	"analyze_batch_pcaps":            "`--batch-dir D --file any.pcap`",
	"list_llm_providers":             "`--help` (Providers section)",
}

// RenderSkillMD builds the SKILL.md markdown document with YAML frontmatter and marker.
func RenderSkillMD(cliCommand string, registered []ToolSpec) string {
	if cliCommand == "" {
		cliCommand = "sonic"
	}
	descJSON, _ := json.Marshal(SkillDescription)
	lines := []string{
		"---",
		"name: " + SkillName,
		"description: " + string(descJSON),
		"---",
		"",
		SkillMarker + ". Run it again after an upgrade; it replaces this file. -->",
		"",
		"# S.O.N.I.C. packet capture diagnostics",
		"",
		"S.O.N.I.C. reads a pcap/pcapng file and answers from the packets: SIP/RTP call quality, IPsec and " +
			"DMVPN encryption and setup, routing adjacency health and failover, ICMP/ARP reachability. The " +
			"network and VPN detectors and the SIP quality scoring are deterministic (no LLM); only the SIP " +
			"diagnosis tools call an LLM.",
		"",
		fmt.Sprintf("Use the MCP tools when the S.O.N.I.C. MCP server is connected; otherwise run the CLI, `%s`. Pass absolute paths to captures.", cliCommand),
		"",
		"## Which tool for which question",
		"",
		"| Question | MCP tool | CLI | Cost |",
		"|---|---|---|---|",
	}

	regSet := make(map[string]bool, len(registered))
	for _, t := range registered {
		regSet[t.Name] = true
	}
	seen := make(map[string]bool, len(registered))
	for _, row := range AllToolGuide {
		if len(registered) > 0 && !regSet[row.Name] {
			continue
		}
		seen[row.Name] = true
		lines = append(lines, fmt.Sprintf("| %s | `%s` | %s | %s |",
			mdCell(row.Question), row.Name, cliHintByTool[row.Name], toolCostText(row.LLM, true)))
	}
	for _, t := range registered {
		if !seen[t.Name] {
			lines = append(lines, fmt.Sprintf("| %s | `%s` | %s | %s |",
				mdCell(t.Title), t.Name, cliHintByTool[t.Name], toolCostText(false, false)))
		}
	}

	lines = append(lines,
		"",
		"## A typical investigation",
		"",
		"1. Start with `analyze_network_pcap`: read `protocols_present`, `overall_status`, `verdicts`, `issues`.",
		"2. Narrow down: `analyze_vpn_pcap` (with `peers`) for encryption, `analyze_routing_pcap` for adjacencies and failover, `analyze_data_plane_pcap` for MTU, ESP, TCP, TLS and QoS.",
		"3. With captures from two or more points, `correlate_pcaps`; for a failover run, `merge_pcap_timelines` with thresholds.",
		"4. If SIP is present, `quick_quality_check`. Use `analyze_pcap` only for a written SIP diagnosis, and ask before using a cloud LLM provider.",
		"5. Report verdict sentences, issue codes and Wireshark frame numbers; say what the capture point could not show.",
		"",
		"## Read more only when you need it",
		"",
	)
	for _, top := range Topics {
		lines = append(lines, fmt.Sprintf("- [%s](reference/%s.md)", top.Title, top.Slug))
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

// renderMCPTools renders reference/mcp-tools.md from live tool schemas and Workflows.
func renderMCPTools(tools []ToolSpec) string {
	lines := []string{
		"# MCP tools, parameters and workflows",
		"",
		"Read from the running server's tool registry. Every tool returns one JSON object; check `status` first (`success` or `error`).",
		"",
	}
	byName := make(map[string]ToolSpec, len(tools))
	for _, t := range tools {
		byName[t.Name] = t
	}
	var ordered []ToolSpec
	seen := make(map[string]bool, len(tools))
	for _, row := range AllToolGuide {
		if t, ok := byName[row.Name]; ok {
			ordered = append(ordered, t)
			seen[t.Name] = true
		}
	}
	for _, t := range tools {
		if !seen[t.Name] {
			ordered = append(ordered, t)
		}
	}

	for _, tool := range ordered {
		entry, known := GuideEntryByName(tool.Name)
		lines = append(lines,
			"## `"+tool.Name+"`",
			"",
			"Use it for: "+entry.Question+"  ",
			"Cost: "+toolCostText(entry.LLM, known)+".",
			"",
			strings.TrimSpace(tool.Description),
			"",
		)
		var schema schemaNode
		if len(tool.InputSchema) > 0 && json.Unmarshal(tool.InputSchema, &schema) == nil && len(schema.Properties) > 0 {
			lines = append(lines, "| Parameter | Type | Required | Default | Meaning |", "|---|---|---|---|---|")
			propNames := make([]string, 0, len(schema.Properties))
			for p := range schema.Properties {
				propNames = append(propNames, p)
			}
			slices.Sort(propNames)
			for _, p := range propNames {
				ps := schema.Properties[p]
				req := slices.Contains(schema.Required, p)
				def := ""
				if !req {
					rawDef := strings.TrimSpace(string(ps.Default))
					if rawDef == "" || rawDef == "null" {
						def = "none"
					} else {
						def = "`" + rawDef + "`"
					}
				}
				yesNo := "no"
				if req {
					yesNo = "yes"
				}
				lines = append(lines, fmt.Sprintf("| `%s` | %s | %s | %s | %s |",
					p, mdCell(schemaTypeName(ps)), yesNo, mdCell(def), mdCell(ps.Description)))
			}
			lines = append(lines, "")
		}
	}

	lines = append(lines, "## Workflows (also served as MCP prompts)", "")
	for _, wf := range Workflows {
		body, _ := WorkflowText(wf.Name, nil)
		if idx := strings.Index(body, "\n\n"); idx >= 0 {
			body = body[idx+2:]
		}
		lines = append(lines, fmt.Sprintf("### `%s`: %s", wf.Name, wf.Title), "", body, "")
	}
	return strings.Join(lines, "\n")
}

// RenderTopic builds the markdown content for one reference topic slug.
func RenderTopic(topic string, tools []ToolSpec, cliCommand string, flags []CLIOptionSpec) (string, error) {
	switch topic {
	case "mcp-tools":
		return renderMCPTools(tools), nil
	case "network-detectors":
		return renderNetworkDetectors()
	case "grpc":
		return renderGRPC()
	case "sip-rtp":
		return renderSIPRTP(), nil
	case "cli":
		return renderCLI(cliCommand, flags), nil
	case "interpreting-results":
		return renderInterpreting(), nil
	default:
		return "", fmt.Errorf("unknown guide topic: %s", topic)
	}
}

// RenderSkill builds every file of the S.O.N.I.C. Agent Skill keyed by relative path.
func RenderSkill(tools []ToolSpec, cliCommand string, flags []CLIOptionSpec) (map[string]string, error) {
	files := make(map[string]string, len(Topics)+1)
	files["SKILL.md"] = RenderSkillMD(cliCommand, tools)
	for _, top := range Topics {
		body, err := RenderTopic(top.Slug, tools, cliCommand, flags)
		if err != nil {
			return nil, err
		}
		files["reference/"+top.Slug+".md"] = fmt.Sprintf("%s; it replaces this file. -->\n\n%s", SkillMarker, body)
	}
	return files, nil
}
