// Package guide builds S.O.N.I.C. agent guidance from a single table and live
// package metadata: MCP instructions, tool annotations, workflow prompts,
// sonic://guide/* resources, and the --create-skill markdown bundle.
package guide

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

const (
	// SkillName is the Agent Skill identifier written by --create-skill.
	SkillName = "sonic"
	// SkillMarker opens a line near the top of every file written by --create-skill.
	SkillMarker = "<!-- written by sonic --create-skill"
	// SkillMarkerWithin is the maximum number of leading lines scanned for SkillMarker.
	SkillMarkerWithin = 20
	// OverviewTopic is the MCP overview resource topic slug.
	OverviewTopic = "overview"
	// DefaultProvider is the default local LLM provider when SONIC_LLM_PROVIDER is unset.
	DefaultProvider = "ollama"
	// ProviderVariable is the environment variable overriding DefaultProvider.
	ProviderVariable = "SONIC_LLM_PROVIDER"
	// SkillDescription describes when agents should activate the S.O.N.I.C. skill.
	SkillDescription = "Diagnose packet captures (pcap/pcapng) with S.O.N.I.C.: SIP/RTP call quality and MOS, " +
		"IPsec/IKE/ESP encryption and DMVPN (GRE/NHRP) overlays, BGP/OSPF/EIGRP adjacencies and " +
		"failover timing, ICMP/ARP reachability. Use when the user hands you a capture file or asks " +
		"whether VPN traffic is encrypted, why a tunnel or routing adjacency did not come up, how long " +
		"a failover took, or why a call dropped or sounded bad."
)

// DefaultSkillDir returns ".claude/skills/sonic" in platform separator syntax.
func DefaultSkillDir() string {
	return filepath.Join(".claude", "skills", SkillName)
}

// TopicSpec pairs a sonic://guide/<Slug> path with its human title.
type TopicSpec struct {
	Slug  string
	Title string
}

// ToolGuideEntry holds canonical agent-facing summary metadata for one MCP tool.
type ToolGuideEntry struct {
	Name     string
	Short    string
	Title    string
	LLM      bool
	Question string
}

// ToolAnnotations holds MCP read-only/idempotency/open-world hints per tool.
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// ToolSpec describes a registered MCP tool passed into guide renderers.
type ToolSpec struct {
	Name        string
	Title       string
	Description string
	InputSchema json.RawMessage
	Annotations ToolAnnotations
}

// WorkflowSpec defines a numbered investigative workflow exposed as an MCP prompt.
type WorkflowSpec struct {
	Name        string
	Title       string
	Description string
	Args        []WorkflowArgSpec
	Steps       []string
}

// WorkflowArgSpec describes one prompt parameter on a WorkflowSpec.
type WorkflowArgSpec struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

// PromptInfo is one entry of an MCP prompts/list result.
type PromptInfo struct {
	Name        string            `json:"name"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Arguments   []WorkflowArgSpec `json:"arguments"`
}

// ResourceInfo is one entry of an MCP resources/list result.
type ResourceInfo struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

// CLIOptionSpec describes one command-line flag for reference/cli.md rendering.
type CLIOptionSpec struct {
	Flags   string
	Values  string
	Default string
	Help    string
}

// ProviderModelRow lists model tiers for one LLM provider in reference/sip-rtp.md.
type ProviderModelRow struct {
	Provider string
	Fast     string
	Detailed string
	Deep     string
}

// PackageMeta holds live analyzer docstrings and MakeIssue codes parsed from Go AST.
type PackageMeta struct {
	Key        string   `json:"key"`
	PackageDir string   `json:"package_dir"`
	Doc        string   `json:"doc"`
	Codes      []string `json:"codes"`
}

// SkillWriteResult summarizes files written, left unchanged, and pruned by WriteSkill.
type SkillWriteResult struct {
	Written   []string
	Unchanged []string
	Removed   []string
}

// SkillWriteRefusedError reports existing destination files not created by S.O.N.I.C.
type SkillWriteRefusedError struct {
	Paths []string
}

// Error implements error for SkillWriteRefusedError matching utils/agent_guide.py.
func (e *SkillWriteRefusedError) Error() string {
	return fmt.Sprintf("not replacing %s: not written by sonic --create-skill. Move it away or choose another directory.",
		joinComma(e.Paths))
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// Topics lists every sonic://guide/<topic> page and its title in display order.
var Topics = []TopicSpec{
	{Slug: "mcp-tools", Title: "MCP tools, parameters and workflows"},
	{Slug: "network-detectors", Title: "Network and VPN detectors and their issue codes"},
	{Slug: "sip-rtp", Title: "SIP and RTP analysis"},
	{Slug: "cli", Title: "Command line (sonic)"},
	{Slug: "grpc", Title: "gRPC, gNMI and gNOI troubleshooting"},
	{Slug: "interpreting-results", Title: "Interpreting results and common pitfalls"},
}

// AllToolGuide lists every S.O.N.I.C. MCP tool in priority investigation order.
var AllToolGuide = []ToolGuideEntry{
	{Name: "analyze_network_pcap", Short: "first call; every detector", Title: "Analyze any capture with the network detectors", LLM: false,
		Question: "Unknown capture, or anything that is not only VoIP: which protocols are present and what is wrong"},
	{Name: "analyze_vpn_pcap", Short: "IPsec/DMVPN up? encrypted?", Title: "Prove VPN encryption and IPsec/DMVPN setup", LLM: false,
		Question: "Is inter-site traffic encrypted? Did IKE/IPsec negotiate? Did DMVPN spokes register?"},
	{Name: "analyze_routing_pcap", Short: "BGP/OSPF/EIGRP, ping loss", Title: "Check routing adjacencies, reachability and failover", LLM: false,
		Question: "Did BGP/OSPF/EIGRP adjacencies form, and if not why; how long did a failover take; is ping lost?"},
	{Name: "analyze_data_plane_pcap", Short: "MTU, ESP, TCP, TLS, QoS", Title: "Inspect the data plane: MTU, ESP, TCP, TLS, QoS", LLM: false,
		Question: "Do packets get through: path MTU and fragmentation, ESP overhead, TCP retransmissions or zero window, TLS policy, DSCP and RTP quality"},
	{Name: "analyze_grpc_pcap", Short: "gRPC/gNMI: RPC status, creds", Title: "Troubleshoot gRPC, gNMI and gNOI from a capture", LLM: false,
		Question: "Why a gRPC, gNMI or gNOI client fails: each RPC's grpc-status and message, HTTP/2 resets, GOAWAY and flow-control stalls, TLS certificate and alert problems, credentials sent in cleartext metadata"},
	{Name: "analyze_restconf_pcap", Short: "RESTCONF/REST: status, errors", Title: "Troubleshoot RESTCONF and REST from a capture", LLM: false,
		Question: "Why a RESTCONF or REST client fails: each request's method, path, status, timing and Content-Type, the ietf-restconf:errors of a failure, a Location on a 201, and credentials present (Authorization, cookies, tokens, masked). Decrypts TLS (HTTP/1.1 and HTTP/2) with a key log"},
	{Name: "analyze_snmp_pcap", Short: "SNMP versions; v3 decrypt (users file)", Title: "Name SNMP versions and decrypt SNMPv3", LLM: false,
		Question: "Which SNMP versions and v3 security levels are on the wire, which v1/v2c communities cross in cleartext (masked), and, with a USM users file, which SNMPv3 authPriv messages decrypt and why the others do not"},
	{Name: "analyze_aaa_pcap", Short: "TACACS+/RADIUS (shared key)", Title: "Read TACACS+ and RADIUS with the shared key", LLM: false,
		Question: "Who asked the AAA server and was it accepted or rejected; the authorization and accounting records; is TACACS+ sent unobfuscated; does the RADIUS shared secret verify the authenticators. De-obfuscates TACACS+ and RADIUS User-Password with the key, values masked"},
	{Name: "analyze_esp_pcap", Short: "ESP decrypt (SA keys)", Title: "Decrypt IPsec ESP with SA keys and analyze the inner traffic", LLM: false,
		Question: "With the SA keys of a Linux or strongSwan endpoint (an SA file or ip xfrm state output): which ESP packets decrypt per SA, why the others do not, and what the inner traffic shows to the network detectors. Cisco IOS does not expose ESP keys, so its tunnels cannot be decrypted this way"},
	{Name: "audit_cleartext_pcap", Short: "pass/fail cleartext gate", Title: "Assert a transport link carried no cleartext", LLM: false,
		Question: "Gate a run on encryption: did anything outside the allowlist (GRE, BGP, OSPF, ICMP, SSH or TLS without real encryption, ...) cross the link?"},
	{Name: "correlate_pcaps", Short: "2+ points: NAT, loss, asymmetry", Title: "Follow packets across two or more captures", LLM: false,
		Question: "With captures from two or more points: NAT translations, where a reply was dropped, asymmetric paths, probes an ACL stopped"},
	{Name: "analyze_convergence_pcap", Short: "failover time and driver", Title: "Time a failover and name what drove it", LLM: false,
		Question: "How long after an event did detection, the BGP reaction and traffic resumption take, and was it DPD or the hold timer?"},
	{Name: "merge_pcap_timelines", Short: "multi-point failover timeline", Title: "Merge capture timelines and time a failover", LLM: false,
		Question: "A chaos or failover run captured at several points: one timeline, and failover time against the design threshold"},
	{Name: "quick_quality_check", Short: "SIP grade, MOS per RTP stream", Title: "Score SIP/RTP call quality without an LLM", LLM: false,
		Question: "How good were the calls: quality grade, MOS per RTP stream, jitter, loss, SIP auth posture"},
	{Name: "analyze_pcap", Short: "written diagnosis of SIP calls", Title: "Diagnose SIP calls with an LLM", LLM: true,
		Question: "A written diagnosis of SIP calls: why a call dropped, failed, or had one-way or choppy audio"},
	{Name: "analyze_pcap_partial_streaming", Short: "SIP quality, then LLM diagnosis", Title: "SIP quality first, then the LLM diagnosis", LLM: true,
		Question: "The quality numbers and the LLM diagnosis of one SIP capture in one call, with timings"},
	{Name: "analyze_batch_pcaps", Short: "LLM diagnosis of a SIP directory", Title: "Diagnose every SIP capture in a directory with an LLM", LLM: true,
		Question: "Many SIP captures in one directory, each diagnosed by an LLM, plus aggregate counts"},
	{Name: "list_llm_providers", Short: "LLM providers, models, keys set", Title: "List LLM providers and configuration", LLM: false,
		Question: "Which LLM providers and models the LLM tools can use, and whether each API key is set"},
}
