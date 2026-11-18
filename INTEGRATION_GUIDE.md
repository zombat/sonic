# S.O.N.I.C. Agentic Integration Guide

S.O.N.I.C. is designed to integrate seamlessly with agentic systems like NetClaw, OpenClaw, and any skills-based client.

---

## How the Integration Works

The key to these integrations is the Model Context Protocol (MCP) server built into S.O.N.I.C.

**MCP Server (`sonic-mcp`)**: S.O.N.I.C. exposes a dependency-free MCP server over stdio JSON-RPC (`build/sonic-mcp` via `make build`, or `go install github.com/zombat/sonic/cmd/sonic-mcp@latest`).

**Agentic Orchestration**: Because it acts as an MCP tool, platforms like NetClaw (or its open-source equivalent, OpenClaw) can register S.O.N.I.C. as a deterministic packet-capture intelligence backend. When your network or voice automation agents need to inspect a capture, run a CI cleartext/policy gate, diff baseline captures, or troubleshoot a WAN/VoIP incident, they can natively call any of S.O.N.I.C.'s 21 MCP tools (`analyze_network_pcap`, `diagnose_media_underlay`, `evaluate_capture_gate`, `diff_pcaps`, `analyze_grpc_pcap`, `analyze_esp_pcap`, `analyze_pcap`, and more).

**Multiple LLM Providers**: S.O.N.I.C. doesn't lock you into one ecosystem. You can use local Ollama (for air-gapped or secure environments where you don't want SIP auth headers leaving your network), Anthropic, OpenAI, or Azure via direct HTTP clients (`internal/llm`).

---

## Supported Integration Targets

| Target | Method |
|--------|--------|
| [NetClaw](https://github.com/automateyournetwork/netclaw) / [OpenClaw](https://github.com/automateyournetwork/openclaw) | MCP server registration |
| Claude Desktop | MCP client config |
| Cline (VSCode) | MCP client config |
| Claude Code / skills-based clients | `--create-skill` command |
| Any MCP-compatible client | stdio JSON-RPC |

---

## Step-by-Step: NetClaw / OpenClaw Integration

### Step 1: Deploy S.O.N.I.C. to the Execution Environment

The S.O.N.I.C. repository needs to live on a machine, container, or jump host that the NetClaw agent has execution access to, along with the pcaps you want to analyze.

```bash
# On the NetClaw execution node (or download a prebuilt release tarball):
git clone https://github.com/zombat/sonic.git /opt/sonic
cd /opt/sonic
make install    # installs sonic and sonic-mcp (tshark required at runtime)
```

### Step 2: Register the MCP Server in NetClaw

NetClaw needs to know where the S.O.N.I.C. binary lives and how to communicate over standard stdio JSON-RPC. Add S.O.N.I.C. to NetClaw's MCP configuration file (prefer `SONIC_ENV_FILE` or `--env-file` so API keys never appear in client config):

```json
{
  "mcpServers": {
    "sonic_voip_analyzer": {
      "command": "/opt/sonic/build/sonic-mcp",
      "args": [],
      "env": {
        "SONIC_LLM_PROVIDER": "anthropic",
        "SONIC_ENV_FILE": "/path/to/secrets/sonic.env"
      }
    }
  }
}
```

> **Note:** For strict data privacy (so pcaps never leave the network), set `SONIC_LLM_PROVIDER` to `ollama` and remove the env file.

### Step 3: Assign the Tools to a NetClaw Agent

NetClaw uses role-based agents. Create or update a Voice Engineering Agent and grant it access to the S.O.N.I.C. toolset. In your NetClaw agent definition (managed via UI or YAML), define the agent's persona and attach the skills:

```yaml
agent:
  name: Packet_Capture_Triage_Bot
  role: Senior Network and VoIP Incident Engineer
  system_prompt: |
    You are a specialized network and VoIP troubleshooting engineer. When a user provides
    one or more capture files, use S.O.N.I.C. deterministic tools (`diagnose_media_underlay`,
    `analyze_network_pcap`, `evaluate_capture_gate`, `diff_pcaps`, `analyze_pcap`) before
    writing a root-cause summary.
  tools_granted:
    - sonic_voip_analyzer.diagnose_media_underlay
    - sonic_voip_analyzer.analyze_network_pcap
    - sonic_voip_analyzer.evaluate_capture_gate
    - sonic_voip_analyzer.diff_pcaps
    - sonic_voip_analyzer.analyze_pcap
    - sonic_voip_analyzer.quick_quality_check
```

### Step 4: Execute the Workflow

Once integrated, the workflow becomes conversational and automated. NetClaw acts as the bridge between a ticketing system (like ServiceNow or Jira) and S.O.N.I.C.

**The Trigger** (via Slack, Webex, or NetClaw UI):

> *"Hey NetClaw, we just got a ticket about one-way audio from the Chicago branch. I dumped a capture to `/mnt/captures/chicago_sip_issue.pcapng`. Can you take a look?"*

**The NetClaw Agent Execution:**

1. NetClaw routes the prompt to the `VoIP_Triage_Bot`
2. The agent calls `analyze_pcap` via the MCP server registered in Step 2
3. S.O.N.I.C. runs locally, processes the pcap, and returns a structured JSON report

**The Response:**

> *"I analyzed `/mnt/captures/chicago_sip_issue.pcapng`. The issue is one-way audio caused by a NAT traversal failure. S.O.N.I.C. detected that the SIP INVITE specified RTP media on `192.168.1.50:10004`, but we only received inbound RTP from the remote peer. The local PBX never sent outbound RTP. I recommend checking the firewall rules on the Chicago branch router to ensure UDP port 10004 is allowed outbound."*

By registering `sonic-mcp` as an MCP server, NetClaw inherits all of S.O.N.I.C.'s packet parsing, deterministic checks, and redaction out of the box.

---

## Skills-Based Clients (Claude Code / Cline)

S.O.N.I.C. writes one Agent Skill, `sonic`, that any skills-aware client can use. It is triggered when you mention a capture file, VoIP call quality, MOS, SIP, RTP, IPsec or VPN encryption, DMVPN, BGP, OSPF, EIGRP or a failover.

**Write the skill into your project:**

```bash
# From your project root (where Claude Code is running):
sonic --create-skill
```

This writes `.claude/skills/sonic/` in the current directory: a short `SKILL.md` (which tool or command answers which question) and `reference/` files the agent reads only when it needs them (`mcp-tools`, `network-detectors`, `sip-rtp`, `cli`, `grpc`, and `interpreting-results`). Pass a directory to write it elsewhere, for example `--create-skill ~/.claude/skills/sonic`. `./build/sonic-mcp --create-skill` writes the same skill.

The reference files are generated from the live code, so rerun the command after an upgrade. It replaces only files it wrote and refuses to overwrite a `SKILL.md` it did not write.

An MCP client gets the same guidance without a skill: the server sends instructions at initialize, and serves the reference pages as `sonic://guide/<topic>` resources and five workflow prompts.

---

## Available MCP Tools (21)

| Tool | LLM Required? | Description |
|------|---------------|-------------|
| `analyze_pcap` | Yes | Full analysis: SIP + quality + MOS + LLM diagnostics |
| `quick_quality_check` | No | Quality/MOS metrics, post-`200 OK` clipping, and RFC 4733 DTMF (fastest, no LLM) |
| `list_llm_providers` | No | Returns available providers, models, and configured key status |
| `analyze_batch_pcaps` | Yes | Processes all `*.pcap*` files in a directory |
| `analyze_pcap_partial_streaming` | Yes | Quality first, then LLM diagnosis with stage timings |
| `analyze_network_pcap` | No | Any capture: protocols present, detectors, optional `fast_path` / `since` / `until` |
| `analyze_vpn_pcap` | No | Encrypted or cleartext between VPN peers, IKE outcomes, DMVPN registrations |
| `analyze_routing_pcap` | No | BGP/OSPF/EIGRP adjacency health, failover timeline, ping outages |
| `audit_cleartext_pcap` | No | Pass/fail cleartext gate over a capture against an allowlist |
| `analyze_convergence_pcap` | No | Measures failover timing and recovery driver |
| `analyze_data_plane_pcap` | No | Path MTU, ESP overhead, TCP health, TLS handshakes, and QoS |
| `correlate_pcaps` | No | Follows matching packets across two or more captures |
| `merge_pcap_timelines` | No | Merges multi-point captures into one event timeline |
| `diagnose_media_underlay` | No | Cross-layer correlation linking SIP/RTP clipping and MOS to WAN/VPN/routing faults |
| `diff_pcaps` | No | Baseline-vs-target capture delta across TLS, MSS, QoS, SIP MOS, and issues |
| `evaluate_capture_gate` | No | CI policy evaluator (`zero-cleartext`, `no-weak-crypto`, `mos-min`, `max-clipping-ms`, `no-critical-issues`) |
| `analyze_grpc_pcap` | No | gRPC/gNMI/gNOI inspection, HTTP/2 trouble, TLS, masked metadata creds |
| `analyze_restconf_pcap` | No | RESTCONF/REST over HTTP/1.1 & HTTP/2, `ietf-restconf:errors`, masked creds |
| `analyze_snmp_pcap` | No | SNMP v1/v2c/v3 identification and USM authPriv decryption |
| `analyze_aaa_pcap` | No | TACACS+ and RADIUS inspection, Message-Authenticator check, credential masking |
| `analyze_esp_pcap` | No | IPsec ESP decryption with SA keys and inner detector analysis |

All tools accept absolute file paths only. Relative paths will produce file-not-found errors. See [docs/MCP.md](docs/MCP.md) for full details.
