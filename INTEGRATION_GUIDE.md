# S.O.N.I.C. Agentic Integration Guide

S.O.N.I.C. is designed to integrate seamlessly with agentic systems like NetClaw, OpenClaw, and any skills-based client.

---

## How the Integration Works

The key to these integrations is the Model Context Protocol (MCP) server built into S.O.N.I.C.

**FastMCP Server (`mcp_server.py`)**: S.O.N.I.C. exposes a standard MCP server using FastMCP. This allows any MCP-compatible client to connect to it via stdio JSON-RPC.

**Agentic Orchestration**: Because it acts as an MCP tool, platforms like NetClaw (or its open-source equivalent, OpenClaw) can register S.O.N.I.C. as a tool. When your network automation agents need to analyze a pcap file or troubleshoot a SIP trunk, they can natively call the `analyze_pcap` or `quick_quality_check` tools exposed by S.O.N.I.C.

**Multiple LLM Providers**: S.O.N.I.C. doesn't lock you into one ecosystem. You can use local Ollama (for air-gapped or secure environments where you don't want SIP auth headers leaving your network), Anthropic, OpenAI, or Azure.

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
# On the NetClaw execution node:
git clone https://github.com/zombat/sonic.git /opt/sonic
cd /opt/sonic
pip install -r requirements.txt
```

### Step 2: Register the MCP Server in NetClaw

NetClaw needs to know where the S.O.N.I.C. tools live and how to communicate with them via standard stdio JSON-RPC. Add the S.O.N.I.C. configuration to NetClaw's tool registry or MCP configuration file.

```json
{
  "mcpServers": {
    "sonic_voip_analyzer": {
      "command": "python3",
      "args": ["/opt/sonic/mcp_server.py"],
      "env": {
        "SONIC_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "sk-ant-...",
        "PYTHONPATH": "/opt/sonic"
      }
    }
  }
}
```

> **Note:** For strict data privacy (so pcaps never leave the network), change the provider to `ollama` and remove the API key. Ollama runs entirely local.

If S.O.N.I.C. is installed as a package (`pip install sonic-sip-mcp`), you can use the installed command directly:

```json
{
  "mcpServers": {
    "sonic_voip_analyzer": {
      "command": "sonic-mcp-server",
      "env": {
        "SONIC_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

### Step 3: Assign the Tools to a NetClaw Agent

NetClaw uses role-based agents. Create or update a Voice Engineering Agent and grant it access to the S.O.N.I.C. toolset. In your NetClaw agent definition (managed via UI or YAML), define the agent's persona and attach the skills:

```yaml
agent:
  name: VoIP_Triage_Bot
  role: Senior Voice Network Engineer
  system_prompt: |
    You are a specialized VoIP network engineer. Your primary responsibility is to analyze
    SIP and RTP traffic to diagnose call quality issues, dropped calls, and authentication
    failures. When a user provides a pcap file, ALWAYS use the `analyze_pcap` tool to
    process it before providing your final diagnostic summary.
  tools_granted:
    - sonic_voip_analyzer.analyze_pcap
    - sonic_voip_analyzer.quick_quality_check
    - sonic_voip_analyzer.analyze_batch_pcaps
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

By registering `mcp_server.py` as a tool provider, NetClaw inherits all of S.O.N.I.C.'s parsing, fallback logic, and AI prompt structuring out of the box.

---

## Skills-Based Clients (Claude Code / Cline)

S.O.N.I.C. writes one Agent Skill, `sonic`, that any skills-aware client can use. It is triggered when you mention a capture file, VoIP call quality, MOS, SIP, RTP, IPsec or VPN encryption, DMVPN, BGP, OSPF, EIGRP or a failover.

**Write the skill into your project:**

```bash
# From your project root (where Claude Code is running):
python3 /path/to/sonic/sonic.py --create-skill
```

This writes `.claude/skills/sonic/` in the current directory: a short `SKILL.md` (which tool or command answers which question) and `reference/` files the agent reads only when it needs them (MCP tools and parameters, network detectors and issue codes, SIP and RTP analysis, the CLI, interpreting results). Pass a directory to write it elsewhere, for example `--create-skill ~/.claude/skills/sonic`. `python3 mcp_server.py --create-skill` writes the same skill.

The reference files are generated from the installed code, so rerun the command after an upgrade. It replaces only files it wrote and refuses to overwrite a `SKILL.md` it did not write.

An MCP client gets the same guidance without a skill: the server sends instructions at initialize, and serves the reference pages as `sonic://guide/<topic>` resources and four workflow prompts.

---

## Available MCP Tools

| Tool | LLM Required? | Description |
|------|---------------|-------------|
| `analyze_pcap` | Yes | Full analysis: SIP + quality + MOS + LLM diagnostics |
| `quick_quality_check` | No | Quality/MOS metrics only — fastest, no inference |
| `list_llm_providers` | No | Returns available providers and current config |
| `analyze_batch_pcaps` | Yes | Processes all pcaps in a directory |
| `analyze_pcap_partial_streaming` | Yes | Quality first, then streams LLM — cloud providers only |
| `analyze_network_pcap` | No | Any capture: protocols present plus IPsec, GRE/NHRP, routing, reachability and conversation detectors |
| `analyze_vpn_pcap` | No | Encrypted or cleartext between VPN peers, IKE outcomes, DMVPN registrations |
| `analyze_routing_pcap` | No | BGP/OSPF/EIGRP adjacency health, failover timeline, ping outages |

All tools accept absolute file paths only. Relative paths will silently produce file-not-found errors.
