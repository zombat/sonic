# S.O.N.I.C. MCP Server Reference

`mcp_server.py` exposes S.O.N.I.C. to an agent over stdio, using the Model Context Protocol. The server is built on FastMCP. This page lists everything it offers. The list is taken from the running server, so it matches the code. Run `python3 mcp_server.py` to start it, and see `docs/ARCHITECTURE.md` (section 3) for the request flow.

Every tool is read-only: it reads a capture and writes nothing. Each tool carries annotations that say whether it is idempotent and whether it calls an external LLM.

## Tools (14)

### SIP and VoIP

| Tool | LLM | What it does |
|---|:---:|---|
| `quick_quality_check` | no | Scores SIP/RTP call quality. The first tool to try for "how good were the calls". |
| `analyze_pcap` | yes | Diagnoses the SIP calls in a capture, with a written explanation for each call. |
| `analyze_pcap_partial_streaming` | yes | Runs the deterministic quality and MOS analysis, then the LLM diagnosis, on one capture, streaming partial results. |
| `analyze_batch_pcaps` | yes | Diagnoses every SIP capture in one directory, one `analyze_pcap` run per file. |
| `list_llm_providers` | no | Lists the providers and models the LLM tools can use, and whether each key is configured. Never returns a key. |

### Network and VPN

| Tool | LLM | What it does |
|---|:---:|---|
| `analyze_network_pcap` | no | Analyzes any capture, not only VoIP, and returns deterministic findings as JSON. |
| `analyze_vpn_pcap` | no | Shows from packets whether traffic between sites is encrypted, for IPsec, GRE/NHRP and DMVPN. |
| `analyze_routing_pcap` | no | Checks BGP, OSPF and EIGRP health and reachability. |
| `audit_cleartext_pcap` | no | Asserts that a crypto transport carried only allowed traffic. Every frame must be accounted for. |
| `analyze_convergence_pcap` | no | Measures a failover from one capture and reports what drove it. |
| `analyze_data_plane_pcap` | no | Looks at path MTU and fragmentation, ESP overhead, TCP health, TLS handshakes and QoS. |
| `correlate_pcaps` | no | Follows the same packets through two or more captures taken at different points. |
| `merge_pcap_timelines` | no | Merges the captures of one failover run into a single event timeline. |

### gRPC

| Tool | LLM | What it does |
|---|:---:|---|
| `analyze_grpc_pcap` | no | Troubleshoots gRPC from a capture: gNMI, gNOI, gRIBI, P4Runtime or any gRPC service. Reports every call with its status, HTTP/2 trouble, TLS findings and credentials in cleartext metadata. Accepts a TLS key log. |

Tools that call an LLM read their provider from the `provider` argument, or from `SONIC_LLM_PROVIDER` when the argument is absent (default: `ollama`).

## Prompts (5)

Prompts are starting points that a client can offer the user. Each one tells the agent which tools to call in what order.

| Prompt | Purpose |
|---|---|
| `diagnose_capture` | General first look at a capture. |
| `check_vpn_encryption` | Confirms that VPN traffic is encrypted. |
| `investigate_failover` | Works through a failover from its captures. |
| `diagnose_sip_call` | Diagnoses one SIP call. |
| `troubleshoot_grpc` | Works through a gRPC problem, with the key log when there is one. |

## Resources (7)

Resources are guidance the agent reads when it needs it. They are not loaded up front.

| URI | Covers |
|---|---|
| `sonic://guide/overview` | What S.O.N.I.C. answers and which tool fits which question. |
| `sonic://guide/mcp-tools` | The tool reference. |
| `sonic://guide/network-detectors` | The network and VPN detectors and their issue codes. |
| `sonic://guide/sip-rtp` | SIP and RTP analysis. |
| `sonic://guide/cli` | The command-line equivalents. |
| `sonic://guide/grpc` | gRPC, TLS and key-log handling. |
| `sonic://guide/interpreting-results` | How to read the verdicts and findings. |

## Instructions

On initialize the server sends a short guide, under 2 KB: what S.O.N.I.C. answers, which tool fits which question, the usual order of an investigation, which tools call an LLM, size limits and what each tool returns.

## Output and safety

- Every tool returns JSON-safe data. The conversion is `to_jsonable` in `analyzers/network_orchestrator.py`.
- stdout is reserved for JSON-RPC. `utils/protocol_stdout.py` points the rest of the process, including tshark, at stderr, so a stray print cannot corrupt the stream.
- Keys and credentials are redacted from every tool result, the logs and the LLM prompt. See the README section on credentials.

## Generated agent skill

`python3 sonic.py --create-skill` writes a Claude skill that describes the same tools. It reads the parameters from the code at write time, so it matches the installed version. Rerun it after an upgrade. It replaces only files it wrote, and it marks each file it writes.

## Tests

The MCP surface is covered by three files: `test_mcp_guidance.py` (instructions, skill, providers), `test_network_mcp.py` (the network tools, including a stdio handshake) and `test_mcp_stdio.py` (stdout carries only JSON-RPC). See `docs/TESTING.md`.
