# S.O.N.I.C. MCP Server Reference

S.O.N.I.C. exposes a Model Context Protocol (MCP) server over stdio JSON-RPC 2.0 via `sonic-mcp` (`cmd/sonic-mcp`, built to `build/sonic-mcp` via `make build`), backed by [internal/mcpserver](../internal/mcpserver), Go analyzers, and direct-HTTP LLM clients.

The server exposes 21 tools, 5 prompts, and 7 resources with embedded schemas in [tools.json](../internal/mcpserver/tools.json). See [docs/ARCHITECTURE.md](ARCHITECTURE.md) for the request flow.

Every tool is read-only: it reads a capture and writes nothing. Each tool carries annotations stating whether it is idempotent and whether it calls an external LLM.

## Tools (21)

### SIP and VoIP

| Tool | LLM | What it does |
|---|:---:|---|
| `quick_quality_check` | no | Scores SIP/RTP call quality, MOS, post-`200 OK` media clipping delay, and RFC 4733 DTMF events. |
| `diagnose_media_underlay` | no | Correlates SIP/RTP quality, clipping, and DTMF against IPsec/DMVPN/routing/PMTUD/TCP/QoS faults in one pass. |
| `analyze_pcap` | yes | Diagnoses SIP calls in a capture with a written explanation plus optional quality and MOS scores. |
| `analyze_pcap_partial_streaming` | yes | Runs deterministic quality and MOS analysis, then LLM diagnosis, and reports stage timings. |
| `analyze_batch_pcaps` | yes | Diagnoses every `*.pcap*` capture directly in a directory, sequentially or in parallel (up to 3 workers). |
| `list_llm_providers` | no | Lists providers and models the LLM tools can use, and whether each key is configured. Never returns a key. |

### Network and VPN

| Tool | LLM | What it does |
|---|:---:|---|
| `analyze_network_pcap` | no | Analyzes any capture and returns deterministic findings across enabled detectors as JSON. |
| `analyze_vpn_pcap` | no | Shows from packets whether inter-site traffic is encrypted for IPsec, GRE/NHRP, and DMVPN. |
| `analyze_routing_pcap` | no | Checks BGP, OSPF, and EIGRP health, reachability, and failover events. |
| `audit_cleartext_pcap` | no | Asserts that a crypto transport carried only allowed traffic. Every frame must be accounted for. |
| `analyze_convergence_pcap` | no | Measures failover convergence from one capture and reports what drove recovery. |
| `analyze_data_plane_pcap` | no | Inspects path MTU and fragmentation, ESP overhead, TCP health, TLS handshakes, and QoS. |
| `correlate_pcaps` | no | Follows matching packets across two or more captures taken at different network points. |
| `diff_pcaps` | no | Compares a working baseline capture against a broken capture and emits exact protocol/cipher/MTU/QoS/VoIP deltas. |
| `evaluate_capture_gate` | no | Evaluates deterministic CI/CD policy rules (`zero-cleartext`, `no-weak-crypto`, `mos-min`, `max-clipping-ms`, `no-critical-issues`). |
| `merge_pcap_timelines` | no | Merges events from multiple captures into one ordered timeline against failover thresholds. |

### Protocol Inspection and Decryption

| Tool | LLM | What it does |
|---|:---:|---|
| `analyze_grpc_pcap` | no | Troubleshoots gRPC/gNMI/gNOI/gRIBI/P4Runtime: RPC status, HTTP/2 trouble, TLS findings, and masked metadata credentials. Accepts a TLS key log. |
| `analyze_restconf_pcap` | no | Troubleshoots RESTCONF/REST over HTTP/1.1 and HTTP/2 (`ietf-restconf:errors`, status codes, timing, masked auth headers). Decrypts TLS with a key log or pcapng secrets. |
| `analyze_snmp_pcap` | no | Identifies SNMP v1/v2c/v3 messages, flags masked communities, and decrypts SNMPv3 authPriv traffic with a USM users file. |
| `analyze_aaa_pcap` | no | Reads TACACS+ and RADIUS sessions, validates Message-Authenticators, and de-obfuscates/decrypts credentials with a shared key file (values masked). |
| `analyze_esp_pcap` | no | Decrypts IPsec ESP packets using SA keys (`sa_file`) and runs the network detectors on the decrypted inner packets. |

Tools that call an LLM read their provider from the `provider` argument, else `SONIC_LLM_PROVIDER`, else `ollama`. Cloud API keys can come from process environment variables or `--env-file PATH` / `SONIC_ENV_FILE`.

## Prompts (5)

| Prompt | Purpose |
|---|---|
| `diagnose_capture` | General first look at an unknown capture. |
| `check_vpn_encryption` | Confirms whether VPN traffic is encrypted. |
| `investigate_failover` | Walks through a routing failover timeline from captures. |
| `diagnose_sip_call` | Checks deterministic quality and MOS first, then optional LLM diagnosis. |
| `troubleshoot_grpc` | Walks through gRPC, HTTP/2, TLS, and metadata credential checks. |

## Resources (7)

| URI | Covers |
|---|---|
| `sonic://guide/overview` | What S.O.N.I.C. answers and which tool fits each question. |
| `sonic://guide/mcp-tools` | Full tool parameter and workflow reference. |
| `sonic://guide/network-detectors` | Network and VPN detectors and their issue codes. |
| `sonic://guide/sip-rtp` | SIP and RTP analysis metrics and LLM provider configuration. |
| `sonic://guide/cli` | Command-line equivalents (`sonic`). |
| `sonic://guide/grpc` | gRPC, TLS, and key-log handling. |
| `sonic://guide/interpreting-results` | How to read verdicts, issue codes, and capture-point limits. |

## Instructions

At `initialize`, the server returns compact guidance under 2 KB covering capture path requirements, tool selection, investigation order, LLM cost/privacy boundaries, `max_items` sizing, and capture-point limits.

## Output and Safety

- Every tool returns valid JSON redacted before leaving the server ([internal/redact](../internal/redact)).
- `stdout` carries strictly newline-delimited JSON-RPC frames (`internal/report` reserves file descriptor 1 via [stdio_unix.go](../internal/report/stdio_unix.go) / [stdio_windows.go](../internal/report/stdio_windows.go)).
- Key files (`--env-file`, `--tls-secrets-log`, `--snmp-users`, `--aaa-secrets`, `--esp-sa`) are read by path or written into private temporary directories (`0700`/`0600` on `/dev/shm` tmpfs on Linux) and never echoed back.
- `initialize` reports `serverInfo.version` compiled from `-ldflags` (`main.version` / `main.commit`), matching `sonic-mcp --version`.

## Generated Agent Skill

Run `sonic --create-skill [DIR]` or `sonic-mcp --create-skill [DIR]` to write `.claude/skills/sonic/` containing `SKILL.md` and `reference/*.md`. Generated files carry a marker so reruns update cleanly without overwriting user-authored files.

## Tests

- **Go MCP unit, golden, and live child-binary stdio tests:** [internal/mcpserver/server_test.go](../internal/mcpserver/server_test.go), [internal/mcpserver/stdio_e2e_test.go](../internal/mcpserver/stdio_e2e_test.go), [internal/guide/guide_test.go](../internal/guide/guide_test.go), and [cmd/sonic-mcp/main_test.go](../cmd/sonic-mcp/main_test.go) (`make test` and `make parity`), plus [tests/stub_llm_mcp_server.go](../tests/stub_llm_mcp_server.go) for offline streaming E2E verification. See [docs/TESTING.md](TESTING.md).
