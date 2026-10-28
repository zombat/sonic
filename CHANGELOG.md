# Changelog

All notable changes to S.O.N.I.C. (SIP Observation and Network Inspection Console) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 🧭 **MCP guidance built into the server** (`utils/agent_guide.py`)
  - Instructions in the initialize result, under 2 KB: which tool answers which question, the order of a typical investigation, which tools call an LLM, result shape, size limits and what packets cannot show
  - Every tool has a title and annotations (read-only, not destructive; deterministic tools idempotent and closed world, LLM tools open world), and a description that says when to use it, what it needs, what it costs and what it returns
  - Prompts `diagnose_capture`, `check_vpn_encryption`, `investigate_failover`, `diagnose_sip_call`
  - Resources `sonic://guide/overview` and `sonic://guide/<topic>` (`mcp-tools`, `network-detectors`, `sip-rtp`, `cli`, `interpreting-results`)
- 🎓 **Agent Skill by progressive disclosure**: `python3 sonic.py --create-skill [DIR]` and `python3 mcp_server.py --create-skill [DIR]` (default `.claude/skills/sonic`) write a short `SKILL.md` and one `reference/` file per area. Tool parameters, detectors and issue codes, CLI options and LLM providers are generated from the live code. Each file carries a marker; a `SKILL.md` or reference file without it is never replaced, files are written atomically, and a rerun leaves unchanged files alone
- 🔑 **Anthropic with a passthrough key** (`utils/credentials.py`): API keys come from the process environment (an MCP client's `env` block passes one through), then from a dotenv file named by `--env-file PATH` (`sonic.py`, `mcp_server.py`) or `SONIC_ENV_FILE`. The file is parsed as literal data, only `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `AZURE_OPENAI_KEY` are kept, and a value is never copied into the environment
- 🙈 **Keys never shown**: redacted by value (and `sk-ant-...` by pattern) from every MCP tool result, CLI output, log records, saved reports and the prompts sent to the LLM (`RedactingLM`); `list_llm_providers` reports only `configured` and the source (`environment` or the env file path)
- 🧪 `test_credentials.py`: parser, precedence, redaction of every output path with dummy keys, the CLI and a real MCP stdio session
- 🧪 `test_mcp_guidance.py`: instructions, annotations, descriptions, prompts and resources, the skill's frontmatter, size, coverage, refusal and idempotence, both entry points, and a real MCP stdio session
- **Data plane detectors** (deterministic, no LLM), run by default in `analyze_network_capture`:
  - `path_mtu`: ICMP Fragmentation Needed / Packet Too Big with the advertised MTU matched to the probe frame, PMTUD black holes for DF pings and TCP (with the bracket the path MTU lies in), IP fragments complete, incomplete and overlapping, reassembly timeouts
  - `esp_overhead`: ESP sizes per SA tested against cipher families, inner size bounds and overhead in tunnel and transport-over-GRE mode, tunnel MTU fit against the transport MTU, ESP fragmented after encryption; labelled as estimates
  - `tcp`: per-connection health from raw sequence numbers (no answer, refused, fast and timeout retransmissions, gaps, duplicate ACKs, zero window with duration, window full, resets, MSS and window scale, RTT and RFC 6298 RTO) with one verdict per connection
  - `tls`: ClientHello and ServerHello on any port with segment reassembly, TLS 1.2 certificates (TLS 1.3 reported as encrypted), cleartext alerts, and a baseline check passed as a parameter
  - `qos`: DSCP per flow, GRE inner against outer DSCP, ESP DSCP per SA, RTP loss, RFC 3550 jitter and DSCP with a MOS estimate from the existing E-model, ECN CE
- **Multi-capture tools**: `correlate_captures` (`analyzers/correlate.py`) follows packets across labelled captures for NAT translations, lost replies, asymmetric paths, stopped probes, transit time, TTL decrement and DSCP rewrites, streaming with a bounded match window; `merge_timelines` (`analyzers/timeline.py`) merges every detector's events from several captures and measures deltas between chosen events against thresholds, optionally writing JSON
- **MCP tools**: `analyze_data_plane_pcap`, `correlate_pcaps`, `merge_pcap_timelines`; `analyze_network_pcap` takes per-detector `options`
- **Tests**: `test_dataplane_detectors.py` (both backends, synthetic fixtures from `tests/fixtures/generate_dataplane_fixtures.py`, real lab captures when present) and new MCP tool tests
- The three data plane MCP tools follow the guidance conventions: titles, annotations, descriptions with returns, cost and limits in the visible text, results through `redact_result`, rows in the instructions and the generated skill

### Changed
- Anthropic models: `claude-haiku-5-5` (fast), `claude-sonnet-5-5` (detailed, the default), `claude-opus-5-5` (new `deep` profile and `--model deep` analysis mode), called as `anthropic/<model>` through DSPy. Anthropic requests no longer send `temperature`, which current Claude models reject with a 400
- Tool descriptions: the returns, limits and examples moved into the text an MCP client sees (fastmcp drops docstring sections such as `Returns:` from the description)
- `analyzers/network_orchestrator.py` keeps its detectors in one registry, `DETECTOR_CLASSES`
- `sonic.py` builds its parser in `build_parser()`; `--file` is still required for every mode except `--create-skill`
- INTEGRATION_GUIDE.md and README.md describe `--create-skill` in place of the `--init-skills` command they named, which did not exist
- Every network record carries `dp` (IP identification, DF/MF, fragment offset, DSCP/ECN, raw TCP sequence numbers, window and options, payload head and hash, ICMP next-hop MTU) from both backends (`extractors/dataplane.py`)
- tshark runs with `ip.defragment:FALSE`, so fragments stay one record per frame as on the scapy backend; the scapy backend reports a UDP length from the header, as tshark does
- `DETECTOR_CLASSES` also holds `path_mtu`, `esp_overhead`, `tcp`, `tls` and `qos`; `_build_detectors` builds from it and passes per-detector `options`

### Fixed
- The MCP server's stdout carries only JSON-RPC (`utils/protocol_stdout.py`). Before serving it keeps the real stdout for the protocol and points descriptor 1 and `sys.stdout` at stderr, so the SIP, network, extractor and reporting prints (and child processes) no longer corrupt the stdio channel; the CLI's output is unchanged. `test_mcp_stdio.py` runs a real stdio session, calls the SIP and network tools on a sample capture and parses every byte written to stdout through the server's exit
- Every LLM tool (`analyze_pcap`, `analyze_pcap_partial_streaming`, `analyze_batch_pcaps`) and every LLM path behind them uses one provider: the call's `provider`, else `SONIC_LLM_PROVIDER`, else `ollama` (`llm_config.resolve_provider`). The batch and streaming tools used to default to `anthropic`, and `SONIC_LLM_PROVIDER` changed none of them; `list_llm_providers` reports the resolved provider as `current_config.provider`
- `sonic.py --model-name NAME` now runs the LLM analysis on that model (one pass in the fast, detailed, deep and combined modes, and in batch and streaming); it was parsed and ignored. It is refused with `--model all`
- `analyze_pcap_partial_streaming` (and `--stream --partial`) failed on every call: `ai/partial_streaming.py` imported `utils.serialization`, which never existed. It now converts the quality and MOS results with `utils.credentials.redact`, the converter every MCP tool result already goes through. `test_mcp_stdio.py` calls the tool over a real stdio session with only the streaming LLM stubbed (`tests/stub_llm_mcp_server.py`)
- `sonic.py --api-key` is removed: it was never used, and a key typed on the command line lands in shell history and `ps` output. Keys come from the environment, then from the file `--env-file` or `SONIC_ENV_FILE` names

---

## [3.1.0] - 2026-10-25

### Added
- 🛰️ **Network and VPN detectors** (deterministic, no LLM)
  - IPsec / VPN: IKEv1 and IKEv2 outcomes per IKE SA, cleartext NOTIFY errors (NO_PROPOSAL_CHOSEN and others), retransmissions without reply, rekeys, ESP flows with sequence gaps and duplicates, NAT-T, and an encrypted or cleartext verdict per peer pair
  - GRE / NHRP (DMVPN): GRE tunnels and keys, NHRP registrations, resolutions, redirects and error indications, hub and spoke roles, spoke-to-spoke tunnels
  - Routing health: BGP sessions (OPEN, NOTIFICATION decoded, resets, End-of-RIB, refused TCP 179), OSPF per link (timer, mask, area, auth, MTU mismatches, one-way neighbors, DR/BDR), EIGRP (K-value and AS mismatches, goodbyes, hold time expiry), routing over GRE, and a failover timeline
  - Reachability: ICMP echo loss, RTT and outage windows, ICMP errors with decoded codes, ARP without replies, duplicate IPs, protocol and conversation summary
  - One entry point (`analyzers/network_orchestrator.py`) that reads the capture once, runs every detector that applies, and runs the existing SIP quality path unchanged when SIP is present
- 🌐 **New MCP tools**: `analyze_network_pcap`, `analyze_vpn_pcap`, `analyze_routing_pcap`, with descriptions written so an agent learns each tool from the tool itself; the server now sends instructions naming which tool fits which capture
- 🔧 **CLI mode** `--network-only`, with `--detectors`, `--peers`, `--display-filter`, `--max-packets` and `--json`; the report is written as markdown or JSON
- 🧪 **Tests and fixtures**: `test_network_detectors.py` (every detector on both the tshark and scapy backends, backend parity, entry point behaviour), `test_network_mcp.py` (the tool functions and a real MCP stdio handshake), and 14 small deterministic fixtures from `tests/fixtures/generate_fixtures.py`

### Changed
- MCP server name is now "S.O.N.I.C. VoIP and Network Analyzer"; the existing five tools are unchanged
- `run_phase2_tests.sh` checks the new MCP tools and runs the network detector tests
- `.gitignore` allows the synthetic fixtures under `tests/fixtures/`

### Technical
- **Extraction**: `extractors/network.py` streams tshark field output (`-T fields`) so memory stays flat, checks which tshark fields exist and reports missing ones, and falls back to scapy with byte-level parsers that produce the same records
- **Report schema**: `sonic.network_report/1`; every section has `status`, `verdict` and `issues` with stable codes and Wireshark frame numbers

---

## [3.0.0] - 2026-03-04

### Added
- 🌐 **NetClaw MCP Server Integration** (MCP Server #38)
  - FastMCP-based Model Context Protocol server for AI assistant integration
  - 5 MCP tools: analyze_pcap, quick_quality_check, list_llm_providers, analyze_batch_pcaps, analyze_pcap_partial_streaming
  - Comprehensive 18-phase integration guide: NETCLAW_SONIC_INTEGRATION_GUIDE.md
  - Full support for Claude Desktop, Cline, and MCP-compatible clients
  - Slack-native workflows for VoIP diagnostics

- 📊 **What Is Analyzed Section** in README
  - Detailed "Top 10 SIP Issues Analyzed by S.O.N.I.C." with coverage matrix
  - Comprehensive symptom detection for each issue category
  - Coverage tracking table showing analysis depth per issue type
  - Clear detection mechanisms and diagnostic approaches

- 🔒 **Phase 3: Advanced Auth Reporting & Visualization**
  - Security posture grading (A+ to F grades)
  - Auth security factors: algorithm strength, qop usage, REGISTER success rates
  - Realm/server mapping with ASCII tree structure
  - Challenge/response sequence diagrams (ASCII for console, Mermaid for markdown)
  - 6-type upgrade recommendation engine
  - Modal analysis: Mermaid sequence diagram generation for markdown reports

- 🔐 **PII Sanitization**
  - Removed sensitive IP addresses from TEST_CAPTURE.md sample output
  - Sanitized SIP URIs and endpoint identifiers
  - Example data uses strictly RFC-defined example ranges (10.0.0.0/8)
  - No real phone numbers or user authentication data in samples

- 📚 **Documentation Updates**
  - Updated README.md with NetClaw integration section (v3.0)
  - Removed deprecated sip_test.py file references (use sonic.py instead)
  - Removed deprecated batch_test.py references
  - Removed sip_server.py and raw_test.py documentation (not part of v3.0 scope)
  - Updated SIP_DOCUMENTATION.md to reference active tools only
  - All examples now use canonical sonic.py entry point

### Changed
- **Documentation Focus**: Shifted from development/testing tools to production VoIP analysis
- **Main Entry Point**: Canonical entry point is now sonic.py (via sonic --help or python3 sonic.py)
- **MCP Integration**: Now primary integration path for external AI agents via NetClaw
- **Version Identifier**: Updated to 3.0 (NetClaw MCP Integration + Phase 3 Auth Reporting)

### Deprecated
- sip_test.py usage in documentation (legacy testing tool, superseded by sonic.py --model combined)
- batch_test.py usage (superseded by sonic.py with directory handling)
- sip_server.py references (out of scope for VoIP analysis tool)
- raw_test.py references (protocol testing framework, not part of analysis)

### Removed
- Deprecated test script references from README
- Outdated SIP server implementation documentation
- Non-functional batch testing documentation
- Raw protocol testing framework from primary documentation

### Security
- PII removed from sample reports
- Example data uses RFC 5737 documentation ranges
- No sensitive authentication credentials in samples
- Sanitized phone numbers and user identifiers

### Technical
- **MCP Server**: stdio-based JSON-RPC 2.0 implementation with FastMCP
- **Quality Scoring v2**: Integrated auth security penalties into weighted scoring
- **Auth Grading Algorithm**: A+ to F scale based on RFC compliance
- **Report Generation**: Enhanced markdown support with Mermaid diagram blocks
- **Testing**: All 15 Phase 3 tests passing, comprehensive validation suite

---

## [2.0.0] - 2025-07-13

### Added
- 🎵 **Comprehensive RTP Stream Analysis**: Full SIP-to-RTP correlation workflow
  - SDP parsing from SIP INVITE messages  
  - RTP packet correlation using IP addresses and ports from SDP
  - Media quality metrics (packet loss, jitter, sequence gap analysis)
  - Industry-standard quality thresholds and assessments

- 🤖 **Enhanced AI Analysis**: Dual-model approach for optimal accuracy
  - Fast model (qwen2.5:0.5b): Structured JSON output with reliable format compliance
  - Detailed model (qwen2.5vl:7b): Comprehensive natural language insights
  - Combined analysis merging strengths of both models

- 🔧 **Codec-Aware Diagnostics**: Comprehensive codec knowledge database
  - G.711 (PCMU/PCMA): High quality analysis with bandwidth monitoring
  - G.729: Low bitrate codec with packet loss sensitivity checks
  - Opus: Adaptive codec with dynamic payload type handling
  - iLBC: Packet loss resistant codec with compatibility checks

- 📊 **Enhanced Data Extraction**: Multi-protocol packet capture analysis
  - Enhanced tshark extraction with RTP field correlation
  - SIP signaling + RTP media stream analysis
  - Robust fallback to scapy when tshark unavailable

- 📈 **Quality Metrics & Thresholds**: Industry-standard VoIP quality assessment
  - Packet Loss: <1% excellent, 1-3% good, >5% poor
  - Jitter: <20ms excellent, 20-50ms acceptable, >50ms problematic
  - Sequence gap analysis for call quality assessment

### Enhanced
- **SIP Message Analysis**: Improved parsing of SIP headers and SDP payloads
- **Error Handling**: Comprehensive format conversion for AI model responses
- **Visual Output**: Rich console indicators with emojis and progress tracking
- **Documentation**: Complete API documentation and usage examples

### Technical
- **Architecture**: Enhanced extraction pipeline with SIP-RTP correlation
- **Performance**: Optimized for 20-35 second combined analysis times
- **Reliability**: Multiple fallback strategies for robust operation
- **Validation**: Pydantic models for structured output validation

## [1.0.0] - 2025-01-13

### Added
- Initial release of S.O.N.I.C. (SIP Observation and Network Inspection Console)
- Basic SIP message extraction and analysis
- AI-powered diagnostic capabilities using DSPy framework
- Support for pcap/pcapng file analysis
- tshark and scapy-based packet extraction
- Multiple output formats (JSON, raw, codec types)
- Comprehensive error handling and format conversion

### Features
- SIP call flow analysis
- Audio quality diagnostics
- Call termination analysis
- User-Agent detection
- Response code analysis
- Visual progress indicators

---

## Legend
- 🎵 Media/RTP related features
- 🤖 AI/Analysis enhancements  
- 🔧 Codec-specific improvements
- 📊 Data extraction/processing
- 📈 Quality metrics and assessment
- 📋 Documentation and usability
