# Changelog

All notable changes to S.O.N.I.C. (SIP Observation and Network Inspection Console) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Zero-cleartext audit (`cleartext_audit` detector, `audit_cleartext_pcap` MCP tool): every frame against an allowlist (default ESP, IKE on UDP 500/4500, NAT-T keepalives; tokens for ARP, ICMP, routing, GRE, link-local layer 2, ports and protocols, each scopable to addresses), reported by protocol and address pair with frame numbers, and a pass or fail result
- IKEv2 exchange decoding: proposals offered and chosen by name with weak algorithms flagged, KE groups and INVALID_KE_PAYLOAD retries, NAT_DETECTION hashes recomputed from the wire and the move to UDP 4500, DPD liveness checks, IKE SA collisions, cleartext INVALID_SPI / INVALID_IKE_SPI, ESP on a stale SPI after a rekey, and a diagnosis code per IKE SA (proposal_mismatch, dh_group_mismatch, auth_failed, auth_no_reply, nat_t_missing, udp_4500_blocked, no_reply, liveness_lost, peer_lost_sa, ...)
- DMVPN Phase 3 sequence proof (`dmvpn_phase3` detector): per redirected flow the ordered steps via hub, redirect, resolution request, resolution reply and direct data, with the first missing step and why; hub-relayed traffic with no redirect; resolution thrashing; and, given the hubs, encrypted spoke-to-spoke shortcuts when NHRP is inside ESP
- BGP: OPEN capabilities, keepalive cadence against hold/3, UPDATE timing, the TCP MSS of each SYN and SYN-ACK checked against `expected_mss`, and the cause of each session drop (hold timer, NOTIFICATION, BFD, RST, FIN, or a hold expiry inferred from silence)
- OSPF: adjacencies stuck in EXSTART or EXCHANGE from DB Description retransmissions, with the cause (for example the DBD MTU mismatch)
- Convergence timeline (`convergence` detector, `analyze_convergence_pcap` MCP tool): from an event time or the first failure sign, the delay to detection, to the first UPDATE on the surviving path and to traffic resuming, and the driver (DPD, BGP hold timer, BFD, explicit close)
- `hubs` on analyze_vpn_pcap and analyze_network_pcap, `expected_mss` on analyze_routing_pcap and analyze_network_pcap
- Nine synthetic fixtures and `test_control_plane.py` (both backends, plus the Pleiades lab captures when present)

### Changed
- The extractor hands the IKE bytes from tshark (`udp.payload`) to the same parser scapy uses, so IKE fields match by construction; records gain the TCP MSS of SYNs, BGP capability codes, OSPF DBD flags and sequence, and an `llc` label for CDP/STP frames
- Synthetic IKEv2 fixtures carry real NAT detection hashes
- MCP tool descriptions put outputs and limits before `Args:`, the part clients show

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
