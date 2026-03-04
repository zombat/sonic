# Changelog

All notable changes to S.O.N.I.C. (SIP Observation and Network Inspection Console) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
