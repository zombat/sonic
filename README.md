# S.O.N.I.C. - SIP Observation and Network Inspection Console

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AI-Powered](https://img.shields.io/badge/AI-Powered-brightgreen.svg)](https://github.com/stanfordnlp/dspy)

**S.O.N.I.C. (SIP Observation and Network Inspection Console)** is a comprehensive SIP (Session Initiation Protocol) diagnostic tool that leverages AI to analyze VoIP call quality issues, call termination problems, and network-related issues from packet capture files. It provides intelligent analysis of SIP message flows and RTP media streams to identify problems like choppy audio, unexpected disconnects, and codec-related issues.

## � Background: From Manual to AI-Powered

**S.O.N.I.C. started as a personal tool to automate what I was already doing by hand.**

As a VoIP engineer, I spent years manually analyzing packet captures: importing pcaps into Wireshark, drilling through SIP dialogs, correlating RTP streams, checking codec payloads, inspecting authentication headers, and writing detailed findings. It was repetitive, thorough, but time-consuming.

What began in 2019 as a simple shell script to automate my manual troubleshooting grew into a sophisticated, multi-stage evolution of my personal workflow. By 2023, I had migrated that logic into Python, codifying every heuristic and analysis step I’d perfected over the years. While this version was excellent at systematic detection, it hit a ceiling: it could identify what was wrong, but it lacked the human-like nuance to explain why.

To bridge that gap, I launched a 2025 weekend project integrating Claude (LLM) to analyze the structured data. Instead of me manually interpreting the results, the AI began processing SIP flows, RTP metrics, and codec negotiations to generate natural-language diagnostics. That successful weekend proof-of-concept quickly scaled through Phase 2 and Phase 3, transforming a personal script into a full-scale production tool.

**Today, S.O.N.I.C. is:**
- ✅ Your systematic VoIP analysis process automated
- ✅ Python-powered for integration and batch processing  
- ✅ AI-enhanced with detailed natural language diagnostics
- ✅ Enterprise-ready with security posture analysis (Phase 3)

This isn't a generic SIP parser. It's the systematic approach I developed through years of hands-on VoIP troubleshooting, now executable at scale.

## �🚀 Key Features

### 🤖 AI-Powered Analysis
- **Dual AI Models**: Fast structured analysis + detailed natural language insights
- **Codec-Aware Diagnostics**: Comprehensive knowledge of G.711, G.729, Opus, and iLBC codecs
- **Intelligent Issue Detection**: Automatic identification of call quality problems

### 🎵 Comprehensive Media Analysis
- **SIP-RTP Correlation**: Correlates SIP INVITE SDP payloads with actual RTP streams
- **Media Quality Metrics**: Packet loss, jitter, sequence gap analysis
- **Codec Quality Assessment**: Bandwidth usage, quality profiles, and compatibility checks

### 📊 Advanced Diagnostics
- **Multi-Format Support**: pcap, pcapng file analysis with tshark and scapy fallback
- **Real-Time Quality Assessment**: Industry-standard thresholds for call quality
- **Visual Indicators**: Rich console output with emojis and progress tracking

### 🔧 Robust Architecture
- **Primary Extraction**: tshark (Wireshark CLI) for structured JSON output
- **Fallback Support**: Pure Python scapy extraction when tshark unavailable
- **Error Recovery**: Comprehensive format conversion and parsing strategies

## 📋 Prerequisites

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install tshark

# macOS
brew install wireshark

# Windows
# Download and install Wireshark from https://www.wireshark.org/
```

### Python Dependencies
```bash
pip install scapy dspy-ai pydantic ollama tqdm
```

### AI Backend (Ollama - Recommended)
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended models
ollama pull qwen2.5:0.5b    # Fast model for structured analysis
ollama pull mistral:7b       # Best available local model for detailed insights

# Optional: Other quality models
# ollama pull gemma3n        # Alternative detailed model
# ollama pull dolphin3       # Alternative detailed model
```

## 🏁 Quick Start

### Quality-Only Analysis (No API Keys Required)
```bash
# Run quality metrics without LLM analysis - completely offline
python3 sonic.py --file capture.pcapng --quality-only --save_file TEST_CAPTURE.md

# Includes: Call quality scoring, MOS analysis, network metrics, call tracking
# NO API keys or LLM required!
```

### Basic LLM Analysis (Local Ollama)
```bash
# Analyze with local mistral:7b (best available)
python3 sonic.py --file capture.pcapng --model detailed --save_file TEST_CAPTURE.md

# Fast analysis with qwen2.5:0.5b
python3 sonic.py --file capture.pcapng --model fast --save_file TEST_CAPTURE.md

# Combined analysis (fast + detailed)
python3 sonic.py --file capture.pcapng --model combined --save_file TEST_CAPTURE.md
```

**Note**: All reports must be saved as `TEST_CAPTURE.md` (enforced policy to prevent pcap-derived markdown proliferation).

## 🌐 NetClaw Integration (v3.0)

S.O.N.I.C. is now available as **MCP Server #38** in [NetClaw](https://github.com/automateyournetwork/netclaw) — an autonomous network engineering agent powered by Claude.

**Capabilities via NetClaw:**
- 📞 VoIP call quality analysis integrated with network troubleshooting
- 🔒 SIP authentication security auditing via Claude analysis
- 📊 Batch VoIP quality reports across multiple sites
- 🔗 Unified workflow: Capture → Analyze (S.O.N.I.C.) → Remediate (NetClaw)
- 🎯 Slack-native VoIP diagnostics with severity-based alerting

**Integration Guide**: See [NETCLAW_SONIC_INTEGRATION_GUIDE.md](NETCLAW_SONIC_INTEGRATION_GUIDE.md) for:
- Complete installation instructions
- MCP server configuration
- Skill file creation for NetClaw
- Standard workflows (call quality investigation, auth audit, codec assessment)
- Testing and validation procedures

**Quick NetClaw Workflow:**
```
User uploads voip-issue.pcap to Slack
    ↓
NetClaw detects SIP/RTP traffic
    ↓
Invokes S.O.N.I.C. via MCP (sonic_analyze_pcap)
    ↓
Returns: MOS score, auth grade, recommendations
    ↓
NetClaw suggests next actions: Check QoS, apply codec change, create CR
```

### Batch Processing
```bash
# Analyze multiple files in a directory with batch mode
for file in /path/to/pcap/files/*.pcap*; do
  python3 sonic.py --file "$file" --model combined --save_file "${file%.pcap*}_report.md"
done

# Test with included samples
python3 sonic.py --file samples/MG-SIP-1.pcapng --model combined --save_file TEST_CAPTURE.md
```

## 📖 Usage Examples

### 1. Combined Analysis (Recommended)
```bash
python3 sonic.py --file "samples/MG-SIP-1.pcapng" --model combined
```

**Output:**
```
🚀 Running combined analysis with top 2 models for optimal results...
  📊 Step 1: Fast structured analysis (qwen2.5:0.5b)...
  🔍 Step 2: Detailed natural language analysis (qwen2.5vl:7b)...
  🔗 Step 3: Combining insights from both models...

✅ Combined analysis completed in 23.45 seconds.

📊 Combined Diagnostic Summary:
   Analysis Method: Combined: Fast structured analysis + Detailed natural language insights
   Total calls analyzed: 3
   Overall assessment: Multiple codec negotiation detected with quality issues

🔍 Enhanced Issue Detection (Combined Analysis):
   Call 1 (abc123@example.com):
     📞 192.168.1.100 ↔ 192.168.1.200
     🎵 Audio Issues (Enhanced Detection):
       ⚠️  High packet loss detected: 5.2%
       ⚠️  G.711 codec on limited bandwidth connection
     📋 Call Flow: INVITE
     🔚 Termination: BYE
     📟 Response Codes: 180 Ringing, 200 OK
     💡 Enhanced Summary: Call completed but experienced quality issues due to network congestion
```

### 2. Codec-Specific Analysis
S.O.N.I.C. automatically detects and provides context for different audio codecs:

**G.711 (PCMU/PCMA):**
- High quality (64 kbps) but high bandwidth usage
- Monitors for network congestion and packet loss sensitivity

**G.729:**
- Low bandwidth (8 kbps) but sensitive to packet loss
- Checks for licensing compliance and implementation quality

**Opus:**
- Adaptive bitrate codec with excellent packet loss resilience
- Monitors dynamic payload type negotiation

**iLBC:**
- Low bitrate with packet loss resistance
- Checks compatibility with modern VoIP systems

## 🔍 Top 10 SIP Issues Analyzed by S.O.N.I.C.

S.O.N.I.C. is designed to detect and analyze the most common SIP/VoIP problems encountered in real-world deployments. This list serves as our diagnostic coverage tracking:

### 1. 🎵 Poor Call Quality
**Symptoms**: Choppy audio, muffled speech, static, distortion, garbled voice  
**S.O.N.I.C. Detection**: 
- RTP packet loss analysis (>1% threshold detection)
- Jitter measurement and assessment (>20ms problematic threshold)
- Codec quality profiling and bandwidth utilization analysis
- Sequence gap detection in RTP streams

### 2. 📞 Dropped Calls  
**Symptoms**: Calls suddenly disconnect during conversation  
**S.O.N.I.C. Detection**:
- SIP BYE message analysis and premature termination detection
- Response code tracking (4xx, 5xx error responses)
- Call duration indicators and early termination patterns
- Session timeout and keepalive failure analysis

### 3. 🔇 One-Way or No Audio
**Symptoms**: Audio flows in only one direction or no audio at all  
**S.O.N.I.C. Detection**:
- SDP media description analysis (`c=IN IP4`, `m=audio` parsing)
- RTP stream correlation with SIP INVITE negotiation
- Asymmetric RTP flow detection
- Media port and IP address validation

### 4. 🔊 Echo or Feedback  
**Symptoms**: Hearing your own voice, distracting echoes, audio loops  
**S.O.N.I.C. Detection**:
- RTP timestamp analysis for echo detection patterns
- Bidirectional audio flow timing correlation
- Codec-specific echo cancellation assessment
- Latency measurements that contribute to echo

### 5. 🚫 Registration Failures
**Symptoms**: SIP devices unable to register with server  
**S.O.N.I.C. Detection**:
- SIP REGISTER message analysis and response codes
- Authentication challenge (401 Unauthorized) tracking
- Credential and realm validation in SIP headers
- Registration refresh and expiration monitoring

### 6. 🛡️ NAT and Firewall Issues
**Symptoms**: Connection problems behind routers, one-way audio  
**S.O.N.I.C. Detection**:
- Private vs public IP address analysis in SIP headers
- Via header inspection for NAT traversal problems
- RTP port range analysis and accessibility assessment
- Contact header rewriting detection

### 7. 🎛️ Codec Mismatches
**Symptoms**: Garbled audio, distorted speech, no audio due to incompatibility  
**S.O.N.I.C. Detection**:
- SDP codec negotiation analysis (payload type mapping)
- Multi-codec environment compatibility assessment
- Dynamic payload type validation (96-127 range)
- Transcoding requirement identification

### 8. 🌐 Network Issues (Congestion, Latency, Packet Loss)
**Symptoms**: Degraded voice quality, conversation delays, missing audio  
**S.O.N.I.C. Detection**:
- **Network Congestion**: Peak usage pattern analysis, jitter buffer assessment
- **Latency**: RTP timestamp analysis and delay calculation
- **Packet Loss**: RTP sequence number gap detection, loss percentage calculation
- Quality threshold monitoring with industry standards

### 9. 🔧 Interoperability and Compatibility Problems  
**Symptoms**: Issues between different vendor equipment and software  
**S.O.N.I.C. Detection**:
- User-Agent header analysis for vendor identification
- SIP protocol variant detection and compliance checking
- Codec support matrix analysis between endpoints
- Signaling method compatibility assessment

### 10. 🔒 Security Vulnerabilities
**Symptoms**: Unauthorized access, call interception, service disruption  
**S.O.N.I.C. Detection**:
- **Eavesdropping**: Unencrypted RTP stream identification
- **Spoofing**: Caller-ID and From header validation
- **DoS Attacks**: Abnormal call pattern and flood detection
- **Toll Fraud**: Unauthorized destination analysis and call pattern anomalies

### 📊 Coverage Tracking

S.O.N.I.C.'s current diagnostic coverage:

| Issue Category | Detection Level | Analysis Depth | RTP Correlation |
|----------------|----------------|----------------|-----------------|
| Poor Call Quality | ✅ Advanced | 🎵 RTP Quality Metrics | ✅ Full |
| Dropped Calls | ✅ Advanced | 📋 SIP Flow Analysis | ✅ Full |
| One-Way/No Audio | ✅ Advanced | 🔗 SDP-RTP Correlation | ✅ Full |
| Echo/Feedback | 🔄 In Progress | ⏱️ Timing Analysis | ✅ Full |
| Registration Failures | ✅ Advanced | 🔐 Auth Analysis | ➖ N/A |
| NAT/Firewall Issues | ✅ Advanced | 🌐 IP Analysis | ✅ Full |
| Codec Mismatches | ✅ Advanced | 🎛️ Codec Intelligence | ✅ Full |
| Network Issues | ✅ Advanced | 📈 Quality Metrics | ✅ Full |
| Interoperability | ✅ Basic | 🔧 Vendor Analysis | ➖ Partial |
| Security Issues | ✅ Implemented | 🔒 Security Analysis + 📊 Reporting | ➖ N/A |

**Legend**: ✅ Implemented | 🔄 In Progress | ➖ Limited/Not Applicable

This comprehensive issue tracking ensures S.O.N.I.C. continues to evolve and address the most critical VoIP diagnostic needs.
````markdown
## 🏗️ Architecture

### Data Extraction Pipeline
```
PCAP File → tshark JSON → SIP/RTP Correlation → Codec Enrichment → AI Analysis
     ↓
   scapy fallback (if tshark unavailable)
```

### AI Analysis Workflow
1. **Fast Model (qwen2.5:0.5b)**: Provides structured JSON output with reliable format compliance
2. **Detailed Model (qwen2.5vl:7b)**: Generates comprehensive natural language insights
3. **Result Combination**: Merges structured data with detailed analysis for optimal accuracy

### RTP-SDP Correlation Process
1. Parse SIP INVITE messages to extract SDP payloads
2. Extract connection info (`c=IN IP4 <ip>`) and media descriptions (`m=audio <port>`)
3. Correlate RTP streams using IP addresses and ports from SDP
4. Analyze RTP quality metrics (jitter, packet loss, sequence gaps)
5. Provide comprehensive media session diagnostics

## 📊 Quality Metrics & Thresholds

### Packet Loss Assessment
- **<1%**: Excellent call quality
- **1-3%**: Good quality, minimal impact
- **>5%**: Poor quality, noticeable degradation

### Jitter Analysis
- **<20ms**: Excellent quality
- **20-50ms**: Acceptable quality
- **>50ms**: Problematic, may cause audio issues

### Codec-Specific Monitoring
- **G.711**: Monitor for network congestion due to high bandwidth
- **G.729**: Watch for packet loss sensitivity and implementation quality
- **Opus**: Check dynamic bitrate adaptation and configuration compatibility
- **iLBC**: Verify compatibility and packet loss recovery

## � Known Limitations & Roadmap

S.O.N.I.C. provides comprehensive VoIP diagnostics for the most common real-world scenarios. The following areas represent the next evolution toward even deeper enterprise analysis:

### Current Gaps (Planned for Future Releases)

**DTMF Analysis**
- ❌ Deep DTMF negotiation analysis (payload type validation, RFC 4733 edge cases)
- 📋 Tracks basic RFC 4733 support; full DTMF tone detection not yet implemented

**Echo & Feedback**
- 🔄 In progress - Basic detection infrastructure exists
- 📋 Detailed echo cancellation quality assessment planned
- 📋 Echo pattern fingerprinting not yet available

**Media Topology**
- ❌ Media forking detection
- ❌ Conferencing topology awareness
- ❌ Cascading media transformations

**SIP Trunk Interoperability**
- ❌ CUBE (Cisco Unified Border Element) hairpinning scenarios
- ❌ SRTP negotiation failure edge cases
- ❌ Vendor-specific SIP dialect conflicts (Avaya, Nortel, older systems)

**Offer/Answer Negotiation**
- ❌ Early offer vs delayed offer detection
- ❌ Reinvite flow analysis for media stream changes
- ❌ Subsequent offer complexity tracking

**Transcoding Analysis**
- ❌ Limited transcoding path analysis
- 📋 Basic codec mismatch identification exists
- 📋 Detailed transcoding latency impact not yet modeled

**Fax & Special Media**
- ❌ No T.38 fax relay diagnostics
- ❌ MSRP (Instant Messaging) not analyzed
- ❌ Video stream quality metrics

### Why These Matter

These advanced features separate enterprise-grade troubleshooting from foundational analysis. They're valuable for:
- Complex enterprise deployments with multi-vendor environments  
- Legacy system migrations and interoperability testing
- Advanced network engineering validation

S.O.N.I.C. prioritizes the **most common 80% of real-world VoIP issues** where you'll have the fastest ROI. The roadmap items address the remaining specialized edge cases.

## �🔧 Configuration

### Environment Variables
```bash
# Optional: Configure Ollama endpoint
export OLLAMA_HOST="localhost:11434"

# Optional: Enable debug logging
export SONIC_DEBUG=1
```

### Model Selection
```bash
# Available analysis modes:
--model combined    # Recommended: Both models with combined insights
--model fast        # Quick structured analysis (qwen2.5:0.5b)
--model detailed    # Comprehensive analysis (qwen2.5vl:7b)
--model all         # Run both models separately for comparison
```

## 🔌 Multi-Provider LLM Support

S.O.N.I.C. supports multiple LLM providers for analysis. **Local Ollama is recommended** for privacy and zero cost. Cloud providers are optional for specific needs.

### Supported Providers

| Provider | Models | Cost | Setup |
|----------|--------|------|-------|
| **Ollama** (default) | mistral:7b, qwen2.5:0.5b | Free | Local installation |
| **Anthropic** (optional) | Claude 3.5 Haiku, Sonnet | ~$0.01-0.03/call | API key required |
| **OpenAI** (optional) | GPT-4o-mini, GPT-4o | ~$0.01-0.05/call | API key required |
| **Azure** (optional) | GPT models via Azure | Varies | Azure OpenAI setup |
| **None** (quality-only) | N/A - no LLM | Free | Use --quality-only flag |

### Configuration Methods

**Recommended: Local Ollama (No API Keys)**
```bash
# Install Ollama and pull models (see above)
# Run with default local provider
python3 sonic.py --file capture.pcapng --model detailed --save_file TEST_CAPTURE.md
```

**Optional: Cloud Providers**
**Optional: Cloud Providers**
```bash
# Option 1: Environment Variables
export SONIC_LLM_PROVIDER=anthropic  # or openai, azure
export ANTHROPIC_API_KEY=sk-ant-api03-...
# OR
export OPENAI_API_KEY=sk-...

# Option 2: Command Line
python3 sonic.py --file capture.pcapng --provider anthropic --save_file TEST_CAPTURE.md
python3 sonic.py --file capture.pcapng --provider openai --save_file TEST_CAPTURE.md

# Option 3: Local OpenAI-compatible endpoint
export OPENAI_BASE_URL=http://localhost:8000/v1
python3 sonic.py --file capture.pcapng --provider openai --save_file TEST_CAPTURE.md
```

### Advanced Options

```bash
# Override model name for a provider
python3 sonic.py --file capture.pcapng --provider ollama --model-name "llama3:8b"

# Pass API key directly (use with caution)
python3 sonic.py --file capture.pcapng --provider openai --api-key sk-...
```

## 🤖 MCP Integration

S.O.N.I.C. provides a Model Context Protocol (MCP) server for seamless integration with AI assistants like Claude Desktop, enabling you to analyze VoIP captures through natural language conversation.

### Supported AI Assistants

- **Claude Desktop** - Anthropic's desktop application
- **Cline** - VSCode AI coding and analysis assistant
- **Any MCP-compatible client** - Custom integrations

### Quick Setup for Claude Desktop

1. **Install FastMCP**:
   ```bash
   pip install fastmcp
   ```

2. **Configure Claude Desktop**:
   
   Edit your Claude configuration:
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`
   - **Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   
   Add the S.O.N.I.C. server:
   ```json
   {
     "mcpServers": {
       "sonic": {
         "command": "python3",
         "args": ["/absolute/path/to/sonic/mcp_server.py"],
         "env": {
           "SONIC_LLM_PROVIDER": "ollama"
         }
       }
     }
   }
   ```
   
   **Optional**: Use cloud provider by adding API key to `env`:
   ```json
         "env": {
           "SONIC_LLM_PROVIDER": "anthropic",
           "ANTHROPIC_API_KEY": "your-api-key-here"
         }
   ```
   
   Replace `/absolute/path/to/sonic/mcp_server.py` with your actual path.

3. **Restart Claude Desktop**

4. **Start Using**:
   - "Analyze the pcap file at /path/to/capture.pcapng"
   - "Do a quick quality check on /home/user/call.pcapng"
   - "What LLM providers does S.O.N.I.C. support?"

### Available MCP Tools

#### `analyze_pcap`
Full VoIP analysis with AI-powered diagnostics.

**Parameters**:
- `file_path` (required): Absolute path to pcap/pcapng file
- `provider` (optional): LLM provider (ollama/anthropic/openai/azure)
- `model` (optional): Analysis mode (fast/detailed/combined)
- `enable_quality` (optional): Include quality scoring (default: true)
- `enable_mos` (optional): Include MOS analysis (default: true)

**Example**:
```
Claude: Analyze /home/user/voip_capture.pcapng using Claude for detailed insights
```

#### `quick_quality_check`
Fast quality metrics without LLM inference.

**Parameters**:
- `file_path` (required): Absolute path to pcap file

**Example**:
```
Claude: Do a quick quality check on /tmp/call.pcapng
```

#### `list_llm_providers`
Show available providers and current configuration.

**Example**:
```
Claude: What LLM providers does S.O.N.I.C. support?
```

### Setup for Cline (VSCode)

1. Install the Cline extension in VSCode
2. Open Cline settings
3. Add MCP server:
   - Command: `python3`
   - Args: `/path/to/sonic/mcp_server.py`
   - Environment variables as needed
4. Restart VSCode

### Testing MCP Server

Run the server standalone to verify it starts:
```bash
python3 mcp_server.py
```

The server will start and wait for MCP client connections.

## 📄 Output Formats

S.O.N.I.C. supports multiple output formats via command-line options:

### Full Diagnostic Report (Default)
```bash
python3 sonic.py --file capture.pcapng --save_file report.md
```
Outputs: Diagnostic summary, call analysis, endpoint analysis, quality metrics, MOS analysis, auth security posture

### Quality Metrics Only (No LLM)
```bash
python3 sonic.py --file capture.pcapng --quality-only --save_file report.md
```
Outputs: Call quality score, MOS grades, network metrics (jitter, packet loss), auth security posture (if REGISTER present)

### Console Output
```bash
python3 sonic.py --file capture.pcapng --model combined
```
Displays formatted analysis directly to terminal with emojis and progress indicators

## 🐛 Troubleshooting

### Common Issues

**"No SIP data found in capture"**
- Verify the capture contains SIP traffic on port 5060
- Check that tshark is properly installed
- Try with scapy fallback if tshark issues persist

**"AI model not found"**
- Ensure Ollama is running: `ollama serve`
- Pull required models: `ollama pull qwen2.5:0.5b`
- Check Ollama is accessible: `curl http://localhost:11434/api/tags`

**"RTP streams not correlated"**
- Verify capture includes complete SIP INVITE messages with SDP
- Check that RTP streams use ports defined in SDP media descriptions
- Ensure capture timeframe includes both signaling and media

### Debug Mode
```bash
# Enable verbose output for troubleshooting
python3 sonic.py --file capture.pcapng --model combined --verbose
```

## 🧪 Testing

Validate S.O.N.I.C. with sample VoIP captures:

```bash
# Test with included sample captures
python3 sonic.py --file samples/MG-SIP-1.pcapng --quality-only

# Run detailed analysis
python3 sonic.py --file samples/MG-SIP-1.pcapng --model combined --save_file test_report.md
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/zombat/sonic.git
cd sonic
pip install -r requirements.txt
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Wireshark](https://www.wireshark.org/) for the powerful tshark CLI
- [DSPy](https://github.com/stanfordnlp/dspy) for the AI framework
- [Ollama](https://ollama.com/) for local AI model hosting
- [Scapy](https://scapy.net/) for Python packet manipulation

## 📧 Support

For support, bug reports, or feature requests, please open an issue on GitHub or contact the maintainer.

---

**Author**: Raymond A Rizzo | Zombat  
**Version**: 3.0 (NetClaw MCP Integration + Phase 3 Auth Reporting)  
**Last Updated**: March 4, 2026  
**Project**: S.O.N.I.C. - SIP Observation and Network Inspection Console
