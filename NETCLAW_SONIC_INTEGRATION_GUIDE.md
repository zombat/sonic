# **NetClaw + S.O.N.I.C. Integration Guide**

**Purpose**: Integrate S.O.N.I.C. VoIP Analyzer as MCP Server #38 in NetClaw  
**Target Audience**: Human engineers or AI coding agents  
**Complexity**: Moderate (60-90 minutes for full integration)  
**Prerequisites**: Working NetClaw installation, Python 3.10+, tshark  
**Version**: 1.0  
**Date**: March 4, 2026

---

## **Executive Summary**

This guide adds **S.O.N.I.C. (SIP Observation and Network Inspection Console)** as an MCP server to NetClaw, enabling CCIE-level VoIP/UC analysis alongside NetClaw's existing packet-analysis skill (Packet Buddy).

**What S.O.N.I.C. Adds:**
- 🎵 **VoIP-specific deep analysis**: SIP/RTP call quality, MOS scoring, jitter, codec assessment
- 🔒 **SIP authentication security**: RFC 3261/2617/3665 compliant auth extraction with security posture grading (A-F)
- 📊 **Advanced diagnostics**: Registration failures, 401/407 challenge tracking, credential validation, quality scoring penalties
- 🔐 **Security reporting**: Realm/server mapping, challenge/response sequence diagrams (ASCII + Mermaid), upgrade recommendations (MD5→SHA-256)
- ⚡ **Fast quality-only mode**: No LLM required for quick MOS/quality checks

**Integration Approach:**
1. Clone S.O.N.I.C. to `netclaw/mcp-servers/sonic-voip-analyzer/`
2. Add installation step to NetClaw's `install.sh`
3. Create skill file: `workspace/skills/sonic-voip-analysis/SKILL.md`
4. Add MCP server entry to OpenClaw configuration
5. Test with VoIP pcap samples

---

## **Phase 1: Installation**

### **Step 1.1: Clone S.O.N.I.C. Repository**

**Location**: Add to NetClaw's `scripts/install.sh` after Packet Buddy MCP installation (step 24)

```bash
# Step 38: Install S.O.N.I.C. VoIP Analyzer MCP
echo "📞 Installing S.O.N.I.C. VoIP Analyzer MCP..."
cd "${MCP_DIR}"

if [ ! -d "sonic-voip-analyzer" ]; then
    git clone https://github.com/rrizzo/sonic.git sonic-voip-analyzer
    cd sonic-voip-analyzer
    
    # Install Python dependencies
    pip3 install -r requirements.txt
    
    # Verify tshark installation (critical for VoIP analysis)
    if ! command -v tshark &> /dev/null; then
        echo "⚠️  tshark not found - installing..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y tshark
        elif command -v brew &> /dev/null; then
            brew install wireshark
        else
            echo "❌ Please install tshark manually: sudo apt-get install tshark"
            exit 1
        fi
    fi
    
    # Test S.O.N.I.C. imports
    python3 -c "
from analyzers.orchestrator import run_analysis_mode
from extractors.auth_info import extract_auth_and_registration_info
from analyzers.call_quality_scoring import CallQualityScorer
print('✅ S.O.N.I.C. modules imported successfully')
" || {
        echo "❌ S.O.N.I.C. installation failed - check dependencies"
        exit 1
    }
    
    echo "✅ S.O.N.I.C. VoIP Analyzer MCP installed"
else
    echo "✅ S.O.N.I.C. VoIP Analyzer MCP already installed"
fi

cd "${NETCLAW_DIR}"
```

**File Location**: `netclaw/scripts/install.sh` (insert after line ~800, after Packet Buddy installation)

---

### **Step 1.2: Verify Installation**

Add to the verification section at the end of `install.sh`:

```bash
# Add to MCP server verification list
"${MCP_DIR}/sonic-voip-analyzer/mcp_server.py"
```

---

## **Phase 2: Skill Creation**

### **Step 2.1: Create Skill Directory**

```bash
mkdir -p ~/.openclaw/workspace/skills/sonic-voip-analysis
```

### **Step 2.2: Create Skill File**

**File**: `~/.openclaw/workspace/skills/sonic-voip-analysis/SKILL.md`

```markdown
---
name: sonic-voip-analysis
description: "Deep VoIP analysis: SIP/RTP call quality, MOS scoring, auth security posture"
user-invocable: true
metadata:
  openclaw:
    requires:
      bins: ["python3", "tshark"]
      env: []
---

# S.O.N.I.C. VoIP Analysis

## Purpose

Perform CCIE-level VoIP/UC analysis on packet captures using S.O.N.I.C. (SIP Observation and Network Inspection Console).

**Capabilities:**
- 📞 SIP call flow analysis (INVITE/100/180/200/BYE, termination reasons)
- 🎵 RTP media quality scoring (MOS, jitter, packet loss, sequence gaps)
- 🎤 Codec assessment (G.711, G.729, Opus, iLBC bandwidth/quality)
- 🔒 SIP authentication security auditing (RFC 3261/2617/3665 compliant)
- 📊 Security posture grading (A+ to F based on algorithm strength, qop, REGISTER success)
- 🔐 Auth diagnostics (registration failures, 401/407 tracking, credential validation)
- 📈 Upgrade recommendations (MD5→SHA-256, missing qop, cascading 407s)

**Differentiator from Packet Buddy:**
- Packet Buddy: General L2-L7 packet analysis (conversations, DNS, HTTP, expert info)
- S.O.N.I.C.: VoIP-specific diagnostics with call quality scoring, authentication security posture, and UC troubleshooting expertise

---

## MCP Tools

### 1. sonic_analyze_pcap
**Purpose**: Full VoIP analysis with AI-powered diagnostics

**Arguments:**
- `file_path` (required): Absolute path to pcap/pcapng file
- `provider` (optional): LLM provider (ollama/anthropic/openai/azure) - default: ollama
- `model` (optional): Analysis mode (fast/detailed/combined) - default: combined
- `enable_quality` (optional): Include quality scoring - default: true
- `enable_mos` (optional): Include MOS analysis - default: true

**Returns**: JSON with diagnostic report, quality scores, auth security posture, recommendations

**When to Use**: Full VoIP troubleshooting with root cause analysis and upgrade recommendations

---

### 2. sonic_quick_quality_check
**Purpose**: Fast quality-only analysis without LLM (no API keys required)

**Arguments:**
- `file_path` (required): Absolute path to pcap/pcapng file

**Returns**: JSON with quality score, grade, MOS analysis, network metrics, auth security posture

**When to Use**: Quick call quality assessment or when LLM provider unavailable

---

### 3. sonic_list_llm_providers
**Purpose**: List available LLM providers and current configuration

**Arguments**: None

**Returns**: JSON with provider list, model mappings, API key status

**When to Use**: Verify S.O.N.I.C. LLM configuration before analysis

---

### 4. sonic_analyze_batch_pcaps
**Purpose**: Batch analyze multiple VoIP captures

**Arguments:**
- `directory` (required): Path to directory containing pcap files
- `provider` (optional): LLM provider - default: anthropic
- `model` (optional): Analysis mode (fast/detailed) - default: fast
- `mode` (optional): Processing mode (sequential/parallel) - default: sequential

**Returns**: Batch results with per-file analysis and aggregate metrics

**When to Use**: Analyze multiple call recordings or historical UC issues

---

### 5. sonic_analyze_pcap_partial_streaming
**Purpose**: Returns quality/MOS immediately, streams LLM analysis after

**Arguments:**
- `file_path` (required): Absolute path to pcap file
- `provider` (optional): LLM provider (anthropic/openai/azure) - default: anthropic

**Returns**: Complete analysis {quality, mos, llm_analysis, timing}

**When to Use**: Get fast quality insight while detailed LLM analysis runs

---

## Standard Workflows

### VoIP Call Quality Investigation

**Scenario**: "User reports choppy audio on extension 2045"

```
Workflow:
1. Identify call:
   - pyats-troubleshoot: check interface errors, bandwidth utilization
   - catc-client-ops: if wireless, check WiFi signal quality
   
2. Capture traffic:
   - cml-packet-capture: if in testbed, capture on router/gateway link
   - User uploads pcap to Slack: NetClaw saves locally
   - Kubeshark: if K8s UC infrastructure, export_pcap for SIP pods
   
3. Analyze with S.O.N.I.C.:
   - sonic_analyze_pcap(file_path, provider="anthropic", model="combined")
   - Returns: MOS score, jitter, packet loss, codec quality, call flow
   
4. Correlate with network:
   - If MOS < 3.5 and jitter > 30ms: Check QoS policies via pyats-network
   - If packet loss > 1%: aws-network-ops (VPC flow logs) or prometheus-monitoring (interface drops)
   
5. Report findings:
   - msgraph-teams: Post VoIP analysis to #voice-operations
   - github-ops: Create issue if codec/config problem
   - GAIT: Full session audit
```

---

### SIP Authentication Security Audit

**Scenario**: "Audit SIP trunk security posture across all sites"

```
Workflow:
1. Collect captures:
   - CML labs: cml-packet-capture (SIP trunk filter: "udp port 5060")
   - Production: Provide previously captured trunk pcaps
   
2. Batch analyze authentication:
   - sonic_analyze_batch_pcaps(directory="/path/to/captures", mode="parallel")
   - Returns: Auth security grades per site (A-F), weak algorithm detection
   
3. Identify risks:
   - Grade D/F sites: MD5 algorithm without qop protection
   - Failed REGISTER attempts: Credential validation issues
   - Cascading 407s: Server/client auth loop problems
   
4. Generate recommendations:
   - S.O.N.I.C. provides: MD5→SHA-256 upgrade paths, qop=auth implementation
   - Cross-reference: fmc-firewall-ops (does SIP ALG interfere?)
   
5. Remediation with change control:
   - servicenow-change-workflow: CR for trunk config changes
   - pyats-config-mgmt: Apply SIP auth hardening to gateways
   - sonic_analyze_pcap: Re-test with new capture to verify Grade A/A+
   
6. Document:
   - msgraph-files: Upload Mermaid sequence diagrams to SharePoint
   - github-ops: Commit updated trunk configs
   - GAIT: Security audit trail
```

---

### Codec Quality Assessment

**Scenario**: "Why do calls to the branch office sound poor?"

```
Workflow:
1. Capture during active call:
   - cml-packet-capture: If lab environment
   - meraki-wireless-ops: Check WiFi signal quality if softphones
   - User provides production pcap
   
2. Fast quality check:
   - sonic_quick_quality_check(file_path) — NO LLM required
   - Returns: Codec type, bandwidth usage, MOS score, network metrics
   
3. Analyze codec appropriateness:
   - G.711 (64 kbps) on WAN link with < 100 kbps available: ❌ Mismatch
   - G.729 (8 kbps) with > 1% packet loss: ❌ Sensitive codec
   - Opus (adaptive): ✅ Ideal for variable bandwidth
   
4. Network correlation:
   - prometheus-monitoring: Interface traffic rate on WAN link
   - aws-cost-ops: If AWS transit, check NAT GW packet drop metrics
   - sdwan-ops: BFD tunnel health, jitter measurements
   
5. Recommendations:
   - S.O.N.I.C. recommends: Opus codec for adaptive quality
   - pyats-config-mgmt: Apply codec preference changes to CUBE/gateway
   - ServiceNow CR: Document codec migration
   
6. Validate:
   - Repeat capture after change
   - sonic_quick_quality_check: Verify MOS improvement
   - GAIT: Track before/after quality metrics
```

---

### CML Lab VoIP Testing

**Scenario**: "Build a SIP trunk lab and validate call quality"

```
Workflow:
1. Build topology:
   - cml-lab-lifecycle: create_lab("SIP Trunk Test")
   - cml-topology-builder: Add CUBE gateways, UC servers, IP phones
   - cml-node-operations: Apply SIP trunk configs with auth settings
   
2. Generate test traffic:
   - Start lab, initiate test calls
   - cml-packet-capture: capture on trunk link (filter "udp port 5060 or rtp")
   
3. VoIP analysis:
   - sonic_analyze_pcap(file_path, provider="anthropic", model="combined")
   - Verify: MOS > 4.0, auth security Grade A+, successful REGISTER
   
4. Inject problems:
   - cml-topology-builder: Add link latency (100ms), packet loss (2%)
   - Re-run test calls
   - sonic_analyze_pcap: Confirm MOS degradation detection
   
5. Validate monitoring:
   - prometheus-monitoring: Prometheus scraping RTP metrics from lab
   - grafana-observability: Dashboard showing MOS trends
   
6. Export validated config:
   - cml-lab-lifecycle: export_lab as YAML
   - github-ops: Commit lab topology + S.O.N.I.C. baseline results
   - GAIT: Lab validation audit
```

---

## Integration with Existing Workflows

### Packet Buddy → S.O.N.I.C. Handoff

```
User uploads suspicious-call.pcap to Slack
↓
1. packet-analysis (Packet Buddy):
   - pcap_protocol_hierarchy: "85% UDP, SIP detected"
   - pcap_conversations: Top talkers (PBX IP, phone IPs)
   - pcap_expert_info: "Out-of-Order segments, Fast Retransmissions"
   
2. Determine if VoIP-specific analysis needed:
   - If SIP/RTP present → Hand off to sonic-voip-analysis
   - If HTTP/DNS only → Stay with Packet Buddy
   
3. sonic_analyze_pcap:
   - Deep SIP call flow analysis
   - RTP jitter/MOS scoring
   - Auth security posture
   - Root cause: "G.729 codec on congested link → MOS 2.1 (Poor)"
   
4. Remediation via NetClaw:
   - pyats-network: Check WAN interface bandwidth
   - pyats-config-mgmt: Apply QoS policy changes
   - ServiceNow CR: Document codec/QoS remediation
```

---

## Phase 3: MCP Server Configuration

### **Step 3.1: Add to OpenClaw mcp.json Stub**

NetClaw doesn't ship a pre-configured `mcp.json` (user configures via `openclaw configure`), but for documentation, the MCP server entry would be:

**Location**: `~/.openclaw/config/mcp.json` (or user's OpenClaw config)

```json
{
  "mcpServers": {
    "sonic-voip": {
      "command": "python3",
      "args": ["${HOME}/.openclaw/mcp-servers/sonic-voip-analyzer/mcp_server.py"],
      "env": {
        "SONIC_LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"
      }
    }
  }
}
```

---

### **Step 3.2: Alternative - MCP Call Script Pattern**

NetClaw invokes MCP tools via `scripts/mcp-call.py`:

```bash
python3 scripts/mcp-call.py \
    "python3 mcp-servers/sonic-voip-analyzer/mcp_server.py" \
    sonic_analyze_pcap \
    '{"file_path": "/path/to/capture.pcap", "provider": "anthropic", "model": "combined"}'
```

---

## Phase 4: Environment Configuration

### **Step 4.1: Add S.O.N.I.C. Environment Variables**

**NetClaw `.env` additions** (optional - S.O.N.I.C. works with Ollama by default):

```bash
# S.O.N.I.C. VoIP Analyzer Configuration
SONIC_LLM_PROVIDER=anthropic    # or: ollama, openai, azure
ANTHROPIC_API_KEY=sk-ant-...    # If using Anthropic
OPENAI_API_KEY=sk-...           # If using OpenAI
```

---

## Phase 5: Testing

### **Step 5.1: Unit Test S.O.N.I.C. MCP Server**

```bash
cd netclaw/mcp-servers/sonic-voip-analyzer

# Test 1: Verify imports
python3 -c "
from analyzers.orchestrator import run_analysis_mode
from extractors.auth_info import extract_auth_and_registration_info
from analyzers.call_quality_scoring import CallQualityScorer
print('✅ S.O.N.I.C. imports OK')
"

# Test 2: MCP server starts
timeout 5 python3 mcp_server.py &
PID=$!
sleep 2
if ps -p $PID > /dev/null; then
    echo "✅ MCP server starts successfully"
    kill $PID
else
    echo "❌ MCP server failed to start"
fi

# Test 3: Quick quality check (no LLM)
cd samples
python3 ../sonic.py --file MG-SIP-1.pcapng --quality-only --save_file TEST_CAPTURE.md
if [ -f "TEST_CAPTURE.md" ]; then
    echo "✅ Quality-only analysis works"
    rm TEST_CAPTURE.md
else
    echo "❌ Quality-only analysis failed"
fi
```

---

### **Step 5.2: Integration Test via NetClaw**

**Test Scenario**: NetClaw agent invokes S.O.N.I.C. via MCP

```bash
cd netclaw

# Test via mcp-call.py
python3 scripts/mcp-call.py \
    "python3 mcp-servers/sonic-voip-analyzer/mcp_server.py" \
    list_llm_providers \
    '{}'

# Expected output: JSON with provider list

# Test with sample pcap
python3 scripts/mcp-call.py \
    "python3 mcp-servers/sonic-voip-analyzer/mcp_server.py" \
    quick_quality_check \
    "{\"file_path\": \"$(pwd)/mcp-servers/sonic-voip-analyzer/samples/MG-SIP-1.pcapng\"}"

# Expected output: JSON with quality scores and MOS analysis
```

---

## Phase 6: Documentation Updates

### **Update NetClaw README.md**

**Add to MCP Servers table (after Packet Buddy #13):**

| # | Name | Repository | Transport | Capabilities |
|---|------|------------|-----------|--------------|
| 38 | S.O.N.I.C. VoIP | automateyournetwork/sonic | stdio (Python) | SIP/RTP call quality, MOS scoring, auth security posture, codec assessment |

**Add to Skills table:**

| Skill | MCP | Description |
|-------|-----|-------------|
| sonic-voip-analysis | S.O.N.I.C. VoIP MCP | Deep VoIP analysis — SIP call flow, RTP quality, MOS scoring, auth security grading (A-F), codec assessment, upgrade recommendations |

---

### **Add Example Conversation**

**In NetClaw README.md Example Conversations section:**

```markdown
"Analyze the VoIP quality in sip-trunk-capture.pcap"
--> sonic-voip-analysis: MOS scoring, jitter analysis, codec assessment, call flow

"Why is the call to 555-0123 choppy?"
--> sonic-voip-analysis: quick_quality_check → "G.729 on congested link, MOS 2.3 (Poor), recommend Opus codec"

"Audit SIP trunk authentication security"
--> sonic-voip-analysis: analyze_pcap → "Grade D: MD5 without qop, recommend SHA-256 upgrade"

"Batch analyze all yesterday's VoIP captures"
--> sonic-voip-analysis: analyze_batch_pcaps → aggregate quality report with per-site MOS averages
```

---

## Phase 7: AI Agent Execution Instructions

**If you are an AI coding agent implementing this integration:**

### Task Breakdown
1. **Modify `netclaw/scripts/install.sh`**:
   - Add S.O.N.I.C. installation step after Packet Buddy (step 24)
   - Clone repo, install dependencies, verify tshark
   - Add to verification list

2. **Create skill file**:
   - Path: `netclaw/workspace/skills/sonic-voip-analysis/SKILL.md`
   - Copy full skill content from Phase 2 above
   - Follow NetClaw YAML frontmatter structure

3. **Update documentation**:
   - `netclaw/README.md`: Add MCP server #38 to table
   - `netclaw/README.md`: Add sonic-voip-analysis to skills table
   - `netclaw/README.md`: Add 4 example conversations

4. **Test installation**:
   - Run modified `install.sh` in clean NetClaw environment
   - Verify S.O.N.I.C. directory created and imports work
   - Test MCP tool invocation via `mcp-call.py`

5. **Validate workflows**:
   - Create test pcap with SIP/RTP traffic (use S.O.N.I.C. samples/)
   - Simulate NetClaw agent invoking tools
   - Verify JSON output parsing and report generation

### Critical Files to Modify
| File | Action | Verification |
|------|--------|--------------|
| `scripts/install.sh` | Insert step 38 | Run install.sh, check mcp-servers/sonic-voip-analyzer/ exists |
| `workspace/skills/sonic-voip-analysis/SKILL.md` | Create new | Skill file validates with OpenClaw |
| `README.md` | Add to MCP table | Table renders correctly |
| `README.md` | Add to Skills table | Table renders correctly |
| `README.md` | Add 4 examples | Examples match NetClaw style |

### Testing Commands
```bash
# Test 1: S.O.N.I.C. installation
cd netclaw/mcp-servers/sonic-voip-analyzer
python3 -c "from mcp_server import mcp; print('✅ MCP server OK')"

# Test 2: MCP tool invocation
cd netclaw
python3 scripts/mcp-call.py \
    "python3 mcp-servers/sonic-voip-analyzer/mcp_server.py" \
    list_llm_providers \
    '{}'

# Test 3: Sample analysis
python3 scripts/mcp-call.py \
    "python3 mcp-servers/sonic-voip-analyzer/mcp_server.py" \
    quick_quality_check \
    "{\"file_path\": \"$(pwd)/mcp-servers/sonic-voip-analyzer/samples/MG-SIP-1.pcapng\"}"
```

---

## Phase 8: Integration Success Criteria

### Functional Requirements
✅ **FR-1**: NetClaw agent can invoke all 5 S.O.N.I.C. MCP tools  
✅ **FR-2**: VoIP pcaps uploaded to Slack trigger S.O.N.I.C. analysis  
✅ **FR-3**: Quality-only mode works without LLM provider  
✅ **FR-4**: Auth security grading appears in diagnostic reports  
✅ **FR-5**: Batch analysis processes multiple captures successfully  

### Quality Requirements
✅ **QR-1**: MOS scores match industry standards (< 3.5 = action required)  
✅ **QR-2**: Auth security grades align with RFC 3261/2617 recommendations  
✅ **QR-3**: Analysis completes in < 30 seconds for typical 5-minute capture  
✅ **QR-4**: Markdown reports include Mermaid sequence diagrams  

### Integration Requirements
✅ **IR-1**: Skill file follows NetClaw SKILL.md structure  
✅ **IR-2**: MCP tools invoked via NetClaw's `mcp-call.py`  
✅ **IR-3**: GAIT audit trail includes S.O.N.I.C. tool invocations  
✅ **IR-4**: ServiceNow CR gating applies to VoIP config changes  
✅ **IR-5**: Slack alerts formatted with VoIP-specific severity (MOS thresholds)  

---

## Appendix A: Sample Outputs

### S.O.N.I.C. Analysis Result (JSON)

```json
{
  "status": "success",
  "diagnostic_report": {
    "total_calls": 1,
    "summary": "Call completed successfully with excellent quality"
  },
  "quality_analysis": {
    "quality_score": 92,
    "quality_grade": "A",
    "network_quality": 95,
    "protocol_quality": 90,
    "codec_quality": 88
  },
  "mos_analysis": {
    "average_mos": 4.3,
    "mos_grade": "Good"
  },
  "auth_security_posture": {
    "grade": "A",
    "score": 90,
    "factors": ["Strong SHA-256 algorithm", "qop=auth present"],
    "recommendations": ["Maintain current security configuration"]
  }
}
```

---

### NetClaw Slack Presentation

```
🎵 S.O.N.I.C. VoIP Analysis Complete

📁 File: production-trunk-capture.pcap
⏱️  Duration: 5m 32s
📞 Calls: 3

━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 CALL QUALITY
━━━━━━━━━━━━━━━━━━━━━━━━━━
Overall Score: 78/100 (Grade: C)
MOS Average: 3.2/5.0 (Fair)

⚠️ High jitter: 42ms (threshold: 30ms)
⚠️ Packet loss: 1.5% (threshold: 1%)
🔧 Codec: G.729 (sensitive to loss)

━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 AUTH SECURITY
━━━━━━━━━━━━━━━━━━━━━━━━━━
Grade: D (Weak)

🚨 MD5 algorithm without qop
🚨 2 failed REGISTER attempts

Recommendations:
1. Upgrade to SHA-256
2. Implement qop=auth
3. Investigate REGISTER failures
```

---

## Appendix B: RFC References

- **RFC 3261**: SIP - Session Initiation Protocol
- **RFC 2617**: HTTP Authentication (DIGEST for SIP)
- **RFC 3665**: SIP Basic Call Flow Examples
- **RFC 4566**: SDP - Session Description Protocol
- **RFC 3551**: RTP Profile for Audio and Video
- **ITU-T P.800**: Methods for subjective determination of transmission quality (MOS)
- **ITU-T G.711**: PCM audio codec (μ-law/A-law)
- **ITU-T G.729**: CS-ACELP audio codec (8 kbps)

---

## Conclusion

**Integration Complexity**: Moderate (1-2 hours for complete integration)

**Key Benefits:**
1. **NetClaw gains VoIP expertise**: CCIE Collaboration-level call quality diagnostics
2. **Unified workflow**: VoIP analysis integrated with network troubleshooting
3. **Security enhancement**: SIP auth security posture auditing
4. **No operational overhead**: MCP server runs on-demand via stdio

**Next Steps After Integration:**
1. Test with production VoIP captures
2. Create Grafana dashboard for MOS tracking
3. Setup Prometheus alerts for MOS < 3.5
4. Document VoIP runbooks referencing sonic-voip-analysis skill

---

**Guide Version**: 1.0  
**Date**: March 4, 2026  
**Maintainer**: NetClaw Integration Working Group

For questions, refer to [S.O.N.I.C. README.md](README.md) or [NetClaw Project](https://github.com/automateyournetwork/netclaw).
