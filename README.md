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

### 🛰️ Network and VPN Detectors (No LLM)
- **Zero-cleartext audit**: every frame of a transport link against an allowlist, pass or fail, so one leaked GRE, BGP, OSPF or ICMP packet fails a runbook gate
- **IPsec / VPN**: IKEv1 and IKEv2 outcomes, IKEv2 proposals offered and chosen, DH group retries, NAT detection checked against the wire, DPD liveness, a diagnosis per SA, NOTIFY errors, rekeys, stale ESP SPIs, NAT-T, and an encrypted or cleartext verdict per peer pair
- **GRE / DMVPN**: GRE keys and tunnels, NHRP registrations, resolutions, redirects and error indications, hub and spoke roles, and the DMVPN Phase 3 sequence proven step by step (or the encrypted shortcut evidence when NHRP is inside ESP)
- **Routing health**: BGP (OPEN capabilities, keepalive cadence, UPDATE timing, MSS clamping, why a session went down), OSPF (mismatches, stuck EXSTART/EXCHANGE) and EIGRP adjacency checks, and a failover timeline
- **Convergence**: from an event time or the first failure sign, the delay to detection, the first UPDATE on the surviving path and traffic resuming, and whether DPD or the BGP hold timer drove it
- **Reachability**: ICMP echo loss, RTT and outage windows, ICMP errors, ARP without replies, top talkers
- See the Network and VPN Detectors section below

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
python3 sonic.py --file capture.pcapng --quality-only --save_file my_capture_report.md

# Includes: Call quality scoring, MOS analysis, network metrics, call tracking
# NO API keys or LLM required!
```

### Network / VPN Analysis (No LLM)
```bash
# Run every non-SIP detector that applies (IPsec, GRE/NHRP, BGP/OSPF/EIGRP, ICMP/ARP)
python3 sonic.py --file wan-link.pcap --network-only

# VPN detectors only, judging traffic between the hub and spoke WAN addresses, JSON on stdout
python3 sonic.py --file wan-link.pcap --network-only --detectors ipsec,gre_nhrp \
    --peers 192.0.2.1,198.51.100.2 --json

# Write the report as JSON instead of markdown
python3 sonic.py --file wan-link.pcap --network-only --save_file wan-report.json
```

The report goes to `--save_file`, or to `<capture>.network.md` when none is given. A path ending in `.json` writes the full JSON report.

### Basic LLM Analysis (Local Ollama)
```bash
# Analyze with local mistral:7b (best available)
python3 sonic.py --file capture.pcapng --model detailed --save_file my_capture_report.md

# Fast analysis with qwen2.5:0.5b
python3 sonic.py --file capture.pcapng --model fast --save_file my_capture_report.md

# Combined analysis (fast + detailed)
python3 sonic.py --file capture.pcapng --model combined --save_file my_capture_report.md
```

**Note**: `--save_file` defaults to `TEST_CAPTURE.md` when not provided. Use any filename you like for real captures (e.g. `--save_file my_capture_report.md`). `TEST_CAPTURE.md` in the repository is a sanitized sample report generated from the included sample captures.

## 🌐 Agentic Platform Integrations

S.O.N.I.C. integrates seamlessly with agentic platforms via its built-in MCP server. It was designed with this kind of pipeline-driven network automation in mind.

**Supported platforms:**
- [NetClaw](https://github.com/automateyournetwork/netclaw) / [OpenClaw](https://github.com/automateyournetwork/openclaw) — register S.O.N.I.C. as a VoIP triage tool in your agent's toolset
- **Claude Desktop / Cline** — MCP client config, analyze captures through natural language
- **Claude Code / skills-based clients**: write the S.O.N.I.C. Agent Skill with `python3 sonic.py --create-skill`

**Integration Guide**: See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for:
- How the MCP server integration works
- Step-by-step NetClaw / OpenClaw setup (4 steps)
- Skills-based client installation (`--create-skill`)
- Full MCP tool reference

**Quick NetClaw Workflow:**
```
User reports one-way audio on Chicago branch
    ↓
NetClaw routes to VoIP_Triage_Bot agent
    ↓
Agent invokes S.O.N.I.C. via MCP (analyze_pcap)
    ↓
Returns: MOS score, auth grade, NAT diagnosis
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
## 🛰️ Network and VPN Detectors

S.O.N.I.C. also reads captures that are not VoIP. The network detectors decode the packets and return structured, JSON-serializable findings. They need no LLM and no API key. Each detector reports a `status` (`ok`, `warning`, `problem` or `not_present`), a one-sentence `verdict`, and a list of `issues` with a stable `code`, a plain `message` and the Wireshark frame numbers to look at.

One call runs every detector that applies. The report lists the protocols it found (`protocols_present`), which detectors ran (`detectors_run`), every issue, and one `timeline` of events in time order. When SIP is present, the existing SIP quality scoring (the same path as `quick_quality_check`) runs unchanged and is attached under `sip`.

Extraction follows the SIP path: tshark first, scapy when tshark is missing. Both backends produce the same records and the tests hold them to identical reports. tshark is read as a stream, so memory stays flat on large captures.

### IPsec / VPN (`ipsec`)
- **IKE negotiation per IKE SA**: IKEv2 IKE_SA_INIT and IKE_AUTH, IKEv1 Main, Aggressive and Quick Mode. The outcome is one of `established`, `failed` (with the NOTIFY name, for example `NO_PROPOSAL_CHOSEN`), `no_response` (requests retransmitted with no reply), `auth_no_response`, `auth_likely_failed`, `authenticated_no_esp`, `sa_init_only`.
- **Rekeys**: CREATE_CHILD_SA exchanges and ESP SPI changes.
- **ESP flows** per SPI and direction: packets, bytes, missing sequence numbers, duplicates (possible replay), out-of-order packets, one-way ESP.
- **NAT-T**: IKE on UDP 4500 (told apart from ESP-in-UDP by the 4-byte non-ESP marker), ESP-in-UDP flows, keepalives, NAT detection payloads.
- **IKEv2 negotiation detail** (`negotiation` per SA): the proposals offered in IKE_SA_INIT and the one chosen, by name (for example `AES-GCM-16-256`, `HMAC-SHA2-512`, `ECP-256 (group 19)`), weak algorithms flagged per RFC 8247, the KE group of each attempt and any INVALID_KE_PAYLOAD retry with the group asked for, the NAT_DETECTION hashes recomputed from the addresses and ports on the wire (so a NAT between the sender and the capture point is proven, not guessed) and the move to UDP 4500, and DPD liveness checks (the SA's empty INFORMATIONAL requests: interval per sender, unanswered checks and their retransmissions).
- **Diagnosis per SA** (`diagnosis.code`): `ok`, `proposal_mismatch` (with the offer, since the responder's proposal never crosses the wire), `dh_group_mismatch`, `auth_failed`, `auth_no_reply`, `nat_t_missing`, `udp_4500_blocked`, `no_reply`, `no_esp_after_auth`, `liveness_lost`, `peer_lost_sa`.
- **IKE SA collisions** (both peers initiating at once, normal for Phase 3 shortcuts), cleartext INVALID_SPI / INVALID_IKE_SPI, and ESP on an old SPI more than 2 s after a newer SPI took over that direction (`ESP_STALE_SPI`).
- **Encryption verdict** (`encryption_verdict`): for each peer pair, every packet between the same two addresses is protected (ESP, IKE, NAT-T keepalive) or cleartext (ICMP, GRE without ESP, TCP/UDP payload, OSPF, ...). The verdict reads like `all inter-site traffic encrypted: 2 peer pair(s), 480 ESP packets, no cleartext between the same endpoints` or `cleartext seen: icmp 198.51.100.2->192.0.2.1 4 packets`. Pass `peers` to judge all traffic between a given set of addresses.

### GRE / DMVPN (`gre_nhrp`)
- GRE tunnels per outer address pair: packets, GRE keys, inner protocols, and a key that differs by direction.
- NHRP registration requests and replies, with the result (`registered`, `refused` with the CIE code, `unanswered`).
- Hub and spoke roles, inferred from who registers with whom.
- Resolution requests and replies (the NBMA address each answer maps to), Traffic Indications (the DMVPN Phase 3 redirect), Error Indications with their codes, and spoke-to-spoke tunnels.
- A `dmvpn_phase_hint`: `phase3`, `phase2_or_phase3`, `hub_and_spoke_only` or `unknown`.

### DMVPN Phase 3 sequence (`dmvpn_phase3`)
- For every flow the hub redirected: `via_hub` (data inside GRE from the spoke to the hub, and where the hub forwarded it), `redirect` (the NHRP Traffic Indication), `resolution_request`, `resolution_reply` (NBMA address and prefix) and `direct` (data straight to that NBMA address), each with frame and time, the first missing step and a diagnosis, plus timings (redirect delay, resolution round trip, time to the shortcut).
- Hub-relayed spoke-to-spoke traffic that got no redirect, NHRP resolution thrashing (requests per spoke per second, repeats for one target with no reply) and error indications.
- With tunnel protection the NHRP steps are inside ESP. Pass `hubs` (the hub NBMA addresses) and an IKE SA between two other addresses is checked as an encrypted shortcut: ESP to a hub before it, IKE_SA_INIT answered, IKE_AUTH answered, the first ESP directly between the spokes.

### Routing health (`routing`)
- **BGP** (TCP 179): TCP SYN without answer or refused with RST, OPEN details (AS, hold time, router ID, capabilities), keepalive cadence against hold/3, UPDATE timing per speaker, the TCP MSS option of each SYN and SYN-ACK (checked against `expected_mss`, for example 1360 for `ip tcp adjust-mss 1360`), the cause of each session drop (`hold_timer_expired`, `notification`, `bfd_down`, `tcp_rst`, `tcp_fin`, or `hold_timer_expired_inferred` when a peer was silent for the hold time before a bare RST/FIN), established and down transitions, UPDATE prefix counts, End-of-RIB, NOTIFICATION code and subcode decoded with a plain hint (for example Hold Timer Expired, OPEN Message Error / Bad Peer AS), gaps longer than the hold time, a peer silent at capture end, flaps.
- **OSPF** (IP 89): routers grouped per link, hello and dead intervals, network mask, area, authentication type, stub flag and DB Description MTU compared between neighbors, adjacencies stuck in EXSTART (initial DB Descriptions repeated, never answered) or EXCHANGE (a DBD sequence retransmitted, never echoed) with the cause (for example the DBD MTU mismatch), DR/BDR changes, one-way neighbors, duplicate router IDs, hello gaps past the dead interval, neighbors dropped and re-added.
- **EIGRP** (IP 88): K-values and AS compared between speakers, hold time, goodbye messages, INIT updates (adjacency starts and restarts), Queries and SIA-Queries, a speaker silent past its hold time.
- Routing protocols carried inside GRE (for example EIGRP or BGP over a DMVPN tunnel without IPsec) are analyzed on the tunnel addresses and marked `over_gre`.
- A `failover_timeline` puts these events in order, so a router failure and the reconvergence after it can be read off.

### Reachability (`reachability`) and conversations (`conversations`)
- ICMP and ICMPv6 echo matching per source and destination: sent, answered, loss percent, RTT min/avg/max, and outage windows (consecutive unanswered requests, with recovery time and duration).
- ICMP errors with decoded codes (host unreachable, port unreachable, fragmentation needed, TTL exceeded) and the destination they refer to.
- ARP requests that never got a reply, gratuitous ARP, and one address claimed by two MAC addresses.
- Protocols by packet and byte count, top conversations and top talkers.

### Zero-cleartext audit (`cleartext_audit`, run only when named)
- Every frame is matched against an allowlist; anything else is reported by protocol, category (`tunnel_without_encryption`, `routing`, `icmp`, `layer2`, `cleartext`, ...) and address pair, with frame numbers, and the audit returns `passed` true or false. An empty capture fails.
- Default allowlist `crypto` (ESP, ISAKMP on UDP 500 and 4500, NAT-T keepalives). Other tokens: `arp`, `icmp`, `routing` or `bgp`/`ospf`/`eigrp`/..., `gre`, `l2-control` (CDP, STP, LLDP, LACP, Cisco loopback keepalives), service names, `tcp:N`, `udp:N`, `proto:N`, `ethertype:0xN`, each optionally scoped to addresses: `icmp@203.0.113.1`.

### Convergence timeline (`convergence`, run only when named)
- Takes an optional `event_time` (epoch, seconds from the first frame, or ISO-8601) and `failed_peer`; otherwise it starts from the first failure sign and infers the peer.
- Failure signs: the last ESP/IKE from a peer before it went quiet, DPD left unanswered, the last BGP message from a speaker whose session dropped, a ping outage. Detection: DPD giving up, Hold Timer Expired, an inferred hold expiry, BFD Down. Reaction: the first BGP UPDATE on a session not involving the failed peer. Resumed: a ping answered again, the surviving tunnels' ESP rate taking over the failed tunnel's (heuristic), or ESP from the failed peer returning.
- Returns the deltas from the event and the driver: `bfd`, `bgp_hold_timer`, `dpd`, `explicit_close` or `undetermined`, with the reason. Without an event, a quiet period counts only when the other side kept sending into it, so idle tunnels are not mistaken for failures.

### What packets cannot show
- A verdict covers only what crossed the capture point. Capture on the underlay (WAN) link to prove encryption; a capture on the tunnel interface shows decrypted traffic.
- IKEv2 IKE_AUTH is encrypted, so `AUTHENTICATION_FAILED`, the child SA proposal, traffic selectors and identities are never visible. A PSK mismatch shows as a small encrypted IKE_AUTH response with no ESP (`auth_failed`, a heuristic) or as IKE_AUTH retransmissions with no reply (`auth_no_reply`), never as a visible hash. S.O.N.I.C. reports `established` only when ESP follows.
- DPD is recognised by size (an empty encrypted INFORMATIONAL). INVALID_SPI normally travels inside the encrypted IKE SA; only an unprotected one is read, and a stale SPI is inferred from ESP timing.
- On a protected DMVPN transport link, convergence is read from ESP rates and DPD; the BGP reaction is not visible there, and the driver is then inferred from timing against `hold_time`. An event time taken on another host's clock shifts every delta by the clock skew.
- ESP with NULL encryption cannot be told apart from encrypted ESP without the keys.
- With IPsec tunnel protection, GRE, NHRP and the routing protocols travel inside ESP and are not visible on the WAN.
- OSPFv3, IS-IS and IPv6 routing are not decoded. EIGRP speakers are grouped per link by unicast exchange or a shared /24.

### Test fixtures
`tests/fixtures/generate_fixtures.py` builds small synthetic captures (each a few KB) with fixed addresses and timestamps, so a rerun produces identical files: IKEv2 with ESP and a rekey, the same plus cleartext ICMP, NO_PROPOSAL_CHOSEN, IKE retransmitted without reply, IKEv1, NAT-T, GRE with NHRP registrations and a Phase 3 redirect, routing over GRE, a BGP session with a hold timer expiry, OSPF hello mismatch and failover, EIGRP mismatches, ICMP loss with ARP, and a minimal SIP call; plus, for the control plane detectors, IKEv2 proposals with a DH retry and DPD, four IKEv2 failure shapes, a stale SPI, one leaked packet of each kind on an encrypted link, broken and encrypted Phase 3 sequences, BGP failover with MSS options, a DPD-driven failover, and OSPF stuck in EXSTART and EXCHANGE. `test_control_plane.py` runs them on both backends (test names say `synthetic`) and checks the Pleiades lab captures when they exist on the machine.

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
| **Anthropic** (optional) | claude-haiku-5-5 (fast), claude-sonnet-5-5 (default), claude-opus-5-5 (deep) | Per token | API key from the environment or an env file |
| **OpenAI** (optional) | GPT-4o-mini, GPT-4o | ~$0.01-0.05/call | API key required |
| **Azure** (optional) | GPT models via Azure | Varies | Azure OpenAI setup |
| **None** (quality-only) | N/A - no LLM | Free | Use --quality-only flag |

### Configuration Methods

**Recommended: Local Ollama (No API Keys)**
```bash
# Install Ollama and pull models (see above)
# Run with default local provider
python3 sonic.py --file capture.pcapng --model detailed --save_file my_capture_report.md
```

### Advanced Options

```bash
# Run the analysis on one model of your choosing (one pass; not with --model all)
python3 sonic.py --file capture.pcapng --provider ollama --model-name "llama3:8b"

# The provider's most capable model (anthropic: claude-opus-5-5)
python3 sonic.py --file capture.pcapng --provider anthropic --model deep
```

### API keys: environment or a passthrough env file

S.O.N.I.C. looks for `ANTHROPIC_API_KEY` (and `OPENAI_API_KEY`, `AZURE_OPENAI_KEY`) in this order:

1. the process environment;
2. a dotenv file named by `--env-file PATH` (on `sonic.py` and `mcp_server.py`) or, without the flag, by `SONIC_ENV_FILE`.

```bash
# Keep the key in a file you control; S.O.N.I.C. reads only the key names above from it
SONIC_ENV_FILE=~/secrets/anthropic.env python3 sonic.py --file capture.pcapng --provider anthropic --model fast
python3 sonic.py --env-file ~/secrets/anthropic.env --file capture.pcapng --provider anthropic
```

The file is parsed as data (`KEY=VALUE`, optional `export`, single or double quotes, `#` comments), never through a shell, and a value is never copied into the environment, so child processes such as tshark do not inherit it. This keeps the key out of an AI assistant's context: the assistant (or an MCP client config) only ever handles the file's path.

A key never appears in anything S.O.N.I.C. prints, writes or returns: it is redacted by value (and anything shaped like `sk-ant-...` by pattern) from CLI output, log records, saved reports, every MCP tool result and the prompt sent to the LLM. `list_llm_providers` reports only whether each key is configured and where it came from (`environment` or the env file's path). There is no option that takes a key: one typed on the command line lands in shell history and the process list, so put it in the environment or in the file `--env-file` or `SONIC_ENV_FILE` names.

## 🤖 MCP Integration

S.O.N.I.C. provides a Model Context Protocol (MCP) server for seamless integration with AI assistants like Claude Desktop, enabling you to analyze VoIP captures through natural language conversation.

### Supported AI Assistants

- **Claude Desktop** - Anthropic's desktop application
- **Cline** - VSCode AI coding and analysis assistant
- **Claude Code / skills-based clients** - Write the S.O.N.I.C. Agent Skill with `python3 sonic.py --create-skill` (see Agent guidance below)
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
   
   **Optional**: use a cloud provider. Point the server at an env file holding the key, so the key itself never sits in the client config or the assistant's context:
   ```json
         "env": {
           "SONIC_LLM_PROVIDER": "anthropic",
           "SONIC_ENV_FILE": "/home/you/secrets/anthropic.env"
         }
   ```
   or pass a key the client already has through its own environment, if your client expands variables there (for example `"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"`). The environment wins over the file.

   `SONIC_LLM_PROVIDER` is the provider every LLM tool (`analyze_pcap`, `analyze_pcap_partial_streaming`, `analyze_batch_pcaps`) uses when a call does not pass `provider`; without it the default is `ollama`.
   
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

#### `analyze_network_pcap`
Deterministic analysis of any capture (no LLM): IPsec/IKE/ESP, GRE/NHRP, BGP/OSPF/EIGRP, ICMP/ARP and conversations. Start here on a capture that is not only VoIP.

**Parameters**:
- `file_path` (required): Absolute path to pcap/pcapng file
- `detectors` (optional): Subset of `ipsec`, `gre_nhrp`, `dmvpn_phase3`, `routing`, `reachability`, `conversations` (the default), plus `cleartext_audit` and `convergence` (only when named)
- `peers` (optional): IP addresses whose mutual traffic the encryption verdict judges
- `display_filter` (optional): Wireshark display filter applied first (needs tshark)
- `max_packets` (optional): Read at most this many frames
- `include_sip` (optional): Run the SIP quality scoring when SIP is present (default: true)
- `max_items` (optional): Cap on each list in the result (default: 25)
- `hubs` (optional): Hub NBMA addresses for the encrypted Phase 3 shortcut check
- `expected_mss` (optional): MSS the BGP SYNs should carry

**Example**:
```
Claude: Analyze /captures/hub-wan.pcap with analyze_network_pcap
```

#### `analyze_vpn_pcap`
Proves from packets whether inter-site traffic is encrypted and whether the IPsec and DMVPN overlay formed. Returns `encryption_verdict` (`encrypted`, `cleartext_seen`, `no_esp`, `not_present`), `verdict`, `negotiation_verdict` and `overlay_verdict` first.

Also `phase3_verdict` and `ike_diagnoses` (one diagnosis code per IKE SA).

**Parameters**: `file_path`, and optional `peers`, `display_filter`, `max_packets`, `max_items`, `hubs`

**Example**:
```
Claude: Is the traffic between 192.0.2.1 and 198.51.100.2 encrypted in /captures/hub-wan.pcap?
```

#### `analyze_routing_pcap`
BGP, OSPF and EIGRP health plus reachability. Returns the routing `verdict`, `reachability_verdict`, a `failover_timeline` and `ping_outages` first.

**Parameters**: `file_path`, and optional `display_filter`, `max_packets`, `max_items`, `expected_mss`

**Example**:
```
Claude: Did OSPF reconverge after R3 failed? Use /captures/r1-r3.pcap
```

#### `audit_cleartext_pcap`
The zero-cleartext assertion: returns `passed` (true or false), `result`, `verdict`, `frames_outside_allowlist`, `first_violation_frame`, `by_protocol` and `violations` with frame numbers.

**Parameters**: `file_path`, and optional `allow` (allowlist tokens, default `["crypto"]`), `display_filter`, `max_packets`, `max_items`

**Example**:
```
Claude: Fail the run if /captures/br1-wan.pcap carried anything but IPsec (Cisco link keepalives allowed): audit_cleartext_pcap with allow ["crypto", "l2-control"]
```

#### `analyze_convergence_pcap`
The failover timeline: `driver` (`dpd`, `bgp_hold_timer`, `bfd`, `explicit_close`, `undetermined`), `failed_peer`, `measurements` (seconds from the event to the first failure sign, detection, first UPDATE on the surviving path and traffic resuming) and an ordered `timeline` with frames.

**Parameters**: `file_path`, and optional `event_time`, `failed_peer`, `hold_time`, `silence_s`, `display_filter`, `max_packets`, `max_items`

**Example**:
```
Claude: CORE1 was stopped at 2026-10-27T19:49:30Z; how long until BR1's traffic moved? Use /captures/br1-wan.pcap
```

Each tool's description (what an MCP client shows the agent) explains its inputs, outputs, verdict values and limits, so an agent can learn the tool from the tool itself.

### Agent guidance: instructions, prompts, resources and a skill

The server teaches the agent that connects to it, so the agent does not need this README:

- **Instructions**: the MCP initialize result carries a short guide (under 2 KB): what S.O.N.I.C. answers, which tool fits which question, the order of a typical investigation, which tools call an LLM, size limits and what every tool returns.
- **Tools**: each tool has a title, annotations (all read-only; the deterministic tools are idempotent, the LLM tools are marked open world) and a description saying when to use it, what it needs, what it costs and what it returns.
- **Prompts**: `diagnose_capture`, `check_vpn_encryption`, `investigate_failover`, `diagnose_sip_call` walk the agent through a common investigation.
- **Resources**: `sonic://guide/overview` and one page per area (`mcp-tools`, `network-detectors`, `sip-rtp`, `cli`, `interpreting-results`), read only when the agent needs that area.

For skills-based clients such as Claude Code, write the same guidance as an Agent Skill:

```bash
python3 sonic.py --create-skill                 # writes .claude/skills/sonic in the current directory
python3 sonic.py --create-skill ~/.claude/skills/sonic
python3 mcp_server.py --create-skill DIR        # the same skill, from the MCP server's entry point
```

The skill uses progressive disclosure: `SKILL.md` holds the overview, the table of which tool or command answers which question, and links; `reference/` holds one file per area, loaded only when needed. The tool parameters, detectors and their issue codes, CLI options and LLM providers are read from the code when the skill is written, so it matches the installed version. Run the command again after an upgrade: it replaces only files it wrote (each carries a `written by sonic --create-skill` marker), refuses to touch a `SKILL.md` or reference file it did not write, writes each file atomically, and leaves unchanged files alone.

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

Network detector tests (no LLM, no network access; the MCP test starts the server over stdio):

```bash
python3 -m pytest -q test_network_detectors.py test_network_mcp.py

# Rebuild the fixtures (identical bytes on every run)
python3 tests/fixtures/generate_fixtures.py
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
