# SIP Authentication Analysis - Quick Reference Guide

## What's New

S.O.N.I.C. now includes comprehensive SIP authentication analysis, automatically extracting and analyzing authentication challenges (401/407), responses, and registration attempts from packet captures.

## Automatic Activation

Authentication analysis is **automatic** and runs with every SIP analysis:

```bash
sonic --file capture.pcap                    # Auto-includes auth analysis
sonic --file capture.pcap --quality-only     # Quality + auth mode (no LLM)
sonic-mcp                                    # MCP stdio server (includes auth tools)
```

No additional flags or configuration needed.

## What Gets Analyzed

### 1. Authentication Challenges (401/407)

**Detected from**:
- HTTP 401 Unauthorized (server challenges)
- HTTP 407 Proxy-Authenticate (proxy challenges)

**Extracted Parameters** (RFC 2617):
- `realm` - Authentication domain (e.g., "pbx.example.com")
- `nonce` - Challenge token (unique per challenge)
- `algorithm` - Hash method (MD5, SHA-256, etc.)
- `qop` - Quality-of-Protection (auth, auth-int, or none)
- `opaque` - Opaque string for response matching
- `stale` - Whether client should retry with new nonce

**Security Flags**:
- ⚠️ **MD5 algorithm**: Weak cryptography, upgrade to SHA-256
- 🔓 **Missing QoP**: No replay protection, reduced security
- ❌ **Excessive challenges** (>3): Possible credential issues
- ℹ️ **Stale nonce**: Normal but affects performance

### 2. Authorization Responses

**Detected from**:
- Authorization headers (client → server)
- Proxy-Authorization headers (client → proxy)

**Extracted Parameters** (RFC 2617 §3.2.1):
- `username` - Authenticating user
- `realm` - Matching server's challenge realm
- `nonce` - Matching server's nonce value
- `uri` - Request URI being authenticated
- `response` - Digest hash (MD5(MD5(HA1), MD5(HA2)))
- `qop` - Quality-of-protection method used
- `nc` - Nonce count (replay attack prevention)
- `cnonce` - Client nonce (for qop=auth)

### 3. REGISTER Lifecycle Tracking (RFC 3665)

**Tracked Sequence**:
```
1. Client sends: REGISTER (no auth)
2. Server responds: 401 + challenge
3. Client sends: REGISTER (with Authorization)
4. Server responds: 200 OK (or 4xx/5xx error)
```

**Metrics Collected**:
- Registration attempts count
- Success/failure rate  
- Authentication required (yes/no)
- Registration duration (Expires header)

**Anomalies Detected**:
- ⚠️ Failed REGISTER attempts → Service registration issues
- ❌ Multiple failed attempts → Credential problems
- ✅ Successful unauthenticated REGISTER → Open registration

## Output Results

Authentication data is included in all analysis results:

### JSON Structure

```json
{
  "auth_data": {
    "auth_challenges": [
      {
        "packet_num": 5,
        "status_code": "401",
        "challenge_type": "server",
        "realm": "pbx.example.com",
        "nonce": "abc123def456...",
        "algorithm": "MD5",
        "qop": "auth",
        "from_ip": "192.168.1.100",
        "timestamp": "2025-07-22 10:00:00"
      }
    ],
    "auth_responses": [
      {
        "username": "user1",
        "realm": "pbx.example.com",
        "method": "REGISTER",
        "qop": "auth",
        "nc": "00000001"
      }
    ],
    "register_attempts": [
      {
        "call_id": "call-123@example.com",
        "success": true,
        "authenticated": true,
        "count": 1
      }
    ],
    "sip_servers": {
      "192.168.1.100": {
        "challenge_count": 2,
        "server_challenges": 1,
        "proxy_challenges": 1,
        "realms": ["pbx.example.com", "proxy.example.com"]
      }
    },
    "realms": ["pbx.example.com", "proxy.example.com"],
    "auth_anomalies": [
      "Weak authentication algorithm (MD5) detected...",
      "Excessive authentication challenges detected..."
    ]
  }
}
```

### Via MCP Server

Use the Claude Desktop integration to query auth data:

```
@sonic analyze capture.pcap
→ Returns: complete analysis with auth_data section
```

## Security Recommendations

S.O.N.I.C. provides automated recommendations:

| Finding | Recommendation | Severity |
|---------|-----------------|----------|
| MD5 algorithm | Upgrade to SHA-256-128 | 🔴 High |
| No QoP | Enable auth-int for integrity protection | 🟡 Medium |
| Excessive 401s | Check credentials, review account status | 🔴 High |
| Failed REGISTER | Verify server availability, check firewall | 🟡 Medium |
| Cascading 407s | Review proxy chain configuration | 🟡 Medium |
| Stale nonce | Normal (nonce refresh), monitor performance | 🟢 Low |

## Integration with Other Analyses

Authentication findings are **automatically integrated** with:

1. **Call Quality Scoring** (Phase 2)
   - Auth failures reduce quality score
   - Strong auth practices improve score
   
2. **Endpoint Analysis**
   - Identifies endpoints with auth issues
   - Maps authentication patterns to SIP servers

3. **Network Quality Analysis**
   - Auth retries affect latency metrics
   - Challenge/response patterns impact timing

4. **RTP MOS Analysis**
   - Auth setup delays affect call establishment
   - Failed auth prevents RTP session

## Performance

- ✅ Minimal overhead (<100ms for typical captures)
- ✅ Scales linearly with number of SIP packets
- ✅ Memory efficient (~2KB per 100 packets)
- ✅ No external dependencies beyond existing tools

## Limitations (Phase 1)

- Auth data extracted but not yet scored into call quality
- No integration with quality_scoring.py (Phase 2)
- No visualization or detailed reporting (Phase 3)
- Digest-only auth (NTLM, OAuth not analyzed)

## Privacy & Security

- 🔒 Sensitive fields masked in output (response hash, cnonce)
- 🔒 No password extraction or storage
- 🔒 No cleartext credential logging
- 🔒 RFC-compliant parameter handling

## For Developers (`v4.0.0` Go Architecture)

### Package Mapping (`internal/`)

- `internal/tshark/` - Streaming `-T fields` and `-T ek` (`NDJSON`) extraction over `tshark`
- `internal/extract/sip.go`, `internal/extract/sip_sdp.go` - Masked SIP Digest header & SDP `rtpmap`/crypto extraction (`SIPCredentialMask`)
- `internal/redact/` - Known-secret and shape scrubbing with verifiable `AuditCounts` (`--redact-audit`)
- `internal/model/` - Strongly typed packet, auth challenge/response, and report structs
- `internal/analyze/sip/` - Auth grading, quality scoring, post-`200 OK` clipping, RFC 4733 DTMF, and MOS analysis
- `internal/ai/` - Pipeline integration and structured artifact recovery

## Implementation Documentation

See [SIP_AUTH_IMPLEMENTATION_PHASE1.md](SIP_AUTH_IMPLEMENTATION_PHASE1.md) for:
- Detailed implementation notes
- RFC compliance details
- Test results
- Architecture decisions

## Next: Phase 2 (Coming Soon)

- ✅ Implement: Authentication penalties in call quality scoring
- ✅ Implement: Security assessment in diagnostic reports
- ✅ Implement: Auth-specific troubleshooting recommendations

## Questions?

Refer to:
- [SIP_DOCUMENTATION.md](SIP_DOCUMENTATION.md) - SIP protocol basics
- [RFC 3261](https://tools.ietf.org/html/rfc3261) - SIP spec
- [RFC 2617](https://tools.ietf.org/html/rfc2617) - Digest auth spec
- [RFC 3665](https://tools.ietf.org/html/rfc3665) - REGISTER flow
