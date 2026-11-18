# S.O.N.I.C. v4.0.0 Sample Diagnostic Report (Sanitized Multi-Scenario Showcase)

**Engine**: `sonic v4.0.0` (Pure Go, zero external Go modules, `go-fast` + `tshark`)  
**PII Status**: Sanitized (RFC 5737 documentation IPv4 ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; credentials redacted via `internal/redact`)

This sample demonstrates how S.O.N.I.C. moves beyond simple SIP header dumps to deterministic root-cause diagnosis across **VoIP media**, **WAN/VPN overlays**, **routing convergence**, **cross-layer correlation**, **CI policy gates**, and **optional LLM reasoning**.

---

## CI Policy Gate & Redaction Audit (`sonic gate`)

Command run:

```bash
sonic gate --file wan_voip_cutover.pcap --allow l2-control --policy "zero-cleartext,no-weak-crypto,mos-min=3.8,max-clipping-ms=500,no-critical-issues" --redact-audit --html gate-report.html
```

| Policy Rule | Threshold / Allowlist | Verdict | Summary |
|---|---|---|---|
| `zero-cleartext` | allow=`l2-control` | FAIL | Unexpected cleartext BGP/ICMP/SIP outside encrypted tunnel peer pair (`CLEARTEXT_OUTSIDE_ALLOWLIST`) |
| `no-weak-crypto` | No IKEv1, weak TLS/SSH, or MD5 SIP Digest | PASS | IKEv2 AEAD/SHA-256 and SIP Digest `SHA-256` observed |
| `mos-min=3.8` | Min `3.8` MOS | FAIL | Worst measured RTP MOS was `2.84` (`mean=3.31`), below `3.8` |
| `max-clipping-ms=500` | Max `500 ms` post-`200 OK` | FAIL | Post-`200 OK` media delay hit `1,140 ms` before first inbound RTP packet |
| `no-critical-issues` | Zero `error` severity findings | FAIL | 3 error findings: `ESP_STALE_SPI`, `ICMP_LOSS`, `PMTU_BLACK_HOLE` |

```json
{
  "exit_code": 3,
  "passed": false,
  "violation_count": 4,
  "redact_audit": {
    "total": 4,
    "auth_headers": 2,
    "bearer_tokens": 1,
    "sdp_keys": 1
  }
}
```

---

## Scenario 1: Cross-Layer Media-to-Underlay Correlation (`--correlate-media`)

Command run (`diagnose_media_underlay` MCP tool equivalent):

```bash
sonic --file wan_voip_cutover.pcap --correlate-media --peers 203.0.113.10,203.0.113.20 --json
```

### Root-Cause Summary ("Tell Me Why")

* **Overall Status**: `problem`
* **Verdict**: One-way post-answer media clipping (`1,140 ms`) and degraded voice quality (`MOS 2.84`, `18.6 ms` jitter, `6.4%` packet loss) align directly in time with a `3.42 s` WAN underlay failover driven by IKEv2 DPD timeout (`IKE_LIVENESS_UNANSWERED`), stale outbound ESP SPI (`ESP_STALE_SPI`), and BGP route withdraw/re-convergence.

### Voice & RTP Telemetry

| Metric | Measured Value | Status / Notes |
|---|---|---|
| Offer Model | Early Offer (`INVITE` w/ SDP, `200 OK` answer) | Complete dialog (`INVITE` -> `200 OK` -> `BYE`) |
| Negotiated Codec | `PCMU (G.711 u-law, PT 0)` + `telephone-event/8000` (`PT 101`) | Dynamic SDP port `42000` decoded via `-d udp.port==42000,rtp` |
| RFC 4733 DTMF Sequence | `1234#` (5 digit bursts, `end_of_event=true` verified) | Payload type `101` matched SDP `rtpmap:101` cleanly |
| Post-`200 OK` Media Clipping | `1,140 ms` delay before first inbound RTP | Severity `warning` (`>500 ms`); caller said "hello" twice |
| RTP Loss / Jitter / MOS | `6.4%` packet loss, `18.6 ms` jitter, **Worst MOS `2.84`** | Degraded during seconds `12.04` to `15.46` of capture |

### Correlated Underlay Fault Timeline

| Capture Window (s) | Layer | Finding Code | Evidence & Link to Media |
|---|---|---|---|
| `11.82` | IPsec / IKEv2 | `IKE_LIVENESS_UNANSWERED` | Primary tunnel peer `203.0.113.10` missed 3 DPD `INFORMATIONAL` exchanges (`frames 412, 419, 427`) |
| `12.04 - 14.90` | WAN ICMP | `ICMP_LOSS` | 6 consecutive echo requests lost on primary path before backup interface took traffic |
| `12.10 - 15.22` | IPsec ESP | `ESP_STALE_SPI` | Voice endpoint kept transmitting on superseded SA SPI `0x8a04c112` during rekey (`frames 438-491`) |
| `12.18 - 15.46` | BGP + Convergence | `CONVERGENCE_NOT_SEEN` -> `3.42 s` | `WITHDRAW` followed by `UPDATE` on backup next-hop `203.0.113.20`; RTP resumed cleanly at `15.46 s` |

---

## Scenario 2: WAN, DMVPN Phase 3, Routing & Data-Plane Inspection (`--network-only`)

Command run (`analyze_network_pcap` / `analyze_vpn_pcap` MCP tool equivalent):

```bash
sonic --file branch_dmvpn_failover.pcap --network-only --peers 203.0.113.10,203.0.113.20
```

| Detector | Status | Key Code(s) | Deterministic Finding |
|---|---|---|---|
| `ipsec` | `warning` | `IKE_NAT_T_MISSING` | NAT detected on UDP `500` without peer switch to `UDP 4500`; rekey latency spiked `1.8 s` |
| `dmvpn` | `warning` | `PHASE3_NO_REDIRECT` | Spoke-to-spoke traffic transited hub `192.0.2.1` after NHRP resolution (`ResResolved`), hub sent zero NHRP Traffic Indication redirects |
| `routing` | `problem` | `BGP_MSS_NOT_CLAMPED`, `BGP_TCP_REFUSED` | BGP session on TCP `179` used `MSS 1460` over GRE+ESP (`1380 B` effective MTU); backup peer port `179` returned `RST` prior to peer bring-up |
| `path_mtu` | `problem` | `PMTU_BLACK_HOLE` | `DF=1` `1,460 B` TCP data frames retransmitted 4 times after ICMP Fragmentation Needed (`MTU 1380`) was filtered upstream |
| `tls` / `grpc` | `ok` | None | gNMI `Subscribe` RPCs negotiated TLS 1.3 (`TLS_AES_128_GCM_SHA256`), HTTP/2 clean (`grpc-status: 0`) |

---

## Scenario 3: VoIP Signaling, SIP Digest Auth & NAT Traversal (`--model combined`)

Command run:

```bash
sonic --file sip_trunk_auth_nat.pcap --model combined --quality --mos
```

### Call Flow, Codec & Security Summary

* **Call 1 (`192.0.2.25 -> 198.51.100.42`)**:
  * **Authentication**: Server challenged with `401 Unauthorized` (`realm="pbx.example.invalid"`, `algorithm=SHA-256`, `qop="auth"`); client retried with matching `nc=00000001` and reached `200 OK`. `Credential` fields emitted as `masked`.
  * **NAT Traversal Root Cause**: `INVITE` advertised private RFC 1918 SDP media address `c=IN IP4 10.20.30.15` (`m=audio 16384 RTP/AVP 0 101`) while SIP transport originated from public NAT gateway `198.51.100.42`. Remote PBX sent RTP to unreachable `10.20.30.15:16384`, producing **one-way audio** (`0` inbound RTP packets received on capture interface).

### Concrete Remediation Checklist

1. **Fix Tunnel MTU & BGP Clamping**: Set `ip tcp adjust-mss 1340` on GRE/DMVPN tunnel interfaces and allow ICMP Type 3 Code 4 (`Fragmentation Needed`) across ACLs to clear `PMTU_BLACK_HOLE`.
2. **Enable DMVPN Phase 3 Hub Redirects**: Add `ip nhrp redirect` on hub `192.0.2.1` and `ip nhrp shortcut` on spokes to eliminate hub hairpinning (`PHASE3_NO_REDIRECT`).
3. **Align NAT Traversal on SBC / PBX**: Rewrite SDP `c=` / `m=` addresses to the WAN NAT IP or enable symmetric RTP (`comedia`) so remote media targets `198.51.100.42` instead of unroutable `10.20.30.15`.
4. **Tighten IKEv2 DPD Timers**: Lower DPD interval/retries on primary peer `203.0.113.10` to cut failover convergence below `1.0 s` (`qos` MOS target `>= 3.8`).

---

*Sanitized sample report reflecting `sonic v4.0.0` deterministic + cross-layer + optional LLM diagnostic schemas (RFC 5737 test IPv4 ranges; secrets redacted).*
