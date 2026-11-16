# Go Refactor Plan for S.O.N.I.C.

## Context

S.O.N.I.C. is currently implemented in roughly 31k+ lines of Python (`analyzers/`, `extractors/`, `utils/`, `handlers/`, `models/`, `ai/`, `sonic.py`, `sonic_packet_mode.py`, `mcp_server.py`, `llm_config.py`, plus tests and Scapy fixture generators). The deterministic network, gRPC, RESTCONF, SNMP, AAA, ESP decryption, TLS audit, and SIP quality layers make up the bulk of the codebase and shell out to `tshark` for protocol dissection.

Moving S.O.N.I.C. to Go delivers a single static binary for jump boxes and CI/CD gates, cheap concurrency for multi-capture correlation, strong typing over protocol states and `tshark` fields, and native integration with the official Go ecosystem and MCP SDK.

## Principles

1. **Strangler pattern.** Python keeps working throughout the migration. Each Go package must match Python's JSON output before replacing its Python counterpart.
2. **Python is the oracle.** Synthetic `.pcap` fixtures in `tests/fixtures/` and their normalized Python outputs in `testdata/golden/` serve as golden tests. Go output is diffed against Python output in CI.
3. **`tshark` stays the dissector.** Go shells out to `tshark` and streams `-T fields` TSV rows (or PDML/JSON where needed, such as gRPC/HTTP2/protobuf and decrypted payloads). Scapy is dropped as a runtime backend; committed `.pcap` fixtures and Python generators remain for test generation.
4. **Freeze behavior during port.** Fix bugs in Python first or log them separately so parity diffs stay meaningful.
5. **Follow workspace house rules.** Adhere strictly to [house-rules.md](file:///home/noot/sonic/.agents/rules/house-rules.md) and [trifecta-triad.md](file:///home/noot/sonic/.agents/rules/trifecta-triad.md): `gofmt`, ~300-line soft cap per logic file, Google-style doc comments, custom domain types (`netip.Addr`, typed `iota` enums, pointer/presence fields for optional `tshark` values), RULE 0 representative tests with `-race` and >= 90% coverage, fuzzing on untrusted inputs, tmpfs secret hygiene, and zero em-dashes or AI attribution.

## Target Layout

```text
cmd/
  sonic/              CLI composition root (replaces sonic.py, sonic_packet_mode.py)
  sonic-mcp/          MCP stdio server (replaces mcp_server.py: 18 tools, 5 prompts, 7 resources)
internal/
  tshark/             process runner, -G fields resolution, TSV row streaming, version check
  wsconfig/           ephemeral /dev/shm tmpfs Wireshark config dir (preferences, UATs, signal/PID cleanup)
  redact/             dotenv loader and SECRET_SHAPES / known-secret redaction (from utils/credentials.py)
  model/              typed packet/flow records and report types (explicit pointers for optional tshark fields)
  extract/            network, dataplane, http2, http_messages, tls_secrets, snmp, aaa, esp, auth_info, tshark SIP
  analyze/            detector packages:
                        tlsinspect, audit, reach, qos, pathmtu, espoverhead, tcphealth,
                        ipsec, grenhrp, dmvpn, routing, convergence,
                        grpc, httpinspect, snmpinspect, aaainspect, espdecrypt,
                        correlate, timeline, sip, orchestrator
  report/             markdown and JSON formatters, plus agent_guide skill generator
  llm/                provider abstraction preserving RedactingLM secret redaction
  parity/             golden JSON comparator for Go-vs-Python diffs
tools/
  gen_golden.py       golden oracle generator over tests/fixtures/
testdata/
  golden/             normalized Python oracle JSON outputs
```

## Phases

### Phase 0: Baseline
- Build `tools/gen_golden.py` to execute Python extractors and analyzers over synthetic fixtures in `tests/fixtures/` and write deterministic JSON to `testdata/golden/`.
- Document normalization rules (hex-encoding raw payload bytes, float comparison tolerance, deterministic key sorting).
- Add a `Makefile` with `golden` and `parity` targets.
- **Exit:** Golden baseline JSON committed and Python test suite green.

### Phase 1: Foundation
- Scaffold `go.mod` (`go 1.27.0`), `Makefile`, `internal/parity`, `internal/wsconfig`, `internal/redact`, `internal/model`, `internal/tshark`, and `internal/extract`.
- Ensure `internal/tshark` handles `tshark -G fields`, `-T fields` streaming, and Wireshark 3.x vs 4.x `ip.frag_offset` unit scaling.
- Ensure `internal/wsconfig` creates `0700` dirs / `0600` files under `/dev/shm` tmpfs with orphan PID sweeping and `SIGTERM`/`SIGINT` cleanup.
- Ensure `internal/redact` matches `parse_dotenv` and every `SECRET_SHAPES` rule in `utils/credentials.py`.
- Implement `sonic dump` in `cmd/sonic` and verify 100% JSON parity against `testdata/golden/records/*.json`.
- **Exit:** All Phase 1 packages pass `go vet` and `go test -race` with >= 90% coverage and full extractor record parity.

### Phase 2: Leaf Detectors
- Pilot with `internal/analyze/tlsinspect` and `internal/analyze/audit` (`cleartext_audit`), matching `audit_cleartext_capture` JSON across all `audit_*.pcap`, `ipsec_*.pcap`, and `enc_*.pcap` golden baselines.
- Port remaining leaf detectors: `reach` (`reachability` and `conversations`), `qos`, `pathmtu` (`path_mtu`), `espoverhead` (`esp_overhead`), `tcphealth` (`tcp_health`), and certificate parsing in `tlsinspect` (`tls_inspect`).
- **Exit:** All leaf detectors match Python golden JSON on all corresponding fixtures.

### Phase 3: Protocol-State and Decryption Detectors
- Port control-plane and VPN state machines: `ipsec` (`ipsec_vpn`), `grenhrp` (`gre_nhrp`), `dmvpn` (`dmvpn_phase3`), `routing` (`routing_health`), and `convergence`.
- Port `tshark`-assisted application and decryption analyzers added after the initial plan: `grpc` (`grpc_inspect` and `gnmi_decode`), `httpinspect` (`http_inspect` / `http_messages`), `snmpinspect` (`snmp_inspect` / `snmp`), `aaainspect` (`aaa_inspect` / `aaa`), `espdecrypt` (`esp_decrypt` / `esp`), and embedded pcapng secret extraction (`tls_secrets`).
- Model finite states with typed `iota` enums and exhaustive `switch` checks.
- **Exit:** Full golden JSON parity across VPN, routing, convergence, gRPC, RESTCONF/HTTP, SNMP, AAA, and ESP fixtures.

### Phase 4: Multi-Capture and Orchestration
- Port `correlate`, `timeline`, `network_orchestrator`, and `orchestrator`.
- Run `tshark` across multiple captures concurrently using bounded goroutines while preserving deterministic output ordering.
- **Exit:** `dp_corr_*` and multi-capture timeline outputs match golden JSON.

### Phase 5: SIP and RTP Quality
- Port `handlers/sip`, `auth_info`, `call_tracking`, `overlap_dialing`, `rtp_mos_analysis`, `call_quality_scoring`, and `endpoint_analysis`.
- Use `tshark` as the required extractor backend (with credential masking for SIP digests, Basic headers, and SDP SRTP/MIKEY/`k=` keys).
- **Exit:** `quick_quality_check` and SIP diagnostic structures match Python golden JSON.

### Phase 6: MCP Server and Reporting
- Port all 18 MCP tools, 5 prompts, and 7 resources in `cmd/sonic-mcp` using the Go MCP SDK, keeping tool names, input schemas, and redacted JSON outputs identical.
- Port `internal/report` (markdown/JSON formatters and `agent_guide` skill generation).
- Validate by running the Python MCP stdio and integration tests (`test_mcp_stdio.py`, `test_network_mcp.py`, `test_mcp_guidance.py`) against the Go `sonic-mcp` binary.
- **Exit:** Existing MCP integration tests pass unchanged against the Go binary.

### Phase 7: LLM Layer (Decision Point)
Evaluate and implement the preferred LLM architecture:
- **Option A:** Retain Python/DSPy behind a sidecar/subprocess boundary.
- **Option B:** Direct Go HTTP provider clients (Ollama, Anthropic, OpenAI, Azure) with structured JSON outputs and `RedactingLM` parity (`internal/llm`).
- **Option C:** Keep the Go binary purely deterministic and delegate reasoning to the calling MCP agent.

### Phase 8: Cutover
- Port remaining test assertions to `go test` while retaining committed `.pcap` fixtures and golden oracle baselines.
- Add release packaging (Linux, macOS, Windows binaries) and CI workflows for `gofmt`, `go vet`, `go test -race`, and parity checks.
- Deprecate the Python entry points cleanly while keeping a `legacy` branch for one release cycle.
