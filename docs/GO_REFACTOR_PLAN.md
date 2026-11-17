# Go Refactor Plan for S.O.N.I.C.

## Status

**Completed on branch `feat/go-migration` (Phases 0 through 8).** Both native Go binaries (`cmd/sonic` and `cmd/sonic-mcp`) pass `-race` tests (`90.2%` to `96.2%` coverage across all 34 packages), golden parity checks, cross-runtime MCP integration parity, fuzz targets, and static cross-compilation across `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`.

## Principles

1. **Strangler pattern.** Python keeps working as the golden oracle and fallback while Go packages reach 100% JSON parity.
2. **Python is the oracle.** Synthetic `.pcap` fixtures in `tests/fixtures/` (`52` files from `8` generators) and normalized outputs in `testdata/golden/` verify Go-vs-Python parity.
3. **`tshark` stays the dissector.** Go shells out to `tshark` and streams `-T fields` TSV rows (or PDML/JSON where needed). Scapy is used only by test fixture generators.
4. **Follow workspace house rules.** Adhere to [house-rules.md](../.agents/rules/house-rules.md) and [trifecta-triad.md](../.agents/rules/trifecta-triad.md): `gofmt`, ~300-line file cap, Google-style doc comments, custom domain types (`netip.Addr`, typed `iota` enums, pointer/presence fields for optional `tshark` values), `-race` tests at >= 90% coverage, fuzzing on untrusted inputs, tmpfs secret hygiene, zero `any`/`interface{}` in core code, zero em-dashes, and zero AI attribution.

## Implemented Layout (`34` Go Packages)

```text
cmd/
  sonic/              Thin CLI composition root (standard/streaming/partial/batch LLM, deterministic network & protocol modes, --create-skill, --fetch-grpc-protos)
  sonic-mcp/          Dependency-free MCP stdio JSON-RPC server (18 tools, 5 prompts, 7 resources, --env-file, --create-skill)
internal/
  tshark/             Process runner, -G fields resolution, TSV streaming, Wireshark 3.x/4.x scaling
  wsconfig/           Ephemeral /dev/shm tmpfs Wireshark config dir (0700/0600, signal cleanup, Unix + Windows build tags)
  redact/             Dotenv loader and SECRET_SHAPES / known-secret redaction
  model/              Typed packet/flow records and report types
  extract/            Network, dataplane, HTTP/2, HTTP/RESTCONF, TLS secrets, SNMP, AAA, ESP, auth_info, and SIP tshark extractors
  analyze/            21 analyzer packages: aaainspect, audit, convergence, correlate, dmvpn, espdecrypt, espoverhead, grenhrp, grpc, httpinspect, ipsec, netorch, pathmtu, qos, reach, routing, sip, snmpinspect, tcphealth, timeline, tlsinspect
  llm/                Direct-HTTP Provider/Completer clients (ollama, anthropic, openai, azure) with SSE/NDJSON streaming, TLS 1.2+, and HTTP 400 drop retries
  ai/                 Artifact & ResponseAdapter interfaces, ArtifactFactory, SIP diagnostic adapters, codec enrichment, batch & partial streaming orchestration
  guide/              Embedded AST detector metadata, MCP instructions, prompts, resources, and --create-skill generator
  mcpserver/          Embedded tools.json registry, JSON-RPC 2.0 server, deterministic and LLM handlers
  report/             Markdown/JSON/console formatters, SIP auth diagrams, and cross-platform protocol stdout reservation (dup2/dup3/Windows)
  parity/             Golden JSON comparator
tools/
  gen_golden.py       Golden baseline generator
  gen_mcp_tools.py    Syncs internal/mcpserver/tools.json from mcp_server.py schemas
  gen_guide_meta.go   Extracts detector docstrings and MakeIssue codes via Go AST into detector_meta.json
testdata/
  golden/             Normalized Python oracle outputs
```

## Phase History

- **Phase 0 (Baseline):** Built `tools/gen_golden.py` and generated `testdata/golden/` snapshots (`make golden`, `make parity`).
- **Phase 1 (Foundation):** Built `internal/{parity,wsconfig,redact,model,tshark,extract}` and `sonic dump` with full record parity.
- **Phase 2 (Leaf Detectors):** Ported `tlsinspect`, `audit`, `reach`, `qos`, `pathmtu`, `espoverhead`, and `tcphealth`.
- **Phase 3 (Protocol-State & Decryption):** Ported `ipsec`, `grenhrp`, `dmvpn`, `routing`, `convergence`, `grpc`, `httpinspect`, `snmpinspect`, `aaainspect`, and `espdecrypt`.
- **Phase 4 (Multi-Capture & Orchestration):** Ported `correlate`, `timeline`, and `netorch`.
- **Phase 5 (SIP & RTP Quality):** Ported SIP auth extraction, call tracking, overlap dialing, RTP MOS E-model, and `quick_quality_check` scoring (`internal/analyze/sip`).
- **Phase 6 (MCP Server & Guidance):**
  - Stage 6A: Built `internal/report` and `cmd/sonic` deterministic modes.
  - Stage 6B (`338fd15`): Built `internal/mcpserver` and `cmd/sonic-mcp`.
  - Stage 6C (`c619015`): Built `tools/gen_guide_meta.go`, `internal/guide`, MCP prompts/resources, and `--create-skill`.
- **Phase 7 (Direct-HTTP LLM Engine, `5ec2a81`):** Selected **Option B** (zero external LLM SDKs). Implemented `Provider` and `Completer` in `internal/llm`, `Artifact`, `ResponseAdapter`, and `ArtifactFactory` in `internal/ai`, wired all 18 MCP tools into `internal/mcpserver` + `cmd/sonic-mcp`, and wired full SIP LLM/stream/partial/batch CLI modes into `cmd/sonic` plus `tests/stub_llm_mcp_server.go`.
- **Phase 8 (Cutover, Packaging & CI, `414c3bd`, `a723e69`):** Split OS-specific descriptor duplication (`dup2`/`dup3`/Windows) in `internal/report` and PID/signal teardown in `internal/wsconfig`, added `make release` (`linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64` static binaries + `SHA256SUMS`), `make mcp-parity`, `make fuzz`, and the `go` CI job in `.github/workflows/ci.yml`. Python entry points remain intact alongside Go during the cutover period.
