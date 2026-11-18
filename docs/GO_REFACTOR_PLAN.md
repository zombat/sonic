# Go Migration Plan & Completion Record for S.O.N.I.C.

## Status

**Completed (`v3.3.0` dual-runtime baseline through `v4.0.0` pure Go cutover).** All 37 Go packages (`cmd/sonic`, `cmd/sonic-mcp`, and `internal/*`) pass `-race` tests at `90.1%` to `96.5%` statement coverage with 20 fuzz targets, golden JSON snapshot verification (`testdata/golden/`), live child-binary stdio E2E tests, and automated cross-compiled release archives across `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, and `windows/arm64`. Legacy Python runtime modules were retired after tagging `v3.3.0`.

## Principles

1. **Zero external Go dependencies.** All extractors, analyzers, MCP JSON-RPC transport, direct-HTTP LLM clients (`internal/llm`), archive packagers (`tools/pack_release.go`), and cryptographic checks use Go standard library packages only.
2. **Committed synthetic fixtures & golden snapshots.** `52` synthetic `.pcap` fixtures live in `testdata/fixtures/` (with dev-only Scapy scripts preserved in `scripts/fixtures/`), and golden JSON snapshots in `testdata/golden/` verify determinism with `make update-golden` (`go test -update`) for controlled updates.
3. **`tshark` is the sole external runtime dependency.** Go streams `tshark` TSV, PDML, and JSON outputs without loading entire captures into memory.
4. **Follow workspace house rules.** Adhere to [house-rules.md](../.agents/rules/house-rules.md) and [trifecta-triad.md](../.agents/rules/trifecta-triad.md): `gofmt`, ~300-line file cap, Google-style doc comments, custom domain types (`netip.Addr`, typed `iota` enums, pointer/presence fields for optional `tshark` values), `-race` tests at >= 90% coverage, fuzzing on untrusted inputs, tmpfs secret hygiene, zero em-dashes, and zero AI attribution.

## Implemented Layout (`37` Go Packages)

```text
cmd/
  sonic/              Thin CLI composition root (--version, LLM standard/streaming/partial/batch, deterministic modes, gate, diff, tui, --create-skill, --fetch-grpc-protos)
  sonic-mcp/          Dependency-free MCP stdio JSON-RPC server (21 tools, 5 prompts, 7 resources, --version, --env-file, --create-skill)
internal/
  tshark/             Process runner, -G fields resolution, TSV and streaming -T ek extraction, Wireshark 3.x/4.x scaling
  wsconfig/           Ephemeral /dev/shm tmpfs Wireshark config dir (0700/0600, signal cleanup, Unix + Windows build tags)
  redact/             Dotenv loader, SECRET_SHAPES / known-secret redaction, and verifiable AuditTracker counts
  model/              Typed packet/flow records and report types
  extract/            Network, pure-Go L2-L4 fast path, dataplane, HTTP/2, HTTP/RESTCONF, TLS secrets, SNMP, AAA, ESP, auth_info, and streaming SIP tshark extractors
  analyze/            22 analyzer packages: aaainspect, audit, convergence, correlate, diff, dmvpn, espdecrypt, espoverhead, grenhrp, grpc, httpinspect, ipsec, netorch, pathmtu, qos, reach, routing, sip, snmpinspect, tcphealth, timeline, tlsinspect
  gate/               Deterministic CI/CD policy evaluator (zero-cleartext, no-weak-crypto, mos-min, max-clipping-ms, no-critical-issues) with SARIF v2.1.0 & JUnit XML
  llm/                Direct-HTTP Provider/Completer clients (ollama, anthropic, openai, azure) with SSE/NDJSON streaming, TLS 1.2+, and HTTP 400 drop retries
  ai/                 Artifact & ResponseAdapter interfaces, ArtifactFactory, SIP diagnostic adapters, codec enrichment, batch & partial streaming orchestration
  guide/              Embedded AST detector metadata, MCP instructions, prompts, resources, and --create-skill generator
  mcpserver/          Embedded tools.json registry, JSON-RPC 2.0 server, deterministic/LLM handlers, and child-binary stdio E2E checks
  report/             Markdown/HTML5/JSON/console formatters, SIP auth diagrams, and cross-platform protocol stdout reservation (dup2/dup3/Windows)
  tui/                Zero-dependency ANSI terminal UI with Unix stty raw keys and Windows fallback
  parity/             Golden JSON comparator and -update writer
tools/
  gen_guide_meta.go   Extracts detector docstrings and MakeIssue codes via Go AST into detector_meta.json
  pack_release.go     Bundles cross-compiled release binaries + LICENSE + README.md into .tar.gz / .zip archives + SHA256SUMS
scripts/
  fixtures/           Dev-only deterministic Scapy capture generators (8 scripts)
testdata/
  fixtures/           52 committed synthetic .pcap captures
  golden/             Normalized JSON baseline snapshots
```

## Phase History

- **Phases 0-6:** Built golden baseline suite, core Go extraction/safety packages (`parity`, `wsconfig`, `redact`, `model`, `tshark`, `extract`), 21 analyzer packages, `internal/report`, `internal/mcpserver`, `internal/guide`, and thin CLI/MCP entry points (`338fd15`, `c619015`).
- **Phase 7 (`5ec2a81`):** Implemented direct-HTTP `Provider`/`Completer` (`internal/llm`) and `ArtifactFactory` (`internal/ai`), wiring all 18 MCP tools and CLI streaming/partial/batch LLM modes.
- **Phase 8 & `v3.3.0` (`414c3bd`, `a723e69`, `f689d4a`, `6e6d28a`):** Completed cross-platform fd/tmpfs isolation, full Python/Go 1:1 parity, empirical benchmarking (`benchmark.md`), and tagged `v3.3.0` as the final dual-runtime baseline.
- **`v4.0.0` (Go-Only Release):** Retired Python runtime/tests, moved fixtures to `testdata/fixtures/` + dev-only `scripts/fixtures/`, ported stdio/guidance/CLI E2E suites into Go, added `-update` golden snapshots (`make update-golden`), injected `-X main.version` / `-X main.commit`, automated `.tar.gz`/`.zip` `release.yml` workflows across 6 platforms, and added streaming `-T ek` SIP extraction, dynamic SDP RTP Decode-As, RFC 4733 DTMF & post-`200 OK` clipping analysis, pure-Go L2-L4 fast path, time windowing (`--since`/`--until`), cross-layer media correlation (`diagnose_media_underlay`), verifiable redaction audit counts (`--redact-audit`), baseline capture diffing (`sonic diff` / `diff_pcaps`), CI/CD policy gates (`sonic gate` / `evaluate_capture_gate` with SARIF & JUnit), offline HTML5 reports, ANSI TUI, and minimal Alpine container packaging (`Dockerfile`).
