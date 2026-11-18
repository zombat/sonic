# Testing S.O.N.I.C.

S.O.N.I.C. is verified by a pure-Go `-race` unit, integration, golden-snapshot, live stdio E2E, and fuzz test suite requiring only `Go 1.27+` and `tshark` on `PATH`.

## Current Status

| Check | Scope / Result | Command |
|---|---|---|
| Go packages (`cmd/*`, `internal/*`) | **37 passed**, `90.1%` to `96.5%` statement coverage (`-race`) | `make test` |
| Go fuzzers (LLM/AI, TLS/SSH/IKE, wire PCAP/PCAPNG, EK, SIP/SDP, policies, report/TUI) | **20 fuzz targets passed** (`1s` smoke runs) | `make fuzz` |
| Golden snapshot checks (`extract`, `audit`, `cmd/sonic`, `mcpserver`, analyzers) | **All passed** against `testdata/golden/` (`-race`) | `make parity` |
| Child-binary CLI & MCP stdio E2E tests | Real compiled `sonic`, `sonic-mcp`, and `tests/stub_llm_mcp_server.go` subprocesses over OS pipes | Included in `make test` |
| Cross-platform `go vet` & archive builds | `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64` | `make release` |

## Running the Tests

```bash
# Full Go race and coverage suite across all 37 packages
make test

# Go vet and release archives + SHA256SUMS (6 platforms)
make vet
make release

# Golden JSON snapshot verification and snapshot regeneration
make parity
make update-golden

# Go fuzz smoke tests across all 20 parser and sanitization targets
make fuzz
```

Note on memory limits: the Makefile sets `GOMAXPROCS=4 GOMEMLIMIT=2400MiB` and `-p 1` for sequential package race runs cleanly on constrained hosts.

## Requirements

- **tshark** on `PATH` (dissection backend used across extraction and protocol tests).
- **Go 1.27+** (per [go.mod](../go.mod)) with zero external Go modules.
- No live LLM endpoint or cloud API key is required. Go tests use local `httptest` servers, in-process stub `llm.Completer` mocks, and [tests/stub_llm_mcp_server.go](../tests/stub_llm_mcp_server.go) for stdio streaming verification.

## Go Packages Covered

| Area | Packages | Coverage Range (`-race`) |
|---|---|---:|
| CLI & MCP Entry Points | `cmd/sonic` (`92.7%`), `cmd/sonic-mcp` (`96.0%`) | `92.7% - 96.0%` |
| LLM & AI Factory Layer | `internal/llm` (`91.1%`), `internal/ai` (`91.7%`) | `91.1% - 91.7%` |
| MCP, Policy Gate & TUI | `internal/mcpserver` (`93.7%`), `internal/guide` (`91.0%`), `internal/gate` (`96.5%`), `internal/tui` (`90.6%`) | `90.6% - 96.5%` |
| Core & Safety Infrastructure | `extract` (`90.2%`), `report` (`90.7%`), `redact` (`94.3%`), `wsconfig` (`90.1%`), `tshark` (`93.3%`), `model` (`93.6%`), `parity` (`91.2%`) | `90.1% - 94.3%` |
| Analyzers (`internal/analyze/*`) | 22 analyzer packages (`aaainspect`, `audit`, `convergence`, `correlate`, `diff`, `dmvpn`, `espdecrypt`, `espoverhead`, `grenhrp`, `grpc`, `httpinspect`, `ipsec`, `netorch`, `pathmtu`, `qos`, `reach`, `routing`, `sip`, `snmpinspect`, `tcphealth`, `timeline`, `tlsinspect`) | `90.3% - 96.2%` |

## Synthetic Fixtures and Golden Snapshots

- `testdata/fixtures/` holds **52** committed deterministic `.pcap` captures.
- `scripts/fixtures/` preserves the **8** developer-only Scapy generator scripts (`generate_fixtures.py`, `generate_dataplane_fixtures.py`, `generate_grpc_fixtures.py`, `generate_tls_audit_fixtures.py`, `generate_aaa_fixtures.py`, `generate_esp_fixtures.py`, `generate_restconf_fixtures.py`, and `generate_snmp_fixtures.py`) for rare fixture additions; CI requires zero Python dependencies and tests directly against `testdata/fixtures/`.
- `testdata/golden/` stores committed normalized JSON baseline snapshots verified by [internal/parity](../internal/parity). When an analyzer intentionally changes JSON output, regenerate snapshots with:

```bash
make update-golden    # runs go test -p 1 -count=1 ./... -update
```

## Optional Real Captures

Optional local tests run when `SONIC_GRPC_CAPTURES` points to real lab captures or `SONIC_PROTO_PATH` points to custom protobuf directories, and skip automatically otherwise.

## Continuous Integration and Releases

- **[ci.yml](../.github/workflows/ci.yml)** runs on every push to `main` and pull request: installs `tshark`, enforces `gofmt -l .`, runs cross-OS `go vet` across all 6 target platforms (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`), runs `make test` (`-race`) and `make fuzz`, and builds `make build release`.
- **[release.yml](../.github/workflows/release.yml)** triggers on `v*` tags: runs the full Go gate (`gofmt`, `vet`, `test`, `fuzz`), builds all 6 platform archives + `SHA256SUMS` with `VERSION=${{ github.ref_name }}`, and publishes GitHub Release artifacts.
- **GitHub CodeQL Default Setup** runs automated CodeQL security and quality scanning over Go source on pushes and pull requests.
