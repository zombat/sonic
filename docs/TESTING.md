# Testing S.O.N.I.C.

This page describes both the native Go test suite and the Python reference/parity test suite, how to run them locally, optional capture variables, and CI gates.

## Current Status

### Go Suite (Primary Build)

| Check | Result | Command |
|---|---|---|
| Go packages (`cmd/*`, `internal/*`) | **34 passed**, `90.2%` to `96.2%` statement coverage (`-race`) | `make test` |
| Go fuzzers (SSE, NDJSON, JSON recovery, `ArtifactFactory`) | **4 fuzz targets passed** (`1s` smoke runs) | `make fuzz` |
| Golden parity tests (`extract`, `audit`, `cmd/sonic`, `mcpserver`) | **All passed** (`-race`) | `make parity` |
| Cross-runtime MCP parity against Go binaries | **27 passed** (`test_mcp_stdio.py` + `test_mcp_guidance.py`), **1 passed** (`TestMcpStdioHandshake`, 12 deselected) | `make mcp-parity` |
| Cross-platform `go vet` & static builds | `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64` passed | `make release` |

### Python Reference Suite

| Metric | Measured Result | Command |
|---|---|---|
| Tests collected (`pytest --collect-only`) | **372** across 16 files | `venv/bin/python -m pytest --collect-only -q` |
| Full local run | **351 passed, 21 skipped**, 285 subtests passed, 9 deprecation warnings | `venv/bin/python -m pytest -q` |

Optional skips occur when private local captures (`SONIC_GRPC_CAPTURES`), `.proto` files (`SONIC_PROTO_PATH`), or container-generated SNMPv3 captures are absent.

## Running the Tests

```bash
# Go race and coverage suite across all 34 packages
make test

# Go vet and cross-platform stripped builds (Linux/macOS/Windows)
make vet
make release

# Golden JSON parity and cross-runtime Python MCP tests against Go binaries
make parity
make mcp-parity

# Go fuzz smoke tests on untrusted parsers and ArtifactFactory
make fuzz

# Python reference suite (372 tests)
venv/bin/python -m pytest -q
```

Note on memory limits: the Makefile sets `GOMAXPROCS=4 GOMEMLIMIT=2400MiB` and `-p 1` for sequential package race runs cleanly on WSL2 / constrained hosts.

## Requirements

- **tshark** on `PATH` (dissection backend used by both Go and Python suites).
- **Go 1.27+** (per `go.mod`) for building, vetting, fuzzing, and running Go tests.
- **Python 3.10+** with packages from `requirements.txt` and `requirements-dev.txt` for Python tests and fixture regeneration.
- No live LLM endpoint or cloud API key is required. Go tests use local `httptest` servers and stub `llm.Completer` implementations; Python MCP tests use `tests/stub_llm_mcp_server.py` (Python) and [tests/stub_llm_mcp_server.go](../tests/stub_llm_mcp_server.go) (Go).

## Go Packages Covered

| Area | Packages | Coverage Range (`-race`) |
|---|---|---:|
| CLI & MCP Entry Points | `cmd/sonic` (`94.7%`), `cmd/sonic-mcp` (`95.0%`) | `94.7% - 95.0%` |
| LLM & AI Factory Layer | `internal/llm` (`90.8%`), `internal/ai` (`91.7%`) | `90.8% - 91.7%` |
| MCP & Guidance | `internal/mcpserver` (`93.8%`), `internal/guide` (`91.8%`) | `91.8% - 93.8%` |
| Core & Safety Infrastructure | `extract` (`90.9%`), `report` (`90.9%`), `redact` (`91.0%`), `wsconfig` (`90.2%`), `tshark` (`91.8%`), `model` (`93.6%`), `parity` (`94.5%`) | `90.2% - 94.5%` |
| Analyzers (`internal/analyze/*`) | 21 analyzer packages (`aaainspect`, `audit`, `convergence`, `correlate`, `dmvpn`, `espdecrypt`, `espoverhead`, `grenhrp`, `grpc`, `httpinspect`, `ipsec`, `netorch`, `pathmtu`, `qos`, `reach`, `routing`, `sip`, `snmpinspect`, `tcphealth`, `timeline`, `tlsinspect`) | `90.3% - 96.2%` |

## Python Test Files (372 Collected)

Measured with `venv/bin/python -m pytest --collect-only -q <file>`:

| File | Tests | What it covers |
|---|---:|---|
| `test_network_detectors.py` | 46 | Network and VPN detectors and orchestrator across tshark and scapy backends |
| `test_control_plane.py` | 44 | IPsec, GRE/NHRP, DMVPN, routing, reachability, convergence, cleartext audit |
| `test_dataplane_detectors.py` | 41 | Path MTU, ESP overhead, TCP, TLS, QoS, correlation, timeline merging |
| `test_grpc.py` | 41 | gRPC/gNMI decoding, HTTP/2 framing, TLS keylog and pcapng secrets, scrubbing |
| `test_tls_audit.py` | 29 | TLS handshake suites, SSH KEXINIT checks, weak/unverified cipher detection |
| `test_aaa.py` | 25 | TACACS+ and RADIUS inspection, Authenticator validation, key de-obfuscation |
| `test_mcp_guidance.py` | 25 | MCP instructions, tool annotations, prompts/resources, `--create-skill`, CLI/MCP parity (`SONIC_CLI_BINARY` / `SONIC_MCP_BINARY`) |
| `test_credentials.py` | 22 | Dotenv parsing, precedence, redaction across outputs and stdio MCP |
| `test_esp.py` | 20 | ESP SA parsing, decryption integrity checks, inner packet analysis |
| `test_snmp.py` | 19 | SNMP v1/v2c/v3 security levels and USM authPriv decryption |
| `test_restconf.py` | 17 | RESTCONF/REST over HTTP/1.1 and HTTP/2, TLS secrets, masked auth headers |
| `test_phase3_reporting.py` | 15 | SIP authentication posture reports and ASCII/Mermaid sequence diagrams |
| `test_network_mcp.py` | 13 | Network MCP tools and stdio handshake (`SONIC_MCP_BINARY` supported) |
| `test_sip_credentials.py` | 10 | SIP digest, Basic, and SDP key scrubbing |
| `test_auth_diagnostics.py` | 3 | SIP authentication diagnostics |
| `test_mcp_stdio.py` | 2 | Strict JSON-RPC stdio framing (`SONIC_MCP_BINARY` / `SONIC_MCP_STUB_BINARY` supported) |
| **Total** | **372** | |

## Synthetic Fixtures and Golden Baselines

- `tests/fixtures/` holds **52** committed `.pcap` files built by 8 deterministic generators: `generate_fixtures.py`, `generate_dataplane_fixtures.py`, `generate_grpc_fixtures.py`, `generate_tls_audit_fixtures.py`, `generate_aaa_fixtures.py`, `generate_esp_fixtures.py`, `generate_restconf_fixtures.py`, and `generate_snmp_fixtures.py`.
- CI runs every generator on each push/PR and fails if git sees any diff. Rebuild locally with:

```bash
for g in tests/fixtures/generate_*.py; do python3 "$g"; done
```

- `testdata/golden/` stores normalized Python baseline JSON outputs rebuilt via `make golden` (`tools/gen_golden.py`) for Go parity comparison (`internal/parity`).

## Continuous Integration

[ci.yml](../.github/workflows/ci.yml) runs on every push to `main` and pull request:

- **go**: Go version from `go.mod`, installs `tshark`, checks `gofmt -l .`, runs `go vet ./...` for `linux/amd64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`, builds `make build release`, and runs `GOMAXPROCS=4 GOMEMLIMIT=2400MiB go test -race -p 1 -count=1 -cover ./...`.
- **test**: Python 3.10 to 3.13 on Ubuntu, installs `tshark`, runs `pytest -q --cov`, uploads `coverage.xml`.
- **lint**: Non-blocking `black --check` and `flake8`.
- **fixtures**: Re-runs all 8 fixture generators and fails on any change.
- **audit** & CodeQL: `pip-audit` and `codeql.yml`.
