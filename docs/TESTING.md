# Testing S.O.N.I.C.

This page is the reference for the test suite: what runs, how to run it, what needs extra setup, and how the fixtures are made. The counts were measured with `pytest --collect-only` and a full run, and are updated when tests change.

## Current status

| | |
|---|---|
| Tests collected | **275** |
| Last full run | **274 passed, 1 skipped**, 266 subtests passed, about 100 s |
| Skipped | `test_grpc.py`: the gNMI `.proto` test, when the protos are not on disk |
| Warnings | 9, from pydantic class-based `config` and fastmcp's `openWorldHint` (deprecations, not failures) |

The only skip is the gNMI protobuf test. It needs `.proto` files, which the `--fetch-grpc-protos` flag downloads. CI will run without them, so the skip is expected there too.

## Running the tests

```bash
# Everything (the usual way)
python3 -m pytest -q

# One file, with the stdlib runner (test_grpc.py documents this)
python3 -m unittest -q test_grpc

# With coverage (CI does the same)
python3 -m pytest -q --cov --cov-report=term --cov-report=xml
```

Optional environment variables for the tests that use real captures:

| Variable | Used by | Effect |
|---|---|---|
| `SONIC_GRPC_CAPTURES` | `test_grpc.py` | Directory of real gRPC captures. Without it, those tests are skipped. |
| `SONIC_PROTO_PATH` | `test_grpc.py` | Directory of gNMI `.proto` files. Enables the protobuf-view test. |

Real captures are not in the repository. The TLS-secrets test on a real SR Linux capture runs only where `SONIC_GRPC_CAPTURES` points at it, and it reads the expected values from the capture with tshark at test time.

## Requirements

- **tshark** on the `PATH`. The network, gRPC and data-plane tests call it. The SIP detectors also have a scapy backend, and the tests run both backends where both exist.
- Python packages from `requirements.txt` and `requirements-dev.txt`.
- Nothing needs network access, an LLM or an API key. The MCP tests start the server over stdio with a stub LLM (`tests/stub_llm_mcp_server.py`).

## Test files

Counts come from `pytest --collect-only`.

| File | Tests | What it covers |
|---|---:|---|
| `test_control_plane.py` | 44 | Control-plane detectors (IPsec, GRE/NHRP, DMVPN, routing, reachability, convergence, cleartext audit) on the tshark and scapy backends, argument checks, real lab captures when present |
| `test_network_detectors.py` | 45 | Network and VPN detectors and the orchestrator on both backends, edge cases, fixtures |
| `test_dataplane_detectors.py` | 41 | Data-plane detectors (path MTU, ESP, TCP, TLS handshakes, QoS), correlation and merged timeline, both backends, real lab captures when present |
| `test_grpc.py` | 41 | gRPC analysis: gNMI decoding, HTTP/2 framing, synthetic fixtures, TLS secrets and credential scrubbing, the real TLS capture, the Wireshark protobuf view, proto fetching |
| `test_tls_audit.py` | 29 | TLS handshake knowledge and encryption findings on both backends, real TLS capture, generated fixtures |
| `test_mcp_guidance.py` | 25 | MCP instructions, generated skill, entry points, LLM provider resolution, CLI model options |
| `test_credentials.py` | 17 | Env-file parsing, key loading, LLM configuration, MCP output without keys, separate processes |
| `test_phase3_reporting.py` | 15 | SIP authentication reports: security posture, upgrade recommendations, realm-to-server mapping, sequence diagrams |
| `test_network_mcp.py` | 13 | The network tools called directly and through the MCP stdio handshake |
| `test_auth_diagnostics.py` | 3 | SIP authentication diagnostics |
| `test_mcp_stdio.py` | 2 | stdout carries only JSON-RPC over stdio |
| **Total** | **275** | |

## Fixtures

Captures are built, not stored, so the suite runs on a fresh clone.

- `tests/fixtures/*.pcap` holds about 45 small synthetic captures. Each is produced by one of four generators:
  - `generate_fixtures.py`: network and VPN captures (names start with the detector).
  - `generate_dataplane_fixtures.py`: data-plane captures (names start with `dp_`).
  - `generate_grpc_fixtures.py`: gRPC captures (names start with `grpc_`).
  - `generate_tls_audit_fixtures.py`: TLS audit captures.
- Each generator writes identical bytes on every run. CI checks this: it runs the generators and fails if git sees a change.
- The TLS 1.3 key-log tests build their sessions at test time with Python's `ssl` module. Nothing is committed for them.
- `samples/` holds no captures, so older documentation that cites `samples/*.pcapng` cannot be run from the repository.

Rebuild the fixtures with:

```bash
for g in tests/fixtures/generate_*.py; do python3 "$g"; done
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

- **test**: Python 3.10 to 3.13 on Ubuntu, tshark installed, `pytest` with coverage. The coverage XML is uploaded as an artifact.
- **lint**: `black --check` and `flake8`. This job does not yet block merges, because the existing code does not pass either tool.
- **fixtures**: regenerates the fixtures and fails if the output changes.

CodeQL runs separately, and `pip-audit` reports dependency vulnerabilities without blocking. See `docs/ARCHITECTURE.md` (section 6) for the pipeline diagram.

## Adding a test

- Put it in the file for the area it covers. Use `unittest.TestCase`, which the suite already uses throughout.
- If it needs a capture, add a generator to `tests/fixtures/` and make it deterministic. Do not commit a binary you cannot rebuild.
- If it needs a real capture, gate it on an environment variable and skip when the variable is unset, the way `test_grpc.py` does.
- Update the count in this file and in the README table when the total changes.
