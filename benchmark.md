# S.O.N.I.C. Performance Benchmark: Go vs Python (`v3.3.0` Reference Baseline)

This document compares execution speed, scaling behavior, binary size, and memory usage between the compiled Go runtime (`cmd/sonic`, `cmd/sonic-mcp`) and the archived Python reference implementation (`sonic.py`, `mcp_server.py` on release tag `v3.3.0`) across all S.O.N.I.C. CLI and MCP use cases. Starting in `v4.0.0`, S.O.N.I.C. ships Go binaries only (`tshark` required at runtime; `v3.3.0` remains tagged for anyone needing Python/`scapy`).

## Executive Summary

- **Startup and skill generation**: Go starts **312x to 371x faster** than Python (`2.5 ms` to `4.6 ms` vs `794.1 ms` to `1,616.3 ms`) because Python imports `scapy`, `dspy`, `pydantic`, and `fastmcp` per process.
- **One-shot CLI capture commands**: Go completes deterministic capture runs **1.80x to 4.33x faster** (`271.5 ms` to `911.7 ms` vs `1,081.2 ms` to `1,641.6 ms`) and mocked-HTTP LLM CLI runs **2.78x to 6.39x faster**, even when both wait on identical external `tshark` calls.
- **Idle and startup memory**: Compiled stripped static Go binaries are `11 MiB` each (`CGO_ENABLED=0`) and hold `10.1 MiB` idle RSS as an MCP server, **15.3x less memory** than Python (`155.5 MiB` idle RSS). During active packet capture dissection, peak tree RSS (~`145 MiB`) is dominated by child `tshark` processes on both runtimes.
- **Warm persistent MCP server**: Once started, small single-capture tools spend ~`135 ms` inside `tshark` (~`1.0x` parity), while Go runs **1.34x to 2.37x faster** on multi-pass/helper modes (`grpc`, `restconf`, `snmp`, `aaa`, `esp`), **~2.0x faster** on multi-capture tools (`correlate_pcaps`, `merge_pcap_timelines`) via goroutine concurrency, and **1.31x faster** at `10,001` frames (`737.1 ms` vs `965.4 ms`).

---

## Test Environment & Methodology

### Hardware & Software

- **Host OS**: `Linux-6.18.58.1-microsoft-standard-WSL2-x86_64-with-glibc2.35` (20 logical CPUs)
- **Go toolchain**: `go version go1.27.3 linux/amd64` (`CGO_ENABLED=0`, `GOMAXPROCS=4`, built with `-trimpath -ldflags="-s -w"`)
- **Python runtime**: `Python 3.10.12` (repository `venv`, `dspy 3.5.0`, `fastmcp 4.1.8`, `ollama 0.6.3`)
- **Dissector**: `TShark (Wireshark) 3.6.2 (Git v3.6.2 packaged as 3.6.2-2)`

### Measurement Protocol

- **Warmup and sample size**: Every timed benchmark executed 1 unmeasured warmup run first, followed by 5 timed iterations (`CLI` deterministic modes and warm `MCP` deterministic tools) or 3 timed iterations (scaled `2,403`-frame and `10,001`-frame captures, mocked-HTTP `LLM` CLI runs, warm `MCP` LLM tools, and cold `MCP` startup). Tables report the **median** (`med`) plus full **min** and **max** wall-clock latencies to expose scheduling jitter clearly.
- **Local LLM HTTP stub**: LLM workflows ran against an in-process HTTP mock on `127.0.0.1` (`0 ms` model inference delay) implementing OpenAI `/v1/responses`, OpenAI `/v1/chat/completions` (JSON + SSE), and Ollama `/api/chat` (NDJSON) + `/chat/completions`. This isolates S.O.N.I.C. process startup, extraction, redaction, HTTP serialization, and response parsing overhead from GPU or cloud inference latency.
- **Persistent vs cold MCP**: Cold MCP timing starts a fresh server process, completes `initialize` + `notifications/initialized`, calls `tools/list`, and exits. Warm MCP timings reuse one already-initialized stdio session so both runtimes cache Python imports / Go setup and `tshark -G fields` metadata in RAM.

---

## Binary Footprint & Memory Usage

Measured via `ls -lh`, `file`, `/usr/bin/time -v` (peak resident set size across the process tree), and `/proc/<pid>/status` (`VmHWM` / `VmRSS` after MCP `initialize`).

| Metric | Go (`cmd/sonic` / `cmd/sonic-mcp`) | Python (`sonic.py` / `mcp_server.py`) | Ratio / Notes |
|---|---:|---:|---|
| Compiled binary size (`make build`) | 11 MiB (`sonic`), 11 MiB (`sonic-mcp`) | N/A (requires Python 3.10+ venv + packages) | Static stripped 64-bit ELF, `tshark` only at runtime |
| CLI startup peak RSS (`--help`) | 9,184 KiB (9.0 MiB) | 117,224 KiB (114.5 MiB) | 12.8x smaller in Go |
| CLI capture peak RSS (`--network-only`, `convergence_dpd.pcap`) | 148,824 KiB (145.3 MiB) | 148,876 KiB (145.4 MiB) | ~1.0x (dominated by child `tshark` process tree) |
| Idle persistent MCP server RSS (`VmRSS` / `VmHWM`) | 10,384 KiB (10.1 MiB) | 159,276 KiB (155.5 MiB) | 15.3x smaller in Go |

---

## 1. CLI Startup & Deterministic Capture Modes

Every command ran with identical flags and temporary `--save_file` paths using repository fixtures under `testdata/fixtures/` (`tests/fixtures/` on `v3.3.0`, plus one synthetic `2,403`-frame mixed SIP/RTP/TCP/ICMP capture, `313 KiB`, for CLI scaling).

| Use Case | Fixture / Input | Runs | Go min / **med** / max (ms) | Python min / **med** / max (ms) | Speedup |
|---|---|---:|---:|---:|---:|
| CLI startup (`--help`) | None | 5 | 2.4 / **2.5** / 3.2 | 784.6 / **794.1** / 819.0 | **312.0x** |
| Agent skill (`--create-skill`) | Built-in tool specs | 5 | 4.3 / **4.6** / 40.6 | 1,479.1 / **1,545.0** / 1,633.3 | **339.1x** |
| SIP quality-only (`--quality-only`) | `sip_minimal.pcap` | 5 | 259.0 / **271.5** / 280.1 | 1,141.9 / **1,174.5** / 1,199.7 | **4.33x** |
| Network / VPN full (`--network-only`) | `ipsec_ikev2_esp.pcap` | 5 | 576.5 / **585.3** / 592.7 | 1,278.1 / **1,297.4** / 1,397.8 | **2.22x** |
| Cleartext audit (`--detectors cleartext_audit`) | `audit_one_leak.pcap` | 5 | 562.1 / **572.0** / 590.3 | 1,289.9 / **1,294.7** / 1,434.8 | **2.26x** |
| Routing health (`--detectors routing`) | `bgp_failover.pcap` | 5 | 579.1 / **581.3** / 594.3 | 1,277.1 / **1,299.8** / 1,330.7 | **2.24x** |
| Convergence (`--detectors convergence`) | `convergence_dpd.pcap` (160 KB) | 5 | 581.3 / **586.9** / 599.2 | 1,287.3 / **1,308.1** / 1,315.5 | **2.23x** |
| Data plane + QoS/RTP (`--detectors tcp,tls,path_mtu,esp_overhead,qos`) | `dp_qos_rtp.pcap` (54 KB) | 5 | 560.9 / **573.2** / 654.6 | 1,284.6 / **1,300.9** / 1,350.2 | **2.27x** |
| Network full on largest repo fixture | `convergence_dpd.pcap` (160 KB) | 5 | 582.6 / **596.3** / 613.8 | 1,318.9 / **1,327.4** / 1,347.1 | **2.23x** |
| gRPC / gNMI / HTTP/2 (`--grpc`) | `grpc_h2_trouble.pcap` (46 KB) | 5 | 568.2 / **590.3** / 596.4 | 1,306.8 / **1,337.3** / 1,382.0 | **2.27x** |
| RESTCONF / HTTP (`--restconf`) | `restconf_cleartext.pcap` | 5 | 710.4 / **712.5** / 717.6 | 1,459.8 / **1,479.0** / 1,570.6 | **2.08x** |
| SNMP inspection (`--snmp`) | `snmp_v1v2c.pcap` | 5 | 304.9 / **306.3** / 314.7 | 1,067.4 / **1,081.2** / 1,109.3 | **3.53x** |
| AAA TACACS+ / RADIUS (`--aaa --aaa-secrets`) | `aaa_tacacs.pcap` | 5 | 443.1 / **452.5** / 465.3 | 1,202.9 / **1,216.3** / 1,363.0 | **2.69x** |
| IPsec ESP decrypt (`--esp-decrypt --esp-sa`) | `esp_tunnel.pcap` | 5 | 878.1 / **883.0** / 910.7 | 1,582.5 / **1,601.8** / 1,798.8 | **1.81x** |
| Scaled SIP quality (`--quality-only`) | 2,403 frames (313 KiB) | 3 | 316.2 / **329.8** / 337.1 | 1,222.8 / **1,233.7** / 1,236.4 | **3.74x** |
| Scaled network full (`--network-only`) | 2,403 frames (313 KiB) | 3 | 899.5 / **911.7** / 928.6 | 1,630.5 / **1,641.6** / 1,758.2 | **1.80x** |

---

## 2. Large-Capture Scaling & Where Time Goes

Inspecting subprocess calls (`strace -f -e execve`) on `--network-only` shows why small-capture timings cluster around fixed plateaus and how larger captures diverge:

1. **Per-process Python startup (~`750 ms` to `800 ms`)**: Python pays import time (`scapy`, `dspy`, `pydantic`, `fastmcp`) on every CLI invocation; Go starts in ~`2.5 ms`.
2. **One-time per-process `tshark` probes (~`450 ms`)**: On the first network capture in a process, both runtimes invoke `tshark --version` (~`150 ms`) and `tshark -G fields` (~`300 ms`) to discover supported dissector fields. Inside a persistent MCP server, that probe runs once per session and is cached in RAM.
3. **Packet extraction and detector loops (`~135 ms` small -> scales with frames)**: Once `tshark -G fields` is cached inside a warm MCP session, small (`1 KB` to `160 KB`) single-capture calls spend almost all their time waiting on one `tshark -r` process (~`135 ms`). Scaling up to a `10,001`-frame (`928 KiB`) mixed SIP/RTP/TCP/ICMP capture increases detector and decoding work:

| Warm MCP Tool | Small Capture (median) | `10,001` Frames / `928 KiB` (median of 3) | Go Speedup at `10,001` Frames |
|---|---|---|---|
| `quick_quality_check` | Go `266.7 ms` vs Py `275.4 ms` (`1.03x`) | Go **`441.3 ms`** vs Py `503.0 ms` | **1.14x** (61.7 ms saved) |
| `analyze_network_pcap` | Go `146.8 ms` vs Py `136.2 ms` (`0.93x`) | Go **`737.1 ms`** vs Py `965.4 ms` | **1.31x** (228.3 ms saved) |

At `10,001` frames, Go parses streaming TSV records and evaluates all 11 network detectors `228 ms` faster than Python (`1.31x` overall end-to-end including `tshark`).

---

## 3. LLM CLI Workflows (Local Mock HTTP Endpoint)

Measured against a zero-delay local HTTP stub (`0 ms` model inference) on `sip_minimal.pcap` (`3` runs per case). Batch benchmarks process 3 identical SIP captures in a temporary directory.

| Workflow | Flags & Provider | Go min / **med** / max (ms) | Python min / **med** / max (ms) | Speedup |
|---|---|---:|---:|---:|
| Single pass (`fast`) | `--provider openai --model fast` | 274.5 / **276.7** / 284.0 | 1,345.1 / **1,354.9** / 1,374.2 | **4.90x** |
| Combined 2-pass | `--provider openai --model combined` | 285.2 / **295.8** / 307.1 | 1,340.3 / **1,344.6** / 1,348.8 | **4.55x** |
| Streaming | `--provider ollama --stream` | 154.3 / **165.7** / 178.7 | 931.7 / **952.2** / 954.8 | **5.75x** |
| Partial streaming | `--provider ollama --stream --partial` | 269.4 / **269.8** / 283.1 | 1,038.4 / **1,045.7** / 1,051.4 | **3.88x** |
| Batch sequential | `--batch-dir` (`sequential`, 3 pcaps) | 392.1 / **413.1** / 414.4 | 1,144.0 / **1,148.2** / 1,228.4 | **2.78x** |
| Batch parallel | `--batch-dir --batch-mode parallel --batch-workers 3` | 139.5 / **140.7** / 143.6 | 886.9 / **899.0** / 921.5 | **6.39x** |

Notes on LLM behavior:
- With a live remote API or local GPU Ollama model, model token-generation latency (typically `1 s` to `30 s+`) dominates total runtime in both Go and Python.
- Python's `--stream` path for `openai` and `anthropic` imports optional third-party pip packages (`openai`, `anthropic`) that are not installed by default in `requirements.txt` (`v3.3.0`), falling back on `ollama`; Go implements SSE and NDJSON streaming directly on Go stdlib `net/http` for every provider.

---

## 4. MCP Stdio Server (Cold Handshake & All 18 Warm Tools)

Comparing `build/sonic-mcp` and `mcp_server.py` speaking raw newline-delimited JSON-RPC 2.0 over stdio (`5` runs per warm deterministic tool, `3` runs for cold handshake and warm LLM tools).

| MCP Call | Input / Scope | Go min / **med** / max (ms) | Python min / **med** / max (ms) | Speedup |
|---|---|---:|---:|---:|
| **Cold handshake** (`initialize` + `tools/list`) | Fresh server process | 4.3 / **4.4** / 5.4 | 1,579.4 / **1,616.3** / 1,630.8 | **371.0x** |
| Warm: `list_llm_providers` | In-memory config/env check | 0.2 / **0.3** / 0.4 | 1.1 / **1.2** / 1.4 | **4.24x** |
| Warm: `quick_quality_check` | `sip_minimal.pcap` | 261.6 / **266.7** / 268.1 | 258.8 / **275.4** / 280.3 | **1.03x** |
| Warm: `analyze_network_pcap` | `ipsec_ikev2_esp.pcap` | 140.8 / **146.8** / 151.6 | 133.8 / **136.2** / 143.1 | 0.93x |
| Warm: `analyze_vpn_pcap` | `ipsec_ikev2_esp.pcap` | 129.3 / **138.0** / 143.9 | 130.7 / **139.3** / 140.6 | **1.01x** |
| Warm: `analyze_routing_pcap` | `bgp_failover.pcap` | 134.0 / **135.2** / 147.8 | 135.4 / **137.4** / 146.9 | **1.02x** |
| Warm: `analyze_data_plane_pcap` | `dp_tcp_health.pcap` | 131.1 / **135.8** / 140.3 | 132.1 / **138.5** / 142.4 | **1.02x** |
| Warm: `correlate_pcaps` | `dp_corr_inside.pcap` + `dp_corr_outside.pcap` | 130.6 / **133.9** / 141.8 | 250.7 / **263.3** / 265.2 | **1.97x** |
| Warm: `merge_pcap_timelines` | `ospf_failover.pcap` + `icmp_loss.pcap` | 132.7 / **134.9** / 143.3 | 264.4 / **271.1** / 283.7 | **2.01x** |
| Warm: `audit_cleartext_pcap` | `audit_one_leak.pcap` | 127.1 / **142.7** / 187.7 | 135.2 / **142.1** / 144.5 | **1.00x** |
| Warm: `analyze_grpc_pcap` | `grpc_h2_trouble.pcap` (46 KB) | 409.7 / **419.6** / 447.8 | 585.3 / **613.7** / 742.3 | **1.46x** |
| Warm: `analyze_restconf_pcap` | `restconf_cleartext.pcap` | 525.9 / **533.5** / 541.9 | 696.9 / **716.2** / 728.1 | **1.34x** |
| Warm: `analyze_snmp_pcap` | `snmp_v1v2c.pcap` | 126.7 / **130.1** / 134.6 | 298.4 / **307.9** / 320.1 | **2.37x** |
| Warm: `analyze_aaa_pcap` | `aaa_tacacs.pcap` + secrets | 271.4 / **279.6** / 297.2 | 436.6 / **456.8** / 468.8 | **1.63x** |
| Warm: `analyze_esp_pcap` | `esp_tunnel.pcap` + SA file | 254.0 / **262.2** / 272.2 | 432.4 / **443.1** / 452.3 | **1.69x** |
| Warm: `analyze_convergence_pcap` | `convergence_dpd.pcap` (160 KB) | 137.5 / **140.3** / 147.2 | 142.8 / **146.4** / 147.1 | **1.04x** |
| Warm LLM (mock): `analyze_pcap` | `sip_minimal.pcap` (`provider=openai`, `model=fast`) | 258.6 / **264.8** / 274.2 | 269.0 / **276.0** / 277.3 | **1.04x** |
| Warm LLM (mock): `analyze_pcap_partial_streaming` | `sip_minimal.pcap` (`provider=ollama`) | 261.9 / **271.0** / 283.3 | 269.7 / **271.2** / 290.4 | **1.00x** |
| Warm LLM (mock): `analyze_batch_pcaps` | 3 captures (`mode=parallel`, `provider=openai`) | 137.6 / **142.3** / 145.6 | 136.3 / **137.4** / 148.1 | 0.97x |

Key MCP insights:
- **Multi-capture concurrency (`1.97x` to `2.01x`)**: `correlate_pcaps` and `merge_pcap_timelines` extract each capture concurrently on Go goroutines (`~134 ms` total for 2 captures vs Python's sequential `~263 ms` to `271 ms`). The gap grows with 3 or more captures.
- **Protocol-specific multi-pass tools (`1.34x` to `2.37x`)**: `analyze_grpc_pcap`, `analyze_restconf_pcap`, `analyze_snmp_pcap`, `analyze_aaa_pcap`, and `analyze_esp_pcap` run multiple extraction passes or payload parsers and complete significantly faster in Go.
- **Warm LLM cache effect**: Inside a persistent Python MCP session, DSPy keeps an in-memory prompt cache across identical calls to the same file (`analyze_pcap`, `analyze_batch_pcaps`), whereas Go always executes fresh direct HTTP requests (matching real production behavior on distinct captures, where parallel batch runs `6.39x` faster on CLI).

---

## Choosing a Runtime

| Scenario | Recommended Binary / Tag | Reason |
|---|---|---|
| Production CLI automation, CI pipelines, cron triage | **Go** (`sonic`) | Zero Python dependencies, 11 MiB static binary, 1.8x to 339x faster CLI runs |
| Desktop MCP clients (`Claude Desktop`, `Cline`, `NetClaw`) | **Go** (`sonic-mcp`) | 4.4 ms launch, 10.1 MiB idle RAM vs 155.5 MiB, 2x faster multi-capture correlation |
| Environments without `tshark` installed | **Pinned `v3.3.0` tag** (`sonic.py`) | Built-in `scapy` packet extraction fallback in the archived Python release |
| Dev fixture regeneration & golden updates | `scripts/fixtures/` + `make update-golden` | Rare `.pcap` rebuilds via Scapy; CI verifies committed snapshots purely in Go |

---

## Reproducing Benchmarks Locally

Build static Go binaries and verify tests first:

```bash
make build
make test
make parity
```

To measure single CLI latency directly with `/usr/bin/time` or shell timing (against `v4.0.0+` fixtures under `testdata/fixtures/`):

```bash
time ./build/sonic --file testdata/fixtures/convergence_dpd.pcap --network-only --save_file /tmp/go.md
```
