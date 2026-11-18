# Changelog

All notable changes to S.O.N.I.C. (SIP Observation and Network Inspection Console) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0] - 2026-11-17

### Breaking Changes
- **Pure Go Runtime Cutover:** Retired the legacy Python CLI/MCP runtime (`sonic.py`, `mcp_server.py`, `analyzers/`, `ai/`, `extractors/`, `handlers/`, `models/`, `utils/`, `llm_config.py`, `requirements*.txt`, and Python test suites). Users who require the archived Python runtime or Scapy offline fallback can check out release tag `v3.3.0`.
- **Single-Runtime Fixtures & Golden Snapshots (`Option B`):** Moved the `52` synthetic `.pcap` captures to `testdata/fixtures/` and archived the `8` Scapy fixture generator scripts into `scripts/fixtures/` for rare offline updates. Added `-update` flag (`make update-golden`) to `internal/parity` so Go tests maintain golden snapshots without Python.

### Added
- **Post-`200 OK` Clipping, RFC 4733 DTMF, & Streaming SIP (`internal/extract/sip*.go`, `internal/analyze/sip/{clipping,dtmf_rtp}.go`):** Replaced buffered `tshark -T json` SIP extraction with streaming `-T ek` NDJSON, added dynamic `-d udp.port==<port>,rtp` second-pass decode-as for non-standard SDP media ports, implemented early/delayed offer tracking and post-`200 OK` media delay flagging (`>500 ms` warning, `>2000 ms` critical), and added dynamic SDP `telephone-event` payload mapping and RFC 4733 digit decoding.
- **Cross-Layer Media-to-Underlay Correlation (`internal/analyze/netorch/media_underlay.go`, `--correlate-media`, MCP `diagnose_media_underlay`):** Runs SIP quality/clipping/DTMF checks concurrently with all network detectors and links voice impairments directly to co-occurring IPsec/DMVPN/routing/PMTUD/TCP/QoS faults.
- **Pure-Go PCAP/PCAPNG L2-L4 Fast Path & Time Windowing (`internal/extract/pcap_{fastpath,decode,l4}.go`, `--fast-path`, `--since`, `--until`):** Reads classic PCAP and PCAPNG captures directly in pure Go (`auto` for pure L2-L4/ESP/QoS/PMTUD/TCP detector runs, `always`, or `never`), bypassing `tshark` startup overhead (`~3.8-6.7 ms` vs `~569-586 ms`, up to `147.9x` faster) while maintaining field-for-field parity on L2-L4 captures.
- **Verifiable Redaction Audit, CI Policy Gate, & Baseline Diffing (`internal/redact/audit.go`, `internal/gate`, `internal/analyze/diff`, `sonic gate`, `sonic diff`):** Added category-level secret scrubbing counts (`--redact-audit`), CI policy evaluation (`zero-cleartext`, `no-weak-crypto`, `mos-min`, `max-clipping-ms`, `no-critical-issues`) with SARIF v2.1.0, JUnit XML, JSON, and exit code `0`/`3` enforcement (`evaluate_capture_gate`), and concurrent baseline-vs-target capture diffing (`diff_pcaps`).
- **Offline HTML5 Reports, Interactive ANSI TUI, & Container Image (`internal/report/html*.go`, `internal/tui`, `Dockerfile`, `.dockerignore`):** Added self-contained air-gapped HTML5 exports (`--html` and `--save_file *.html`), a zero-dependency interactive terminal viewer (`sonic tui` / `--tui`), and a multi-stage rootless Alpine image bundling `sonic`, `sonic-mcp`, and headless `tshark` (`make container`, `make container-up`, `make container-down` with `docker`/`podman` auto-detection).
- **Version Injection & Release Packaging (`cmd/sonic`, `cmd/sonic-mcp`, `tools/pack_release.go`, `Makefile`):** Wired `-ldflags` `main.version` and `main.commit` into `--version` on both binaries and `serverInfo.version` during MCP `initialize`. Added pure-Go cross-platform archive packaging across 6 targets (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`) outputting `.tar.gz`/`.zip` bundles with `LICENSE`, `README.md`, and `SHA256SUMS`.
- **Release Workflow & Go-Only CI (`.github/workflows/release.yml`, `ci.yml`, `codeql.yml`):** Added automated `v*` tag releases publishing artifacts via `softprops/action-gh-release`, streamlined `ci.yml` to run `gofmt`, 6-platform `go vet`, `make test`, `make fuzz`, and `make build release`, and switched CodeQL to `languages: go`.
- **Native Go E2E Coverage (`cmd/sonic/cli_e2e_test.go`, `cmd/sonic/workflows_test.go`, `internal/mcpserver/stdio_e2e_test.go`):** Expanded child-binary CLI/workflow tests, stdout JSON-RPC purity checks across all `21` MCP tools, stubbed streaming MCP verification, prompts/resources inspection, and self-teaching tool schema validation in Go.

## [3.3.0] - 2026-11-17

Pinned final dual-runtime baseline with full 1:1 Go and Python parity across CLI modes, extractors, 21 analyzers, direct-HTTP LLM clients, 18 MCP tools, and empirical performance benchmarks (`benchmark.md`).

### Go Migration (Phases 0-8)
- **Native Go CLI and MCP Server (`cmd/sonic`, `cmd/sonic-mcp`):** Single dependency-free binaries sharing extracted logic under `internal/` with zero Python or external LLM SDK dependencies (`tshark` only).
- **Extractors and 21 Analyzers (`internal/extract`, `internal/analyze/*`, `internal/tshark`, `internal/model`):** Complete golden-parity ports of SIP/RTP call quality and MOS scoring, IPsec/IKE/ESP, GRE/NHRP/DMVPN Phase 3, BGP/OSPF/EIGRP routing and convergence, reachability, path MTU, ESP overhead, TCP health, TLS inspection, QoS, cleartext audit, gRPC/gNMI/gNOI, RESTCONF/REST, SNMPv1/v2c/v3, TACACS+/RADIUS AAA, ESP decryption, multi-capture correlation, and timeline merging.
- **Direct-HTTP LLM Layer and Artifact Factory (`internal/llm`, `internal/ai`):** `Provider` and `Completer` interfaces over standard `net/http` SSE/NDJSON (`ollama`, `anthropic`, `openai`, `azure`) with TLS 1.2+, redirect refusal, loopback-only plaintext checks, HTTP 400 parameter-drop retries, `Artifact` / `ResponseAdapter` / `ArtifactFactory` normalization and validation, streaming (`--stream`, `--partial`), and parallel/sequential batch processing (`--batch-dir`).
- **Security and Stdio Safety (`internal/wsconfig`, `internal/redact`, `internal/report`):** Ephemeral `0700`/`0600` Wireshark config dirs under `/dev/shm` tmpfs with orphan PID cleanup, cross-platform build-tagged process/stdio guards (`dup2`, `dup3` for `linux/arm64`, `os.Stdout` redirection on Windows), dotenv literal parsing, and secret scrubbing across all outputs and outbound LLM prompts.
- **MCP Surface and Agent Guidance (`internal/mcpserver`, `internal/guide`, `tools/gen_mcp_tools.py`, `tools/gen_guide_meta.go`):** All 18 MCP tools, 5 prompts, 7 resources, and `--create-skill` generator parity verified via Go tests (`-race`) and `tests/stub_llm_mcp_server.go` (`make mcp-parity`).
- **Build, Cross-Platform Release, and CI (`Makefile`, `.github/workflows/ci.yml`):** Added `build`, `install`, `uninstall`, `release` (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64` + `SHA256SUMS`), `vet`, `test`, `fuzz`, `parity`, `mcp-parity`, and `help` targets plus a full `go` CI job.
- **1:1 Parity Hardening (`cmd/sonic`, `internal/analyze/audit`, `internal/analyze/netorch`, `internal/report`, `internal/ai`):** Matched Python's `analyze_network_capture` wrapper for `--network-only --detectors cleartext_audit` (while preserving standalone `--detectors cleartext_audit`), emitted `audit` timeline `first_leak` events, added `--quality-only --save_file` Markdown/JSON saving (`BuildQualityMarkdown` / `SaveQualityReport`) alongside `--quality-only --json`, added default `<capture>.<mode>.md` output when `--json` and `--save_file` are omitted, exposed `--create-skill` / `--fetch-grpc-protos` / providers in `--help` (`flag.ErrHelp` exit 0), and fixed non-streaming `ollama` batch token counting (`aggregate.total_tokens > 0`) and `output.analysis_method`.

### Documentation and CI
- **Architecture, MCP, Testing, Refactor Plan, Integration Guide, and README** (`docs/ARCHITECTURE.md`, `docs/MCP.md`, `docs/TESTING.md`, `docs/GO_REFACTOR_PLAN.md`, `INTEGRATION_GUIDE.md`, `README.md`): Documented the native Go CLI and MCP binaries, updated `docs/MCP.md` to cover all 18 MCP tools, updated `docs/TESTING.md` and `README.md` with the 34-package Go `-race` test suite (`90.2%` to `96.2%` coverage), 4 fuzz targets, 52 synthetic fixtures from 8 generators, and the measured 372-test Python suite (`351 passed, 21 skipped`).

### Added
- 🔐 **IPsec ESP decrypted from SA keys, and the inner traffic analysed** (`analyzers/esp_decrypt.py`, `extractors/esp.py`, `utils/esp_reporting.py`; MCP `analyze_esp_pcap`, CLI `--esp-decrypt`, `--esp-sa`), deterministic, through tshark's ESP decryption and its `esp_sa` table
  - The SA file (src, dst, spi, encryption and key, integrity and key; AES-GCM keys with their salt) or the output of `ip -s xfrm state` as it is (`enc`, `auth-trunc`, `aead rfc4106(gcm(aes))`), read by path and written to a private temporary `esp_sa` table, never a command line, with the exact labels tshark 3.6.2 takes (each checked; its ESP NULL label is plain `NULL`)
  - Per SA: ESP packets seen and decrypted, tunnel or transport mode, tshark's integrity check, and when packets did not decrypt, why: a bad ICV (the integrity key, or for AES-GCM the key and salt), a good ICV with no decryption (the integrity key is right, so the encryption key is wrong), or no packet for that SA. A packet counts as decrypted only when its decrypted trailer is real (RFC 4303 default padding, a real next header, an inner IP packet of exactly the payload's length): tshark fills its decrypted-data field under a wrong key too
  - The decrypted packets (tunnel mode as sent, transport mode given back the outer addresses, NAT-T over UDP 4500 included) are rebuilt into a temporary capture and run through the existing network detectors (`inner_analysis`)
  - Cisco IOS and IOS XE do not expose ESP session keys, so their tunnels cannot be decrypted this way; the docs, the tool description and the limits say so
  - `docs/ESP_DECRYPTION.md`, `test_esp.py` on a deterministic scapy fixture (`tests/fixtures/esp_tunnel.pcap`: AES-CBC with HMAC-SHA1-96 and HMAC-SHA256-128, AES-GCM, transport mode, NAT-T), plus NULL encryption, wrong keys of each kind and an `ip xfrm state` import
- 🛂 **TACACS+ and RADIUS read with the shared key** (`analyzers/aaa_inspect.py`, `extractors/aaa.py`, `utils/aaa_reporting.py`; MCP `analyze_aaa_pcap`, CLI `--aaa`, `--aaa-secrets`), deterministic, through tshark's TACACS+ and RADIUS dissectors
  - TACACS+ per session: who asked, the authentication result (PASS, FAIL, GETPASS, ...), authorization and accounting status, service and privilege level; a session sent with the unencrypted flag is `AAA_CLEARTEXT_TACACS`
  - RADIUS per transaction: Access-Request with Accept, Reject or Challenge, and Accounting Start/Stop, with User-Name, NAS and Calling-Station; whether the shared secret validated the Response Authenticator (`RADIUS_BAD_AUTHENTICATOR` when not), and each side's Message-Authenticator checked as RFC 3579 defines, which tshark 3.6 does not do (`RADIUS_BAD_MESSAGE_AUTHENTICATOR`; a response without one is `RADIUS_NO_MESSAGE_AUTHENTICATOR`, the Blast-RADIUS CVE-2024-3596 hardening point)
  - With a key file (`tacacs_key:` and/or `radius_secret:`) the TACACS+ bodies are de-obfuscated through `tacplus.key` and the RADIUS User-Password decrypted through `radius.shared_secret`; a recovered password is masked (`AAA_CREDENTIAL_RECOVERED`), and the keys are written only to a private temporary preferences file, never a command line, and scrubbed by value from every output
  - `docs/AAA_TROUBLESHOOTING.md`, `test_aaa.py` on synthetic scapy fixtures (`tests/fixtures/generate_aaa_fixtures.py`: RADIUS with valid, absent and altered Message-Authenticators; TACACS+ authentication, authorization, accounting, a FAIL and an unobfuscated session), with the Message-Authenticator check tested against scapy's own implementation
- 📟 **SNMP: every version named, and SNMPv3 decrypted with a USM users file** (`analyzers/snmp_inspect.py`, `extractors/snmp.py`, `extractors/wsconfig.py`, `utils/snmp_reporting.py`; MCP `analyze_snmp_pcap`, CLI `--snmp`, `--snmp-users`), deterministic, through tshark's SNMP dissector and its `snmp_users` table
  - Every message named v1, v2c or v3, v3 by its security level (noAuthNoPriv, authNoPriv, authPriv), engine discovery named; a v1/v2c community is a cleartext credential (`SNMP_CLEARTEXT_COMMUNITY`, value masked)
  - With a users file (block or CSV: user, optional engine id, auth and passphrase, priv and passphrase), each authenticated v3 message says whether it authenticated and each authPriv message whether it decrypted, and when not, why: `unknown_user`, `unknown_engine`, `auth_failed`, `decrypt_failed`. An agent's Report is named by its usmStats counter (`usmStatsUnknownUserNames`, `usmStatsWrongDigests`, ...). A decrypted PDU's contents are never reported
  - The users file is read by path and turned into a private temporary `WIRESHARK_CONFIG_DIR` (never a command line, where `ps` would show it); passphrases and communities are scrubbed by value from every output
  - Measured against net-snmp 5.9.4: tshark 3.6.2's table takes auth `MD5`, `SHA1`, `SHA2-224/256/384/512` and priv `DES`, `AES`, `AES192`, `AES256` as labels (no 3DES, no separate Cisco entry). DES and AES-128 decrypt with every auth; AES-192/256 decrypt over SHA2-256/512. Over SHA1 or MD5 they do not: tshark 3.6.2 extends the short key the Reeder (Cisco) way, net-snmp the Blumenthal-draft way, verified byte for byte, and the reason says so
  - `docs/SNMP_DECRYPTION.md`, `test_snmp.py`: v1/v2c on a committed synthetic fixture (`tests/fixtures/snmp_v1v2c.pcap`), SNMPv3 on real traffic `tests/fixtures/generate_snmp_fixtures.py --v3` captures from a pinned, unprivileged net-snmp container (every algorithm net-snmp offers, a wrong privacy and a wrong auth passphrase, an unknown user), written outside the repository with throwaway credentials and never committed
- 🌐 **RESTCONF and REST troubleshooting over HTTP/1.1 and HTTP/2, decrypted with a key log** (`analyzers/http_inspect.py`, `extractors/http_messages.py`, `utils/http_reporting.py`; MCP `analyze_restconf_pcap`, CLI `--restconf`), deterministic, with Wireshark's HTTP, HTTP/2, HPACK and TLS dissectors through tshark
  - Finds HTTP on the well-known HTTP(S) ports (80, 443, 8080, 8443, 8008, 8888, 4443), on a TLS session offering ALPN `h2` or `http/1.1`, and on a cleartext HTTP/2 preface (h2c) on any port; each flow named by its service port, extra ports with `--http-ports`
  - A troubleshooting view per request (paired to its response): method, path, HTTP status and phrase, time from request to response, request and response `Content-Type`, response body size, a `Location` on a 201, whether it is RESTCONF, and for a RESTCONF error the `ietf-restconf:errors` fields (`error-type`, `error-tag`, `error-app-tag`, `error-path`, `error-message`) parsed from the body in JSON or XML (RFC 8040 section 3.9)
  - Credentials present, never shown: an `Authorization` scheme (Basic, Bearer) kept and its credential masked; `Cookie`, `Set-Cookie` and token headers (`X-Auth-Token`, `X-API-Key`, CSRF, ...) flagged by name with the value dropped. Over cleartext each is a `CLEARTEXT_CREDENTIAL`, over TLS a `CREDENTIAL_IN_REQUEST` (seen only because the secrets decrypted it). Masked at the source, scrubbed by value, and run through the key redaction; message bodies are never decoded except RESTCONF error documents
  - TLS decrypted with a key log (`--tls-secrets-log`, SSLKEYLOGFILE format) or the secrets a pcapng carries in a Decryption Secrets Block (no key log needed); `tls_decryption` says per TLS session whether it decrypted, which source held its secret, and when not, why, with a total. Without a key log a TLS session shows only the handshake (`HTTP_TLS_NOT_DECRYPTED`)
  - Issue codes `RESTCONF_ERROR`, `HTTP_CLIENT_ERROR`, `HTTP_SERVER_ERROR`, `HTTP_NO_RESPONSE`, `CLEARTEXT_CREDENTIAL`, `CREDENTIAL_IN_REQUEST`, `HTTP_TLS_NOT_DECRYPTED`, `TLS_SESSION_NOT_DECRYPTED`, `TLS_SECRETS_IN_CAPTURE`; report schema `sonic.http_report/1`
  - `docs/RESTCONF_TROUBLESHOOTING.md`, the `analyze_restconf_pcap` MCP tool and skill reference, `test_restconf.py` (synthetic fixtures from `tests/fixtures/generate_restconf_fixtures.py`; RESTCONF over TLS 1.3 for HTTP/1.1 and HTTP/2 built at test time with Python's `ssl` module and its key log, and the same with the secrets embedded in a pcapng by editcap). No real RESTCONF-over-TLS capture with a key log is on this machine (the one RESTCONF capture is TLS 1.3 with no key log), so that case is proven on the synthetic TLS sessions and the real capture is asserted to show only the handshake (the honest "not decrypted" state)
- 🔓 **TLS decryption proven on a real capture, secrets inside pcapng, and decryption coverage** (`analyzers/grpc_inspect.py`, `extractors/tls_secrets.py`)
  - Proven on a real capture of gNMI over TLS 1.3 to Nokia SR Linux 26.7.2 with the key log its client wrote: all ten calls (Capabilities, Get, Set, Subscribe) by name with their status and timing, the TLS 1.3 certificate, and the `username`/`password` metadata of every call flagged (`CREDENTIAL_IN_METADATA`) with values masked
  - A pcapng that carries its TLS secrets in a Decryption Secrets Block (`editcap --inject-secrets tls,KEYLOG in.pcap out.pcapng`) is decrypted with no key log; the report says so (`capture.tls_secrets`, transport `tls (decrypted with the secrets in the pcapng)`, `TLS_SECRETS_IN_CAPTURE`)
  - `tls_decryption`: every TLS session in the capture, whether the secrets decrypted it, which source held its secret, and when not, why (no secret for its ClientHello random, no ClientHello captured, only the handshake secrets), with a total in the verdict; `TLS_SESSION_NOT_DECRYPTED` names each session the secrets did not open. Shown in the CLI summary and the markdown report
  - The key log is still handed to tshark by path; to say which sessions it covers only its labels and ClientHello randoms are read, and the secret column is dropped as each line is read
- 🔏 **Encryption proven by the handshake** in the cleartext audit (`analyzers/cleartext_audit.py`)
  - TLS: the suite the ServerHello chose, read from the record bytes on any port (after a HelloRetryRequest, the real ServerHello). NULL ciphers, anonymous and export key exchange and the RFC 9150 integrity-only suites (`TLS_SHA256_SHA256`, `TLS_SHA384_SHA384`) count as cleartext; TLS 1.1 and older, RC4, DES, 3DES and MD5 pass with a `WEAK_ENCRYPTION` warning
  - SSH: each direction's cipher and MAC, derived from both KEXINITs as RFC 4253 7.1 does (the first algorithm on the client's list that the server also offers). `none` counts as cleartext; arcfour, CBC modes, 64-bit block ciphers and the MAC `none` pass with a `WEAK_ENCRYPTION` warning
  - A session that does not encrypt is `<protocol> without encryption` (category `unencrypted_session`), its frames after the handshake count as cleartext, and the verdict names the suite or cipher
  - A session whose handshake is not in the capture passes only as encrypted, unverified (`ENCRYPTION_UNVERIFIED`, a warning): a TLS session already past its handshake is recognised by its application data records, an SSH session that began before the capture by tcp/22 or tcp/830 and payload that looks like ciphertext (text on tcp/22 without a banner stays cleartext)
  - `clean` (a pass with no weak or unverified session; the verdict then reads `PASS with warnings` and the detector's status is `warning`), `encryption` (sessions by state), `tcp_sessions[].encryption` (state, version, suite or ciphers, the frames read, why), `violations[].reasons`, and one `ENCRYPTED_OUTSIDE_TUNNEL` info issue naming the SSH and TLS sessions that passed as protected by their own encryption rather than by IPsec
- 📚 The TLS suite table (`analyzers/tls_inspect.py`) holds every NULL, anonymous, export and integrity-only suite Wireshark knows, plus CCM, ARIA and Camellia GCM, DHE-DSS and static ECDH suites, each name checked against `tshark -G values`; `suite_encryption()` and `version_is_weak()` judge a chosen suite and version
- `sonic.py --allow TOKENS` for `--network-only --detectors cleartext_audit`
- 🧪 `test_tls_audit.py`: the suite table against Wireshark's, the SSH choice, both backends on seven synthetic fixtures from `tests/fixtures/generate_tls_audit_fixtures.py` (TLS 1.2 NULL, TLS 1.3 integrity-only, TLS 1.0, SSH `none`, SSH `aes128-cbc`, sessions that began before the capture, text on tcp/22), and the real NETCONF/RESTCONF/SSH capture, which now passes by default with the ciphers Wireshark's own dissectors read, and the plaintext gNMI capture, which still fails with its credentials
- 📡 **gRPC troubleshooting** (`analyzers/grpc_inspect.py`, `extractors/http2.py`, `analyzers/gnmi_decode.py`; MCP `analyze_grpc_pcap`, prompt `troubleshoot_grpc`, CLI `--grpc`), deterministic, with Wireshark's HTTP/2, HPACK, gRPC, TLS and protobuf dissectors through tshark
  - Finds gRPC by the HTTP/2 preface on any port, by ALPN h2, and on the well-known gRPC ports (9339, 9340, 9559, 57400, 6030, 50001, 50051, 50052, 32767), decoding each with decode-as; each flow is named by its service port
  - Per RPC: method, authority, content-type, deadline, message counts and sizes, HTTP status, grpc-status by name and grpc-message, time to the first response and to the trailers, and a diagnosis
  - Per connection: SETTINGS, RST_STREAM and GOAWAY with error codes and debug data (too_many_pings named), flow-control stalls, PING round trips, frames and header lists over the peer's limits, too many concurrent streams, messages over the 4 MiB default, an unanswered preface, undecodable HPACK blocks, TCP resets with RPCs open
  - gNMI Capabilities, Get, Set and Subscribe decoded without .proto files (paths, encodings checked against the Capabilities answer, modes, notifications, sync_response, in-band errors; never values), gNOI system.Time against the capture clock, gRPC health
  - Credentials in gRPC metadata (username, password, authorization, x-api-key, tokens, cookies) from the HPACK-decoded headers, one finding per key and flow (`CLEARTEXT_CREDENTIAL`); values masked at extraction and scrubbed by value
  - TLS without keys: SNI, ALPN, version, certificate, alerts with their meaning; with a key log (`keylog_file`, CLI `--tls-secrets-log`, passed to tshark and never copied) the sessions are decrypted and the TLS 1.3 certificate read
  - `python3 sonic.py --fetch-grpc-protos [DIR]` (`utils/grpc_protos.py`) downloads the gNMI and gNOI .proto files and the protobuf well-known types at pinned commits with SHA-256 checks, for Wireshark's protobuf view; they are not shipped (Apache-2.0 and BSD-3-Clause)
  - `docs/GRPC_TROUBLESHOOTING.md`, the `grpc` guide topic and skill reference, `test_grpc.py` (real captures when present, synthetic fixtures from `tests/fixtures/generate_grpc_fixtures.py`, a TLS 1.3 session with its key log built at test time)
- 🔐 **Cleartext audit by content**: SSH (banner, key exchange to NEWKEYS, then encrypted), TLS (handshake, then application data) and cleartext HTTP/2 (named `grpc` when its requests are gRPC) are recognised on any port; every frame is counted in `protection` (`encrypted`, `key_exchange`, `cleartext`, ...), `tcp_sessions` names each flow by its service port, `cleartext_frames` answers "is anything cleartext", and credentials in cleartext gRPC metadata are flagged. New allowlist tokens `ssh`, `netconf`, `tls`, `http2` and `encrypted`; new issue code `ENCRYPTED_OUTSIDE_ALLOWLIST`
- 🔏 **TLS detector**: the certificate's IP SANs, who sent each alert and what it means, and `TLS_CERT_NO_IP_SAN` when a client that sent no SNI (so dialled an IP) meets a certificate without that IP as a SAN
- `analyze_network_pcap` lists `http2`, `ssh` and `tls` in `protocols_present`
- 🧭 **MCP guidance built into the server** (`utils/agent_guide.py`)
  - Instructions in the initialize result, under 2 KB: which tool answers which question, the order of a typical investigation, which tools call an LLM, result shape, size limits and what packets cannot show
  - Every tool has a title and annotations (read-only, not destructive; deterministic tools idempotent and closed world, LLM tools open world), and a description that says when to use it, what it needs, what it costs and what it returns
  - Prompts `diagnose_capture`, `check_vpn_encryption`, `investigate_failover`, `diagnose_sip_call`
  - Resources `sonic://guide/overview` and `sonic://guide/<topic>` (`mcp-tools`, `network-detectors`, `sip-rtp`, `cli`, `interpreting-results`)
- 🎓 **Agent Skill by progressive disclosure**: `python3 sonic.py --create-skill [DIR]` and `python3 mcp_server.py --create-skill [DIR]` (default `.claude/skills/sonic`) write a short `SKILL.md` and one `reference/` file per area. Tool parameters, detectors and issue codes, CLI options and LLM providers are generated from the live code. Each file carries a marker; a `SKILL.md` or reference file without it is never replaced, files are written atomically, and a rerun leaves unchanged files alone
- 🔑 **Anthropic with a passthrough key** (`utils/credentials.py`): API keys come from the process environment (an MCP client's `env` block passes one through), then from a dotenv file named by `--env-file PATH` (`sonic.py`, `mcp_server.py`) or `SONIC_ENV_FILE`. The file is parsed as literal data, only `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `AZURE_OPENAI_KEY` are kept, and a value is never copied into the environment
- 🙈 **Keys never shown**: redacted by value (and `sk-ant-...` by pattern) from every MCP tool result, CLI output, log records, saved reports and the prompts sent to the LLM (`RedactingLM`); `list_llm_providers` reports only `configured` and the source (`environment` or the env file path)
- 🧪 `test_credentials.py`: parser, precedence, redaction of every output path with dummy keys, the CLI and a real MCP stdio session
- 🧪 `test_mcp_guidance.py`: instructions, annotations, descriptions, prompts and resources, the skill's frontmatter, size, coverage, refusal and idempotence, both entry points, and a real MCP stdio session
- **Data plane detectors** (deterministic, no LLM), run by default in `analyze_network_capture`:
  - `path_mtu`: ICMP Fragmentation Needed / Packet Too Big with the advertised MTU matched to the probe frame, PMTUD black holes for DF pings and TCP (with the bracket the path MTU lies in), IP fragments complete, incomplete and overlapping, reassembly timeouts
  - `esp_overhead`: ESP sizes per SA tested against cipher families, inner size bounds and overhead in tunnel and transport-over-GRE mode, tunnel MTU fit against the transport MTU, ESP fragmented after encryption; labelled as estimates
  - `tcp`: per-connection health from raw sequence numbers (no answer, refused, fast and timeout retransmissions, gaps, duplicate ACKs, zero window with duration, window full, resets, MSS and window scale, RTT and RFC 6298 RTO) with one verdict per connection
  - `tls`: ClientHello and ServerHello on any port with segment reassembly, TLS 1.2 certificates (TLS 1.3 reported as encrypted), cleartext alerts, and a baseline check passed as a parameter
  - `qos`: DSCP per flow, GRE inner against outer DSCP, ESP DSCP per SA, RTP loss, RFC 3550 jitter and DSCP with a MOS estimate from the existing E-model, ECN CE
- **Multi-capture tools**: `correlate_captures` (`analyzers/correlate.py`) follows packets across labelled captures for NAT translations, lost replies, asymmetric paths, stopped probes, transit time, TTL decrement and DSCP rewrites, streaming with a bounded match window; `merge_timelines` (`analyzers/timeline.py`) merges every detector's events from several captures and measures deltas between chosen events against thresholds, optionally writing JSON
- **MCP tools**: `analyze_data_plane_pcap`, `correlate_pcaps`, `merge_pcap_timelines`; `analyze_network_pcap` takes per-detector `options`
- **Tests**: `test_dataplane_detectors.py` (both backends, synthetic fixtures from `tests/fixtures/generate_dataplane_fixtures.py`, real lab captures when present) and new MCP tool tests
- The three data plane MCP tools follow the guidance conventions: titles, annotations, descriptions with returns, cost and limits in the visible text, results through `redact_result`, rows in the instructions and the generated skill
- Zero-cleartext audit (`cleartext_audit` detector, `audit_cleartext_pcap` MCP tool): every frame against an allowlist (default ESP, IKE on UDP 500/4500, NAT-T keepalives; tokens for ARP, ICMP, routing, GRE, link-local layer 2, ports and protocols, each scopable to addresses), reported by protocol and address pair with frame numbers, and a pass or fail result
- IKEv2 exchange decoding: proposals offered and chosen by name with weak algorithms flagged, KE groups and INVALID_KE_PAYLOAD retries, NAT_DETECTION hashes recomputed from the wire and the move to UDP 4500, DPD liveness checks, IKE SA collisions, cleartext INVALID_SPI / INVALID_IKE_SPI, ESP on a stale SPI after a rekey, and a diagnosis code per IKE SA (proposal_mismatch, dh_group_mismatch, auth_failed, auth_no_reply, nat_t_missing, udp_4500_blocked, no_reply, liveness_lost, peer_lost_sa, ...)
- DMVPN Phase 3 sequence proof (`dmvpn_phase3` detector): per redirected flow the ordered steps via hub, redirect, resolution request, resolution reply and direct data, with the first missing step and why; hub-relayed traffic with no redirect; resolution thrashing; and, given the hubs, encrypted spoke-to-spoke shortcuts when NHRP is inside ESP
- BGP: OPEN capabilities, keepalive cadence against hold/3, UPDATE timing, the TCP MSS of each SYN and SYN-ACK checked against `expected_mss`, and the cause of each session drop (hold timer, NOTIFICATION, BFD, RST, FIN, or a hold expiry inferred from silence)
- OSPF: adjacencies stuck in EXSTART or EXCHANGE from DB Description retransmissions, with the cause (for example the DBD MTU mismatch)
- Convergence timeline (`convergence` detector, `analyze_convergence_pcap` MCP tool): from an event time or the first failure sign, the delay to detection, to the first UPDATE on the surviving path and to traffic resuming, and the driver (DPD, BGP hold timer, BFD, explicit close)
- `hubs` on analyze_vpn_pcap and analyze_network_pcap, `expected_mss` on analyze_routing_pcap and analyze_network_pcap
- Nine synthetic fixtures and `test_control_plane.py` (both backends, plus the Pleiades lab captures when present)

### Changed
- 🔓 README gains a Decryption section (what each decrypting tool needs, how secrets are kept off command lines and out of outputs, what TShark 3.6.2 can and cannot do, and what is out of scope: SSH, and WinRM sealed with NTLM); the `diagnose_capture` workflow names the decrypting tools and says to pass key files by path; `run_phase2_tests.sh` runs the four decryption test modules
- MCP instructions: tool summaries shortened so the instructions stay under 2 KB with the new tools, and a line that decryption keys are passed as file paths, never pasted
- 🔐 **The cleartext audit's default allowlist is now `encrypted`, not `crypto`**: besides IPsec it passes SSH and TLS sessions, but only when their handshake shows real encryption. To get the old behaviour (IPsec only, the tunnel question) pass `allow=["crypto"]` (MCP `audit_cleartext_pcap`, `audit_cleartext_capture`) or `--allow crypto` (CLI, new); SSH and TLS then fail as `ENCRYPTED_OUTSIDE_ALLOWLIST` as before. A harness that pins an earlier S.O.N.I.C. release (such as the CVD harness) is unaffected
- The `ssh`, `netconf`, `tls` and `encrypted` tokens no longer accept a session that negotiated no encryption (see below); a port token (`tcp:443`) still does, and its frames still count as cleartext
- The TLS detector's `TLS_WEAK_CIPHER_CHOSEN` says when the chosen suite does not encrypt at all, and the RFC 9150 integrity-only suites count as weak there too
- The `ssh` allowlist token means an SSH session recognised by its banner, not port 22; an encrypted session outside the allowlist is a warning (`ENCRYPTED_OUTSIDE_ALLOWLIST`), not a cleartext finding
- Every TCP record carries `svc`, the listening side's port, once the connection's SYN, SYN-ACK, HTTP/2 preface or ClientHello shows it, and flow labels use it
- `run_phase2_tests.sh` runs `test_grpc.py` and `test_control_plane.py`
- Anthropic models: `claude-haiku-5-5` (fast), `claude-sonnet-5-5` (detailed, the default), `claude-opus-5-5` (new `deep` profile and `--model deep` analysis mode), called as `anthropic/<model>` through DSPy. Anthropic requests no longer send `temperature`, which current Claude models reject with a 400
- Tool descriptions: the returns, limits and examples moved into the text an MCP client sees (fastmcp drops docstring sections such as `Returns:` from the description)
- `analyzers/network_orchestrator.py` keeps its detectors in one registry, `DETECTOR_CLASSES`
- `sonic.py` builds its parser in `build_parser()`; `--file` is still required for every mode except `--create-skill`
- INTEGRATION_GUIDE.md and README.md describe `--create-skill` in place of the `--init-skills` command they named, which did not exist
- Every network record carries `dp` (IP identification, DF/MF, fragment offset, DSCP/ECN, raw TCP sequence numbers, window and options, payload head and hash, ICMP next-hop MTU) from both backends (`extractors/dataplane.py`)
- tshark runs with `ip.defragment:FALSE`, so fragments stay one record per frame as on the scapy backend; the scapy backend reports a UDP length from the header, as tshark does
- `DETECTOR_CLASSES` also holds `path_mtu`, `esp_overhead`, `tcp`, `tls` and `qos`; `_build_detectors` builds from it and passes per-detector `options`
- The extractor hands the IKE bytes from tshark (`udp.payload`) to the same parser scapy uses, so IKE fields match by construction; records gain the TCP MSS of SYNs, BGP capability codes, OSPF DBD flags and sequence, and an `llc` label for CDP/STP frames
- Synthetic IKEv2 fixtures carry real NAT detection hashes

### Fixed
- TLS-wrapped gRPC was not decrypted when a client's first segment arrived after its second (a large post-quantum ClientHello split in two, as SR Linux's gNMI clients send): TShark 3.6's out-of-order reassembly never fills a gap with a segment it marks as a retransmission, so no ClientHello was read and no secret matched. A connection left undecoded that way is read again without out-of-order reassembly (`capture.reread_without_out_of_order`)
- A masked user name was scrubbed from the report wherever its value appeared, so a gNMI path `/interface[name=mgmt0]/admin-state` read `.../[REDACTED]-state` (which also gave the name away); user names are now scrubbed only where they stand alone, and passwords and tokens wherever they appear
- A server's RST_STREAM NO_ERROR right after its own status (RFC 9113 8.1, how SR Linux ends a Subscribe ONCE) was a warning; it is info now, and every reset records whether the server had already ended the stream
- A gNMI message whose fields had unexpected wire types stopped the whole gRPC analysis with a TypeError; it is now an entry in `decoded.decode_errors`
- The TLS detector lost every TLS 1.3 handshake that began with a HelloRetryRequest: it took the middlebox-compatibility ChangeCipherSpec after it as the start of encryption and never read the ServerHello, reporting `TLS_NO_SERVER_HELLO` (all three RESTCONF sessions of a real Catalyst 8000V capture)
- Flows were labelled by the client's ephemeral port when both ports were high (a gNMI session to tcp/50001 read as tcp/47814)
- The cleartext audit reported SSH and TLS as cleartext
- The MCP server's stdout carries only JSON-RPC (`utils/protocol_stdout.py`). Before serving it keeps the real stdout for the protocol and points descriptor 1 and `sys.stdout` at stderr, so the SIP, network, extractor and reporting prints (and child processes) no longer corrupt the stdio channel; the CLI's output is unchanged. `test_mcp_stdio.py` runs a real stdio session, calls the SIP and network tools on a sample capture and parses every byte written to stdout through the server's exit
- Every LLM tool (`analyze_pcap`, `analyze_pcap_partial_streaming`, `analyze_batch_pcaps`) and every LLM path behind them uses one provider: the call's `provider`, else `SONIC_LLM_PROVIDER`, else `ollama` (`llm_config.resolve_provider`). The batch and streaming tools used to default to `anthropic`, and `SONIC_LLM_PROVIDER` changed none of them; `list_llm_providers` reports the resolved provider as `current_config.provider`
- `sonic.py --model-name NAME` now runs the LLM analysis on that model (one pass in the fast, detailed, deep and combined modes, and in batch and streaming); it was parsed and ignored. It is refused with `--model all`
- `analyze_pcap_partial_streaming` (and `--stream --partial`) failed on every call: `ai/partial_streaming.py` imported `utils.serialization`, which never existed. It now converts the quality and MOS results with `utils.credentials.redact`, the converter every MCP tool result already goes through. `test_mcp_stdio.py` calls the tool over a real stdio session with only the streaming LLM stubbed (`tests/stub_llm_mcp_server.py`)
- `sonic.py --api-key` is removed: it was never used, and a key typed on the command line lands in shell history and `ps` output. Keys come from the environment, then from the file `--env-file` or `SONIC_ENV_FILE` names

### Security
- The decryption keys handed to tshark (the TACACS+ key, the RADIUS secret, SNMPv3 passphrases, ESP SA keys) are written to tmpfs (`/dev/shm`) where there is one, so they never reach a disk or its journal; without tmpfs (macOS) they fall back to the temporary directory on disk with a one-time warning on stderr. The directory is now also removed on SIGTERM and SIGINT and at exit, not only when the run ends normally; SIGKILL cannot be caught, and the next run removes a directory whose process is gone (`extractors/wsconfig.py`, `test_aaa.py`)
- Saved reports, the console, log records, MCP results and LLM prompts mask secrets S.O.N.I.C. was never given by shape, not only the keys it loaded and `sk-ant-` keys: other provider keys, AWS access key ids, GitHub and Slack tokens, JWTs, PEM private keys, Authorization Basic and Bearer credentials, and `password=`/`secret=`/`key=` style values, from one list every path shares (`utils/credentials.py` `SECRET_SHAPES`; `test_credentials.py` tests each shape and that OIDs, MAC addresses and hashes are left alone)
- SIP `Authorization` and `Proxy-Authorization` headers went into the summary sent to the LLM as captured, Digest `response=` included. They are now masked at extraction (`extractors/tshark.py` `mask_sip_credentials`, on the tshark summary, the scapy fallback and tshark's raw output): the Digest response and `auts`, and Basic or Bearer credentials, become `[MASKED]`, while username, realm, nonce, algorithm and qop stay visible; `auth_info` keeps no part of the response. The README says what is sent to the LLM (`test_sip_credentials.py`: the extraction, the LLM prompt and the CLI report)
- SDP media keys reached the LLM through the scapy fallback's raw SIP text: an SDES SRTP master key (`a=crypto:... inline:`), an `a=key-mgmt` payload such as MIKEY, a `k=` key. They are masked at extraction, keeping the crypto suite, lifetime and MKI and the key-mgmt protocol name, and are one of the shapes every output path masks (`utils/credentials.py` `mask_sdp_keys`; `test_sip_credentials.py`, `test_credentials.py`)

---

## [3.1.0] - 2026-10-25

### Added
- 🛰️ **Network and VPN detectors** (deterministic, no LLM)
  - IPsec / VPN: IKEv1 and IKEv2 outcomes per IKE SA, cleartext NOTIFY errors (NO_PROPOSAL_CHOSEN and others), retransmissions without reply, rekeys, ESP flows with sequence gaps and duplicates, NAT-T, and an encrypted or cleartext verdict per peer pair
  - GRE / NHRP (DMVPN): GRE tunnels and keys, NHRP registrations, resolutions, redirects and error indications, hub and spoke roles, spoke-to-spoke tunnels
  - Routing health: BGP sessions (OPEN, NOTIFICATION decoded, resets, End-of-RIB, refused TCP 179), OSPF per link (timer, mask, area, auth, MTU mismatches, one-way neighbors, DR/BDR), EIGRP (K-value and AS mismatches, goodbyes, hold time expiry), routing over GRE, and a failover timeline
  - Reachability: ICMP echo loss, RTT and outage windows, ICMP errors with decoded codes, ARP without replies, duplicate IPs, protocol and conversation summary
  - One entry point (`analyzers/network_orchestrator.py`) that reads the capture once, runs every detector that applies, and runs the existing SIP quality path unchanged when SIP is present
- 🌐 **New MCP tools**: `analyze_network_pcap`, `analyze_vpn_pcap`, `analyze_routing_pcap`, with descriptions written so an agent learns each tool from the tool itself; the server now sends instructions naming which tool fits which capture
- 🔧 **CLI mode** `--network-only`, with `--detectors`, `--peers`, `--display-filter`, `--max-packets` and `--json`; the report is written as markdown or JSON
- 🧪 **Tests and fixtures**: `test_network_detectors.py` (every detector on both the tshark and scapy backends, backend parity, entry point behaviour), `test_network_mcp.py` (the tool functions and a real MCP stdio handshake), and 14 small deterministic fixtures from `tests/fixtures/generate_fixtures.py`

### Changed
- MCP server name is now "S.O.N.I.C. VoIP and Network Analyzer"; the existing five tools are unchanged
- `run_phase2_tests.sh` checks the new MCP tools and runs the network detector tests
- `.gitignore` allows the synthetic fixtures under `tests/fixtures/`

### Technical
- **Extraction**: `extractors/network.py` streams tshark field output (`-T fields`) so memory stays flat, checks which tshark fields exist and reports missing ones, and falls back to scapy with byte-level parsers that produce the same records
- **Report schema**: `sonic.network_report/1`; every section has `status`, `verdict` and `issues` with stable codes and Wireshark frame numbers

---

## [3.0.0] - 2026-03-04

### Added
- 🌐 **NetClaw MCP Server Integration** (MCP Server #38)
  - FastMCP-based Model Context Protocol server for AI assistant integration
  - 5 MCP tools: analyze_pcap, quick_quality_check, list_llm_providers, analyze_batch_pcaps, analyze_pcap_partial_streaming
  - Comprehensive 18-phase integration guide: NETCLAW_SONIC_INTEGRATION_GUIDE.md
  - Full support for Claude Desktop, Cline, and MCP-compatible clients
  - Slack-native workflows for VoIP diagnostics

- 📊 **What Is Analyzed Section** in README
  - Detailed "Top 10 SIP Issues Analyzed by S.O.N.I.C." with coverage matrix
  - Comprehensive symptom detection for each issue category
  - Coverage tracking table showing analysis depth per issue type
  - Clear detection mechanisms and diagnostic approaches

- 🔒 **Phase 3: Advanced Auth Reporting & Visualization**
  - Security posture grading (A+ to F grades)
  - Auth security factors: algorithm strength, qop usage, REGISTER success rates
  - Realm/server mapping with ASCII tree structure
  - Challenge/response sequence diagrams (ASCII for console, Mermaid for markdown)
  - 6-type upgrade recommendation engine
  - Modal analysis: Mermaid sequence diagram generation for markdown reports

- 🔐 **PII Sanitization**
  - Removed sensitive IP addresses from TEST_CAPTURE.md sample output
  - Sanitized SIP URIs and endpoint identifiers
  - Example data uses strictly RFC-defined example ranges (10.0.0.0/8)
  - No real phone numbers or user authentication data in samples

- 📚 **Documentation Updates**
  - Updated README.md with NetClaw integration section (v3.0)
  - Removed deprecated sip_test.py file references (use sonic.py instead)
  - Removed deprecated batch_test.py references
  - Removed sip_server.py and raw_test.py documentation (not part of v3.0 scope)
  - Updated SIP_DOCUMENTATION.md to reference active tools only
  - All examples now use canonical sonic.py entry point

### Changed
- **Documentation Focus**: Shifted from development/testing tools to production VoIP analysis
- **Main Entry Point**: Canonical entry point is now sonic.py (via sonic --help or python3 sonic.py)
- **MCP Integration**: Now primary integration path for external AI agents via NetClaw
- **Version Identifier**: Updated to 3.0 (NetClaw MCP Integration + Phase 3 Auth Reporting)

### Deprecated
- sip_test.py usage in documentation (legacy testing tool, superseded by sonic.py --model combined)
- batch_test.py usage (superseded by sonic.py with directory handling)
- sip_server.py references (out of scope for VoIP analysis tool)
- raw_test.py references (protocol testing framework, not part of analysis)

### Removed
- Deprecated test script references from README
- Outdated SIP server implementation documentation
- Non-functional batch testing documentation
- Raw protocol testing framework from primary documentation

### Security
- PII removed from sample reports
- Example data uses RFC 5737 documentation ranges
- No sensitive authentication credentials in samples
- Sanitized phone numbers and user identifiers

### Technical
- **MCP Server**: stdio-based JSON-RPC 2.0 implementation with FastMCP
- **Quality Scoring v2**: Integrated auth security penalties into weighted scoring
- **Auth Grading Algorithm**: A+ to F scale based on RFC compliance
- **Report Generation**: Enhanced markdown support with Mermaid diagram blocks
- **Testing**: All 15 Phase 3 tests passing, comprehensive validation suite

---

## [2.0.0] - 2025-07-13

### Added
- 🎵 **Comprehensive RTP Stream Analysis**: Full SIP-to-RTP correlation workflow
  - SDP parsing from SIP INVITE messages  
  - RTP packet correlation using IP addresses and ports from SDP
  - Media quality metrics (packet loss, jitter, sequence gap analysis)
  - Industry-standard quality thresholds and assessments

- 🤖 **Enhanced AI Analysis**: Dual-model approach for optimal accuracy
  - Fast model (qwen2.5:0.5b): Structured JSON output with reliable format compliance
  - Detailed model (qwen2.5vl:7b): Comprehensive natural language insights
  - Combined analysis merging strengths of both models

- 🔧 **Codec-Aware Diagnostics**: Comprehensive codec knowledge database
  - G.711 (PCMU/PCMA): High quality analysis with bandwidth monitoring
  - G.729: Low bitrate codec with packet loss sensitivity checks
  - Opus: Adaptive codec with dynamic payload type handling
  - iLBC: Packet loss resistant codec with compatibility checks

- 📊 **Enhanced Data Extraction**: Multi-protocol packet capture analysis
  - Enhanced tshark extraction with RTP field correlation
  - SIP signaling + RTP media stream analysis
  - Robust fallback to scapy when tshark unavailable

- 📈 **Quality Metrics & Thresholds**: Industry-standard VoIP quality assessment
  - Packet Loss: <1% excellent, 1-3% good, >5% poor
  - Jitter: <20ms excellent, 20-50ms acceptable, >50ms problematic
  - Sequence gap analysis for call quality assessment

### Enhanced
- **SIP Message Analysis**: Improved parsing of SIP headers and SDP payloads
- **Error Handling**: Comprehensive format conversion for AI model responses
- **Visual Output**: Rich console indicators with emojis and progress tracking
- **Documentation**: Complete API documentation and usage examples

### Technical
- **Architecture**: Enhanced extraction pipeline with SIP-RTP correlation
- **Performance**: Optimized for 20-35 second combined analysis times
- **Reliability**: Multiple fallback strategies for robust operation
- **Validation**: Pydantic models for structured output validation

## [1.0.0] - 2025-01-13

### Added
- Initial release of S.O.N.I.C. (SIP Observation and Network Inspection Console)
- Basic SIP message extraction and analysis
- AI-powered diagnostic capabilities using DSPy framework
- Support for pcap/pcapng file analysis
- tshark and scapy-based packet extraction
- Multiple output formats (JSON, raw, codec types)
- Comprehensive error handling and format conversion

### Features
- SIP call flow analysis
- Audio quality diagnostics
- Call termination analysis
- User-Agent detection
- Response code analysis
- Visual progress indicators

---

## Legend
- 🎵 Media/RTP related features
- 🤖 AI/Analysis enhancements  
- 🔧 Codec-specific improvements
- 📊 Data extraction/processing
- 📈 Quality metrics and assessment
- 📋 Documentation and usability
