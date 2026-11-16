# S.O.N.I.C. gRPC Troubleshooting (gNMI, gNOI, any gRPC service)

## 🚀 Overview

S.O.N.I.C. reads gRPC from a packet capture and says why a client and a server did not get along: which RPCs ran, what each one returned (`grpc-status` by name and `grpc-message`), what HTTP/2 did underneath (resets, GOAWAY, flow control, keepalive pings, limits), what the TLS handshake shows without keys, and whether a credential crossed the network in cleartext gRPC metadata. It is deterministic (no LLM) and uses Wireshark's own HTTP/2, HPACK, gRPC, TLS and protobuf dissectors through `tshark`, so the hard parts (TCP reassembly, TLS decryption from a key log, HPACK header decompression with its Huffman coding and dynamic table) are Wireshark's.

```bash
python3 sonic.py --file gnmi.pcap --grpc                                    # summary, report in gnmi.pcap.grpc.md
python3 sonic.py --file gnmi.pcap --grpc --json                             # the full report as JSON on stdout
python3 sonic.py --file srl.pcapng --grpc --tls-secrets-log /tmp/keys.log   # decrypt TLS with the client's key log
python3 sonic.py --file srl-with-secrets.pcapng --grpc                      # the same, secrets inside the pcapng
python3 sonic.py --file gnmi.pcap --grpc --grpc-ports 7777                  # also decode tcp/7777 as HTTP/2
python3 sonic.py --fetch-grpc-protos                                        # .proto files for Wireshark (optional)
```

Over MCP the tool is `analyze_grpc_pcap` (prompt `troubleshoot_grpc`); the cleartext audit (`audit_cleartext_pcap`) uses the same decoding to name cleartext HTTP/2 as gRPC and to flag credentials in its metadata. Its default allowlist (`encrypted`) passes TLS-wrapped gRPC only when the ServerHello chose a suite that encrypts: a NULL or RFC 9150 integrity-only suite (`TLS_SHA256_SHA256`) fails it as cleartext, and a session captured without its handshake passes only as encrypted, unverified.

## 🔎 How it finds gRPC

Three `tshark` passes, each streamed, so memory stays flat:

1. **Discovery** (`-T fields`, a narrow display filter): every SYN, SYN-ACK and RST, every TLS ClientHello and ServerHello (SNI, ALPN), and the payload segments on the well-known gRPC ports. The SYN's destination is the server, so each flow is named by its service port (`tcp/50001`), not by the client's ephemeral port.
2. **Prefaces**: every segment that opens with the HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), on any port.
3. **HTTP/2** (`-T pdml -Y http2`), with decode-as for:
   - each port where the preface was seen (cleartext HTTP/2, h2c): `-d tcp.port==P,http2`;
   - each well-known gRPC port whose connections are not TLS, even without a captured preface;
   - TLS on a gRPC port, or offering ALPN `h2`: `-d tcp.port==P,tls`, with HTTP/2 inside following ALPN or Wireshark's TLS heuristic (only decrypted with a key log);
   - `ports` / `--grpc-ports` given by the caller.

The PDML tree keeps each HTTP/2 frame with its own fields, so headers, SETTINGS, WINDOW_UPDATE, PING, RST_STREAM, GOAWAY and DATA stay attributed to the right stream. gRPC messages are framed from the DATA bytes (1 flag byte, 4 length bytes, the message) by S.O.N.I.C. itself.

| Port | Service |
|---|---|
| 9339 | gNMI and gNOI (IANA `gnmi-gnoi`) |
| 9340 | gRIBI (IANA) |
| 9559 | P4Runtime (IANA) |
| 57400 | gNMI on Nokia SR Linux, Cisco IOS XR |
| 6030 | gNMI on Arista EOS |
| 50001 | gNMI on Stratum |
| 50051 | a common gRPC default (Cisco NX-OS gNMI) |
| 50052 | gNMI insecure on Cisco IOS XE |
| 32767 | gNMI on Juniper Junos |

### tshark dissectors and preferences used

| What | How |
|---|---|
| HTTP/2 framing and HPACK | the `http2` dissector, by decode-as on `tcp.port` |
| TLS | the `tls` dissector (by decode-as on gRPC ports, and its TCP heuristic elsewhere) |
| Decryption | `-o tls.keylog_file:PATH`, and a pcapng's Decryption Secrets Block (tshark reads it by itself) |
| Out-of-order segments | `-o tcp.reassemble_out_of_order:TRUE`, then without it for a connection that stayed undecoded (see below) |
| Decryption coverage | `-T fields` over `tls.handshake.type`, `tls.handshake.random`, `tls.handshake.certificate`, `tls.app_data_proto` |
| gRPC and protobuf (optional) | `-o uat:protobuf_search_paths:"DIR","TRUE"` and `-o protobuf.pbf_as_hf:TRUE` |
| Output | `-T pdml -J "ip ipv6 tcp tls http2 [protobuf]"` |

Verified with TShark (Wireshark) 3.6.2. The report's `capture.tshark` names the version that ran and `capture.decode_as` the options used.

## 📋 What the report holds

- `verdict` and `summary` (connections, RPCs, `rpc_status` counts, cleartext credentials).
- `connections[]`: `flow`, `service` (`tcp/<port>`), `service_name`, `server_known_by` (`syn`, `syn-ack`, `preface`, `client_hello`, `port`), `transport` (`cleartext`, `tls`, `tls (decrypted with the key log)`), `detected_by` (`preface`, `alpn h2`, `grpc port`), `protocol` (`grpc`, `http2`, `tls, h2 offered`), `services`, `settings` per side, `pings` (sent, acked, median round trip, interval), `goaways`, `rst_streams`, `flow_control.stalls`, `oversize_frames`, `oversize_header_lists`, `tcp_resets`, `credential_keys`, `metadata_keys` (names only), `capabilities` (the gNMI Capabilities answer on that connection), `tls`.
- `rpcs[]`: `stream_id`, `method`, `family` (gNMI, gNOI, gRIBI, P4Runtime, gNSI, gRPC health, gRPC), `authority`, `content_type`, `user_agent`, `grpc_timeout_s`, `request` and `response` (`messages`, `bytes`, `largest`, `compressed`), `http_status`, `grpc_status`, `grpc_status_name`, `grpc_message`, `trailers_only`, `outcome` (`ok`, `error`, `reset`, `incomplete`), `reset`, `timing` (`to_first_response_ms`, `to_end_ms`), `frames`, `state_changing` (Set, gNOI Reboot, SetPackage, file Put and Remove, certificate Install and Rotate, ...), `decoded`, `wireshark_protobuf` (with .proto files) and `diagnosis`.
- `credentials[]`: `flow`, `service`, `key`, `cleartext`, `transport`, `requests`, `first_frame`, `frames`, `value: "masked"`.
- `tls_decryption`: `verdict`, `decrypted`, `total`, `secrets_source` and `sessions[]` (`flow`, `service`, `tcp_stream`, `client_hello_frame`, `version`, `decrypted`, `handshake_decrypted`, `application_data`, `secret_in` (`key log`, `pcapng`), `labels`, `reason`), for every TLS session in the capture.
- `issues[]` (errors first, with Wireshark frame numbers), `timeline`, `capture` and `limits`.

### Issue codes

| Code | Meaning |
|---|---|
| `GRPC_<STATUS>` | an RPC ended with that grpc-status (`GRPC_UNAUTHENTICATED`, `GRPC_UNIMPLEMENTED`, `GRPC_INVALID_ARGUMENT`, `GRPC_DEADLINE_EXCEEDED`, `GRPC_RESOURCE_EXHAUSTED`, `GRPC_UNAVAILABLE`, ...) |
| `GRPC_NO_STATUS` | no trailers before the capture ended (info for a STREAM or POLL subscription, which stays open) |
| `GNMI_INBAND_ERROR` | status OK, but the response carried the deprecated gNMI `error` field |
| `GRPC_CLEARTEXT` | gRPC over cleartext HTTP/2 |
| `CLEARTEXT_CREDENTIAL` | a credential key in cleartext gRPC metadata, one per key and flow |
| `CREDENTIAL_IN_METADATA` | the same key over TLS, seen only because the key log decrypted it (info) |
| `HTTP2_RST_STREAM` | a stream reset, with the error code (a client CANCEL after the server's trailers is normal cleanup, info) |
| `HTTP2_GOAWAY` | a GOAWAY, with last stream id, error and debug data, and the streams it left unprocessed |
| `HTTP2_TOO_MANY_PINGS` | GOAWAY ENHANCE_YOUR_CALM `too_many_pings`: the client's keepalive is more frequent than the server allows |
| `HTTP2_FLOW_CONTROL_STALL` | a sender's connection or stream window reached 0 with its stream open, and for how long |
| `HTTP2_FRAME_TOO_LARGE` | a frame over the peer's SETTINGS_MAX_FRAME_SIZE |
| `HTTP2_HEADER_LIST_TOO_LARGE` | a header list over the peer's SETTINGS_MAX_HEADER_LIST_SIZE |
| `HTTP2_MAX_CONCURRENT_STREAMS_EXCEEDED` | more open streams than the server's SETTINGS_MAX_CONCURRENT_STREAMS |
| `GRPC_MESSAGE_OVER_DEFAULT_LIMIT` | a message over the common 4 MiB default receive limit |
| `HTTP2_PREFACE_UNANSWERED` | a cleartext preface the server never answered with HTTP/2 (often a TLS-only port) |
| `HTTP2_HPACK_DECODE_FAILED` | header blocks that name HPACK table entries the capture never saw (it started mid-connection) |
| `TCP_RESET_DURING_RPC` | a TCP reset while RPCs were open (the client sees UNAVAILABLE) |
| `TLS_ALERT` | a TLS alert, with who sent it and what it means |
| `TLS_CERT_NO_IP_SAN` | the client sent no SNI (so it most likely dialled an IP) and the certificate has no IP SAN for it |
| `TLS_NO_SNI` | the same in TLS 1.3 without a key log, where the certificate cannot be seen (info) |
| `TLS_NO_SERVER_HELLO` | a ClientHello nobody answered with TLS |
| `GRPC_TLS_NOT_DECRYPTED` | TLS without a usable key log: only the handshake is visible (info) |
| `TLS_SESSION_NOT_DECRYPTED` | a TLS session the given secrets did not decrypt, with why (no secret for its ClientHello random, no ClientHello in the capture, only the handshake secrets) |
| `TLS_SECRETS_IN_CAPTURE` | the pcapng carries TLS secrets in a Decryption Secrets Block, used with no separate key log: anyone with the file can read what they cover (info) |

## 🔐 Credentials in metadata

gNMI clients send `username` and `password` as gRPC metadata; other services use `authorization`, `x-api-key`, tokens or cookies. HPACK Huffman-codes header values, so the value is not in the capture as plain bytes and a byte search finds nothing; Wireshark's HPACK decoder does. S.O.N.I.C. reports each credential key once per flow, with the frames and the request count, and **never the value**:

- header values are masked in the extractor, before anything else sees them: only the values of an allowlist of names (pseudo-headers, `content-type`, `grpc-status`, `grpc-message`, `user-agent`, `grpc-timeout`, ...) are kept; every other value is replaced, and a credential-like name is flagged;
- the masked values are kept only in memory, so any echo of one elsewhere (for example inside a `grpc-message`) is scrubbed from the report by value;
- the report, the markdown and JSON files and every MCP result also pass through S.O.N.I.C.'s redaction of API keys.

## 🔒 TLS: without keys, and with a key log

Without keys the TLS detector reports SNI, ALPN offered (and chosen, in TLS 1.2), the version and suite, the certificate (TLS 1.2 and older: subject, issuer, validity at capture time, DNS and IP SANs; TLS 1.3 encrypts it), and alerts with who sent them and what they mean:

| Alert | From | Meaning |
|---|---|---|
| `unknown_ca` | client | the client does not trust the CA that signed the server's certificate (self-signed or private CA): give it the CA (`gnmic --tls-ca`) |
| `bad_certificate`, `certificate_unknown` | client | the client refused the server's certificate, often the name: an address the client dialled must be an IP SAN |
| `certificate_expired` | client | outside its validity period, or a clock is wrong |
| `bad_certificate`, `certificate_required` | server | mutual TLS: the server refused or did not get a client certificate |
| `no_application_protocol` | either | no common ALPN; a gRPC client needs `h2` |
| `handshake_failure`, `protocol_version` | either | no common suite, group or version |

A client that sends no SNI most likely dialled an IP address (RFC 6066 forbids IP literals in SNI); if the certificate has no IP SAN for that address, a verifying client refuses it, which Go reports as a certificate that does not contain any IP SANs. S.O.N.I.C. flags it (`TLS_CERT_NO_IP_SAN`).

**With a key log** the sessions are decrypted and every RPC check runs on them. Have the client write a key log while capturing: gnmic with `--log-tls-secret` (it writes `<target>.tlssecret.log`), Python clients and curl with `SSLKEYLOGFILE` set, a Go program through `tls.Config.KeyLogWriter` (Go's TLS does not read `SSLKEYLOGFILE` by itself). Then pass the file as `keylog_file` (MCP) or `--tls-secrets-log` (CLI; S.O.N.I.C. keeps the word key out of CLI option names). The key log is handed to tshark by path: it is never copied to or named in a report. To say which sessions it covers S.O.N.I.C. reads its first two columns only, the label and the ClientHello random (`extractors/tls_secrets.py`); the secret column is dropped as each line is read. With it, the TLS 1.3 certificate is read too.

**Secrets inside the capture.** A pcapng can carry the key log in a Decryption Secrets Block: `editcap --inject-secrets tls,KEYLOG in.pcap out.pcapng`. tshark decrypts such a file by itself, so no `keylog_file` is needed; the report says the secrets came from the pcapng (`capture.tls_secrets`, transport `tls (decrypted with the secrets in the pcapng)`) and raises `TLS_SECRETS_IN_CAPTURE`, because whoever holds that file can read the sessions. A key log and embedded secrets can be used together, and each session is credited to the source that held its secret.

**Decryption coverage.** `tls_decryption` lists every TLS session in the capture and says whether the secrets decrypted it, which source held its secret, and when it was not decrypted, why: no line for its ClientHello random (the key log is from another session or client), no ClientHello in the capture (the session began before it, so no secret can be matched), or only the handshake secrets. A session the secrets did not open is never skipped silently: it is a `TLS_SESSION_NOT_DECRYPTED` warning, and the total reads `3 of 4 TLS session(s) decrypted with the key log; not decrypted: ...`.

**TShark 3.6 and out-of-order reassembly.** S.O.N.I.C. asks tshark to reassemble out-of-order TCP segments. TShark 3.6 never fills a gap with a segment it marks as a retransmission, so a direction whose first segment arrived late is never reassembled: on the SR Linux capture below each client's first ClientHello (1.5 KB with a post-quantum key share, two segments) had its first segment arrive after the second, and with out-of-order reassembly tshark dissected no ClientHello, matched no secret and decrypted nothing. A connection that should carry HTTP/2 from both sides (TLS with secrets, or a cleartext preface) and does not is therefore read again without out-of-order reassembly, and the richer reading is kept; `capture.reread_without_out_of_order` and `capture.warnings` name each one.

## 🧬 gNMI and gNOI decoding, and .proto files

Without any .proto file S.O.N.I.C. decodes, from the gNMI field numbers:

- **Capabilities**: gNMI version, supported encodings, model count and names;
- **Get**: paths, data type, encoding (an absent field means JSON, the proto3 default), and on the response notifications and updates (an empty notification for an absent path) and an in-band error;
- **Set**: the paths deleted, replaced and updated (counts and paths, never values) and the results;
- **Subscribe**: mode (`STREAM`, `ONCE`, `POLL`), encoding, each subscription's path, mode and sample interval, `updates_only`, Poll requests, and on the responses notifications, updates, `sync_response` and in-band errors;
- **gNOI system.Time**: the target's clock against the capture's; **gRPC health**: `SERVING`, `NOT_SERVING`.

A requested encoding is checked against the Capabilities answer on the same connection, so a refused Get says "the request asked for JSON_IETF; Capabilities on this connection lists only PROTO".

With .proto files, Wireshark's protobuf dissector names every message type (`wireshark_protobuf`: `gnmi.GetRequest`, `gnoi.system.TimeResponse`, ...) and S.O.N.I.C. reads a few of its enum fields. **S.O.N.I.C. does not ship the files.** They are Apache-2.0 (openconfig/gnmi, openconfig/gnoi) and BSD-3-Clause (the protobuf well-known types), S.O.N.I.C. is MIT, and keeping them out keeps its licensing single. `python3 sonic.py --fetch-grpc-protos [DIR]` downloads them on request from GitHub at pinned commits, checks each file's SHA-256, and writes them with their licenses into `~/.cache/sonic/grpc-protos` (or DIR):

| Source | Pin | Files |
|---|---|---|
| openconfig/gnmi | v0.14.1 (8b7dd494) | gnmi.proto, gnmi_ext.proto |
| openconfig/gnoi | v0.8.0 (3d3c7f19) | types, common, system, cert, file, healthz (os.proto left out: it pulls in openconfig/bootz and gnsi) |
| protocolbuffers/protobuf | v3.20.3 (fe271ab7) | any, descriptor, duration, timestamp (Wireshark 3.6 rejects newer descriptor.proto syntax) |

An analysis uses `proto_paths` / `--proto-path`, else `SONIC_PROTO_PATH`, else that directory when it exists. Nothing is downloaded during an analysis.

## 🛰️ What targets were measured to do (2026-11-15)

| Target | gNMI | Facts |
|---|---|---|
| Nokia SR Linux 26.7.2 | 0.10.0 on tcp/57400, TLS 1.3 (`TLS_AES_128_GCM_SHA256` after a HelloRetryRequest), self-signed certificate (CN `srl`) without an IP SAN | encodings PROTO, ASCII, JSON_IETF plus vendor values; plain JSON refused with UNIMPLEMENTED; a wrong password gets UNAUTHENTICATED; an absent path returns an empty notification; Set is all or none; a Subscribe ONCE ends with the trailers and then RST_STREAM NO_ERROR from the server (RFC 9113 8.1, reported as info). Decrypted with the client's key log (2026-11-16): ten calls (Capabilities, Get, Set, Subscribe) by name, all OK, 12 to 18 ms each, `username` and `password` in every call's metadata (masked) |
| Stratum (opennetworking/mn-stratum) | 0.7.0 on tcp/50001, plaintext | PROTO only (Get with JSON or JSON_IETF refused INVALID_ARGUMENT "Get response can only be encoded as PROTO."); no authentication; Subscribe ONCE answers with the deprecated in-band `error` "Unsupported path."; gNOI os.Verify UNIMPLEMENTED |

## ⚠️ Limits

- Wireshark needs the start of each HTTP/2 connection: HPACK headers are compressed against a table both sides build from the first request on, so a capture that begins mid-connection may leave headers undecodable (`HTTP2_HPACK_DECODE_FAILED`).
- Without a key log (or secrets embedded in a pcapng), TLS-wrapped gRPC shows only the handshake; TLS 1.3 encrypts the certificate too.
- A session's secret is matched by its ClientHello random: a session whose ClientHello is not in the capture cannot be decrypted, whatever the key log holds.
- HTTP/2 that upgraded from HTTP/1.1 (`Upgrade: h2c`) on a port without a preface is not decoded.
- Flow control is followed only when the connection's start was captured.
- The 4 MiB message limit is the common default; the receiver's real limit is configuration and not on the wire.
- Message values are never decoded; other services show sizes and counts, or Wireshark's protobuf view.

## 🧪 Tests

`test_grpc.py` has 41 tests and `test_tls_audit.py` has 29 that cover this path. The full reference, with per-file counts, is in [TESTING.md](TESTING.md). The TLS decryption sequence is in [ARCHITECTURE.md](ARCHITECTURE.md#2-sequence-grpc-and-tls-decryption).

```bash
python3 -m unittest -q test_grpc
SONIC_GRPC_CAPTURES=/path/to/captures python3 -m unittest -q test_grpc      # also the real captures (gnmi-plaintext.pcap,
                                                                            # netconf-restconf-ssh.pcap, gnmi-tls-srlinux.pcap with
                                                                            # gnmi-tls-srlinux.keylog)
SONIC_PROTO_PATH=~/.cache/sonic/grpc-protos python3 -m unittest -q test_grpc # also Wireshark's protobuf view
```

The synthetic fixtures (`tests/fixtures/generate_grpc_fixtures.py`, names start with `grpc_`) cover what no real capture on hand shows: RST_STREAM, GOAWAY, a flow-control stall, limits exceeded, TLS alerts. The key log path is tested on TLS 1.3 sessions the test builds with Python's `ssl` module (real TLS, never committed): one session with its key log, the same with the key log embedded in a pcapng by editcap, and two sessions with the key log of one, for coverage. The real TLS gNMI capture of SR Linux and its key log (`TestRealTlsCapture`) prove decryption end to end: the calls expected, the credential values and the key log's secrets are read from the capture with tshark at test time, never written in the test, and the assertions are that every call is named with its status and timing and that no value or secret appears in the report, the CLI output or the markdown file.
