# S.O.N.I.C. RESTCONF and REST Troubleshooting (HTTP/1.1 and HTTP/2, TLS)

## Overview

S.O.N.I.C. reads RESTCONF (RFC 8040) and any REST-over-HTTP exchange from a packet capture
and says what each request asked, what it got back, and whether a credential crossed the
network. It decrypts TLS with the same key log the gRPC troubleshooter uses, reads HTTP/1.1
and HTTP/2 with Wireshark's own HTTP, HTTP/2, HPACK and TLS dissectors through `tshark`, and
is deterministic (no LLM).

```bash
python3 sonic.py --file restconf.pcap --restconf                              # summary, report in restconf.pcap.restconf.md
python3 sonic.py --file restconf.pcap --restconf --json                       # the full report as JSON on stdout
python3 sonic.py --file restconf-tls.pcapng --restconf --tls-secrets-log keys.log  # decrypt TLS with a key log
python3 sonic.py --file restconf-secrets.pcapng --restconf                    # the same, secrets inside the pcapng
python3 sonic.py --file api.pcap --restconf --http-ports 9443                 # also decode tcp/9443 as HTTP(S)
```

Over MCP the tool is `analyze_restconf_pcap`. The summary goes to `--save_file`, or to
`<capture>.restconf.md`; a path ending in `.json` writes JSON.

## Where it finds HTTP

- the well-known HTTP(S) ports (80, 443, 8080, 8443, 8008, 8888, 4443);
- a TLS session offering ALPN `h2` or `http/1.1`, on any port (decrypted only with a key log);
- a cleartext HTTP/2 connection by its preface (`PRI * HTTP/2.0`), on any port (h2c);
- extra ports from `--http-ports` / `ports`.

Each flow is named by its service port (the SYN's destination). A RESTCONF request is one
whose path starts with `/restconf` (or `/.well-known/host-meta`) or whose Content-Type is a
`application/yang-data+...` / `application/yang-patch+...` / `application/yang.api+...` media
type; everything else HTTP is reported as plain REST.

### tshark dissectors and preferences used

| What | How |
|---|---|
| HTTP/1.1 (request/response pairing, timing, body) | the `http` dissector, by decode-as on `tcp.port` |
| HTTP/2 framing and HPACK | the `http2` dissector (shared with the gRPC path) |
| TLS | the `tls` dissector (decode-as on HTTP(S) ports, ALPN inside) |
| Decryption | `-o tls.keylog_file:PATH`, and a pcapng's Decryption Secrets Block (tshark reads it itself) |
| Out-of-order segments | `-o tcp.reassemble_out_of_order:TRUE`, then without it for a session left undecoded |
| HTTP/1.1 body (for RESTCONF errors) | `http.file_data`, paired to the request by `http.request_in` |

Verified with TShark (Wireshark) 3.6.2. The report's `capture.tshark` names the version that
ran and `capture.decode_as` the options used.

## What the report holds

- `verdict` and `summary` (connections, requests, RESTCONF requests, status counts, RESTCONF
  errors, cleartext credentials).
- `connections[]`: `flow`, `service`, `transport` (`cleartext`, `tls (decrypted)`,
  `tls (not decrypted)`, `tls (no key log)`), `http_versions`, `restconf`, `requests`, `sni`,
  `alpn_offered`, `decrypted`.
- `requests[]`: `method`, `path`, `host`, `status`, `phrase`, `request_content_type`,
  `response_content_type`, `request_body_bytes`, `response_body_bytes`, `timing_ms`,
  `location`, `restconf`, `restconf_errors` (`error-type`, `error-tag`, `error-app-tag`,
  `error-path`, `error-message`), `credentials`, `frames`, `outcome`.
- `credentials[]`: `flow`, `service`, `header`, `kind` (`authorization`, `cookie`, `token`),
  `scheme` (Basic, Bearer, ...), `cleartext`, `requests`, `value: "masked"`.
- `tls_decryption`: `verdict`, `decrypted`, `total`, `secrets_source`, and `sessions[]` (per TLS
  session: whether it decrypted, which source held its secret, and why not).
- `issues[]`, `capture` and `limits`.

### Issue codes

| Code | Meaning |
|---|---|
| `RESTCONF_ERROR` | a request failed with an `ietf-restconf:errors` body, named by `error-tag` |
| `HTTP_CLIENT_ERROR` | a 4xx with no RESTCONF errors body |
| `HTTP_SERVER_ERROR` | a 5xx |
| `HTTP_NO_RESPONSE` | a request with no response before the capture ended |
| `CLEARTEXT_CREDENTIAL` | an Authorization, cookie or token header on cleartext HTTP (value masked) |
| `CREDENTIAL_IN_REQUEST` | the same header over TLS, seen only because the secrets decrypted it (info) |
| `HTTP_TLS_NOT_DECRYPTED` | a TLS session with no key log: only the handshake is visible (info) |
| `TLS_SESSION_NOT_DECRYPTED` | a TLS session the given secrets did not decrypt, with why |
| `TLS_SECRETS_IN_CAPTURE` | the pcapng carries TLS secrets in a Decryption Secrets Block (info) |

## Credentials, never shown

An Authorization header's scheme (Basic, Bearer, ...) is kept; its credential is masked. Cookie,
Set-Cookie and token headers (`X-Auth-Token`, `X-API-Key`, CSRF tokens, ...) are flagged by name
with the value dropped. The masking happens in the extractor, before anything else sees the value;
any echo of a value is then scrubbed from the report by value, and the whole report passes through
S.O.N.I.C.'s key redaction. Over cleartext each credential is a `CLEARTEXT_CREDENTIAL`; over TLS it
is a `CREDENTIAL_IN_REQUEST`, reported as present because the key log made it visible.

## TLS: with a key log, and without

With a key log (SSLKEYLOGFILE format, `--tls-secrets-log`), or the TLS secrets a pcapng carries in
a Decryption Secrets Block (`editcap --inject-secrets tls,KEYLOG in.pcap out.pcapng`, no key log
needed), the TLS sessions are decrypted and every request is read. The key log is handed to tshark
by path and never copied to a report; only its labels and ClientHello randoms are read, to say which
sessions it covers. `tls_decryption` lists every TLS session and, when one was not decrypted, why
(no secret for its ClientHello random, no ClientHello captured, only the handshake secrets).

Without a key log a TLS session shows only its handshake: the report names the connection, its ALPN
and SNI, and raises `HTTP_TLS_NOT_DECRYPTED`.

## RESTCONF error documents

A failure body of media type `application/yang-data+json` / `+xml` (RFC 8040 section 3.9) is parsed
into its `ietf-restconf:errors`: `error-type`, `error-tag`, `error-app-tag`, `error-path` and
`error-message`, in both JSON and XML. A successful response's body (a GET returning configuration)
is never decoded: only its Content-Type and size are reported.

## Limits

- TLS-wrapped RESTCONF/REST without a key log shows only the handshake; TLS 1.3 encrypts the
  certificate too.
- A session's secret is matched by its ClientHello random: a session whose ClientHello is not in the
  capture cannot be decrypted, whatever the key log holds.
- A capture that begins mid-connection may leave an HTTP/2 request without its method or path (HPACK
  state missing) or an HTTP/1.1 body unreassembled.
- Only RESTCONF error documents are parsed from a body; configuration is never decoded.
- RESTCONF event-stream notifications (`text/event-stream`) are reported as a long-lived GET; their
  contents are not decoded.

## Tests

```bash
python3 -m unittest -q test_restconf
```

The synthetic fixtures (`tests/fixtures/generate_restconf_fixtures.py`, names start with
`restconf_`) cover cleartext RESTCONF over HTTP/1.1 and h2c and a plain REST call. RESTCONF over
TLS 1.3 (HTTP/1.1 and HTTP/2) with its key log is built at test time with Python's `ssl` module
(real TLS, never committed), and the same session with its key log embedded in a pcapng by editcap.
No real RESTCONF-over-TLS capture with a key log is on this machine (the one RESTCONF capture,
`netconf-restconf-ssh.pcap`, is TLS 1.3 with no key log), so that proof is the synthetic TLS
sessions; `TestRealRestconfCapture` asserts the real capture shows only the handshake, the honest
"not decrypted" state.
