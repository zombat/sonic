# CodeQL alert triage

Maintainer notes on the CodeQL alerts raised against `main` at e827d7d (after the decryption work
of PR #6). Each alert is either fixed, with the commit that fixes it, or a false positive, with the
reason. Alerts are dismissed in the GitHub UI by the maintainer; this file is the record of why.

| Alert | Where | Verdict | Commit or reason |
|---|---|---|---|
| #1 | `utils/credentials.py` `write_redacted` | Fixed | 89825fc: redaction also masks secrets by shape (provider API keys, AWS key ids, GitHub and Slack tokens, JWTs, PEM private keys, Authorization Basic/Bearer credentials, `password=`/`secret=`/`key=` values), shared by `write_redacted`, `install_output_redaction`, `redact` and the LLM prompt through `redact_text` |
| #5 to #14 | console summaries and saved reports of the protocol tools | False positive | The values CodeQL traces are masked at extraction before any report exists, then output-redacted: HTTP/RESTCONF headers in `extractors/http_messages.py` (`_mask_credential`) and `extractors/http2.py` (headers masked by name, `secret_values` kept in memory only), gRPC metadata in `extractors/http2.py` and scrubbed by value in `analyzers/grpc_inspect.py` (`_scrub_rules`, `_scrub`), SNMP communities in `analyzers/snmp_inspect.py` (`"value": "masked"`, `_scrub`), AAA passwords and keys in `analyzers/aaa_inspect.py` (`"value": "masked"`, `_scrub`); every print goes through `install_output_redaction` (`sonic.py`, `mcp_server.py`) and every file through `write_redacted` |
| #15, #16 | tests | False positive | Not real credentials: synthetic placeholder literals the tests assert never appear in any output |
| #17, #18 | `extractors/wsconfig.py` (the preferences and UAT writes) | Fixed | e129384: the secret files go on tmpfs (`/dev/shm`) where there is one, so no key reaches a disk; without tmpfs a one-time warning says so; cleanup on SIGTERM, SIGINT and exit as well as the finally, and a directory left by SIGKILL is removed by the next run. Writing them is the design that keeps the keys off tshark's command line |
| #19 | `utils/http_reporting.py:40` | False positive | It prints `tls_decryption["verdict"]`, built in `analyzers/http_inspect.py` `_decryption_coverage` from session counts, flow addresses and `secrets["source"]`, which is one of the fixed strings "the key log" and "the secrets in the pcapng" (`_secrets_view`). No secret is read into it: the key log is parsed for labels and ClientHello randoms only, the secret column dropped (`extractors/tls_secrets.py`). CodeQL tracks the `secrets` name, not a secret value |
| #22 to #24 | `tests/fixtures/generate_aaa_fixtures.py` (lines 63, 88, 96) | False positive | MD5 is what RFC 2865 (User-Password hiding, Response Authenticator) and RFC 3579 (HMAC-MD5 Message-Authenticator) define; the fixture generator must use it to build valid RADIUS packets, with synthetic secrets. It hashes no real password and protects nothing |

Not CodeQL alerts, fixed alongside:

- ca1869b: SIP `Authorization` and `Proxy-Authorization` headers went into the summary sent to the LLM with
  the Digest `response=` (a hash an offline dictionary attack can test passwords against) and any Basic
  credential as captured; they are masked at extraction now (`extractors/tshark.py` `mask_sip_credentials`).
- dbab20e: SDP media keys (an SDES `a=crypto` `inline:` SRTP master key, an `a=key-mgmt` MIKEY payload, a
  `k=` key) reached the LLM through the scapy fallback's raw SIP text; they are masked at extraction and by
  every output path (`utils/credentials.py` `mask_sdp_keys`, one of `SECRET_SHAPES`), the suite name kept.

Alerts #2 to #4, #20 and #21 were not in the reviewed list and are not triaged here.
