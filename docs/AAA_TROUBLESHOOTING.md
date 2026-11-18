# S.O.N.I.C. TACACS+ and RADIUS Troubleshooting (de-obfuscated with a shared key)

## Overview

S.O.N.I.C. reads the AAA exchange (authentication, authorization, accounting) from a packet
capture and, given the shared key an operator supplies, de-obfuscates TACACS+ bodies and
decrypts the RADIUS User-Password so the exchange can be read. It uses Wireshark's own TACACS+
and RADIUS dissectors through `tshark`, is deterministic (no LLM), and never writes a key or a
recovered credential anywhere.

```bash
sonic --file aaa.pcap --aaa                           # versions and metadata, no key
sonic --file aaa.pcap --aaa --aaa-secrets keys.txt       # de-obfuscate with the shared key
sonic --file aaa.pcap --aaa --aaa-secrets keys.txt --json
```

Over MCP the tool is `analyze_aaa_pcap`. The summary goes to `--save_file`, or to
`<capture>.aaa.md`; a path ending in `.json` writes JSON.

## The shared-key file

The key file is a secret, read by path and never echoed. It names each key:

```
# AAA shared keys (throwaway for the capture being read)
tacacs_key:    <the TACACS+ server's shared key>
radius_secret: <the RADIUS server's shared secret>
```

`tacacs_key` (aliases `tacplus.key`, `tacacs`) and `radius_secret` (aliases
`radius.shared_secret`, `radius`) are both optional; give only the one you have. A file with a
single bare line (no `name:`) uses that one value for both protocols. The key is passed to
tshark through a **temporary WIRESHARK_CONFIG_DIR** (a private directory, each file `0600`, on
tmpfs at `/dev/shm` where there is one, so the key never reaches a disk; see the README's
Decryption section for the fallback and the cleanup on signals), never with `-o pref:VALUE` on
the command line, so the secret is not visible in the tshark
process's `argv` (where any user could read it from `ps` or `/proc`). tshark takes one
`tacplus.key` and one `radius.shared_secret`, so a capture mixing servers with different keys
decrypts only the sessions that key fits.

## What the report holds

- `verdict` and `summary` (RADIUS transactions, TACACS+ sessions, accepts, rejects, cleartext
  TACACS+ sessions, credentials recovered).
- `radius[]`: one row per transaction (`client`, `server`, `id`, `kind` auth/accounting,
  `request_code`, `response_code`, `result` accept/reject/challenge/accounted/no_response,
  `username`, `nas`, `calling_station`, `acct_status`, `authenticator_valid` (did the shared
  secret validate the Response Authenticator), `message_authenticator` (`request` and `response`:
  `valid`, `invalid`, `absent`, or `unchecked` without a secret), `credential` (`masked` when a
  User-Password was recovered)).
- `tacacs[]`: one row per session id (`client`, `server`, `user`, `action`, `service`,
  `priv_lvl`, `types` authentication/authorization/accounting, `authentication` (PASS, FAIL,
  GETPASS, ...), `authorization` (PASS_ADD, FAIL, ...), `accounting` (SUCCESS, ERROR),
  `cleartext` (the unencrypted flag was set), `credential` (`masked` when a password was
  de-obfuscated)).
- `credentials[]`: one row per recovered credential (`protocol`, `flow`, `username`, `kind`,
  `value: "masked"`).
- `issues[]`, `capture` and `limits`.

### Issue codes

| Code | Meaning |
|---|---|
| `AAA_ACCESS_REJECT` | a RADIUS Access-Request answered Access-Reject |
| `AAA_NO_RESPONSE` | a RADIUS Access-Request with no response |
| `RADIUS_BAD_AUTHENTICATOR` | a RADIUS response whose authenticator did not validate against the shared secret (the key is wrong, or the packet was altered) |
| `RADIUS_BAD_MESSAGE_AUTHENTICATOR` | a Message-Authenticator that did not verify against the shared secret (the key is wrong, or the packet was altered) |
| `RADIUS_NO_MESSAGE_AUTHENTICATOR` | an Access-Accept, Reject or Challenge without a Message-Authenticator: such a response can be forged by Blast-RADIUS (CVE-2024-3596); have the server send it on every response and the client require it |
| `AAA_AUTH_FAIL` | a TACACS+ authentication that FAILed |
| `AAA_AUTHORIZATION_FAIL` | a TACACS+ authorization that FAILed or ERRORed |
| `AAA_CLEARTEXT_TACACS` | a TACACS+ session sent with the unencrypted flag set: its body crosses the network readable |
| `AAA_CREDENTIAL_RECOVERED` | a password or User-Password was de-obfuscated with the key (value masked): anyone with the key and the capture can read it (info) |

## Credentials, never shown; the key, never read out

A recovered password (a de-obfuscated TACACS+ password, a decrypted RADIUS User-Password) is read
only to note that it was recovered; its value is masked at the source and any echo of it is
scrubbed from the report by value. The user name (who asked) is shown, as RESTCONF and gRPC show
it. The shared key itself is never read into a record, a log or a report, and is passed to tshark
only through the private config directory above.

## TShark 3.6.2

TACACS+ de-obfuscation uses the `tacplus.key` preference; RADIUS User-Password decryption and
Response Authenticator validation use `radius.shared_secret` with `radius.validate_authenticator`
(fields `radius.User_Password`, `radius.authenticator.valid` / `.invalid`, and for TACACS+
`tacplus.user`, `tacplus.flags`, `tacplus.body_authen_rep.status`, ...). Both preferences are
verified working with TShark (Wireshark) 3.6.2, set through a preferences file in a temporary
`WIRESHARK_CONFIG_DIR`. EAP, MS-CHAP and CHAP credentials are noted as present but not decrypted.

**Message-Authenticator.** tshark 3.6.2 shows a RADIUS Message-Authenticator but does not verify
it. S.O.N.I.C. verifies it as RFC 3579 section 3.2 defines: the HMAC-MD5, keyed with the shared
secret, of the whole message with the attribute's value zeroed, and in an Access-Accept, Reject or
Challenge with the Request Authenticator of the matching Access-Request in the authenticator
field. It reads the raw message (`udp.payload`) into memory for this and keeps only the verdict.
The check is tested against scapy's own independent implementation. An Accounting or other message's
Message-Authenticator is reported as `unchecked`.

## Tests

```bash
go test -race ./internal/analyze/aaainspect/...
```

The synthetic fixtures (`scripts/fixtures/generate_aaa_fixtures.py`, written to `testdata/fixtures/`, names start with `aaa_`) are
built with scapy: a RADIUS Access-Accept/Reject and Accounting flow with an encrypted
User-Password, valid authenticators, Message-Authenticators valid, absent and altered, and TACACS+ authentication, authorization and accounting
sessions plus a FAIL and one sent with the unencrypted flag. The keys and passwords are synthetic
placeholders; the tests pass the key through a key file written at test time and assert no key,
password or recovered credential appears in the report, the CLI output or the saved files.
