# S.O.N.I.C. SNMP Troubleshooting (v1, v2c and v3, with SNMPv3 USM decryption)

## 🚀 Overview

S.O.N.I.C. reads SNMP from a packet capture, names every message's version and, for v3, its
security level, flags v1/v2c community strings as cleartext credentials, and, given a USM users
file the operator supplies, decrypts SNMPv3 authPriv messages through tshark's `snmp_users`
table. For every v3 message it says whether it authenticated and decrypted, and when not, why.
Deterministic (no LLM); no passphrase or community value is ever written out.

```bash
sonic --file snmp.pcap --snmp                               # versions, levels, communities
sonic --file snmp.pcap --snmp --snmp-users users.txt        # also decrypt SNMPv3
sonic --file snmp.pcap --snmp --snmp-users users.txt --json
```

Over MCP the tool is `analyze_snmp_pcap` (`users_file` is a path on the server). The report goes
to `--save_file`, or to `<capture>.snmp.md`; a path ending in `.json` writes JSON.

## 🏷️ Naming every version

- **v1** and **v2c** (`snmp.version` 0 and 1): the community string is a cleartext credential,
  one `SNMP_CLEARTEXT_COMMUNITY` per version and address pair, value masked.
- **v3** (`snmp.msgVersion` 3): named by security level from msgFlags, `noAuthNoPriv`,
  `authNoPriv` or `authPriv`. The empty-user noAuthNoPriv probe a manager sends first is named
  `engine discovery`.
- An SNMPv3 **Report** from the agent is named by the `usmStats` counter it returns, which is the
  agent's own verdict on the request before it: `usmStatsUnknownUserNames`, `usmStatsWrongDigests`
  (auth failed), `usmStatsDecryptionErrors`, `usmStatsNotInTimeWindows`,
  `usmStatsUnsupportedSecLevels`, `usmStatsUnknownEngineIDs` (normal during discovery).

## 🔑 The USM users file (a secret, read by path)

Block format, one user per record, records separated by a blank line:

```
user: operator
engine_id: 0x80001f8880c223a740     # optional: only for a user keyed to one engine
auth: SHA                           # MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
auth_pass: <auth passphrase>
priv: AES                           # DES, AES, AES-192, AES-256
priv_pass: <privacy passphrase>
```

or CSV, one user per line: `user,auth,auth_pass,priv,priv_pass[,engine_id]` (a header row whose
first column is `user` is skipped). net-snmp's spellings and tshark's own labels are both accepted.
An algorithm tshark 3.6.2 does not offer is refused before tshark runs, naming the user and the
algorithm and never a passphrase. A passphrase holding a double quote or a backslash is refused,
because tshark's table format cannot carry it.

The file is turned into tshark's `snmp_users` table inside a private temporary
`WIRESHARK_CONFIG_DIR` (directory `0700`, file `0600`, on tmpfs at `/dev/shm` where there is one,
removed after the run; the README's Decryption section says where it goes without tmpfs and how
it is cleaned up on a signal), so no passphrase is
ever on a command line, where any user could read it from `ps`. Every passphrase and community is
also scrubbed by value from the report, the CLI output and the saved files.

## 🔓 What TShark 3.6.2 can and cannot decrypt (measured)

Measured against net-snmp 5.9.4 on real traffic (`scripts/fixtures/generate_snmp_fixtures.py --v3`):

| Auth | Priv | Decrypted by tshark 3.6.2 |
|---|---|---|
| MD5, SHA1 | DES | yes |
| MD5, SHA1, SHA2-224, SHA2-256, SHA2-384, SHA2-512 | AES (AES-128) | yes |
| SHA2-256 | AES-192, AES-256 | yes |
| SHA2-512 | AES-256 | yes |
| SHA1 | AES-192, AES-256 | **no** (key-extension mismatch) |
| MD5 | AES-256 | **no** (key-extension mismatch) |

- **The table's labels.** tshark 3.6.2's `snmp_users` table stores its two enum columns as labels
  and accepts exactly auth `MD5`, `SHA1`, `SHA2-224`, `SHA2-256`, `SHA2-384`, `SHA2-512` and priv
  `DES`, `AES`, `AES192`, `AES256`. There is no 3DES and no separate "Cisco" AES entry; an integer
  or any other label is refused with a table error on stderr (S.O.N.I.C. reports such a refusal as
  `SNMP_USERS_TABLE_REFUSED` rather than leaving that user silently out).
- **The Reeder ("Cisco") key extension.** AES-192 and AES-256 need a 24- or 32-byte key; when the
  auth hash is shorter (SHA1 20 bytes, MD5 16), the localized key must be extended. tshark 3.6.2
  extends it the **Reeder** way (draft-reeder-snmpv3-usm-3desede: append the key localized again
  from the previous one as a passphrase), which is what Cisco implements. **net-snmp 5.9.4 extends
  it the Blumenthal-draft way** (draft-blumenthal-aes-usm-04: append the hash of what is there).
  So tshark 3.6.2 decrypts such a user's traffic from a Cisco-style agent but not from net-snmp.
  This was verified byte for byte: for an MD5 / AES-256 message, the plaintext tshark produced is
  exactly the AES-CFB decryption under the Reeder-extended key, while only the Blumenthal-extended
  key yields a valid scoped PDU. With SHA2-256 or SHA2-512 no extension is needed, and both agree.
- **What "decrypted" means.** tshark fills `snmp.decrypted_pdu` with whatever a key produced, right
  or wrong. S.O.N.I.C. counts a message as decrypted only when its scoped PDU dissected
  (`snmp.data`); a wrong key shows as a malformed packet or tshark's "not formatted as expected"
  item, and a wrong auth passphrase as `snmp.authentication_error`.

## 🧭 Per message: decrypted or not, and why (never silent)

| `outcome` | Meaning | Issue |
|---|---|---|
| `decrypted` | the authPriv scoped PDU dissected (its contents are not reported, only its PDU type) | |
| `authenticated` | an authNoPriv message whose digest verified | |
| `auth_failed` | the digest did not verify: wrong auth passphrase or protocol | `SNMP_AUTH_FAILED` |
| `decrypt_failed` | decryption failed: wrong privacy passphrase or protocol, or (AES-192/256 over SHA1 or MD5) the key-extension mismatch above, named in the reason | `SNMP_DECRYPT_FAILED` |
| `unknown_user` | the users file has no entry for this user | `SNMP_UNKNOWN_USER` |
| `unknown_engine` | the users file gives this user only for another engine id | `SNMP_UNKNOWN_ENGINE` |
| `no_keys` | no users file was given (info) | `SNMP_NOT_DECRYPTED` |

`v3_users` totals each user's outcomes, and a user from the file that sent nothing is
`SNMP_USER_NOT_SEEN` (info).

## 📋 What the report holds

`verdict`, `summary` (messages, versions, v3 security levels, v3 outcomes, authPriv decrypted and
not), `v3_users`, `messages[]` (frame, version, security_level, pdu, src, dst, and for v3 user,
engine_id, role, outcome, reason, report), `credentials[]` (cleartext communities, value masked),
`issues[]`, `capture` (users_file_given, users_count, the table warnings) and `limits`.

## 🧪 Tests and fixtures

```bash
python3 scripts/fixtures/generate_snmp_fixtures.py --v3   # capture the v3 matrix (Docker, a few minutes)
go test -race ./internal/analyze/snmpinspect/...
```

v1 and v2c are proven on a committed synthetic scapy fixture (`testdata/fixtures/snmp_v1v2c.pcap`).
SNMPv3 cannot be built by hand (USM localizes each key from the passphrase and the agent's engine
id), so `generate_snmp_fixtures.py --v3` captures it from a real net-snmp: one container from a
pinned image (`alpine@sha256:d9e853e8...`, alpine 3.20, net-snmp 5.9.4), unprivileged (tcpdump
uses Docker's default NET_RAW only), removed afterwards, running snmpd and snmpget on loopback
with tcpdump on `lo`. It configures v1 and v2c communities, a noAuthNoPriv and an authNoPriv user,
and an authPriv user for each combination in the table above, and also sends a wrong privacy
passphrase, a wrong auth passphrase and an unknown user. The capture, its users file and a README
go to `~/.cache/sonic/snmp-captures` (or `SONIC_SNMP_CAPTURES`), outside the repository; every
credential is a throwaway placeholder from the generator, and the tests assert none appears in the
report, the CLI output or the markdown file. `TestRealV3Matrix` skips when that capture is absent,
and `TestLabCaptures` reads any `snmp-*.pcap` another writer leaves in the lab captures directory.
