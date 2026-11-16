# S.O.N.I.C. IPsec ESP Decryption (from SA keys)

## 🚀 Overview

Given the Security Association keys an operator supplies, S.O.N.I.C. decrypts ESP with
Wireshark's own ESP decryption through `tshark`, says per SA which packets decrypted and why the
others did not, rebuilds the decrypted packets into a temporary capture, and runs the existing
network detectors over that inner traffic. Deterministic (no LLM); no SA key is ever written out.

```bash
python3 sonic.py --file tunnel.pcap --esp-decrypt --esp-sa sa.txt            # decrypt, analyze the inner traffic
python3 sonic.py --file tunnel.pcap --esp-decrypt --esp-sa xfrm.txt --json   # an `ip -s xfrm state` dump works as is
python3 sonic.py --file tunnel.pcap --esp-decrypt --esp-sa sa.txt --detectors tcp,reachability
```

Over MCP the tool is `analyze_esp_pcap` (`sa_file` is a path on the server). The report goes to
`--save_file`, or to `<capture>.esp.md`; a path ending in `.json` writes JSON.

## ⛔ Cisco IOS cannot be decrypted this way

**Cisco IOS and IOS XE do not expose ESP session keys.** There is no command that prints them, so a
capture of a Cisco IOS site-to-site or DMVPN tunnel (the CVD lab's, for one) cannot be decrypted
with this feature, whatever the capture holds. This is for SAs whose keys an operator can read: a
Linux or strongSwan endpoint (`ip -s xfrm state` as root), or a lab where the keys were set by hand.
A Cisco tunnel is still analysed from the outside (SPIs, sequence numbers, rekeys, overhead, NAT-T,
DPD) by `analyze_vpn_pcap` / `--network-only --detectors ipsec,esp_overhead`.

## 🔑 The SA file (a secret, read by path)

S.O.N.I.C.'s format, one SA per record, records separated by a blank line:

```
src: 198.51.100.1
dst: 198.51.100.2
spi: 0x00001001                # 0x hex; bare digits are decimal
encryption: aes-cbc            # aes-cbc, aes-gcm (aes-gcm-12, aes-gcm-8), aes-ctr, 3des-cbc, des-cbc, null
encryption_key: 0x000102...
integrity: hmac-sha1-96        # hmac-sha1-96, hmac-sha256-128, hmac-sha384-192, hmac-sha512-256, hmac-md5-96, none
integrity_key: 0x000102...

src: 198.51.100.2
dst: 198.51.100.1
spi: 0x00001002
encryption: aes-gcm            # AEAD: no integrity line; the key is the cipher key followed by its 4-byte salt
encryption_key: 0x000102...deadbeef
```

Or the output of **`ip -s xfrm state`**, pasted as it is (detected automatically): `enc cbc(aes)`,
`auth-trunc hmac(sha1) ... 96`, `aead rfc4106(gcm(aes)) <key+salt> 128` and the rest map to the same
SAs, and the anti-replay, lifetime and stats lines are ignored.

Each SA becomes a row of tshark's `esp_sa` table, with the exact labels tshark 3.6.2 uses
(`AES-CBC [RFC3602]`, `AES-GCM with 16 octet ICV [RFC4106]`, `HMAC-SHA-1-96 [RFC2404]`,
`HMAC-SHA-256-128 [RFC4868]`, ...), written into a private temporary `WIRESHARK_CONFIG_DIR`
(directory `0700`, file `0600`, on tmpfs at `/dev/shm` where there is one, removed after the run;
the README's Decryption section says where it goes without tmpfs and how it is cleaned up on a
signal), so no key is ever on a command line, where
any user could read it from `ps`. tshark runs with `esp.enable_encryption_decode` and
`esp.enable_authentication_check` on. An unknown algorithm, a key that is not hex or an SPI out of
range is refused with a message that never quotes a key.

## 🔓 What counts as decrypted

tshark fills `esp.decrypted_data` under any key, right or wrong, so its presence proves nothing.
S.O.N.I.C. counts a packet as decrypted only when its decrypted ESP trailer is real (RFC 4303 2.4 to
2.6): the padding reads 1, 2, 3, ... (the default Linux, strongSwan and scapy send), the next header
is a real protocol, and in tunnel mode the inner IP packet's own length is exactly the payload's.
Under a wrong key those bytes are noise and the packet is rejected. A packet whose ICV tshark found
bad is never counted. A sender that pads with something other than the default is not recognised
(said in `limits`).

Per SA the report gives the packets seen and decrypted, how many were tunnel and transport mode, and
tshark's integrity check, and when packets did not decrypt, why:

| Reason | What it means |
|---|---|
| packets failed the integrity check | the integrity key or algorithm is wrong (for AES-GCM, the key or its salt), or the packets were altered |
| no decryption although the integrity check passed | the integrity key is proven right, so the encryption key or algorithm is wrong |
| no ESP packet matched this SA | wrong addresses or SPI, the other direction's SA, or the traffic is not in this capture |

## 🔁 The inner traffic

Decrypted packets are rebuilt into a temporary capture (removed afterwards): tunnel-mode inner IP
packets as they were sent, and a transport-mode payload given back an IP header with the SA's outer
addresses (its ports and payload are the sender's; the IP header is rebuilt). ESP in UDP 4500
(NAT-T) is decrypted like plain ESP. The same detectors `--network-only` runs (reachability, TCP
health, routing, TLS, QoS, path MTU, ...) then read the inner capture, and `inner_analysis` carries
the protocols present, each detector's verdict and its issues. `--detectors` (MCP `detectors`) picks
a subset.

## 📋 What the report holds

`verdict`, `summary` (security_associations, esp_packets, esp_decrypted, sas_decrypting),
`security_associations[]` (src, dst, spi, encryption, integrity, packets, decrypted, tunnel,
transport, icv_good, icv_bad, reason), `inner_analysis`, `issues[]` (`ESP_SA_NOT_DECRYPTED`,
`ESP_SA_PARTIAL`, `ESP_SA_NO_PACKETS`, `ESP_SA_TABLE_REFUSED`), `capture` (sa_count, esp_packets, esp_decrypted,
inner_packets_reconstructed) and `limits`.

## TShark 3.6.2

Verified with TShark (Wireshark) 3.6.2: AES-CBC with HMAC-SHA1-96 and with HMAC-SHA-256-128, and
AES-GCM with a 16-octet ICV, decrypt from an `esp_sa` row in tunnel mode, transport mode and over
UDP 4500; the ICV check verifies HMAC and GCM tags (`esp.icv_good`, `esp.icv_bad`). tshark 3.6.2's
`esp_sa` table also offers 3DES-CBC, DES-CBC, AES-CTR, CAST5, Blowfish, Twofish, NULL and AES-GCM
with 8- and 12-octet ICVs; those labels are mapped and each was checked to be accepted by the table,
but only NULL among them is exercised by the tests. Its NULL label for ESP is plain `NULL` (the
`NULL [RFC2410]` label belongs to its IKEv2 table and is refused here). It has no ChaCha20-Poly1305
for ESP. One quirk: with NULL encryption tshark 3.6.2 leaves the ICV at the end of its decrypted data
and does not dissect the inner packet, so S.O.N.I.C. strips the ICV by the SA's integrity length before
reading the trailer. A row the table refuses is reported as `ESP_SA_TABLE_REFUSED` rather than leaving
that SA silently out.

## ⚠️ Limits

- Only ESP whose (src, dst, SPI) matches an SA and whose key and algorithm are right decrypts.
- A sender that pads with something other than the RFC 4303 default is not recognised as decrypted.
- A transport-mode packet's IP header is rebuilt from the SA's addresses.
- The inner analysis sees only what the ESP packets carried; a one-way capture shows one direction.
- SA keys are read by path, kept off the tshark command line, and never written to a record, a log or
  a report.

## 🧪 Tests

```bash
python3 -m unittest -q test_esp
```

`tests/fixtures/esp_tunnel.pcap` is built by `tests/fixtures/generate_esp_fixtures.py` with scapy's
IPsec support, deterministically (fixed IVs): AES-CBC with HMAC-SHA1-96 and with HMAC-SHA256-128,
AES-GCM in both directions, a transport-mode SA and a NAT-T SA, over inner ICMP and TCP. The tests
write the keys (synthetic placeholders) to an SA file and an `ip -s xfrm state` dump, check every
SA's counts, a wrong encryption key with the right integrity key, a wrong integrity key, a wrong
AES-GCM key, an SA with no packets and the detectors over the inner traffic, and assert no key
appears in the report, the CLI output or the markdown file.
