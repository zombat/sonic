#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. SNMP Test Fixtures

Two kinds, by what SNMP needs:

- v1 and v2c are built synthetically with scapy (snmp_v1v2c.pcap, committed), deterministically
  at fixed addresses (RFC 5737) and timestamps, so a rerun produces an identical file. Its
  community strings are synthetic placeholders.

- SNMPv3 cannot be built by hand (USM localizes each key from the passphrase and the agent's
  engine id, and runs a real cipher), so generate_v3_captures() captures it from a real net-snmp
  `snmpd`: it starts one container from a pinned Alpine image (by digest, unprivileged, removed
  afterwards) that installs net-snmp and tcpdump, configures v1 and v2c communities and a v3 user
  for every auth and privacy algorithm net-snmp 5.9.4 offers, and runs net-snmp's `snmpget` against
  it while tcpdump captures loopback inside the container. Also captured: a noAuthNoPriv and an
  authNoPriv user, a wrong privacy passphrase, a wrong auth passphrase and an unknown user. It
  writes snmp-v3-matrix.pcap, the matching users file (snmp-users.txt, S.O.N.I.C.'s format) and a
  README into a captures directory outside the repository (default ~/.cache/sonic/snmp-captures).
  The traffic is real but every credential is a throwaway placeholder defined here, and the files
  are not committed; test_snmp.py reads them from that directory and skips when they are absent.
  Engine ids, salts and timings differ on each run, so the capture is regenerated, not compared.

Usage:
    python3 tests/fixtures/generate_snmp_fixtures.py [OUT_DIR]        # write snmp_v1v2c.pcap
    python3 tests/fixtures/generate_snmp_fixtures.py --v3 [OUT_DIR]   # capture SNMPv3 (needs Docker)
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate_dataplane_fixtures import Capture  # noqa: E402
from scapy.all import IP, UDP, Ether  # noqa: E402
from scapy.layers.snmp import SNMP, SNMPget, SNMPnext, SNMPresponse, SNMPtrapv2, SNMPvarbind  # noqa: E402

COMMUNITY_V1 = "public-v1-not-real"
COMMUNITY_V2C = "private-v2c-not-real"

# alpine:3.20 (created 2026-04-16), net-snmp 5.9.4 from its packages; pinned by digest.
SNMPD_IMAGE = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
DEFAULT_V3_DIR = os.path.join(os.path.expanduser("~"), ".cache", "sonic", "snmp-captures")

V3_COMMUNITY_V1 = "v1-community-not-real"
V3_COMMUNITY_V2C = "v2c-community-not-real"
# Every auth/priv pair worth telling apart: each auth protocol over AES-128, DES over MD5 and SHA, and
# AES-192/256 both where the key must be extended (SHA1, MD5) and where it need not be (SHA-256, SHA-512).
V3_AUTHPRIV = [
    ("u_md5_des", "MD5", "DES"), ("u_sha_des", "SHA", "DES"),
    ("u_md5_aes", "MD5", "AES"), ("u_sha_aes", "SHA", "AES"), ("u_sha224_aes", "SHA-224", "AES"),
    ("u_sha256_aes", "SHA-256", "AES"), ("u_sha384_aes", "SHA-384", "AES"), ("u_sha512_aes", "SHA-512", "AES"),
    ("u_sha_aes192", "SHA", "AES-192"), ("u_sha_aes256", "SHA", "AES-256"), ("u_md5_aes256", "MD5", "AES-256"),
    ("u_sha256_aes192", "SHA-256", "AES-192"), ("u_sha256_aes256", "SHA-256", "AES-256"),
    ("u_sha512_aes256", "SHA-512", "AES-256"),
]
V3_AUTHNOPRIV = ("u_authnopriv", "SHA", "authpass-anp-not-real")
V3_NOAUTH = "u_noauth"


def auth_pass(user):
    return f"auth-{user}-not-real"


def priv_pass(user):
    return f"priv-{user}-not-real"


def v3_secrets():
    """Every passphrase and community in the v3 capture (for the tests' no-leak assertions)."""
    out = [V3_COMMUNITY_V1, V3_COMMUNITY_V2C, V3_AUTHNOPRIV[2], "wrong-priv-not-real", "wrong-auth-not-real",
           "auth-nobody-not-real", "priv-nobody-not-real"]
    for user, _, _ in V3_AUTHPRIV:
        out += [auth_pass(user), priv_pass(user)]
    return out


def build_v1v2c():
    cap = Capture()
    manager, agent = "198.51.100.30", "203.0.113.40"

    def send(t, from_manager, pdu, version, community, sport, dport):
        src, dst = (manager, agent) if from_manager else (agent, manager)
        macs = ("02:00:00:00:00:01", "02:00:00:00:00:02")
        mac_src, mac_dst = macs if from_manager else macs[::-1]
        cap.add(t, Ether(src=mac_src, dst=mac_dst) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
                / SNMP(version=version, community=community, PDU=pdu))

    oid = lambda s: SNMPvarbind(oid=s)  # noqa: E731
    send(0.0, True, SNMPget(varbindlist=[oid("1.3.6.1.2.1.1.1.0")]), 0, COMMUNITY_V1, 40000, 161)
    send(0.02, False, SNMPresponse(varbindlist=[oid("1.3.6.1.2.1.1.1.0")]), 0, COMMUNITY_V1, 161, 40000)
    send(0.10, True, SNMPnext(varbindlist=[oid("1.3.6.1.2.1.1.5.0")]), 1, COMMUNITY_V2C, 40001, 161)
    send(0.12, False, SNMPresponse(varbindlist=[oid("1.3.6.1.2.1.1.5.0")]), 1, COMMUNITY_V2C, 161, 40001)
    send(0.20, False, SNMPtrapv2(varbindlist=[oid("1.3.6.1.2.1.1.3.0")]), 1, COMMUNITY_V2C, 40002, 162)
    return cap


def users_file_text():
    """The users file (S.O.N.I.C.'s block format) that decrypts snmp-v3-matrix.pcap."""
    lines = ["# SNMPv3 USM users for snmp-v3-matrix.pcap (throwaway placeholders, never real)"]
    for user, auth, priv in V3_AUTHPRIV:
        lines += ["", f"user: {user}", f"auth: {auth}", f"auth_pass: {auth_pass(user)}", f"priv: {priv}",
                  f"priv_pass: {priv_pass(user)}"]
    lines += ["", f"user: {V3_AUTHNOPRIV[0]}", f"auth: {V3_AUTHNOPRIV[1]}", f"auth_pass: {V3_AUTHNOPRIV[2]}"]
    return "\n".join(lines) + "\n"


def _container_script() -> str:
    create = [f"createUser {V3_NOAUTH}",
              f'createUser {V3_AUTHNOPRIV[0]} {V3_AUTHNOPRIV[1]} "{V3_AUTHNOPRIV[2]}"']
    create += [f'createUser {u} {a} "{auth_pass(u)}" {p} "{priv_pass(u)}"' for u, a, p in V3_AUTHPRIV]
    access = [f"rocommunity {V3_COMMUNITY_V1} 127.0.0.1", f"rocommunity {V3_COMMUNITY_V2C} 127.0.0.1",
              f"rouser {V3_NOAUTH} noauth", f"rouser {V3_AUTHNOPRIV[0]} auth"]
    access += [f"rouser {u} priv" for u, _, _ in V3_AUTHPRIV]
    oid = "1.3.6.1.2.1.1.5.0"
    get = "snmpget -r0 -t2"
    gets = [f"{get} -v1 -c {V3_COMMUNITY_V1} 127.0.0.1 {oid}", f"{get} -v2c -c {V3_COMMUNITY_V2C} 127.0.0.1 {oid}",
            f"{get} -v3 -l noAuthNoPriv -u {V3_NOAUTH} 127.0.0.1 {oid}",
            f"{get} -v3 -l authNoPriv -u {V3_AUTHNOPRIV[0]} -a {V3_AUTHNOPRIV[1]} -A {V3_AUTHNOPRIV[2]} 127.0.0.1 {oid}"]
    gets += [f"{get} -v3 -l authPriv -u {u} -a {a} -A {auth_pass(u)} -x {p} -X {priv_pass(u)} 127.0.0.1 {oid}"
             for u, a, p in V3_AUTHPRIV]
    gets += [f"{get} -v3 -l authPriv -u u_sha_aes -a SHA -A {auth_pass('u_sha_aes')} -x AES -X wrong-priv-not-real "
             f"127.0.0.1 {oid}",
             f"{get} -v3 -l authPriv -u u_sha_aes -a SHA -A wrong-auth-not-real -x AES -X {priv_pass('u_sha_aes')} "
             f"127.0.0.1 {oid}",
             f"{get} -v3 -l authPriv -u u_nobody -a SHA -A auth-nobody-not-real -x AES -X priv-nobody-not-real "
             f"127.0.0.1 {oid}"]
    nl = "\n"
    return f"""set -e
apk add --no-cache net-snmp net-snmp-tools tcpdump >/dev/null 2>&1
mkdir -p /var/lib/net-snmp /etc/snmp
cat > /var/lib/net-snmp/snmpd.conf <<'CONF'
{nl.join(create)}
CONF
cat > /etc/snmp/snmpd.conf <<'CONF'
{nl.join(access)}
CONF
snmpd -f -Lf /tmp/snmpd.log -c /etc/snmp/snmpd.conf udp:127.0.0.1:161 &
SPID=$!
sleep 2
tcpdump -i lo -s 0 -U -w /tmp/snmp.pcap 'udp port 161' 2>/dev/null &
TPID=$!
sleep 1
{nl.join(g + ' >/dev/null 2>&1 || true' for g in gets)}
sleep 1
kill $TPID 2>/dev/null || true
sleep 1
kill $SPID 2>/dev/null || true
snmpget --version 2>&1 | head -1 > /out/net-snmp.version
cp /tmp/snmp.pcap /out/snmp-v3-matrix.pcap
chown $(stat -c %u:%g /out) /out/snmp-v3-matrix.pcap /out/net-snmp.version
"""


def generate_v3_captures(out_dir: str = DEFAULT_V3_DIR, image: str = SNMPD_IMAGE) -> str:
    """
    Capture the SNMPv3 matrix from a real net-snmp snmpd; returns the pcap path. Needs Docker and
    network access for the container's package install. The container runs with Docker's default
    (unprivileged) capabilities, tcpdump using NET_RAW only, and is removed whatever happens.
    """
    os.makedirs(out_dir, exist_ok=True)
    os.chmod(out_dir, 0o700)
    script_path = os.path.join(out_dir, "capture.sh")
    with open(script_path, "w") as handle:
        handle.write(_container_script())
    container = "sonic-snmp-fixture"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    try:
        subprocess.run(["docker", "run", "--rm", "--name", container, "-v", f"{os.path.abspath(out_dir)}:/out",
                        image, "sh", "/out/capture.sh"], check=True, capture_output=True, text=True, timeout=600)
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        if os.path.exists(script_path):
            os.remove(script_path)  # it holds the throwaway passphrases; the users file below is the record
    pcap = os.path.join(out_dir, "snmp-v3-matrix.pcap")
    if not os.path.exists(pcap) or os.path.getsize(pcap) == 0:
        raise RuntimeError("the container produced no SNMPv3 capture")
    version = ""
    version_path = os.path.join(out_dir, "net-snmp.version")
    if os.path.exists(version_path):
        with open(version_path) as handle:
            version = handle.read().strip()
        os.remove(version_path)
    users_path = os.path.join(out_dir, "snmp-users.txt")
    with open(os.open(users_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
        handle.write(users_file_text())
    os.chmod(pcap, 0o600)
    with open(os.path.join(out_dir, "snmp-v3-matrix.README.md"), "w") as handle:
        handle.write(
            "# snmp-v3-matrix: real SNMP from net-snmp, every v3 algorithm\n\n"
            f"Captured by tests/fixtures/generate_snmp_fixtures.py --v3 from `{image}` ({version or 'net-snmp'}), "
            "snmpd and snmpget on loopback inside one unprivileged container, tcpdump on `lo`.\n\n"
            "- v1 and v2c gets with a community each\n"
            f"- v3 noAuthNoPriv ({V3_NOAUTH}) and authNoPriv ({V3_AUTHNOPRIV[0]}, {V3_AUTHNOPRIV[1]})\n"
            + "".join(f"- v3 authPriv {u}: {a} / {p}\n" for u, a, p in V3_AUTHPRIV)
            + "- a wrong privacy passphrase and a wrong auth passphrase for u_sha_aes, and an unknown user u_nobody\n\n"
            "Every credential is a throwaway placeholder from the generator; the users file is snmp-users.txt. "
            "Not committed.\n")
    return pcap


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--v3":
        out = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_V3_DIR
        print(f"capturing SNMP v1, v2c and v3 from net-snmp into {out} (needs Docker) ...")
        print(f"wrote {generate_v3_captures(out)} and snmp-users.txt")
        return
    out_dir = sys.argv[1] if len(sys.argv) > 1 else HERE
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "snmp_v1v2c.pcap")
    build_v1v2c().write(path)
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
