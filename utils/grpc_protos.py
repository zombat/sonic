#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. gNMI and gNOI .proto Files for Wireshark

Wireshark's protobuf dissector decodes every field of a gRPC message when it is
given the .proto files that define it. S.O.N.I.C. does not ship them: they are
Apache-2.0 (openconfig/gnmi, openconfig/gnoi) and BSD-3-Clause (the protobuf
well-known types), S.O.N.I.C. is MIT, and keeping them out of the repository keeps
its licensing single and its tree small. Instead `python3 sonic.py
--fetch-grpc-protos [DIR]` downloads them on request, once, from GitHub at pinned
commits, checks each file's SHA-256 against the pin below, and writes them with
their licenses into DIR (default ~/.cache/sonic/grpc-protos), laid out so their
import paths resolve (github.com/openconfig/gnmi/proto/gnmi/gnmi.proto, ...).
analyze_grpc_capture uses that directory when it exists, or SONIC_PROTO_PATH, or
proto_paths passed in; nothing is downloaded during an analysis.

Pins and why:
    openconfig/gnmi v0.14.1     gnmi.proto, gnmi_ext.proto
    openconfig/gnoi v0.8.0      types, common, system, cert, file, healthz. os.proto is left out: it
                                imports bootconfig.proto, which pulls in openconfig/bootz and gnsi.
    protobuf v3.20.3            any, descriptor, duration, timestamp. Wireshark 3.6's .proto parser
                                rejects the editions syntax of newer descriptor.proto files.

Author: Raymond A Rizzo | Zombat
"""

import hashlib
import os
import tempfile
import urllib.request
from typing import Callable, Dict, List, Optional

DEFAULT_PROTO_DIR = os.path.join(os.path.expanduser("~"), ".cache", "sonic", "grpc-protos")
RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"

GNMI = ("openconfig/gnmi", "v0.14.1", "8b7dd494c4f6ff517431965d662621d8884bad0f")
GNOI = ("openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be")
PROTOBUF = ("protocolbuffers/protobuf", "v3.20.3", "fe271ab76f2ad2b2b28c10443865d2af21e27e0e")

# (source, path in the repository, path under the destination, SHA-256 of the file at that commit)
FILES = [
    (GNMI, "proto/gnmi/gnmi.proto", "github.com/openconfig/gnmi/proto/gnmi/gnmi.proto",
     "45abf90bfee289544e2430c8ce1b5b10e4f851736a508ddba54d3cf12e82f7b7"),
    (GNMI, "proto/gnmi_ext/gnmi_ext.proto", "github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto",
     "b0e96bd0c540cf249512783ee5abeb3f0d05805115f18c7d714ac90316981e2e"),
    (GNOI, "types/types.proto", "github.com/openconfig/gnoi/types/types.proto",
     "f2cfcaf19623b93e1ce5c075bd745ea0b81e6b982f0752e9fb8297da2b85c12b"),
    (GNOI, "common/common.proto", "github.com/openconfig/gnoi/common/common.proto",
     "45d64bbd89fd952cee3a83ee5657a14d534f09089f1ccd3c5088bd268c457f13"),
    (GNOI, "system/system.proto", "github.com/openconfig/gnoi/system/system.proto",
     "fa5d4ff283af2178207dd94755ca5c901fd08a13ac44d28d8ae06a53cb8df30e"),
    (GNOI, "cert/cert.proto", "github.com/openconfig/gnoi/cert/cert.proto",
     "85d36865c7efbef71f93a68bc4720d84fcfaf14eaeb166b343916c8a94417e4d"),
    (GNOI, "file/file.proto", "github.com/openconfig/gnoi/file/file.proto",
     "9a2c133f0b745e5400ccb4c4ce0384e97854c38cb5445cd22dcde6414c01d971"),
    (GNOI, "healthz/healthz.proto", "github.com/openconfig/gnoi/healthz/healthz.proto",
     "dac77213f87900fded24f9ab93b1d9a740f1ef279a5741c70529fb028d071bc4"),
    (PROTOBUF, "src/google/protobuf/any.proto", "google/protobuf/any.proto",
     "1aa80cf90ddbd380b73b1422bae51d76d99b82a4cdf0b183f21a802f72aafe8b"),
    (PROTOBUF, "src/google/protobuf/descriptor.proto", "google/protobuf/descriptor.proto",
     "c05fcefb4de00db652f321ee62c1f463b0158a0589ba1abd26209707b965d011"),
    (PROTOBUF, "src/google/protobuf/duration.proto", "google/protobuf/duration.proto",
     "099047097e8fe73657b49ef67af914a7a686ac6154f9d872882708b5eb3db04c"),
    (PROTOBUF, "src/google/protobuf/timestamp.proto", "google/protobuf/timestamp.proto",
     "9489462cbd4eff7c013d10de596be38da1087c7824ea34357669bc21bf5c0800"),
    (GNMI, "LICENSE", "LICENSES/openconfig-gnmi.LICENSE",
     "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"),
    (GNOI, "LICENSE", "LICENSES/openconfig-gnoi.LICENSE",
     "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1"),
    (PROTOBUF, "LICENSE", "LICENSES/protobuf.LICENSE",
     "6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d"),
]

README = """These files were downloaded by `sonic.py --fetch-grpc-protos` for Wireshark's protobuf
dissector, which S.O.N.I.C. points at this directory when it analyzes gRPC captures.
They are not part of S.O.N.I.C. and keep their own licenses (LICENSES/):
  github.com/openconfig/gnmi  openconfig/gnmi {gnmi_tag} ({gnmi_commit}), Apache-2.0
  github.com/openconfig/gnoi  openconfig/gnoi {gnoi_tag} ({gnoi_commit}), Apache-2.0
  google/protobuf             protocolbuffers/protobuf {pb_tag} ({pb_commit}), BSD-3-Clause
"""


def _default_opener(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "sonic-fetch-grpc-protos"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (fixed https URLs)
        return response.read()


def _write_atomic(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".sonic-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def fetch_protos(dest: Optional[str] = None, opener: Optional[Callable[[str], bytes]] = None,
                 pins: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """
    Download the pinned .proto files and licenses into dest and check each SHA-256.

    Args:
        dest: destination directory (default ~/.cache/sonic/grpc-protos)
        opener: url -> bytes (tests pass a fake; the default fetches over HTTPS)
        pins: optional {destination path: sha256} overriding PINS

    Returns:
        {"status": "success", "dir", "files": [...]} or {"status": "error", "error", "file"}.
        A file whose digest does not match its pin is not written.
    """
    dest = os.path.abspath(os.path.expanduser(dest or DEFAULT_PROTO_DIR))
    opener = opener or _default_opener
    pins = dict(PINS if pins is None else pins)
    written: List[str] = []
    for (repo, _tag, commit), path, target, _ in FILES:
        url = RAW.format(repo=repo, commit=commit, path=path)
        try:
            data = opener(url)
        except Exception as exc:  # network errors are reported, not raised
            return {"status": "error", "error": f"download failed: {type(exc).__name__}: {exc}", "file": url}
        digest = hashlib.sha256(data).hexdigest()
        expected = pins.get(target)
        if expected and digest != expected:
            return {"status": "error", "file": url,
                    "error": f"SHA-256 mismatch for {target}: got {digest}, pinned {expected}"}
        _write_atomic(os.path.join(dest, target), data)
        written.append(target)
    _write_atomic(os.path.join(dest, "README.txt"), README.format(
        gnmi_tag=GNMI[1], gnmi_commit=GNMI[2], gnoi_tag=GNOI[1], gnoi_commit=GNOI[2],
        pb_tag=PROTOBUF[1], pb_commit=PROTOBUF[2]).encode())
    return {"status": "success", "dir": dest, "files": written}


def fetch_command(dest: Optional[str]) -> int:
    """CLI entry: fetch the files and print what was written; exit status 0 or 1."""
    result = fetch_protos(dest)
    if result["status"] != "success":
        print(f"Fetching the gRPC .proto files failed: {result['error']}")
        return 1
    print(f"Wrote {len(result['files'])} files (gNMI, gNOI, protobuf well-known types and their licenses) "
          f"to {result['dir']}")
    print("analyze_grpc_pcap and sonic.py --grpc use this directory when it is the default one, or pass it "
          "as proto_paths / --proto-path, or set SONIC_PROTO_PATH.")
    return 0


PINS: Dict[str, str] = {target: sha for _, _, target, sha in FILES}
