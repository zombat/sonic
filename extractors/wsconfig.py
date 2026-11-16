#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. temporary Wireshark configuration (keys and UATs off the command line)

Some tshark decryptions take their key material from a preference (tacplus.key,
radius.shared_secret) or a UAT file (esp_sa, snmp_users), not from a key-log-style
file path. Passing a secret with `-o pref:VALUE` would put it in the tshark process's
argv, where any user on the box could read it from `ps` or /proc. To avoid that,
S.O.N.I.C. writes the preferences and UAT files into a private temporary directory
(0700, each file 0600) and points tshark at it with WIRESHARK_CONFIG_DIR, so the
secret never appears on a command line.

Where the secret files live:

- On Linux the directory is made under /dev/shm, a tmpfs, so the key material is held in
  memory and never reaches a disk or a filesystem journal (it can still reach swap, as any
  process memory can). /dev/shm is used only when it exists, is a writable directory and,
  where /proc/self/mounts can be read, is mounted as tmpfs or ramfs.
- Where there is no such tmpfs (macOS, some containers), the directory falls back to the
  normal temporary directory, which is on disk. S.O.N.I.C. says so once per process on
  stderr. The files are still 0600 in a 0700 directory and removed after the run, but their
  blocks can stay on the disk or in its journal until overwritten.

When the directory is removed:

- when the context exits, whatever happened (a finally);
- on SIGTERM and SIGINT: a handler removes every live directory, then hands the signal to
  whatever handler was there before (the default one ends the process as the signal would);
- at interpreter exit (atexit).

SIGKILL cannot be caught, and neither can a crash of the interpreter itself, so either can
leave a directory behind. Each directory's name carries the process id that made it
(sonic-ws-<pid>-...), and the next run removes any of the user's own directories whose process
no longer exists. On tmpfs a leftover is also gone at the next reboot.

No secret is ever logged, returned or written anywhere else. The caller reads the key
material by path (an operator-supplied file) and hands it here as data.

Author: Raymond A Rizzo | Zombat
"""

import atexit
import contextlib
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import threading
from typing import Dict, Iterator, List, Optional, Set

PREFIX = "sonic-ws-"
SHM_DIR = "/dev/shm"
MEMORY_FILESYSTEMS = ("tmpfs", "ramfs")
CLEANUP_SIGNALS = (signal.SIGTERM, signal.SIGINT)

_live_dirs: Set[str] = set()
_previous_handlers: Dict[int, object] = {}
_lock = threading.Lock()
_warned_on_disk = False
_name = re.compile(r"^" + re.escape(PREFIX) + r"(\d+)-")


def _mount_type(path: str) -> Optional[str]:
    """The filesystem type /proc/self/mounts gives for exactly path, or None when unknown."""
    try:
        with open("/proc/self/mounts", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == path:
                    return fields[2]
    except OSError:
        return None
    return None


def secret_dir_root() -> Optional[str]:
    """The memory-backed directory to hold secret files in, or None when there is none."""
    if not os.path.isdir(SHM_DIR) or not os.access(SHM_DIR, os.W_OK | os.X_OK):
        return None
    kind = _mount_type(SHM_DIR)
    if kind is not None and kind not in MEMORY_FILESYSTEMS:
        return None
    return SHM_DIR


def _warn_on_disk() -> None:
    global _warned_on_disk
    if _warned_on_disk:
        return
    _warned_on_disk = True
    print(f"⚠️  S.O.N.I.C.: no tmpfs at {SHM_DIR}, so the decryption keys handed to tshark are written "
          f"to a private directory under {tempfile.gettempdir()} on disk (0700, files 0600, removed "
          "after the run). Their blocks can stay on the disk until overwritten.", file=sys.stderr)


def _remove(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
    with _lock:
        _live_dirs.discard(path)


def cleanup_all() -> None:
    """Remove every secret directory this process still holds."""
    with _lock:
        paths = list(_live_dirs)
    for path in paths:
        _remove(path)


def _remove_orphans(root: str) -> None:
    """Remove this user's leftover directories whose process no longer exists (a SIGKILL, a crash)."""
    if os.name != "posix":  # os.kill(pid, 0) is a liveness probe only on POSIX
        return
    try:
        names = os.listdir(root)
    except OSError:
        return
    uid = os.getuid()
    for name in names:
        match = _name.match(name)
        if not match:
            continue
        pid = int(match.group(1))
        if pid == os.getpid():
            continue
        path = os.path.join(root, name)
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if info.st_uid != uid or not stat.S_ISDIR(info.st_mode):  # lstat: a symlink is not followed
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            shutil.rmtree(path, ignore_errors=True)
        except (PermissionError, OSError):
            continue


def _handler(signum, frame):
    cleanup_all()
    previous = _previous_handlers.get(signum, signal.SIG_DFL)
    if callable(previous):
        previous(signum, frame)
    elif previous == signal.SIG_IGN:
        return
    else:  # SIG_DFL, or None (a handler not installed from Python): end as the signal would
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)


def install_signal_cleanup() -> bool:
    """
    Make SIGTERM and SIGINT remove the secret directories before the previous handler runs.

    Signal handlers can only be set from the main thread; elsewhere this does nothing and
    returns False (the finally and atexit still clean up). Called on import and again each
    time a directory is made, so a handler installed later by someone else is wrapped too.
    """
    if threading.current_thread() is not threading.main_thread():
        return False
    for signum in CLEANUP_SIGNALS:
        current = signal.getsignal(signum)
        if current is _handler:
            continue
        try:
            signal.signal(signum, _handler)
        except (ValueError, OSError):
            return False
        _previous_handlers[signum] = current
    return True


atexit.register(cleanup_all)
install_signal_cleanup()


@contextlib.contextmanager
def wireshark_config(preferences: Optional[Dict[str, str]] = None,
                     uats: Optional[Dict[str, List[str]]] = None) -> Iterator[str]:
    """
    A temporary WIRESHARK_CONFIG_DIR holding the given preferences and UAT files.

    Made under /dev/shm (tmpfs) when there is one, else under the normal temporary directory
    with a one-time warning; see the module docstring.

    Args:
        preferences: {pref name: value}, written to a `preferences` file (one `name: value`
            per line). Used for tacplus.key and radius.shared_secret, whose values are secrets.
        uats: {uat name: [record line, ...]}, each written to a file of that name (esp_sa,
            snmp_users). Each record line is a full UAT row as Wireshark stores it.

    Yields:
        the directory path, to pass as the WIRESHARK_CONFIG_DIR environment variable.
    """
    root = secret_dir_root()
    if root is None:
        _warn_on_disk()
    _remove_orphans(root or tempfile.gettempdir())
    install_signal_cleanup()
    path = tempfile.mkdtemp(prefix=f"{PREFIX}{os.getpid()}-", dir=root)
    with _lock:
        _live_dirs.add(path)
    try:
        os.chmod(path, 0o700)
        if preferences:
            pref_path = os.path.join(path, "preferences")
            with open(os.open(pref_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w",
                      encoding="utf-8") as handle:
                for name, value in preferences.items():
                    handle.write(f"{name}: {value}\n")
        for name, rows in (uats or {}).items():
            uat_path = os.path.join(path, name)
            with open(os.open(uat_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w",
                      encoding="utf-8") as handle:
                for row in rows:
                    handle.write(row.rstrip("\n") + "\n")
        yield path
    finally:
        _remove(path)


def tshark_env(config_dir: str) -> Dict[str, str]:
    """A copy of os.environ with WIRESHARK_CONFIG_DIR set to config_dir, for a tshark subprocess."""
    env = dict(os.environ)
    env["WIRESHARK_CONFIG_DIR"] = config_dir
    return env
