#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Credentials

Where the LLM API keys come from, and the guarantee that a key never shows up
in anything S.O.N.I.C. prints, writes or returns.

Lookup order for each key S.O.N.I.C. uses (API_KEY_NAMES):

1. the process environment, so an MCP client passes a key through its own
   "env" block or environment passthrough;
2. a dotenv file named by --env-file PATH (sonic.py, mcp_server.py) or, without
   the flag, by the SONIC_ENV_FILE environment variable.

The dotenv file is read as data by a small literal parser (KEY=VALUE, optional
"export ", single or double quotes, # comments). Nothing is expanded, nothing
runs through a shell, and only the names in API_KEY_NAMES are kept; every other
line is skipped without being stored. A value loaded from the file stays in
this module and is handed to the LLM client directly; it is not copied into
os.environ, so child processes such as tshark never inherit it.

Every key S.O.N.I.C. knows of, from either source, is redacted by value from
MCP tool results, CLI output, log records, saved reports and the prompts sent
to the LLM. Status reports say only whether a key is configured and where it
came from.

A secret S.O.N.I.C. was never given (a key an error message quotes, a token in
a capture's file name, a password in a log line) cannot be redacted by value,
so the same paths also mask common secret shapes (SECRET_SHAPES, one list for
redact_text, the output streams, the log filter, the saved reports and the LLM
prompts): provider API keys (sk-ant-, sk-, sk-proj-, Stripe sk_live_/rk_live_,
Google AIza), AWS access key ids (AKIA, ASIA), GitHub tokens (ghp_, gho_, ghu_,
ghs_, ghr_, github_pat_), Slack tokens (xoxb-, xoxp-, xoxa-, xoxs-), JWTs, PEM
private key blocks, the credential of an Authorization or Proxy-Authorization
Basic or Bearer value, the value of a password=, secret=, token=, key=
style assignment (and password:, secret:, passphrase:), and SDP media keys
(an a=crypto inline: SRTP master key, an a=key-mgmt payload such as MIKEY,
a k=clear:/k=base64: key). Shapes are matched
narrowly so that ordinary report text (OIDs, MAC addresses, packet hashes,
SPIs, nonces) is left alone; a value with none of these shapes and not loaded
here is not masked.

Author: Raymond A Rizzo | Zombat
"""

import dataclasses
import enum
import functools
import io
import logging
import os
import re
import sys
from typing import Any, Dict, Optional

API_KEY_NAMES = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_KEY")
ENV_FILE_VARIABLE = "SONIC_ENV_FILE"
REDACTED = "[REDACTED]"
# Anthropic keys, and their partial forms an error message may quote.
KEY_PATTERN = re.compile(r"sk-ant-[A-Za-z0-9_\-]+")
MIN_SECRET_LENGTH = 8  # shorter values are not redacted by value (they would mangle ordinary text)

_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----"
    r"(?:.*?-----END \1-----|.*\Z)",  # an unterminated block (cut-off text) is masked to the end
    re.DOTALL)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
# The credential of an Authorization header, whatever surrounds it (an HTTP line, a SIP header,
# a JSON value, a log message): the scheme stays, so "Basic over cleartext" can still be said.
_AUTH_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?\s*)(basic|bearer)(\s+)([A-Za-z0-9+/._~\-]+=*)")
_BEARER = re.compile(r"\b(Bearer\s+)([A-Za-z0-9._~+/\-]{16,}=*)")
_BASIC = re.compile(r"\b(Basic\s+)([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
_TOKEN_SHAPES = re.compile(
    r"\bsk-ant-[A-Za-z0-9_\-]+"                       # Anthropic, partial forms included
    r"|\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"  # OpenAI and similar sk- keys
    r"|\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"         # Stripe secret and restricted keys
    r"|\bAIza[0-9A-Za-z_\-]{35}"                       # Google API keys
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"                  # AWS access key ids (long-term, temporary)
    r"|\bgh[pousr]_[A-Za-z0-9]{36,255}\b"              # GitHub tokens
    r"|\bgithub_pat_[A-Za-z0-9_]{22,255}\b"            # GitHub fine-grained tokens
    r"|\bxox[bpas]-[A-Za-z0-9-]{10,}")                 # Slack tokens
_SECRET_NAME = r"[A-Za-z0-9_.\-]*(?:password|passwd|passphrase|pwd|secret|token|api[_\-]?key|apikey|key|psk)"
_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_.\-])(" + _SECRET_NAME + r"\s*=\s*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&\"'<>()\[\]{}]+)")
# A colon form only for names that cannot be ordinary prose ("key: 3 SAs" is ordinary).
_COLON_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_.\-])([\"']?[A-Za-z0-9_.\-]*(?:password|passwd|passphrase|secret)[\"']?\s*:[ \t]*)"
    r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&\"'<>()\[\]{}]+)")
# SDP media keys: SDES a=crypto inline: key||salt (RFC 4568; the suite, lifetime and MKI stay),
# a=key-mgmt data such as a MIKEY payload (RFC 4567; the protocol id stays), and the k= line
# (RFC 4566 clear:, base64:; uri: and prompt carry no key and stay).
_SDP_INLINE = re.compile(r"(\binline:)([A-Za-z0-9+/]{16,}={0,2})")  # SRTP key||salt: 40+ chars
_SDP_KEY_MGMT = re.compile(r"(?im)(\ba=key-mgmt:[ \t]*[A-Za-z0-9._\-]+[ \t]+)([^\r\n\"]+)")
_SDP_K_LINE = re.compile(r"(?im)(^k=(?:clear|base64):)([^\r\n\"]+)")
_NOT_A_VALUE = {"", "none", "null", "true", "false", "redacted", REDACTED.lower(), "masked", "[masked]"}


def _basic_credential(match: "re.Match") -> str:
    """A standalone `Basic X` is masked only when X decodes to user:password (not "Basic authentication")."""
    import base64
    import binascii
    try:
        decoded = base64.b64decode(match.group(2) + "=" * (-len(match.group(2)) % 4), validate=True)
    except (binascii.Error, ValueError):
        return match.group(0)
    return match.group(1) + REDACTED if b":" in decoded else match.group(0)


def _bearer_credential(match: "re.Match") -> str:
    """A standalone `Bearer X` is masked when X looks like a token (has a digit), not a word."""
    return match.group(1) + REDACTED if re.search(r"\d", match.group(2)) else match.group(0)


def _assigned_value(match: "re.Match") -> str:
    value = match.group(2)
    bare = value.strip("\"'").strip().lower()
    if bare in _NOT_A_VALUE:
        return match.group(0)
    quote = value[0] if value[:1] in ("'", '"') else ""
    return match.group(1) + quote + REDACTED + quote


def mask_sdp_keys(text: str, mask: str = REDACTED) -> str:
    """SDP with every SRTP master key (a=crypto inline:), key-mgmt payload and k= key replaced by mask."""
    if not isinstance(text, str) or not text:
        return text
    text = _SDP_INLINE.sub(lambda m: m.group(1) + mask, text)
    text = _SDP_KEY_MGMT.sub(lambda m: m.group(1) + mask, text)
    return _SDP_K_LINE.sub(lambda m: m.group(1) + mask, text)


# One list, applied in order by mask_secret_shapes and so by redact_text, which every output
# path (the streams, the log filter, write_redacted, redact, the LLM prompt) goes through.
SECRET_SHAPES = (
    (_PEM_PRIVATE_KEY, lambda m: f"-----BEGIN {m.group(1)}-----{REDACTED}-----END {m.group(1)}-----"),
    (_JWT, REDACTED),
    (_AUTH_HEADER, lambda m: m.group(1) + m.group(2) + m.group(3) + REDACTED),
    (_TOKEN_SHAPES, REDACTED),
    (_BEARER, _bearer_credential),
    (_BASIC, _basic_credential),
    (_ASSIGNMENT, _assigned_value),
    (_COLON_ASSIGNMENT, _assigned_value),
    (_SDP_INLINE, lambda m: m.group(1) + REDACTED),
    (_SDP_KEY_MGMT, lambda m: m.group(1) + REDACTED),
    (_SDP_K_LINE, lambda m: m.group(1) + REDACTED),
)


def mask_secret_shapes(text: str) -> str:
    """Mask every SECRET_SHAPES match in text (secrets S.O.N.I.C. was never given)."""
    if not isinstance(text, str) or not text:
        return text
    for pattern, replacement in SECRET_SHAPES:
        text = pattern.sub(replacement, text)
    return text

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


class EnvFileError(Exception):
    """The env file could not be used. The message names the path and line, never a value."""


class _State:
    def __init__(self):
        self.file_values: Dict[str, str] = {}
        self.file_path: Optional[str] = None
        self.loaded = False


_state = _State()


def parse_dotenv(text: str, wanted=API_KEY_NAMES, path: str = "env file") -> Dict[str, str]:
    """
    Parse dotenv text as literal data and return only the wanted keys.

    A line is KEY=VALUE with an optional "export " prefix. A value in single or
    double quotes is taken literally up to the closing quote; an unquoted value
    ends at " #" (an inline comment) or the end of the line. Blank lines and
    lines starting with # are skipped. A malformed line is an error that names
    the line number only. Lines for other keys are skipped without being kept.
    """
    found: Dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE.match(raw)
        if not match:
            raise EnvFileError(f"{path}: line {number} is not KEY=VALUE")
        name, value = match.group(1), match.group(2)
        if name not in wanted:
            continue
        if value[:1] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            if end < 0:
                raise EnvFileError(f"{path}: line {number} has an unterminated quote")
            rest = value[end + 1:].strip()
            if rest and not rest.startswith("#"):
                raise EnvFileError(f"{path}: line {number} has text after the closing quote")
            value = value[1:end]
        else:
            comment = re.search(r"\s#", value)
            if comment:
                value = value[:comment.start()].rstrip()
        found[name] = value
    return found


def configure(env_file: Optional[str] = None) -> None:
    """
    Load the dotenv file once: env_file (from --env-file) or else $SONIC_ENV_FILE.

    Without either, nothing is read. Raises EnvFileError when the named file
    cannot be read or parsed; the message never contains file content.
    """
    path = env_file or os.environ.get(ENV_FILE_VARIABLE) or None
    _state.file_values = {}
    _state.file_path = None
    _state.loaded = True
    if not path:
        return
    path = os.path.abspath(os.path.expanduser(path))
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise EnvFileError(f"cannot read env file {path}: {exc.strerror or type(exc).__name__}") from None
    except UnicodeDecodeError:
        raise EnvFileError(f"env file {path} is not UTF-8 text") from None
    _state.file_values = {k: v for k, v in parse_dotenv(text, path=path).items() if v}
    _state.file_path = path


def _ensure_loaded() -> None:
    if not _state.loaded:
        configure()


def get_secret(name: str) -> Optional[str]:
    """The value of one API key: the environment first, then the env file."""
    value = os.environ.get(name)
    if value:
        return value
    _ensure_loaded()
    return _state.file_values.get(name)


def credential_status() -> Dict[str, Dict[str, Any]]:
    """For each API key: configured true/false and its source. Never any part of a value."""
    _ensure_loaded()
    status = {}
    for name in API_KEY_NAMES:
        if os.environ.get(name):
            status[name] = {"configured": True, "source": "environment"}
        elif _state.file_values.get(name):
            status[name] = {"configured": True, "source": f"env file {_state.file_path}"}
        else:
            status[name] = {"configured": False, "source": None}
    return status


def _known_secrets():
    values = set()
    for name in API_KEY_NAMES:
        for value in (os.environ.get(name), _state.file_values.get(name)):
            if value and len(value) >= MIN_SECRET_LENGTH:
                values.add(value)
    return sorted(values, key=len, reverse=True)


def redact_text(text: str) -> str:
    """Replace every known key by value, and every SECRET_SHAPES match, with [REDACTED]."""
    if not isinstance(text, str) or not text:
        return text
    for secret in _known_secrets():
        if secret in text:
            text = text.replace(secret, REDACTED)
    return mask_secret_shapes(text)


def redact(value: Any) -> Any:
    """Redact every string inside a result, converting dataclasses and enums to plain JSON types."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, enum.Enum):
        return redact(value.value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: redact(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {redact_text(str(k)) if isinstance(k, str) else k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, set):
        return [redact(v) for v in sorted(value, key=str)]
    if isinstance(value, BaseException):
        return redact_text(str(value))
    return value


def redact_result(fn):
    """Decorator: redact a function's return value (used on every MCP tool)."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return redact(fn(*args, **kwargs))
    return wrapper


class RedactingStream(io.TextIOBase):
    """A text stream that redacts keys from everything written, then passes it on."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        self._stream.write(redact_text(text))
        return len(text)

    def flush(self):
        self._stream.flush()

    def isatty(self):
        return self._stream.isatty()

    def fileno(self):
        return self._stream.fileno()

    @property
    def encoding(self):
        return getattr(self._stream, "encoding", "utf-8")

    @property
    def buffer(self):
        return self._stream.buffer

    def __getattr__(self, name):
        return getattr(self._stream, name)


class RedactingLogFilter(logging.Filter):
    """Redacts keys from a log record's formatted message."""

    def filter(self, record):
        message = record.getMessage()
        cleaned = redact_text(message)
        if cleaned != message:
            record.msg, record.args = cleaned, ()
        return True


def install_output_redaction(stdout: bool = True) -> None:
    """
    Redact keys from stderr, optionally stdout, and every logging handler that exists now.

    Both go through redact_text, so they mask the same SECRET_SHAPES as write_redacted.
    A stream is masked one write at a time: a secret split across two writes is not seen whole.

    The MCP server passes stdout=False: stdout carries its JSON-RPC stream, whose
    tool results are already redacted by redact_result.
    """
    if not isinstance(sys.stderr, RedactingStream):
        sys.stderr = RedactingStream(sys.stderr)
    if stdout and not isinstance(sys.stdout, RedactingStream):
        sys.stdout = RedactingStream(sys.stdout)
    log_filter = RedactingLogFilter()
    loggers = [logging.getLogger()] + [logging.getLogger(name) for name in list(logging.root.manager.loggerDict)]
    for logger in loggers:
        if not any(isinstance(f, RedactingLogFilter) for f in logger.filters):
            logger.addFilter(log_filter)
        for handler in getattr(logger, "handlers", []):
            if not any(isinstance(f, RedactingLogFilter) for f in handler.filters):
                handler.addFilter(log_filter)


def write_redacted(path: str, text: str) -> None:
    """Write a report file with every known key and every SECRET_SHAPES match redacted."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(redact_text(text))
