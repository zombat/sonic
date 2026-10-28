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

Every key S.O.N.I.C. knows of, from either source, is redacted by value (and
anything shaped like an Anthropic key by pattern) from MCP tool results, CLI
output, log records, saved reports and the prompts sent to the LLM. Status
reports say only whether a key is configured and where it came from.

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
    """Replace every known key, and anything shaped like an Anthropic key, with [REDACTED]."""
    if not isinstance(text, str) or not text:
        return text
    for secret in _known_secrets():
        if secret in text:
            text = text.replace(secret, REDACTED)
    return KEY_PATTERN.sub(REDACTED, text)


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
    """Write a report file with every key redacted."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(redact_text(text))
