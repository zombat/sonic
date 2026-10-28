#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Protocol Stdout

On the MCP stdio transport, stdout is the JSON-RPC channel: one stray byte from a
print() corrupts it, and a client may drop the session or misread a response.
The SIP, network, extractor and reporting code prints progress for the CLI, so
the MCP server reserves stdout for the protocol before it serves:

1. the real stdout is duplicated onto a private descriptor, the protocol channel;
2. descriptor 1 is pointed at stderr, so a child process (tshark), C code, and
   any object that captured the original sys.stdout (or sys.__stdout__) write to
   stderr;
3. sys.stdout becomes a text stream that writes to sys.stderr, and whose .buffer
   is the protocol channel.

Step 3 is how the protocol keeps the real stdout. The MCP SDK's stdio_server()
writes the protocol to sys.stdout.buffer: the mcp 1.x SDK always does, and the
2.x SDK does when sys.stdout is not backed by descriptor 1 (otherwise it claims
descriptor 1 itself, and output still buffered in sys.stdout when the session
ends is flushed onto the wire at exit). Text written to sys.stdout, by print()
or anything else, never reaches .buffer. The CLI never calls this, so its
output is unchanged.

Author: Raymond A Rizzo | Zombat
"""

import io
import os
import sys


class StdoutToStderr(io.TextIOBase):
    """
    sys.stdout while the MCP server serves: text goes to stderr; .buffer is the
    protocol channel, which only the MCP transport writes.
    """

    def __init__(self, text_stream, protocol_buffer):
        self._text = text_stream
        self._protocol = protocol_buffer

    def write(self, text):
        self._text.write(text)
        return len(text)

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def flush(self):
        self._text.flush()

    def writable(self):
        return True

    def isatty(self):
        return self._text.isatty()

    def fileno(self):
        return self._text.fileno()

    @property
    def encoding(self):
        return getattr(self._text, "encoding", "utf-8")

    @property
    def errors(self):
        return getattr(self._text, "errors", "strict")

    @property
    def buffer(self):
        return self._protocol


def reserve_stdout_for_protocol():
    """
    Keep the real stdout for the MCP protocol and send every other write to stderr.

    Returns the binary protocol stream. Call it once, just before serving over
    stdio, after the stderr redaction is installed.
    """
    if isinstance(sys.stdout, StdoutToStderr):
        return sys.stdout.buffer
    if sys.stdout is not None:
        sys.stdout.flush()
    protocol_fd = os.dup(1)
    os.dup2(2, 1)
    protocol = os.fdopen(protocol_fd, "wb")
    sys.stdout = StdoutToStderr(sys.stderr, protocol)
    return protocol
