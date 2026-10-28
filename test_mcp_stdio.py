#!/usr/bin/env python3
"""
The MCP server's stdout carries only JSON-RPC.

On the stdio transport stdout is the protocol channel, and the SIP path prints
progress lines as it extracts and scores. This test starts the real server as a
child process, speaks JSON-RPC to it over its stdin and stdout by hand (no MCP
client library, so nothing filters what the server wrote), calls the SIP tool and
the network tool on a sample capture, and then holds every byte the server wrote
to stdout, up to its exit, to one rule: each line is one JSON-RPC 2.0 message.
The SIP path's progress lines must have gone to stderr instead.

Run with:  python3 -m pytest -q test_mcp_stdio.py
"""

import json
import os
import queue
import subprocess
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "mcp_server.py")
SIP_CAPTURE = os.path.join(HERE, "tests", "fixtures", "sip_minimal.pcap")
TIMEOUT = 120


class StdioSession:
    """A raw JSON-RPC session with the server: every stdout byte is kept for the assertions."""

    def __init__(self):
        self.proc = subprocess.Popen([sys.executable, SERVER], cwd=HERE, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.lines = queue.Queue()
        self._readers = [threading.Thread(target=self._read_stdout, daemon=True),
                         threading.Thread(target=self._drain, args=(self.proc.stderr, self.stderr), daemon=True)]
        for reader in self._readers:
            reader.start()
        self._next_id = 0

    def _read_stdout(self):
        for line in iter(self.proc.stdout.readline, b""):
            self.stdout.extend(line)
            self.lines.put(line)

    @staticmethod
    def _drain(stream, into):
        for chunk in iter(lambda: stream.read(4096), b""):
            into.extend(chunk)

    def send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def request(self, method, params=None):
        """Send a request and return its response, skipping the server's notifications."""
        self._next_id += 1
        self.send({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params or {}})
        while True:
            line = self.lines.get(timeout=TIMEOUT)
            message = json.loads(line)
            if message.get("id") == self._next_id:
                return message

    def close(self):
        """Close stdin, let the server exit on its own, and collect everything it wrote."""
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for reader in self._readers:
            reader.join(timeout=TIMEOUT)
        self.proc.stdout.close()
        self.proc.stderr.close()


class TestStdoutIsOnlyJsonRpc(unittest.TestCase):

    def test_sip_tool_output_never_reaches_the_protocol_channel(self):
        session = StdioSession()
        try:
            init = session.request("initialize", {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "stdio-purity-test", "version": "0"},
            })
            self.assertIn("result", init, init)
            session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            call = session.request("tools/call", {"name": "quick_quality_check",
                                                  "arguments": {"file_path": SIP_CAPTURE}})
            # The network path, which also runs the SIP scoring when SIP is present.
            network = session.request("tools/call", {"name": "analyze_network_pcap",
                                                     "arguments": {"file_path": SIP_CAPTURE}})
        finally:
            session.close()

        for response in (call, network):
            self.assertIn("result", response, response)
            result = response["result"]
            self.assertFalse(result.get("isError"), result)
            payload = result.get("structuredContent") or json.loads(result["content"][0]["text"])
            payload = payload.get("result", payload)
            self.assertEqual(payload["status"], "success", payload)

        # Every byte on stdout, through the server's exit, is a JSON-RPC message.
        raw = bytes(session.stdout)
        self.assertTrue(raw.endswith(b"\n"), raw[-200:])
        for line in raw.split(b"\n")[:-1]:
            try:
                message = json.loads(line)
            except ValueError:
                self.fail(f"stdout carried a line that is not JSON-RPC: {line[:200]!r}")
            self.assertIsInstance(message, dict, line[:200])
            self.assertEqual(message.get("jsonrpc"), "2.0", line[:200])

        # The SIP path did print, and its lines went to stderr.
        self.assertIn(b"Extracting SIP data", bytes(session.stderr))


if __name__ == "__main__":
    unittest.main()
