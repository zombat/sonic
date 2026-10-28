#!/usr/bin/env python3
"""
Tests for API key loading and redaction (utils/credentials.py).

Every test uses a temporary env file holding dummy keys and asserts that the
dummy never appears in anything S.O.N.I.C. prints, writes or returns: MCP tool
results (called directly and over a real stdio session), CLI output, saved
reports, log records, and the prompt handed to the LLM client.

Run with:  python3 -m pytest -q test_credentials.py
"""

import asyncio
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "mcp_server.py")
CLI = os.path.join(HERE, "sonic.py")
FIXTURE = os.path.join(HERE, "tests", "fixtures", "ipsec_natt.pcap")

# Dummies only. One has the Anthropic key shape, one does not (redacted by value).
DUMMY_ANTHROPIC = "sk-ant-api03-DUMMYdummyDUMMY0123456789-test"
DUMMY_OPENAI = "dummy-openai-value-0123456789"
KEY_NAMES = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_KEY", "SONIC_ENV_FILE")

from utils import credentials  # noqa: E402


def clean_env(**extra):
    """The process environment without any real key, plus extra."""
    env = {k: v for k, v in os.environ.items() if k not in KEY_NAMES}
    env.update(extra)
    return env


class EnvFileCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env_file = os.path.join(self.tmp.name, "test.env")
        with open(self.env_file, "w", encoding="utf-8") as handle:
            handle.write(
                "# a comment\n"
                "export OTHER_SECRET=not-for-sonic-0123456789\n"
                f"ANTHROPIC_API_KEY=\"{DUMMY_ANTHROPIC}\"\n"
                f"OPENAI_API_KEY={DUMMY_OPENAI}  # inline comment\n"
            )
        patcher = mock.patch.dict(os.environ, clean_env(), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        credentials.configure(self.env_file)
        self.addCleanup(credentials.configure, None)

    def tearDown(self):
        self.tmp.cleanup()

    def assertClean(self, text):
        self.assertNotIn(DUMMY_ANTHROPIC, text)
        self.assertNotIn(DUMMY_OPENAI, text)
        self.assertNotIn("sk-ant-", text)


class TestParser(unittest.TestCase):
    def test_literal_values_quotes_and_comments(self):
        text = ("# comment\n\nexport ANTHROPIC_API_KEY='a b $HOME #x'\n"
                "OPENAI_API_KEY=plain-value # trailing\nAZURE_OPENAI_KEY=\"q\"  # c\nIGNORED=1\n")
        self.assertEqual(credentials.parse_dotenv(text), {
            "ANTHROPIC_API_KEY": "a b $HOME #x", "OPENAI_API_KEY": "plain-value", "AZURE_OPENAI_KEY": "q"})

    def test_other_keys_are_not_kept(self):
        self.assertEqual(credentials.parse_dotenv("SECRET=x\nAWS_KEY=y\n"), {})

    def test_errors_name_the_line_never_the_value(self):
        for text in (f"ANTHROPIC_API_KEY=\"{DUMMY_ANTHROPIC}\n", f"not a line {DUMMY_ANTHROPIC}\n"):
            with self.assertRaises(credentials.EnvFileError) as ctx:
                credentials.parse_dotenv(text, path="/x/.env")
            self.assertIn("line 1", str(ctx.exception))
            self.assertNotIn(DUMMY_ANTHROPIC, str(ctx.exception))

    def test_missing_file_names_the_path_only(self):
        with mock.patch.dict(os.environ, clean_env(), clear=True):
            with self.assertRaises(credentials.EnvFileError) as ctx:
                credentials.configure("/nonexistent/sonic.env")
            self.assertIn("/nonexistent/sonic.env", str(ctx.exception))
        credentials.configure(None)


class TestLoading(EnvFileCase):
    def test_env_file_supplies_the_key_and_status_says_where(self):
        self.assertEqual(credentials.get_secret("ANTHROPIC_API_KEY"), DUMMY_ANTHROPIC)
        status = credentials.credential_status()
        self.assertEqual(status["ANTHROPIC_API_KEY"],
                         {"configured": True, "source": f"env file {os.path.abspath(self.env_file)}"})
        self.assertEqual(status["AZURE_OPENAI_KEY"], {"configured": False, "source": None})
        self.assertClean(json.dumps(status))
        self.assertNotIn("not-for-sonic", json.dumps(credentials._state.file_values))
        self.assertNotIn("ANTHROPIC_API_KEY", os.environ)  # never copied into the environment

    def test_environment_wins_over_the_file(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "from-the-environment-123"}):
            self.assertEqual(credentials.get_secret("ANTHROPIC_API_KEY"), "from-the-environment-123")
            self.assertEqual(credentials.credential_status()["ANTHROPIC_API_KEY"]["source"], "environment")

    def test_sonic_env_file_variable_is_the_default(self):
        with mock.patch.dict(os.environ, {"SONIC_ENV_FILE": self.env_file}):
            credentials.configure(None)
            self.assertEqual(credentials.get_secret("OPENAI_API_KEY"), DUMMY_OPENAI)

    def test_redaction_by_value_and_by_shape(self):
        text = f"auth failed for {DUMMY_OPENAI}; key {DUMMY_ANTHROPIC}; other sk-ant-api03-zzz"
        self.assertClean(credentials.redact_text(text))
        nested = credentials.redact({"a": [DUMMY_OPENAI, {"b": (DUMMY_ANTHROPIC,)}], "n": 3})
        self.assertClean(json.dumps(nested))
        self.assertEqual(nested["n"], 3)

    def test_streams_and_logs_are_redacted(self):
        sink = io.StringIO()
        stream = credentials.RedactingStream(sink)
        print(f"error: {DUMMY_OPENAI}", file=stream)
        self.assertClean(sink.getvalue())
        self.assertIn(credentials.REDACTED, sink.getvalue())
        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "key %s", (DUMMY_ANTHROPIC,), None)
        credentials.RedactingLogFilter().filter(record)
        self.assertClean(record.getMessage())

    def test_saved_reports_are_redacted(self):
        import shutil
        from analyzers.network_orchestrator import analyze_network_capture
        from utils.network_reporting import save_network_report
        capture = os.path.join(self.tmp.name, f"{DUMMY_OPENAI}.pcap")  # the key lands in report["file"]
        shutil.copy(FIXTURE, capture)
        report = analyze_network_capture(capture)
        self.assertIn(DUMMY_OPENAI, report["file"])
        for name in ("r.json", "r.md"):
            path = os.path.join(self.tmp.name, name)
            save_network_report(report, path)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertClean(text)
            self.assertIn(credentials.REDACTED, text)


class TestLlmConfig(EnvFileCase):
    def test_anthropic_models(self):
        from llm_config import LLMConfig
        config = LLMConfig("anthropic")
        self.assertEqual(config.get_model_name("fast"), "claude-haiku-5-5")
        self.assertEqual(config.get_model_name("detailed"), "claude-sonnet-5-5")
        self.assertEqual(config.get_model_name("deep"), "claude-opus-5-5")
        self.assertEqual(LLMConfig("openai").get_model_name("deep"), "gpt-4o")  # falls back to detailed

    def test_key_reaches_the_client_but_never_the_prompt(self):
        import dspy
        from llm_config import RedactingLM, get_llm
        lm = get_llm("detailed", "anthropic")
        self.assertIsInstance(lm, RedactingLM)
        self.assertEqual(lm.model, "anthropic/claude-sonnet-5-5")
        self.assertEqual(lm.kwargs.get("api_key"), DUMMY_ANTHROPIC)
        self.assertIsNone(lm.kwargs.get("temperature"))  # current Claude models 400 on a non-default value
        seen = {}

        def capture(self_lm, prompt=None, *, messages=None, **kwargs):
            seen["prompt"], seen["messages"] = prompt, messages
            return ["ok"]

        with mock.patch.object(dspy.LM, "__call__", capture):
            lm(messages=[{"role": "user", "content": f"SIP header has {DUMMY_ANTHROPIC} and {DUMMY_OPENAI}"}])
            lm(f"prompt with {DUMMY_OPENAI}")
        self.assertClean(json.dumps(seen))
        self.assertIn(credentials.REDACTED, json.dumps(seen))


class TestMcpTools(EnvFileCase):
    def test_list_llm_providers_reports_status_only(self):
        import mcp_server
        result = mcp_server.list_llm_providers()
        dumped = json.dumps(result)
        self.assertClean(dumped)
        creds = result["current_config"]["credentials"]
        self.assertTrue(creds["ANTHROPIC_API_KEY"]["configured"])
        self.assertIn(os.path.abspath(self.env_file), creds["ANTHROPIC_API_KEY"]["source"])
        self.assertEqual(result["models"]["anthropic"]["deep"], "claude-opus-5-5")

    def test_tool_results_are_redacted(self):
        import mcp_server
        result = mcp_server.analyze_network_pcap(file_path=f"/nonexistent/{DUMMY_OPENAI}.pcap")
        self.assertEqual(result["status"], "error")
        self.assertClean(json.dumps(result))
        self.assertIn(credentials.REDACTED, result["error"])


class TestOverProcesses(unittest.TestCase):
    """The real entry points, with the dummy file named by SONIC_ENV_FILE or --env-file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env_file = os.path.join(self.tmp.name, "test.env")
        with open(self.env_file, "w", encoding="utf-8") as handle:
            handle.write(f"ANTHROPIC_API_KEY={DUMMY_ANTHROPIC}\nOPENAI_API_KEY={DUMMY_OPENAI}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def assertClean(self, text):
        self.assertNotIn(DUMMY_ANTHROPIC, text)
        self.assertNotIn(DUMMY_OPENAI, text)

    def test_cli_never_prints_the_key(self):
        missing = os.path.join(self.tmp.name, f"{DUMMY_OPENAI}.pcap")
        done = subprocess.run([sys.executable, CLI, "--env-file", self.env_file, "--file", missing,
                               "--network-only", "--json"], cwd=HERE, env=clean_env(),
                              capture_output=True, text=True, timeout=300)
        self.assertEqual(done.returncode, 1)
        self.assertClean(done.stdout + done.stderr)
        self.assertIn(credentials.REDACTED, done.stdout)

    def test_cli_refuses_a_missing_env_file(self):
        done = subprocess.run([sys.executable, CLI, "--env-file", "/nonexistent/x.env", "--file", FIXTURE,
                               "--network-only"], cwd=HERE, env=clean_env(), capture_output=True, text=True,
                              timeout=300)
        self.assertEqual(done.returncode, 2)
        self.assertIn("cannot read env file /nonexistent/x.env", done.stderr)

    def test_mcp_session_never_returns_the_key(self):
        from fastmcp import Client

        async def session():
            env = clean_env(SONIC_ENV_FILE=self.env_file)
            config = {"mcpServers": {"sonic": {"command": sys.executable, "args": [SERVER], "env": env}}}
            async with Client(config) as client:
                providers = await client.call_tool("list_llm_providers", {})
                failed = await client.call_tool("analyze_network_pcap",
                                                {"file_path": f"/nonexistent/{DUMMY_ANTHROPIC}.pcap"})
                return providers, failed

        providers, failed = asyncio.run(asyncio.wait_for(session(), timeout=120))
        for call in (providers, failed):
            text = json.dumps(call.structured_content) + "".join(getattr(c, "text", "") for c in call.content)
            self.assertClean(text)
        creds = providers.structured_content["current_config"]["credentials"]
        self.assertEqual(creds["ANTHROPIC_API_KEY"], {"configured": True, "source": f"env file {self.env_file}"})


if __name__ == "__main__":
    unittest.main()
