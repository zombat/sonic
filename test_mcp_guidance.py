#!/usr/bin/env python3
"""
Tests for the guidance S.O.N.I.C. gives an AI agent (utils/agent_guide.py).

1. The MCP server: its instructions name every tool, every tool has a title,
   annotations and a client-visible description that says when to use it, what
   it costs and what it returns, and the guide resources and workflow prompts
   are registered.
2. The Agent Skill written by --create-skill: valid frontmatter, a short body,
   reference files that name every MCP tool, parameter, detector and issue
   code, refusal to replace a file it did not write, and a rerun that changes
   nothing.
3. Both entry points (sonic.py and mcp_server.py) and a real MCP stdio session.

Run with:  python3 -m pytest -q test_mcp_guidance.py
"""

import asyncio
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "mcp_server.py")
CLI = os.path.join(HERE, "sonic.py")
EM_DASH = chr(0x2014)

import mcp_server  # noqa: E402
from analyzers import network_orchestrator as orch  # noqa: E402
from utils import agent_guide as guide  # noqa: E402


def server_tools():
    return list(asyncio.run(mcp_server.mcp.list_tools()))


def frontmatter(text):
    """The YAML frontmatter of a SKILL.md as a dict, and the body after it."""
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not match:
        raise AssertionError("SKILL.md has no frontmatter")
    import yaml
    return yaml.safe_load(match.group(1)), match.group(2)


class TestServerGuidance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = server_tools()
        cls.names = {tool.name for tool in cls.tools}

    def test_tool_guide_matches_the_registered_tools(self):
        self.assertEqual({row["name"] for row in guide.TOOL_GUIDE}, self.names)

    def test_instructions_are_set_short_and_name_every_tool(self):
        text = mcp_server.mcp.instructions
        self.assertTrue(text)
        self.assertLess(len(text), 2048)  # some clients cap server instructions at 2 KB
        self.assertNotIn(EM_DASH, text)
        for name in self.names:
            self.assertIn(name, text)
        for word in ("absolute", "[LLM]", "max_items", "status", "capture point"):
            self.assertIn(word, text)

    def test_every_tool_teaches_itself(self):
        for tool in self.tools:
            with self.subTest(tool=tool.name):
                description = tool.description or ""
                self.assertGreater(len(description), 200)
                self.assertIn("Returns", description)  # the client sees what comes back
                self.assertIn("For example", description)
                self.assertIn("LLM", description)  # says whether it calls one
                self.assertNotIn(EM_DASH, description)
                self.assertTrue(tool.title)
                for pname, schema in tool.parameters.get("properties", {}).items():
                    self.assertTrue(schema.get("description"), f"{tool.name}.{pname} has no description")

    def test_annotations_follow_the_tool_guide(self):
        rows = {row["name"]: row for row in guide.TOOL_GUIDE}
        for tool in self.tools:
            with self.subTest(tool=tool.name):
                notes = tool.annotations
                self.assertTrue(notes.readOnlyHint)
                self.assertFalse(notes.destructiveHint)
                self.assertEqual(notes.idempotentHint, not rows[tool.name]["llm"])
                self.assertEqual(notes.openWorldHint, rows[tool.name]["llm"])

    def test_prompts_and_resources_are_registered(self):
        prompts = {p.name for p in asyncio.run(mcp_server.mcp.list_prompts())}
        self.assertEqual(prompts, {w["name"] for w in guide.WORKFLOWS})
        uris = {str(r.uri) for r in asyncio.run(mcp_server.mcp.list_resources())}
        expected = {f"sonic://guide/{topic}" for topic, _ in guide.TOPICS} | {"sonic://guide/overview"}
        self.assertEqual(uris, expected)

    def test_workflow_text_fills_arguments(self):
        text = guide.workflow_text("check_vpn_encryption", file_path="/c/wan.pcap", peers=["192.0.2.1"])
        self.assertIn("analyze_vpn_pcap(file_path='/c/wan.pcap', peers=['192.0.2.1'])", text)
        self.assertIn("<file_path>", guide.workflow_text("diagnose_capture"))


class TestSkill(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = server_tools()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "sonic")

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, rel):
        with open(os.path.join(self.dir, rel), encoding="utf-8") as handle:
            return handle.read()

    def create(self):
        return guide.create_skill(self.dir, server=mcp_server.mcp)

    def test_skill_md_has_valid_frontmatter_and_a_short_body(self):
        self.create()
        meta, body = frontmatter(self.read("SKILL.md"))
        self.assertEqual(meta["name"], guide.SKILL_NAME)
        self.assertRegex(meta["name"], r"^[a-z0-9-]{1,64}$")
        self.assertLessEqual(len(meta["description"]), 1024)
        self.assertIn("Use when", meta["description"])
        self.assertLess(len(body.splitlines()), 150)
        for topic, _title in guide.TOPICS:
            self.assertIn(f"(reference/{topic}.md)", body)
            self.assertTrue(os.path.isfile(os.path.join(self.dir, "reference", f"{topic}.md")))
        for row in guide.TOOL_GUIDE:
            self.assertIn(f"`{row['name']}`", body)

    def test_reference_files_name_every_tool_parameter_detector_and_code(self):
        self.create()
        tools_md = self.read("reference/mcp-tools.md")
        for tool in self.tools:
            self.assertIn(f"## `{tool.name}`", tools_md)
            for pname in tool.parameters.get("properties", {}):
                self.assertIn(f"`{pname}`", tools_md)
        detectors_md = self.read("reference/network-detectors.md")
        for name in orch.DETECTOR_NAMES:
            self.assertIn(f"`{name}`", detectors_md)
        self.assertNotIn("<computed>", detectors_md)
        for code in ("IKE_NO_RESPONSE", "CLEARTEXT_BETWEEN_PEERS", "NHRP_REGISTRATION_REFUSED",
                     "OSPF_HELLO_INTERVAL_MISMATCH", "BGP_TCP_REFUSED", "EIGRP_K_VALUE_MISMATCH", "ICMP_LOSS"):
            self.assertIn(f"`{code}`", detectors_md)
        cli_md = self.read("reference/cli.md")
        for option in ("--network-only", "--detectors", "--peers", "--quality-only", "--create-skill"):
            self.assertIn(f"`{option}`", cli_md)
        self.assertIn("anthropic", self.read("reference/sip-rtp.md"))
        for rel in ["SKILL.md"] + [f"reference/{t}.md" for t, _ in guide.TOPICS]:
            text = self.read(rel)
            self.assertTrue(guide.written_by_sonic(os.path.join(self.dir, rel)), rel)
            self.assertNotIn(EM_DASH, text, rel)

    def test_issue_codes_come_from_every_make_issue_call(self):
        groups = guide.detector_modules()
        self.assertEqual(sorted(n for g in groups for n in g["names"]), sorted(orch.DETECTOR_NAMES))
        codes = {c for g in groups for c in g["codes"]}
        self.assertIn("OSPF_AREA_MISMATCH", codes)  # resolved from the checks table a loop walks
        self.assertIn("IKE_<...>", codes)  # an f-string code

    def test_rerun_changes_nothing(self):
        first = self.create()
        self.assertEqual(len(first["written"]), 1 + len(guide.TOPICS))
        before = {rel: self.read(rel) for rel in first["written"]}
        second = self.create()
        self.assertEqual(second["written"], [])
        self.assertEqual(sorted(second["unchanged"]), sorted(first["written"]))
        self.assertEqual(before, {rel: self.read(rel) for rel in before})
        leftovers = [n for _, _, files in os.walk(self.dir) for n in files if n.startswith(".sonic-skill-")]
        self.assertEqual(leftovers, [])

    def test_refuses_a_skill_md_it_did_not_write(self):
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: sonic\ndescription: mine\n---\nhand written\n")
        with self.assertRaises(guide.SkillWriteRefused):
            self.create()
        self.assertIn("hand written", self.read("SKILL.md"))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "reference")))

    def test_refuses_a_reference_file_it_did_not_write(self):
        os.makedirs(os.path.join(self.dir, "reference"))
        with open(os.path.join(self.dir, "reference", "cli.md"), "w", encoding="utf-8") as handle:
            handle.write("my notes\n")
        with self.assertRaises(guide.SkillWriteRefused):
            self.create()
        self.assertEqual(self.read("reference/cli.md"), "my notes\n")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "SKILL.md")))

    def test_removes_only_its_own_stale_reference_files(self):
        self.create()
        stale = os.path.join(self.dir, "reference", "old-topic.md")
        mine = os.path.join(self.dir, "reference", "notes.md")
        with open(stale, "w", encoding="utf-8") as handle:
            handle.write(f"{guide.SKILL_MARKER}; it replaces this file. -->\n\nold\n")
        with open(mine, "w", encoding="utf-8") as handle:
            handle.write("kept\n")
        result = self.create()
        self.assertEqual(result["removed"], ["reference/old-topic.md"])
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(mine))


class TestEntryPoints(unittest.TestCase):
    """--create-skill through the real command lines."""

    def run_cli(self, script, target):
        return subprocess.run([sys.executable, script, "--create-skill", target], cwd=HERE,
                              capture_output=True, text=True, timeout=300)

    def test_sonic_cli_writes_then_refuses_a_foreign_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sonic")
            done = self.run_cli(CLI, target)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("Skill 'sonic'", done.stdout)
            self.assertTrue(os.path.isfile(os.path.join(target, "SKILL.md")))
            other = os.path.join(tmp, "other")
            os.makedirs(other)
            with open(os.path.join(other, "SKILL.md"), "w", encoding="utf-8") as handle:
                handle.write("foreign\n")
            refused = self.run_cli(CLI, other)
            self.assertEqual(refused.returncode, 1)
            self.assertIn("not written by sonic --create-skill", refused.stderr)

    def test_mcp_server_entry_point_writes_the_same_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sonic")
            done = self.run_cli(SERVER, target)
            self.assertEqual(done.returncode, 0, done.stderr)
            files = guide.render_skill(server_tools())
            for rel, content in files.items():
                with open(os.path.join(target, rel), encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), content, rel)

    def test_sonic_cli_still_requires_file(self):
        done = subprocess.run([sys.executable, CLI], cwd=HERE, capture_output=True, text=True, timeout=300)
        self.assertEqual(done.returncode, 2)
        self.assertIn("--file", done.stderr)


class TestStdioGuidance(unittest.TestCase):
    """A real MCP session: the client receives the instructions, prompts and resources."""

    def test_client_sees_instructions_prompts_and_guide(self):
        from fastmcp import Client

        async def session():
            config = {"mcpServers": {"sonic": {"command": sys.executable, "args": [SERVER]}}}
            async with Client(config) as client:
                # fastmcp 4 exposes the negotiated instructions era-neutrally; older
                # clients only through the initialize result.
                init = getattr(client, "instructions", None)
                if init is None and client.initialize_result is not None:
                    init = client.initialize_result.instructions
                prompts = await client.list_prompts()
                prompt = await client.get_prompt("check_vpn_encryption",
                                                 {"file_path": "/c/wan.pcap", "peers": "192.0.2.1, 198.51.100.2"})
                guide_text = await client.read_resource("sonic://guide/mcp-tools")
                return init, prompts, prompt, guide_text

        init, prompts, prompt, guide_text = asyncio.run(asyncio.wait_for(session(), timeout=120))
        self.assertIn("analyze_network_pcap", init or "")
        self.assertIn("sonic://guide/", init)
        self.assertEqual({p.name for p in prompts}, {w["name"] for w in guide.WORKFLOWS})
        message = prompt.messages[0].content.text
        self.assertIn("peers=['192.0.2.1', '198.51.100.2']", message)
        text = guide_text[0].text
        self.assertIn("## `analyze_vpn_pcap`", text)
        self.assertIn("| `peers` |", text)


class TestProviderResolution(unittest.TestCase):
    """Every LLM tool defaults to one provider: its argument, else SONIC_LLM_PROVIDER, else ollama."""

    LLM_TOOLS = [row["name"] for row in guide.TOOL_GUIDE if row["llm"]]

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.env = mock.patch.dict(os.environ)
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("SONIC_LLM_PROVIDER", None)

    def test_no_llm_tool_hard_codes_a_provider_default(self):
        tools = {tool.name: tool for tool in server_tools()}
        for name in self.LLM_TOOLS:
            schema = tools[name].parameters["properties"]["provider"]
            self.assertIsNone(schema.get("default"), name)

    def providers_used(self):
        """Call each LLM tool without provider; return the provider each one handed on."""
        seen = {}
        mock = self.mock
        fixture = os.path.join(HERE, "tests", "fixtures", "sip_minimal.pcap")
        directory = os.path.dirname(fixture)

        def record(name):
            def fake(*_args, **kwargs):
                seen[name] = kwargs.get("provider")
                return {"status": "success"}
            return fake

        import types
        import ai.batch_streaming as batch
        partial = types.ModuleType("ai.partial_streaming")  # the tools import these inside the call
        partial.run_partial_analysis_streaming = record("analyze_pcap_partial_streaming")
        with mock.patch.object(mcp_server, "run_analysis_mode", record("analyze_pcap")), \
                mock.patch.object(batch, "analyze_batch", record("analyze_batch_pcaps")), \
                mock.patch.dict(sys.modules, {"ai.partial_streaming": partial}):
            for name in self.LLM_TOOLS:
                tool = getattr(mcp_server, name)
                fn = getattr(tool, "fn", tool)
                fn(directory=directory) if name == "analyze_batch_pcaps" else fn(file_path=fixture)
        return seen

    def test_without_the_variable_every_tool_uses_ollama(self):
        self.assertEqual(self.providers_used(), {name: "ollama" for name in self.LLM_TOOLS})

    def test_the_variable_sets_every_tool(self):
        os.environ["SONIC_LLM_PROVIDER"] = "anthropic"
        self.assertEqual(self.providers_used(), {name: "anthropic" for name in self.LLM_TOOLS})
        fn = getattr(mcp_server.list_llm_providers, "fn", mcp_server.list_llm_providers)
        self.assertEqual(fn()["current_config"]["provider"], "anthropic")

    def test_the_argument_wins(self):
        os.environ["SONIC_LLM_PROVIDER"] = "anthropic"
        from llm_config import LLMConfig, resolve_provider
        self.assertEqual(resolve_provider("openai"), "openai")
        self.assertEqual(LLMConfig("openai").provider, "openai")
        self.assertEqual(LLMConfig().provider, "anthropic")

    def test_guidance_states_the_resolution(self):
        tools = server_tools()
        for text in (guide.build_instructions(), guide.render_topic("sip-rtp", tools),
                     guide.render_topic("interpreting-results", tools)):
            self.assertIn("SONIC_LLM_PROVIDER", text)
            self.assertNotIn("does not override", text)


class TestCliModelOptions(unittest.TestCase):
    """--api-key is gone; --model-name reaches the LLM; --model all refuses it."""

    def test_no_option_takes_an_api_key(self):
        import sonic
        options = [opt for action in sonic.build_parser()._actions for opt in action.option_strings]
        self.assertFalse([opt for opt in options if "key" in opt], options)
        done = subprocess.run([sys.executable, CLI, "--file", "x.pcap", "--api-key", "abc"], cwd=HERE,
                              capture_output=True, text=True, timeout=300)
        self.assertEqual(done.returncode, 2)
        self.assertIn("unrecognized arguments", done.stderr)

    def test_model_name_reaches_get_llm(self):
        from unittest import mock
        from analyzers import orchestrator
        fixture = os.path.join(HERE, "tests", "fixtures", "sip_minimal.pcap")
        names = []

        def fake_get_llm(profile="fast", provider=None, model_name=None, api_key=None):
            names.append(model_name)
            return object()

        with mock.patch.object(orchestrator, "get_llm", fake_get_llm), \
                mock.patch("ai.analysis.get_llm", fake_get_llm), \
                mock.patch.object(orchestrator, "sip_diagnostic_test", return_value={"status": "error"}), \
                mock.patch("ai.analysis.sip_diagnostic_test", return_value={"status": "error"}):
            for mode in ("fast", "detailed", "deep", "combined"):
                orchestrator.run_analysis_mode(fixture, mode, provider="ollama", model_name="llama3:8b")
        self.assertEqual(names, ["llama3:8b"] * 4)

    def test_model_name_refused_with_all(self):
        done = subprocess.run([sys.executable, CLI, "--file", "x.pcap", "--model", "all",
                               "--model-name", "llama3:8b"], cwd=HERE, capture_output=True, text=True, timeout=300)
        self.assertEqual(done.returncode, 2)
        self.assertIn("--model-name cannot be used with --model all", done.stderr)


if __name__ == "__main__":
    unittest.main()
