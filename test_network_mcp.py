#!/usr/bin/env python3
"""
Tests for the network MCP tools in mcp_server.py.

1. Each network tool's function is called directly on a (synthetic) fixture.
2. A real MCP stdio handshake: the server is started as a child process through
   a fastmcp Client, the tool list is read, and a network tool is called over the
   protocol.

Run with:  python3 -m pytest -q test_network_mcp.py
"""

import asyncio
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
SERVER = os.path.join(HERE, "mcp_server.py")

EXISTING_TOOLS = {"analyze_pcap", "quick_quality_check", "list_llm_providers",
                  "analyze_batch_pcaps", "analyze_pcap_partial_streaming"}
NETWORK_TOOLS = {"analyze_network_pcap", "analyze_vpn_pcap", "analyze_routing_pcap", "audit_cleartext_pcap",
                 "analyze_convergence_pcap"}


def fixture(name):
    return os.path.join(FIXTURES, name)


class TestNetworkToolFunctions(unittest.TestCase):
    """The tool functions, called the way the MCP server calls them."""

    @classmethod
    def setUpClass(cls):
        import mcp_server
        cls.server = mcp_server

    def call(self, name, **kwargs):
        tool = getattr(self.server, name)
        fn = getattr(tool, "fn", tool)  # older fastmcp wraps the function in a Tool object
        result = fn(**kwargs)
        json.dumps(result)
        return result

    def test_analyze_network_pcap(self):
        result = self.call("analyze_network_pcap", file_path=fixture("bgp_session.pcap"))
        self.assertEqual(result["status"], "success")
        self.assertIn("routing", result["detectors_run"])
        self.assertIn("BGP:", result["verdicts"]["routing"])

    def test_analyze_network_pcap_reports_errors_as_data(self):
        result = self.call("analyze_network_pcap", file_path=fixture("bgp_session.pcap"), detectors=["bogus"])
        self.assertEqual(result["status"], "error")
        self.assertIn("valid_detectors", result)

    def test_analyze_vpn_pcap(self):
        result = self.call("analyze_vpn_pcap", file_path=fixture("ipsec_cleartext_icmp.pcap"),
                           peers=["192.0.2.1", "198.51.100.2"])
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["encryption_verdict"], "cleartext_seen")
        self.assertIn("cleartext seen: icmp", result["verdict"])

    def test_analyze_routing_pcap(self):
        result = self.call("analyze_routing_pcap", file_path=fixture("ospf_failover.pcap"))
        self.assertEqual(result["status"], "success")
        self.assertTrue(any(e["event"] == "neighbor_down" for e in result["failover_timeline"]))

    def test_audit_cleartext_pcap(self):
        result = self.call("audit_cleartext_pcap", file_path=fixture("audit_one_leak.pcap"))
        self.assertEqual(result["status"], "success")
        self.assertFalse(result["passed"])
        self.assertEqual(result["first_violation_frame"], 9)
        allowed = self.call("audit_cleartext_pcap", file_path=fixture("audit_one_leak.pcap"),
                            allow=["crypto", "arp", "l2-control", "icmp", "gre"])
        self.assertTrue(allowed["passed"])
        bad = self.call("audit_cleartext_pcap", file_path=fixture("audit_one_leak.pcap"), allow=["bogus"])
        self.assertEqual(bad["status"], "error")

    def test_analyze_convergence_pcap(self):
        result = self.call("analyze_convergence_pcap", file_path=fixture("convergence_dpd.pcap"), event_time="+30")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["driver"]["mechanism"], "dpd")
        self.assertEqual(result["measurements"]["event_to_traffic_resumed_s"], 12.0)

    def test_new_options_reach_the_detectors(self):
        vpn = self.call("analyze_vpn_pcap", file_path=fixture("phase3_encrypted.pcap"),
                        hubs=["192.0.2.1", "192.0.2.2"])
        self.assertIn("1 of 2 encrypted spoke-to-spoke shortcut", vpn["phase3_verdict"])
        routing = self.call("analyze_routing_pcap", file_path=fixture("bgp_failover.pcap"), expected_mss=1360)
        self.assertTrue(any(i["code"] == "BGP_MSS_NOT_CLAMPED" for i in routing["issues"]))

    def test_tool_descriptions_teach_usage(self):
        # fastmcp keeps only the text before the first docstring section (Args:, Returns:, ...)
        # as the description a client sees, so returns, limits and examples live in that text.
        tools = {tool.name: tool for tool in asyncio.run(self.server.mcp.list_tools())}
        for name in NETWORK_TOOLS:
            tool = getattr(self.server, name)
            doc = (getattr(tool, "fn", tool).__doc__ or "")
            description = tools[name].description or ""
            with self.subTest(tool=name):
                self.assertIn("Args:", doc)
                self.assertIn("Returns a JSON object", description)
                self.assertIn("For example", description)
                self.assertNotIn(chr(0x2014), doc)  # no em dashes in tool descriptions


class TestMcpStdioHandshake(unittest.TestCase):
    """A real MCP session over stdio against a child server process."""

    def test_handshake_lists_and_calls_tools(self):
        from fastmcp import Client

        async def session():
            config = {"mcpServers": {"sonic": {"command": sys.executable, "args": [SERVER],
                                               "env": {"SONIC_LLM_PROVIDER": "ollama"}}}}
            async with Client(config) as client:
                tools = await client.list_tools()
                call = await client.call_tool("analyze_vpn_pcap", {"file_path": fixture("ipsec_natt.pcap")})
                audit = await client.call_tool("audit_cleartext_pcap", {"file_path": fixture("audit_one_leak.pcap"),
                                                                        "allow": ["crypto"]})
                conv = await client.call_tool("analyze_convergence_pcap",
                                              {"file_path": fixture("convergence_dpd.pcap"), "event_time": 30})
                return tools, call, audit, conv

        tools, call, audit, conv = asyncio.run(asyncio.wait_for(session(), timeout=120))
        names = {tool.name for tool in tools}
        self.assertTrue(EXISTING_TOOLS <= names, names)
        self.assertTrue(NETWORK_TOOLS <= names, names)
        described = {tool.name: tool.description or "" for tool in tools}
        self.assertIn("encryption_verdict", described["analyze_vpn_pcap"])
        data = call.data if hasattr(call, "data") else json.loads(call.content[0].text)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["encryption_verdict"], "encrypted")
        self.assertTrue(data["ipsec"]["nat_traversal"]["in_use"])
        self.assertIn("passed", described["audit_cleartext_pcap"])
        self.assertIn("event_time", described["analyze_convergence_pcap"])
        audit = audit.data if hasattr(audit, "data") else json.loads(audit.content[0].text)
        self.assertEqual(audit["result"], "fail")
        conv = conv.data if hasattr(conv, "data") else json.loads(conv.content[0].text)
        self.assertEqual(conv["driver"]["mechanism"], "dpd")


if __name__ == "__main__":
    unittest.main()
