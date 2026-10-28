#!/usr/bin/env python3
"""
Tests for the network MCP tools in mcp_server.py.

1. Each new tool's function is called directly on a fixture.
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
NETWORK_TOOLS = {"analyze_network_pcap", "analyze_vpn_pcap", "analyze_routing_pcap",
                 "analyze_data_plane_pcap", "correlate_pcaps", "merge_pcap_timelines"}


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

    def test_analyze_data_plane_pcap_synthetic(self):
        result = self.call("analyze_data_plane_pcap", file_path=fixture("dp_tls.pcap"),
                           tls_baseline={"versions": ["TLS1.3"]})
        self.assertEqual(result["status"], "success")
        self.assertIn("fail the baseline", result["tls_verdict"])
        self.assertEqual(list(result)[:3], ["status", "overall_status", "path_mtu_verdict"])

    def test_analyze_network_pcap_takes_detector_options(self):
        result = self.call("analyze_network_pcap", file_path=fixture("dp_esp_sizes.pcap"),
                           detectors=["esp_overhead"], options={"esp_overhead": {"tunnel_mtu": 1476}})
        self.assertIn("ESP_EXCEEDS_TRANSPORT_MTU", {i["code"] for i in result["esp_overhead"]["issues"]})

    def test_correlate_pcaps_synthetic(self):
        result = self.call("correlate_pcaps", captures=[
            {"path": fixture("dp_corr_inside.pcap"), "label": "inside"},
            {"path": fixture("dp_corr_outside.pcap"), "label": "outside"}])
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["nat"])
        bad = self.call("correlate_pcaps", captures=[{"path": fixture("dp_corr_inside.pcap"), "label": "x"}])
        self.assertEqual(bad["status"], "error")

    def test_merge_pcap_timelines_synthetic(self):
        result = self.call("merge_pcap_timelines", captures=[
            {"path": fixture("ospf_failover.pcap"), "label": "core"}],
            measurements=[{"name": "ospf", "from": {"event": "neighbor_down"}, "to": {"event": "neighbor_up"},
                           "max_s": 15}])
        self.assertEqual(result["measurements"][0]["verdict"], "within")

    def test_tool_descriptions_teach_usage(self):
        for name in NETWORK_TOOLS:
            tool = getattr(self.server, name)
            doc = (getattr(tool, "fn", tool).__doc__ or "")
            with self.subTest(tool=name):
                self.assertIn("Args:", doc)
                self.assertIn("Returns:", doc)
                self.assertIn("Example:", doc)
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
                return tools, call

        tools, call = asyncio.run(asyncio.wait_for(session(), timeout=120))
        names = {tool.name for tool in tools}
        self.assertTrue(EXISTING_TOOLS <= names, names)
        self.assertTrue(NETWORK_TOOLS <= names, names)
        described = {tool.name: tool.description or "" for tool in tools}
        self.assertIn("encryption_verdict", described["analyze_vpn_pcap"])
        data = call.data if hasattr(call, "data") else json.loads(call.content[0].text)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["encryption_verdict"], "encrypted")
        self.assertTrue(data["ipsec"]["nat_traversal"]["in_use"])


if __name__ == "__main__":
    unittest.main()
