#!/usr/bin/env python3
"""
Dump the MCP tool definitions the Go server must serve.

The Go MCP server (internal/mcpserver) serves the deterministic tools with the
same names, titles, descriptions, input schemas and annotations as the Python
server in mcp_server.py. This script reads them from the live Python server, the
way an MCP client sees them on the wire, and writes internal/mcpserver/tools.json,
which the Go server embeds. Rerun it after any change to a tool in mcp_server.py.

The LLM tools (analyze_pcap, analyze_pcap_partial_streaming, analyze_batch_pcaps)
and list_llm_providers are left out until the Phase 7 LLM decision.

Run with:  venv/bin/python tools/gen_mcp_tools.py
"""

import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

OUT = os.path.join(HERE, "internal", "mcpserver", "tools.json")
DEFERRED = {"analyze_pcap", "analyze_pcap_partial_streaming", "analyze_batch_pcaps", "list_llm_providers"}


def main() -> int:
    """Write the deterministic tool definitions to OUT and report how many."""
    import mcp_server  # imported here so the path insert above applies

    tools = []
    for tool in asyncio.run(mcp_server.mcp.list_tools()):
        if tool.name in DEFERRED:
            continue
        wire = tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True, mode="json")
        wire.pop("_meta", None)  # fastmcp-only tags, not part of the tool contract
        tools.append(wire)
    text = json.dumps(tools, indent=2, ensure_ascii=False) + "\n"
    if chr(0x2014) in text:
        print("tool text carries an em dash; fix mcp_server.py first", file=sys.stderr)
        return 1
    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"Wrote {len(tools)} tool definitions to {os.path.relpath(OUT, HERE)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
