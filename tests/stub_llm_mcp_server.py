#!/usr/bin/env python3
"""
Test launcher: the real S.O.N.I.C. MCP server with a stubbed streaming LLM.

Only the streaming LLM factory is replaced (ai.streaming_analysis.get_llm_streaming),
by one that streams STUB_REPORT as JSON tokens without any network or key. Every
other part runs as served: argument parsing, credentials, the stdout reservation,
the stdio transport, the tool, SIP extraction, quality and MOS scoring. Used by
test_mcp_stdio.py; never by S.O.N.I.C. itself.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

STUB_REPORT = {"calls": [], "overallAssessment": "stub diagnosis", "stub": True}


def stub_get_llm_streaming(profile="fast", provider=None, model_name=None, on_token=None):
    def stream(prompt):
        for token in json.dumps(STUB_REPORT).split(" "):
            token += " "
            if on_token:
                on_token(token)
            yield token
    return stream


if __name__ == "__main__":
    import ai.streaming_analysis
    ai.streaming_analysis.get_llm_streaming = stub_get_llm_streaming
    import mcp_server
    sys.exit(mcp_server.main(sys.argv[1:]))
