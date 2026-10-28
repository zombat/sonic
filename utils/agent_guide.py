#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S.O.N.I.C. Agent Guide

Everything that teaches an AI agent to use S.O.N.I.C., built from one place:

- the MCP server's instructions (sent in the initialize result),
- each MCP tool's title and annotations (read-only, idempotent, open world),
- the guide topics the MCP server serves as resources (sonic://guide/<topic>),
- the Agent Skill that `sonic.py --create-skill` and `mcp_server.py --create-skill`
  write: a short SKILL.md plus one reference/ file per area, which an agent reads
  only when it needs that area (progressive disclosure).

TOOL_GUIDE is the one hand-written table: per MCP tool, the question it answers
and whether it calls an LLM. The tests hold it equal to the tools the server
registers. Everything listed in the reference files (tool parameters and their
schemas, detectors and their issue codes, CLI options, LLM providers, quality
fields) is read from the live code when the guide is rendered, so the skill
cannot drift from the code that answers.

Author: Raymond A Rizzo | Zombat
"""

import ast
import asyncio
import contextlib
import dataclasses
import inspect
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

SKILL_NAME = "sonic"
DEFAULT_SKILL_DIR = os.path.join(".claude", "skills", SKILL_NAME)
# The CLI this skill points at: the sonic.py beside this package.
SONIC_CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sonic.py")

# Opens a line near the top of every file --create-skill writes. A file without
# it was not written by S.O.N.I.C. and is never replaced.
SKILL_MARKER = "<!-- written by sonic --create-skill"
SKILL_MARKER_WITHIN = 20

SKILL_DESCRIPTION = (
    "Diagnose packet captures (pcap/pcapng) with S.O.N.I.C.: SIP/RTP call quality and MOS, "
    "IPsec/IKE/ESP encryption and DMVPN (GRE/NHRP) overlays, BGP/OSPF/EIGRP adjacencies and "
    "failover timing, ICMP/ARP reachability. Use when the user hands you a capture file or asks "
    "whether VPN traffic is encrypted, why a tunnel or routing adjacency did not come up, how long "
    "a failover took, or why a call dropped or sounded bad."
)

# One row per MCP tool, in the order an agent should consider them.
TOOL_GUIDE: List[Dict[str, Any]] = [
    {"name": "analyze_network_pcap", "short": "first call on any capture; protocols present, every detector", "title": "Analyze any capture with the network detectors", "llm": False,
     "question": "Unknown capture, or anything that is not only VoIP: which protocols are present and what is wrong"},
    {"name": "analyze_vpn_pcap", "short": "is inter-site traffic encrypted, did IKE/IPsec and DMVPN come up", "title": "Prove VPN encryption and IPsec/DMVPN setup", "llm": False,
     "question": "Is inter-site traffic encrypted? Did IKE/IPsec negotiate? Did DMVPN spokes register?"},
    {"name": "analyze_routing_pcap", "short": "BGP/OSPF/EIGRP adjacencies, failover timeline, ping loss", "title": "Check routing adjacencies, reachability and failover", "llm": False,
     "question": "Did BGP/OSPF/EIGRP adjacencies form, and if not why; how long did a failover take; is ping lost?"},
    {"name": "quick_quality_check", "short": "SIP call quality grade and MOS per RTP stream", "title": "Score SIP/RTP call quality without an LLM", "llm": False,
     "question": "How good were the calls: quality grade, MOS per RTP stream, jitter, loss, SIP auth posture"},
    {"name": "analyze_pcap", "short": "written diagnosis of SIP calls (drops, one-way audio)", "title": "Diagnose SIP calls with an LLM", "llm": True,
     "question": "A written diagnosis of SIP calls: why a call dropped, failed, or had one-way or choppy audio"},
    {"name": "analyze_pcap_partial_streaming", "short": "SIP quality plus LLM diagnosis, with timings", "title": "SIP quality first, then the LLM diagnosis", "llm": True,
     "question": "The quality numbers and the LLM diagnosis of one SIP capture in one call, with timings"},
    {"name": "analyze_batch_pcaps", "short": "LLM diagnosis of every SIP capture in a directory", "title": "Diagnose every SIP capture in a directory with an LLM", "llm": True,
     "question": "Many SIP captures in one directory, each diagnosed by an LLM, plus aggregate counts"},
    {"name": "list_llm_providers", "short": "LLM providers, models, which API keys are set", "title": "List LLM providers and configuration", "llm": False,
     "question": "Which LLM providers and models the LLM tools can use, and whether each API key is set"},
]

# The reference topics: file name (also the MCP resource sonic://guide/<topic>) and title.
TOPICS = [
    ("mcp-tools", "MCP tools, parameters and workflows"),
    ("network-detectors", "Network and VPN detectors and their issue codes"),
    ("sip-rtp", "SIP and RTP analysis"),
    ("cli", "Command line (sonic.py)"),
    ("interpreting-results", "Interpreting results and common pitfalls"),
]

# Workflows, served as MCP prompts and listed in the MCP tools reference.
WORKFLOWS: List[Dict[str, Any]] = [
    {"name": "diagnose_capture", "title": "Diagnose an unknown capture",
     "args": ["file_path"],
     "steps": [
         "Call analyze_network_pcap(file_path={file_path}). Read protocols_present, overall_status, "
         "verdicts and the first issues.",
         "If ike, esp or gre is present, call analyze_vpn_pcap with peers set to the VPN endpoints' WAN "
         "addresses when you know them.",
         "If bgp, ospf or eigrp is present, or overall_status is not ok, call analyze_routing_pcap to read "
         "the failover_timeline and ping_outages.",
         "If sip is present, call quick_quality_check for the grade and MOS. Use analyze_pcap only if the "
         "user wants a written SIP diagnosis and accepts an LLM call.",
         "Answer with the verdict sentences, issue codes and Wireshark frame numbers, and say what the "
         "capture point could not show.",
     ]},
    {"name": "check_vpn_encryption", "title": "Is the VPN traffic encrypted?",
     "args": ["file_path", "peers"],
     "steps": [
         "Call analyze_vpn_pcap(file_path={file_path}, peers={peers}). Leave peers out if none are known.",
         "Report encryption_verdict and verdict word for word. cleartext_seen names the protocol, "
         "direction and packet count of what crossed in the clear.",
         "Report negotiation_verdict (IKE outcome per SA) and overlay_verdict (NHRP registrations).",
         "If the verdict is not_present or no_esp, check where the capture was taken: only the "
         "underlay (WAN) link proves encryption; a tunnel interface shows decrypted traffic.",
     ]},
    {"name": "investigate_failover", "title": "Read a routing failover from a capture",
     "args": ["file_path"],
     "steps": [
         "Call analyze_routing_pcap(file_path={file_path}).",
         "Read verdict per protocol, then failover_timeline in order (t is seconds from the first frame).",
         "Line ping_outages up with the timeline: convergence time is from the first down or "
         "hello_gap event to the outage's recovery.",
         "Explain any mismatch issue (for example OSPF_HELLO_INTERVAL_MISMATCH, EIGRP_K_VALUE_MISMATCH, "
         "BGP_TCP_REFUSED) with the values the issue carries.",
     ]},
    {"name": "diagnose_sip_call", "title": "Diagnose SIP call quality",
     "args": ["file_path"],
     "steps": [
         "Call quick_quality_check(file_path={file_path}) first: no LLM, a few seconds.",
         "Report quality_analysis.grade and overall_score, mos_analysis.average_mos and worst_mos, and the "
         "degradation_factors.",
         "Only if the user wants a written diagnosis, call analyze_pcap. Ask before choosing a cloud "
         "provider: the SIP data, including authentication headers, leaves this machine.",
     ]},
]

_TOOLS_BY_NAME = {row["name"]: row for row in TOOL_GUIDE}


def _cost(row: Dict[str, Any]) -> str:
    return "LLM, tens of seconds to minutes" if row["llm"] else "no LLM, seconds"


def tool_options(name: str) -> Dict[str, Any]:
    """
    The FastMCP tool() keyword arguments for one tool: its title and annotations.

    Every tool only reads capture files, so all are read-only and not destructive.
    The deterministic tools are idempotent and closed world; the LLM tools give a
    different answer each call and may reach a cloud API, so they are neither.
    """
    row = _TOOLS_BY_NAME[name]
    return {
        "title": row["title"],
        "annotations": {
            "title": row["title"],
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": not row["llm"],
            "openWorldHint": row["llm"],
        },
    }


def build_instructions() -> str:
    """The MCP server instructions: short (under 2 KB, which some clients cap), naming every tool."""
    lines = [
        "S.O.N.I.C. reads pcap/pcapng files on the server's machine and answers from the packets. "
        "Pass absolute paths.",
        "",
        "Tools (no LLM unless marked):",
    ]
    for row in TOOL_GUIDE:
        lines.append(f"- {row['name']}{' [LLM]' if row['llm'] else ''}: {row['short']}")
    lines += [
        "",
        "Order: analyze_network_pcap; then analyze_vpn_pcap (pass peers, the WAN IPs) or "
        "analyze_routing_pcap; quick_quality_check if SIP is present; analyze_pcap only for a written "
        "SIP diagnosis. Quote verdicts, issue codes and frame numbers.",
        "",
        "[LLM] tools take seconds to minutes; pass provider. A cloud provider sends SIP data, "
        "auth headers included, off this machine: ask first. The rest are deterministic.",
        "",
        "Every tool returns JSON; check status (errors are data). Lists stop at max_items (default 25), "
        "*_omitted counts the rest; narrow big captures with display_filter or max_packets.",
        "",
        "Limits: only what crossed the capture point (capture the WAN link to prove encryption); IKEv2 "
        "auth failure is a labelled heuristic; NULL ESP looks encrypted.",
        "",
        "More: resources sonic://guide/<topic> (overview, " + ", ".join(t for t, _ in TOPICS) + "); "
        "prompts " + ", ".join(w["name"] for w in WORKFLOWS) + ".",
    ]
    return "\n".join(lines)


def workflow_text(name: str, **values: str) -> str:
    """
    One workflow as numbered steps. An argument passed in is filled in (an empty
    one reads None); one not passed at all stays a <placeholder>.
    """
    flow = next(w for w in WORKFLOWS if w["name"] == name)
    shown = {arg: ("<" + arg + ">" if arg not in values else repr(values[arg]) if values[arg] else "None")
             for arg in flow["args"]}
    steps = [f"{i}. {step.format(**shown)}" for i, step in enumerate(flow["steps"], 1)]
    return f"{flow['title']} with S.O.N.I.C.\n\n" + "\n".join(steps)


# ---------------------------------------------------------------------------
# Live facts read from the code
# ---------------------------------------------------------------------------

def _schema_type(schema: Dict[str, Any]) -> str:
    """A JSON schema as a short type name, for example 'array of string'."""
    if "anyOf" in schema:
        parts = [_schema_type(s) for s in schema["anyOf"] if s.get("type") != "null"]
        return " or ".join(parts) or "null"
    kind = schema.get("type", "any")
    if kind == "array":
        return f"array of {_schema_type(schema.get('items', {}))}"
    return kind


def _cell(text: Any) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _issue_codes(module) -> List[str]:
    """
    The issue codes a detector module can raise, read from its make_issue calls.

    A literal code is taken as is. A code built with an f-string is shown with
    <...> for the computed part. A code held in a loop variable is resolved from
    the table the loop walks.
    """
    tree = ast.parse(inspect.getsource(module))
    codes = set()
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for call in ast.walk(func):
            if not (isinstance(call, ast.Call) and getattr(call.func, "id", None) == "make_issue"
                    and len(call.args) > 1):
                continue
            arg = call.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                codes.add(arg.value)
            elif isinstance(arg, ast.JoinedStr):
                codes.add("".join(v.value if isinstance(v, ast.Constant) else "<...>" for v in arg.values))
            elif isinstance(arg, ast.Name):
                codes.update(_codes_from_loop_table(func, arg.id))
            else:
                codes.add("<computed>")
    return sorted(codes)


def _codes_from_loop_table(func: ast.AST, var: str) -> List[str]:
    found = []
    tables = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            tables[node.targets[0].id] = node.value
    for node in ast.walk(func):
        if not (isinstance(node, ast.For) and isinstance(node.target, ast.Tuple)):
            continue
        names = [getattr(t, "id", None) for t in node.target.elts]
        if var not in names:
            continue
        index = names.index(var)
        table = tables.get(node.iter.id) if isinstance(node.iter, ast.Name) else node.iter
        if isinstance(table, (ast.List, ast.Tuple)):
            for row in table.elts:
                if isinstance(row, ast.Tuple) and len(row.elts) > index and isinstance(row.elts[index], ast.Constant):
                    found.append(row.elts[index].value)
    return found or ["<computed>"]


def detector_modules() -> List[Dict[str, Any]]:
    """The detector registry grouped by module: names, module docstring, issue codes."""
    from analyzers import network_orchestrator as orch
    groups: Dict[str, Dict[str, Any]] = {}
    for name, cls in orch.DETECTOR_CLASSES.items():
        module = sys.modules[cls.__module__]
        group = groups.setdefault(module.__name__, {"module": module, "names": []})
        group["names"].append(name)
    out = []
    for group in groups.values():
        module = group["module"]
        doc = inspect.getdoc(module) or ""
        body = [line for line in doc.splitlines() if not line.startswith("Author:")]
        if body and body[0].startswith("S.O.N.I.C."):
            body = body[1:]
        out.append({"names": group["names"], "module": module.__name__,
                    "doc": "\n".join(body).strip(), "codes": _issue_codes(module)})
    return out


def list_tools_sync(server) -> List[Any]:
    """The tools a FastMCP server registers, as its clients see them."""
    return list(asyncio.run(server.list_tools()))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_skill_md() -> str:
    """SKILL.md: frontmatter, marker, and a short body that links the reference files."""
    lines = [
        "---",
        f"name: {SKILL_NAME}",
        f"description: {json.dumps(SKILL_DESCRIPTION)}",
        "---",
        "",
        f"{SKILL_MARKER}. Run it again after an upgrade; it replaces this file. -->",
        "",
        "# S.O.N.I.C. packet capture diagnostics",
        "",
        "S.O.N.I.C. reads a pcap/pcapng file and answers from the packets: SIP/RTP call quality, IPsec and "
        "DMVPN encryption and setup, routing adjacency health and failover, ICMP/ARP reachability. The "
        "network and VPN detectors and the SIP quality scoring are deterministic (no LLM); only the SIP "
        "diagnosis tools call an LLM.",
        "",
        "Use the MCP tools when the S.O.N.I.C. MCP server is connected; otherwise run the CLI, "
        f"`python3 {SONIC_CLI}`. Pass absolute paths to captures.",
        "",
        "## Which tool for which question",
        "",
        "| Question | MCP tool | CLI | Cost |",
        "|---|---|---|---|",
    ]
    cli = {
        "analyze_network_pcap": "`--file F --network-only`",
        "analyze_vpn_pcap": "`--file F --network-only --detectors ipsec,gre_nhrp --peers A,B`",
        "analyze_routing_pcap": "`--file F --network-only --detectors routing,reachability`",
        "quick_quality_check": "`--file F --quality-only`",
        "analyze_pcap": "`--file F --provider P --model combined`",
        "analyze_pcap_partial_streaming": "`--file F --stream --partial`",
        "analyze_batch_pcaps": "`--batch-dir D --file any.pcap`",
        "list_llm_providers": "`--help` (Providers section)",
    }
    for row in TOOL_GUIDE:
        lines.append(f"| {_cell(row['question'])} | `{row['name']}` | {cli.get(row['name'], '')} | {_cost(row)} |")
    lines += [
        "",
        "## A typical investigation",
        "",
        "1. Start with `analyze_network_pcap`: read `protocols_present`, `overall_status`, `verdicts`, `issues`.",
        "2. Narrow down: `analyze_vpn_pcap` (with `peers`) for encryption, `analyze_routing_pcap` for "
        "adjacencies and failover.",
        "3. If SIP is present, `quick_quality_check`. Use `analyze_pcap` only for a written SIP diagnosis, "
        "and ask before using a cloud LLM provider.",
        "4. Report verdict sentences, issue codes and Wireshark frame numbers; say what the capture point "
        "could not show.",
        "",
        "## Read more only when you need it",
        "",
    ]
    for topic, title in TOPICS:
        lines.append(f"- [{title}](reference/{topic}.md)")
    lines.append("")
    return "\n".join(lines)


def render_mcp_tools(tools: List[Any]) -> str:
    lines = [
        "# MCP tools, parameters and workflows",
        "",
        "Read from the running server's tool registry. Every tool returns one JSON object; check `status` "
        "first (`success` or `error`).",
        "",
    ]
    by_name = {tool.name: tool for tool in tools}
    ordered = [by_name[row["name"]] for row in TOOL_GUIDE if row["name"] in by_name]
    ordered += [tool for tool in tools if tool.name not in _TOOLS_BY_NAME]
    for tool in ordered:
        row = _TOOLS_BY_NAME.get(tool.name, {"llm": None, "question": ""})
        cost = "unknown" if row["llm"] is None else _cost(row)
        lines += [f"## `{tool.name}`", "", f"Use it for: {row['question']}  ", f"Cost: {cost}.", ""]
        lines += [(tool.description or "").strip(), ""]
        props = (tool.parameters or {}).get("properties", {})
        required = set((tool.parameters or {}).get("required", []))
        if props:
            lines += ["| Parameter | Type | Required | Default | Meaning |", "|---|---|---|---|---|"]
            for pname, schema in props.items():
                default = "" if pname in required else f"`{schema.get('default')!r}`".replace("`None`", "none")
                lines.append(f"| `{pname}` | {_cell(_schema_type(schema))} | {'yes' if pname in required else 'no'} "
                             f"| {_cell(default)} | {_cell(schema.get('description', ''))} |")
            lines.append("")
    lines += ["## Workflows (also served as MCP prompts)", ""]
    for flow in WORKFLOWS:
        lines += [f"### `{flow['name']}`: {flow['title']}", "", workflow_text(flow["name"]).split("\n\n", 1)[1], ""]
    return "\n".join(lines)


def render_network_detectors() -> str:
    from analyzers import network_orchestrator as orch
    from analyzers import network_common as common
    lines = [
        "# Network and VPN detectors",
        "",
        "Deterministic, no LLM. Read from the detector registry "
        "(`analyzers/network_orchestrator.py`, `DETECTOR_CLASSES`).",
        "",
        "| Detector | MCP tools that run it | CLI |",
        "|---|---|---|",
    ]
    for name in orch.DETECTOR_NAMES:
        tools = ["analyze_network_pcap"]
        if name in orch.VPN_DETECTORS:
            tools.append("analyze_vpn_pcap")
        if name in orch.ROUTING_DETECTORS:
            tools.append("analyze_routing_pcap")
        lines.append(f"| `{name}` | {', '.join(f'`{t}`' for t in tools)} | `--network-only --detectors {name}` |")
    lines += [
        "",
        f"Each detector section has `status` ({', '.join(f'`{s}`' for s in common.STATUS_ORDER)}), "
        "a one-sentence `verdict`, and `issues`, each with `severity` "
        f"({', '.join(f'`{s}`' for s in common.SEVERITY_ORDER)}), a stable `code`, a `message` and "
        "`frames` (Wireshark frame numbers).",
        "",
    ]
    for group in detector_modules():
        lines += [f"## {', '.join(f'`{n}`' for n in group['names'])}", "", group["doc"], "",
                  "Issue codes (`<...>` is filled in from the packet, for example a NOTIFY or ICMP type name):", ""]
        lines.append(", ".join(f"`{code}`" for code in group["codes"]) or "none")
        lines.append("")
    return "\n".join(lines)


def render_sip_rtp() -> str:
    from analyzers.call_quality_scoring import QualityGrade, QualityMetrics
    from analyzers.rtp_mos_analysis import MOSAnalysisResult, MOSCategory
    from llm_config import LLMConfig
    lines = [
        "# SIP and RTP analysis",
        "",
        "Two paths. The quality path is deterministic: `quick_quality_check` (CLI `--quality-only`) scores the "
        "calls and computes MOS per RTP stream (ITU-T G.107 E-model) in seconds, with no LLM. The diagnosis "
        "path (`analyze_pcap`, `analyze_pcap_partial_streaming`, `analyze_batch_pcaps`; CLI default mode) "
        "sends the extracted SIP/SDP data to an LLM for a written diagnosis of each call.",
        "",
        "Run the quality path first. It answers \"how bad\"; the LLM answers \"why\" in prose and is slower, "
        "costs tokens, and with a cloud provider sends SIP data (including authentication headers) off the "
        "machine.",
        "",
        "## Quality result (`quality_analysis`)",
        "",
        f"Fields: {', '.join(f'`{f.name}`' for f in dataclasses.fields(QualityMetrics))}.",
        f"Grades: {', '.join(f'`{g.value}`' for g in QualityGrade)}.",
        "",
        "## MOS result (`mos_analysis`)",
        "",
        f"Fields: {', '.join(f'`{f.name}`' for f in dataclasses.fields(MOSAnalysisResult))}.",
        f"Categories: {', '.join(f'`{c.value}`' for c in MOSCategory)}.",
        "",
        "## LLM providers and models",
        "",
        "Pass `provider` explicitly on every LLM tool. Analysis modes: `fast` (small model), `detailed` "
        "(larger model), `combined` (both, recommended), `all` (CLI only).",
        "",
        "| Provider | Fast model | Detailed model |",
        "|---|---|---|",
    ]
    for provider, models in LLMConfig.PROVIDER_MODELS.items():
        lines.append(f"| `{provider}` | `{models.get('fast', '')}` | `{models.get('detailed', '')}` |")
    lines += [
        "",
        "## What the SIP path covers",
        "",
        "Call setup and teardown, failed and dropped calls, one-way or no audio (SDP versus RTP), codec "
        "negotiation, RTP loss, jitter and latency, NAT and firewall symptoms, REGISTER and digest "
        "authentication posture. A capture with no SIP returns `{\"status\": \"error\", \"error\": \"No SIP "
        "data found ...\"}`; use `analyze_network_pcap` for anything else.",
        "",
    ]
    return "\n".join(lines)


def render_cli() -> str:
    import sonic
    parser = sonic.build_parser()
    lines = ["# Command line (`sonic.py`)", "", "Read from the CLI's own argument parser.", "",
             "| Option | Values | Default | Meaning |", "|---|---|---|---|"]
    for action in parser._actions:
        if not action.option_strings or action.dest == "help":
            continue
        values = ", ".join(map(str, action.choices)) if action.choices else (action.metavar or "")
        if action.nargs == 0:
            values = "flag"
        elif not values:
            values = action.dest.upper()
        default = action.default if action.default not in (None, False) else ""
        lines.append(f"| `{', '.join(action.option_strings)}` | {_cell(values)} | {_cell(default)} "
                     f"| {_cell(action.help or '')} |")
    epilog = (parser.epilog or "").replace("%(prog)s", "python3 sonic.py").strip("\n")
    lines[2:2] = [f"Run it as `python3 {SONIC_CLI}`.", ""]
    lines += ["", "## Examples and providers", "", "```text", epilog, "```", ""]
    return "\n".join(lines)


def render_interpreting() -> str:
    from analyzers import network_orchestrator as orch
    return "\n".join([
        "# Interpreting results and common pitfalls",
        "",
        "## Reading a network report",
        "",
        f"- `schema` is `{orch.REPORT_SCHEMA}`. Check `status` first; an error carries `error` (and "
        "`valid_detectors` for an unknown detector name).",
        "- `overall_status` is the worst detector status, conversations and SIP excluded. `not_present` means "
        "the protocol was not in the capture, which is not a pass.",
        "- `verdicts` holds one sentence per detector; quote it rather than paraphrasing.",
        "- `issues` are sorted errors first; `frames` are Wireshark frame numbers the user can open.",
        "- `timeline` events carry `t`, seconds from the first frame, and `time` in UTC.",
        "- Lists are cut at `max_items` (default 25); `issues_omitted` and `timeline_omitted` count the rest. "
        "Raise `max_items` or narrow with `display_filter` instead of assuming the list is whole.",
        "- `capture.backend` is `tshark` or `scapy`; `capture.missing_tshark_fields` and `capture.warnings` "
        "say what the installed tshark could not decode.",
        "",
        "## Pitfalls",
        "",
        "- Relative paths resolve against the server's working directory. Always pass absolute paths.",
        "- A verdict covers only what crossed the capture point. Encryption is proven on the underlay (WAN) "
        "link; a capture on the tunnel interface shows decrypted traffic.",
        "- With IPsec tunnel protection, GRE, NHRP and routing protocols travel inside ESP and are invisible "
        "on the WAN. `overlay_verdict` says so; capture the tunnel interface to see the overlay.",
        "- IKEv2 IKE_AUTH is encrypted: `auth_likely_failed` is a labelled heuristic (a small response and "
        "no ESP), not a decoded AUTHENTICATION_FAILED.",
        "- ESP with NULL encryption cannot be told apart from encrypted ESP without the keys.",
        "- OSPFv3 and IS-IS are not decoded; EIGRP speakers are grouped per link by unicast exchange or a "
        "shared /24.",
        "- Without `peers`, the encryption verdict judges only pairs that spoke IKE/ESP plus GRE endpoints. "
        "Pass the WAN addresses to judge all traffic between them.",
        "- `display_filter` needs tshark; with the scapy fallback it is not applied.",
        "- The LLM tools' `provider` defaults differ (`analyze_pcap`: ollama; batch and streaming: anthropic) "
        "and SONIC_LLM_PROVIDER does not override them. Pass `provider` explicitly.",
        "- LLM output varies from call to call; the deterministic tools give the same answer every time.",
        "",
    ])


def render_topic(topic: str, tools: List[Any]) -> str:
    """One reference topic as markdown (tools: the server's live tool list)."""
    renderers = {
        "mcp-tools": lambda: render_mcp_tools(tools),
        "network-detectors": render_network_detectors,
        "sip-rtp": render_sip_rtp,
        "cli": render_cli,
        "interpreting-results": render_interpreting,
    }
    return renderers[topic]()


def render_skill(tools: List[Any]) -> Dict[str, str]:
    """Every file of the skill: relative path -> content (each carries the marker)."""
    files = {"SKILL.md": render_skill_md()}
    for topic, _title in TOPICS:
        body = render_topic(topic, tools)
        files[f"reference/{topic}.md"] = f"{SKILL_MARKER}; it replaces this file. -->\n\n{body}"
    return files


# ---------------------------------------------------------------------------
# Writing the skill
# ---------------------------------------------------------------------------

class SkillWriteRefused(Exception):
    """A file in the way was not written by S.O.N.I.C.; nothing was written."""


def written_by_sonic(path: str) -> bool:
    """True when the file at path carries the marker within its first lines."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for i, line in enumerate(handle):
                if i >= SKILL_MARKER_WITHIN:
                    return False
                if line.startswith(SKILL_MARKER):
                    return True
    except OSError:
        return False
    return False


def _write_atomic(path: str, content: str) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sonic-skill-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def write_skill(target_dir: str, files: Dict[str, str]) -> Dict[str, List[str]]:
    """
    Write the skill files into target_dir, atomically, one file at a time.

    Every existing file that would be replaced is checked first; if any lacks
    the marker, nothing is written and SkillWriteRefused names it. A file whose
    content is already identical is left untouched, so a rerun changes nothing.
    A marked reference file the current version no longer writes is removed.
    """
    target_dir = os.path.abspath(target_dir)
    foreign = [rel for rel in files
               if os.path.exists(os.path.join(target_dir, rel))
               and not written_by_sonic(os.path.join(target_dir, rel))]
    if foreign:
        raise SkillWriteRefused(
            f"not replacing {', '.join(os.path.join(target_dir, rel) for rel in foreign)}: "
            "not written by sonic --create-skill. Move it away or choose another directory.")
    result = {"written": [], "unchanged": [], "removed": []}
    for rel, content in files.items():
        path = os.path.join(target_dir, rel)
        try:
            with open(path, encoding="utf-8") as handle:
                if handle.read() == content:
                    result["unchanged"].append(rel)
                    continue
        except OSError:
            pass
        _write_atomic(path, content)
        result["written"].append(rel)
    ref_dir = os.path.join(target_dir, "reference")
    if os.path.isdir(ref_dir):
        for name in sorted(os.listdir(ref_dir)):
            rel = f"reference/{name}"
            path = os.path.join(ref_dir, name)
            if rel not in files and name.endswith(".md") and written_by_sonic(path):
                os.unlink(path)
                result["removed"].append(rel)
    return result


def create_skill(target_dir: str, server=None) -> Dict[str, List[str]]:
    """Render the skill from the live code and write it into target_dir."""
    if server is None:
        from mcp_server import mcp as server
    return write_skill(target_dir, render_skill(list_tools_sync(server)))


def create_skill_command(target_dir: str) -> int:
    """The --create-skill entry point shared by sonic.py and mcp_server.py. Returns an exit status."""
    try:
        result = create_skill(target_dir)
    except SkillWriteRefused as exc:
        print(f"sonic: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"sonic: cannot write the skill: {exc}", file=sys.stderr)
        return 1
    where = os.path.abspath(target_dir)
    print(f"Skill '{SKILL_NAME}' in {where}: {len(result['written'])} written, "
          f"{len(result['unchanged'])} unchanged, {len(result['removed'])} removed.")
    return 0
