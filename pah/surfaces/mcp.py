"""MCP: server entries in agent configuration (what starts, from where, with which environment) and server code
whose tool descriptions carry instructions for the model.
"""
from __future__ import annotations

import re

from ..hosts import classify_host
from ..indicators import SECRET_PATHS
from ..patterns import AI_ADDRESSED
from .rules import R_APPROVALS, R_CMD_SETTING, R_MCP_SERVER, R_TOOL_POISON, R_UNPINNED_MCP
from .base import File, State, as_command, line_of, load_jsonc, load_toml
from .env import check_env
from .instructions import unpinned_runner, well_known


def mcp_config(state: State, f: File, agent: str, trigger: str) -> None:
    data = load_jsonc(f.text or "") if not f.rel.endswith(".toml") else load_toml(f.text or "")
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") or data.get("servers") or data.get("mcp_servers") or data.get("context_servers") or \
        data.get("amp.mcpServers") or {}
    if not isinstance(servers, dict):
        return
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        line = line_of(f.text, f'"{name}"') or line_of(f.text, name)
        if spec.get("command"):
            cmd = as_command(spec)
            state.command(cmd, f.rel, line, f"{agent} MCP server '{name}'", trigger, floor=(R_MCP_SERVER, "low"))
            unpinned = unpinned_runner(cmd)
            if unpinned:
                state.add(R_UNPINNED_MCP, "low" if well_known(*unpinned) else "medium", f.rel, line,
                          f"'{name}' runs {unpinned[1]} without a pinned version", cmd)
        url = spec.get("url") or spec.get("serverUrl") or ""
        if url:
            kind = classify_host(url)
            state.surface(f"{agent} remote MCP server '{name}'", f.rel, trigger, url, line)
            if kind in ("raw-ip", "plain-http", "lookalike"):
                state.add(R_MCP_SERVER, "high", f.rel, line, f"remote server '{name}' at {url} ({kind})", url)
        if isinstance(spec.get("env"), dict):
            check_env(state, spec["env"], f, f"MCP server '{name}'")
        if spec.get("headersHelper"):  # a program run to produce the request headers
            state.command(as_command(spec["headersHelper"]), f.rel, line_of(f.text, "headersHelper"),
                          f"{agent} MCP server '{name}' headersHelper", trigger, floor=(R_CMD_SETTING, "medium"))
        if spec.get("trust") is True or spec.get("autoApprove") in (True, "*") or spec.get("alwaysAllow") == "*":
            state.add(R_APPROVALS, "medium", f.rel, line, f"tools of the MCP server '{name}' run without asking",
                      f"{name}: trust/autoApprove")


MCP_IMPORT = re.compile(r"@modelcontextprotocol/sdk|\bfrom\s+mcp(?:\.server)?\b|\bimport\s+mcp\b|\bfastmcp\b|\bFastMCP\b|McpServer\b")


DESCRIPTIONS = re.compile(r"(?s)(?:description\s*[:=]\s*|\.tool\(\s*['\"][\w-]+['\"]\s*,\s*)(?P<q>\"\"\"|'''|`|\"|')(?P<body>.{20,6000}?)(?P=q)"
                          r"|@(?:mcp|server|app)\.tool\([^)]*\)\s*\n\s*(?:async\s+)?def\s+\w+\([^)]*\)[^:]*:\s*(?P<dq>\"\"\"|''')(?P<doc>.{20,6000}?)(?P=dq)")


POISON = re.compile(r"<\s*/?\s*(?:IMPORTANT|instructions?|system|secret|hidden)\s*>|before\s+(?:using|calling)\s+this\s+tool|"
                    r"(?:pass|include|send|provide)\s+(?:its|the|their)?\s*(?:contents?|text|data)\s+(?:as|in)\s+(?:the\s+)?[\w\"'`]+\s*(?:parameter|argument|field)"
                    r"|do\s+not\s+(?:mention|tell|show|reveal)", re.I)


def mcp_server_code(state: State, f: File) -> None:
    text = f.text or ""
    if not MCP_IMPORT.search(text):
        return
    for m in DESCRIPTIONS.finditer(text):
        body = m.group("body") or m.group("doc") or ""
        reasons = []
        if POISON.search(body):
            reasons.append("hidden directives")
        if SECRET_PATHS.search(body):
            reasons.append("names credential files")
        if AI_ADDRESSED.search(body):
            reasons.append("addresses the model")
        if len(reasons) >= 1 and (SECRET_PATHS.search(body) or POISON.search(body)):
            state.add(R_TOOL_POISON, "critical" if len(reasons) >= 2 else "high", f.rel, text.count("\n", 0, m.start()) + 1,
                      "tool description " + ", ".join(reasons), body[:300], "code")
