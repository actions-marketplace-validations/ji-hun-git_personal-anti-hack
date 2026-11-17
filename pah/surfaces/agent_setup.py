"""The agent setup a repository proposes, read as a whole: commands its settings pre-approve that can run any program
through their arguments (PAH-A020), and tools it lets run without asking that together carry content anyone can write
to a way out (PAH-A021). The judgement lives in pah/flows.py, which checkup uses for the user's own setup."""
from __future__ import annotations

from ..flows import R_ARGV_EXEC, R_TOXIC_FLOW, argv_exec, describe, tools_from_allow, tools_from_servers, toxic
from .base import File, State, line_of, load_jsonc

# Agent: the files at the top of a repository that together make up its setup there.
SETUPS = {
    "Claude Code": (".claude/settings.json", ".claude/settings.local.json", ".mcp.json"),
    "Cursor": (".cursor/mcp.json",),
    "Gemini CLI": (".gemini/settings.json",),
    "VS Code agent": (".vscode/settings.json", ".vscode/mcp.json"),
}


def pre_approved(state: State, f: File, entries, agent: str) -> None:
    """PAH-A020 for each allow-list entry that lets the agent run any program through the arguments. Interpreters and
    package runners are medium; tools that run programs only through an option or the repository's scripts are low,
    since projects pre-approve their own test commands."""
    for entry in entries or []:
        if not isinstance(entry, str):
            continue
        hit = argv_exec(entry)
        if hit:
            _prog, how, interpreter = hit
            state.add(R_ARGV_EXEC, "medium" if interpreter else "low", f.rel, line_of(f.text or "", entry),
                      f"{agent} pre-approves {entry}: {how}", entry)


def toxic_flows(state: State) -> None:
    """PAH-A021: the repository's settings let a tool that reads content anyone can write and a tool that sends data
    out both run without asking."""
    for agent, rels in SETUPS.items():
        allow, servers, everything, where = [], {}, False, []
        for rel in rels:
            f = state.files.get(rel)
            data = load_jsonc(f.text or "") if f is not None and f.text else None
            if not isinstance(data, dict):
                continue
            where.append(rel)
            perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
            tools = data.get("tools") if isinstance(data.get("tools"), dict) else {}
            allow += [a for a in (perms.get("allow") or []) + (tools.get("allowed") or []) if isinstance(a, str)]
            everything |= perms.get("defaultMode") == "bypassPermissions" or bool(data.get("yolo")) or \
                data.get("chat.tools.autoApprove") is True or data.get("chat.tools.global.autoApprove") is True
            nested = data.get("mcp") if isinstance(data.get("mcp"), dict) else {}
            for block in (data.get("mcpServers"), data.get("servers"), nested.get("servers")):
                if isinstance(block, dict):
                    servers.update(block)
        if not where:
            continue
        flow = toxic(tools_from_allow(allow) + tools_from_servers(servers, allow, everything_auto=everything))
        if flow:
            state.add(R_TOXIC_FLOW, "medium", where[0], 0, f"{agent}: {describe(flow)}", ", ".join(where), "config")
