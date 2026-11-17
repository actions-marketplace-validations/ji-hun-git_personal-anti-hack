"""Agent configuration files: Claude Code settings and plugins, Cursor, Codex, Gemini CLI, Copilot, OpenCode,
Crush, Aider, OpenClaw and the hook files of other agents. Each records what runs, when, and on whose approval.
"""
from __future__ import annotations

import json
import posixpath
import re

from ..hosts import classify_host
from ..indicators import EXFIL_HOSTS
from .rules import (OFFICIAL_MARKETPLACES, R_AGENT_EXTENSION, R_APPROVALS, R_CMD_SETTING, R_CODEX_HOME, R_CURSOR_HOOKS,
                    R_HOOKS, R_MCP_AUTO, R_MCP_SERVER, R_OTHER_AGENT, R_PLUGIN_REQUEST)
from .agent_setup import pre_approved
from .base import File, State, as_command, hook_urls, line_of, load_jsonc, refs_in_command, walk_commands
from .env import INJECT_ENV, REDIRECT_ENV, check_env
from .mcp import mcp_config


CLAUDE_TRIGGER = "Claude Code session in this folder (after trust; without a prompt under claude -p / SDK)"


EARLY_EVENTS = {"SessionStart", "Setup", "UserPromptSubmit", "InstructionsLoaded", "ConfigChange"}


def claude_settings(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for event, entries in hooks.items():
        for _path, cmd in walk_commands(entries):
            line = line_of(f.text, cmd.split()[0]) if cmd else 0
            state.command(cmd, f.rel, line, f"Claude Code hook ({event})", CLAUDE_TRIGGER, base_dir="",
                          floor=(R_HOOKS, "medium" if event in EARLY_EVENTS else "low"))
    for entries in hooks.values():
        for url in hook_urls(entries):  # "type": "http" hooks post every event to a server
            kind = classify_host(url)
            state.surface("Claude Code HTTP hook", f.rel, CLAUDE_TRIGGER, url, line_of(f.text, url))
            if kind in ("raw-ip", "plain-http", "lookalike") or EXFIL_HOSTS.search(url):
                state.add(R_HOOKS, "high", f.rel, line_of(f.text, url), f"HTTP hook sends agent events to {url}", url)
    for key in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper",
                "statusLine", "subagentStatusLine", "fileSuggestion"):
        if key in data:
            cmd = as_command(data[key])
            state.command(cmd, f.rel, line_of(f.text, key), f"Claude Code {key}", CLAUDE_TRIGGER,
                          floor=(R_CMD_SETTING, "low" if key in ("statusLine", "subagentStatusLine", "fileSuggestion")
                                 else "high"))
    sandbox = data.get("sandbox") if isinstance(data.get("sandbox"), dict) else {}
    network = sandbox.get("network") if isinstance(sandbox.get("network"), dict) else {}
    if sandbox.get("allowUnsandboxedCommands") is True or sandbox.get("ignoreViolations") or \
            "*" in [str(d) for d in network.get("allowedDomains") or []]:
        state.add(R_APPROVALS, "medium", f.rel, line_of(f.text, "sandbox"), "project settings loosen the sandbox",
                  json.dumps(sandbox)[:160])
    if isinstance(data.get("env"), dict):
        check_env(state, data["env"], f, "Claude Code settings")
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode == "bypassPermissions":
        state.add(R_APPROVALS, "high", f.rel, line_of(f.text, "bypassPermissions"), "defaultMode: bypassPermissions",
                  "bypassPermissions")
    for entry in perms.get("allow") or []:
        if isinstance(entry, str) and re.fullmatch(r"\s*(?:\*|Bash|Bash\(\s*\*\s*\)|Bash\(:\*\)|Bash\(\*:\*\))\s*", entry):
            state.add(R_APPROVALS, "high", f.rel, line_of(f.text, entry), f"allows every shell command: {entry}", entry)
    pre_approved(state, f, perms.get("allow"), "Claude Code")
    if data.get("enableAllProjectMcpServers") is True:
        state.add(R_MCP_AUTO, "high", f.rel, line_of(f.text, "enableAllProjectMcpServers"), "enableAllProjectMcpServers",
                  "enableAllProjectMcpServers: true")
    if data.get("enabledMcpjsonServers"):
        state.add(R_MCP_AUTO, "high", f.rel, line_of(f.text, "enabledMcpjsonServers"),
                  f"pre-approves {data['enabledMcpjsonServers']}", "enabledMcpjsonServers")
    plugin_requests(state, f, data)


def _marketplace_source(spec) -> tuple[str, str]:
    """(type, location) of a marketplace in extraKnownMarketplaces: github owner/repo, a git or https URL, or a path."""
    src = spec.get("source") if isinstance(spec, dict) else spec
    if isinstance(src, dict):
        return str(src.get("source") or ""), str(src.get("repo") or src.get("url") or src.get("path") or "")
    value = str(src or "")
    return ("url" if "://" in value else "directory" if value.startswith((".", "/", "~")) else "github"), value


def plugin_requests(state: State, f: File, data: dict) -> None:
    """extraKnownMarketplaces and enabledPlugins in project settings: on trust, Claude Code offers to install
    plugins whose hooks, MCP servers and skills are not part of the repository being scanned."""
    markets = data.get("extraKnownMarketplaces") if isinstance(data.get("extraKnownMarketplaces"), dict) else {}
    enabled = data.get("enabledPlugins")
    plugins = [k for k, v in enabled.items() if v] if isinstance(enabled, dict) else \
        [str(p) for p in enabled] if isinstance(enabled, list) else []
    for name, spec in markets.items():
        stype, source = _marketplace_source(spec)
        kind = classify_host(source) if "://" in source else ""
        local = stype in ("directory", "path", "file", "local")
        sev = "high" if kind in ("raw-ip", "plain-http", "lookalike") else "low" if local else "medium"
        named = [p for p in plugins if p.endswith("@" + name)]
        state.surface(f"Claude Code plugin marketplace '{name}'", f.rel, "trusting the folder in Claude Code (install "
                      "prompt)", source, line_of(f.text, name))
        state.add(R_PLUGIN_REQUEST, sev, f.rel, line_of(f.text, name),
                  f"asks Claude Code to add the marketplace '{name}' ({source or 'no source'})"
                  + (f" and enable {', '.join(named[:4])}" if named else ""), f"{name}: {source}")
    known = set(markets)
    for plugin in plugins:
        market = plugin.rsplit("@", 1)[1] if "@" in plugin else ""
        if market and market not in known and market not in OFFICIAL_MARKETPLACES:
            state.add(R_PLUGIN_REQUEST, "low", f.rel, line_of(f.text, plugin), f"enables the plugin {plugin}", plugin)


def cursor_hooks(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    for path, cmd in walk_commands(data or {}):
        state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"Cursor hook ({'/'.join(path[1:2]) or 'hook'})",
                      "Cursor agent events in this workspace", floor=(R_CURSOR_HOOKS, "medium"))


def codex_config(state: State, f: File) -> None:
    mcp_config(state, f, "Codex", "Codex session (when CODEX_HOME or a trusted project points here)")
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*approval_policy\s*=\s*[\"']never[\"']|^\s*sandbox_mode\s*=\s*[\"']danger-full-access[\"']", text):
        state.add(R_APPROVALS, "high", f.rel, text.count("\n", 0, m.start()) + 1, m.group().strip(), m.group())
    m = re.search(r"(?m)^\s*notify\s*=\s*(\[.*?\])", text, re.S)
    if m:
        state.command(m.group(1), f.rel, text.count("\n", 0, m.start()) + 1, "Codex notify program",
                      "every Codex turn", floor=(R_CMD_SETTING, "high"))


def dotenv(state: State, f: File) -> None:
    text = f.text or ""
    env = {}
    for m in re.finditer(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']?([^\"'\n#]*)", text):
        env[m.group(1)] = m.group(2).strip()
    if "CODEX_HOME" in env:
        state.add(R_CODEX_HOME, "critical" if not f.dir else "high", f.rel, line_of(text, "CODEX_HOME"),
                  f"CODEX_HOME={env['CODEX_HOME']}", f"CODEX_HOME={env['CODEX_HOME']}")
        env.pop("CODEX_HOME")
    check_env(state, {k: v for k, v in env.items() if REDIRECT_ENV.match(k) or INJECT_ENV.match(k) or k.upper() == "PATH"},
              f, ".env", cap=None if not f.dir else "medium")


def gemini_settings(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    for event, entries in (data.get("hooks") or {}).items() if isinstance(data.get("hooks"), dict) else []:
        for _path, cmd in walk_commands(entries):
            state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"Gemini CLI hook ({event})",
                          "Gemini CLI session in this folder", floor=(R_HOOKS, "medium" if event in EARLY_EVENTS else "low"))
    mcp_config(state, f, "Gemini CLI", "Gemini CLI session in this folder")
    tools = data.get("tools") if isinstance(data.get("tools"), dict) else {}
    agent = "Qwen Code" if ".qwen/" in f.rel.lower() else "Gemini CLI"
    for key in ("discoveryCommand", "callCommand"):  # tools.discoveryCommand runs at start; callCommand on every call
        if isinstance(tools.get(key), str):
            state.command(tools[key], f.rel, line_of(f.text, key), f"{agent} tools.{key}", f"{agent} session in this folder",
                          floor=(R_CMD_SETTING, "high"))
    status = ((data.get("ui") or {}).get("statusLine") or {}) if isinstance(data.get("ui"), dict) else {}
    if isinstance(status, dict) and isinstance(status.get("command"), str):
        state.command(status["command"], f.rel, line_of(f.text, status["command"][:40]), f"{agent} status line",
                      f"{agent} session in this folder", floor=(R_CMD_SETTING, "low"))
    if data.get("yolo") or tools.get("autoAccept") or tools.get("approvalMode") == "yolo" or \
            (data.get("security") or {}).get("approvalMode") == "yolo":
        state.add(R_APPROVALS, "high", f.rel, line_of(f.text, "yolo") or line_of(f.text, "autoAccept"),
                  "auto-accepts tool calls", "yolo/autoAccept")
    pre_approved(state, f, tools.get("allowed"), agent)
    if isinstance(data.get("env"), dict):
        check_env(state, data["env"], f, "Gemini CLI settings")


def openclaw_extension(state: State, f: File) -> None:
    state.mark_autoexec(f.rel, "OpenClaw workspace extension")
    if f.name in ("package.json", "openclaw.plugin.json", "index.js", "index.ts", "index.mjs"):
        state.surface("OpenClaw workspace extension", f.rel, "opening the workspace in OpenClaw")
        state.add(R_AGENT_EXTENSION, "high", f.rel, 1, "extension loads with the workspace", f.rel)


def aider_conf(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*(test-cmd|lint-cmd|lint|test|notifications-command)\s*:\s*(.+)$", text):
        # test-cmd runs at startup in 0.86 (CVE-2026-85674, no fix); notifications-command too (CVE-2026-115726)
        state.command(m.group(2).strip().strip("'\""), f.rel, text.count("\n", 0, m.start()) + 1,
                      f"Aider {m.group(1)}", "Aider runs it at start or after edits", floor=(R_OTHER_AGENT, "medium"))
    m = re.search(r"(?m)^\s*load\s*:\s*(.+)$", text)
    if m:  # a file of /commands Aider runs at launch, /run included
        for ref in refs_in_command(m.group(1).strip().strip("'\""), f.dir, state.files):
            state.add(R_OTHER_AGENT, "medium", f.rel, text.count("\n", 0, m.start()) + 1, f"Aider loads and runs the "
                      f"commands in {ref} at launch", m.group(0).strip())
            state.mark_autoexec(ref, f"commands Aider runs at launch ({f.rel})")


def generic_agent_json(state: State, f: File, agent: str, trigger: str) -> None:
    data = load_jsonc(f.text or "")
    for path, cmd in walk_commands(data or {}):
        state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"{agent} ({'/'.join(path[:2])})", trigger,
                      floor=(R_OTHER_AGENT, "medium"))


HOOK_EARLY = {e.lower() for e in EARLY_EVENTS} | {"userpromptsubmitted", "promptsubmit", "taskstart", "taskresume",
                                                 "agentspawn"}


def _shell_variants(obj, out: list) -> None:
    """Copilot hooks name one command per shell ("bash", "powershell") instead of a "command"."""
    if isinstance(obj, dict):
        for key in ("bash", "powershell", "pwsh"):
            if isinstance(obj.get(key), str):
                out.append(obj[key])
        for value in obj.values():
            _shell_variants(value, out)
    elif isinstance(obj, list):
        for value in obj:
            _shell_variants(value, out)


def hook_commands(data) -> list[tuple[str, str]]:
    """(event, command) in the hook files agents read: {"hooks": {Event: [...]}} (Claude Code, Codex, Devin, Copilot),
    {"hooks": [{"trigger": Event, "action": ...}]} (Kiro CLI) and {"when": ..., "then": ...} (Kiro IDE)."""
    def commands(obj) -> list[str]:
        found = [cmd for _path, cmd in walk_commands(obj)]
        _shell_variants(obj, found)
        return found

    if not isinstance(data, dict):
        return []
    out = []
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            out += [(str(event), cmd) for cmd in commands(entries)]
    elif isinstance(hooks, list):
        for entry in hooks:
            if isinstance(entry, dict):
                when = entry.get("when") if isinstance(entry.get("when"), dict) else {}
                event = entry.get("trigger") or entry.get("event") or when.get("type") or "hook"
                out += [(str(event), cmd) for cmd in commands(entry)]
    if isinstance(data.get("then"), dict):
        when = data.get("when") if isinstance(data.get("when"), dict) else {}
        out += [(str(when.get("type") or "hook"), cmd) for cmd in commands(data["then"])]
    return out


def agent_hooks(state: State, f: File, agent: str, trigger: str) -> None:
    """Hook files of the agents other than Claude Code, Gemini CLI and Cursor, which have their own handlers."""
    for event, cmd in hook_commands(load_jsonc(f.text or "")):
        state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"{agent} hook ({event})", trigger, base_dir="",
                      floor=(R_HOOKS, "medium" if event.lower() in HOOK_EARLY else "low"))


def hook_script(state: State, f: File, agent: str) -> None:
    """Cline runs the executable named after the hook event in .clinerules/hooks/."""
    event = f.name.split(".")[0]
    state.surface(f"{agent} hook script ({event})", f.rel, f"{agent} runs it on {event}", (f.text or "")[:200])
    state.mark_autoexec(f.rel, f"{agent} hook script")
    state.add(R_HOOKS, "medium" if event.lower() in HOOK_EARLY else "low", f.rel, 1, f"{agent} hook script ({event})",
              f.rel, "autoexec")


PLUGIN_TRIGGER = "Claude Code sessions once the plugin is installed"


def plugin_folder(state: State, folder: str) -> bool:
    """A Claude Code plugin's folder: it has .claude-plugin/plugin.json, or the repository is a marketplace whose
    plugins live in subfolders."""
    return posixpath.join(folder, ".claude-plugin/plugin.json") in state.files or \
        any(p.endswith(".claude-plugin/marketplace.json") for p in state.files)


def is_plugin_hooks(state: State, f: File) -> bool:
    return plugin_folder(state, posixpath.dirname(f.dir))


def plugin_hooks(state: State, f: File) -> None:
    """A plugin's hooks run after someone installs it, not when the repository is opened, so they are recorded at a
    low floor; what they run is marked as running on its own and judged as such."""
    data = load_jsonc(f.text or "")
    hooks = data.get("hooks") if isinstance(data, dict) and isinstance(data.get("hooks"), dict) else {}
    for event, entries in hooks.items():
        for _path, cmd in walk_commands(entries):
            state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"Claude Code plugin hook ({event})", PLUGIN_TRIGGER,
                          base_dir=posixpath.dirname(f.dir), floor=(R_HOOKS, "low"))


def cursor_permissions(state: State, f: File) -> None:
    """.cursor/sandbox.json and .cursor/permissions.json in a repository override the user's own for every command."""
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    if str(data.get("type", "")).lower() in ("insecure_none", "none") or data.get("enabled") is False:
        state.add(R_APPROVALS, "high", f.rel, line_of(text, "type") or 1, "turns Cursor's sandbox off for this project",
                  json.dumps(data)[:160])
    for path in data.get("additionalReadwritePaths") or []:
        if re.match(r"(?:~|\$HOME|/|[A-Za-z]:[\\/])\s*$|~[\\/]\.(?:ssh|aws|claude|codex|gemini|config)", str(path)):
            state.add(R_APPROVALS, "high", f.rel, line_of(text, str(path)), f"lets sandboxed commands write {path}", str(path))
    allow = data.get("terminalAllowlist") or data.get("allowlist") or []
    if data.get("autoRun") is True or "*" in [str(a).strip() for a in allow]:
        state.add(R_APPROVALS, "high", f.rel, line_of(text, "autoRun") or line_of(text, "*"), "runs terminal commands "
                  "without asking", json.dumps(data)[:160])
    pre_approved(state, f, allow if isinstance(allow, list) else [], "Cursor")


def setup_commands(state: State, f: File, trigger: str) -> None:
    """Install and start commands of cloud agents (Cursor environment.json, worktrees.json, Devin blueprints)."""
    text = f.text or ""
    if f.rel.lower().endswith(".json"):
        data = load_jsonc(text)
        values = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ("install", "start", "setup-worktree", "setup-worktree-unix", "setup-worktree-windows"):
                    values += value if isinstance(value, list) else [value]
                elif key == "terminals" and isinstance(value, list):
                    values += [t.get("command") for t in value if isinstance(t, dict)]
        cmds = [as_command(v) for v in values if v]
    else:
        cmds = []
        for m in re.finditer(r"(?m)^(\s*)(initialize|maintenance)\s*:\s*\|?\s*$", text):
            indent, rest = len(m.group(1)), text[m.end():].split("\n")
            for line in rest[1:]:
                if line.strip() and len(line) - len(line.lstrip()) <= indent:
                    break
                if line.strip() and not line.strip().startswith("#"):
                    cmds.append(re.sub(r"^\s*-\s*(?:run:\s*)?", "", line).strip())
    for cmd in filter(None, cmds):
        state.command(cmd, f.rel, line_of(text, cmd[:40]), "cloud agent setup command", trigger)


def allowed_tools_json(state: State, f: File) -> None:
    """Amazon Q / Kiro CLI agents, Augment and Amp list tools that run without asking."""
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    allowed = [str(t) for t in (data.get("allowedTools") or [])] + \
        [str(t) for t in ((data.get("toolsSettings") or {}).get("execute_bash") or {}).get("allowedCommands") or []]
    if any(t.strip() in ("*", "execute_bash", "@builtin", "shell", ".*") for t in allowed):
        state.add(R_APPROVALS, "high", f.rel, line_of(f.text, "allowedTools") or line_of(f.text, "allowedCommands"),
                  "lets the agent run shell commands without asking", ", ".join(allowed[:6]))


def opencode_config(state: State, f: File) -> None:
    """opencode.json / kilo.json: npm plugins installed and loaded at start, MCP and formatter commands."""
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    agent = "Kilo" if "kilo" in f.name.lower() else "OpenCode"
    plugins = data.get("plugin") or data.get("plugins") or []
    for plugin in plugins if isinstance(plugins, list) else []:
        name = str(plugin)
        if name.startswith((".", "/")):
            for ref in refs_in_command(name, f.dir, state.files):
                state.mark_autoexec(ref, f"{agent} plugin named in {f.rel}")
            continue
        state.packages.append(("npm", re.sub(r"(?<=.)@[^@/]*$", "", name), f.rel, line_of(text, name), "autoexec"))
        state.add(R_AGENT_EXTENSION, "medium", f.rel, line_of(text, name), f"{agent} installs the npm package {name} and "
                  "loads it as a plugin when it starts", name)
    mcp = data.get("mcp") if isinstance(data.get("mcp"), dict) else {}
    for name, spec in mcp.items():
        if isinstance(spec, dict) and spec.get("command"):
            state.command(as_command(spec["command"]), f.rel, line_of(text, f'"{name}"'), f"{agent} MCP server '{name}'",
                          f"starting {agent} in this folder", floor=(R_MCP_SERVER, "low"))
    formatters = data.get("formatter") if isinstance(data.get("formatter"), dict) else {}
    for name, spec in formatters.items():
        if isinstance(spec, dict) and spec.get("command"):
            state.command(as_command(spec["command"]), f.rel, line_of(text, f'"{name}"'), f"{agent} formatter '{name}'",
                          f"{agent} runs it after every edit", floor=(R_OTHER_AGENT, "medium"))


def crush_rc(state: State, f: File) -> None:
    """Crush runs .crushrc as a Bash script on every launch, before its interface appears."""
    state.surface("Crush startup script", f.rel, "every launch of Crush in this folder", (f.text or "")[:200])
    state.mark_autoexec(f.rel, "Crush startup script")
    state.add(R_OTHER_AGENT, "medium", f.rel, 1, "Crush runs this script on every launch", f.rel, "autoexec")


def agent_plugin(state: State, f: File, agent: str, trigger: str, severity: str) -> None:
    """Plugin code an agent imports from the project folder when it starts there."""
    state.mark_autoexec(f.rel, f"{agent} plugin")
    state.surface(f"{agent} plugin", f.rel, trigger)
    state.add(R_AGENT_EXTENSION, severity, f.rel, 1, f"{agent} loads this plugin when it starts in the folder", f.rel)
