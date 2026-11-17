"""Which handler reads which file."""
from __future__ import annotations

import posixpath
import re

from .rules import R_WEAK_SETTINGS
from .base import File, State, line_of
from .instructions import AUTO_LOADED, SETUP_DOC, instructions, skill_shell
from .mcp import mcp_config, mcp_server_code
from .agent_configs import (agent_hooks, agent_plugin, aider_conf, allowed_tools_json, claude_settings, codex_config,
                            crush_rc, cursor_hooks, cursor_permissions, dotenv, gemini_settings, generic_agent_json,
                            hook_script, is_plugin_hooks, openclaw_extension, opencode_config, plugin_folder,
                            plugin_hooks, setup_commands)
from .ide import devcontainer, envrc, vscode_settings, vscode_tasks
from .workflows import workflow
from .git import bare_repo, git_config, git_hook, git_indirection, gitmodules


def dispatch(state: State, f: File) -> None:
    """Run every handler that applies to this file."""
    rel, low, name = f.rel, f.rel.lower(), f.name.lower()
    if f.text is None:
        return
    if re.search(r"(?:^|/)\.claude/settings(?:\.local)?\.json$", low):
        claude_settings(state, f)
    elif low.endswith(".mcp.json") or re.search(r"(?:^|/)(?:\.cursor|\.roo|\.amazonq|\.kiro/settings)/mcp\.json$", low) \
            or name in ("claude_desktop_config.json", "cline_mcp_settings.json", "mcp_config.json"):
        mcp_config(state, f, "MCP", "agent session in this folder (approval prompt in interactive mode)")
    elif re.search(r"(?:^|/)\.cursor/hooks\.json$", low):
        cursor_hooks(state, f)
    elif re.search(r"(?:^|/)\.codex/config\.toml$", low):
        codex_config(state, f)
    elif re.search(r"(?:^|/)\.gemini/settings\.json$", low):
        gemini_settings(state, f)
    elif re.search(r"(?:^|/)\.qwen/settings\.json$", low):
        gemini_settings(state, f)
    elif re.search(r"(?:^|/)\.cursor/(?:sandbox|permissions)\.json$", low):
        cursor_permissions(state, f)
    elif re.search(r"(?:^|/)\.cursor/(?:environment|worktrees)\.json$", low):
        setup_commands(state, f, "Cursor cloud agent or worktree setup (with your repository's access)")
    elif re.search(r"(?:^|/)\.devin/blueprint\.ya?ml$", low):
        setup_commands(state, f, "Devin's environment build (with your repository's access)")
    elif re.search(r"(?:^|/)(?:\.devin|\.agents|\.factory)/mcp(?:_config)?\.json$|(?:^|/)\.junie/mcp/mcp\.json$", low):
        mcp_config(state, f, "Agent", "agent session in this folder")
    elif re.search(r"(?:^|/)\.augment/settings\.json$|(?:^|/)\.amazonq/cli-agents/[^/]+\.json$|(?:^|/)\.amp/settings\.json$", low):
        agent_hooks(state, f, "Agent", "agent session in this folder")
        mcp_config(state, f, "Agent", "agent session in this folder")
        allowed_tools_json(state, f)
    elif re.search(r"(?:^|/)\.factory/hooks\.json$", low):
        agent_hooks(state, f, "Factory Droid", "Droid session in this folder")
    elif re.search(r"(?:^|/)(?:\.opencode/)?(?:opencode|kilo)\.jsonc?$", low):
        opencode_config(state, f)
    elif name in (".crushrc", "crushrc"):
        crush_rc(state, f)
    elif name in ("crush.json", ".crush.json"):
        generic_agent_json(state, f, "Crush", "starting Crush in this folder")
    elif re.search(r"(?:^|/)\.codex/hooks\.json$", low):
        agent_hooks(state, f, "Codex", "Codex session in this folder")
    elif re.search(r"(?:^|/)\.github/hooks/[^/]+\.json$", low):
        agent_hooks(state, f, "GitHub Copilot", "Copilot CLI or the VS Code agent in this repository")
    elif re.search(r"(?:^|/)\.kiro/hooks/[^/]+\.(?:json|kiro\.hook)$", low):
        agent_hooks(state, f, "Kiro", "Kiro in this workspace")
    elif re.search(r"(?:^|/)\.devin/(?:hooks\.v1|config)\.json$", low):
        agent_hooks(state, f, "Devin", "Devin session in this folder")
    elif re.search(r"(?:^|/)\.agents/hooks\.json$", low):
        agent_hooks(state, f, "Agent", "agent session in this folder")
    elif re.search(r"(?:^|/)\.clinerules/hooks/[^/]+$", low):
        hook_script(state, f, "Cline")
    elif re.search(r"(?:^|/)hooks/hooks\.json$", low) and is_plugin_hooks(state, f):
        plugin_hooks(state, f)
    elif re.search(r"(?:^|/)\.vscode/tasks\.json$", low):
        vscode_tasks(state, f)
    elif re.search(r"(?:^|/)\.vscode/settings\.json$", low):
        vscode_settings(state, f)
    elif re.search(r"(?:^|/)\.vscode/mcp\.json$", low):
        mcp_config(state, f, "VS Code", "VS Code agent in this workspace")
    elif re.search(r"(?:^|/)\.zed/(?:settings|tasks)\.json$", low):
        generic_agent_json(state, f, "Zed", "Zed in this workspace")
    elif re.search(r"(?:^|/)\.continue/(?:config|mcpServers/).*\.(?:json|ya?ml)$", low):
        generic_agent_json(state, f, "Continue", "Continue in this workspace")
    elif re.search(r"(?:^|/)\.devcontainer(?:/[^/]+)?/devcontainer\.json$|(?:^|/)\.devcontainer\.json$", low):
        devcontainer(state, f)
    elif re.search(r"(?:^|/)\.aider\.conf\.ya?ml$", low):
        aider_conf(state, f)
    elif name == ".envrc":
        envrc(state, f)
    elif re.fullmatch(r"\.env(?:\.[\w.-]+)?", name) and not name.endswith((".example", ".sample", ".template", ".dist")):
        dotenv(state, f)
    elif re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", low):
        workflow(state, f)
    elif name == ".gitmodules":
        gitmodules(state, f)
    elif re.search(r"(?:^|/)\.git/config$", low) or name == ".lfsconfig" or (name == "config" and bare_repo(state, f)):
        git_config(state, f)
    elif re.search(r"(?:^|/)\.git/hooks/[^/]+$", low):
        git_hook(state, f)
    elif re.search(r"(?:^|/)\.git/(?:commondir|gitdir)$|(?:^|/)\.git/worktrees/[^/]+/gitdir$", low) or \
            (name == ".git" and (f.text or "").startswith("gitdir:") and ".." in (f.text or "")):
        git_indirection(state, f)
    if re.search(r"(?:^|/)\.openclaw/extensions/", low):
        openclaw_extension(state, f)
    if re.search(r"(?:^|/)\.(?:opencode|kilo)/plugins?/[^/]+\.(?:[cm]?js|[cm]?ts)$", low):
        agent_plugin(state, f, "OpenCode" if ".opencode/" in low else "Kilo", "starting it in this folder", "medium")
    if re.search(r"(?:^|/)\.vscode/[^/]+\.json$", low) and re.search(r"[\"']__proto__[\"']\s*:", f.text or ""):
        # CVE-2026-121662: a __proto__ key started an MCP server on open, even in Restricted Mode (fixed in 1.145.3)
        state.add(R_WEAK_SETTINGS, "high", rel, line_of(f.text, "__proto__"), "__proto__ key in VS Code workspace "
                  "settings (CVE-2026-121662)", "__proto__")
    if re.search(r"(?:^|/)\.amp/plugins/[^/]+\.(?:[cm]?js|[cm]?ts)$", low):
        agent_plugin(state, f, "Amp", "starting Amp in this folder", "medium")
    if re.search(r"(?:^|/)commands/[^/]+\.md$", low) and not AUTO_LOADED.search(rel) and \
            plugin_folder(state, posixpath.dirname(f.dir)):
        skill_shell(state, f)  # a plugin's slash commands
    if AUTO_LOADED.search(rel):
        instructions(state, f, auto_loaded=True)
    elif SETUP_DOC.search(rel) and low.endswith((".md", ".rst", ".txt", ".markdown")) or re.fullmatch(r"readme(?:\.[a-z]+)?", name):
        instructions(state, f, auto_loaded=False)
    if low.endswith((".js", ".ts", ".mjs", ".cjs", ".py")) and "node_modules/" not in low:
        mcp_server_code(state, f)
