"""Agent setups as a whole: which tools an agent may use without asking, what each one reaches, and whether together
they open a path from content anyone can write to a way out.

Two research results drive it. The "lethal trifecta" (Simon Willison, 2025) and Invariant Labs' toxic flow analysis:
an agent that has private data, reads untrusted content and can communicate out can be told by that content to leak,
and the defence is to break one leg, which CaMeL (Debenedetti et al., 2025) turns into capabilities attached to data.
For a coding agent the private leg is always there (it reads the project, its .env files and often your home folder),
so the check is whether a tool that brings in content anyone can write and a tool that sends data out both run without
asking (PAH-A021).

And Trail of Bits (2025): an allow-listed command is only as safe as its arguments. go test -exec, find -exec, fd -x,
rg --pre, git -c and xargs run any program, and npm test, make or cargo run the repository's own code, so a prompt
injection that only chooses the arguments runs code without a prompt (PAH-A020).

Used by the surface handlers (a repository's agent settings) and by checkup (the user's own setup).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import rule

R_ARGV_EXEC = rule(
    "PAH-A020", "Pre-approved command can run any program through its arguments",
    "Allow-listing a command lets the agent run it without asking, with whatever arguments it chooses. Many everyday "
    "commands run other programs through an option or through files in the repository: go test -exec, find -exec, "
    "fd -x, rg --pre, git -c core.pager or git show --output, xargs, and npm test, make or cargo, which run the "
    "repository's own scripts. A prompt injection in a file, issue or web page only has to choose the arguments.",
    "Allow exact commands with fixed arguments (Bash(npm test) instead of Bash(npm:*)), keep the others on ask, and "
    "never pre-approve interpreters or package runners (node, python, npx, uvx, bash).",
    attack=("T1059",), owasp=("LLM01", "LLM06", "ASI02"),
    refs=("https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/",))
R_TOXIC_FLOW = rule(
    "PAH-A021", "Agent setup lets content anyone can write reach a way out without asking",
    "The agent may, without asking, use a tool that brings in content anyone can write (issues, web pages, email, chat "
    "messages) and a tool that sends data out (web requests, messages, posts). Together with its access to your files "
    "and keys, that is the lethal trifecta: text planted in an issue or a page can tell the agent to send your data "
    "out, as in the GitHub MCP (2025) and Supabase MCP (2025) incidents and the Deadbugz MCP server (2026).",
    "Cut one leg: keep either the tools that read untrusted content or the tools that send data out on ask (remove "
    "them from the allow list or auto-approve), and keep keys and .env files out of the agent's reach with deny rules.",
    attack=("T1567",), owasp=("LLM01", "LLM02", "LLM06", "ASI01"),
    refs=("https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/", "https://invariantlabs.ai/blog/toxic-flow-analysis",
          "https://arxiv.org/abs/2503.18813", "https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign"))

UNTRUSTED, PRIVATE, OUTBOUND = "untrusted content", "private data", "a way out"
SERVER_LEGS = [
    (r"github|gitlab|bitbucket|gitea", {UNTRUSTED, PRIVATE, OUTBOUND}),
    (r"slack|discord|teams|telegram|mattermost|whatsapp", {UNTRUSTED, PRIVATE, OUTBOUND}),
    (r"gmail|e-?mail|imap|smtp|outlook|mailgun|postmark|sendgrid|resend", {UNTRUSTED, PRIVATE, OUTBOUND}),
    (r"jira|linear|asana|trello|clickup|zendesk|intercom|freshdesk|sentry|hubspot|salesforce", {UNTRUSTED, PRIVATE}),
    (r"notion|confluence|google[-_]?(?:drive|docs)|gdrive|onedrive|dropbox|sharepoint", {UNTRUSTED, PRIVATE}),
    (r"fetch|firecrawl|browserbase|puppeteer|playwright|browser|chrome|selenium|scrap|crawl|web[-_]?search|brave|tavily"
     r"|\bexa\b|perplexity|serp|duckduckgo|searx|jina", {UNTRUSTED, OUTBOUND}),
    (r"filesystem|file[-_]?system", {PRIVATE}),
    (r"postgres|mysql|maria|sqlite|supabase|mongo|redis|neon|planetscale|snowflake|bigquery|clickhouse|database", {PRIVATE}),
    (r"1password|bitwarden|vault|secret|keychain|\baws\b|gcp|azure|kubernetes|k8s|cloudflare|stripe", {PRIVATE}),
    (r"shell|terminal|desktop[-_]?commander|\bssh\b", {PRIVATE, OUTBOUND}),
    (r"webhook|http[-_]?request|zapier|n8n|ifttt", {OUTBOUND}),
]
BUILTIN_LEGS = {"webfetch": {UNTRUSTED, OUTBOUND}, "websearch": {UNTRUSTED}, "web_fetch": {UNTRUSTED, OUTBOUND},
                "google_web_search": {UNTRUSTED}}
SHELL_LEGS = {"curl": {OUTBOUND, UNTRUSTED}, "wget": {OUTBOUND, UNTRUSTED}, "gh": {UNTRUSTED, OUTBOUND},
              "glab": {UNTRUSTED, OUTBOUND}, "nc": {OUTBOUND}, "ssh": {OUTBOUND}, "scp": {OUTBOUND}}

# program: (subcommand prefixes that take the dangerous options, or None for any), how it runs other programs
ARGV_EXEC = {
    "find": (None, "find -exec runs any program"), "fd": (None, "fd -x runs any program"),
    "xargs": (None, "xargs runs any program"), "rg": (None, "rg --pre runs a program on every file"),
    "git": ({"-c", "show", "log", "diff", "grep", "config", "submodule", "clone", "fetch", "pull", "difftool", "blame"},
            "git -c core.pager or core.sshCommand runs a program; show and log --output overwrite files"),
    "go": ({"test", "run", "generate", "build", "vet", "tool"}, "go test -exec, go run and go generate run code"),
    "cargo": ({"build", "test", "run", "bench", "check", "install"}, "cargo runs build.rs and the repository's tests"),
    "npm": ({"test", "t", "run", "run-script", "exec", "x", "install", "i", "ci", "start", "explore"},
            "npm test and npm run run the repository's scripts"),
    "pnpm": ({"test", "run", "exec", "dlx", "install", "i", "start"}, "pnpm test and pnpm run run the repository's scripts"),
    "yarn": ({"test", "run", "exec", "dlx", "install", "start"}, "yarn test and yarn run run the repository's scripts"),
    "bun": ({"test", "run", "x", "install", "i"}, "bun run and bun test run the repository's code"),
    "make": (None, "make runs the repository's Makefile"), "just": (None, "just runs the repository's justfile"),
    "pytest": (None, "pytest imports the repository's conftest.py"), "tox": (None, "tox runs the repository's commands"),
    "tar": (None, "tar --to-command and --checkpoint-action=exec run programs"),
    "zip": (None, "zip -T -TT runs a program"), "awk": (None, "awk system() runs programs"),
    "sed": (None, "GNU sed's e command runs programs"), "ssh": (None, "ssh -o ProxyCommand runs a program"),
    "docker": (None, "docker run runs anything"), "kubectl": ({"exec", "run", "debug", "apply"}, "kubectl exec runs "
                                                              "commands in a cluster"),
    "pip": ({"install"}, "pip install runs the setup code of what it installs"),
    "uv": ({"run", "pip", "tool"}, "uv run runs any command"),
}
INTERPRETERS = {"env": "env runs any program", "npx": "npx runs any package", "bunx": "bunx runs any package",
                "pnpx": "pnpx runs any package", "uvx": "uvx runs any package", "pipx": "pipx run runs any package",
                "node": "node -e runs any code", "python": "python -c runs any code", "python3": "python3 -c runs any code",
                "py": "py -c runs any code", "deno": "deno eval runs any code", "ruby": "ruby -e runs any code",
                "perl": "perl -e runs any code", "php": "php -r runs any code", "bash": "bash -c runs any command",
                "sh": "sh -c runs any command", "zsh": "zsh -c runs any command", "pwsh": "pwsh -c runs any command",
                "powershell": "powershell -c runs any command", "cmd": "cmd /c runs any command", "eval": "eval runs any command"}


@dataclass(frozen=True)
class Tool:
    label: str
    legs: frozenset
    auto: bool


def _words(command: str) -> list[str]:
    return [w for w in re.split(r"\s+", command.strip()) if w]


def allowed_command(entry: str) -> tuple[str, bool] | None:
    """The shell command an allow-list entry pre-approves, and whether it takes any further arguments.

    Claude Code: Bash(git:*), Bash(npm run test *), Bash(git status) (exact). Gemini CLI: run_shell_command(git).
    Cursor and Copilot lists hold plain command prefixes."""
    e = entry.strip()
    m = re.fullmatch(r"(?:Bash|run_shell_command|shell|ShellTool)\((.*)\)", e, re.I)
    if m:
        inner = m.group(1).strip()
        if inner.endswith(":*") or inner.endswith(" *") or inner.endswith("*"):
            return inner.rstrip("*").rstrip(":").strip(), True
        return inner, m.group(0).lower().startswith(("run_shell_command", "shell"))  # Gemini matches by prefix
    if re.fullmatch(r"[A-Za-z0-9_./-]+(?: [A-Za-z0-9_./=-]+)*", e):
        return e, True  # Cursor / Copilot: prefixes
    return None


def argv_exec(entry: str) -> tuple[str, str, bool] | None:
    """(program, how it runs other programs, interpreter?) when an allow-list entry lets the agent run any program
    through the arguments; None for exact commands and harmless ones."""
    found = allowed_command(entry)
    if not found or not found[1]:
        return None
    words = _words(found[0])
    if not words:
        return None
    prog = words[0].lower().rsplit("/", 1)[-1].removesuffix(".exe")
    if prog in INTERPRETERS:
        return prog, INTERPRETERS[prog], True
    if prog in ARGV_EXEC:
        subs, how = ARGV_EXEC[prog]
        if subs is None or len(words) == 1 or words[1].lower() in subs:
            return prog, how, False
    return None


def server_legs(name: str, spec) -> set[str]:
    """What an MCP server reaches, from its name, command, arguments and URL."""
    hay = name.lower()
    if isinstance(spec, dict):
        hay += " " + " ".join(str(spec.get(k) or "") for k in ("command", "url", "serverUrl", "httpUrl"))
        hay += " " + " ".join(str(a) for a in (spec.get("args") or []) if isinstance(a, (str, int)))
    legs: set[str] = set()
    for pattern, gives in SERVER_LEGS:
        if re.search(pattern, hay.lower()):
            legs |= gives
    return legs


def tools_from_allow(entries) -> list[Tool]:
    """Built-in tools and shell commands an allow list runs without asking."""
    out = []
    for entry in entries or []:
        if not isinstance(entry, str):
            continue
        low = entry.strip().lower()
        if low in BUILTIN_LEGS:  # bare WebFetch: any domain; WebFetch(domain:docs.python.org) is scoped
            out.append(Tool(entry.strip(), frozenset(BUILTIN_LEGS[low]), True))
            continue
        found = allowed_command(entry)
        if found and found[1]:
            words = _words(found[0])
            prog = words[0].lower().rsplit("/", 1)[-1] if words else ""
            if prog in SHELL_LEGS:
                out.append(Tool(entry.strip(), frozenset(SHELL_LEGS[prog]), True))
    return out


def tools_from_servers(servers, allow, *, everything_auto: bool = False) -> list[Tool]:
    """MCP servers, with whether their tools run without asking: allow-listed (mcp__name, mcp__name__*), marked
    auto-approved in the server entry (autoApprove, alwaysAllow, trust), or every tool when approvals are off."""
    allow_low = {str(a).strip().lower() for a in allow or [] if isinstance(a, str)}
    out = []
    for name, spec in (servers or {}).items():
        if not isinstance(spec, dict):
            continue
        legs = server_legs(str(name), spec)
        if not legs:
            continue
        key = re.sub(r"[^a-z0-9_-]", "_", str(name).lower())
        auto = everything_auto or f"mcp__{key}" in allow_low or f"mcp__{key}__*" in allow_low or \
            spec.get("trust") is True or bool(spec.get("autoApprove")) or bool(spec.get("alwaysAllow"))
        out.append(Tool(f"MCP server {name}", frozenset(legs), auto))
    return out


def toxic(tools: list[Tool]) -> tuple[list[Tool], list[Tool]] | None:
    """The tools that bring in untrusted content and the tools that send data out, when both run without asking."""
    auto = [t for t in tools if t.auto]
    sources = [t for t in auto if UNTRUSTED in t.legs]
    sinks = [t for t in auto if OUTBOUND in t.legs]
    return (sources, sinks) if sources and sinks else None


def describe(flow: tuple[list[Tool], list[Tool]]) -> str:
    sources, sinks = flow
    names = lambda ts: ", ".join(dict.fromkeys(t.label for t in ts))  # noqa: E731
    return (f"content anyone can write comes in through {names(sources)} and can go out through {names(sinks)}, "
            "without asking")
