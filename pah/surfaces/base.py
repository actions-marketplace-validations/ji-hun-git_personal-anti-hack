"""Files and scan state shared by every handler, and the parsing they share: commands split into the files they
run, JSON with comments, TOML, and every command nested anywhere in a configuration file.
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..model import Finding, Surface, clip
from ..names import R_LOOKALIKE, lookalike, lookalike_severity, names_in_command
from ..patterns import analyze_command
from ..policy import inert_path


@dataclass
class File:
    rel: str
    size: int
    data: bytes
    text: str | None
    link_target: str | None = None

    @property
    def name(self) -> str:
        return posixpath.basename(self.rel)

    @property
    def dir(self) -> str:
        return posixpath.dirname(self.rel)


@dataclass
class State:
    root: Path
    files: dict[str, File] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    autoexec: dict[str, str] = field(default_factory=dict)
    doc_auto: set[str] = field(default_factory=set)
    incomplete: list[str] = field(default_factory=list)
    packages: list[tuple[str, str, str, int, str]] = field(default_factory=list)  # ecosystem, name, path, line, context
    extra: dict = field(default_factory=dict)  # stats from optional checks (dependencies, antivirus)
    archives_opened: int = 0

    def add(self, rule_id: str, severity: str | None, path: str, line: int = 0, message: str = "", evidence: str = "",
            context: str = "config") -> None:
        if severity:
            self.findings.append(Finding(rule_id, severity, path, line, message, clip(evidence), context))

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def surface(self, kind: str, path: str, trigger: str, command: str = "", line: int = 0) -> None:
        if inert_path(path):
            return  # a hook config inside a test fixture or an archive is not a surface of this repository
        self.surfaces.append(Surface(kind, path, trigger, clip(command, 300), line))

    def mark_autoexec(self, rel: str, reason: str, source: str | None = None) -> None:
        """Mark a file as running on its own. Fixtures and archive members only count when something outside them
        (an install script, a hook) runs them: a setup.py inside tests/fixtures/ is test data."""
        if rel not in self.files or rel in self.autoexec:
            return
        if inert_path(rel) and inert_path(source or rel):
            return
        self.autoexec[rel] = reason

    def command(self, cmd: str, path: str, line: int, kind: str, trigger: str, base_dir: str = "",
                floor: tuple[str, str] | None = None) -> list[Finding]:
        """Record a command surface, analyze it, mark the files it runs, and check the packages it installs."""
        cmd = cmd.strip()
        if not cmd:
            return []
        self.surface(kind, path, trigger, cmd, line)
        found = analyze_command(cmd, path, line, "autoexec")
        self.extend(found)
        for ref in exec_refs_in_command(cmd, base_dir or posixpath.dirname(path), self.files):
            self.mark_autoexec(ref, f"run by {kind} in {path}", source=path)
        for eco, name in names_in_command(cmd):
            self.packages.append((eco, name, path, line, "autoexec"))
            hit = lookalike(name, eco)
            if hit:
                self.add(R_LOOKALIKE, lookalike_severity(hit[1], "command"), path, line,
                         f"{name} ({eco}) {hit[1]} from {hit[0]}", cmd, "autoexec")
        if floor:
            self.add(floor[0], floor[1], path, line, kind, cmd, "autoexec")
        return found


_TOKEN = re.compile(r"\"([^\"]*)\"|'([^']*)'|(\S+)")


_PLACEHOLDERS = re.compile(r"^(?:\$\{?(?:workspaceFolder|workspaceRoot|CLAUDE_PROJECT_DIR|PWD|fileDirname|localWorkspaceFolder|"
                           r"containerWorkspaceFolder|CLAUDE_PLUGIN_ROOT)\}?|%CD%|\$\(pwd\))[\\/]")


_QUOTED_PLACEHOLDER = re.compile(r"[\"']?(?:\$\{?(?:workspaceFolder|workspaceRoot|CLAUDE_PROJECT_DIR|PWD|localWorkspaceFolder|"
                                 r"containerWorkspaceFolder|fileDirname|CLAUDE_PLUGIN_ROOT)\}?|%CD%|\$\(pwd\))[\"']?[\\/]")


def refs_in_command(cmd: str, base_dir: str, files: dict) -> list[str]:
    """Repository files a command would run or read."""
    out = []
    cmd = _QUOTED_PLACEHOLDER.sub("", cmd)
    for m in _TOKEN.finditer(cmd):
        tok = next(g for g in m.groups() if g is not None)
        tok = tok.split("=", 1)[1] if tok.startswith("--") and "=" in tok else tok
        tok = _PLACEHOLDERS.sub("", tok).replace("\\", "/")
        if not tok or tok.startswith(("-", "http:", "https:", "$")) or len(tok) > 300:
            continue
        for cand in (posixpath.normpath(posixpath.join(base_dir, tok)), posixpath.normpath(tok)):
            if cand in files and cand not in out:
                out.append(cand)
                break
    return out


_SIMPLE_SPLIT = re.compile(r"&&|\|\||;|\||\n|(?<![<>&0-9])&(?![>&])")


_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


_WRAPPERS = {"sudo", "env", "exec", "time", "nohup", "nice", "command", "builtin", "call", "start", "doas"}


_RUNNERS = re.compile(r"^(?:(?:ba|z|da|k|fi|c|tc)?sh|python[0-9.]*|py|pypy[0-9.]*|node|nodejs|deno|bun|bunx|tsx|ts-node|"
                      r"ruby|perl|php|pwsh|powershell|osascript|cscript|wscript|source|\.|lua|rscript|julia|java|go|"
                      r"npx|pnpx|uv|uvx|pipx|poetry|pdm|hatch|rye|pnpm|yarn|npm|dotnet|cmd)(?:\.exe)?$", re.I)


NOT_CODE = (".md", ".markdown", ".rst", ".txt", ".adoc", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".lock", ".csv",
            ".tsv", ".html", ".htm", ".xml", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".css", ".scss",
            ".map", ".d.ts", ".ini", ".cfg", ".conf", ".env", ".log")


def exec_refs_in_command(cmd: str, base_dir: str, files: dict) -> list[str]:
    """Repository files a command would execute: the program itself (./setup.sh, bin/tool) or a script handed to an
    interpreter or runner (bash x.sh, node x.js, npx tsx x.ts, uv run x.py). Files a command only reads
    (cat README.md, docker build -f Dockerfile, git add x.sh) are not executed by it."""
    out: list[str] = []
    cmd = _QUOTED_PLACEHOLDER.sub("", cmd)
    for part in _SIMPLE_SPLIT.split(cmd):
        toks = []
        for m in _TOKEN.finditer(part):
            tok = next(g for g in m.groups() if g is not None)
            tok = tok.split("=", 1)[1] if tok.startswith("--") and "=" in tok else tok
            toks.append(_PLACEHOLDERS.sub("", tok).replace("\\", "/"))
        i = 0
        while i < len(toks) and (_ENV_ASSIGN.match(toks[i]) or toks[i].lower() in _WRAPPERS):
            i += 1
        if i >= len(toks):
            continue
        toks = [t.strip("\"'") for t in toks]
        head = toks[i]
        program = posixpath.basename(head.lower())
        if _RUNNERS.match(program):
            candidates = toks[i + 1:]
        elif "/" in head or head.lower().endswith((".bat", ".cmd", ".exe", ".com")):
            candidates = [head]  # a path is run as given; cmd.exe also runs batch files from the current folder
        else:
            continue
        for tok in candidates:
            if not tok or tok.startswith(("-", "/", "http:", "https:", "$")) or len(tok) > 300:
                continue
            if tok.lower().endswith(NOT_CODE):
                continue
            for cand in (posixpath.normpath(posixpath.join(base_dir, tok)), posixpath.normpath(tok)):
                if cand in files and cand not in out:
                    out.append(cand)
                    break
    return out


def load_jsonc(text: str):
    """JSON with comments and trailing commas (VS Code, devcontainer, Claude settings)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    if len(text) > 2_000_000:
        return None
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    try:
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))
    except ValueError:
        return None


def load_toml(text: str):
    try:
        import tomllib
    except ImportError:  # Python 3.10: handlers fall back to line patterns
        return None
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None


def line_of(text: str, needle: str) -> int:
    pos = text.find(needle) if needle else -1
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 0


def as_command(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    if isinstance(value, dict):
        if "command" in value:
            return as_command(value.get("command")) + (" " + as_command(value.get("args")) if value.get("args") else "")
        return " ; ".join(as_command(v) for v in value.values())
    return ""


def hook_urls(obj) -> list[str]:
    out = []
    if isinstance(obj, dict):
        if str(obj.get("type", "")).lower() == "http" and isinstance(obj.get("url"), str):
            out.append(obj["url"])
        for v in obj.values():
            out += hook_urls(v)
    elif isinstance(obj, list):
        for v in obj:
            out += hook_urls(v)
    return out


def walk_commands(obj, path: tuple = ()):
    """(json path, command) for every object with a string "command" (hooks, MCP servers, tasks)."""
    if isinstance(obj, dict):
        if isinstance(obj.get("command"), str):
            yield path, as_command(obj)
        for k, v in obj.items():
            if k not in ("command", "args"):
                yield from walk_commands(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_commands(v, path + (str(i),))
