"""Git: submodules, repository configuration that runs programs, bare repositories and hooks shipped in a
repository.
"""
from __future__ import annotations

import posixpath
import re

from .rules import R_GITMODULES, R_GIT_CONFIG, R_GIT_HOOKS, R_WORKTREE
from .base import File, State


def gitmodules(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*(url|path|update|branch)\s*=\s*(.*)$", text):
        key, value = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        if key == "url" and (value.startswith(("ext::", "-", "fd::")) or "--upload-pack" in value or "ProxyCommand" in value):
            state.add(R_GITMODULES, "critical", f.rel, line, f"submodule URL can run commands: {value}", value)
        elif key == "update" and value.strip().startswith("!"):
            state.add(R_GITMODULES, "critical", f.rel, line, f"custom submodule update command {value}", value)
        elif key == "path" and (re.search(r"[\r\x00-\x1f]", value) or value.startswith(("/", "..")) or "/.git" in value
                                or value.startswith(".git") or "\\" in value):
            state.add(R_GITMODULES, "high", f.rel, line, f"submodule path {value!r} escapes or targets .git", repr(value))
    if "[submodule" in text:
        state.surface("git submodules", f.rel, "git clone --recursive / git submodule update")


GIT_DANGEROUS = re.compile(r"(?mi)^\s*(fsmonitor|hookspath|sshcommand|pager|editor|askpass|helper|external|textconv|"
                           r"clean|smudge|process|packobjectshook|program|uploadpack|receivepack)\s*=\s*(.+)$")


def git_config(state: State, f: File) -> None:
    text = f.text or ""
    for m in GIT_DANGEROUS.finditer(text):
        key, value = m.group(1).lower(), m.group(2).strip()
        if key == "fsmonitor" and value.lower() in ("true", "false"):
            continue
        if value.startswith(("git-lfs ", "git lfs ")) or (key == "helper" and value in ("manager", "manager-core", "store",
                                                                                         "cache", "osxkeychain", "wincred")):
            continue
        sev = "high" if key in ("fsmonitor", "sshcommand", "packobjectshook", "uploadpack") else "medium"
        if key == "hookspath" and re.search(r"\.husky", value):
            sev = "low"
        state.add(R_GIT_CONFIG, sev, f.rel, text.count("\n", 0, m.start()) + 1, f"{key} = {value}", m.group(0))
    for m in re.finditer(r"(?m)^\s*(\w[\w-]*)\s*=\s*!(.+)$", text):
        state.add(R_GIT_CONFIG, "medium", f.rel, text.count("\n", 0, m.start()) + 1, f"alias {m.group(1)} runs a shell "
                  "command", m.group(0))


def bare_repo(state: State, f: File) -> bool:
    """config next to HEAD in a folder that is not .git: a bare repository inside the project. Git uses its config
    when a command runs in that folder (safe.bareRepository defaults to all), as agents do before any trust prompt."""
    head = state.files.get(posixpath.join(f.dir, "HEAD"))
    return bool(head and head.text and re.match(r"ref:\s*refs/|[0-9a-f]{40}", head.text.strip())
                and posixpath.basename(f.dir) != ".git")


def git_hook(state: State, f: File) -> None:
    if f.name.endswith(".sample"):
        return
    state.surface("git hook", f.rel, "git commit / checkout / push in this repository", (f.text or "")[:200])
    state.mark_autoexec(f.rel, "git hook")
    state.add(R_GIT_HOOKS, "high", f.rel, 1, "hook file present in .git/hooks", f.rel)


def git_indirection(state: State, f: File) -> None:
    target = (f.text or "").strip().removeprefix("gitdir:").strip()
    state.add(R_WORKTREE, "high", f.rel, 1, f"{f.name} points to {target}", target)
