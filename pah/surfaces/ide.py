"""Editors and dev containers: VS Code and Cursor tasks that run when a folder opens, settings that run
programs, dev container lifecycle commands and host mounts, and direnv files.
"""
from __future__ import annotations

import json
import posixpath
import re

from ..model import rank
from ..patterns import analyze_command
from .rules import R_DEVCONTAINER_HOST, R_DEVCONTAINER_MOUNT, R_ENVRC, R_EXEC_SETTING, R_FOLDER_OPEN, R_WEAK_SETTINGS
from .agent_setup import pre_approved
from .base import File, State, as_command, line_of, load_jsonc, refs_in_command
from .mcp import mcp_config


TASK_TRIGGER = "opening the folder in VS Code or Cursor"


EXEC_SETTING = re.compile(r"(?:^|\.)(?:path|executablePath|serverPath|interpreterPath|defaultInterpreterPath|runtime|"
                          r"command|exePath|binPath|shellPath)$|^terminal\.integrated\.(?:profiles|shell|automationProfile)", re.I)


def vscode_tasks(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    for task in data.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        run_on = ((task.get("runOptions") or {}).get("runOn") or "").lower()
        cmds = [as_command(task)] + [as_command(task[os_]) for os_ in ("windows", "osx", "linux")
                                     if isinstance(task.get(os_), dict) and task[os_].get("command")]
        label = task.get("label") or task.get("taskName") or "task"
        for cmd in filter(None, cmds):
            line = line_of(f.text, str(task.get("command"))[:40]) if task.get("command") else 0
            if run_on == "folderopen":
                state.command(cmd, f.rel, line, f"folder-open task '{label}'", TASK_TRIGGER,
                              base_dir=posixpath.dirname(f.dir), floor=(R_FOLDER_OPEN, "high"))
            else:
                state.surface(f"task '{label}'", f.rel, "when you run the task", cmd, line)


def vscode_settings(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    checks = (("chat.tools.autoApprove", True), ("chat.tools.global.autoApprove", True),
              ("task.allowAutomaticTasks", "on"), ("security.workspace.trust.enabled", False),
              ("chat.agent.autoApprove", True), ("github.copilot.chat.agent.autoApprove", True),
              ("chat.tools.terminal.autoApproveWorkspaceNpmScripts", True))
    for key, bad in checks:
        if key in data and data[key] == bad:
            state.add(R_WEAK_SETTINGS, "high", f.rel, line_of(text, key), f"{key}: {json.dumps(bad)}", key)
    terminal = data.get("chat.tools.terminal.autoApprove")

    def wide(pattern) -> bool:  # "*" or a /regex/ that matches anything
        p = str(pattern).strip()
        return p in ("*", ".*", "/.*/", "/.+/", "/^.*$/") or (p.startswith("/") and (".*" in p or "\\S+" in p))

    if terminal is True or (isinstance(terminal, dict) and any(v is True and wide(k) for k, v in terminal.items())):
        state.add(R_WEAK_SETTINGS, "high", f.rel, line_of(text, "chat.tools.terminal.autoApprove"),
                  "approves terminal commands for the agent by pattern", "chat.tools.terminal.autoApprove")
    if isinstance(terminal, dict):
        pre_approved(state, f, [k for k, v in terminal.items() if v is True and not str(k).startswith("/")], "VS Code agent")
    for key, value in data.items():
        if isinstance(value, str) and EXEC_SETTING.search(key):
            ref = refs_in_command(value, posixpath.dirname(f.dir), state.files)
            if ref:
                state.add(R_EXEC_SETTING, "high", f.rel, line_of(text, key), f"{key} runs {ref[0]}", f"{key}: {value}")
                state.mark_autoexec(ref[0], f"executable named in {f.rel}")
        elif isinstance(value, dict) and key.startswith("terminal.integrated.profiles"):
            for name, prof in value.items():
                if isinstance(prof, dict) and isinstance(prof.get("path"), str):
                    ref = refs_in_command(prof["path"], posixpath.dirname(f.dir), state.files)
                    if ref:
                        state.add(R_EXEC_SETTING, "high", f.rel, line_of(text, prof["path"]), f"terminal profile {name} runs {ref[0]}",
                                  prof["path"])
    mcp_config(state, f, "VS Code", "VS Code agent in this workspace")


DEV_LIFECYCLE = ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand")


SENSITIVE_MOUNT = re.compile(r"\.ssh|\.aws|\.config[\\/]gcloud|\.kube|\.docker|docker\.sock|^/,|^\$\{localEnv:(?:HOME|USERPROFILE)\}/?,"
                             r"|^~/?,|\.claude|\.codex|\.gemini|\.gnupg|\.netrc|\.npmrc|\.git-credentials", re.I)


def _host_mount_sources(data: dict) -> list[str]:
    """Host paths bind-mounted into the container. Named volumes (type=volume) live in Docker, not on the host."""
    out = []
    for mount in data.get("mounts") or []:
        if isinstance(mount, dict):
            if str(mount.get("type", "bind")).lower() != "volume" and mount.get("source"):
                out.append(str(mount["source"]))
        elif isinstance(mount, str):
            fields = dict(part.split("=", 1) for part in mount.split(",") if "=" in part)
            if fields.get("type", "bind").lower() != "volume" and (fields.get("source") or fields.get("src")):
                out.append(fields.get("source") or fields.get("src"))
    args = [str(a) for a in data.get("runArgs") or []]
    for i, arg in enumerate(args):
        value = None
        if arg in ("-v", "--volume", "--mount") and i + 1 < len(args):
            value = args[i + 1]
        elif arg.startswith(("-v=", "--volume=", "--mount=")):
            value = arg.split("=", 1)[1]
        if value is None:
            continue
        if "source=" in value or "src=" in value:
            fields = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
            if fields.get("type", "bind").lower() != "volume":
                out.append(fields.get("source") or fields.get("src") or "")
        elif ":" in value and value.split(":", 1)[0].startswith(("/", "~", "$", ".")):
            out.append(value.split(":", 1)[0])
    return [src for src in out if src]


def devcontainer(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    if data.get("initializeCommand"):
        state.command(as_command(data["initializeCommand"]), f.rel, line_of(text, "initializeCommand"),
                      "dev container initializeCommand (host)", "opening the folder in a dev container",
                      base_dir=posixpath.dirname(f.dir) if f.dir.endswith(".devcontainer") else f.dir,
                      floor=(R_DEVCONTAINER_HOST, "high"))
    for key in DEV_LIFECYCLE:  # these run inside the container
        if data.get(key):
            cmd = as_command(data[key])
            state.surface(f"dev container {key} (inside the container)", f.rel, "dev container start", cmd, line_of(text, key))
            state.extend([x for x in analyze_command(cmd, f.rel, line_of(text, key), "autoexec")
                          if rank(x.severity) >= rank("high")])
    mounts = json.dumps(data.get("mounts") or []) + " " + json.dumps(data.get("runArgs") or [])
    host_sources = _host_mount_sources(data)
    sensitive = [src for src in host_sources if SENSITIVE_MOUNT.search(src + ",")]
    if sensitive:
        state.add(R_DEVCONTAINER_MOUNT, "high", f.rel, line_of(text, "mounts") or line_of(text, "runArgs"),
                  "mounts host credentials or the Docker socket: " + ", ".join(sensitive[:3]), mounts[:200])
    if re.search(r"--privileged|--pid=host|--net=host|--cap-add[= ](?:ALL|SYS_ADMIN)", mounts) or data.get("privileged"):
        state.add(R_DEVCONTAINER_MOUNT, "medium", f.rel, line_of(text, "privileged") or line_of(text, "runArgs"),
                  "privileged container", mounts[:200])


def envrc(state: State, f: File) -> None:
    state.surface(".envrc", f.rel, "entering the directory after `direnv allow`", (f.text or "")[:200])
    state.mark_autoexec(f.rel, "direnv .envrc")
    state.add(R_ENVRC, "low", f.rel, 1, "runs on cd once allowed", (f.text or "")[:120])
