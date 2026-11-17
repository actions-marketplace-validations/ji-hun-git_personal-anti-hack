"""What an agent did earlier in a session, so the guard can judge a step by the steps before it.

Every hook call appends one line to ~/.personal-anti-hack/sessions/<id>.jsonl: the kind of step, its tags (a credential
read, a download, data sent out, instructions found in a tool's output, ...) and what the guard answered. No file
contents, command output or secret values are kept: only a short description with anything token-shaped masked. Files
older than a week are removed. Nothing leaves the machine.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from .guard import HOME

SESSIONS = HOME / "sessions"
WINDOW = 12 * 3600  # steps older than this no longer count toward a chain
KEEP_DAYS = 7
MAX_SESSIONS = 200
MAX_LINES = 400

_ID_KEYS = ("session_id", "sessionId", "conversation_id", "conversationId", "thread_id", "threadId", "task_id", "taskId",
            "chat_id", "chatId")


def session_key(agent: str, data: dict, cwd: str = "") -> str:
    """The agent's own session id when its hook payload has one; otherwise the folder it works in, so steps in the same
    folder within WINDOW count as one session."""
    for key in _ID_KEYS:
        value = data.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return f"{agent}:{str(value).strip()[:200]}"
    return f"{agent}:folder:{cwd or data.get('cwd') or os.getcwd()}"


def _file(key: str) -> Path:
    return SESSIONS / (hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:24] + ".jsonl")


_SECRETISH = re.compile(
    r"(?i)((?:authorization|x-api-key|api[_-]?key|access[_-]?token|token|secret|password|passwd|pwd)[\"']?\s*[:=]\s*"
    r"(?:bearer\s+|token\s+|basic\s+)?|bearer\s+|--password[= ]|\s-p(?=\S{6,}))[\"']?[^\s\"'&;|]+"
    r"|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_\w{8,}|(?:AKIA|ASIA)[0-9A-Z]{8,}|xox[abprs]-[\w-]{8,}"
    r"|npm_[A-Za-z0-9]{8,}|hf_[A-Za-z0-9]{8,}|AIza[\w-]{8,}|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*|[A-Za-z0-9+/=_-]{40,}")


def mask(text: str, limit: int = 180) -> str:
    """A description safe to keep: values that look like secrets become '…', and the text is cut short."""
    text = " ".join(str(text).split())
    text = _SECRETISH.sub(lambda m: (m.group(1) or "") + "…", text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def load(key: str, now: float | None = None, window: float = WINDOW) -> list[dict]:
    """Steps recorded for this session within the window, oldest first."""
    path = _file(key)
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 400_000))
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    now = time.time() if now is None else now
    events = []
    for line in raw.splitlines()[-MAX_LINES:]:
        try:
            event = json.loads(line)
        except ValueError:
            continue  # the first line after seeking into the middle of the file, or a torn write
        if isinstance(event, dict) and now - float(event.get("t", 0)) <= window:
            events.append(event)
    return events


def append(key: str, event: dict) -> None:
    """Record one step. Appending one short line keeps parallel hook calls from overwriting each other."""
    try:
        SESSIONS.mkdir(parents=True, exist_ok=True)
        path = _file(key)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
        if path.stat().st_size > 1_500_000:
            kept = path.read_text(encoding="utf-8", errors="replace").splitlines()[-MAX_LINES:]
            tmp = path.with_suffix(".tmp")
            tmp.write_text("\n".join(kept) + "\n", encoding="utf-8")
            os.replace(tmp, path)
        if int(time.time()) % 50 == 0:
            prune()
    except OSError:
        pass  # a guard that cannot write its log still judges the step


def prune(now: float | None = None) -> int:
    now = time.time() if now is None else now
    removed = 0
    try:
        files = sorted(SESSIONS.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return 0
    for i, path in enumerate(files):
        try:
            if i >= MAX_SESSIONS or now - path.stat().st_mtime > KEEP_DAYS * 86400:
                path.unlink()
                removed += 1
        except OSError:
            pass
    return removed


def sessions(limit: int = 20) -> list[dict]:
    """Recent sessions, newest first: id, agent, folder, number of steps, alerts and when it was last active."""
    out = []
    try:
        files = sorted(SESSIONS.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    except OSError:
        return out
    for path in files:
        events = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-MAX_LINES:]:
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        if not events:
            continue
        alerts = [a for e in events for a in e.get("alerts", [])]
        out.append({"id": path.stem, "agent": events[-1].get("agent", ""), "cwd": events[-1].get("cwd", ""),
                    "steps": len(events), "alerts": alerts, "denied": sum(e.get("action") == "deny" for e in events),
                    "last": events[-1].get("t", 0), "path": str(path)})
    return out


def events_of(session_id: str) -> list[dict]:
    """All recorded steps of one session, by the id `pah session list` shows (or 'latest')."""
    if session_id == "latest":
        recent = sessions(1)
        if not recent:
            return []
        session_id = recent[0]["id"]
    path = SESSIONS / f"{re.sub(r'[^0-9a-f]', '', session_id.lower())[:24]}.jsonl"
    events = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return events
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def clear(session_id: str | None = None) -> int:
    """Forget one session's steps, or all of them."""
    if session_id:
        path = SESSIONS / f"{re.sub(r'[^0-9a-f]', '', session_id.lower())[:24]}.jsonl"
        try:
            path.unlink()
            return 1
        except OSError:
            return 0
    count = 0
    for path in SESSIONS.glob("*.jsonl"):
        try:
            path.unlink()
            count += 1
        except OSError:
            pass
    return count
