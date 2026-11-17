"""Real incidents: what happened, how it reached people, what agent-white-hat checks for, the traces it leaves on a
computer, and what to do about it, in order.

The catalog is data (data/incidents.json). checkup looks for the traces, `pah incident` shows an incident with its
response, the MCP server answers lookups, and docs/incidents.md is generated from it. Every incident cites its sources;
tests check that its rules exist, that its trap repositories are caught by those rules and that every step resolves.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data" / "incidents.json"
KINDS = ("repository", "package", "extension", "skill", "mcp", "ci", "install-page", "instruction-file", "agent-flaw",
         "stealer", "malware", "model")
SEVERITIES = ("critical", "high", "medium")


@dataclass(frozen=True)
class Trace:
    """Something an incident leaves on a computer: a file or folder (path), a file whose name starts a certain way
    (a * in the last part of the path), or a line in a file (match, a regular expression)."""

    path: str
    what: str
    severity: str = "critical"
    match: str = ""


@dataclass(frozen=True)
class Incident:
    id: str
    name: str
    when: str  # YYYY-MM, or YYYY when the month is not known
    kind: str
    summary: str
    entry: tuple[str, ...]  # how it got in and what ran
    rules: tuple[str, ...]  # rules that report it in a repository, package, skill or command
    cases: tuple[str, ...]  # TrapRepo cases built on it
    traces: tuple[Trace, ...]
    respond: tuple[str, ...]  # in order; "@name" is a shared step
    refs: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "when": self.when, "kind": self.kind, "summary": self.summary,
                "entry": list(self.entry), "rules": list(self.rules), "cases": list(self.cases),
                "traces": [{"path": t.path, "what": t.what, "severity": t.severity, **({"match": t.match} if t.match
                                                                                        else {})} for t in self.traces],
                "respond": playbook(self), "refs": list(self.refs)}


@lru_cache(maxsize=1)
def _data() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def steps() -> dict[str, str]:
    """Response steps shared by several incidents."""
    return dict(_data()["steps"])


@lru_cache(maxsize=1)
def catalog() -> tuple[Incident, ...]:
    """Every incident, newest first."""
    out = []
    for d in _data()["incidents"]:
        out.append(Incident(d["id"], d["name"], d["when"], d["kind"], d["summary"], tuple(d.get("entry", ())),
                            tuple(d.get("rules", ())), tuple(d.get("cases", ())),
                            tuple(Trace(**t) for t in d.get("traces", ())), tuple(d.get("respond", ())),
                            tuple(d.get("refs", ()))))
    return tuple(sorted(out, key=lambda i: (i.when, i.id), reverse=True))


def get(incident_id: str) -> Incident | None:
    return next((i for i in catalog() if i.id == incident_id.strip().lower()), None)


def search(text: str) -> list[Incident]:
    """Incidents whose id, name, summary, entry, rules or cases mention every word of text."""
    words = text.lower().split()
    found = []
    for i in catalog():
        hay = " ".join((i.id, i.name, i.kind, i.summary, *i.entry, *i.rules, *i.cases)).lower()
        if all(w in hay for w in words):
            found.append(i)
    return found


def for_rule(rule_id: str) -> list[Incident]:
    return [i for i in catalog() if rule_id in i.rules]


def playbook(incident: Incident) -> list[str]:
    """The response in order, with shared steps written out."""
    shared = steps()
    return [shared[s[1:]] if s.startswith("@") else s for s in incident.respond]


# --------------------------------------------------------------------------------------------- traces on this machine


def expand(path: str) -> Path | None:
    """Where a trace path is on this computer; None when it cannot exist on this operating system.

    ~/ is the home folder; {temp} the temporary folder; {localappdata}, {appdata} and {programdata} the Windows
    folders of those names; /... a Unix path; C:/... a Windows path.
    """
    win = sys.platform == "win32"
    home = Path.home()
    if path.startswith("~/"):
        return home / path[2:]
    m = re.match(r"\{(\w+)\}/(.*)$", path)
    if m:
        base, rest = m.group(1), m.group(2)
        if base == "temp":
            return Path(tempfile.gettempdir()) / rest
        if not win:
            return None
        folder = {"localappdata": os.environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local"),
                  "appdata": os.environ.get("APPDATA") or str(home / "AppData" / "Roaming"),
                  "programdata": os.environ.get("ProgramData") or "C:/ProgramData"}.get(base)
        return Path(folder) / rest if folder else None
    if path.startswith("/"):
        return None if win else Path(path)
    if re.match(r"[A-Za-z]:/", path):
        return Path(path) if win else None
    return None


def present(trace: Trace) -> list[Path]:
    """Where this trace is found on this computer (read-only)."""
    p = expand(trace.path)
    if p is None:
        return []
    try:
        if trace.match:
            text = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
            return [p] if re.search(trace.match, text, re.M) else []
        if any(c in p.name for c in "*?["):
            return sorted(Path(e.path) for e in os.scandir(p.parent) if fnmatch.fnmatch(e.name, p.name))[:3]
        return [p] if os.path.lexists(p) else []
    except OSError:
        return []


def found(incidents: list[Incident] | tuple[Incident, ...] | None = None) -> list[tuple[Incident, Trace, Path]]:
    """Every trace of the given incidents (all by default) present on this computer."""
    return [(i, t, p) for i in (catalog() if incidents is None else incidents) for t in i.traces for p in present(t)]


# --------------------------------------------------------------------------------------------- rendering


def text(incident: Incident, located: list[tuple[Trace, Path]] | None = None) -> str:
    """One incident for people: what happened, how it got in, what is checked, traces, what to do, sources."""
    from .model import RULES

    out = [f"{incident.name}  ({incident.when}, {incident.kind})", "", incident.summary]
    if incident.entry:
        out += ["", "How it got in"] + [f"  - {e}" for e in incident.entry]
    if incident.rules or incident.cases:
        out += ["", "What agent-white-hat checks"]
        out += [f"  {r}  {RULES[r].title if r in RULES else ''}".rstrip() for r in incident.rules]
        if incident.cases:
            out.append("  trap repositories: " + ", ".join(incident.cases))
    if incident.traces:
        out += ["", f"Traces on a computer (pah incident check {incident.id})"]
        width = max(len(t.path) for t in incident.traces)
        out += [f"  {t.path.ljust(width)}  {t.what}" for t in incident.traces]
    if located:
        out += ["", "FOUND ON THIS COMPUTER"] + [f"  {p}  ({t.what})" for t, p in located]
    out += ["", "What to do, in order"] + [f"  {n}. {s}" for n, s in enumerate(playbook(incident), 1)]
    out += ["", "Sources"] + [f"  {r}" for r in incident.refs]
    return "\n".join(out)


def table() -> str:
    """Every incident on one line each."""
    rows = [(i.when, i.id, i.name) for i in catalog()]
    w = max(len(r[1]) for r in rows)
    return "\n".join(f"{when:<7}  {iid.ljust(w)}  {name}" for when, iid, name in rows)


def markdown() -> str:
    """docs/incidents.md"""
    from .model import RULES

    def cell(s: str) -> str:
        return s.replace("|", "\\|")

    out = ["# Incidents", "",
           "Real attacks on people who use AI agents, and what to do about each one: how it got in, which rules and trap",
           "repositories cover it, what it leaves on a computer (`pah incident check` looks for these, and so does",
           "`pah checkup`), and the response in order. Generated from [pah/data/incidents.json](../pah/data/incidents.json)",
           "by `pah incident list --markdown`.", "",
           "| When | Incident | Kind | Caught by | Traces |", "| --- | --- | --- | --- | --- |"]
    for i in catalog():
        out.append(f"| {i.when} | [{cell(i.name)}](#{i.id}) | {i.kind} | {', '.join(i.rules) or '-'} | "
                   f"{len(i.traces) or '-'} |")
    for i in catalog():
        out += ["", f'<a id="{i.id}"></a>', f"## {i.name}", "", f"*{i.when}, {i.kind}.* {i.summary}"]
        if i.entry:
            out += ["", "**How it got in**", ""] + [f"- {e}" for e in i.entry]
        if i.rules or i.cases:
            out += ["", "**What agent-white-hat checks**", ""]
            out += [f"- [{r}](rules.md) {RULES[r].title if r in RULES else ''}".rstrip() for r in i.rules]
            if i.cases:
                out.append("- Trap repositories: " + ", ".join(f"`{c}`" for c in i.cases))
        if i.traces:
            out += ["", f"**Traces on a computer** (`pah incident check {i.id}`)", ""]
            out += [f"- `{t.path}`" + (f" containing `{t.match}`" if t.match else "") + f": {t.what}" for t in i.traces]
        out += ["", "**What to do, in order**", ""] + [f"{n}. {s}" for n, s in enumerate(playbook(i), 1)]
        out += ["", "**Sources:** " + ", ".join(f"<{r}>" for r in i.refs)]
    return "\n".join(out) + "\n"
