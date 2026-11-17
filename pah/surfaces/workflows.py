"""CI workflows: untrusted text pasted into scripts, secrets sent out, privileged triggers and AI agent actions
that act on anyone's issue. They run on the CI provider's machines and matter to maintainers.
"""
from __future__ import annotations

import re

from ..hosts import classify_host
from .rules import R_CI_AGENT, R_CI_INJECTION, R_CI_PRT, R_CI_SECRETS
from .base import File, State, exec_refs_in_command, line_of


UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|"
    r"head_commit|commits|workflow_run|pages|release)\b[\w.\[\]*'\"-]*?\.(?:title|body|message|ref|head_ref|head_branch|"
    r"label|name|email|default_branch|page_name)|github\.head_ref)\s*\}\}", re.I)


OUTSIDE_TRIGGERS = re.compile(r"(?m)^\s*(?:on\s*:\s*\[?[^\n]*\b|-\s*|)(?:issues|issue_comment|pull_request_target|discussion|"
                              r"discussion_comment|pull_request_review_comment|workflow_run)\b\s*"
                              r"(?::(?!\s*(?:read|write|none)\b)|,|\]|$)")  # not `issues: write` under permissions


SEND_KIND = {"raw-ip": "a bare IP address", "plain-http": "a plain-HTTP address", "lookalike": "a look-alike domain",
             "exfil": "a capture or tunnel service"}


AI_ACTIONS = re.compile(r"(?mi)^\s*(?:-\s*)?uses\s*:\s*[\"']?(anthropics/claude-code(?:-base)?-action|openai/codex-action|"
                        r"google-github-actions/run-gemini-cli|google-gemini/gemini-cli-action|actions/ai-inference|"
                        r"cline/[\w.-]+|warpdotdev/[\w.-]+|qodo-ai/[\w.-]+)@")


AI_ACTION_UNSAFE = re.compile(r"allowed_non_write_users\s*:\s*[\"']?\*|allow-users\s*:\s*[\"']?\*|--dangerously[-_]skip[-_]permissions"
                              r"|Bash\(\s*\*\s*\)|--yolo\b|danger-full-access|safety-strategy\s*:\s*[\"']?unsafe", re.I)


RUNNER_MEMORY = re.compile(r"Runner\.(?:Worker|Listener)[^\n]{0,300}(?:/proc/|ReadProcessMemory|isSecret|ptrace|gcore)"
                           r"|(?:/proc/[^\s\"']*/(?:mem|maps|environ)|ReadProcessMemory|isSecret)[^\n]{0,300}Runner\.(?:Worker|Listener)")


def script_blocks(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every line inside `run:` and github-script `script:` values of a workflow."""
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:-\s+)?(run|script)\s*:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(3).strip()
        if rest and rest not in ("|", ">", "|-", ">-", "|+", ">+"):
            out.append((i + 1, lines[i]))
            i += 1
            continue
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
            out.append((j + 1, lines[j]))
            j += 1
        i = j
    return out


def workflow(state: State, f: File) -> None:
    text = f.text or ""
    if re.search(r"(?m)^\s*(?:on:\s*\[?[^\n]*\bpull_request_target\b|pull_request_target\s*:)", text) and \
            re.search(r"github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/", text):
        # A risk to the repository's CI secrets, not to the machine of someone who clones it.
        state.add(R_CI_PRT, "low", f.rel, line_of(text, "pull_request_target"),
                  "pull_request_target checks out pull-request code", "pull_request_target", "config")
    outside = OUTSIDE_TRIGGERS.search(text)
    blocks = script_blocks(text)
    for line, body in blocks:
        m = UNTRUSTED_EXPR.search(body)
        if m:
            state.add(R_CI_INJECTION, "low", f.rel, line, f"{m.group().strip()} is pasted into a script"
                      + (" in a workflow that outsiders can trigger" if outside else ""), body.strip(), "config")
            break
    secrets_json = re.search(r"toJSON\(\s*secrets\s*\)", text, re.I)
    sends = [(line, body) for line, body in blocks if re.search(r"\b(?:curl|wget|Invoke-(?:WebRequest|RestMethod)|iwr|irm|nc)\b", body)
             and classify_host_in(body) in ("raw-ip", "plain-http", "lookalike", "exfil")]
    if secrets_json and not sends:
        # The step may hand the secrets to a repository script that does the posting (WFX Phantom, Nov 2026: a hidden
        # .ci-xxxxxx.sh run from a step named like a cache restore).
        for line, body in blocks:
            run = re.sub(r"^\s*(?:-\s*)?run:\s*[|>]?[-+]?\s*", "", body)
            for ref in exec_refs_in_command(run, "", state.files):
                script = (state.files.get(ref).text or "") if state.files.get(ref) else ""
                if re.search(r"\b(?:curl|wget|Invoke-(?:WebRequest|RestMethod)|iwr|irm|nc)\b", script) and \
                        classify_host_in(script) in ("raw-ip", "plain-http", "lookalike", "exfil"):
                    sends = [(line, script)]
                    break
            if sends:
                break
    if secrets_json:
        sev = "high" if sends else "low"  # on its own, over-sharing secrets with one step (zizmor: overprovisioned-secrets)
        state.add(R_CI_SECRETS, sev, f.rel, line_of(text, secrets_json.group()), "toJSON(secrets) passes every secret "
                  "to one step" + (" and the workflow posts to " + SEND_KIND[classify_host_in(sends[0][1])] if sends else ""),
                  secrets_json.group(), "config")
    elif sends and any("secrets." in body or "printenv" in body or "toJSON(" in body for _l, body in sends):
        line, body = next((l, b) for l, b in sends if "secrets." in b or "printenv" in b or "toJSON(" in b)
        state.add(R_CI_SECRETS, "high", f.rel, line, "a step sends secrets or the environment to a raw-IP, plain-HTTP or "
                  "capture address", body.strip(), "config")
    mem = RUNNER_MEMORY.search(text)
    if mem:
        state.add(R_CI_SECRETS, "critical", f.rel, line_of(text, mem.group()[:40]), "reads the runner's memory for secrets",
                  mem.group(), "config")
    agent = AI_ACTIONS.search(text)
    if agent and outside:
        reasons = []
        if UNTRUSTED_EXPR.search(text):
            reasons.append("untrusted event text reaches the workflow")
        unsafe = AI_ACTION_UNSAFE.search(text)
        if unsafe:
            reasons.append(f"it runs with {unsafe.group()}")
        if reasons:
            state.add(R_CI_AGENT, "low", f.rel, text.count("\n", 0, agent.start()) + 1,
                      f"{agent.group(1)} runs on outsiders' issues or comments: " + "; ".join(reasons), agent.group(1), "config")


def classify_host_in(text: str) -> str:
    """The riskiest kind of destination named on a line: exfil (capture and tunnel services), raw-ip, plain-http..."""
    from ..indicators import EXFIL_HOSTS
    if EXFIL_HOSTS.search(text):
        return "exfil"
    kinds = [classify_host(u) for u in re.findall(r"\b(?:https?|ftp)://[^\s\"'<>`)\]}|]+", text, re.I)]
    for kind in ("raw-ip", "lookalike", "plain-http"):
        if kind in kinds:
            return kind
    return kinds[0] if kinds else ""
