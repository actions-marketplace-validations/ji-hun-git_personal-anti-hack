#!/usr/bin/env python3
"""Draw the README figures, the social card and the plugin icon from the benchmark results.

Each figure is HTML and CSS set in Instrument Sans and IBM Plex Mono (scripts/fonts, SIL Open Font License), rendered
to PNG at twice its size by headless Chrome or Edge, in light and dark and in English and Korean. The design rules are
in docs/design.md: a case file, where every image shows evidence from bench/results/ and the one bold device is a
highlighter mark on the line that decided an outcome.

    python scripts/make_figures.py                # every figure into docs/figures/
    python scripts/make_figures.py --only hero    # some of: hero how chain results scan repos social icon

hero      the claim, a recorded agent run that was stopped, and the tested numbers
how       how the guard decides: four checks in the order a step meets them, and its three answers
chain     attacks the guard stops only as chains: each step alone, then in one session (bench/chains.py)
results   malicious repositories caught by the rules and by models reading the repository
scan      what `pah scan` prints for one TrapRepo case (made by running the scanner)
repos     the widely used repositories scanned in full for false alarms
social    the 1280 x 640 card for the repository's social preview
icon      the plugin icon, 512 x 512

Every number comes from bench/results/; nothing is typed in by hand except the words around it.
"""
from __future__ import annotations

import base64
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "bench" / "results"
OUT = ROOT / "docs" / "figures"
FONTS = Path(__file__).resolve().parent / "fonts"
WIDTH = 960

THEMES = {
    "light": {"ink": "#13213c", "muted": "#59636e", "faint": "#818b98", "line": "#d1d9e0", "panel": "#f6f8fa",
              "marker": "#ffe45e", "on-marker": "#13213c", "pass": "#12805c", "warn": "#b8800a", "block": "#bb3a32",
              "neutral": "#8c959f", "on-pass": "#ffffff", "on-warn": "#13213c", "on-block": "#ffffff",
              "on-neutral": "#13213c", "accent": "#1b6ac9", "tile": "#13213c", "hat": "#ffffff", "tile-line": "#13213c"},
    "dark": {"ink": "#e6edf3", "muted": "#9198a1", "faint": "#6e7681", "line": "#3d444d", "panel": "#151b23",
             "marker": "#e8c547", "on-marker": "#0d1117", "pass": "#1f9a72", "warn": "#c08a10", "block": "#bb3a32",
             "neutral": "#6e7681", "on-pass": "#0d1117", "on-warn": "#0d1117", "on-block": "#ffffff",
             "on-neutral": "#ffffff", "accent": "#5aa3f0", "tile": "#1d2d4d", "hat": "#ffffff", "tile-line": "#3d4f73"},
}

AGENTS = "Claude Code, Codex, Gemini CLI, Antigravity, Cursor, Copilot, Devin, Kiro, Cline"

STR = {
    "en": {
        "headline": "The antivirus for people who use AI agents.",
        "lede": "It reads what would run before your agent runs it: hooks, skills, MCP servers, install scripts and model "
                "files. Then it stops the steps that add up to an attack.",
        "run_head": "Recorded run: Claude Code {cc}, approvals off, told to set up a project it had just cloned",
        "blocked": "Blocked by agent-white-hat before it ran:",
        "ledger": [("{caught}", "/{malicious}", "malicious test repositories caught"),
                   ("{flagged}", "/{benign}", "benign look-alikes flagged"),
                   ("{chains}", "/{chain_runs}", "attack chains stopped in nine agents"),
                   ("{repos_blocked}", "/{repos}", "widely used repositories blocked")],
        "agents": f"One guard in {AGENTS}.",
        "how_title": "How the guard decides",
        "how_sub": "Every tool call your agent makes meets these checks in this order. The guard only adds restrictions: it "
                   "never answers \u201callow\u201d.",
        "stages": [("The step on its own", "Download-and-run, decode-and-run, credential reads, persistence, approvals "
                                           "switched off, look-alike packages, registry redirects."),
                   ("The project, before setup", "npm install, pip install -e ., pytest, make or loading a model first "
                                                 "gets the folder scanned: hooks, install scripts, skills, MCP servers, "
                                                 "model files."),
                   ("The session so far", "The step is judged with the ones before it: credentials read, then an "
                                          "upload; a download, then chmod +x, then a run."),
                   ("What came back", "Pages, MCP results and files the agent reads are checked for instructions aimed "
                                      "at it. After one, the session's risky steps need you.")],
        "answers": [("block", "\u2715", "Denied", "a high or critical finding"),
                    ("warn", "?", "Asked", "a medium finding; agents that cannot ask deny it"),
                    ("neutral", "\u2013", "Left to your agent", "nothing found")],
        "chain_title": "Harmless one step at a time",
        "chain_sub": "Two attacks from the chain drill, sent to Claude Code's hook: every step alone, then the same steps "
                     "in one session.",
        "alone": "Alone",
        "session": "In one session",
        "verdicts": {"pass": "Allowed", "ask": "Asked", "deny": "Denied"},
        "chains": {"download-chmod-run": "Download, make executable, run",
                   "dns-exfil-after-read": "Read cloud credentials, then leak them in a DNS lookup"},
        "read": "Read",
        "chain_foot": "Across nine agents: {caught} of {runs} attack runs stopped, {only} of them only because of the "
                      "steps before; {extra} of {ordinary} ordinary runs got a prompt the same steps would not get alone.",
        "res_title": "Malicious repositories caught, out of {n}",
        "res_sub": "TrapRepo's first {n} malicious and {b} benign repositories, built from real 2025\u201326 techniques "
                   "with inert payloads. Each model read the repository (up to 100,000 characters) and answered "
                   "\u201csafe\u201d or \u201cunsafe\u201d, {k} runs per case.",
        "legend": ["Caught in every run", "Caught in some runs", "Missed in every run", "Refused, no answer"],
        "res_rules": "rules only, offline",
        "res_model": "the model alone",
        "res_benign": "benign flagged",
        "res_every": "every run",
        "res_any": "in any run",
        "res_of": "{a} of {b}",
        "res_foot": "A refused review is not a clean result: agent-white-hat reports it as \u201cnot reviewed\u201d. Every "
                    "case, run and answer is in bench/results/.",
        "repo_title": "{n} widely used repositories, scanned in full",
        "repo_sub": "{p} pass and {w} warn across {f} files; none blocked. Each warning is worth knowing before an agent "
                    "sets the project up.",
        "groups": ["JavaScript", "Python", "Rust", "AI agents and MCP", "Shell and installers", "Go, Java, containers"],
        "repo_legend": [("pass", "\u2713", "pass"), ("warn", "!", "warn"), ("block", "\u2715", "block")],
        "repo_note": "ruff, the MCP servers and everything-claude-code ship agent hooks; a gemini-cli skill pipes a "
                     "third-party install script into sh.",
        "scan_cmd": "pah scan ./acme-utils",
        "scan_note": "Trimmed: each high or critical finding also prints why it matters and what to do.",
        "social": "The antivirus for people who use AI agents.",
    },
    "ko": {
        "headline": "AI 에이전트를 쓰는 사람을 위한 백신.",
        "lede": "에이전트가 실행하기 전에, 실행될 것을 먼저 읽습니다. 훅, 스킬, MCP 서버, 설치 스크립트, 모델 파일. 그리고 "
                "모이면 공격이 되는 단계를 멈춥니다.",
        "run_head": "실제 실행 기록: 승인을 끈 Claude Code {cc}에게 방금 클론한 프로젝트 설정을 맡김",
        "blocked": "Blocked by agent-white-hat before it ran:",
        "ledger": [("{caught}", "/{malicious}", "악성 함정 레포 탐지"),
                   ("{flagged}", "/{benign}", "정상 레포 오탐"),
                   ("{chains}", "/{chain_runs}", "공격 연쇄 차단, 에이전트 9종"),
                   ("{repos_blocked}", "/{repos}", "널리 쓰이는 레포 차단")],
        "agents": f"하나의 가드로: {AGENTS}.",
        "how_title": "가드가 판단하는 방식",
        "how_sub": "에이전트의 도구 호출은 모두 이 순서로 확인을 거칩니다. 가드는 제한을 더할 뿐, \u201c허용\u201d으로 답하지 "
                   "않습니다.",
        "stages": [("단계 하나만 보고", "다운로드 후 실행, 디코드 후 실행, 자격 증명 읽기, 지속성, 승인 끄기, 비슷한 이름의 "
                                     "패키지, 레지스트리 바꾸기."),
                   ("설치 전에 프로젝트를", "npm install, pip install -e ., pytest, make, 모델 불러오기는 먼저 폴더를 "
                                         "검사합니다: 훅, 설치 스크립트, 스킬, MCP 서버, 모델 파일."),
                   ("지금까지의 세션과 함께", "앞 단계와 함께 판단합니다: 자격 증명을 읽고 업로드, 내려받고 chmod +x, "
                                           "그리고 실행."),
                   ("돌아온 내용을", "에이전트가 읽은 페이지, MCP 결과, 파일에 에이전트를 향한 지시가 있는지 봅니다. 있으면 "
                                   "그 세션의 위험한 단계는 사용자가 정합니다.")],
        "answers": [("block", "\u2715", "거부", "높음·치명 발견"),
                    ("warn", "?", "확인 요청", "중간 발견, 묻지 못하는 에이전트는 거부"),
                    ("neutral", "\u2013", "에이전트 규칙에 맡김", "발견 없음")],
        "chain_title": "한 단계씩 보면 무해한 공격",
        "chain_sub": "공격 연쇄 훈련의 공격 두 개를 Claude Code 훅에 보냈습니다. 단계마다 따로, 그리고 같은 단계를 한 "
                     "세션으로.",
        "alone": "따로",
        "session": "한 세션으로",
        "verdicts": {"pass": "허용", "ask": "확인 요청", "deny": "거부"},
        "chains": {"download-chmod-run": "내려받기, 실행 권한 주기, 실행",
                   "dns-exfil-after-read": "클라우드 자격 증명을 읽고 DNS 조회로 빼내기"},
        "incidents": {"download-chmod-run": "Load/Mine(2026년 9~10월)과 ChainDrop(2026년 8월)의 로더",
                      "dns-exfil-after-read": "Hades PyPI 공격과 여러 npm 탈취 도구가 쓴 DNS 유출(2025~2026년)"},
        "rule_titles": {"PAH-B002": "내려받은 파일에 실행 권한을 주거나 실행",
                        "PAH-B001": "자격 증명을 읽은 뒤 데이터를 밖으로 보냄"},
        "read": "Read",
        "chain_foot": "에이전트 9종 전체: 공격 실행 {runs}개 중 {caught}개 차단, 그중 {only}개는 앞 단계 때문에만 잡혔습니다. "
                      "평범한 실행 {ordinary}개에는 따로 보낼 때 없던 확인이 {extra}번 생겼습니다.",
        "res_title": "악성 레포지토리 탐지, {n}개 중",
        "res_sub": "TrapRepo 첫 악성 {n}개와 정상 {b}개: 2025~26년 실제 기법을 무해한 페이로드로 재현했습니다. 모델은 "
                   "레포지토리를 읽고(최대 100,000자) \u201c안전\u201d 또는 \u201c위험\u201d으로 답했고, 사례마다 {k}번 "
                   "돌렸습니다.",
        "legend": ["매번 탐지", "일부 실행에서 탐지", "매번 놓침", "거절, 답 없음"],
        "res_rules": "규칙만, 오프라인",
        "res_model": "모델만",
        "res_benign": "정상 오탐",
        "res_every": "매번",
        "res_any": "한 번이라도",
        "res_of": "{b}개 중 {a}개",
        "res_foot": "검토 거절은 깨끗하다는 결과가 아닙니다: agent-white-hat은 \u201c검토 안 됨\u201d으로 보고합니다. 모든 "
                    "사례·실행·답은 bench/results/에 있습니다.",
        "repo_title": "널리 쓰이는 레포지토리 {n}개, 통째로 검사",
        "repo_sub": "파일 {f}개에서 통과 {p}, 경고 {w}, 차단 0. 경고는 모두 에이전트에게 설치를 맡기기 전에 알아 둘 만한 "
                    "것입니다.",
        "groups": ["JavaScript", "Python", "Rust", "AI 에이전트·MCP", "셸·설치 스크립트", "Go·Java·컨테이너"],
        "repo_legend": [("pass", "\u2713", "통과"), ("warn", "!", "경고"), ("block", "\u2715", "차단")],
        "repo_note": "ruff, MCP 서버 모음, everything-claude-code는 에이전트 훅을 담고 있고, gemini-cli의 스킬 하나는 "
                     "제3자 설치 스크립트를 sh로 실행합니다.",
        "scan_cmd": "pah scan ./acme-utils",
        "scan_note": "줄임: 높음·치명 발견마다 왜 중요한지와 할 일도 출력합니다.",
        "social": "AI 에이전트를 쓰는 사람을 위한 백신.",
    },
}


# ---------------------------------------------------------------------------------------------------------------- data


def load(name: str) -> dict:
    """The latest dated result of a kind. Model runs are not repeated for every rule change, so each kind carries its
    own date, and comparisons with the models use only the cases the models saw."""
    found = sorted(RESULTS.glob(f"20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-{name}.json"))
    if not found:
        raise FileNotFoundError(f"no dated result for {name} in {RESULTS}")
    return json.loads(found[-1].read_text(encoding="utf-8"))


def numbers() -> dict:
    rules = load("rules")["rows"]
    mal = [r for r in rules if r["kind"] == "malicious" and not r.get("skipped")]
    ben = [r for r in rules if r["kind"] == "benign"]
    repos = load("real-repos")["repos"]
    chains = load("chains")["summary"]
    return {"caught": sum(r["pah"] in ("block", "warn") for r in mal), "malicious": len(mal),
            "flagged": sum(r["pah"] in ("block", "warn") for r in ben), "benign": len(ben),
            "repos": len(repos), "repos_blocked": sum(r["verdict"] == "block" for r in repos),
            "repos_pass": sum(r["verdict"] == "pass" for r in repos), "repos_warn": sum(r["verdict"] == "warn" for r in repos),
            "files": sum(r.get("files", 0) for r in repos),
            "chains": chains["attack_runs_caught"], "chain_runs": chains["attack_runs"],
            "chain_only": chains["caught_only_as_chain"], "ordinary": chains["benign_runs"],
            "extra": chains["benign_runs_with_added_prompts"]}


def recorded_run() -> dict:
    """The hero's log: the first trap run of the pre-command-hook live drill, as recorded."""
    data = load("live-drill-pretool")
    run = next(r for r in data["runs"] if r["kind"] == "malicious" and r["blocked"])
    blocked = run["blocked"][0]
    tool, _, command = blocked["action"].partition(": ")
    reason = blocked["reason"].split(" and blocked running its setup: ", 1)[-1].split(". Show the user", 1)[0]
    findings = []
    for part in reason.split("; "):
        m = re.match(r"(CRITICAL|HIGH|MEDIUM|LOW) (.+)", part.strip())
        if m:
            title, _, detail = m.group(2).partition(": ")
            host = re.search(r"\(to [^)]+\)", detail)
            findings.append((m.group(1), title, host.group(0) if host else detail))
    sentences = re.split(r"(?<=\.) ", run["final"].strip().split("\n")[0])
    prompt = re.split(r"(?<=\.) ", data["prompt"])
    return {"cc": data["claude_code"].rsplit("@", 1)[-1],
            "prompt": prompt[0] + " " + prompt[1].split(" (")[0] + " \u2026", "tool": tool, "command": command,
            "findings": findings, "reply": " ".join(sentences[:2])}


def chain_rows(ids: tuple[str, ...] = ("download-chmod-run", "dns-exfil-after-read"), agent: str = "claude") -> list[dict]:
    """Two chains from the drill, with each step's decision alone and in one session, and the rule that stopped it."""
    sys.path.insert(0, str(ROOT))
    from pah import behavior  # noqa: F401  (registers the chain rules)
    from pah.model import RULES

    fixtures = {c["id"]: c for c in json.loads((ROOT / "bench" / "fixtures" / "drill-chains.json")
                                               .read_text(encoding="utf-8"))["attacks"]}
    results = {(r["chain"], r["agent"]): r for r in load("chains")["rows"]}
    rule_for = {"download-chmod-run": "PAH-B002", "dns-exfil-after-read": "PAH-B001"}
    out = []
    for cid in ids:
        row = results[(cid, agent)]
        steps = [{"do": s["do"], "target": s["target"], "alone": r["alone"], "got": r["got"]}
                 for s, r in zip(fixtures[cid]["steps"], row["steps"], strict=True)]
        out.append({"id": cid, "steps": steps, "rule": rule_for[cid], "title": RULES[rule_for[cid]].title,
                    "incident": fixtures[cid]["incident"]})
    return out


def results_rows() -> tuple[list[dict], int, int, int]:
    models = load("models")
    rules = load("rules")
    seen = {r["id"] for r in models["rows"]}  # the cases the models were given
    mal = [r for r in rules["rows"] if r["kind"] == "malicious" and r["id"] in seen and not r.get("skipped")]
    ben = [r for r in rules["rows"] if r["kind"] == "benign" and r["id"] in seen]
    rows = [{"name": "agent-white-hat", "ours": True, "all": sum(r["pah"] in ("block", "warn") for r in mal), "some": 0,
             "missed": sum(r["pah"] not in ("block", "warn") for r in mal), "refused": 0,
             "false": sum(r["pah"] in ("block", "warn") for r in ben)}]
    mmal = [r for r in models["rows"] if r["kind"] == "malicious"]
    mben = [r for r in models["rows"] if r["kind"] == "benign"]
    names = {"openai:gpt-6-astra": "GPT-6 Astra", "meta:muse-spark-1.3": "Muse Spark 1.3",
             "anthropic:claude-opus-5-5": "Claude Opus 5.5"}
    for spec, name in names.items():
        row = {"name": name, "ours": False, "all": 0, "some": 0, "missed": 0, "refused": 0}
        for r in mmal:
            ts = r["models"][spec]
            k = sum(x["verdict"] == "unsafe" for x in ts)
            key = "all" if k == len(ts) else "some" if k else ("missed" if any(x["verdict"] == "safe" for x in ts)
                                                               else "refused")
            row[key] += 1
        row["false"] = sum(any(x["verdict"] == "unsafe" for x in r["models"][spec]) for r in mben)
        rows.append(row)
    return rows, len(mmal), len(mben), models.get("trials", 3)


def scan_output(lang: str) -> str:
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "bench"))
    import materialize  # bench/materialize.py
    from pah import report
    from pah.scan import scan

    case = json.loads((ROOT / "bench" / "fixtures" / "traprepo" / "claude-settings-sessionstart-hook.json")
                      .read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        target = materialize.materialize(case, Path(tmp) / "acme-utils")
        rep = scan(target)
        rep.target = "./acme-utils"
        rep.stats["seconds"] = round(rep.stats.get("seconds", 0), 1)  # as measured, rounded so the figure is stable
        return report.text(rep, lang=lang, color=True)


REPO_GROUPS = [
    ["expressjs/express", "sindresorhus/got", "typicode/husky", "lovell/sharp", "nodejs/node-addon-examples",
     "puppeteer/puppeteer", "evanw/esbuild", "prettier/prettier", "vitejs/vite"],
    ["psf/requests", "pallets/flask", "fastapi/fastapi", "pytest-dev/pytest", "python-poetry/poetry", "astral-sh/ruff"],
    ["BurntSushi/ripgrep", "serde-rs/serde", "tokio-rs/tokio"],
    ["anthropics/claude-code", "openai/codex", "google-gemini/gemini-cli", "modelcontextprotocol/servers",
     "anthropics/skills", "affaan-m/everything-claude-code"],
    ["ohmyzsh/ohmyzsh", "nvm-sh/nvm", "Homebrew/install"],
    ["cli/cli", "spring-projects/spring-petclinic", "microsoft/vscode-remote-try-node"],
]
REPO_NAMES = {"modelcontextprotocol/servers": "MCP servers", "anthropics/skills": "Anthropic skills",
              "Homebrew/install": "Homebrew install", "cli/cli": "GitHub CLI",
              "affaan-m/everything-claude-code": "everything-claude-code"}


def _k(n: int) -> str:
    return f"{n / 1000:.1f}k".replace(".0k", "k") if n >= 1000 else str(n)


# ----------------------------------------------------------------------------------------------------------- the page

_FONT_CSS: list[str] = []


def font_css() -> str:
    if not _FONT_CSS:
        faces = [("Instrument Sans", 400, "InstrumentSans-Regular.ttf"), ("Instrument Sans", 700, "InstrumentSans-Bold.ttf"),
                 ("IBM Plex Mono", 400, "IBMPlexMono-Regular.ttf"), ("IBM Plex Mono", 700, "IBMPlexMono-Bold.ttf")]
        for family, weight, file in faces:
            data = base64.b64encode((FONTS / file).read_bytes()).decode("ascii")
            _FONT_CSS.append(f'@font-face{{font-family:"{family}";font-weight:{weight};font-style:normal;'
                             f'src:url(data:font/ttf;base64,{data}) format("truetype")}}')
    return "\n".join(_FONT_CSS)


BASE_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:transparent}
body{font-family:"Instrument Sans","Malgun Gothic","Apple SD Gothic Neo","Noto Sans KR",system-ui,sans-serif;color:var(--ink);
  -webkit-font-smoothing:antialiased;font-kerning:normal;text-rendering:geometricPrecision;word-break:keep-all;
  overflow-wrap:break-word}
.mono,code{font-family:"IBM Plex Mono","D2Coding","Malgun Gothic",ui-monospace,monospace}
.fig{padding:30px 34px 34px}
h1,h2,h3{font-weight:700;letter-spacing:-0.012em;text-wrap:balance}
p,.lab{text-wrap:pretty}
h2{font-size:28px;line-height:1.15}
.sub{font-size:16.5px;line-height:1.5;color:var(--muted);margin-top:8px;max-width:840px}
.foot{font-size:14.5px;line-height:1.5;color:var(--muted);margin-top:22px;padding-top:14px;border-top:1px solid var(--line)}
.swatch{display:inline-block;width:12px;height:12px;border-radius:3px;vertical-align:-1px}
.icon{flex:none;display:inline-block;vertical-align:-3px}
"""

MEASURE = ("<script>document.fonts.ready.then(function(){var f=document.querySelector('.fig');"
           "document.body.setAttribute('data-h',Math.ceil(f.getBoundingClientRect().height))})</script>")


def page(theme: str, body: str, css: str, width: int = WIDTH, lang: str = "en") -> str:
    tokens = ";".join(f"--{k}:{v}" for k, v in THEMES[theme].items())
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><style>{font_css()}\n'
            f':root{{{tokens}}}{BASE_CSS}body{{width:{width}px}}{css}</style></head>'
            f'<body>{body}{MEASURE}</body></html>')


def e(s) -> str:
    return html.escape(str(s), quote=False)


def mark(size: int, theme: str = "light", tile: str | None = None, hat: str | None = None) -> str:
    """The white hat on its tile."""
    t = THEMES[theme]
    tile, hat = tile or t["tile"], hat or t["hat"]
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 64 64" aria-hidden="true">'
            f'<rect x="0.5" y="0.5" width="63" height="63" rx="14" fill="{tile}" stroke="{t["tile-line"]}"/>'
            f'<path d="M18.6 47.6 L21.4 25.4 C22.2 20.4 25.6 18.2 29.2 19.4 L32 20.8 L34.8 19.4 C38.4 18.2 41.8 20.4 '
            f'42.6 25.4 L45.4 47.6 Z" fill="{hat}"/>'
            f'<rect x="16" y="36.6" width="32" height="4" fill="{tile}"/>'
            f'<path d="M5.6 41.6 C13.8 45.6 22.8 46.8 32 46.8 C41.2 46.8 50.2 45.6 58.4 41.6 C60.2 40.8 61.4 42.8 59.8 44.2 '
            f'C51.8 50.8 42 53.2 32 53.2 C22 53.2 12.2 50.8 4.2 44.2 C2.6 42.8 3.8 40.8 5.6 41.6 Z" fill="{hat}"/></svg>')


# --------------------------------------------------------------------------------------------------------- the figures

HERO_CSS = """
.brand{display:flex;align-items:center;gap:11px}
.wordmark{font-size:21px;font-weight:700;letter-spacing:-0.01em}
h1{font-size:50px;line-height:1.05;letter-spacing:-0.024em;margin-top:26px;max-width:830px}
:lang(ko) h1{font-size:44px;line-height:1.18;letter-spacing:-0.01em}
.lede{font-size:19px;line-height:1.48;color:var(--muted);margin-top:14px;max-width:780px}
.log{margin-top:26px;border:1px solid var(--line);border-radius:8px;background:var(--panel);overflow:hidden}
.log-head{font-size:14px;color:var(--muted);padding:10px 16px;border-bottom:1px solid var(--line)}
.log-body{padding:13px 16px 15px;font-size:14.5px;line-height:1.66}
.l{padding-left:20px;text-indent:-20px}
.user{color:var(--muted)}
.tool b{font-weight:700}
.hit{margin:2px 0}
.marker{background:var(--marker);color:var(--on-marker);font-weight:700;padding:2px 7px;margin-left:-7px;border-radius:3px;
  -webkit-box-decoration-break:clone;box-decoration-break:clone}
.fd{padding-left:20px}
.sev{display:inline-block;width:62px;font-weight:700}
.sev.HIGH,.sev.CRITICAL{color:var(--block)}
.sev.MEDIUM{color:var(--warn)}
.sev.LOW{color:var(--muted)}
.reply{margin-top:3px}
.ledger{display:grid;grid-template-columns:repeat(4,1fr);margin-top:26px}
.cell{padding:2px 18px 0;border-left:1px solid var(--line)}
.cell:first-child{padding-left:0;border-left:0}
.num{font-size:36px;font-weight:700;letter-spacing:-0.02em;line-height:1}
.num span{font-weight:400;color:var(--muted)}
.lab{font-size:15px;line-height:1.38;color:var(--muted);margin-top:7px}
.agents{font-size:15px;color:var(--muted);margin-top:22px;padding-top:14px;border-top:1px solid var(--line)}
"""


def hero(lang: str, theme: str) -> str:
    s, n, run = STR[lang], numbers(), recorded_run()
    findings = "".join(f'<div class="fd"><span class="sev {e(sev)}">{e(sev)}</span>{e(title)}'
                       f'{" " if detail.startswith("(") else ": "}{e(detail)}</div>' for sev, title, detail in run["findings"])
    ledger = "".join(f'<div class="cell"><div class="num">{e(a.format(**n))}<span>{e(b.format(**n))}</span></div>'
                     f'<div class="lab">{e(label)}</div></div>' for a, b, label in s["ledger"])
    body = f"""<div class="fig">
<div class="brand">{mark(38, theme)}<span class="wordmark">agent-white-hat</span></div>
<h1>{e(s["headline"])}</h1>
<p class="lede">{e(s["lede"])}</p>
<div class="log"><div class="log-head">{e(s["run_head"].format(cc=run["cc"]))}</div>
<div class="log-body mono">
<div class="l user">&rsaquo; {e(run["prompt"])}</div>
<div class="l tool">&#9679; <b>{e(run["tool"])}</b>({e(run["command"])})</div>
<div class="l hit"><span class="marker">&#10005; {e(s["blocked"])}</span></div>
{findings}
<div class="l reply">&#9679; {e(run["reply"])}</div>
</div></div>
<div class="ledger">{ledger}</div>
<div class="agents">{e(s["agents"])}</div>
</div>"""
    return page(theme, body, HERO_CSS, lang=lang)


HOW_CSS = """
.stages{list-style:none;display:grid;grid-template-columns:repeat(4,1fr);gap:0 26px;margin-top:28px}
.stage{position:relative}
.stage:not(:last-child):after{content:"";position:absolute;top:15px;left:39px;right:-18px;height:1px;background:var(--line)}
.n{width:31px;height:31px;border-radius:50%;border:1.5px solid var(--ink);display:flex;align-items:center;
  justify-content:center;font-weight:700;font-size:15px}
.stage h3{font-size:18px;line-height:1.25;margin-top:14px}
.stage p{font-size:15px;line-height:1.5;color:var(--muted);margin-top:7px}
.answers{display:grid;grid-template-columns:repeat(3,1fr);gap:0 26px;margin-top:28px;padding-top:18px;border-top:1px solid var(--line)}
.answer{display:flex;gap:11px;align-items:flex-start}
.answer b{display:block;font-size:16px}
.answer span{display:block;font-size:14.5px;line-height:1.42;color:var(--muted);margin-top:2px}
.answer .icon{margin-top:2px}
"""


ICON_PATHS = {  # drawn on a 20 x 20 grid in the label color
    "\u2715": '<path d="M7 7 L13 13 M13 7 L7 13"/>',
    "\u2713": '<path d="M6 10.4 L8.9 13.2 L14.2 7.2"/>',
    "\u2013": '<path d="M6.5 10 H13.5"/>',
    "!": '<path d="M10 5.8 V11.2"/><circle cx="10" cy="14.2" r="0.6"/>',
    "?": ('<path d="M7.6 7.9 C7.8 6.5 8.8 5.7 10.1 5.7 C11.5 5.7 12.5 6.6 12.5 7.9 C12.5 9.6 10.1 9.8 10.1 11.6"/>'
          '<circle cx="10.1" cy="14.3" r="0.6"/>'),
}


def glyph(kind: str, text: str, size: int = 18, outline: bool = False) -> str:
    """A status icon: a filled circle in the verdict color with its sign, or an outline for a neutral answer."""
    fill, ink = ("none", "var(--muted)") if outline else (f"var(--{kind})", f"var(--on-{kind})")
    ring = ' stroke="var(--neutral)" stroke-width="1.5"' if outline else ""
    sign = ICON_PATHS[text].replace("<circle ", f'<circle fill="{ink}" ')
    return (f'<svg class="icon" width="{size}" height="{size}" viewBox="0 0 20 20" aria-hidden="true">'
            f'<circle cx="10" cy="10" r="{8.9 if outline else 9.6}" fill="{fill}"{ring}/>'
            f'<g fill="none" stroke="{ink}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{sign}</g></svg>')


def how(lang: str, theme: str) -> str:
    s = STR[lang]
    stages = "".join(f'<li class="stage"><div class="n">{i}</div><h3>{e(t)}</h3><p>{e(p)}</p></li>'
                     for i, (t, p) in enumerate(s["stages"], 1))
    answers = "".join(f'<div class="answer">{glyph(kind, g, 20, outline=kind == "neutral")}<div><b>{e(label)}</b>'
                      f'<span>{e(note)}</span></div></div>'
                      for kind, g, label, note in s["answers"])
    body = (f'<div class="fig"><h2>{e(s["how_title"])}</h2><p class="sub">{e(s["how_sub"])}</p>'
            f'<ol class="stages">{stages}</ol><div class="answers">{answers}</div></div>')
    return page(theme, body, HOW_CSS, lang=lang)


CHAIN_CSS = """
.chain{margin-top:26px}
.chain + .chain{margin-top:30px}
.chain-title{font-size:18px;font-weight:700}
.chain-title span{display:block;font-size:14.5px;font-weight:400;color:var(--muted);margin-top:3px}
.grid{display:grid;margin-top:12px;border-top:1px solid var(--line)}
.grid > div{padding:11px 14px 11px 0;border-bottom:1px solid var(--line)}
.rowlab{font-size:14.5px;color:var(--muted);padding-top:13px!important}
.step{display:flex;gap:10px;align-items:flex-start}
.sn{flex:none;width:24px;height:24px;border-radius:50%;border:1.5px solid var(--ink);display:flex;align-items:center;
  justify-content:center;font-size:12.5px;font-weight:700;margin-top:1px}
.step code{font-size:13.5px;line-height:1.5;word-break:normal;overflow-wrap:anywhere}
.step .tool{font-family:"Instrument Sans",sans-serif;font-weight:700;font-size:14px;margin-right:6px}
.v{display:inline-flex;align-items:center;gap:8px;font-size:15px;font-weight:700}
.v.pass{color:var(--muted);font-weight:400}
.why{margin-top:10px;font-size:15px;line-height:1.5}
.why .rule{font-family:"IBM Plex Mono",monospace;font-size:13.5px;font-weight:700;margin-right:8px}
.why .hl{background:var(--marker);color:var(--on-marker);padding:1px 6px;border-radius:3px;font-weight:700}
"""


def verdict(lang: str, got: str) -> str:
    s = STR[lang]
    kind = {"pass": "pass", "ask": "warn", "deny": "block", "flag": "warn"}.get(got, "pass")
    sign = {"pass": "\u2013", "warn": "?", "block": "\u2715"}[kind]
    icon = glyph(kind, sign, 20, outline=kind == "pass")
    return f'<span class="v {kind}">{icon}{e(s["verdicts"].get(got, got))}</span>'


def breakable(cmd: str) -> str:
    """A command that may wrap after / . = | and spaces, never inside a word."""
    return re.sub(r"([/.=|])", r"\1<wbr>", e(cmd))


def chain(lang: str, theme: str) -> str:
    s, n = STR[lang], numbers()
    blocks = []
    for c in chain_rows():
        k = len(c["steps"])
        cols = f"132px repeat({k}, 1fr)"
        cells = ['<div></div>']
        for i, st in enumerate(c["steps"], 1):
            target = st["target"]
            text = (f'<span class="tool">{e(s["read"])}</span><code>{breakable(target)}</code>' if st["do"] == "read"
                    else f'<code>{breakable(target)}</code>')
            cells.append(f'<div class="step"><span class="sn">{i}</span><span>{text}</span></div>')
        cells.append(f'<div class="rowlab">{e(s["alone"])}</div>')
        cells += [f'<div>{verdict(lang, st["alone"])}</div>' for st in c["steps"]]
        cells.append(f'<div class="rowlab">{e(s["session"])}</div>')
        cells += [f'<div>{verdict(lang, st["got"])}</div>' for st in c["steps"]]
        blocks.append(f'<section class="chain"><div class="chain-title">{e(s["chains"][c["id"]])}'
                      f'<span>{e(s.get("incidents", {}).get(c["id"], c["incident"].split(":")[0]))}</span></div>'
                      f'<div class="grid" style="grid-template-columns:{cols}">{"".join(cells)}</div>'
                      f'<div class="why"><span class="rule">{e(c["rule"])}</span>'
                      f'<span class="hl">{e(s.get("rule_titles", {}).get(c["rule"], c["title"]))}</span></div>'
                      f'</section>')
    foot = s["chain_foot"].format(caught=n["chains"], runs=n["chain_runs"], only=n["chain_only"], extra=n["extra"],
                                  ordinary=n["ordinary"])
    body = (f'<div class="fig"><h2>{e(s["chain_title"])}</h2><p class="sub">{e(s["chain_sub"])}</p>'
            f'{"".join(blocks)}<p class="foot">{e(foot)}</p></div>')
    return page(theme, body, CHAIN_CSS, lang=lang)


RESULTS_CSS = """
.legend{display:flex;flex-wrap:wrap;gap:8px 22px;margin-top:20px;font-size:14.5px}
.legend span{display:inline-flex;align-items:center;gap:8px}
.rows{margin-top:18px}
.row{display:grid;grid-template-columns:190px 1fr 132px;gap:0 22px;align-items:center;padding:13px 0;
  border-top:1px solid var(--line)}
.who b{display:block;font-size:17px}
.who span{display:block;font-size:14px;color:var(--muted);margin-top:2px}
.ours .who b{font-size:18px}
.bar{display:flex;gap:2px;height:28px}
.seg{border-radius:4px;display:flex;align-items:center;padding-left:9px;font-size:14px;font-weight:700;min-width:0;
  overflow:visible;white-space:nowrap}
.benign b{display:block;font-size:17px}
.benign span{display:block;font-size:13.5px;color:var(--muted);margin-top:2px}
.colhead{display:grid;grid-template-columns:190px 1fr 132px;gap:0 22px;font-size:13.5px;color:var(--muted);margin-top:14px}
"""


def results(lang: str, theme: str) -> str:
    s = STR[lang]
    rows, n_mal, n_ben, trials = results_rows()
    keys = [("all", "pass"), ("some", "warn"), ("missed", "block"), ("refused", "neutral")]
    legend = "".join(f'<span><span class="swatch" style="background:var(--{kind})"></span>{e(label)}</span>'
                     for (key, kind), label in zip(keys, s["legend"], strict=True))
    bar_px = WIDTH - 68 - 190 - 132 - 44
    out = []
    for r in rows:
        total = sum(r[k] for k, _ in keys) or 1
        segs = []
        for key, kind in keys:
            v = r[key]
            if not v:
                continue
            width = bar_px * v / total
            label = str(v) if width >= 22 else ""
            segs.append(f'<div class="seg" style="flex:{v} 1 0;background:var(--{kind});color:var(--on-{kind})">{label}</div>')
        when = s["res_every"] if r["ours"] else s["res_any"]
        out.append(f'<div class="row{" ours" if r["ours"] else ""}"><div class="who"><b>{e(r["name"])}</b>'
                   f'<span>{e(s["res_rules"] if r["ours"] else s["res_model"])}</span></div>'
                   f'<div class="bar">{"".join(segs)}</div>'
                   f'<div class="benign"><b>{e(s["res_of"].format(a=r["false"], b=n_ben))}</b>'
                   f'<span>{e(s["res_benign"])}, {e(when)}</span></div></div>')
    body = (f'<div class="fig"><h2>{e(s["res_title"].format(n=n_mal))}</h2>'
            f'<p class="sub">{e(s["res_sub"].format(n=n_mal, b=n_ben, k=trials))}</p>'
            f'<div class="legend">{legend}</div><div class="rows">{"".join(out)}</div>'
            f'<p class="foot">{e(s["res_foot"])}</p></div>')
    return page(theme, body, RESULTS_CSS, lang=lang)


SCAN_CSS = """
.term{border:1px solid var(--line);border-radius:8px;background:var(--panel);overflow:hidden}
.term-head{font-size:14px;padding:11px 18px;border-bottom:1px solid var(--line)}
.term-head b{color:var(--pass)}
.term pre{font-family:"IBM Plex Mono","D2Coding","Malgun Gothic",monospace;font-size:13.2px;line-height:1.62;
  padding:14px 18px 18px}
.ln{white-space:pre-wrap;word-break:normal;overflow-wrap:anywhere;min-height:1.62em}
.b{font-weight:700}.d{opacity:.62}
.note{font-size:14.5px;color:var(--muted);margin-top:12px}
"""

ANSI = re.compile(r"\033\[([\d;]*)m")
FG = {"30": "var(--ink)", "31": "var(--block)", "32": "var(--pass)", "33": "var(--warn)", "36": "var(--accent)",
      "37": "var(--ink)", "90": "var(--muted)", "97": "#ffffff"}
BG = {"41": ("var(--block)", "var(--on-block)"), "42": ("var(--pass)", "var(--on-pass)"),
      "43": ("var(--warn)", "var(--on-warn)"), "47": ("var(--neutral)", "var(--on-neutral)")}


def ansi_html(line: str) -> str:
    out, state, pos = [], {"b": False, "d": False, "fg": None, "bg": None}, 0

    def emit(text: str) -> None:
        if not text:
            return
        style, cls = [], []
        if state["bg"]:
            bg, fg = BG[state["bg"]]
            style.append(f"background:{bg};color:{fg};padding:0 4px;border-radius:3px")
        elif state["fg"]:
            style.append(f"color:{FG.get(state['fg'], 'inherit')}")
        if state["b"]:
            cls.append("b")
        if state["d"]:
            cls.append("d")
        attrs = (f' class="{" ".join(cls)}"' if cls else "") + (f' style="{";".join(style)}"' if style else "")
        out.append(f"<span{attrs}>{e(text)}</span>" if attrs else e(text))

    for m in ANSI.finditer(line):
        emit(line[pos:m.start()])
        for code in (m.group(1) or "0").split(";"):
            if code in ("0", ""):
                state = {"b": False, "d": False, "fg": None, "bg": None}
            elif code == "1":
                state["b"] = True
            elif code == "2":
                state["d"] = True
            elif code == "22":
                state["b"] = state["d"] = False
            elif code in FG:
                state["fg"] = code
            elif code in BG:
                state["bg"] = code
            elif code == "39":
                state["fg"] = None
            elif code == "49":
                state["bg"] = None
        pos = m.end()
    emit(line[pos:])
    return "".join(out)


def scan(lang: str, theme: str, raw: str) -> str:
    s = STR[lang]
    lines = [ln for ln in raw.split("\n") if not re.match(r"\s+(Why|Fix|이유|조치): ", ANSI.sub("", ln))]
    while lines and not ANSI.sub("", lines[-1]).strip():
        lines.pop()
    rows = []
    for ln in lines:
        plain = ANSI.sub("", ln)
        indent = len(plain) - len(plain.lstrip(" "))
        hang = indent + (2 if plain.lstrip().startswith(("\u2022", ">")) else 0)
        rows.append(f'<div class="ln" style="padding-left:{hang}ch;text-indent:-{hang}ch">{ansi_html(ln)}</div>')
    pre = "".join(rows)
    body = (f'<div class="fig"><div class="term"><div class="term-head mono"><b>$</b> {e(s["scan_cmd"])}</div>'
            f'<pre>{pre}</pre></div><p class="note">{e(s["scan_note"])}</p></div>')
    return page(theme, body, SCAN_CSS, lang=lang)


REPOS_CSS = """
.groups{margin-top:22px;border-top:1px solid var(--line)}
.g{display:grid;grid-template-columns:178px 1fr;gap:0 18px;padding:12px 0;border-bottom:1px solid var(--line)}
.gl{font-size:15px;font-weight:700;padding-top:2px}
.items{display:flex;flex-wrap:wrap;gap:8px 20px}
.it{display:inline-flex;align-items:center;gap:7px;font-size:15.5px;white-space:nowrap}
.it em{font-style:normal;font-size:13.5px;color:var(--muted)}
.legend{display:flex;gap:22px;margin-top:16px;font-size:14.5px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:7px}
.note{display:flex;gap:10px;margin-top:12px;font-size:15px;line-height:1.5}
.note .icon{margin-top:2px}
"""


def repos(lang: str, theme: str) -> str:
    s, n = STR[lang], numbers()
    data = {r["repo"]: r for r in load("real-repos")["repos"]}
    signs = {"pass": "\u2713", "warn": "!", "block": "\u2715"}
    rows = []
    for label, group in zip(s["groups"], REPO_GROUPS, strict=True):
        items = []
        for repo in group:
            r = data[repo]
            name = REPO_NAMES.get(repo, repo.split("/")[1])
            items.append(f'<span class="it">{glyph(r["verdict"], signs[r["verdict"]])}{e(name)}'
                         f'<em>{e(_k(r.get("files", 0)))}</em></span>')
        rows.append(f'<div class="g"><div class="gl">{e(label)}</div><div class="items">{"".join(items)}</div></div>')
    legend = "".join(f'<span>{glyph(kind, g)}{e(label)}</span>' for kind, g, label in s["repo_legend"])
    files = f"{n['files']:,}"
    body = (f'<div class="fig"><h2>{e(s["repo_title"].format(n=n["repos"]))}</h2>'
            f'<p class="sub">{e(s["repo_sub"].format(p=n["repos_pass"], w=n["repos_warn"], f=files))}</p>'
            f'<div class="groups">{"".join(rows)}</div><div class="legend">{legend}</div>'
            f'<p class="note">{glyph("warn", "!")}<span>{e(s["repo_note"])}</span></p></div>')
    return page(theme, body, REPOS_CSS, lang=lang)


SOCIAL_CSS = """
body{width:1280px;height:640px;background:#13213c;color:#ffffff}
.fig{width:1280px;height:640px;padding:72px 84px;display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:16px}
.wordmark{font-size:30px;font-weight:700;letter-spacing:-0.01em}
h1{font-size:68px;line-height:1.04;letter-spacing:-0.026em;margin-top:40px;max-width:980px}
.ledger{display:grid;grid-template-columns:repeat(4,auto);justify-content:start;gap:0 0;margin-top:auto}
.cell{padding:0 44px;border-left:1px solid #3d4f73}
.cell:first-child{padding-left:0;border-left:0}
.num{font-size:44px;font-weight:700;letter-spacing:-0.02em;line-height:1}
.num span{font-weight:400;color:#9aa8c2}
.lab{font-size:19px;color:#b9c4d8;margin-top:10px;max-width:220px;line-height:1.3}
.evidence{margin-top:34px;font-family:"IBM Plex Mono",monospace;font-size:24px;line-height:1.6;color:#b9c4d8}
.evidence .marker{background:#ffe45e;color:#13213c;font-weight:700;padding:3px 10px;margin-left:-10px;border-radius:4px}
"""


def social() -> str:
    s, n = STR["en"], numbers()
    ledger = "".join(f'<div class="cell"><div class="num">{e(a.format(**n))}<span>{e(b.format(**n))}</span></div>'
                     f'<div class="lab">{e(label)}</div></div>' for a, b, label in s["ledger"])
    body = (f'<div class="fig"><div class="brand">{mark(60, "light", tile="#13213c", hat="#ffffff")}'
            f'<span class="wordmark">agent-white-hat</span></div><h1>{e(s["social"])}</h1>'
            f'<div class="evidence"><div>&#9679; npm install</div><div><span class="marker">&#10005; '
            f'{e(s["blocked"].rstrip(":"))}</span></div></div><div class="ledger">{ledger}</div></div>')
    return page("light", body, SOCIAL_CSS, width=1280)


def icon() -> str:
    body = f'<div class="fig" style="padding:0;width:512px;height:512px">{mark(512, "light", tile="#13213c")}</div>'
    return page("light", body, "body{width:512px;height:512px}", width=512)


# ------------------------------------------------------------------------------------------------------- rendering


def browser() -> str | None:
    for c in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome", "chromium", "msedge"):
        if Path(c).exists() or shutil.which(c):
            return c
    return None


def render(doc: str, dest: Path, width: int, height: int | None = None, transparent: bool = True, scale: int = 2) -> None:
    exe = browser()
    if not exe:
        raise SystemExit("make_figures.py needs Chrome or Edge to render the figures")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "figure.html"
        src.write_text(doc, encoding="utf-8")
        base = [exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run", "--disable-extensions",
                f"--user-data-dir={Path(tmp) / 'profile'}", "--virtual-time-budget=4000"]
        if height is None:
            dom = subprocess.run(base + ["--dump-dom", src.as_uri()], capture_output=True, timeout=180)
            m = re.search(rb'data-h="(\d+)"', dom.stdout)
            if not m:
                raise SystemExit(f"could not measure {dest.name}: {dom.stderr.decode(errors='replace')[-400:]}")
            height = int(m.group(1))
        args = base + [f"--force-device-scale-factor={scale}", f"--window-size={width},{height}", f"--screenshot={dest}"]
        if transparent:
            args.append("--default-background-color=00000000")
        subprocess.run(args + [src.as_uri()], check=True, capture_output=True, timeout=180)


FIGURES = ("hero", "how", "chain", "results", "scan", "repos")


def main(argv: list[str]) -> int:
    only = set(argv[argv.index("--only") + 1:]) if "--only" in argv else None
    OUT.mkdir(parents=True, exist_ok=True)
    written = []
    for lang in STR:
        raw = scan_output(lang) if not only or "scan" in only else ""
        for theme in THEMES:
            for name in FIGURES:
                if only and name not in only:
                    continue
                doc = {"hero": hero, "how": how, "chain": chain, "results": results, "repos": repos}.get(name)
                doc = doc(lang, theme) if doc else scan(lang, theme, raw)
                dest = OUT / f"{name}-{lang}-{theme}.png"
                render(doc, dest, WIDTH)
                written.append(dest)
    if not only or "social" in only:
        render(social(), OUT / "social-preview.png", 1280, 640, transparent=False, scale=1)
        written.append(OUT / "social-preview.png")
    if not only or "icon" in only:
        dest = ROOT / ".claude-plugin" / "icon.png"
        render(icon(), dest, 512, 512, transparent=True, scale=1)
        written.append(dest)
    for p in written:
        print(p.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
