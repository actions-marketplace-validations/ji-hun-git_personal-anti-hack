"""Files agents read and follow: AGENTS.md, CLAUDE.md, rules files, setup documents and skills. Commands they
ask for are analyzed like commands an agent is about to run; skill shell lines and pre-approved tools are
surfaces of their own.
"""
from __future__ import annotations

import posixpath
import re

from ..content_rules import R_AGENT_CFG_WRITE, R_DOWNLOAD_EXEC
from ..hosts import host_kind
from ..model import bump, rank
from ..names import R_LOOKALIKE, lookalike, lookalike_severity, names_in_command, normalize, popular
from ..patterns import HOST_NOTE, analyze_command
from ..policy import is_test_code
from ..text import Lines
from .rules import R_INSTRUCTION, R_SKILL_FETCH, R_SKILL_SHELL, R_UNPINNED_RUN
from .base import File, State, exec_refs_in_command, line_of


AUTO_LOADED = re.compile(
    r"(?:^|/)(?:AGENTS(?:\.override)?\.md|CLAUDE(?:\.local)?\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|"
    r"\.roorules|CONVENTIONS\.md|SKILL\.md|SOUL\.md|copilot-instructions\.md)$"
    r"|(?:^|/)\.cursor/rules/.*\.mdc?$|(?:^|/)\.github/(?:instructions|prompts)/.*\.md$|(?:^|/)\.claude/(?:agents|commands|skills)/.*\.md$"
    r"|(?:^|/)\.gemini/commands/.*\.toml$|(?:^|/)\.windsurf/rules/.*\.md$|(?:^|/)\.clinerules/(?!hooks/).*$|(?:^|/)\.roo/rules[^/]*/.*\.md$"
    r"|(?:^|/)\.amazonq/rules/.*\.md$|(?:^|/)\.kiro/steering/.*\.md$|(?:^|/)\.junie/guidelines\.md$"
    r"|(?:^|/)\.claude/(?:rules|output-styles)/.*\.md$|(?:^|/)\.(?:agents|devin|augment)/rules/.*\.md$|(?:^|/)\.augment/SYSTEM\.md$"
    r"|(?:^|/)\.github/(?:agents/.*\.agent|chatmodes/.*\.chatmode)\.md$|(?:^|/)\.factory/droids/.*\.md$|(?:^|/)\.kiro/agents/.*\.md$"
    r"|(?:^|/)(?:\.goosehints|WARP\.md|AGENT\.md)$", re.I)


SETUP_DOC = re.compile(r"(?:^|/)(?:README|INSTALL|SETUP|CONTRIBUTING|GETTING[-_]STARTED|QUICKSTART|DEVELOPMENT|BUILDING)"
                       r"(?:\.[a-z]+)?$|(?:^|/)docs?/.*(?:install|setup|getting[-_]started|quickstart).*\.md$", re.I)


IMPERATIVES = [
    (re.compile(r"\b(?:update|change|modify|edit|overwrite|rewrite|add\s+(?:the\s+following\s+|this\s+|these\s+lines\s+)?to)\s+"
                r"(?:your|the\s+agent'?s?|its)\s+(?:own\s+)?(?:global\s+|user\s+)?(?:settings|config(?:uration)?|settings\.json|"
                r"config\.toml|preferences|mcp\s+servers?|hooks)", re.I), "high", "tells the agent to change its own settings"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|\$CODEX_HOME)[\\/](?:\.(?:claude|codex|gemini|cursor|openclaw|copilot|kiro)[\\/])?"
                r"(?:settings(?:\.local)?\.json|config\.toml|hooks\.json|mcp(?:_config)?\.json|auth\.json|\.credentials\.json|"
                r"openclaw\.json)\b|\.claude\.json\b"), "medium", "points the agent at its machine-wide configuration"),
    # Naming the file is how skills document "add this MCP server to ~/.claude.json"; telling the agent to rewrite its
    # own settings, switch off approvals or move its API traffic is what the attacks do, and those stay high.
    # Naming ANTHROPIC_BASE_URL in documentation is not an instruction; setting it to a host that is not the provider's is.
    (re.compile(r"\b(?:ANTHROPIC|OPENAI|GEMINI|GOOGLE_GEMINI|CODEX|AZURE_OPENAI|OPENROUTER)_(?:BASE_URL|API_BASE|API_URL)\b"
                r"[\"'`]?\s*(?:=|:|\bto\b)\s*[\"'`]?https?://(?!(?:api\.anthropic\.com|api\.openai\.com|generativelanguage\."
                r"googleapis\.com|localhost|127\.0\.0\.1)\b)[\w.-]+"
                r"|\bCODEX_HOME\s*=\s*[\"']?(?!~?/?\.codex\b)[\w./~$-]+", re.I),
     "high", "changes where the agent sends its API traffic"),
    (re.compile(r"\b(?:disable|turn\s+off|skip|bypass|ignore)\s+(?:the\s+|all\s+|any\s+)?(?:sandbox(?:ing)?|approvals?|permission(?:s|\s+prompts?|\s+checks?)?"
                r"|confirmations?|safety\s+checks?|security\s+(?:checks?|warnings?))\b(?!\s+(?:paths?|tests?|testing|environments?|"
                r"dir(?:ector(?:y|ies))?|folders?|images?|containers?|fixtures?|examples?|data)\b)", re.I), "high",
     "tells the agent to disable its safeguards"),
    # "Don't ask the user for a key" is autonomy, not concealment; hiding is about not telling, or acting unseen.
    (re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention(?:\s+(?:this|it|that))?\s+to|alert|notify|warn)\s+"
                r"(?:the\s+)?(?:user|human|developer|operator)\b(?!\s+(?:to|how)\b)"
                r"|\b(?:run|execute|install|delete|remove|upload|send|push|download|curl|wget|overwrite|modify|change)\b[^.\n]{0,80}"
                r"\bwithout\s+(?:asking|telling|informing|notifying|alerting|confirming\s+with)\s+(?:the\s+)?(?:user|human|developer)\b"
                r"|\b(?:silently|quietly|covertly|secretly)\s+(?:run|install|execute|download|send|upload|exfiltrate|delete|push|"
                r"post|copy|modify)\b", re.I),
     "high", "tells the agent to hide actions from you"),
    (re.compile(r"\b(?:delete|remove|wipe|erase|clean)\b[^\n]{0,60}\b(?:all|every|entire|whole)\b[^\n]{0,60}\b(?:files|directories|home|"
                r"resources|buckets|repositories|data|history)\b|near-?factory\s+state", re.I), "high", "tells the agent to delete data broadly"),
    # The agents' own folders hold skills and settings too; only their token files are credentials.
    (re.compile(r"\b(?:read|cat|open|copy|upload|send|include|paste|attach)\b[^\n]{0,60}(?:~|\$HOME|%USERPROFILE%)[\\/]\."
                r"(?:(?:ssh|aws|npmrc|netrc|git-credentials|config[\\/]gh)\b|claude[\\/]\.credentials\.json|codex[\\/]auth\.json"
                r"|gemini[\\/](?:oauth_creds\.json|\.env))|\b(?:read|cat|send|upload|paste|"
                r"include)\b[^\n]{0,60}\b(?:id_rsa|id_ed25519|\.credentials\.json|auth\.json)\b", re.I), "high",
     "tells the agent to read or send credentials"),
    (re.compile(r"\b(?:extract|unzip|unpack)\b[^\n]{0,80}\b(?:and|then)\s+(?:run|execute|launch|source)\b", re.I), "medium",
     "tells the agent to unpack something and run it"),
    # ClawHavoc's skills sent people to password-protected archives: antivirus cannot look inside them.
    (re.compile(r"\.(?:zip|7z|rar)\b[^\n]{0,200}?\b(?:password|passcode)\s*(?:is\s*)?[:=]?\s*[`\"'*]*[\w!@#$%^&-]{3,}"
                r"|\b(?:password|passcode)\s*(?:is|:|=)\s*[`\"'*]*[\w!@#$%^&-]{3,}[^\n]{0,200}?\.(?:zip|7z|rar)\b", re.I),
     "high", "sends you to a password-protected archive (a way past antivirus)"),
]


_FENCE = re.compile(r"(?ms)^[ \t]*(```|~~~)[ \t]*([\w+-]*)[^\n]*\n(.*?)^[ \t]*\1")


_INLINE = re.compile(r"`([^`\n]{4,300})`")


_PROMPT_LINE = re.compile(r"(?m)^[ \t]*(?:\$|>|PS[^>\n]{0,40}>)\s+(.+)$")


_SHELLY = re.compile(r"^\s*(?:sudo\s+)?(?:(?:curl|wget|npm|npx|pnpm|yarn|bun|bunx|pip[0-9.]*|uv|uvx|pipx|poetry|cargo|go|gem|brew|"
                     r"apt|powershell|pwsh|iwr|irm|iex|mshta|bash|sh|zsh|python[0-9.]*|node|deno|docker|git|chmod|xattr|export|"
                     r"set|setx|claude|codex|gemini|cursor-agent|openclaw|make)(?=\s|$)|\./)", re.I)


def commands_in_markdown(text: str) -> list[tuple[int, str]]:
    """(line, command) for shell-like commands in fenced blocks, prompt lines and inline code."""
    out = []
    for m in _FENCE.finditer(text):
        lang = m.group(2).lower()
        if lang and lang not in ("sh", "bash", "shell", "zsh", "console", "terminal", "powershell", "ps1", "pwsh", "cmd",
                                 "bat", "shellsession", "text", "txt"):
            continue
        start = text.count("\n", 0, m.start(3)) + 1
        body = re.sub(r"\\\n\s*", " ", m.group(3))
        for i, line in enumerate(body.splitlines()):
            line = re.sub(r"^\s*(?:\$|>|PS[^>]{0,40}>)\s+", "", line)
            if line.strip() and not line.lstrip().startswith("#"):
                out.append((start + i, line.strip()))
    for m in _PROMPT_LINE.finditer(text):
        out.append((text.count("\n", 0, m.start()) + 1, m.group(1).strip()))
    for m in _INLINE.finditer(text):
        if _SHELLY.match(m.group(1)):
            out.append((text.count("\n", 0, m.start()) + 1, m.group(1).strip()))
    return out


_NEGATION = re.compile(r"\b(?:never|not|don'?t|doesn'?t|won'?t|cannot|can'?t|mustn'?t|shouldn'?t|avoid|refuse\s+to|no\s+longer"
                       r"|rather\s+than|instead\s+of)\b", re.I)


_AFFIRMATIVE = re.compile(r"\b(?:never|don'?t|do\s+not)\s+(?:forget|fail|hesitate|neglect|omit)\b", re.I)


_RESUMES = re.compile(r"\b(?:always|then|but|instead|however|must|should|please|now|first|and\s+also)\b", re.I)


def _negated(text: str, pos: int) -> bool:
    """True when the matched instruction is forbidden in its own sentence ("Never A, B or disable the sandbox"), but not
    for "never forget to disable the sandbox" or "never run untrusted code, then disable the sandbox", which are orders."""
    start = max(text.rfind(c, 0, pos) for c in ".!?\n:;")
    before = text[start + 1:pos]
    negations = list(_NEGATION.finditer(before))
    if not negations or _AFFIRMATIVE.search(before):
        return False
    return not _RESUMES.search(before[negations[-1].end():])


_QUOTED = re.compile(r"\"[^\"\n]{1,300}\"|“[^”\n]{1,300}”")


def _quoted_example(text: str, start: int, end: int) -> bool:
    """The phrase sits inside double quotes on its line: an example of what an attacker writes ("skip approval"),
    which documentation quotes to warn about it, not an instruction."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line = text[line_start:line_end if line_end >= 0 else len(text)]
    return any(q.start() <= start - line_start and end - line_start <= q.end() for q in _QUOTED.finditer(line))


def instructions(state: State, f: File, auto_loaded: bool) -> None:
    """Instruction files agents load automatically, and setup docs people and agents follow."""
    text = f.text or ""
    lines = Lines(text)
    if auto_loaded:
        state.doc_auto.add(f.rel)
    seen = set()
    for line, cmd in commands_in_markdown(text):
        if (line, cmd) in seen:
            continue
        seen.add((line, cmd))
        for ref in exec_refs_in_command(cmd, f.dir, state.files) + exec_refs_in_command(cmd, "", state.files):
            if not auto_loaded and is_test_code(ref):
                continue  # "run the tests: node tests/x.test.js" in a setup document is development, not setup
            state.mark_autoexec(ref, f"run by the instructions in {f.rel}", source=f.rel)
        unpinned = unpinned_runner(cmd)
        if unpinned:
            # A name nobody has registered yet is a slopsquat waiting to happen; a well-known package is a pinning nit.
            sev = "medium" if auto_loaded and not well_known(*unpinned) else "low"
            state.add(R_UNPINNED_RUN, sev, f.rel, line, f"runs {unpinned[1]} without a pinned version", cmd, "doc")
        for finding in analyze_command(cmd, f.rel, line, "doc"):
            # Commands that edit the agent's own configuration are what config-maintenance skills do, shown to you
            # as tool calls; install-time code doing the same is judged as critical elsewhere.
            if auto_loaded and rank(finding.severity) >= rank("medium") and finding.rule != R_AGENT_CFG_WRITE:
                finding.severity = bump(finding.severity)
                finding.message += " (in a file agents load automatically)"
            elif auto_loaded and finding.rule == R_DOWNLOAD_EXEC and finding.severity == "low":
                finding.severity = "medium"
                finding.message += " (in a file agents load automatically)"
            state.findings.append(finding)
        for eco, name in names_in_command(cmd):
            state.packages.append((eco, name, f.rel, line, "doc"))
            hit = lookalike(name, eco)
            if hit:
                state.add(R_LOOKALIKE, lookalike_severity(hit[1], "auto-doc" if auto_loaded else "doc"), f.rel, line,
                          f"{name} ({eco}) {hit[1]} from {hit[0]}", cmd, "doc")
    for pattern, sev, message in IMPERATIVES:
        for m in pattern.finditer(text):
            if _negated(text, m.start()) or _quoted_example(text, m.start(), m.end()):
                continue
            state.add(R_INSTRUCTION, sev if auto_loaded else "low", f.rel, lines.line(m.start()),
                      message + ("" if auto_loaded else " (setup document)"), text[max(0, m.start() - 60):m.end() + 80], "doc")
            break
    if f.name.upper() == "SKILL.MD" or re.search(r"(?:^|/)(?:\.claude/)?commands/[^/]+\.md$", f.rel):
        skill_shell(state, f)
    if f.name.upper() == "SKILL.MD":
        skill(state, f)


SKILL_SHELL = re.compile(r"(?<![`\w])!`([^`\n]{2,400})`")


ALLOWED_TOOLS = re.compile(r"(?mi)^allowed[-_]tools\s*:\s*(.*(?:\n[ \t]*-[^\n]*)*)")


UNRESTRICTED_BASH = re.compile(r"(?:^|[\s,\[\"'-])Bash(?:\(\s*(?:\*|\*\s*:\s*\*|:\s*\*)?\s*\))?(?=$|[\s,\]\"'])", re.M)


def frontmatter(text: str) -> str:
    text = text.lstrip(chr(0xFEFF))  # a byte-order mark before the opening ---
    m = re.match(r"---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|$)", text, re.S)
    return m.group(1) if m else ""


def skill_shell(state: State, f: File) -> None:
    """Shell lines (!`command`) in skills and slash commands run when they are invoked, before the model reads them,
    and `allowed-tools: Bash` lets every shell command through without a prompt while the skill is active."""
    text = f.text or ""
    allowed = ALLOWED_TOOLS.search(frontmatter(text))
    if allowed and UNRESTRICTED_BASH.search(allowed.group(1)):
        state.add(R_SKILL_SHELL, "medium", f.rel, line_of(text, allowed.group(0).split("\n")[0]),
                  "allowed-tools pre-approves every shell command while it is active", allowed.group(0).strip()[:120], "doc")
    fences = [(m.start(), m.end()) for m in _FENCE.finditer(text)]
    for m in SKILL_SHELL.finditer(text):
        if any(a <= m.start() < b for a, b in fences):
            continue
        state.command(m.group(1), f.rel, text.count("\n", 0, m.start()) + 1, "shell line in a skill or command",
                      "invoking the skill or command, before the model reads it", base_dir=f.dir,
                      floor=(R_SKILL_SHELL, "low"))


_UNPINNED = re.compile(r"\b(?P<npm>npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx)\s+(?P<npmargs>[^|;&\n]*)|\buvx\s+(?P<uvargs>[^|;&\n]*)"
                       r"|\bpipx\s+run\s+(?P<pipxargs>[^|;&\n]*)")


_RUNNER_FLAGS_WITH_VALUE = {"-p", "--package", "--from", "--with", "--python", "-c", "--call", "--spec", "--index-url"}


KNOWN_SCOPES = ("@anthropic-ai/", "@modelcontextprotocol/", "@openai/", "@google/", "@google-cloud/", "@microsoft/",
                "@azure/", "@aws-sdk/", "@playwright/", "@vercel/", "@cloudflare/", "@github/", "@octokit/", "@angular/",
                "@vue/", "@nestjs/", "@babel/", "@types/", "@eslint/", "@typescript-eslint/", "@biomejs/", "@sentry/",
                "@supabase/", "@stripe/", "@shopify/", "@nx/", "@storybook/", "@tanstack/", "@prisma/", "@redis/")


def unpinned_runner(cmd: str) -> tuple[str, str] | None:
    """(ecosystem, package) for npx/uvx/pipx runs of a package with no exact version, or None."""
    m = _UNPINNED.search(cmd)
    if not m:
        return None
    eco = "npm" if m.group("npm") else "pypi"
    args = (m.group("npmargs") or m.group("uvargs") or m.group("pipxargs") or "").split()
    skip = False
    for tok in args:
        tok = tok.strip("\"'`")
        if skip:
            skip = False
            if re.match(r"(?:\.{0,2}/|~|[A-Za-z]:[\\/]|https?:|git\+|file:)", tok):
                return None  # --from ./src/tool, --package git+https://...: not a bare registry name
            continue
        if tok.startswith("-"):
            skip = tok in _RUNNER_FLAGS_WITH_VALUE
            continue
        if re.match(r"(?:\.{0,2}/|~|[A-Za-z]:[\\/]|https?:|git\+|file:)", tok) or "$" in tok:
            return None  # a local path or a URL, not a registry package
        name, _, version = tok[1:].partition("@") if tok.startswith("@") else tok.partition("@")
        name = ("@" + name) if tok.startswith("@") else name
        if eco == "pypi":
            name, _, version = tok.partition("==")
        if version and re.match(r"\d", version):
            return None
        return (eco, name) if re.fullmatch(r"@?[\w.-]+(?:/[\w.-]+)?", name) else None
    return None


def well_known(eco: str, name: str) -> bool:
    """A popular package or one under a vendor's npm scope: it exists, so it cannot be a slopsquat."""
    return name.startswith(KNOWN_SCOPES) or normalize(name, eco) in popular(eco)


SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".bat", ".cmd", ".rb", ".pl")


_DOC_LINK = re.compile(r"\]\(\s*<?([^)\s>#]+\.(?:md|markdown|txt))|`([\w./-]+\.(?:md|markdown|txt))`"
                       r"|(?<![\w./-])([\w./-]+\.(?:md|markdown))\b", re.I)
_FOLLOW = re.compile(r"\b(?:follow|run|execute|install|set\s*up|setup|bootstrap|first\s+use|before\s+(?:first\s+)?"
                     r"us(?:e|ing)|prerequisites?|must\s+(?:first|complete)|initiali[sz]e)\b", re.I)


def _linked_docs(state: State, f: File) -> list[str]:
    """Documents of the same skill that SKILL.md tells the agent to follow: "before first use, follow
    setup-installation.md". The agent carries them out as part of the skill (the Paperclip skill clones, Aug 2026,
    kept SKILL.md clean and put the loader there). References the skill only points to ("the checklist is in
    references/rotation.md") are not followed."""
    base = f.dir
    text = f.text or ""
    out: list[str] = []
    for m in _DOC_LINK.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        anchor = text.rfind("[", start, m.start()) if text[m.start()] == "]" else m.start()  # before the link's text
        anchor = m.start() if anchor < 0 else anchor
        if not _FOLLOW.search(text[max(start, anchor - 80):anchor]):  # "follow [setup.md]", not a mention
            continue
        ref = next(g for g in m.groups() if g)
        rel = posixpath.normpath(posixpath.join(base, ref)) if base else posixpath.normpath(ref)
        if rel != f.rel and rel in state.files and state.files[rel].text and (not base or rel.startswith(base + "/")) \
                and rel not in out:
            out.append(rel)
    return out[:20]


def skill(state: State, f: File) -> None:
    base = f.dir
    state.surface("Agent Skill", f.rel, "loaded by the agent when the skill applies")
    for ref in _linked_docs(state, f):
        # Read like a setup document: what it tells the agent to run is analyzed, and a dangerous command there is
        # still high, but reference pages do not carry the weight of a file the agent loads on its own.
        instructions(state, state.files[ref], auto_loaded=False)
    prefix = base + "/" if base else ""
    for rel in state.files:
        if rel.startswith(prefix) and rel.count("/") - prefix.count("/") <= 2 and rel.lower().endswith(SCRIPT_SUFFIXES) \
                and not is_test_code(rel):  # a skill's own test suite is not one of its steps
            state.mark_autoexec(rel, f"script bundled with the skill {f.rel}")
    text = f.text or ""
    for m in re.finditer(r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest)\b[^\n]{0,200}?https?://\S+[^\n]{0,120}?"
                         r"(?:\.(?:zip|dmg|pkg|exe|bin|tar\.gz|tgz|sh|ps1)\b|[|]\s*(?:ba|z)?sh\b)", text, re.I):
        kind = host_kind(m.group(0))
        if kind == "official":
            continue
        # A skill is followed by the agent without a second look; a vendor's own installer is fine, a script from
        # someone's GitHub account is worth asking about, a look-alike domain or plain HTTP is not acceptable.
        sev = "high" if kind in ("risky", "plain-http") else "medium"
        state.add(R_SKILL_FETCH, sev, f.rel, text.count("\n", 0, m.start()) + 1, "skill downloads and runs a file"
                  + HOST_NOTE[kind], m.group(0), "doc")
        break
