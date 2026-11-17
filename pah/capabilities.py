"""What a file can do, as capabilities: network requests, sending data, starting programs, running code built at run
time, reading credentials or the whole environment, persistence, writing agent configuration, decoding, obfuscation,
crypto wallets, compiled code and install-time hooks.

A list of findings says what looks malicious; capabilities say what the code is able to do, whether or not a rule
describes it yet. Comparing them between two versions is how compromised updates are caught (Chainguard's malcontent
diff): a patch release whose install script suddenly reads credentials and talks to the network deserves a look even
before any rule fires. diff.py uses this module; the patterns come from the rules, so both agree on what they see.
"""
from __future__ import annotations

import json
import posixpath
import re

from .campaigns import CODE_SINK, PROCESS_SINK, WALLET_FORMAT, WALLET_LITERAL
from .indicators import SECRET_PATHS, WRITE_OP
from .patterns import AGENT_CONFIG, ENV_DUMP, JSFUCK, NETWORK, OBF_SIGNATURE, PACKER, PERSIST, SEND_DATA

CAPABILITIES = {
    "install-time": "runs when the package is installed or built",
    "network": "makes network requests",
    "sends-data": "sends data out",
    "process": "starts other programs",
    "dynamic-code": "runs code it builds at run time",
    "credentials": "reads credential files or tokens",
    "environment": "collects the whole environment",
    "persistence": "makes itself start again",
    "agent-config": "writes AI-agent configuration",
    "decoding": "decodes hidden data",
    "obfuscation": "is obfuscated",
    "wallet": "handles crypto wallet addresses",
    "native-code": "is a compiled program",
}
# Capabilities that matter when code that runs on its own gains them.
RISKY = frozenset(CAPABILITIES) - {"install-time", "native-code"}

CODE_EXT = (".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish",
            ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".rb", ".pl", ".php", ".lua", ".go", ".rs", ".java", ".kt", ".cs",
            ".swift", ".c", ".cc", ".cpp", ".h", ".gyp", ".gypi", ".pth")
CODE_NAMES = ("makefile", "gnumakefile", "dockerfile", "rakefile", "justfile", "build.rs", "setup.py", "conftest.py",
              "extconf.rb")
SHELLISH = (".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", "makefile", "gnumakefile", "justfile",
            "dockerfile")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
NATIVE_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf")

SHELL_NET = re.compile(r"(?<![\w./-])(?:curl|wget|nc|ncat)(?![\w.-])|\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
                       r"|\bNet\.WebClient\b", re.I)
DECODING = re.compile(r"\batob\s*\(|Buffer\.from\s*\([^)]{0,200}['\"](?:base64|hex)['\"]|\bb64decode\b"
                      r"|\bbase64\s+(?:-d|--decode)\b|\bzlib\.(?:decompress|inflate\w*)|\bmarshal\.loads\b"
                      r"|FromBase64String|\bString\.fromCharCode\s*\(|\bbytes\.fromhex\s*\(|\bcodecs\.decode\s*\(")
TOKENS = re.compile(r"\b(?:NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN"
                    r"|ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY|PYPI_TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN)\b"
                    r"|_authToken\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b|\.netrc\b|\.claude\.json\b"
                    r"|\.codex[\\/]auth\.json|\bwallet\.dat\b|security\s+find-(?:generic|internet)-password|\bkeytar\b")
CHECKS = (("network", NETWORK), ("sends-data", SEND_DATA), ("process", PROCESS_SINK), ("dynamic-code", CODE_SINK),
          ("credentials", SECRET_PATHS), ("credentials", TOKENS), ("environment", ENV_DUMP), ("persistence", PERSIST),
          ("decoding", DECODING), ("obfuscation", OBF_SIGNATURE), ("obfuscation", PACKER), ("obfuscation", JSFUCK),
          ("wallet", WALLET_LITERAL), ("wallet", WALLET_FORMAT))


def _snippet(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start:end if end >= 0 else len(text)].strip()
    return line if len(line) <= 120 else line[:119] + "…"


def is_code(rel: str) -> bool:
    low = rel.lower()
    return low.endswith(CODE_EXT) or posixpath.basename(low) in CODE_NAMES


def _install_time(rel: str, text: str) -> str | None:
    name = posixpath.basename(rel.lower())
    if name == "package.json":
        try:
            scripts = json.loads(text).get("scripts") or {}
        except (ValueError, AttributeError):
            return None
        hooks = [f"{k}: {v}" for k, v in scripts.items() if k in LIFECYCLE and isinstance(v, str)]
        return "; ".join(hooks) if hooks else None
    if name == "setup.py":
        return "setup.py runs when the package is built or installed from source"
    if name == "binding.gyp" and "<!" in text:
        return "binding.gyp runs commands while the package is built"
    if name.endswith(".pth") and re.search(r"(?m)^\s*import\s", text):
        return ".pth file with an import line, run at every Python start"
    if name in ("sitecustomize.py", "usercustomize.py"):
        return f"{name} runs at every Python start"
    if name == "build.rs":
        return "build.rs runs when the crate is built"
    if name == "extconf.rb":
        return "extconf.rb runs when the gem is installed (native extension)"
    if name.endswith(".gemspec") and re.search(r"\.extensions\s*(?:=|<<|\+=)", text):
        return "the gemspec builds native extensions at install"
    return None


DEPENDENCY_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")


def dependencies(rel: str, text: str | None) -> set[str]:
    """Dependency names a manifest declares (package.json, Cargo.toml, requirements*.txt, *.gemspec)."""
    if text is None:
        return set()
    name = posixpath.basename(rel.lower())
    if name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return set()
        return {k for sec in DEPENDENCY_SECTIONS for k in (data.get(sec) or {}) if isinstance(data.get(sec), dict)}
    if name == "cargo.toml":
        out, inside = set(), False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                inside = bool(re.match(r"\[(?:target\.[^\]]+\.)?(?:build-)?dependencies\]", s))
            elif inside and re.match(r"[A-Za-z0-9_-]+\s*=", s):
                out.add(s.split("=", 1)[0].strip())
        return out
    if re.match(r"requirements[^/]*\.txt$", name):
        return {m.group(1).lower() for m in re.finditer(r"(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", text)}
    if name.endswith(".gemspec"):
        return set(re.findall(r"add_(?:runtime_)?dependency\s*\(?\s*['\"]([^'\"]+)['\"]", text))
    return set()


def of_file(rel: str, data: bytes, text: str | None) -> dict[str, str]:
    """Capabilities of one file, each with the first line that shows it."""
    if text is None:
        return {"native-code": "compiled program"} if data[:4].startswith(NATIVE_MAGIC) else {}
    caps: dict[str, str] = {}
    hook = _install_time(rel, text)
    if hook:
        caps["install-time"] = hook
    if not is_code(rel):
        return caps
    low = rel.lower()
    checks = CHECKS + ((("network", SHELL_NET),) if low.endswith(SHELLISH) or posixpath.basename(low) in SHELLISH else ())
    for cap, rx in checks:
        if cap not in caps:
            m = rx.search(text)
            if m:
                caps[cap] = _snippet(text, m.start())
    if "agent-config" not in caps:
        m = AGENT_CONFIG.search(text)
        if m and WRITE_OP.search(text):
            caps["agent-config"] = _snippet(text, m.start())
    return caps
