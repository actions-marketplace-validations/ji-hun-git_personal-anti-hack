"""Environment variables set by a repository that redirect an agent's API traffic, inject code into processes
or relocate an agent's configuration.
"""
from __future__ import annotations

import re

from ..hosts import host_of
from ..model import rank
from .rules import R_BASE_URL
from .base import File, State, line_of


OFFICIAL_API_HOSTS = ("api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "api.meta.ai",
                      "localhost", "127.0.0.1")


REDIRECT_ENV = re.compile(r"^(?:ANTHROPIC_(?:BASE_URL|API_URL|BEDROCK_BASE_URL|VERTEX_BASE_URL|FOUNDRY_BASE_URL)|"
                          r"OPENAI_(?:BASE_URL|API_BASE)|GOOGLE_GEMINI_BASE_URL|GEMINI_BASE_URL|CODEX_BASE_URL|OLLAMA_HOST|"
                          r"(?:AZURE_OPENAI|OPENROUTER|GROQ|MISTRAL|DEEPSEEK|XAI|TOGETHER|FIREWORKS|PERPLEXITY|COHERE|"
                          r"LITELLM|CLAUDE_CODE|COPILOT|CURSOR|AIDER|LLM)_(?:BASE_URL|API_BASE|API_URL|ENDPOINT|HOST))$", re.I)


SECRET_ENV = re.compile(r"^(?:ANTHROPIC_(?:API_KEY|AUTH_TOKEN)|OPENAI_API_KEY|GEMINI_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)$", re.I)


INJECT_ENV = re.compile(r"^(?:NODE_OPTIONS|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|HTTPS?_PROXY|ALL_PROXY|"
                        r"PYTHONSTARTUP|PYTHONPATH|LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|PROMPT_COMMAND|"
                        r"GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS|CODEX_HOME|CLAUDE_CONFIG_DIR|GEMINI_CLI_HOME|"
                        r"GEMINI_SYSTEM_MD|QWEN_HOME)$", re.I)


RELOCATING_ENV = ("CODEX_HOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "CLAUDE_CONFIG_DIR", "GEMINI_CLI_HOME", "QWEN_HOME")


def repo_first_on_path(value: str) -> bool:
    """PATH whose first entry is inside the project: its bin/git runs whenever the agent calls git (Datadog, Aug 2026)."""
    first = re.split(r"[:;]", value.strip(), maxsplit=1)[0].strip("\"'")
    if re.search(r"CLAUDE_PROJECT_DIR|workspaceFolder|\$PWD|\$\{PWD\}", first):
        return True
    return bool(first) and not first.startswith(("/", "$", "~", "%")) and not re.match(r"[A-Za-z]:[\\/]", first)


def check_env(state: State, env: dict, f: File, origin: str, cap: str | None = None) -> None:
    """Variables that redirect an agent's API traffic, hand it someone else's key, or inject code into its process.
    cap limits the severity (a .env below the repository root is read only by tools started in that folder)."""
    add = state.add if cap is None else (lambda rule_id, sev, *a, **k: state.add(rule_id, sev if rank(sev) <= rank(cap)
                                                                                 else cap, *a, **k))
    for key, value in env.items():
        value = str(value)
        line = line_of(f.text or "", key)
        if key.upper() == "PATH":
            if repo_first_on_path(value):
                add(R_BASE_URL, "high", f.rel, line, f"{origin} puts a folder of the repository first on PATH: {value}",
                    f"PATH={value}")
            continue
        if REDIRECT_ENV.match(key):
            host = host_of(value) if "://" in value else value.split(":")[0]
            if host and host not in OFFICIAL_API_HOSTS and not host.endswith((".anthropic.com", ".openai.com")) \
                    and not value.startswith("$"):
                add(R_BASE_URL, "critical", f.rel, line, f"{origin} sets {key}={value}", f"{key}={value}")
        elif SECRET_ENV.match(key):
            add(R_BASE_URL, "high", f.rel, line, f"{origin} supplies its own {key} (your session would run "
                "under someone else's account, which can read it)", key)
        elif INJECT_ENV.match(key):
            sev = "critical" if key.upper() in RELOCATING_ENV \
                or (key.upper() == "NODE_OPTIONS" and re.search(r"(?:--require|-r|--import|--loader)\b", value)) else "high"
            add(R_BASE_URL, sev, f.rel, line, f"{origin} sets {key}={value}", f"{key}={value}")
