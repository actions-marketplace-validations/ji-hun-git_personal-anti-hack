"""Indicators of attack: judge a step by the steps the session took before it.

One step can look harmless while the sequence is an attack: read ~/.aws/credentials, then a few steps later send a
request to a host nobody has heard of; download a file, then make it executable, then run it. Endpoint products judge
behavior this way (CrowdStrike calls these indicators of attack, Palo Alto's Cortex XDR follows causality chains).
Here the steps are the tool calls an agent makes, as its hooks see them, recorded per session by session.py.

Each step is reduced to tags, and the rules below look for the orders attacks take:

  cred      a credential store read: a key file, a token command (gh auth token, ...); "weak" for .env files,
            secret environment variables and environment dumps
  hunt      a search for secrets across the home folder or the whole disk
  stage     credential folders packed into an archive or encoded
  send      data sent to a host: unknown, raw-ip, exfil (capture or tunnel service), publish (a gist, a repository, a
            package registry, cloud storage) or mcp (an MCP tool that posts, sends or creates)
  fetch     a file downloaded, with the host's kind and where it was saved
  arm       a file made executable or stripped of its downloaded-from-the-internet mark
  run       a file run by its path
  persist   something set to run at login, on a schedule, or on every git or package command
  agentcfg  an agent's settings, hooks or instructions changed
  tamper    the guard or an agent's permission checks switched off
  wipe      shell history or logs cleared
  pkgrun    a package installed or run by name (npx, uvx, pip install <name>): what injected text asks for
  injected  a tool's output carried instructions aimed at the agent (outputs.py)
"""
from __future__ import annotations

import os
import posixpath
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field

from .indicators import EXFIL_HOSTS, SECRET_PATHS, is_private_ip
from .model import rank, rule

R_CRED_SEND = rule(
    "PAH-B001", "Credentials read, then data sent out",
    "The session read a credential store (an SSH key, cloud credentials, a token command) and a later step sends data "
    "to a host that is not a known service. Each step alone can be ordinary; in this order they are how stealers and "
    "prompt-injected agents take keys (s1ngularity asked agents to find and upload secrets).",
    "Do not allow the send until you know what it carries and who receives it. If it already ran, rotate the "
    "credentials that were read.",
    attack=("T1552.001", "T1041"), owasp=("ASI02", "LLM02"),
    refs=("https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/indicators-of-attack-ioa/",
          "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/"))
R_FETCH_RUN = rule(
    "PAH-B002", "Downloaded file made executable or run",
    "A file the session downloaded is now being made executable, unblocked or run. Split across steps, download, "
    "chmod +x and run escape any check that looks at one command at a time.",
    "Check where the file came from and what it is before running it.",
    attack=("T1105", "T1204.002", "T1553.001"),
    refs=("https://www.paloaltonetworks.com/cortex/cortex-xdr",))
R_AFTER_INJECTION = rule(
    "PAH-B003", "Sensitive step after a tool returned injected instructions",
    "Earlier in the session a web page, issue, MCP result or file carried text aimed at the agent. After that the "
    "agent's next sensitive steps (reading credentials, sending data out, changing settings) may be the attacker's, "
    "so the user decides them, as CaMeL and FIDES separate untrusted data from the actions it may cause.",
    "Read the flagged output yourself. Allow the step only if it is what you asked for.",
    attack=("T1059",), owasp=("LLM01", "ASI01"),
    refs=("https://arxiv.org/abs/2503.18813", "https://arxiv.org/abs/2505.23643"))
R_PERSIST_AFTER_FETCH = rule(
    "PAH-B004", "Persistence set up after a download",
    "After downloading from an unknown host, the session now makes something run at login, on a schedule or on every "
    "git or package command: how a one-time payload becomes a lasting foothold.",
    "Read the change before allowing it. Remove it if it already ran.",
    attack=("T1546.004", "T1053", "T1547.001"))
R_TAMPER = rule(
    "PAH-B005", "Agent switching off its guard or permission checks",
    "Disabling hooks, the agent's permission prompts or this guard is what malware does first; an agent should never "
    "do it on its own, least of all after reading untrusted content or downloading files.",
    "Refuse unless you asked for it yourself. Check the agent's settings and `pah watch check`.",
    attack=("T1562.001",), owasp=("ASI03",))
R_WIPE = rule(
    "PAH-B006", "Shell history or logs cleared",
    "Clearing history or logs removes the record of what ran. After credential access or a download it hides an "
    "intrusion.", "Do not allow it. Look at what the session did before this step (`pah session show latest`).",
    attack=("T1070.003", "T1070.001"))
R_CRED_SWEEP = rule(
    "PAH-B007", "Credentials collected from many stores",
    "The session has read or searched several different credential stores (SSH, cloud, registry tokens, browsers, "
    "wallets). Ordinary work needs one; collecting many is what infostealers and the s1ngularity prompt did.",
    "Stop the session and check what it was asked to do.",
    attack=("T1552.001", "T1555"), owasp=("ASI02",))

BEHAVIOR_RULES = (R_CRED_SEND, R_FETCH_RUN, R_AFTER_INJECTION, R_PERSIST_AFTER_FETCH, R_TAMPER, R_WIPE, R_CRED_SWEEP)

UNTRUSTED_SEND = {"unknown", "raw-ip", "lookalike", "plain-http", "exfil"}
TRUSTED_KINDS = {"official", "reference", "local"}

# ------------------------------------------------------------------------------------------------ parsing helpers

_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\r?\n|(?<!\|)\|(?!\|))\s*")
_LEAD = re.compile(r"^(?:\s*(?:sudo(?:\s+-\S+)*|env|nohup|time|exec|command|builtin|&|\(|\{|then|do|else)\s+"
                   r"|\s*[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S*)\s+)+")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`)\]}|;]+", re.I)


def _segments(command: str) -> list[str]:
    """Split a command line at &&, ||, ;, | and newlines that are not inside quotes."""
    parts, buf, quote, i = [], [], "", 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                buf.append(command[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = ""
            buf.append(ch)
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif command.startswith(("&&", "||"), i):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        elif ch in ";|\n":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [s.strip() for s in parts if s.strip()]


def _program(segment: str) -> tuple[str, str]:
    """(program name in lower case without .exe, the rest of the segment)."""
    seg = _LEAD.sub("", segment.strip())
    m = re.match(r"\s*([\"']?)([^\s\"']+)\1\s*(.*)", seg, re.S)
    if not m:
        return "", ""
    prog = m.group(2).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return (prog[:-4] if prog.endswith(".exe") else prog), m.group(3)


def _strip(token: str) -> str:
    return token.strip().strip("\"'`").rstrip(",;)")


def _host_kind(target: str) -> tuple[str, str]:
    """(kind, host) for a URL or a bare host name: official | reference | local | exfil | raw-ip | lookalike |
    plain-http | unknown."""
    from .hosts import classify_host, host_of

    url = target if "://" in target else "https://" + target
    host = host_of(url)
    if not host:
        return "unknown", target[:60]
    if host in ("localhost", "::1") or host.endswith((".localhost", ".local", ".internal", ".lan")) or (
            re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) and is_private_ip(host)):
        return "local", host
    if EXFIL_HOSTS.search(url):
        return "exfil", host
    return classify_host(url), host


_STORES = (
    ("ssh", r"\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys"),
    ("aws", r"\.aws|\baws\s|AWS_SECRET|AWS_SESSION"),
    ("gcloud", r"gcloud|application_default_credentials|GOOGLE_APPLICATION"),
    ("azure", r"\.azure|\baz\s+account"),
    ("kubernetes", r"\.kube|kubectl"),
    ("docker", r"\.docker|docker-credential"),
    ("git", r"git-credentials|git\s+credential|\.netrc"),
    ("github", r"\bgh\s+auth|[\\/]gh[\\/]hosts|GITHUB_TOKEN|GH_TOKEN"),
    ("npm", r"\.npmrc|npm\s+(?:token|config)|NPM_TOKEN|_authToken"),
    ("pypi", r"\.pypirc|PYPI_TOKEN|TWINE_PASSWORD"),
    ("browser", r"Login Data|Cookies|Local State|Web Data|key[34]\.db|logins\.json|Chrome|Firefox|Edge|Brave"),
    ("wallet", r"wallet|Exodus|Electrum|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|mnemonic|seed"),
    ("keychain", r"keychain|security\s+find|cmdkey|vaultcmd|Credential|SecureString|dpapi"),
    ("ai-agent", r"\.claude|\.codex|\.gemini|copilot|\.cline|\.continue|openclaw|state\.vscdb|ANTHROPIC|OPENAI"),
    ("password-manager", r"\bop\s+(?:read|item)|\bbw\s+get|\bpass\s+show|\.kdbx"),
    ("cloud-secrets", r"secretsmanager|secrets\s+versions|\bvault\s"),
)


def store_of(text: str) -> str:
    for name, pattern in _STORES:
        if re.search(pattern, text, re.I):
            return name
    return "other"


# ------------------------------------------------------------------------------------------------ tag patterns

READ_PROG = {"cat", "tac", "type", "more", "less", "head", "tail", "bat", "nl", "od", "xxd", "hexdump", "strings", "base64",
             "base32", "openssl", "gpg", "cp", "copy", "copy-item", "cpi", "scp", "rsync", "tar", "zip", "7z", "7za", "rar",
             "compress-archive", "get-content", "gc", "select-string", "sls", "grep", "egrep", "fgrep", "rg", "awk", "sed",
             "jq", "yq", "sqlite3", "pbcopy", "clip", "set-clipboard", "python", "python3", "py", "node", "perl", "ruby",
             "php", "xargs", "dd", "curl", "wget", "nc", "ncat", "iconv", "sort", "uniq", "cut", "tr", "zcat", "gzip",
             "export", "source", "."}
TOKEN_CMD = re.compile(
    r"\bgh\s+auth\s+(?:token\b|status\b[^\n|;&]*(?:\s-t\b|--show-token))"
    r"|\bgcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity)-token"
    r"|\baz\s+account\s+get-access-token|\baws\s+(?:configure\s+(?:export-credentials|get\s+aws_secret_access_key)"
    r"|sts\s+get-session-token|ecr\s+get-login-password|secretsmanager\s+get-secret-value)"
    r"|\bsecurity\s+find-(?:generic|internet)-password\b|\bcmdkey\s+/list|\bvaultcmd\b|\bgit\s+credential\s+(?:fill|get)\b"
    r"|\bnpm\s+(?:config\s+get\s+[^\n|;&]*_authToken|token\s+list)|\bop\s+(?:read|item\s+get)\b|\bbw\s+get\b|\bpass\s+show\b"
    r"|\bkubectl\s+config\s+view\b[^\n|;&]*--raw|\bdocker-credential-[\w-]+\s+get\b|\bgcloud\s+secrets\s+versions\s+access\b"
    r"|\bvault\s+(?:kv\s+get|read)\b|\bGet-StoredCredential\b|\bConvertFrom-SecureString\b", re.I)
DOTENV = re.compile(r"(?:^|[\s\"'=/\\<])\.env(?:\.(?!example\b|sample\b|template\b|dist\b|defaults?\b|schema\b|test\b)[\w-]+)?"
                    r"(?=$|[\s\"';&|)>])", re.I)
SECRET_VAR = re.compile(r"(?:\becho|\bprintf|\bWrite-(?:Output|Host)|\bprint)\b[^\n|;&]{0,80}\$(?:env:)?\{?[A-Za-z_]*"
                        r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)\b", re.I)
ENV_DUMP_CMD = re.compile(r"(?:^|[;&|(`])\s*(?:printenv|env|set|Get-ChildItem\s+env:|gci\s+env:|dir\s+env:)\s*(?:$|[|>;&])"
                          r"|\[Environment\]::GetEnvironmentVariables\(\)", re.I)
SECRET_DIRS = re.compile(r"(?:~|\$HOME|\$\{HOME\}|\$env:USERPROFILE|%USERPROFILE%)?[/\\]\.(?:ssh|aws|gnupg|kube|docker|azure)"
                         r"(?=[/\\\s\"']|$)|[/\\]\.config[/\\](?:gcloud|gh)\b|AppData[/\\](?:Local|Roaming)[/\\](?:Google[/\\]Chrome"
                         r"|Microsoft[/\\]Edge|BraveSoftware|Mozilla[/\\]Firefox)|Library[/\\](?:Keychains|Application Support"
                         r"[/\\](?:Google[/\\]Chrome|Firefox))", re.I)
HOME_SCOPE = re.compile(r"(?:^|[\s=\"'(])(?:~(?=[/\\\s\"')]|$)|\$HOME\b|\$\{HOME\}|\$env:(?:USERPROFILE|HOMEPATH|HOME)\b"
                        r"|%USERPROFILE%|/home(?=[/\s\"']|$)|/Users(?=[/\s\"']|$)|/root(?=[/\s\"']|$)|[A-Za-z]:[/\\]+Users"
                        r"(?=[/\\\s\"']|$)|/(?=[\s\"']|$)|[A-Za-z]:[/\\]?(?=[\s\"']|$))", re.I)
SEARCH_PROG = {"find", "fd", "locate", "mdfind", "get-childitem", "gci", "dir", "ls", "grep", "egrep", "rg", "ag", "ack",
               "findstr", "select-string", "sls", "tree", "where"}
SECRET_TERMS = re.compile(r"id_rsa|id_ed25519|id_ecdsa|\.pem\b|\*\.key\b|\.p12\b|\.pfx\b|\.kdbx\b|\.ovpn\b|wallet|keystore|"
                          r"keychain|mnemonic|seed[\s._-]?phrase|\.env\b|credentials?\b|secrets?\b|tokens?\b|passwords?\b|passwd|"
                          r"private[_ -]?key|api[_-]?key|AKIA|ghp_|github_pat_|sk-(?:ant|proj|live)|xox[abp]-|"
                          r"BEGIN [A-Z ]*PRIVATE", re.I)
STAGE_PROG = {"tar", "zip", "7z", "7za", "rar", "compress-archive", "gzip", "base64", "openssl", "gpg", "xxd"}
# registry tokens in the home folder (a project's own .npmrc usually holds only a registry address)
HOME_TOKENS = re.compile(r"(?:~|\$HOME|\$\{HOME\}|\$env:USERPROFILE|%USERPROFILE%)[/\\](?:\.npmrc|\.yarnrc(?:\.yml)?"
                         r"|\.config[/\\]pip[/\\]pip\.conf|\.gem[/\\]credentials|\.cargo[/\\]credentials(?:\.toml)?)\b", re.I)
# installing or running a package someone named: what injected text asks for (Agentjacking's npx command)
PKG_RUN = re.compile(r"\b(?:npx|bunx|pnpx)\s+(?:-{1,2}[\w-]+\s+)*(?!-)[@\w./-]+|\b(?:pnpm|yarn)\s+dlx\s+\S+|\buvx\s+\S+"
                     r"|\bpipx\s+run\s+\S+|\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)(?:\s+-{1,2}[\w-]+)*\s+(?!-)[@\w./:-]+"
                     r"|\bpip[0-9.]*\s+install(?:\s+-{1,2}[\w-]+)*\s+(?!-r\b|-e\b|\.)(?!-)[\w.\[\]=<>~!-]+"
                     r"|\bcargo\s+install\s+(?!--path)\S+|\bgo\s+install\s+\S+@|\bgem\s+install\s+\S+", re.I)

PUBLISH = re.compile(
    r"\bgh\s+(?:gist\s+create|repo\s+create|release\s+(?:create|upload)|issue\s+(?:create|comment)|pr\s+(?:create|comment)"
    r"|api\b[^\n|;&]*(?:-X\s*(?:POST|PUT|PATCH)|--method[ =](?:POST|PUT|PATCH)|\s-[fF]\s|--(?:raw-)?field\b|--input\b))"
    r"|\b(?:npm|pnpm|bun)\s+publish\b|\byarn\s+(?:npm\s+)?publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b"
    r"|\bdocker\s+push\b|\b(?:poetry|uv|hatch|flit)\s+publish\b|\bdotnet\s+nuget\s+push\b|\bmvn\b[^\n|;&]*\bdeploy\b"
    r"|\baws\s+s3\s+(?:cp|mv|sync)\s+(?!s3://)\S+\s+s3://|\bgsutil\s+(?:-m\s+)?(?:cp|rsync|mv)\s+(?:-\S+\s+)*(?!gs://)\S+\s+gs://"
    r"|\baz\s+storage\s+blob\s+upload\b|\brclone\s+(?:copy|sync|move)\s+\S+\s+[\w-]+:", re.I)
CURL_SEND = re.compile(r"(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode|-ascii)?|-F|--form(?:-string)?|-T|--upload-file|--json)"
                       r"(?=[\s=@'\"]|$)|(?:^|\s)(?:-X\s*|--request[ =])(?:POST|PUT|PATCH)\b", re.I)
WGET_SEND = re.compile(r"--(?:post|body)-(?:data|file)\b|--method[ =](?:POST|PUT|PATCH)\b", re.I)
PS_SEND = re.compile(r"-Method\s+['\"]?(?:Post|Put|Patch)\b|\s-Body\b|\s-InFile\b", re.I)
# data carried in a URL: a substitution, or a long encoded query value (long documentation paths do not count)
URL_DATA = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_]\w*|%[A-Z_]+%|[?&#][^=&#\s]{0,40}=[A-Za-z0-9+/_%=.-]{64,}")
CODE_SEND = re.compile(r"requests\.(?:post|put|patch)\b|urlopen\([^)]*data\s*=|urllib\.request\.Request\([^)]*data\s*=|"
                       r"http\.client|httpx\.(?:post|put)\b|aiohttp|fetch\([^)]*method\s*:\s*['\"](?:POST|PUT|PATCH)|"
                       r"https?\.request\(|axios\.(?:post|put)\b|socket\.(?:connect|create_connection|send)|"
                       r"net\.(?:connect|createConnection)|Net::HTTP\.post|HTTP::Tiny->new->post|LWP::UserAgent|curl_exec", re.I)
INTERPRETERS = {"python", "python3", "py", "node", "bun", "deno", "perl", "ruby", "php", "pwsh", "powershell"}
DNS_SEND = re.compile(r"^(?:nslookup|dig|host|resolve-dnsname|ping)$")
REMOTE_SPEC = re.compile(r"^(?:[\w.-]+@)?((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}):")
DEV_TCP = re.compile(r"/dev/(?:tcp|udp)/([\w.-]+)/\d+")
MCP_SEND = re.compile(r"(?:^|_)(?:send|post|create|upload|publish|comment|reply|message|email|mail|share|write|push|"
                      r"submit|forward|invite|transfer|tweet|notify)", re.I)

ARM = re.compile(r"\bchmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwxXst]*x[rwxXst]*|0?[0-7]?[1357][0-7][0-7])\s+([^\s;&|]+)"
                 r"|\bUnblock-File\s+(?:-(?:Literal)?Path\s+)?([^\s;&|]+)"
                 r"|\bxattr\s+(?:-r\s+)?-d\s+com\.apple\.quarantine\s+([^\s;&|]+)|\bxattr\s+-c\s+([^\s;&|]+)"
                 r"|\bspctl\s+--add\s+([^\s;&|]+)", re.I)
LAUNCHERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "source", ".", "python", "python3", "py", "node", "bun", "deno",
             "perl", "ruby", "php", "pwsh", "powershell", "cmd", "cscript", "wscript", "mshta", "rundll32", "regsvr32",
             "msiexec", "start-process", "start", "open", "osascript", "java", "invoke-item", "ii", "&"}
PERSIST_CMD = re.compile(
    r"\bcrontab\b(?!\s+-l\b)|\bschtasks(?:\.exe)?\s+/create\b|\breg(?:\.exe)?\s+add\s+[^\n]*\\(?:Run|RunOnce|Winlogon)\b"
    r"|\bNew-ItemProperty\b[^\n]*\\(?:Run|RunOnce)\b|\bSet-ItemProperty\b[^\n]*\\(?:Run|RunOnce)\b|\bRegister-ScheduledTask\b"
    r"|\blaunchctl\s+(?:load|bootstrap|enable|submit)\b|\bsystemctl\s+--user\s+(?:enable|start)\b"
    r"|\bgit\s+config\s+--(?:global|system)\s+(?:core\.(?:hooksPath|sshCommand|pager|fsmonitor)|credential\.helper"
    r"|alias\.[\w-]+\s+[\"']?!)|\bnpm\s+config\s+set\s+(?:script-shell|node-options|init-module)\b"
    r"|\bpip[0-9.]*\s+config\s+set\s+global\.(?:index-url|extra-index-url)\b", re.I)
WRITE_TARGET = re.compile(
    r"(?:>>?|\btee\s+(?:-a\s+)?)\s*[\"']?([^\s\"';&|<>]+)"
    r"|\bsed\s+(?:-\S+\s+)*-i\S*\s+(?:'[^']*'|\"[^\"]*\"|\S+)\s+([^\s;&|]+)"
    r"|\b(?:Set-Content|Add-Content|Out-File|New-Item)\b[^\n|;&]*?\s(?:-(?:Literal)?Path\s+|-FilePath\s+)?[\"']?"
    r"((?:~|\$env:|\$HOME|[A-Za-z]:|\.{0,2}[/\\])[^\s\"';&|]+)", re.I)
COPY_PROG = {"cp", "mv", "install", "ln", "copy-item", "move-item", "cpi", "mi", "copy", "move", "rsync"}
TAMPER_CMD = re.compile(
    r"\bPAH_(?:ASK_FALLBACK|OUTPUT_SCAN|ONLINE|HOME|BEHAVIOR)\s*=|disableAllHooks"
    r"|--dangerously[-_]skip[-_]permissions|--dangerously[-_]bypass[-_]approvals[-_]and[-_]sandbox|--approval-mode[ =]+yolo"
    r"|\b(?:gemini|codex|qwen)\b[^\n|;&]{0,120}--yolo\b"
    r"|\b(?:rm|del|rmdir|rd|Remove-Item|ri|erase)\b[^\n|;&]*(?:\.personal-anti-hack|agent-white-hat|agent-virus-check)"
    r"|\bpip[0-9.]*\s+uninstall\b[^\n|;&]*\b(?:agent-white-hat|agent-virus-check|personal-anti-hack)"
    r"|\bclaude\s+plugin\s+(?:disable|uninstall|remove)\b", re.I)
WIPE_CMD = re.compile(
    r"\bhistory\s+-[cw]\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null|\bexport\s+HISTSIZE=0\b|\bset\s+\+o\s+history\b"
    r"|\b(?:rm|del|Remove-Item|ri|shred|truncate)\b[^\n|;&]*(?:_history\b|ConsoleHost_history|\.zsh_history|\.bash_history)"
    r"|\bClear-History\b|\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|\bClear-EventLog\b|\blog\s+erase\b"
    r"|\bjournalctl\s+--vacuum", re.I)
HF_DOWNLOAD = re.compile(r"\b(?:huggingface-cli|hf)\s+download\s+([\w.-]+/[\w.-]+)", re.I)
_ARG = r"[\"']?([^\s\"';&|]+)"
DOWNLOAD_OUT = {  # where each downloader saves: curl -o (also in -fsSLo), wget -O, PowerShell -OutFile, ...
    "curl": re.compile(r"(?:^|\s)-[A-Za-z]*o\s*" + _ARG + r"|--output[ =]" + _ARG + r"|(?:^|\s)>\s*" + _ARG),
    "wget": re.compile(r"(?:^|\s)-[A-Za-z]*O\s*" + _ARG + r"|--output-document[ =]" + _ARG + r"|(?:^|\s)>\s*" + _ARG),
    "invoke-webrequest": re.compile(r"-OutFile\s+" + _ARG, re.I),
    "start-bitstransfer": re.compile(r"-Destination\s+" + _ARG, re.I),
    "aria2c": re.compile(r"(?:^|\s)-o\s*" + _ARG + r"|--out[ =]" + _ARG),
}
DOWNLOAD_OUT.update({"iwr": DOWNLOAD_OUT["invoke-webrequest"], "irm": DOWNLOAD_OUT["invoke-webrequest"],
                     "invoke-restmethod": DOWNLOAD_OUT["invoke-webrequest"]})


@dataclass
class Act:
    """One step reduced to what matters for chains."""

    kind: str
    tool: str
    text: str = ""
    cwd: str = ""
    tags: dict = field(default_factory=lambda: defaultdict(list))

    def add(self, tag: str, value: str) -> None:
        if value not in self.tags[tag]:
            self.tags[tag].append(value)

    def plain(self) -> dict:
        return {k: v for k, v in self.tags.items() if v}


def _norm_path(path: str, cwd: str) -> str:
    path = _strip(path)
    if not path:
        return ""
    home = os.path.expanduser("~")
    temp = os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp"
    for pat, rep in ((r"^\$HOME|^\$\{HOME\}|^\$env:USERPROFILE|^%USERPROFILE%", home),
                     (r"^\$env:TEMP|^%TEMP%|^\$env:TMP|^%TMP%|^\$TMPDIR", temp)):
        path = re.sub(pat, lambda m, rep=rep: rep.replace("\\", "/"), path, flags=re.I)
    path = os.path.expanduser(path).replace("\\", "/")
    if not re.match(r"^(?:/|[A-Za-z]:/)", path):
        path = posixpath.join((cwd or os.getcwd()).replace("\\", "/"), path)
    path = posixpath.normpath(path)
    return path.lower() if os.name == "nt" or re.match(r"^[A-Za-z]:/", path) else path


def _url_basename(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        name = posixpath.basename(urlsplit(url).path)
    except ValueError:
        return ""
    return name


def _shell(act: Act, command: str, cwd: str) -> None:
    segs = _segments(command)
    progs = []
    for seg in segs:
        prog, rest = _program(seg)
        progs.append(prog)
        _segment(act, seg, prog, rest, cwd, command)
    # credential reads: a key file named next to a program that reads or copies it
    if (SECRET_PATHS.search(command) or SECRET_DIRS.search(command)) and (set(progs) & READ_PROG or re.search(r"<\s*\S", command)):
        for m in SECRET_PATHS.finditer(command):
            if command[m.end():m.end() + 4].lower() == ".pub":
                continue  # a public key is meant to be shared
            act.add("cred", f"{store_of(m.group())}|{m.group()[:60]}")
        for m in SECRET_DIRS.finditer(command):
            after = command[m.end():m.end() + 2]
            if after[:1] in ("/", "\\") and after[1:2] not in ("", " ", "\"", "'"):
                continue  # a file inside the folder: judged by its own name above
            act.add("cred", f"{store_of(m.group())}|{m.group()[:60]}")
    for m in TOKEN_CMD.finditer(command):
        act.add("cred", f"{store_of(m.group())}|{m.group()[:60]}")
    if set(progs) & READ_PROG:
        for m in HOME_TOKENS.finditer(command):
            act.add("cred", f"{store_of(m.group())}|{m.group()[:60]}")
    m = PKG_RUN.search(command)
    if m:
        act.add("pkgrun", m.group()[:60])
    if DOTENV.search(command) and set(progs) & READ_PROG:
        act.add("cred_weak", "env|.env file")
    if SECRET_VAR.search(command):
        act.add("cred_weak", "env|secret environment variable")
    if ENV_DUMP_CMD.search(command):
        act.add("cred_weak", "env|environment dump")
    if PUBLISH.search(command):
        act.add("send", f"publish|{PUBLISH.search(command).group()[:50]}")
    if TAMPER_CMD.search(command):
        act.add("tamper", TAMPER_CMD.search(command).group()[:60])
    else:
        from .guard import SELF_CONTROL

        if SELF_CONTROL.search(command):
            act.add("tamper", SELF_CONTROL.search(command).group()[:60])
    if WIPE_CMD.search(command):
        act.add("wipe", WIPE_CMD.search(command).group()[:60])
    if PERSIST_CMD.search(command):
        act.add("persist", PERSIST_CMD.search(command).group()[:60])
    for m in DEV_TCP.finditer(command):
        kind, host = _host_kind(m.group(1))
        if kind != "local":
            act.add("send", f"{kind}|{host}")


def _segment(act: Act, seg: str, prog: str, rest: str, cwd: str, whole: str) -> None:
    from .guard import GLOBAL_AGENT_FILES, PERSISTENCE_FILES, PROJECT_AGENT_FILES

    seg_urls = _URL.findall(seg)
    # searches for secrets across the home folder or the disk
    if prog in SEARCH_PROG and SECRET_TERMS.search(rest) and HOME_SCOPE.search(" " + rest):
        act.add("hunt", f"{store_of(rest)}|{seg[:60]}")
    if prog in STAGE_PROG and (SECRET_PATHS.search(rest) or SECRET_DIRS.search(rest)):
        act.add("stage", f"{store_of(rest)}|{seg[:60]}")
    # data going out
    sends: list[str] = []
    if prog == "curl" and (CURL_SEND.search(" " + rest) or any(URL_DATA.search(u) for u in seg_urls)):
        sends = seg_urls or ["$URL"]
    elif prog == "wget" and (WGET_SEND.search(rest) or any(URL_DATA.search(u) for u in seg_urls)):
        sends = seg_urls or ["$URL"]
    elif prog in ("invoke-webrequest", "invoke-restmethod", "iwr", "irm") and (PS_SEND.search(" " + rest)
                                                                              or any(URL_DATA.search(u) for u in seg_urls)):
        sends = seg_urls or ["$URL"]
    elif prog in ("http", "https", "xh") and re.search(r"(?:^|\s)(?:POST|PUT|PATCH)\s|(?:^|\s)(?:-f|--form)\b|\s\S+@\S", " " + rest):
        sends = seg_urls or [t for t in rest.split() if "." in t and not t.startswith("-")][:1]
    elif prog in ("nc", "ncat", "netcat", "socat", "telnet"):
        host = next((t for t in rest.split() if not t.startswith("-") and not t.isdigit()), "")
        piped = re.search(r"\|\s*(?:nc|ncat|netcat|socat|telnet)\b", whole) or "<" in seg
        if host and piped:
            sends = [host]
    elif prog in ("scp", "rsync", "sftp"):
        args = [_strip(t) for t in rest.split() if not t.startswith("-")]
        if args and REMOTE_SPEC.match(args[-1]):
            sends = [REMOTE_SPEC.match(args[-1]).group(1)]
        elif args and REMOTE_SPEC.match(args[0]):
            act.add("fetch", f"{_host_kind(REMOTE_SPEC.match(args[0]).group(1))[0]}|{args[0][:60]}|{_norm_path(args[-1], cwd)}")
    elif prog == "ssh" and ("<" in seg or re.search(r"\|\s*ssh\b", whole)):
        host = next((t.split("@")[-1] for t in rest.split() if not t.startswith("-")), "")
        if host:
            sends = [host]
    elif prog in INTERPRETERS and re.search(r"(?:^|\s)(?:-c|-e|-r|eval|-Command)\b", rest) and CODE_SEND.search(rest):
        sends = seg_urls or ["(inline code)"]
    elif DNS_SEND.match(prog) and re.search(r"\$\(|`|\$\{|\$[A-Za-z_]|[A-Za-z0-9+/=_-]{40,}\.", rest):
        sends = ["(DNS lookup carrying data)"]
    elif prog == "git" and re.match(r"push\b", rest):
        args = [_strip(t) for t in rest.split()[1:] if not t.startswith("-")]
        if args and ("://" in args[0] or REMOTE_SPEC.match(args[0])):
            act.add("send", f"publish|git push {args[0][:50]}")
    for target in sends:
        kind, host = _host_kind(target) if target[:1] not in "$(" else ("unknown", target)
        if kind != "local":
            act.add("send", f"{kind}|{host}")
    # downloads, with where they land
    if prog in ("curl", "wget", "invoke-webrequest", "iwr", "irm", "invoke-restmethod", "start-bitstransfer", "certutil",
                "bitsadmin", "aria2c") and seg_urls and not sends:
        pattern = DOWNLOAD_OUT.get(prog)
        out = pattern.search(" " + rest) if pattern else None
        dest = next((g for g in out.groups() if g), "") if out else ""
        if not dest and prog in ("certutil", "bitsadmin"):
            tail = [t for t in rest.split() if not t.startswith(("-", "/")) and "://" not in t]
            dest = tail[-1] if tail else ""
        if not dest and (prog == "wget" or (prog == "curl" and re.search(r"(?:^|\s)-[A-Za-z]*O\b|--remote-name\b", rest))):
            dest = _url_basename(seg_urls[0])
        kind, host = _host_kind(seg_urls[0])
        act.add("fetch", f"{kind}|{host}|{_norm_path(dest, cwd) if dest else ''}")
    hf = HF_DOWNLOAD.search(seg)
    if hf:
        local = re.search(r"--local-dir[ =]([^\s;&|]+)", seg)
        act.add("fetch", f"unknown|huggingface.co/{hf.group(1)}|{_norm_path(local.group(1), cwd) if local else ''}")
    # files made executable, then run
    for m in ARM.finditer(seg):
        path = next(g for g in m.groups() if g)
        act.add("arm", _norm_path(path, cwd))
    target = ""
    if prog and (prog.startswith((".", "/", "~", "$")) or re.match(r"^[a-z]:", prog) or "/" in _LEAD.sub("", seg.strip()).split(" ")[0].replace("\\", "/")):
        first = _LEAD.sub("", seg.strip()).split()[0] if _LEAD.sub("", seg.strip()).split() else ""
        target = first if first not in ("&",) else ""
    elif prog in LAUNCHERS:
        args = [t for t in re.findall(r"\"[^\"]+\"|'[^']+'|\S+", rest)]
        skip = False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-m", "-c", "-e", "-Command", "/c", "-r", "--eval"):
                break  # inline code or a module: no file to match
            if a in ("-jar", "-File", "-FilePath", "/i", "/a", "/s", "-ExecutionPolicy", "-ep"):
                skip = a in ("-ExecutionPolicy", "-ep")
                continue
            if a.startswith("-") or a.startswith("/") and len(a) <= 3:
                continue
            target = a
            break
    target = _strip(target).split(",")[0]  # rundll32 x.dll,Entry runs x.dll
    if target and "://" not in target and (not re.match(r"^[\w.-]+$", target) or prog in LAUNCHERS):
        act.add("run", _norm_path(target, cwd))
    # writes to persistence or agent configuration
    targets = [next(g for g in m.groups() if g) for m in WRITE_TARGET.finditer(seg)]
    if prog in COPY_PROG:
        args = [_strip(t) for t in rest.split() if not t.startswith("-")]
        if len(args) >= 2:
            targets.append(args[-1])
    for t in targets:
        full = _norm_path(t, cwd)
        if not full or full.endswith(("/dev/null", "nul")):
            continue
        shown = t[:80]
        if PERSISTENCE_FILES.search(full) or PERSISTENCE_FILES.search(t):
            act.add("persist", shown)
        if GLOBAL_AGENT_FILES.search(full) or PROJECT_AGENT_FILES.search(t) or PROJECT_AGENT_FILES.search(full):
            act.add("agentcfg", shown)
        if re.search(r"[\\/]\.personal-anti-hack(?:[\\/]|$)", full):
            act.add("tamper", shown)


def tool_name_of(data: dict) -> str:
    for key in ("tool_name", "toolName", "tool"):
        if isinstance(data.get(key), str):
            return data[key]
    for key in ("toolCall", "preToolUse", "tool_call"):
        inner = data.get(key)
        if isinstance(inner, dict):
            return str(inner.get("name") or inner.get("toolName") or "")
    return ""


def act_of(event, tool: str = "") -> Act:
    """Tags for one tool call (an agents.ToolEvent)."""
    from .guard import GLOBAL_AGENT_FILES, HOME, PERSISTENCE_FILES, PROJECT_AGENT_FILES

    act = Act(event.kind, tool or event.kind, cwd=event.cwd)
    if event.kind == "shell":
        act.text = event.command
        _shell(act, event.command, event.cwd)
    elif event.kind == "write":
        act.text = "write " + ", ".join(event.paths)
        for path in event.paths:
            full = _norm_path(path, event.cwd)
            if PERSISTENCE_FILES.search(full) or PERSISTENCE_FILES.search(path):
                act.add("persist", path[:80])
            if GLOBAL_AGENT_FILES.search(full) or PROJECT_AGENT_FILES.search(path) or PROJECT_AGENT_FILES.search(full):
                act.add("agentcfg", path[:80])
            if full.startswith(_norm_path(str(HOME), "")) or "/.personal-anti-hack/" in full + "/":
                act.add("tamper", path[:80])
        if event.content and disables_guard(event.content):
            act.add("tamper", disables_guard(event.content))
    elif event.kind == "read":
        act.text = "read " + ", ".join(event.paths)
        for path in event.paths:
            norm = path.replace("\\", "/")
            if SECRET_PATHS.search(norm) or SECRET_DIRS.search(norm):
                act.add("cred", f"{store_of(norm)}|{path[:60]}")
            elif DOTENV.search(" " + norm):
                act.add("cred_weak", "env|.env file")
    elif event.kind == "fetch":
        act.text = "fetch " + event.url
        if URL_DATA.search(event.url) and re.search(r"[?&#]", event.url):
            kind, host = _host_kind(event.url)
            if kind != "local":
                act.add("send", f"{kind}|{host}")
    elif tool.lower().startswith(("mcp__", "mcp:", "mcp_")):
        act.text = tool
        name = re.split(r"__|:", tool)[-1]
        if MCP_SEND.search(name):
            act.add("send", f"mcp|{tool[:60]}")
    return act


_DISABLES = re.compile(
    r"\"disableAllHooks\"\s*:\s*true|\"defaultMode\"\s*:\s*\"bypassPermissions\""
    r"|\"(?:agent-white-hat|personal-anti-hack|agent-virus-check)(?:@[^\"]*)?\"\s*:\s*false"
    r"|^\s*sandbox_mode\s*=\s*[\"']danger-full-access[\"']|^\s*approval_policy\s*=\s*[\"']never[\"']"
    r"|\"(?:skipDangerousModePermissionPrompt|dangerouslySkipPermissions)\"\s*:\s*true", re.M)


def disables_guard(content: str) -> str:
    """The part of new configuration that turns off hooks, permission prompts or this guard, or ''."""
    m = _DISABLES.search(content[:500_000])
    return m.group().strip()[:80] if m else ""


# ------------------------------------------------------------------------------------------------ the rules


def _values(events: list[dict], *tags: str) -> list[tuple[dict, str, str]]:
    return [(e, tag, v) for e in events for tag in tags for v in e.get("tags", {}).get(tag, [])]


def _step(e: dict) -> str:
    when = time.strftime("%H:%M", time.localtime(e.get("t", 0)))
    return f"{when} {e.get('text', '')[:70]}"


def evaluate(act: Act, history: list[dict]) -> list[tuple[str, str, str]]:
    """(rule, severity, message) for each chain this step completes."""
    live = [e for e in history if e.get("action") != "deny"]
    now = {"tags": act.plain(), "text": act.text, "t": time.time()}
    alerts: list[tuple[str, str, str]] = []
    tags = act.plain()

    strong = _values(live + [now], "cred", "hunt", "stage")
    weak = _values(live + [now], "cred_weak")
    for value in tags.get("send", []):
        kind, _, host = value.partition("|")
        if kind in UNTRUSTED_SEND and strong:
            e, tag, v = strong[0]
            alerts.append((R_CRED_SEND, "high", f"sends data to {host} ({kind} host) after this session read "
                                                f"{v.split('|', 1)[-1]} ({_step(e)}): the order of a credential theft"))
        elif kind in UNTRUSTED_SEND and weak:
            alerts.append((R_CRED_SEND, "medium", f"sends data to {host} ({kind} host) after this session read "
                                                  f"{weak[0][2].split('|', 1)[-1]}"))
        elif kind in ("publish", "mcp") and strong:
            e, tag, v = strong[0]
            alerts.append((R_CRED_SEND, "medium", f"publishes or posts data ({host}) after this session read "
                                                  f"{v.split('|', 1)[-1]} ({_step(e)})"))

    downloads = _values(live + [now], "fetch")
    ran_untrusted_download = False
    for tag in ("run", "arm"):
        for path in tags.get(tag, []):
            for e, _, v in downloads:
                kind, host, dest = (v.split("|") + ["", ""])[:3]
                if not dest or not path:
                    continue
                if dest == path or (posixpath.basename(dest) == posixpath.basename(path) and len(posixpath.basename(path)) > 2):
                    if kind in TRUSTED_KINDS:
                        break  # an official installer saved, then run: the usual way to install a tool
                    sev = "high"
                    ran_untrusted_download = True
                    verb = "runs" if tag == "run" else "makes executable"
                    alerts.append((R_FETCH_RUN, sev, f"{verb} {posixpath.basename(path)}, downloaded from {host} "
                                                     f"({kind} host) earlier in this session ({_step(e)})"))
                    break

    injected = _values(live, "injected")
    if injected:
        top = max(injected, key=lambda x: rank(x[2].split("|", 1)[0] if x[2].split("|", 1)[0] in
                                                ("low", "medium", "high", "critical") else "medium"))
        e, _, v = top
        sev_in, _, source = v.partition("|")
        hard = "high" if sev_in in ("high", "critical") else "medium"
        what = []
        for value in tags.get("send", []):
            kind = value.split("|", 1)[0]
            if kind in UNTRUSTED_SEND:
                what.append((hard, f"sending data to {value.split('|', 1)[-1]}"))
            elif kind in ("publish", "mcp"):
                what.append(("medium", f"posting or publishing ({value.split('|', 1)[-1]})"))
        for tag, label in (("persist", "setting up something that runs on its own"), ("agentcfg", "changing agent settings"),
                           ("tamper", "switching off a guard or permission check")):
            if tags.get(tag):
                what.append((hard, label))
        if ran_untrusted_download:
            what.append((hard, "running a downloaded file"))
        for value in tags.get("fetch", []):
            kind, host, dest = (value.split("|") + ["", ""])[:3]
            if kind not in TRUSTED_KINDS and dest:
                what.append(("medium", f"downloading from {host}"))
        if tags.get("cred") or tags.get("hunt") or tags.get("stage"):
            what.append(("medium", "reading credentials"))
        if tags.get("pkgrun"):
            what.append(("medium", f"installing or running a package ({tags['pkgrun'][0]})"))
        if what:
            sev = "high" if any(s == "high" for s, _ in what) else "medium"
            alerts.append((R_AFTER_INJECTION, sev, f"{', '.join(dict.fromkeys(w for _, w in what))} after {source} "
                                                   f"returned instructions aimed at the agent ({_step(e)})"))

    def saved_untrusted(v: str) -> bool:  # a file saved from a host that is not a known service
        kind, _, dest = (v.split("|") + ["", ""])[:3]
        return kind not in TRUSTED_KINDS and bool(dest)

    if tags.get("persist"):
        risky = [(e, v) for e, _, v in _values(live, "fetch") if saved_untrusted(v)]
        if risky:
            e, v = risky[0]
            alerts.append((R_PERSIST_AFTER_FETCH, "high", f"sets up {tags['persist'][0]} after downloading from "
                                                          f"{v.split('|')[1]} ({_step(e)})"))

    if tags.get("tamper"):
        context = _values(live, "injected", "cred") + [x for x in _values(live, "fetch") if saved_untrusted(x[2])]
        if context:
            alerts.append((R_TAMPER, "high", f"{tags['tamper'][0]} after {_step(context[0][0])}"))
        else:
            alerts.append((R_TAMPER, "medium", f"{tags['tamper'][0]}: only the user should switch off the guard or "
                                               "the agent's permission checks"))

    if tags.get("wipe"):
        context = _values(live, "cred", "stage", "send", "run")
        alerts.append((R_WIPE, "high" if context else "medium",
                       f"{tags['wipe'][0]}" + (f" after {_step(context[0][0])}" if context else "")))

    if tags.get("stage"):
        alerts.append((R_CRED_SWEEP, "medium", f"packs credential folders into one file ({tags['stage'][0].split('|', 1)[-1]}): "
                                               "how stolen keys are gathered before they are sent"))
    if tags.get("cred") or tags.get("hunt"):
        stores = {v.split("|", 1)[0] for _, _, v in _values(live + [now], "cred", "hunt")} - {"other", "env"}
        if len(stores) >= 3:
            alerts.append((R_CRED_SWEEP, "high" if len(stores) >= 5 else "medium",
                           f"this session has now read or searched {len(stores)} credential stores: {', '.join(sorted(stores))}"))
    return alerts


# ------------------------------------------------------------------------------------------------ hook glue


_PATH_TAGS = ("fetch", "arm", "run")  # local paths (and a host name), compared with later steps


def enabled() -> bool:
    return os.environ.get("PAH_BEHAVIOR", "1") != "0"


def observe(agent: str, data: dict, event, decision, tool: str = ""):
    """Judge one step against its session, make the decision stricter where a chain completes, and record the step."""
    if not enabled():
        return decision
    from .session import append, load, mask, session_key

    tool = tool or tool_name_of(data) or event.kind
    key = session_key(agent, data, event.cwd)
    try:
        history = load(key)
    except OSError:
        history = []
    act = act_of(event, tool)
    alerts = evaluate(act, history)
    for rule_id, sev, message in alerts:
        decision.stricter("deny" if rank(sev) >= rank("high") else "ask", f"agent-white-hat ({rule_id}): {message}")
    # Paths that later steps are matched against stay whole: masking would turn a long folder name (macOS keeps the
    # temporary folder under /var/folders/<random>/T/) into "…", and the download would never be matched to its run.
    tags = {k: [x[:500] if k in _PATH_TAGS else mask(x, 120) for x in v] for k, v in act.plain().items()}
    append(key, {"t": round(time.time(), 3), "agent": agent, "tool": tool[:60], "kind": act.kind,
                 "text": mask(act.text), "tags": tags,
                 "action": decision.action, "alerts": [a[0] for a in alerts], "cwd": event.cwd[:300]})
    return decision


def record_output(agent: str, data: dict, tool: str, severity: str, source: str, summary: str, cwd: str = "") -> None:
    """Note in the session that a tool's output carried instructions aimed at the agent."""
    if not enabled():
        return
    from .session import append, mask, session_key

    append(session_key(agent, data, cwd), {
        "t": round(time.time(), 3), "agent": agent, "tool": tool[:60], "kind": "output",
        "text": mask(f"{tool} output: {summary}"), "tags": {"injected": [f"{severity}|{mask(source, 100)}"]},
        "action": "defer", "alerts": [], "cwd": cwd[:300]})
