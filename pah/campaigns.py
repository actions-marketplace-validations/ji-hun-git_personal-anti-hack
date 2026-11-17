"""Shapes of named campaigns that single rules miss: blockchain dead drops, worms that republish packages with
stolen tokens, CI backdoors, wipers armed by token revocation, wallet hijackers, hidden processes, secret
sweeps at install time and payloads read out of image pixels."""
from __future__ import annotations

import re

from .codectx import first_near, has
from .collector import Collector
from .content_rules import (R_CI_BACKDOOR, R_DEAD_DROP, R_DEADMAN, R_DECODE_EXEC, R_HIDDEN_PROC, R_NET_AUTO, R_SWEEP,
                            R_WALLET, R_WORM)
from .indicators import WRITE_OP


# Shapes of 2025-2026 campaigns that need two pieces of evidence near each other in one file.
DEAD_DROP = re.compile(
    r"\beth_(?:call|getTransactionByHash|getTransactionReceipt|getStorageAt|getLogs)\b|\bgetSignaturesForAddress\b"
    r"|\bgetConfirmedSignaturesForAddress2\b|api\.trongrid\.io|bsc-dataseed|\b(?:etherscan|bscscan|polygonscan|arbiscan)\."
    r"(?:io|com)/api|api\.mainnet-beta\.solana\.com|\bjsonkeeper\.com|\bjsonsilo\.com|\bapi\.npoint\.io|\bapi\.jsonbin\.io"
    r"|\bcalendar\.app\.google|api\.github\.com/search/(?:commits|issues|code)", re.I)


DEAD_DROP_NEED = ("eth_", "getsignatures", "getconfirmedsignatures", "trongrid", "bsc-dataseed", "scan.io/api",
                  "scan.com/api", "solana.com", "jsonkeeper", "jsonsilo", "npoint", "jsonbin", "calendar.app.google",
                  "api.github.com/search")


CODE_SINK = re.compile(r"(?<![.\w$])(?:exec|eval)\s*\(\s*(?!['\"`)])|\bnew\s+Function\s*\((?!\s*['\"]return this)"
                       r"|\bvm\.run\w*\s*\(|\bexec\s*\(\s*compile\s*\(")


PROCESS_SINK = re.compile(r"\bchild_process\b|\bexecSync\s*\(|\bspawn(?:Sync)?\s*\(|\bsubprocess\.\w+\s*\(|\bos\.system\s*\(")


PUBLISH = re.compile(r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|upload\.pypi\.org/legacy", re.I)


REGISTRY_TOKEN = re.compile(r"_authToken|\bNPM_TOKEN\b|\bNODE_AUTH_TOKEN\b|\.npmrc\b|\.pypirc\b|\bPYPI_TOKEN\b|\bTWINE_PASSWORD\b", re.I)


WORM_EXTRA = re.compile(r"/-/whoami\b|/-/v1/search\?text=maintainer|\bmaintainer:\$?\{?[\w.]|/-/user/|\bnpm\s+owner\s+ls\b"
                        r"|\bnpm\s+access\s+(?:ls-packages|list\s+packages)\b", re.I)


WORKFLOW_PATH = re.compile(r"\.github[\\/]workflows[\\/][^\s\"'`]*\.ya?ml", re.I)


RUNNER_SETUP = re.compile(r"\bconfig\.(?:sh|cmd)\b[^\n]{0,200}--url\s+\S*github\.com[^\n]{0,200}--token\b|\bRUNNER_ALLOW_RUNASROOT\b"
                          r"|actions-runner-(?:linux|osx|win)-[\w.-]+\.(?:tar\.gz|zip)", re.I)


TOKEN_CHECK = re.compile(r"api\.github\.com/user\b|/-/whoami\b|\bgh\s+auth\s+status\b", re.I)


WIPE_HOME = re.compile(r"\brm\s+-[a-z]*[rR][a-z]*\s+(?:-[a-z]+\s+)*[\"']?(?:~|\$HOME|\$\{HOME\})|rmSync\([^)]{0,80}(?:homedir|HOME)"
                       r"|\b(?:shutil\.)?rmtree\([^)]{0,80}(?:home|expanduser)|\bshred\s+-|\bcipher(?:\.exe)?\s+/w\b"
                       r"|Remove-Item[^\n]{0,80}(?:\$HOME|USERPROFILE)[^\n]{0,80}-Recurse|\bfs\.(?:promises\.)?rm\([^)]{0,80}(?:homedir|HOME)", re.I)


TOKEN_FAILED = re.compile(r"\b40[13]\b|status(?:Code)?\s*!==?\s*200|!\s*[\w.]+\.ok\b|\.ok\s*===?\s*false|\bnot\s+[\w.]+\.ok\b", re.I)


FETCH_HOOK = re.compile(r"\b(?:window|globalThis|self)\.fetch\s*=(?!=)|XMLHttpRequest\.prototype\.(?:open|send)\s*=(?!=)"
                        r"|\bethereum\.request\s*=(?!=)", re.I)


WALLET_FORMAT = re.compile(r"0x\[(?:a-fA-F0-9|0-9a-fA-F|a-f0-9|0-9a-f)\]\{40\}|\bbc1\[|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|T\[A-Za-z1-9\]\{33\}")


WALLET_LITERAL = re.compile(r"['\"]0x[a-fA-F0-9]{40}['\"]")


HIDDEN_PROCESS = re.compile(
    r"detached\s*:\s*true[\s\S]{0,200}?stdio\s*:\s*['\"]ignore['\"]|stdio\s*:\s*['\"]ignore['\"][\s\S]{0,200}?detached\s*:\s*true"
    r"|windowsHide\s*:\s*true[\s\S]{0,200}?detached\s*:\s*true|detached\s*:\s*true[\s\S]{0,200}?windowsHide\s*:\s*true"
    r"|creationflags\s*=\s*[^\n]{0,80}(?:CREATE_NO_WINDOW|DETACHED_PROCESS|0x0*8000000\b)"
    r"|start_new_session\s*=\s*True[\s\S]{0,200}?DEVNULL|DEVNULL[\s\S]{0,200}?start_new_session\s*=\s*True"
    r"|\bnohup\b[^\n]{0,200}>\s*/dev/null\s+2>&1\s*&|\bspawn\(\s*(?:['\"]node['\"]|process\.execPath)\s*,\s*\[\s*['\"]-i['\"]"
    r"|Start-Process[^\n]{0,200}-WindowStyle\s+Hidden", re.I)


SECRET_SWEEP = re.compile(r"\btrufflehog\b|\bgitleaks\b|169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal"
                          r"|\bListSecrets\b|\bGetSecretValue\b|secretmanager\.googleapis\.com|vault\.azure\.net", re.I)


PIXEL_READ = re.compile(r"\bJimp\.read\b|\bgetPixelColou?r\b|\bsharp\([^)]*\)[\s\S]{0,80}?\.raw\(|\bPNG\.sync\.read\b"
                        r"|\bImage\.open\([^)]*\)[\s\S]{0,80}?\.getdata\(|\.getpixel\(", re.I)


RUNTIME_BOOTSTRAP = re.compile(r"bun\.sh/install|oven-sh/bun/releases|deno\.land/(?:x/)?install|denoland/deno/releases", re.I)


def campaign_shapes(col: Collector, text: str, context: str, low: str, live, nets: list[int]) -> None:
    """Dead drops, worms, CI backdoors, dead-man switches, wallet hijackers, hidden processes and secret sweeps."""
    auto = context == "autoexec"
    if has(low, DEAD_DROP_NEED):
        drops = [m.start() for m in live(DEAD_DROP.finditer(text), 20)]
        sinks = [m.start() for m in live(CODE_SINK.finditer(text), 50)]
        if auto:
            sinks += [m.start() for m in live(PROCESS_SINK.finditer(text), 50)]
        hit = first_near(drops, sinks, 3000) if drops and sinks else None
        if hit is not None:
            col.add(R_DEAD_DROP, "critical" if auto else "high", hit, "reads a blockchain, paste-site or search result "
                    "and executes code next to it", context)
    if has(low, ("publish", "twine", "upload.pypi")):
        pub = next(iter(live(PUBLISH.finditer(text), 1)), None)
        token = next(iter(live(REGISTRY_TOKEN.finditer(text), 1)), None) if pub else None
        extra = next(iter(live(WORM_EXTRA.finditer(text), 1)), None) if token else None
        if pub and token and (auto or extra):
            col.add(R_WORM, "critical" if auto and extra else "high", pub.start(), "publishes packages with the registry "
                    "token it finds" + (" after listing the packages you maintain" if extra else ""), context)
    if auto and has(low, (".github", "runner")):
        for m in live(WORKFLOW_PATH.finditer(text), 20):
            start = text.rfind("\n", 0, text.rfind("\n", 0, m.start())) + 1
            stop = text.find("\n", text.find("\n", m.end()) + 1)
            if WRITE_OP.search(text[start:stop if stop >= 0 else len(text)]):
                col.add(R_CI_BACKDOOR, "high", m.start(), "writes a GitHub Actions workflow", context)
                break
        runner = next(iter(live(RUNNER_SETUP.finditer(text), 1)), None)
        if runner:
            col.add(R_CI_BACKDOOR, "critical", runner.start(), "registers a self-hosted GitHub Actions runner", context)
    if has(low, ("whoami", "api.github.com/user", "gh auth")):
        checks = [m.start() for m in live(TOKEN_CHECK.finditer(text), 20)]
        wipes = [m.start() for m in live(WIPE_HOME.finditer(text), 20)] if checks else []
        fails = [m.start() for m in TOKEN_FAILED.finditer(text)] if wipes else []
        hit = first_near(wipes, checks, 2000) if wipes else None
        if hit is not None and first_near([hit], fails, 1500) is not None:
            col.add(R_DEADMAN, "critical", hit, "deletes the home folder when a token check fails", context)
    if has(low, ("fetch", "xmlhttprequest", "ethereum")):
        hook = next(iter(live(FETCH_HOOK.finditer(text), 1)), None)
        if hook and (WALLET_FORMAT.search(text) or len(WALLET_LITERAL.findall(text)) >= 10):
            col.add(R_WALLET, "critical" if auto else "high", hook.start(), "replaces the page's network or wallet calls "
                    "and matches wallet addresses", context)
    if auto:
        hidden = next(iter(live(HIDDEN_PROCESS.finditer(text), 1)), None)
        if hidden:
            col.add(R_HIDDEN_PROC, "high" if nets else "medium", hidden.start(), "starts a hidden or detached process"
                    + (" and the file talks to the network" if nets else ""), context)
        sweep = next(iter(live(SECRET_SWEEP.finditer(text), 1)), None)
        if sweep:
            col.add(R_SWEEP, "high", sweep.start(), f"uses {sweep.group()} while installing or opening", context)
        boot = next(iter(live(RUNTIME_BOOTSTRAP.finditer(text), 1)), None)
        if boot:
            col.add(R_NET_AUTO, "medium", boot.start(), "installs another JavaScript runtime while installing (Shai-Hulud "
                    "2.0 brought Bun along to run its payload)", context)
    if has(low, ("jimp", "pixel", "sharp(", "png.sync", "getdata", "getpixel")):
        pixels = [m.start() for m in live(PIXEL_READ.finditer(text), 20)]
        sinks = [m.start() for m in live(CODE_SINK.finditer(text), 50)] + \
            ([m.start() for m in live(PROCESS_SINK.finditer(text), 50)] if auto else [])
        hit = first_near(pixels, sinks, 2000) if pixels and sinks else None
        if hit is not None:
            col.add(R_DECODE_EXEC, "critical" if auto else "high", hit, "reads code out of an image's pixels and runs it",
                    context)
