"""What a shell command really runs, worked out without running it.

Attacks aimed at agents hide a command from pattern matching with the shell's own syntax: quote and backslash breaks
(c''url, cu\\rl), ${IFS} in place of spaces, a command assembled in variables, a command handed to a runner
(script -qc, watch, bash -c), and text decoded on its way into a shell (base64, hex, octal printf, rot13 through tr,
rev, gzip). unfold() returns the commands these forms stand for, so the same rules judge them, and marks which of
them are payloads a decode-and-run pipeline would hand to a shell. Every step is a string transformation with size
and depth limits; nothing is executed.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import re
import shlex

from .deobfuscate import _expand_shell, _shell_values

MAX_TEXT = 20_000
MAX_PAYLOAD = 100_000

IFS = re.compile(r"\$\{IFS[^}]{0,8}\}|\$IFS(?!\w)")
BREAK_HINT = re.compile(r"[\w./-](?:''|\"\")|(?:''|\"\")[\w./-]|[\w./-]\\[\w./-]|(?<![\w\\])\\[A-Za-z](?=\w)"
                        r"|[\w./-]['\"][\w./-]+['\"]|(?<![\w'\"])['\"][\w./-]+['\"][\w./-]")
SINK = re.compile(r"^(?:sudo\s+(?:-\S+\s+)*)?(?:/usr)?(?:/bin/)?(?:ba|z|da|k|fi)?sh(?:\s+-[sil]+)*(?:\s+-)?$"
                  r"|^(?:source|\.)\s+/dev/stdin$")
EXEC_BEFORE = re.compile(r"(?:\beval|\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*-c|\b(?:ba|z|da|k)?sh\s*<<<|\bsource|(?<![\w.])\.)"
                         r"\s*[\"']?$|^\s*[\"']?$")
WORDCHAR = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./")
RUNNERS = {"script": ("-c", "-qc", "-cq", "--command"), "watch": None, "timeout": None, "nohup": None, "nice": None,
           "stdbuf": None, "setsid": None, "env": None}


def _close(s: str, i: int) -> int:
    """Index of the quote closing the one at i, or -1."""
    q = s[i]
    j = i + 1
    while j < len(s):
        if q == '"' and s[j] == "\\":
            j += 2
            continue
        if s[j] == q:
            return j
        j += 1
    return -1


def unbreak(cmd: str) -> str:
    """The command with ${IFS} read as a space and the quote and backslash breaks inside words removed, the way the
    shell removes them. Quoted text that is more than a broken word keeps its quotes."""
    s = IFS.sub(" ", cmd)
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] != "\n":
            nxt = s[i + 1]
            out.append(nxt if nxt in WORDCHAR else c + nxt)
            i += 2
            continue
        if c in "'\"":
            j = _close(s, i)
            if j < 0:
                out.append(s[i:])
                break
            body = s[i + 1:j]
            before = s[i - 1] if i else " "
            after = s[j + 1] if j + 1 < n else " "
            if (before in WORDCHAR or after in WORDCHAR) and all(ch in WORDCHAR for ch in body):
                out.append(body)
            else:
                out.append(s[i:j + 1])
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def split_top(text: str, seps: tuple[str, ...]) -> list[str]:
    """Split on separators that are not quoted, escaped or inside $( ), <( ) or ( )."""
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = _close(text, i)
            j = n - 1 if j < 0 else j
            cur.append(text[i:j + 1])
            i = j + 1
            continue
        if c == "\\" and i + 1 < n:
            cur.append(text[i:i + 2])
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        if depth == 0:
            sep = next((s for s in seps if text.startswith(s, i)), None)
            if sep:
                out.append("".join(cur))
                cur = []
                i += len(sep)
                continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


def statements(text: str) -> list[str]:
    return [s.strip() for s in split_top(text, ("&&", "||", ";", "\n", "&")) if s.strip()]


def _words(stage: str) -> list[str] | None:
    try:
        return shlex.split(stage, comments=False, posix=True)
    except ValueError:
        return None


ESC = re.compile(r"\\(0[0-7]{0,3}|[0-7]{1,3}|x[0-9A-Fa-f]{1,2}|[abfnrtv\\'\"])")
_SIMPLE = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"'}


def _escapes(s: str) -> str:
    def one(m: re.Match) -> str:
        e = m.group(1)
        if e[0] == "x":
            return chr(int(e[1:], 16))
        if e[0] in "01234567":
            return chr(int(e, 8) & 0xFF)
        return _SIMPLE[e]
    return ESC.sub(one, s)


def _printf(fmt: str, args: list[str]) -> str | None:
    text = _escapes(fmt)
    it = iter(args)
    out = re.sub(r"%(%|[-+ #0]*\d*(?:\.\d+)?[sbdiqc])",
                 lambda m: "%" if m.group(1) == "%" else (_escapes(next(it, "")) if m.group(1).endswith("b")
                                                          else next(it, "")), text)
    return out


def _source(stage: str) -> str | None:
    """The text an echo, printf or here-string source writes."""
    words = _words(stage)
    if not words:
        return None
    if words[0] in ("echo", "/bin/echo"):
        args = words[1:]
        interpret = False
        while args and re.fullmatch(r"-[neE]+", args[0]):
            interpret = interpret or "e" in args[0]
            args = args[1:]
        text = " ".join(args)
        return _escapes(text) if interpret else text
    if words[0] in ("printf", "/usr/bin/printf") and len(words) >= 2:
        args = words[1:]
        if args[0] == "--":
            args = args[1:]
        return _printf(args[0], args[1:]) if args else None
    if words[0] == "cat" and len(words) == 3 and words[1] == "<<<":
        return words[2]
    return None


def _tr_set(spec: str) -> str:
    out = []
    i = 0
    spec = _escapes(spec.strip("[]")) if re.fullmatch(r"\[[^\]]+\]", spec) and "-" in spec else _escapes(spec)
    while i < len(spec):
        if i + 2 < len(spec) and spec[i + 1] == "-":
            out.extend(chr(c) for c in range(ord(spec[i]), ord(spec[i + 2]) + 1))
            i += 3
        else:
            out.append(spec[i])
            i += 1
    return "".join(out)


def _decode(stage: str, data: bytes) -> bytes | None:
    """One decoding stage of a pipeline, or None when the stage is not a decoder this module knows."""
    words = _words(stage)
    if not words:
        return None
    name, flags = words[0], words[1:]
    joined = " ".join(flags)
    try:
        if name in ("base64", "gbase64", "basenc") and re.search(r"(?:^|\s)-\w*[dD]|--decode", joined):
            clean = re.sub(rb"\s+", b"", data)
            return base64.b64decode(clean + b"=" * (-len(clean) % 4))
        if name == "openssl" and re.search(r"\b(?:base64|enc)\b", joined) and re.search(r"(?:^|\s)-d\b", joined):
            clean = re.sub(rb"\s+", b"", data)
            return base64.b64decode(clean + b"=" * (-len(clean) % 4))
        if name == "base32" and re.search(r"(?:^|\s)-d\b|--decode", joined):
            return base64.b32decode(re.sub(rb"\s+", b"", data))
        if name == "xxd" and "r" in joined and "p" in joined:
            return binascii.unhexlify(re.sub(rb"[^0-9A-Fa-f]", b"", data))
        if name == "rev" and not flags:
            return b"\n".join(line[::-1] for line in data.split(b"\n"))
        if name == "tr" and len(flags) == 2 and not flags[0].startswith("-"):
            a, b = _tr_set(flags[0]), _tr_set(flags[1])
            if not a or not b:
                return None
            b = b + b[-1] * max(0, len(a) - len(b))
            return data.decode("latin-1").translate(str.maketrans(a, b[:len(a)])).encode("latin-1")
        if name in ("gunzip", "zcat") or (name == "gzip" and re.search(r"(?:^|\s)-\w*d|--decompress", joined)):
            return gzip.decompress(data)[:MAX_PAYLOAD]
    except (ValueError, binascii.Error, OSError, EOFError):
        return None
    return None


def _text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\n\t\r" for ch in text)
    return text if text and printable / len(text) > 0.95 else None


def _run_pipeline(stages: list[str]) -> str | None:
    """The text a source-and-decoders pipeline produces, or None when any stage is not understood."""
    first = stages[0].strip()
    here = re.match(r"^(.*?)\s*<<<\s*(.+)$", first, re.S)
    if here and _words(here.group(2)):
        data, rest = _words(here.group(2))[0].encode("utf-8", "replace"), [here.group(1)] + stages[1:]
    else:
        src = _source(first)
        if src is None:
            return None
        data, rest = src.encode("utf-8", "replace"), stages[1:]
    for stage in rest:
        if not stage.strip():
            return None
        out = _decode(stage.strip(), data)
        if out is None or len(out) > MAX_PAYLOAD:
            return None
        data = out
    return _text(data)


def _substitutions(text: str) -> list[tuple[int, str, str]]:
    """(start, kind, inner) of each $( ) and <( ) at the top level of text."""
    out = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "'":
            j = _close(text, i)
            i = n if j < 0 else j + 1
            continue
        if text.startswith(("$(", "<("), i) and not text.startswith("$((", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j] in "'\"":
                    k = _close(text, j)
                    j = n if k < 0 else k + 1
                    continue
                depth += {"(": 1, ")": -1}.get(text[j], 0)
                j += 1
            if depth == 0:
                out.append((i, text[i], text[i + 2:j - 1]))
            i = j
            continue
        i += 1
    return out


def payloads(text: str) -> tuple[list[tuple[str, str]], bool]:
    """The commands decode-and-run pipelines in text hand to a shell, and whether some pipeline into a shell could
    not be decoded."""
    found: list[tuple[str, str]] = []
    undecoded = False
    for stmt in statements(text):
        stages = [s.strip() for s in split_top(stmt, ("|&", "|"))]
        if len(stages) >= 2 and SINK.match(stages[-1]):
            body = _run_pipeline(stages[:-1])
            if body is None:
                undecoded = undecoded or len(stages) > 2 or not re.match(r"(?:curl|wget)\b", stages[0])
            else:
                found.append((body, f"what the pipeline hands to {stages[-1].split()[-1]}"))
        for start, kind, inner in _substitutions(stmt):
            inner_stages = [s.strip() for s in split_top(inner, ("|&", "|"))]
            before = stmt[:start]
            runs = (EXEC_BEFORE.search(before) if kind == "$" else
                    re.search(r"(?:\b(?:ba|z|da|k)?sh|\bsource|(?<![\w.])\.)\s*$", before))
            if not runs:
                continue
            body = _run_pipeline(inner_stages)
            if body is None:
                undecoded = undecoded or len(inner_stages) > 1
            else:
                found.append((body, "what the substitution runs"))
    return found, undecoded


def _runner_inner(stmt: str) -> str | None:
    """The command a runner such as script -qc, watch, timeout or bash -c is given."""
    words = _words(stmt)
    if not words or len(words) < 2:
        return None
    name = words[0].rsplit("/", 1)[-1]
    if name in ("bash", "sh", "zsh", "dash", "ksh") and "-c" in words[1:3]:
        k = words.index("-c")
        return words[k + 1] if k + 1 < len(words) else None
    if name == "script":
        for k, w in enumerate(words[1:], 1):
            if w in ("-c", "--command") or re.fullmatch(r"-[a-z]*c", w):
                return words[k + 1] if k + 1 < len(words) else None
        return None
    if name in ("watch", "timeout", "nohup", "nice", "stdbuf", "setsid", "env"):
        rest = words[1:]
        while rest and (rest[0].startswith("-") or re.fullmatch(r"[\d.]+[smhd]?", rest[0]) or "=" in rest[0]):
            if rest[0] in ("-n", "--interval", "-s", "--signal", "-k", "--kill-after") and len(rest) > 1:
                rest = rest[2:]
                continue
            rest = rest[1:]
        return " ".join(rest) if len(rest) > 1 else (rest[0] if rest else None)
    return None


def unfold(command: str) -> tuple[list[tuple[str, str, bool]], bool]:
    """(text, how, is_payload) for each command the given one stands for, and whether a pipeline into a shell could
    not be decoded. The command itself is not included."""
    if len(command) > MAX_TEXT:
        return [], False
    seen = {command}
    out: list[tuple[str, str, bool]] = []

    def add(text: str, how: str, payload: bool = False) -> None:
        text = text.strip()
        if text and text not in seen and len(text) <= MAX_PAYLOAD:
            seen.add(text)
            out.append((text, how, payload))

    base = command
    if BREAK_HINT.search(command) or IFS.search(command):
        base = unbreak(command)
        add(base, "with its quote, backslash and $IFS breaks removed")
    values = _shell_values(base)
    if values:
        expanded = _expand_shell(base, values)
        if expanded != base:
            base = expanded
            add(base, "with its variables filled in")
            if BREAK_HINT.search(base) or IFS.search(base):
                base = unbreak(base)
                add(base, "with its quote, backslash and $IFS breaks removed")
    for stmt in statements(base):
        inner = _runner_inner(stmt)
        if inner:
            add(inner, f"run by {stmt.split()[0].rsplit('/', 1)[-1]}")
    found, undecoded = payloads(base)
    for body, how in found:
        add(body, how, payload=True)
    return out, undecoded
