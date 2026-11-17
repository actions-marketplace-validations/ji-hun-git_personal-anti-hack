"""Decoding what code hides, before the rules run: pieces of strings joined, character codes, escapes and ROT13
decoded, members reached through brackets or getattr written plainly, and shell variables expanded.

decoded_items() lists every disguised value with where it is; deobfuscate() returns the text with each one
spelled out and every line in place, so the rules can run on it again.
"""
from __future__ import annotations

import ast
import re
import warnings

from .codectx import JS_SUFFIXES
from .indicators import SECRET_PATHS


_LIT = r"(?:'(?:[^'\\\n]|\\.){0,200}'|\"(?:[^\"\\\n]|\\.){0,200}\")"


SPLIT_STRINGS = re.compile(
    rf"\[[ \t]*{_LIT}(?:[ \t]*,[ \t]*{_LIT})+[ \t]*,?[ \t]*\][ \t]*\.[ \t]*join\([ \t]*(?:''|\"\")[ \t]*\)"  # a list of quoted pieces joined with ''
    rf"|(?:''|\"\")[ \t]*\.[ \t]*join\([ \t]*[\[(][ \t]*{_LIT}(?:[ \t]*,[ \t]*{_LIT})+[ \t]*,?[ \t]*[\])][ \t]*\)"  # Python's ''.join over quoted pieces
    rf"|{_LIT}(?:[ \t]*\+[ \t]*{_LIT})+")  # quoted pieces added together


SPLIT_HINT = re.compile(r"['\"][ \t]*\+[ \t]*['\"]|\][ \t]*\.[ \t]*join\([ \t]*(?:''|\"\")|(?:''|\"\")[ \t]*\.[ \t]*join\(")


SENSITIVE_NAMES = {"eval", "function", "constructor", "child_process", "exec", "execsync", "execfile", "execfilesync",
                   "spawn", "spawnsync", "fork", "http", "https", "net", "dns", "tls", "dgram", "env", "process", "require",
                   "atob", "fromcharcode", "writefilesync", "appendfilesync", "system", "popen", "subprocess",
                   "__import__", "__builtins__", "builtins", "getattr", "compile", "b64decode", "urlopen", "urllib",
                   "socket", "powershell", "invoke-expression", "iex", "curl", "wget", "globalthis", "xmlhttprequest",
                   "sendbeacon", "websocket", "importscripts", "settimeout", "setinterval"}


FOLD_LIMIT = 2_000_000


def _literal(lit: str) -> str:
    """The value of a quoted literal. JavaScript escapes Python does not know (\\[) would print a SyntaxWarning."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            value = ast.literal_eval(lit)
        return value if isinstance(value, str) else lit[1:-1]
    except (ValueError, SyntaxError):
        return lit[1:-1]


def fold_strings(text: str) -> tuple[str, list[tuple[int, str]]]:
    """Join string literals that code splits apart (quoted pieces added together, or joined from a list). Returns the text with the
    pieces joined, every line kept in place, and (position in the original, joined value) for each join."""
    joins: list[tuple[int, str]] = []

    def joined(m: re.Match) -> str:
        value = "".join(_literal(p) for p in re.findall(_LIT, m.group()))
        joins.append((m.start(), value))
        return repr(value.replace("\n", " "))

    return SPLIT_STRINGS.sub(joined, text), joins


CHAR_CODES = re.compile(r"String\.fromCharCode\(\s*((?:\d{1,6}\s*,\s*){1,400}\d{1,6})\s*\)"
                        r"|''\.join\(\s*map\(\s*chr\s*,\s*[\[(]\s*((?:\d{1,6}\s*,\s*){1,400}\d{1,6})\s*,?\s*[\])]\s*\)\s*\)"
                        r"|\bbytes\(\s*\[\s*((?:\d{1,3}\s*,\s*){1,400}\d{1,3})\s*\]\s*\)\.decode\([^)]{0,20}\)")


ESCAPED = re.compile(r"(['\"])((?:[^'\"\\\n]|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){0,400}?\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})"
                     r"(?:[^'\"\\\n]|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){0,400})\1")


ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})")


ROT13_PY = re.compile(r"(?:__import__\(\s*['\"]codecs['\"]\s*\)|\bcodecs)\.decode\(\s*(['\"])([^'\"\\\n]{1,400})\1\s*,\s*"
                      r"['\"]rot[_-]?13['\"]\s*\)")


ROT13_JS_FN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=[^\n;]{0,200}?charCodeAt\(\s*0?\s*\)\s*\+\s*13\b"
                         r"|\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{[^}]{0,240}?charCodeAt\(\s*0?\s*\)\s*\+\s*13\b")


JS_BRACKET = re.compile(r"(?<=[\w$)\]])\[\s*(['\"])([A-Za-z_$][\w$]*)\1\s*\]")


PY_GETATTR = re.compile(r"\bgetattr\(\s*([A-Za-z_][\w.]*)\s*,\s*(['\"])([A-Za-z_]\w*)\2\s*\)")


SH_ASSIGN = re.compile(r"(?:^|(?<=[;&|\n]))[ \t]*([A-Za-z_]\w*)=('[^'\n]*'|\"[^\"$`\n]*\"|[^\s;&|'\"$`()]*)(?=[ \t]*(?:[;&|\n]|$))")


SH_VAR = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")


SHELL_FILES = (".sh", ".bash", ".zsh", ".ksh")


SHELL_TOOLS = re.compile(r"(?<![\w./-])(?:curl|wget|bash|sh|zsh|nc|ncat|python3?|node|base64|powershell|pwsh|eval)(?![\w.-])")


DEOBF_HINT = re.compile(r"fromCharCode|map\(\s*chr|bytes\(\s*\[|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|rot[_-]?13|\+\s*13\b"
                        r"|getattr\(|\[\s*['\"][A-Za-z_$]|\$\{?[A-Za-z_]")


SENSITIVE_TEXT = re.compile(r"\b(?:curl|wget)\b|\|\s*(?:ba|z)?sh\b|\bnpm\s+publish\b|/-/whoami|\.npmrc\b|\.pypirc\b|\bid_rsa\b"
                            r"|\bchild_process\b|\beval\s*\(|\bexec\s*\(", re.I)


def _rot13(s: str) -> str:
    return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                     "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def _quoted(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def _from_codes(m: re.Match) -> str:
    try:
        return "".join(chr(int(n)) for n in re.findall(r"\d+", next(g for g in m.groups() if g)))
    except (ValueError, OverflowError):
        return ""


def _unescape(body: str) -> str:
    """Decode the escapes that stand for printable characters. Control characters, quotes and backslashes stay
    escaped, so the literal stays well formed and a control character added as padding cannot stop the decoding."""
    def one(m: re.Match) -> str:
        c = chr(int(m.group(1) or m.group(2), 16))
        return c if c.isprintable() and c not in "'\"\\" else m.group()
    return ESCAPE.sub(one, body)


def _spells_text(body: str) -> bool:
    """Whether some escape stands for a letter or digit, which nothing needs to escape: the escapes are hiding text
    ("http" written as \\x68\\x74\\x74\\x70). Escapes for control characters, as in terminal sequences around a plain
    URL, hide nothing."""
    return any((c := chr(int(m.group(1) or m.group(2), 16))).isascii() and c.isalnum() for m in ESCAPE.finditer(body))


def _printable(s: str) -> bool:
    return bool(s) and all(c.isprintable() or c in "\t\n" for c in s)


def _rot13_functions(text: str) -> list[str]:
    return [m.group(1) or m.group(2) for m in ROT13_JS_FN.finditer(text)]


def _shell_values(text: str) -> dict[str, str]:
    values = {}
    for m in SH_ASSIGN.finditer(text):
        raw = m.group(2)
        values[m.group(1)] = raw[1:-1] if raw[:1] in ("'", '"') else raw
    return values


def _expand_shell(text: str, values: dict[str, str]) -> str:
    for _ in range(3):  # a=cu; b=${a}rl; $b
        new = SH_VAR.sub(lambda m: values.get(m.group(1) or m.group(2), m.group()), text)
        if new == text:
            break
        text = new
    return text


def is_sensitive(value: str) -> bool:
    v = value.strip()
    return v.lower() in SENSITIVE_NAMES or "://" in v or bool(SECRET_PATHS.search(v)) or bool(SENSITIVE_TEXT.search(v))


def decoded_items(text: str, path: str) -> list[tuple[int, str, str]]:
    """(position, decoded value, how) for every value the code spells in a disguise: pieces, character codes,
    escapes, ROT13, or a shell command assembled from variables."""
    items = [(pos, value, "builds out of pieces") for pos, value in fold_strings(text)[1]] if SPLIT_HINT.search(text) else []
    items += [(m.start(), _from_codes(m), "decodes from character codes") for m in CHAR_CODES.finditer(text)]
    items += [(m.start(), _unescape(m.group(2)), "decodes from escape sequences") for m in ESCAPED.finditer(text)
              if _spells_text(m.group(2))]
    items += [(m.start(), _rot13(m.group(2)), "decodes with ROT13") for m in ROT13_PY.finditer(text)]
    for name in _rot13_functions(text):
        items += [(m.start(), _rot13(m.group(2)), "decodes with ROT13")
                  for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}\(\s*(['\"])([^'\"\\\n]{{1,400}})\1\s*\)", text)]
    if path.lower().endswith(SHELL_FILES):
        values = _shell_values(text)
        if values:
            whole = {v.strip().split(" ")[0] for v in values.values()}  # CURL=curl names the tool in one piece
            for m in re.finditer(r"[^\n]*\$\{?[A-Za-z_][^\n]*", text):
                expanded = _expand_shell(m.group(), values)
                tools = set(SHELL_TOOLS.findall(expanded)) - set(SHELL_TOOLS.findall(m.group())) - whole
                if tools:
                    items.append((m.start(), " ".join(sorted(tools)) + ": " + expanded.strip()[:120],
                                  "assembles a command from shell variables"))
    return items


def deobfuscate(text: str, path: str) -> str:
    """The text with what the code hides spelled out, every line in place: pieces joined, character codes and escapes
    decoded, ROT13 undone where the file carries a decoder, members reached through brackets or getattr written
    plainly, and shell variables expanded."""
    if SPLIT_HINT.search(text):
        text = fold_strings(text)[0]
    text = CHAR_CODES.sub(lambda m: _quoted(_from_codes(m)) if _printable(_from_codes(m)) else m.group(), text)
    text = ESCAPED.sub(lambda m: m.group(1) + _unescape(m.group(2)) + m.group(1), text)
    text = ROT13_PY.sub(lambda m: _quoted(_rot13(m.group(2))), text)
    for name in _rot13_functions(text):
        text = re.sub(rf"(?<![\w$.]){re.escape(name)}\(\s*(['\"])([^'\"\\\n]{{1,400}})\1\s*\)",
                      lambda m: _quoted(_rot13(m.group(2))), text)
    text = PY_GETATTR.sub(lambda m: f"{m.group(1)}.{m.group(3)}", text)
    if path.lower().endswith(JS_SUFFIXES):
        text = JS_BRACKET.sub(lambda m: "." + m.group(2), text)
    if path.lower().endswith(SHELL_FILES):
        values = _shell_values(text)
        if values:
            text = _expand_shell(text, values)
    return text
