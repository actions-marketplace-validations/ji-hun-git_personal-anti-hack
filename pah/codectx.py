"""Where a match sits in a file: inside a string, a comment, a regular expression or test data. Rules use it to
tell code that does something from text that only mentions it."""
from __future__ import annotations

import bisect
import re

from .policy import is_test_code


def has(low: str, words: tuple[str, ...]) -> bool:
    return not words or any(w in low for w in words)


def first_near(anchors: list[int], others: list[int], limit: int) -> int | None:
    """The first anchor with one of the other positions within limit characters, or None."""
    others = sorted(others)
    for a in anchors:
        i = bisect.bisect_left(others, a)
        if any(0 <= j < len(others) and abs(others[j] - a) <= limit for j in (i - 1, i)):
            return a
    return None


def line_window(text: str, start: int, end: int, extra: int = 200) -> str:
    stop = text.find("\n", end)
    stop = len(text) if stop < 0 else stop
    return text[start:min(stop, end + extra)]


EXEC_ON_LINE = re.compile(r"\b(?:exec(?:Sync|File(?:Sync)?|a)?|spawn(?:Sync)?|system|popen|Popen|check_output|check_call|"
                          r"subprocess\.\w+|shell_exec|passthru|Command::new|ProcessBuilder|Start-Process|Invoke-Expression|"
                          r"iex|eval|Function|run_command|sh|bash)\s*[(`]", re.I)


_STRING = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\\n]|\\.)*`")


REGEX_LIKE = re.compile(r"\(\?[:!=<iIsmx]|\\[bsdwBSDW]|\[\^|\\[.(|)\[]|\{\d+,\d*\}|\[[^\]\s]{1,30}\][*+?]"
                         r"|(?:[\w.-]+\|){3,}[\w.-]+")


LONG_LINE = 4000  # minified or generated lines: string boundaries there are guesswork, and costly to compute


def enclosing_string(text: str, pos: int) -> str | None:
    """The single-line string literal around pos, or None (also for very long lines, which keep their findings)."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    if end - start > LONG_LINE:
        return None
    line = text[start:end]
    for m in _STRING.finditer(line):
        if m.start() <= pos - start < m.end():
            return m.group()
    return None


def _code_part(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    if end - start > LONG_LINE:
        return text[max(start, pos - 300):min(end, pos + 300)]
    return _STRING.sub('""', text[start:end])


_TRIPLE = re.compile(r'"""|\'\'\'')


_TRIPLE_CACHE: dict = {}


def _triple_quoted(text: str, pos: int) -> str | None:
    """The triple-quoted string (a Python docstring, a prompt template) around pos, or None."""
    key = (id(text), len(text), text[:32])
    spans = _TRIPLE_CACHE.get(key)
    if spans is None:
        spans, opened, quote = [], None, ""
        for m in _TRIPLE.finditer(text):
            if opened is None:
                opened, quote = m.end(), m.group()
            elif m.group() == quote:
                spans.append((opened, m.start()))
                opened = None
        if len(_TRIPLE_CACHE) > 32:
            _TRIPLE_CACHE.clear()
        _TRIPLE_CACHE[key] = spans
    i = bisect.bisect_right([a for a, _ in spans], pos) - 1
    if i >= 0 and spans[i][0] <= pos < spans[i][1] and spans[i][1] - spans[i][0] <= 20_000:
        return text[spans[i][0]:spans[i][1]]
    return None


_REGEX_LITERAL = re.compile(r"(?:^|[=(,:;!&|?{}\[]|\breturn)\s*/(?![/*\s])((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+)/"
                            r"[dgimsuyv]*(?=\s*(?:[,;)\]}.]|$))", re.M)


JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")


_RULE_ENTRY = re.compile(r"\b(?:re|regex|regexp|pattern|rx|match|test|detect)\s*:\s*/(?![/*\s])")


def _line_has_regex(text: str, pos: int) -> bool:
    """A detection-table entry ({ re: /.../, label: '...' }): its strings describe the pattern."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    return end - start <= LONG_LINE and _RULE_ENTRY.search(text[start:end]) is not None


def _in_regex_literal(text: str, pos: int) -> bool:
    """pos sits inside a JavaScript regular-expression literal: /curl[^|]*\\|\\s*sh/ in a detection rule."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    if end - start > LONG_LINE:
        return False
    return any(m.start(1) <= pos - start < m.end(1) for m in _REGEX_LITERAL.finditer(text[start:end]))


_RUST_RAW = re.compile(r'(?<![\w"])r(#*)"')
RAW_WINDOW = 50_000


def raw_multiline(text: str, pos: int, path: str) -> str | None:
    """The multi-line string literal around pos in languages that have them: Rust raw strings (r#"..."#), and
    backtick strings in Go and JavaScript (template literals). Test suites keep whole shell scripts in them; they are
    data there, as a Python triple-quoted string is."""
    low = path.lower()
    if low.endswith(".rs"):
        for m in reversed(list(_RUST_RAW.finditer(text, max(0, pos - RAW_WINDOW), pos))):
            close = text.find('"' + m.group(1), m.end())
            if close >= pos:
                return text[m.start():close + 1 + len(m.group(1))]
            # this raw string closed before pos; an earlier one cannot be open either
            return None
        return None
    if low.endswith((".go",) + JS_SUFFIXES):
        start = max(0, pos - RAW_WINDOW)
        before = text[start:pos]
        ticks = [i for i, c in enumerate(before) if c == "`" and (i == 0 or before[i - 1] != "\\")]
        if len(ticks) % 2 == 1:  # an odd number of backticks before pos: inside one
            close = text.find("`", pos)
            if close >= 0:
                return text[start + ticks[-1]:close + 1]
    return None


def data_string(text: str, pos: int, path: str, context: str) -> bool:
    """A match that is data rather than behavior: inside a regular expression, inside a sentence of prose, or inside
    a string in a test file, on a line whose code does not hand strings to a shell, eval or exec. Detection tools,
    linters and test suites are full of these; a payload passed to exec() is not."""
    literal = enclosing_string(text, pos)
    if path.lower().endswith(JS_SUFFIXES) and (_in_regex_literal(text, pos) or (literal is not None and _line_has_regex(text, pos))):
        # a detection table: { re: /curl[^|]*\|\s*sh/, label: 'pipe-to-shell (curl|sh)' }
        return not EXEC_ON_LINE.search(_code_part(text, pos))
    if literal is None and path.lower().endswith((".py", ".pyw")):
        literal = _triple_quoted(text, pos)
    if literal is None and context == "code" and is_test_code(path):
        # Only in test suites: elsewhere a stray backtick in a comment must not turn the code after it into "data".
        literal = raw_multiline(text, pos, path)
    if literal is None or EXEC_ON_LINE.search(_code_part(text, pos)):
        return False
    if REGEX_LIKE.search(literal):
        return True
    words = re.findall(r"[A-Za-z]{3,}", literal)
    if len(words) >= (8 if context == "autoexec" else 6) and literal.count(" ") >= 5 and not re.search(r"https?://", literal):
        return True  # a sentence: rule descriptions, log messages, help text
    return context == "code" and is_test_code(path)


_COMMAND_STRING = re.compile(r"\s*(?:sudo\s+)?(?:curl|wget|nslookup|dig|nc|ncat|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|"
                             r"powershell|pwsh|bash|sh)(?:\.exe)?\s+\S", re.I)


def named_in_string(text: str, pos: int) -> bool:
    """A network API or tool named inside a string that is not itself a command line: "fetch", "nslookup " in a
    keyword list, an API name in a message. A string like "curl -d @file https://..." still counts, since that is how
    scripts run commands."""
    literal = enclosing_string(text, pos)
    if literal is None:
        return False
    return not _COMMAND_STRING.match(literal[1:-1]) and not EXEC_ON_LINE.search(_code_part(text, pos))


HASH_COMMENT = (".py", ".pyw", ".sh", ".bash", ".zsh", ".rb", ".pl", ".r", ".yml", ".yaml", ".toml", ".ps1")


SLASH_COMMENT = JS_SUFFIXES + (".go", ".rs", ".java", ".c", ".cc", ".cpp", ".h", ".cs", ".kt", ".swift", ".php", ".dart")


def after_trailing_comment(text: str, pos: int, path: str) -> bool:
    """pos follows a # or // comment marker on its own line, outside every string. Quotes are tracked, so code cannot
    hide behind a quote the way it could if any # counted."""
    low = path.lower()
    marker = "#" if low.endswith(HASH_COMMENT) else "//" if low.endswith(SLASH_COMMENT) else None
    if marker is None:
        return False
    i, quote = text.rfind("\n", 0, pos) + 1, None
    while i < pos:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif text.startswith(marker, i):
            return True
        i += 1
    return False


def in_other_string(text: str, pos: int, path: str) -> bool:
    """pos sits inside a string that began earlier: an example in a docstring or a message, not code."""
    if path.lower().endswith((".py", ".pyw")) and _triple_quoted(text, pos) is not None:
        return True
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    if end - start > LONG_LINE:
        return False
    col = pos - start
    return any(m.start() < col < m.end() for m in _STRING.finditer(text[start:end]))
