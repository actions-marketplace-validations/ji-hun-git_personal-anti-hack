"""Collecting one file's findings: deduplicated by rule and line, capped per rule."""
from __future__ import annotations

from .model import Finding, clip
from .text import Lines, line_at


class Collector:
    """Findings for one file, deduplicated by rule and line, capped per rule."""

    def __init__(self, path: str, text: str, lines: Lines | None = None, line_offset: int = 0, note: str = "",
                 command: bool = False):
        self.path, self.text, self.lines = path, text, lines or Lines(text)
        self.offset, self.note = line_offset, note
        self.command = command  # a single command line: no comments or test strings to account for
        self.items: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()
        self._per_rule: dict[str, int] = {}

    def add(self, rule_id: str, severity: str | None, pos: int, message: str, context: str, evidence: str | None = None,
            line: int | None = None) -> None:
        if not severity:
            return
        ln = line if line is not None else self.offset + self.lines.line(pos)
        key = (rule_id, ln)
        if key in self._seen:
            return
        count = self._per_rule.get(rule_id, 0)
        if count >= 6:
            return
        self._per_rule[rule_id] = count + 1
        self._seen.add(key)
        ev = evidence if evidence is not None else line_at(self.text, pos)
        self.items.append(Finding(rule_id, severity, self.path, ln, (self.note + message) if self.note else message,
                                  clip(ev), context))

    def has(self, *rule_ids: str) -> bool:
        return any(f.rule in rule_ids for f in self.items)
