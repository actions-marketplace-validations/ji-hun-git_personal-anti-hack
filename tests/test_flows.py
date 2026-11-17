"""Agent setups: pre-approved commands that run any program through their arguments (PAH-A020), and tools that carry
content anyone can write to a way out without asking (PAH-A021), in a repository and in the user's own setup."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PAH_HOME", tempfile.mkdtemp(prefix="pah-test-home-"))

from pah import checkup  # noqa: E402
from pah.flows import argv_exec, server_legs  # noqa: E402
from pah.scan import scan  # noqa: E402


def write(root: Path, files: dict) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content, indent=1), encoding="utf-8")
    return root


class ArgvTests(unittest.TestCase):
    def test_entries(self):
        cases = {"Bash(find:*)": "find", "Bash(git:*)": "git", "Bash(go test:*)": "go", "Bash(npm test:*)": "npm",
                 "Bash(npx:*)": "npx", "run_shell_command(git)": "git", "npm test": "npm", "Bash(rg *)": "rg",
                 "Bash(git status)": None, "Bash(git status:*)": None, "Bash(ls:*)": None, "WebFetch": None,
                 "Bash(npm run build)": None, "Read(~/project/**)": None}
        for entry, prog in cases.items():
            with self.subTest(entry):
                hit = argv_exec(entry)
                self.assertEqual(hit[0] if hit else None, prog)
        self.assertTrue(argv_exec("Bash(npx:*)")[2], "npx is an interpreter-class runner")
        self.assertFalse(argv_exec("Bash(npm test:*)")[2])

    def test_server_legs(self):
        self.assertEqual(server_legs("github", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}),
                         {"untrusted content", "private data", "a way out"})
        self.assertEqual(server_legs("docs", {"command": "uvx", "args": ["mcp-server-fetch"]}),
                         {"untrusted content", "a way out"})
        self.assertEqual(server_legs("notes", {"command": "node", "args": ["notes.js"]}), set())


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pah-test-flows-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def rules(self, files: dict) -> dict:
        rep = scan(write(self.tmp / str(len(list(self.tmp.iterdir()))), files))
        return {(f.rule, f.severity) for f in rep.findings}, rep.verdict

    def test_preapproved_runners(self):
        found, verdict = self.rules({".claude/settings.json": {"permissions": {"allow": ["Bash(npx:*)", "Bash(npm test:*)"]}}})
        self.assertIn(("PAH-A020", "medium"), found)
        self.assertIn(("PAH-A020", "low"), found)
        self.assertEqual(verdict, "warn")

    def test_toxic_flow_needs_both_legs_without_asking(self):
        servers = {"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
                                  "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}}
        found, _ = self.rules({".mcp.json": servers, ".claude/settings.json": {"permissions": {"allow": ["mcp__github",
                                                                                                         "mcp__fetch"]}}})
        self.assertIn(("PAH-A021", "medium"), found)
        found, _ = self.rules({".mcp.json": servers})  # each tool call still asks
        self.assertNotIn("PAH-A021", {r for r, _ in found})
        found, _ = self.rules({".claude/settings.json": {"permissions": {"allow": ["WebFetch"]}}})
        self.assertIn(("PAH-A021", "medium"), found)

    def test_scoped_and_exact_entries_stay_quiet(self):
        found, verdict = self.rules({".claude/settings.json": {"permissions": {"allow": [
            "Bash(npm test)", "Bash(git status:*)", "Bash(git diff)", "WebFetch(domain:docs.python.org)", "Read(src/**)"]}}})
        self.assertEqual(verdict, "pass", found)


class HomeTests(unittest.TestCase):
    def test_checkup_reads_the_users_setup(self):
        home = Path(tempfile.mkdtemp(prefix="pah-test-flows-home-"))
        self.addCleanup(shutil.rmtree, home, True)
        write(home, {".claude/settings.json": {"permissions": {"allow": ["mcp__github__*", "WebFetch", "Bash(find:*)"]}},
                     ".claude.json": {"mcpServers": {"github": {"command": "npx", "args": [
                         "-y", "@modelcontextprotocol/server-github"]}}}})
        with mock.patch.object(Path, "home", return_value=home):
            rep = checkup.run(key_roots=[])
        by_rule = {f.rule: f for f in rep.findings}
        self.assertIn("PAH-A020", by_rule)
        self.assertIn("find -exec", by_rule["PAH-A020"].message)
        self.assertIn("PAH-A021", by_rule)
        self.assertIn("MCP server github", by_rule["PAH-A021"].message)


if __name__ == "__main__":
    unittest.main()
