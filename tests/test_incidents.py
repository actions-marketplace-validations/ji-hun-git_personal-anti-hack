"""The incident catalog: every entry complete, its rules real, its trap repositories caught by those rules, its traces
found on a computer, and docs/incidents.md current. Standard library only."""
from __future__ import annotations

import contextlib
import io
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
sys.path.insert(0, str(ROOT / "bench"))
os.environ.setdefault("PAH_HOME", tempfile.mkdtemp(prefix="pah-test-home-"))

from pah import av, checkup, cli, diff, guard, incidents, intel, mcp_server, packages, review, surfaces, watch  # noqa: E402,F401
from pah.model import RULES  # noqa: E402
from pah.scan import scan  # noqa: E402

CASES = ROOT / "bench" / "fixtures" / "traprepo"


class CatalogTests(unittest.TestCase):
    def test_every_incident_is_complete(self):
        ids = [i.id for i in incidents.catalog()]
        self.assertEqual(len(ids), len(set(ids)), "duplicate incident ids")
        shared = incidents.steps()
        for i in incidents.catalog():
            with self.subTest(i.id):
                self.assertRegex(i.id, r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
                self.assertRegex(i.when, r"^20\d\d(?:-(?:0[1-9]|1[0-2]))?$")
                self.assertIn(i.kind, incidents.KINDS)
                self.assertTrue(i.summary and i.respond and i.refs)
                self.assertTrue(i.rules or i.traces, "nothing would find it: give it rules or traces")
                self.assertTrue(all(r.startswith("https://") for r in i.refs))
                for step in i.respond:
                    if step.startswith("@"):
                        self.assertIn(step[1:], shared)
                for r in i.rules:
                    self.assertIn(r, RULES)
                for c in i.cases:
                    self.assertTrue((CASES / f"{c}.json").exists(), f"no TrapRepo case {c}")
                for t in i.traces:
                    self.assertIn(t.severity, incidents.SEVERITIES)
                    self.assertTrue(t.path.startswith(("~/", "{", "/")) or t.path[1:3] == ":/", t.path)
        used = {s[1:] for i in incidents.catalog() for s in i.respond if s.startswith("@")}
        self.assertEqual(set(shared) - used, set(), "shared steps no incident uses")

    def test_trap_repositories_are_caught_by_the_incidents_rules(self):
        from materialize import materialize

        tmp = Path(tempfile.mkdtemp(prefix="pah-test-incidents-"))
        try:
            for i in incidents.catalog():
                for c in i.cases:
                    with self.subTest(incident=i.id, case=c), contextlib.redirect_stderr(io.StringIO()):
                        root = materialize(json.loads((CASES / f"{c}.json").read_text(encoding="utf-8")), tmp / c)
                        found = {f.rule for f in scan(root).findings}
                        self.assertTrue(found & set(i.rules), f"{c} gave {sorted(found)}, none of {list(i.rules)}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_docs_are_current(self):
        self.assertEqual((ROOT / "docs" / "incidents.md").read_text(encoding="utf-8"), incidents.markdown(),
                         "regenerate: python -I pah_entry.py incident list --markdown > docs/incidents.md")


class TraceTests(unittest.TestCase):
    """Traces planted in a throwaway home folder are found, by checkup and by `pah incident check`."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="pah-test-traces-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        patcher = mock.patch.object(Path, "home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    def plant(self, rel: str, text: str = "x") -> None:
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def test_files_prefixes_and_lines(self):
        self.plant(".node_modules/.npm-ws-runner.js")
        self.plant(".config/.smt-cache")
        self.plant(".ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3x svc-telemetry\n")
        self.plant(".zshrc", "export PATH=$HOME/bin:$PATH\nsudo shutdown -h 0\n")
        self.plant(".bashrc", "alias ll='ls -l'\n")  # clean: no finding
        hits = {(i.id, p.name) for i, _, p in incidents.found()}
        self.assertEqual(hits, {("polinrider", ".npm-ws-runner.js"), ("trojanized-claude-code-extension", ".smt-cache"),
                                ("trojanized-claude-code-extension", "authorized_keys"), ("s1ngularity-nx", ".zshrc")})
        rep = checkup.run(key_roots=[])
        iocs = [f for f in rep.findings if f.rule == "PAH-H007"]
        self.assertTrue(any("pah incident show polinrider" in f.message and f.severity == "critical" for f in iocs))
        self.assertTrue(any(".smt" in f.path and f.severity == "high" for f in iocs))

    def test_check_command_prints_the_response_in_order(self):
        self.plant(".local/bin/net-health-checker.sh")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["incident", "check", "testmetest-worm"])
        self.assertEqual(code, 2)
        text = out.getvalue()
        self.assertIn("FOUND ON THIS COMPUTER", text)
        self.assertLess(text.index("Do not revoke the stolen token first"), text.index("Only now revoke"))

    def test_clean_computer(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["incident", "check"]), 0)
        self.assertIn("No traces", out.getvalue())


class LookupTests(unittest.TestCase):
    def test_search_and_mcp(self):
        self.assertEqual(incidents.get("PolinRider").id, "polinrider")
        self.assertIn("shai-hulud", [i.id for i in incidents.search("worm republish")] +
                      [i.id for i in incidents.for_rule("PAH-C024")])
        text, is_error = mcp_server.call_tool("incident", {"query": "s1ngularity"})
        self.assertFalse(is_error)
        data = json.loads(text)
        self.assertEqual([d["id"] for d in data], ["s1ngularity-nx"])
        self.assertTrue(any("shutdown" in step for step in data[0]["respond"]))
        listing = json.loads(mcp_server.call_tool("incident", {})[0])
        self.assertEqual(len(listing), len(incidents.catalog()))


if __name__ == "__main__":
    unittest.main()
