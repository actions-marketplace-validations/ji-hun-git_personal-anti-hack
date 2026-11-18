"""The statistics behind docs/statistics.md: exact intervals and tests checked against closed forms and textbook
values, and the report kept in step with the results it is made from."""
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))

import stats  # noqa: E402


class StatsTests(unittest.TestCase):
    def test_clopper_pearson(self):
        lo, hi = stats.exact_ci(5, 10)  # the textbook interval for 5 of 10
        self.assertAlmostEqual(lo, 0.1871, places=4)
        self.assertAlmostEqual(hi, 0.8129, places=4)
        for n in (12, 30, 40, 76, 353):  # 0 of n and n of n have closed forms
            self.assertAlmostEqual(stats.exact_ci(0, n)[1], 1 - 0.025 ** (1 / n), places=8)
            self.assertAlmostEqual(stats.exact_ci(n, n)[0], 0.025 ** (1 / n), places=8)
            self.assertEqual(stats.exact_ci(0, n)[0], 0.0)
            self.assertEqual(stats.exact_ci(n, n)[1], 1.0)
        lo, hi = stats.exact_ci(44, 54)
        self.assertTrue(lo < 44 / 54 < hi)

    def test_mcnemar(self):
        self.assertAlmostEqual(stats.mcnemar(10, 0), 2 * 0.5 ** 10)
        self.assertEqual(stats.mcnemar(0, 0), 1.0)
        self.assertEqual(stats.mcnemar(3, 2), 1.0)
        self.assertAlmostEqual(stats.mcnemar(8, 1), 2 * (1 + 9) * 0.5 ** 9)
        self.assertTrue(math.isclose(stats.mcnemar(5, 0), 0.0625))

    def test_holm(self):
        adjusted = stats.holm({"a": 0.01, "b": 0.04, "c": 0.03})  # 3 x 0.01; then 2 x 0.03; then max(that, 0.04)
        self.assertAlmostEqual(adjusted["a"], 0.03)
        self.assertAlmostEqual(adjusted["c"], 0.06)
        self.assertAlmostEqual(adjusted["b"], 0.06)
        self.assertEqual(stats.holm({"x": 0.7, "y": 0.9}), {"x": 1.0, "y": 1.0})

    def test_two_versions_paired_sample_by_sample(self):
        def row(stratum, now, before, name):
            return {"set": stratum, "package": name, "version": "1", "verdict": now, "verdict_baseline": before,
                    "rules": {}}
        rows = ([row("npm/malicious_intent", "block", "pass", f"m{i}") for i in range(8)]
                + [row("npm/malicious_intent", "pass", "warn", "lost")]
                + [row("npm/malicious_intent", "block", "block", f"k{i}") for i in range(3)]
                + [row("npm/popular", "pass", "warn", f"p{i}") for i in range(4)]
                + [row("npm/popular", "warn", "pass", "newly-flagged")]
                + [{"set": "npm/popular", "package": "e", "version": "1", "error": "HTTPError: 404"}])
        out = stats.paired_rounds(rows)
        m = out["sets"]["npm/malicious_intent"]
        self.assertEqual((m["only_now"], m["only_before"], m["now"]["k"], m["before"]["k"], m["now"]["n"]),
                         (8, 1, 11, 4, 12))
        self.assertAlmostEqual(m["p"], stats.mcnemar(8, 1))
        b = out["sets"]["npm/popular"]
        self.assertEqual((b["only_now"], b["only_before"], b["left_out"], b["now"]["n"]), (1, 4, 1, 5))
        self.assertEqual(out["lost"], [("npm/malicious_intent", "lost", "1")])
        self.assertEqual(out["false_alarms"], [("npm", "newly-flagged", "1", "warn")])
        self.assertEqual((out["overall"]["malicious"]["only_now"], out["overall"]["benign"]["only_before"]), (8, 4))
        self.assertGreaterEqual(out["overall"]["malicious"]["p_holm"], out["overall"]["malicious"]["p"])

    def test_report_is_current(self):
        report = stats.markdown(stats.analyse())
        self.assertEqual((ROOT / "docs" / "statistics.md").read_text(encoding="utf-8"), report,
                         "docs/statistics.md is stale: run python bench/stats.py")


if __name__ == "__main__":
    unittest.main()
