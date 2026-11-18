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

    def test_report_is_current(self):
        report = stats.markdown(stats.analyse())
        self.assertEqual((ROOT / "docs" / "statistics.md").read_text(encoding="utf-8"), report,
                         "docs/statistics.md is stale: run python bench/stats.py")


if __name__ == "__main__":
    unittest.main()
