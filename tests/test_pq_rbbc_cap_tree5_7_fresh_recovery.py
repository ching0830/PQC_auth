from __future__ import annotations

import unittest

import pq_rbbc_cap_tree5_7_fresh_recovery as fresh


class Tree5Through7FreshRecoveryTests(unittest.TestCase):
    def test_format_and_targets_are_bounded(self) -> None:
        self.assertEqual(fresh.TARGETS, (5, 6, 7))
        self.assertEqual(fresh.FORMAT, "PQRBBC-CAP-TREE5-7-FRESH-RECOVERY-1")

    def test_performance_allowlist_is_narrow(self) -> None:
        self.assertEqual(
            fresh.PERFORMANCE_FIELDS,
            ("generation_seconds", "verification_seconds", "peak_rss_kib"),
        )


if __name__ == "__main__":
    unittest.main()
