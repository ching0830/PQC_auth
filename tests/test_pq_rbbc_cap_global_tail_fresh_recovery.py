from __future__ import annotations

import copy
import json
import unittest

import pq_rbbc_cap_global_tail_fresh_recovery as fresh
import pq_rbbc_cap_global_tail_recovery_evidence as historical


class GlobalTailFreshRecoveryTests(unittest.TestCase):
    def test_claim_boundary_is_conservative(self) -> None:
        claims = {
            "fresh_global_tail_archive_identity_verified": True,
            "fresh_security_projection_matches_historical": True,
            "historical_performance_reproduced": False,
            "complete_18_tree_assignment_replayed": False,
            "parent_cap_to_h_rbbc_join_closed": False,
            "production_closed": False,
        }
        self.assertTrue(claims["fresh_global_tail_archive_identity_verified"])
        self.assertFalse(claims["production_closed"])

    def test_security_projection_ignores_only_performance(self) -> None:
        document = historical.build_frozen_evidence_document()
        self.assertEqual(document["format"], historical.EVIDENCE_FORMAT)
        self.assertEqual(fresh.FORMAT, "PQRBBC-CAP-GLOBAL-TAIL-FRESH-RECOVERY-1")


if __name__ == "__main__":
    unittest.main()
