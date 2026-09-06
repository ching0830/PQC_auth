import unittest

import pq_rbbc_cap_tree11_17_recovery_evidence as evidence


class Tree11To17RecoveryEvidenceTests(unittest.TestCase):
    def test_expected_manifest_set_is_exact(self) -> None:
        self.assertEqual(sorted(evidence.EXPECTED_MANIFESTS), list(range(11, 18)))

    def test_claim_boundary_is_bounded(self) -> None:
        claims = evidence.claim_boundary()
        self.assertEqual(claims["materialized_planned_tree_count"], 18)
        self.assertTrue(claims["remaining_planned_tree_producers_materialized"])
        self.assertTrue(claims["all_72_output_relocations_closed"])
        for name in (
            "complete_18_tree_assignment_replayed",
            "cross_segment_wire_identity_closed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name])


if __name__ == "__main__":
    unittest.main()
