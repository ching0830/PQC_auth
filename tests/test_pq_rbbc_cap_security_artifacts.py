import unittest
from pathlib import Path

import pq_rbbc_cap_security_artifacts as artifacts


EXTERNAL_CACHE = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_19_composer_recovery/"
    "pq_rbbc_cap_composition_execution_v2_8.pkl"
)


class CAPSecurityArtifactsTests(unittest.TestCase):
    def test_tracked_authoring_sources_are_exact(self) -> None:
        artifacts.validate_tracked_sources()

    def test_numeric_mixed_tree_accounting_is_fail_closed(self) -> None:
        accounting = artifacts.numeric_advantage_accounting()
        self.assertEqual(accounting["tree_leaf_log2_sum"], 200)
        self.assertEqual(
            accounting["mixed_degree_accept_probability_without_pow"],
            "2^-182",
        )
        self.assertFalse(accounting["fork_pow_implemented"])
        self.assertFalse(accounting["paper_pow_may_be_added_to_fork_bound"])
        self.assertFalse(
            accounting["target_met_by_raw_tree_schedule_at_q_H_1"]
        )
        self.assertFalse(accounting["complete_total_bound_available"])
        by_budget = {
            item["q_H_log2"]: item
            for item in accounting["query_budget_diagnostics"]
        }
        self.assertEqual(
            by_budget[64]["dominant_listed_term_negative_log2"], 118
        )

    def test_estimate_never_requests_large_replay(self) -> None:
        estimate = artifacts.build_estimate()
        self.assertEqual(estimate["expected_oracle_records"], 122_847)
        self.assertFalse(estimate["large_row_replay"])
        self.assertFalse(estimate["trusted_pickle_will_be_committed"])
        self.assertFalse(estimate["qualification_claim_after_generation"])

    @unittest.skipUnless(
        EXTERNAL_CACHE.is_file(),
        "trusted local v2.19 execution cache is not installed",
    )
    def test_optional_trusted_cache_revalidates_without_replay(self) -> None:
        execution = artifacts.load_trusted_execution(EXTERNAL_CACHE)
        self.assertEqual(len(execution.xof_calls), 122_847)
        self.assertEqual(len(execution.commitment.encoded), 5_391)


if __name__ == "__main__":
    unittest.main()
