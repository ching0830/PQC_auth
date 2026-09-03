import unittest

import pq_rbbc_cap_aggregate_preflight as preflight


class AggregatePreflightTests(unittest.TestCase):
    def test_frozen_contract_is_bounded(self) -> None:
        document = preflight.build_frozen_manifest()
        self.assertEqual(len(document["external_requirements"]["tree_assignments"]), 18)
        self.assertEqual(document["namespace"]["planned_composition_rows"], 586_057_567)
        self.assertTrue(document["runner_requirement"]["implemented_at_preflight_freeze"])
        claims = document["claim_boundary"]
        self.assertTrue(claims["aggregate_preflight_contract_closed"])
        for name, value in claims.items():
            if name not in (
                "aggregate_preflight_contract_closed",
                "aggregate_runner_implemented",
            ):
                self.assertFalse(value, name)

    def test_missing_artifacts_and_runner_fail_closed(self) -> None:
        report = preflight.build_environment_report(None, None, {}, 64_000_000_000, 32_000_000_000)
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["large_replay_started"])
        self.assertTrue(report["checks"]["aggregate_runner"]["verified"])
        self.assertEqual(len(report["checks"]["tree_assignments"]), 18)

    def test_tree_archive_parser_rejects_duplicates(self) -> None:
        with self.assertRaises(ValueError):
            preflight.parse_tree_archives(["1=/a", "1=/b"])

    def test_exact_command_names_all_tree_archives(self) -> None:
        command = preflight.exact_execution_command()
        for tree_index in range(18):
            self.assertIn(f"--tree-archive {tree_index}=", command)
        self.assertIn("pq_rbbc_cap_aggregate_replay.py", command)
        self.assertIn("--full-row-replay", command)


if __name__ == "__main__":
    unittest.main()
