import unittest
from pathlib import Path

import pq_rbbc_cap_unified_tree_migration_preflight as preflight


ROOT = Path(__file__).resolve().parents[1]


class UnifiedTreeMigrationPreflightTests(unittest.TestCase):
    def test_tracked_inputs_and_legacy_profile_are_exact(self) -> None:
        self.assertEqual(preflight.validate_tracked_inputs(), ())
        self.assertEqual(
            preflight.LEGACY_PROFILE_FINGERPRINT,
            "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38",
        )

    def test_reserved_profile_is_distinct_and_preserves_legacy(self) -> None:
        descriptor = preflight.reserved_profile_descriptor()
        self.assertEqual(
            descriptor["relation_id"], preflight.RESERVED_PROFILE_RELATION_ID
        )
        self.assertNotEqual(descriptor["name"], preflight.LEGACY_PROFILE_NAME)
        self.assertTrue(descriptor["base_profile"]["preserved_unchanged"])
        self.assertFalse(
            descriptor["base_profile"]["accepted_as_new_profile_evidence"]
        )
        self.assertNotEqual(
            bytes.fromhex(descriptor["reserved_serialization"]["commitment_magic_hex"]),
            preflight.legacy_cap.COMMITMENT_MAGIC,
        )
        self.assertTrue(descriptor["domain_policy"]["all_cap_domains_must_be_new"])

    def test_interleaved_mapping_is_a_bijection(self) -> None:
        observed = set()
        for repetition, leaves in enumerate(preflight.logical_leaf_counts()):
            for position in range(leaves):
                index = preflight.unified_leaf_index(repetition, position)
                self.assertEqual(
                    preflight.inverse_unified_leaf_index(index),
                    (repetition, position),
                )
                observed.add(index)
        self.assertEqual(observed, set(range(preflight.UNIFIED_LEAVES)))
        self.assertEqual(preflight.UNIFIED_LEAVES, 40_960)

    def test_impact_forbids_reusing_old_tree_observations(self) -> None:
        impact = preflight.migration_impact_contract()
        forbidden = " ".join(impact["must_not_be_reused_as_new_observation"])
        self.assertIn("stream_bytes", forbidden)
        self.assertIn("589030555", forbidden)
        rebuilt = " ".join(impact["must_be_rebuilt_or_replayed"])
        self.assertIn("global tail", rebuilt)
        self.assertIn("parent CAP-to-H_RBBC", rebuilt)
        self.assertFalse(
            impact["claim_boundary"]["legacy_evidence_invalidated"]
        )

    def test_resource_projection_is_conservative_not_exact(self) -> None:
        estimate = preflight.resource_estimate()
        projection = estimate["unified_tree_projection"]
        self.assertEqual(projection["additional_seed_derive_calls_vs_legacy"], 35)
        self.assertEqual(
            projection["projected_min_additional_rows_if_all_other_topology_is_unchanged"],
            23_520,
        )
        self.assertEqual(projection["projected_min_combined_rows"], 589_054_075)
        self.assertFalse(projection["exact_rows_known"])
        self.assertFalse(
            estimate["recommended_execution_envelope"][
                "elapsed_time_estimate_available"
            ]
        )
        self.assertGreater(estimate["pow_grinding"]["expected_trials"], 15_000)

    def test_exact_commands_do_not_authorize_large_execution(self) -> None:
        commands = preflight.exact_command_contract()
        self.assertIn("--report", commands["read_only_preflight"])
        for phase in (
            "production_prefreeze",
            "production_frozen_replay",
            "aggregate_parent_replay",
        ):
            self.assertFalse(commands[phase]["executable_now"])
            self.assertFalse(commands[phase]["authorized_now"])
            self.assertIn("--allow-large", commands[phase]["command"])

    def test_missing_migration_artifacts_never_start_large_work(self) -> None:
        report = preflight.build_environment_report({}, {})
        self.assertTrue(report["safe_to_run_read_only_preflight"])
        self.assertFalse(report["safe_to_author_unified_tree_specification"])
        self.assertFalse(report["safe_to_implement_reduced_prototype"])
        self.assertFalse(report["safe_to_start_production_prefreeze"])
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["safe_to_start_large_proving_run"])
        self.assertFalse(report["large_profile_build_started"])
        self.assertFalse(report["large_replay_started"])

    def test_claim_boundary_records_authorization_without_completion(self) -> None:
        claims = preflight.claim_boundary()
        for name in (
            "v2_33_read_only_migration_preflight_closed",
            "unified_tree_namespace_reserved",
            "migration_impact_contract_frozen",
            "migration_authorization_recorded",
            "legacy_18_tree_profile_preserved",
        ):
            self.assertTrue(claims[name], name)
        for name in (
            "unified_tree_profile_implemented",
            "unified_tree_profile_fingerprint_frozen",
            "unified_tree_runner_qualified",
            "reduced_prototype_verified",
            "production_prefreeze_started",
            "large_replay_started",
            "large_proving_run_started",
            "cap_security_qualified",
            "production_closed",
            "system_architecture_changed",
            "ticket_lifecycle_changed",
            "pq_sat_auth_changed",
        ):
            self.assertFalse(claims[name], name)

    def test_frozen_manifest_matches_generator(self) -> None:
        path = ROOT / "manifests/pq_rbbc_cap_unified_tree_migration_manifest_v2_33.json"
        self.assertEqual(path.read_bytes(), preflight.canonical_json(preflight.build_frozen_manifest()))


if __name__ == "__main__":
    unittest.main()
