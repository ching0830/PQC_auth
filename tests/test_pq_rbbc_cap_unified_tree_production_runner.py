import copy
import json
from pathlib import Path
import tempfile
import unittest

import pq_rbbc_cap_unified_tree as unified
import pq_rbbc_cap_unified_tree_production_runner as runner


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    ROOT / "manifests/"
    "pq_rbbc_cap_unified_tree_production_runner_manifest_v2_35.json"
)
EXTERNAL = Path(
    "/tmp/pq_rbbc_external_artifacts_rebuilt/v2_35_unified_tree_runner/qualification"
)
EVIDENCE = EXTERNAL / runner.EVIDENCE_FILENAME
QUALIFICATION = EXTERNAL / runner.QUALIFICATION_FILENAME
STATE = EXTERNAL / runner.STATE_FILENAME


class UnifiedTreeProductionRunnerTests(unittest.TestCase):
    def test_manifest_and_relation_contract_are_frozen(self) -> None:
        self.assertEqual(
            MANIFEST.read_bytes(), runner.canonical_json(runner.build_manifest())
        )
        document = runner.validate_manifest(MANIFEST)
        contract = document["relation_contract"]
        self.assertEqual(
            document["relation_contract_sha256"],
            runner.RELATION_CONTRACT_SHA256,
        )
        self.assertEqual(contract["profile"]["total_leaves"], 40_960)
        self.assertEqual(contract["profile"]["internal_nodes"], 40_959)
        self.assertEqual(
            contract["planning_lower_bounds_not_observations"]["combined_rows"],
            589_054_075,
        )
        self.assertTrue(all(
            value is None
            for value in contract["pre_freeze_observations"].values()
        ))
        forbidden = " ".join(contract["forbidden_as_new_observations"])
        self.assertIn("tree 0-17 observed stream_bytes", forbidden)
        self.assertIn("v2.29 589030555-row transcript", forbidden)

    def test_production_shaped_profile_has_all_18_logical_vectors(self) -> None:
        parameters = runner.QUALIFICATION_PARAMETERS
        self.assertEqual(parameters.vector_count, 18)
        self.assertEqual(parameters.logical_leaf_counts, (4, 4) + (2,) * 16)
        self.assertEqual(parameters.total_leaves, 40)
        observed = set()
        for repetition, leaves in enumerate(parameters.logical_leaf_counts):
            for position in range(leaves):
                index = unified.logical_to_unified_index(
                    parameters, repetition, position
                )
                self.assertEqual(
                    unified.unified_to_logical_index(parameters, index),
                    (repetition, position),
                )
                observed.add(index)
        self.assertEqual(observed, set(range(40)))

    def test_external_qualification_evidence_is_exact_and_bounded(self) -> None:
        self.assertEqual(
            runner.identity(EVIDENCE),
            {
                "filename": runner.EVIDENCE_FILENAME,
                "bytes": 5_506,
                "sha256": (
                    "f17a82f67785612b040301893852eb72ee46eabe21e93dd017fc69d8599e3659"
                ),
            },
        )
        document = json.loads(EVIDENCE.read_text())
        self.assertEqual(document["deterministic_result_identity"], (
            "5075ebcbabb7cfa95a459f27a21bf2a0db11b7ef0f7ec69e30a4414f0c3a2a0f"
        ))
        stages = {stage["stage"]: stage for stage in document["stages"]}
        self.assertEqual(stages["commit"]["leaf_count"], 40)
        self.assertEqual(stages["commit"]["xof_call_count"], 138)
        self.assertEqual(stages["opening"]["counter"], 4)
        self.assertEqual(stages["opening"]["trials"], 5)
        self.assertEqual(stages["opening"]["frontier_count"], 12)
        self.assertTrue(stages["verify"]["accepted"])
        resources = document["resource_measurements"]
        self.assertEqual(resources["qualification_leaves_expanded"], 40)
        self.assertEqual(resources["production_leaves_expanded"], 0)
        self.assertEqual(resources["relation_rows_replayed"], 0)
        self.assertEqual(resources["proofs_generated"], 0)
        claims = document["claim_boundary"]
        self.assertTrue(claims["v2_35_runner_skeleton_implemented"])
        self.assertFalse(claims["production_profile_implemented"])
        self.assertFalse(claims["production_runner_qualified"])

    def test_runner_qualification_freezes_control_flow_only(self) -> None:
        self.assertEqual(
            runner.identity(QUALIFICATION),
            {
                "filename": runner.QUALIFICATION_FILENAME,
                "bytes": 1_867,
                "sha256": (
                    "f124f9b27d5c6b6a82ff717ddf148ef683c43a0cc4e16ff47961cc7ba6e59329"
                ),
            },
        )
        document = json.loads(QUALIFICATION.read_text())
        checks = document["checks"]
        for key in (
            "fresh_qualification_completed",
            "interrupted_after_plan",
            "resume_state_identity_revalidated",
            "resumed_result_matches_fresh_result",
            "existing_output_overwrite_refused",
            "production_branch_rejected_before_output",
        ):
            self.assertTrue(checks[key], key)
        self.assertFalse(checks["state_uses_pickle"])
        self.assertEqual(checks["production_leaves_expanded"], 0)
        self.assertEqual(checks["relation_rows_replayed"], 0)
        self.assertTrue(document["result"]["runner_skeleton_qualified"])
        self.assertFalse(document["result"]["production_runner_qualified"])
        self.assertFalse(
            document["result"]["safe_to_start_production_prefreeze"]
        )

    def test_production_branch_rejects_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            with self.assertRaisesRegex(RuntimeError, "production-prefreeze unavailable"):
                runner.reject_production_prefreeze(
                    MANIFEST, output, Path(directory) / "fake-authorization.json", True
                )
            self.assertFalse(output.exists())

    def test_manifest_and_resume_mutations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            manifest_document = json.loads(MANIFEST.read_text())
            manifest_document["authorization_scope"][
                "production_prefreeze_authorized"
            ] = True
            changed_manifest = base / MANIFEST.name
            changed_manifest.write_bytes(runner.canonical_json(manifest_document))
            with self.assertRaisesRegex(ValueError, "not the frozen"):
                runner.validate_manifest(changed_manifest)

            state_document = json.loads(STATE.read_text())
            state_document["contract"]["production_profile_permitted"] = True
            changed_state = base / STATE.name
            changed_state.write_bytes(runner.canonical_json(state_document))
            with self.assertRaisesRegex(ValueError, "resume state identity mismatch"):
                runner._load_state(changed_state, runner.state_contract(MANIFEST))

    def test_claim_boundary_does_not_promote_production(self) -> None:
        claims = runner.claim_boundary()
        for key in (
            "v2_35_relation_contract_authored",
            "v2_35_runner_skeleton_implemented",
            "production_shaped_qualification_fixture_implemented",
            "legacy_18_tree_profile_preserved",
        ):
            self.assertTrue(claims[key], key)
        for key in (
            "production_profile_implemented",
            "production_checkpoint_payload_implemented",
            "production_runner_qualified",
            "production_relation_contract_frozen_by_observation",
            "resource_reservation_frozen",
            "independent_review_frozen",
            "production_prefreeze_authorized",
            "production_prefreeze_started",
            "large_replay_started",
            "large_proving_run_started",
            "cap_security_qualified",
            "fork_security_proof_revalidated",
            "system_architecture_changed",
            "ticket_lifecycle_changed",
            "pq_sat_auth_changed",
            "production_closed",
        ):
            self.assertFalse(claims[key], key)


if __name__ == "__main__":
    unittest.main()
