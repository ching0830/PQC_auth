import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_unified_tree as unified
import pq_rbbc_cap_unified_tree_runner as runner


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/pq_rbbc_cap_unified_tree_migration_manifest_v2_33.json"


class UnifiedTreeRunnerTests(unittest.TestCase):
    def test_manifest_contract_is_exact(self) -> None:
        document = runner.validate_manifest(MANIFEST)
        descriptor = document["reserved_profile_descriptor"]
        self.assertEqual(descriptor["relation_id"], unified.RELATION_ID)
        self.assertEqual(descriptor["unified_tree"]["root_seed_count"], 1)
        self.assertEqual(descriptor["unified_tree"]["leaves"], 40_960)

    def test_fresh_resume_and_overwrite_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reduced"
            self.assertIsNone(runner.run_reduced(
                MANIFEST,
                output,
                fresh_cache=True,
                stop_after="commit",
                include_mutations=False,
            ))
            first = json.loads((output / runner.STATE_FILENAME).read_text())
            self.assertEqual(first["completed_stage_names"], ["commit"])
            self.assertIsNone(runner.run_reduced(
                MANIFEST,
                output,
                resume=True,
                stop_after="commit",
                include_mutations=False,
            ))
            second = json.loads((output / runner.STATE_FILENAME).read_text())
            self.assertEqual(first, second)
            with self.assertRaises(FileExistsError):
                runner.run_reduced(
                    MANIFEST,
                    output,
                    fresh_cache=True,
                    stop_after="commit",
                    include_mutations=False,
                )

    def test_state_contract_forbids_large_execution(self) -> None:
        contract = runner._state_contract(MANIFEST)
        self.assertEqual(contract["phase"], "reduced")
        self.assertFalse(contract["large_profile_permitted"])

    def test_evidence_claim_boundary_is_reduced_only(self) -> None:
        commit_stage = {"stage": "commit", "identity": "test"}
        opening_stage = {"stage": "opening", "identity": "test"}
        verify_stage = {
            "stage": "verify",
            "accepted": True,
            "failures": [],
            "opened_leaf_count": 8,
            "hidden_leaf_count": 4,
            "opened_tape_sha256": "00" * 32,
        }
        evidence = runner.build_reduced_evidence(
            runner._state_contract(MANIFEST),
            commit_stage,
            opening_stage,
            verify_stage,
            [],
            0.0,
            0,
        )
        claims = evidence["claim_boundary"]
        self.assertTrue(claims["reduced_positive_vector_verified"])
        self.assertFalse(claims["production_profile_implemented"])
        self.assertFalse(claims["large_replay_started"])
        self.assertFalse(claims["cap_security_qualified"])


if __name__ == "__main__":
    unittest.main()
