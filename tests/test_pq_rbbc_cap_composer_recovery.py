#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.18 composer recovery gate."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_composer_recovery as recovery


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifests" / recovery.MANIFEST_NAME


class ComposerRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generated = recovery.build_preflight_manifest()
        cls.frozen = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_contract_binds_the_frozen_v28_production_identity(self) -> None:
        contract = recovery.build_contract()
        self.assertEqual(
            recovery.contract_sha256(contract), recovery.FROZEN_CONTRACT_SHA256
        )
        self.assertEqual(contract.source_relation_id, composer.RELATION_ID)
        self.assertEqual(
            contract.source_document_sha256, composer.FROZEN_DOCUMENT_SHA256
        )
        self.assertEqual(
            contract.source_commitment_sha256,
            composer.FROZEN_COMMITMENT_SHA256,
        )
        self.assertEqual(
            contract.source_xof_trace_sha256,
            composer.FROZEN_XOF_TRACE_SHA256,
        )
        self.assertEqual(contract.production_tree_count, 18)
        self.assertEqual(
            contract.production_tree_shapes,
            ((4096, 13),) * 2 + ((2048, 12),) * 16,
        )

    def test_interrupted_resume_is_bit_exact_on_the_real_reduced_composer(self) -> None:
        evidence = self.generated["reduced_recovery_fixture"]
        self.assertEqual(evidence["tree_count"], 2)
        self.assertEqual(
            tuple(tuple(item) for item in evidence["tree_shapes"]),
            ((4, 3), (4, 3)),
        )
        self.assertTrue(evidence["resume_observed"])
        self.assertEqual(evidence["checkpoints_written_after_resume"], 4)
        self.assertEqual(
            evidence["direct_execution_sha256"],
            recovery.FROZEN_REDUCED_EXECUTION_SHA256,
        )
        self.assertEqual(
            evidence["resumed_execution_sha256"],
            recovery.FROZEN_REDUCED_EXECUTION_SHA256,
        )
        self.assertTrue(evidence["execution_bit_exact"])
        self.assertEqual(evidence["final_checkpoint_phase"], "complete")
        self.assertEqual(
            evidence["final_checkpoint_sha256"],
            recovery.FROZEN_REDUCED_FINAL_CHECKPOINT_SHA256,
        )
        self.assertEqual(evidence["execution_cache_validation_failures"], 0)
        self.assertTrue(evidence["fixture_is_not_production_execution_evidence"])

    def test_all_checkpoint_mutations_fail_closed(self) -> None:
        probes = self.generated["checkpoint_mutation_probes"]
        self.assertEqual(len(probes), 8)
        self.assertTrue(all(item["rejected"] for item in probes))
        self.assertTrue(all(item["failures"] for item in probes))

    def test_saved_interruption_is_loadable_and_wrong_randomness_rejects(self) -> None:
        parameters = cap.REDUCED_TEST_PARAMETERS
        randomness = cap.deterministic_randomness(parameters)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "execution.checkpoint.pkl"
            with self.assertRaises(recovery.CheckpointPause):
                recovery.build_checkpointed_execution(
                    parameters,
                    randomness,
                    path,
                    workers=1,
                    leaf_batch=2,
                    stop_after_checkpoints=1,
                )
            checkpoint = recovery.load_checkpoint(path, parameters, randomness)
            self.assertEqual(checkpoint.phase, "leaves")
            wrong_randomness = cap.deterministic_randomness(
                parameters, b"PQ-RBBC/v2.18/wrong-randomness"
            )
            with self.assertRaisesRegex(ValueError, "wrong_randomness"):
                recovery.load_checkpoint(path, parameters, wrong_randomness)

    def test_preflight_manifest_is_frozen_and_conservative(self) -> None:
        self.assertEqual(json.loads(json.dumps(self.generated)), self.frozen)
        production = self.generated["production_recovery"]
        self.assertEqual(production["status"], "not_started")
        self.assertEqual(production["production_derivation_levels_checkpointed"], 0)
        self.assertEqual(production["production_leaf_outputs_checkpointed"], 0)
        claims = self.generated["claim_boundary"]
        self.assertTrue(
            claims["production_composer_checkpoint_recovery_gate_closed"]
        )
        self.assertTrue(claims["reduced_checkpoint_resume_bit_exact"])
        for name in (
            "production_execution_cache_regenerated",
            "production_global_tail_archive_regenerated",
            "production_tree2_rebased_assignment_materialized",
            "production_tree2_rebased_full_replay_closed",
            "representative_producers_rebased_replayed",
            "complete_18_tree_assignment_replayed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_production_recovery_refuses_existing_outputs_before_execution(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "existing-cache.pkl"
            cache.write_bytes(b"do-not-overwrite")
            with self.assertRaisesRegex(FileExistsError, "refusing to replace"):
                recovery.run_production_recovery(
                    root / "checkpoint.pkl",
                    cache,
                    root / "composition.json",
                    workers=1,
                    leaf_batch=2,
                    replace_checkpoint=False,
                    replace_outputs=False,
                    progress=None,
                )
            self.assertEqual(cache.read_bytes(), b"do-not-overwrite")


if __name__ == "__main__":
    unittest.main()
