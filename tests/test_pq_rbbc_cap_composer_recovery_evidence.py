#!/usr/bin/env python3
"""Regression tests for the sealed PQ-RBBC v2.19 recovery evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path

import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_composer_recovery as recovery
import pq_rbbc_cap_composer_recovery_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT
    / "artifacts"
    / "metadata"
    / "production_recovery_v2_19"
    / evidence.MANIFEST_NAME
)


class ComposerRecoveryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.frozen_bytes = MANIFEST_PATH.read_bytes()
        cls.frozen = json.loads(cls.frozen_bytes)

    def test_portable_evidence_is_frozen(self) -> None:
        generated = evidence.build_frozen_evidence_document()
        self.assertEqual(generated, self.frozen)
        self.assertEqual(evidence.validate_evidence_document(generated), ())
        self.assertEqual(evidence.verify_frozen_evidence(MANIFEST_PATH), ())
        self.assertEqual(
            hashlib.sha256(self.frozen_bytes).hexdigest(),
            evidence.FROZEN_EVIDENCE_SHA256,
        )

    def test_recovered_execution_matches_every_v28_identity(self) -> None:
        source = self.frozen["source_recovery"]
        execution = self.frozen["production_execution"]
        document = self.frozen["composition_document"]
        self.assertEqual(source["contract_sha256"], recovery.FROZEN_CONTRACT_SHA256)
        self.assertTrue(source["resumed_checkpoint"])
        self.assertEqual(source["checkpoint_phase"], "complete")
        self.assertEqual(source["derivation_levels_checkpointed"], 182)
        self.assertEqual(source["derivations_checkpointed"], 40_924)
        self.assertEqual(source["seed_nodes_checkpointed"], 40_960)
        self.assertEqual(source["leaf_outputs_checkpointed"], 40_960)
        self.assertEqual(execution["tree_count"], 18)
        self.assertEqual(execution["leaf_count"], 40_960)
        self.assertEqual(execution["xof_calls"], 122_847)
        self.assertEqual(
            execution["commitment_sha256"], composer.FROZEN_COMMITMENT_SHA256
        )
        self.assertEqual(
            execution["xof_trace_sha256"], composer.FROZEN_XOF_TRACE_SHA256
        )
        self.assertEqual(
            document["document_sha256"], composer.FROZEN_DOCUMENT_SHA256
        )
        self.assertTrue(document["mutation_probes_rejected"])

    def test_claim_boundary_advances_only_the_recovery_result(self) -> None:
        claims = self.frozen["claim_boundary"]
        self.assertTrue(claims["production_execution_cache_regenerated"])
        self.assertTrue(claims["production_composition_document_revalidated"])
        for name in (
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

    def test_portable_evidence_contains_no_local_paths_or_pickle(self) -> None:
        encoded = self.frozen_bytes.decode("ascii")
        self.assertNotIn("/workspace/", encoded)
        self.assertNotIn("checkpoint_path", encoded)
        self.assertNotIn("execution_cache_path", encoded)
        policy = self.frozen["artifact_policy"]
        self.assertFalse(policy["large_artifacts_tracked_in_git"])
        self.assertFalse(policy["portable_evidence_contains_absolute_paths"])
        self.assertTrue(policy["untrusted_pickle_must_never_be_loaded"])

    def test_identity_and_claim_mutations_fail_closed(self) -> None:
        mutations = []
        wrong_source = copy.deepcopy(self.frozen)
        wrong_source["source_recovery"]["checkpoint_state_sha256"] = "00" * 32
        mutations.append(wrong_source)
        wrong_cache = copy.deepcopy(self.frozen)
        wrong_cache["production_execution"]["execution_cache_sha256"] = "11" * 32
        mutations.append(wrong_cache)
        wrong_document = copy.deepcopy(self.frozen)
        wrong_document["composition_document"]["document_sha256"] = "22" * 32
        mutations.append(wrong_document)
        wrong_policy = copy.deepcopy(self.frozen)
        wrong_policy["artifact_policy"]["large_artifacts_tracked_in_git"] = True
        mutations.append(wrong_policy)
        overclaim = copy.deepcopy(self.frozen)
        overclaim["claim_boundary"]["production_closed"] = True
        mutations.append(overclaim)
        for changed in mutations:
            self.assertTrue(evidence.validate_evidence_document(changed))

    def test_optional_trusted_external_artifacts_reseal_exactly(self) -> None:
        root_value = os.environ.get("PQRBBC_V2_19_RECOVERY_ROOT")
        if not root_value:
            self.skipTest("trusted external v2.19 recovery artifacts are not installed")
        root = Path(root_value)
        generated = evidence.build_evidence_from_artifacts(
            root / "pq_rbbc_cap_composer_recovery_manifest_v2_18.json",
            root / "pq_rbbc_cap_composer_checkpoint_v2_18.pkl",
            root / "pq_rbbc_cap_composition_execution_v2_8.pkl",
            root / "pq_rbbc_cap_composition_manifest_v2_8.json",
        )
        self.assertEqual(generated, self.frozen)


if __name__ == "__main__":
    unittest.main()
