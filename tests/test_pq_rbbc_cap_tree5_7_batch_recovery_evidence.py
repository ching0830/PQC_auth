#!/usr/bin/env python3
"""Regression tests for PQ-RBBC v2.25 tree-5 through tree-7 evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path

import pq_rbbc_cap_tree5_7_batch_recovery_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "artifacts" / "metadata" / "tree5_7_batch_recovery_v2_25" / evidence.MANIFEST_NAME
GLOBAL_MANIFEST_PATH = ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"


class Tree5Through7BatchRecoveryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.frozen_bytes = MANIFEST_PATH.read_bytes()
        cls.frozen = json.loads(cls.frozen_bytes)

    def test_portable_evidence_is_frozen(self) -> None:
        generated = evidence.build_frozen_evidence_document()
        self.assertEqual(generated, self.frozen)
        self.assertEqual(evidence.validate_evidence_document(generated), ())
        self.assertEqual(evidence.verify_frozen_evidence(MANIFEST_PATH), ())
        self.assertEqual(hashlib.sha256(self.frozen_bytes).hexdigest(), evidence.FROZEN_EVIDENCE_SHA256)

    def test_each_tree_is_independently_sealed(self) -> None:
        trees = self.frozen["production_tree_batch"]
        self.assertEqual([item["tree_index"] for item in trees], [5, 6, 7])
        for item in trees:
            frozen = evidence.FROZEN_TREES[item["tree_index"]]
            self.assertEqual(item["rows"], evidence.FROZEN_ROWS)
            self.assertEqual(item["wires"], evidence.FROZEN_WIRES)
            self.assertEqual(item["row_stream_bytes"], evidence.FROZEN_STREAM_BYTES)
            self.assertEqual(item["archive_sha256"], frozen["archive_sha256"])
            self.assertEqual(item["row_stream_sha256"], frozen["stream_sha256"])
            self.assertEqual(item["tree_component_sha256"], frozen["tree_component_sha256"])
            self.assertEqual(item["external_assertions"], 0)
            self.assertEqual(item["replay_failures"], 0)
            self.assertTrue(item["all_mutation_probes_rejected"])
            self.assertTrue(all(output["exact_value_match"] for output in item["output_matches"]))

    def test_claim_boundary_advances_exactly_through_tree7(self) -> None:
        claims = self.frozen["claim_boundary"]
        self.assertEqual(claims["materialized_planned_tree_indices"], list(range(8)))
        self.assertEqual(claims["materialized_planned_tree_count"], 8)
        for tree_index in (5, 6, 7):
            self.assertTrue(claims[f"production_tree{tree_index}_planned_assignment_materialized"])
            self.assertTrue(claims[f"production_tree{tree_index}_planned_full_replay_closed"])
        for name in ("remaining_planned_tree_producers_materialized", "all_72_output_relocations_closed", "complete_18_tree_assignment_replayed", "cross_segment_wire_identity_closed", "parent_cap_to_h_rbbc_join_closed", "fork_security_proof_revalidated", "production_closed"):
            self.assertFalse(claims[name], name)

    def test_portable_evidence_contains_no_local_paths_or_assignment(self) -> None:
        encoded = self.frozen_bytes.decode("ascii")
        self.assertNotIn("/workspace/", encoded)
        self.assertNotIn("archive_path", encoded)
        self.assertFalse(self.frozen["artifact_policy"]["large_artifacts_tracked_in_git"])
        self.assertFalse(self.frozen["artifact_policy"]["trusted_pickle_cache_tracked_in_git"])

    def test_identity_and_overclaim_mutations_fail_closed(self) -> None:
        mutations = []
        for tree_offset, key in ((0, "archive_sha256"), (1, "row_stream_sha256"), (2, "tree_component_sha256")):
            changed = copy.deepcopy(self.frozen)
            changed["production_tree_batch"][tree_offset][key] = "00" * 32
            mutations.append(changed)
        wrong_output = copy.deepcopy(self.frozen)
        wrong_output["production_tree_batch"][2]["output_matches"][0]["exact_value_match"] = False
        mutations.append(wrong_output)
        overclaim = copy.deepcopy(self.frozen)
        overclaim["claim_boundary"]["production_closed"] = True
        mutations.append(overclaim)
        for changed in mutations:
            self.assertTrue(evidence.validate_evidence_document(changed))

    def test_optional_external_artifacts_reseal_exactly(self) -> None:
        root_value = os.environ.get("PQRBBC_V2_25_BATCH_ROOT")
        if not root_value:
            self.skipTest("external v2.25 batch artifacts are not installed")
        generated = evidence.build_evidence_from_artifacts(Path(root_value), GLOBAL_MANIFEST_PATH)
        self.assertEqual(generated, self.frozen)


if __name__ == "__main__":
    unittest.main()
