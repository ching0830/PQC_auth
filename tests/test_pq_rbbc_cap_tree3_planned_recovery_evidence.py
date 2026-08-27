#!/usr/bin/env python3
"""Regression tests for PQ-RBBC v2.23 tree-3 planned evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path

import pq_rbbc_cap_tree3_planned_recovery_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT
    / "artifacts"
    / "metadata"
    / "tree3_planned_recovery_v2_23"
    / evidence.MANIFEST_NAME
)
GLOBAL_MANIFEST_PATH = ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"


class Tree3PlannedRecoveryEvidenceTests(unittest.TestCase):
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

    def test_archive_and_replay_identities_are_exact(self) -> None:
        replay = self.frozen["production_tree3_planned"]
        self.assertEqual(replay["rows"], 25_666_386)
        self.assertEqual(replay["wires"], 19_478_436)
        self.assertEqual(replay["archive_bytes"], 486_961_028)
        self.assertEqual(replay["archive_sha256"], evidence.FROZEN_ARCHIVE_SHA256)
        self.assertEqual(replay["body_sha256"], evidence.FROZEN_BODY_SHA256)
        self.assertEqual(replay["row_stream_bytes"], 8_961_160_824)
        self.assertEqual(replay["row_stream_sha256"], evidence.FROZEN_STREAM_SHA256)
        self.assertEqual(replay["external_assertions"], 0)
        self.assertEqual(replay["replay_failures"], 0)
        self.assertTrue(replay["all_mutation_probes_rejected"])
        self.assertTrue(
            all(item["exact_value_match"] for item in replay["output_matches"])
        )

    def test_claim_boundary_advances_only_tree3_replay(self) -> None:
        claims = self.frozen["claim_boundary"]
        self.assertTrue(claims["production_tree3_planned_assignment_materialized"])
        self.assertTrue(claims["production_tree3_planned_full_replay_closed"])
        self.assertTrue(claims["production_tree1_planned_assignment_materialized"])
        self.assertTrue(claims["production_tree1_planned_full_replay_closed"])
        self.assertEqual(claims["materialized_planned_tree_indices"], [0, 1, 2, 3])
        self.assertEqual(claims["materialized_planned_tree_count"], 4)
        for name in (
            "remaining_planned_tree_producers_materialized",
            "all_72_output_relocations_closed",
            "complete_18_tree_assignment_replayed",
            "cross_segment_wire_identity_closed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_portable_evidence_contains_no_local_paths_or_assignment(self) -> None:
        encoded = self.frozen_bytes.decode("ascii")
        self.assertNotIn("/workspace/", encoded)
        self.assertNotIn("archive_path", encoded)
        policy = self.frozen["artifact_policy"]
        self.assertFalse(policy["large_artifacts_tracked_in_git"])
        self.assertFalse(policy["portable_evidence_contains_absolute_paths"])
        self.assertFalse(policy["trusted_pickle_cache_tracked_in_git"])

    def test_identity_and_overclaim_mutations_fail_closed(self) -> None:
        mutations = []
        wrong_archive = copy.deepcopy(self.frozen)
        wrong_archive["production_tree3_planned"]["archive_sha256"] = "00" * 32
        mutations.append(wrong_archive)
        wrong_stream = copy.deepcopy(self.frozen)
        wrong_stream["production_tree3_planned"]["row_stream_sha256"] = "11" * 32
        mutations.append(wrong_stream)
        wrong_output = copy.deepcopy(self.frozen)
        wrong_output["production_tree3_planned"]["output_matches"][0][
            "exact_value_match"
        ] = False
        mutations.append(wrong_output)
        overclaim = copy.deepcopy(self.frozen)
        overclaim["claim_boundary"]["production_closed"] = True
        mutations.append(overclaim)
        for changed in mutations:
            self.assertTrue(evidence.validate_evidence_document(changed))

    def test_optional_external_artifacts_reseal_exactly(self) -> None:
        root_value = os.environ.get("PQRBBC_V2_23_TREE3_ROOT")
        if not root_value:
            self.skipTest("external v2.23 tree-3 artifacts are not installed")
        root = Path(root_value)
        generated = evidence.build_evidence_from_artifacts(
            root / "pq_rbbc_production_tree_3_producer_v2_23_planned.f193assign",
            root / "pq_rbbc_cap_planned_tree3_replayed_manifest_v2_23.json",
            GLOBAL_MANIFEST_PATH,
        )
        self.assertEqual(generated, self.frozen)


if __name__ == "__main__":
    unittest.main()
