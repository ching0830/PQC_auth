#!/usr/bin/env python3
"""Regression tests for sealed PQ-RBBC v2.20 global-tail recovery evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path

import pq_rbbc_cap_global_tail as global_tail
import pq_rbbc_cap_global_tail_recovery_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    ROOT
    / "artifacts"
    / "metadata"
    / "global_tail_recovery_v2_20"
    / evidence.MANIFEST_NAME
)
HISTORICAL_MANIFEST_PATH = (
    ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"
)


class GlobalTailRecoveryEvidenceTests(unittest.TestCase):
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

    def test_recovered_archive_matches_every_v29_identity(self) -> None:
        tail = self.frozen["production_global_tail"]
        self.assertEqual(tail["archive_bytes"], 1_004_865_028)
        self.assertEqual(
            tail["archive_sha256"],
            global_tail.FROZEN_PRODUCTION_ASSIGNMENT_SHA256,
        )
        self.assertEqual(tail["body_bytes"], 1_004_864_900)
        self.assertEqual(tail["body_sha256"], evidence.FROZEN_BODY_SHA256)
        self.assertEqual(tail["rows"], 56_806_711)
        self.assertEqual(tail["wires"], 40_194_596)
        self.assertEqual(
            tail["row_stream_sha256"],
            global_tail.FROZEN_PRODUCTION_STREAM_SHA256,
        )
        self.assertEqual(tail["external_assertions"], 0)
        self.assertEqual(tail["replay_failures"], 0)
        self.assertTrue(tail["stale_witness_probes_rejected"])

    def test_claim_boundary_advances_only_global_tail_recovery(self) -> None:
        claims = self.frozen["claim_boundary"]
        self.assertTrue(claims["production_execution_cache_regenerated"])
        self.assertTrue(claims["production_global_tail_archive_regenerated"])
        self.assertTrue(claims["production_global_tail_native_closed"])
        for name in (
            "production_tree2_rebased_assignment_materialized",
            "production_tree2_rebased_full_replay_closed",
            "representative_producers_rebased_replayed",
            "complete_18_tree_assignment_replayed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_portable_evidence_contains_no_local_paths_or_archive_bytes(self) -> None:
        encoded = self.frozen_bytes.decode("ascii")
        self.assertNotIn("/workspace/", encoded)
        self.assertNotIn("archive_path", encoded)
        policy = self.frozen["artifact_policy"]
        self.assertFalse(policy["large_artifacts_tracked_in_git"])
        self.assertFalse(policy["portable_evidence_contains_absolute_paths"])
        self.assertTrue(policy["archive_format_is_non_executable_binary"])

    def test_identity_and_claim_mutations_fail_closed(self) -> None:
        mutations = []
        wrong_archive = copy.deepcopy(self.frozen)
        wrong_archive["production_global_tail"]["archive_sha256"] = "00" * 32
        mutations.append(wrong_archive)
        wrong_body = copy.deepcopy(self.frozen)
        wrong_body["production_global_tail"]["body_sha256"] = "11" * 32
        mutations.append(wrong_body)
        wrong_replay = copy.deepcopy(self.frozen)
        wrong_replay["production_global_tail"]["replay_failures"] = 1
        mutations.append(wrong_replay)
        wrong_policy = copy.deepcopy(self.frozen)
        wrong_policy["artifact_policy"]["large_artifacts_tracked_in_git"] = True
        mutations.append(wrong_policy)
        overclaim = copy.deepcopy(self.frozen)
        overclaim["claim_boundary"]["production_closed"] = True
        mutations.append(overclaim)
        for changed in mutations:
            self.assertTrue(evidence.validate_evidence_document(changed))

    def test_optional_external_archive_reseals_exactly(self) -> None:
        root_value = os.environ.get("PQRBBC_V2_20_GLOBAL_TAIL_ROOT")
        if not root_value:
            self.skipTest("external v2.20 global-tail archive is not installed")
        root = Path(root_value)
        generated = evidence.build_evidence_from_artifacts(
            root / "pq_rbbc_cap_global_tail_assignment_v2_9.f193assign",
            root / "pq_rbbc_cap_global_tail_manifest_v2_9.json",
            HISTORICAL_MANIFEST_PATH,
        )
        self.assertEqual(generated, self.frozen)


if __name__ == "__main__":
    unittest.main()
