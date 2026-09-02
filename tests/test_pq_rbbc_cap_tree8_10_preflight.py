#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.26 bounded preflight."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_tree8_10_preflight as preflight


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifests" / preflight.MANIFEST_NAME


class Tree8Through10PreflightTests(unittest.TestCase):
    def test_frozen_manifest_is_exact(self) -> None:
        encoded = MANIFEST_PATH.read_bytes()
        document = json.loads(encoded)
        self.assertEqual(document, preflight.build_frozen_manifest())
        self.assertEqual(preflight.verify_frozen_manifest(MANIFEST_PATH), ())
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(), preflight.FROZEN_MANIFEST_SHA256
        )

    def test_initial_contracts_keep_stream_bytes_unknown(self) -> None:
        document = preflight.build_frozen_manifest()
        self.assertEqual([item["tree_index"] for item in document["targets"]], [8, 9, 10])
        for target in document["targets"]:
            self.assertIsNone(target["contract"]["stream_bytes"])
            self.assertEqual(target["contract_validation_failures"], [])
            self.assertEqual(
                target["contract_sha256"],
                preflight.INITIAL_CONTRACT_SHA256[target["tree_index"]],
            )
            self.assertFalse(any(target["formal_target_claims"].values()))

    def test_claim_boundary_does_not_advance_replay(self) -> None:
        claims = preflight.build_frozen_manifest()["claim_boundary"]
        self.assertTrue(claims["bounded_preflight_contracts_closed"])
        for name, value in claims.items():
            if name != "bounded_preflight_contracts_closed":
                self.assertFalse(value, name)

    def test_missing_external_artifacts_fail_closed(self) -> None:
        report = preflight.build_environment_report(None, None, None)
        self.assertFalse(report["safe_to_start_large_replay"])
        self.assertFalse(report["large_replay_started"])
        self.assertTrue(report["checks"]["frozen_preflight_manifest"]["verified"])
        self.assertTrue(report["checks"]["tracked_global_tail_evidence"]["verified"])
        self.assertTrue(report["checks"]["tracked_tree5_7_batch_evidence"]["verified"])
        self.assertFalse(report["checks"]["global_tail_assignment"]["verified"])

    def test_wrong_external_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory) / "wrong.br1cs"
            wrong.write_bytes(b"wrong")
            check = preflight._file_identity(
                wrong,
                preflight.INCREMENTAL_BR1CS_BYTES,
                preflight.INCREMENTAL_BR1CS_SHA256,
            )
        self.assertFalse(check["verified"])
        self.assertIn("bytes", check["failures"])
        self.assertIn("sha256", check["failures"])

    def test_overclaim_changes_frozen_identity(self) -> None:
        changed = copy.deepcopy(preflight.build_frozen_manifest())
        changed["claim_boundary"]["production_closed"] = True
        self.assertNotEqual(changed, preflight.build_frozen_manifest())


if __name__ == "__main__":
    unittest.main()
