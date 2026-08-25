#!/usr/bin/env python3
"""Fast preflight tests for the v2.14 tree-index-2 production checkpoint."""

from __future__ import annotations

import pickle
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_production_tree2_producer as production


class ProductionTree2CheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.randomness = cap.deterministic_randomness(
            cap.PRODUCTION_PARAMETERS, composer.FROZEN_RANDOMNESS_LABEL
        )
        self.points = (1, 2)

    def test_frozen_shape_and_wire_contract(self) -> None:
        self.assertEqual(production.TREE_INDEX, 2)
        self.assertEqual(production.LEAVES, 2048)
        self.assertEqual(production.EXTENSION_DEGREE, 12)
        self.assertEqual(production.GLOBAL_POINT_STARTS, (39_945_673, 39_945_866))
        self.assertEqual(production.LOCAL_WIRE_START, 40_194_597)
        self.assertEqual(production.validate_point_imports(production.GLOBAL_POINT_STARTS), ())

    def test_checkpoint_is_sealed_to_every_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v2-14-cache-") as directory:
            path = Path(directory) / "checkpoint.pkl"
            state, resumed = production._load_execution_checkpoint(
                path, self.randomness, self.points
            )
            self.assertFalse(resumed)
            for key in (
                "relation_id",
                "profile_fingerprint",
                "randomness_label",
                "randomness_sha256",
                "source_assignment_sha256",
                "point_value_sha256",
                "tree_index",
            ):
                self.assertIn(key, state)
            path.write_bytes(pickle.dumps(state, protocol=pickle.HIGHEST_PROTOCOL))
            _, resumed = production._load_execution_checkpoint(
                path, self.randomness, self.points
            )
            self.assertTrue(resumed)
            with self.assertRaisesRegex(ValueError, "point_value_sha256"):
                production._load_execution_checkpoint(path, self.randomness, (1, 3))

    def test_resumable_writer_rejects_a_changed_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v2-14-prefix-") as directory:
            path = Path(directory) / "resume.f193assign"
            first = production.ResumableAssignmentArchiveWriter(path)
            first.append_values((0, 1, 2, 3))
            first.abort()
            resumed = production.ResumableAssignmentArchiveWriter(path)
            with self.assertRaisesRegex(ValueError, "prefix value mismatch"):
                resumed.append_values((0, 1, 9, 3))
            resumed.abort()


if __name__ == "__main__":
    unittest.main()
