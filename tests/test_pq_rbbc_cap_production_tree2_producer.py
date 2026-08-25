#!/usr/bin/env python3
"""Regression tests for the sealed PQ-RBBC v2.14 index-2 producer."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_production_tree2_producer as production
import pq_rbbc_cap_shard_assignment as assignment


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = Path(os.environ.get("PQRBBC_ARTIFACT_ROOT", ROOT))
DIRECTORY = ROOT / "artifacts" / "metadata" / "production_tree2_v2_14"
MANIFEST_PATH = DIRECTORY / "pq_rbbc_cap_production_tree2_manifest_v2_14.json"
EXTERNAL_DIRECTORY = ARTIFACT_ROOT / "production_tree2_v2_14"
ARCHIVE_PATH = EXTERNAL_DIRECTORY / "pq_rbbc_production_tree_2_producer_v2_14.f193assign"
CACHE_PATH = EXTERNAL_DIRECTORY / "tree_2_execution_checkpoint_v2_14.pkl"
GLOBAL_ARCHIVE_PATH = ARTIFACT_ROOT / "pq_rbbc_cap_global_tail_assignment_v2_9.f193assign"


class ProductionTree2ProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_frozen_vector_and_archive_are_exact(self) -> None:
        if not ARCHIVE_PATH.exists():
            self.skipTest("external v2.14 tree-2 assignment is not installed")
        trace = self.manifest["trace"]
        archive = self.manifest["assignment_archive"]
        self.assertEqual(trace["rows"], production.FROZEN_ROWS)
        self.assertEqual(trace["local_wires"], production.FROZEN_LOCAL_WIRES)
        self.assertEqual(trace["max_wire_id"], production.FROZEN_MAX_WIRE_ID)
        self.assertEqual(trace["stream_bytes"], production.FROZEN_STREAM_BYTES)
        self.assertEqual(trace["stream_sha256"], production.FROZEN_STREAM_SHA256)
        self.assertEqual(archive["archive_bytes"], production.FROZEN_ASSIGNMENT_BYTES)
        self.assertEqual(archive["archive_sha256"], production.FROZEN_ASSIGNMENT_SHA256)
        self.assertEqual(ARCHIVE_PATH.stat().st_size, production.FROZEN_ASSIGNMENT_BYTES)
        with assignment.AssignmentArchiveReader(ARCHIVE_PATH, verify_body=False) as reader:
            self.assertEqual(reader.wires, production.FROZEN_LOCAL_WIRES)
            self.assertEqual(reader.row_stream_sha256, production.FROZEN_STREAM_SHA256)

    def test_points_outputs_and_all_probes_close(self) -> None:
        imported = self.manifest["point_import"]
        self.assertEqual(tuple(imported["wire_starts"]), production.GLOBAL_POINT_STARTS)
        self.assertFalse(imported["local_copy_allocated"])
        self.assertEqual(imported["value_sha256"], production.FROZEN_POINT_VALUE_SHA256)
        self.assertTrue(all(item["rejected"] for item in imported["mutations"]))
        outputs = self.manifest["output_matches"]
        self.assertEqual(
            tuple(item["producer_wire_start"] for item in outputs),
            production.FROZEN_OUTPUT_WIRE_STARTS,
        )
        self.assertTrue(all(item["exact_value_match"] for item in outputs))
        self.assertFalse(any(item["exact_wire_identity"] for item in outputs))
        self.assertTrue(
            all(item["rejected"] for item in self.manifest["stale_witness_probes"])
        )

    def test_checkpoint_cache_is_complete_and_identity_sealed(self) -> None:
        if not CACHE_PATH.exists() or not GLOBAL_ARCHIVE_PATH.exists():
            self.skipTest("external v2.14 replay artifacts are not installed")
        with assignment.AssignmentArchiveReader(
            GLOBAL_ARCHIVE_PATH, verify_body=False
        ) as global_values:
            point_values = tuple(
                production._field_from_bits(global_values, start)
                for start in production.GLOBAL_POINT_STARTS
            )
        randomness = cap.deterministic_randomness(
            cap.PRODUCTION_PARAMETERS, production.composer.FROZEN_RANDOMNESS_LABEL
        )
        state, resumed = production._load_execution_checkpoint(
            CACHE_PATH, randomness, point_values
        )
        self.assertTrue(resumed)
        self.assertEqual(state["phase"], "complete")
        self.assertEqual(len(state["nodes"]), production.LEAVES)
        self.assertEqual(len(state["leaf_outputs"]), production.LEAVES)
        self.assertEqual(state["relation_id"], production.RELATION_ID)

    def test_claim_boundary_is_exact(self) -> None:
        claims = self.manifest["claim_boundary"]
        for name in (
            "production_index0_4096_degree13_producer_native_closed",
            "production_index0_point_wire_identity_closed",
            "production_index0_output_values_match_tail",
            "production_index2_2048_degree12_producer_native_closed",
            "production_index2_point_wire_identity_closed",
            "production_index2_output_values_match_tail",
        ):
            self.assertTrue(claims[name], name)
        for name in (
            "production_tree_producer_segments_materialized",
            "producer_point_wire_identity_closed",
            "all_four_output_relocations_closed",
            "complete_18_tree_assignment_replayed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)


if __name__ == "__main__":
    unittest.main()
