#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.13 production tree-0 producer."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_production_tree0_producer as production
import pq_rbbc_cap_shard_assignment as assignment
import pq_rbbc_cap_tree_producer as producer


ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = (
    ROOT
    / "production_tree0_v2_13"
    / "pq_rbbc_cap_production_tree0_manifest_v2_13.json"
)
ARCHIVE_PATH = (
    ROOT
    / "production_tree0_v2_13"
    / "pq_rbbc_production_tree_0_producer_v2_13.f193assign"
)
CACHE_PATH = (
    ROOT
    / "production_tree0_v2_13"
    / "tree_0_execution_checkpoint_v2_13.pkl"
)


class ProductionTree0ProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_frozen_production_vector_is_exact(self) -> None:
        trace = self.manifest["trace"]
        archive = self.manifest["assignment_archive"]
        self.assertEqual(trace["rows"], production.FROZEN_ROWS)
        self.assertEqual(trace["local_wires"], production.FROZEN_LOCAL_WIRES)
        self.assertEqual(trace["max_wire_id"], production.FROZEN_MAX_WIRE_ID)
        self.assertEqual(trace["stream_bytes"], production.FROZEN_STREAM_BYTES)
        self.assertEqual(trace["stream_sha256"], production.FROZEN_STREAM_SHA256)
        self.assertEqual(archive["archive_bytes"], production.FROZEN_ASSIGNMENT_BYTES)
        self.assertEqual(
            archive["archive_sha256"], production.FROZEN_ASSIGNMENT_SHA256
        )
        if not ARCHIVE_PATH.exists():
            self.skipTest("973 MB tree-0 archive is an optional release artifact")
        self.assertEqual(ARCHIVE_PATH.stat().st_size, production.FROZEN_ASSIGNMENT_BYTES)
        with assignment.AssignmentArchiveReader(
            ARCHIVE_PATH, verify_body=False
        ) as values:
            self.assertEqual(values.wires, production.FROZEN_LOCAL_WIRES)
            self.assertEqual(values.row_stream_sha256, production.FROZEN_STREAM_SHA256)

    def test_exact_point_wire_identity_and_mutations(self) -> None:
        point_import = self.manifest["point_import"]
        self.assertEqual(
            tuple(point_import["wire_starts"]), production.GLOBAL_POINT_STARTS
        )
        self.assertFalse(point_import["local_copy_allocated"])
        self.assertEqual(
            point_import["value_sha256"], production.FROZEN_POINT_VALUE_SHA256
        )
        mutations = point_import["mutations"]
        self.assertEqual(len(mutations), 3)
        self.assertTrue(all(item["rejected"] for item in mutations))
        self.assertEqual(
            {item["mutation"] for item in mutations},
            {"flip-imported-point", "swap-imported-points"},
        )

    def test_all_outputs_match_the_frozen_tail(self) -> None:
        matches = self.manifest["output_matches"]
        self.assertEqual(len(matches), 4)
        self.assertTrue(all(item["exact_value_match"] for item in matches))
        self.assertFalse(any(item["exact_wire_identity"] for item in matches))
        self.assertEqual(
            tuple(item["producer_wire_start"] for item in matches),
            production.FROZEN_OUTPUT_WIRE_STARTS,
        )

    def test_claim_boundary_closes_only_index_zero(self) -> None:
        claims = self.manifest["claim_boundary"]
        self.assertTrue(
            claims["production_index0_4096_degree13_producer_native_closed"]
        )
        self.assertTrue(claims["production_index0_point_wire_identity_closed"])
        self.assertTrue(claims["production_index0_output_values_match_tail"])
        for name in (
            "production_tree_producer_segments_materialized",
            "producer_point_wire_identity_closed",
            "production_index2_2048_degree12_producer_native_closed",
            "all_four_output_relocations_closed",
            "complete_18_tree_assignment_replayed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)

    def test_resume_evidence_and_execution_cache_are_sealed(self) -> None:
        evidence = self.manifest["resume_evidence"]
        self.assertTrue(evidence["execution_cache_checkpointed_per_ggm_level"])
        self.assertEqual(
            evidence["execution_cache_checkpointed_every_leaf_batch"], 128
        )
        self.assertTrue(evidence["assignment_prefix_preserved_on_interruption"])
        self.assertTrue(evidence["generation_and_replay_separate_stages"])
        if not CACHE_PATH.exists():
            self.skipTest("tree-0 execution cache is an optional release artifact")
        randomness = cap.deterministic_randomness(
            cap.PRODUCTION_PARAMETERS, production.composer.FROZEN_RANDOMNESS_LABEL
        )
        state, resumed = production._load_execution_checkpoint(CACHE_PATH, randomness)
        self.assertTrue(resumed)
        self.assertEqual(state["phase"], "complete")
        self.assertEqual(len(state["nodes"]), production.LEAVES)
        self.assertEqual(len(state["leaf_outputs"]), production.LEAVES)

    def test_point_import_validator_fails_closed(self) -> None:
        self.assertEqual(
            production.validate_point_imports(production.GLOBAL_POINT_STARTS), ()
        )
        self.assertIn(
            "wrong_point_relocation",
            production.validate_point_imports(
                (production.GLOBAL_POINT_STARTS[0] + 1, production.GLOBAL_POINT_STARTS[1])
            ),
        )
        self.assertIn(
            "noncontiguous_point_ranges",
            production.validate_point_imports(
                (production.GLOBAL_POINT_STARTS[0], production.GLOBAL_POINT_STARTS[1] + 1)
            ),
        )
        self.assertIn(
            "point_import_overlaps_local_wires",
            production.validate_point_imports(
                production.GLOBAL_POINT_STARTS,
                local_wire_start=production.GLOBAL_POINT_STARTS[0],
            ),
        )

    def test_resumable_writer_preserves_and_checks_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v2-13-writer-") as directory:
            path = Path(directory) / "resume.f193assign"
            first = production.ResumableAssignmentArchiveWriter(path)
            first.append_values((0, 1, 2, 3))
            first.abort()
            resumed = production.ResumableAssignmentArchiveWriter(path)
            self.assertEqual(resumed.existing_wires, 4)
            resumed.append_values((0, 1, 2, 3, 4, 5))
            metadata = resumed.finish(6, "00" * 32)
            self.assertEqual(metadata.wires, 6)
            with assignment.AssignmentArchiveReader(path) as values:
                self.assertEqual(tuple(values[index] for index in range(1, 7)), tuple(range(6)))

    def test_external_point_mode_replays_without_local_copy(self) -> None:
        parameters = cap.REDUCED_TEST_PARAMETERS
        randomness = cap.deterministic_randomness(parameters)
        execution = cap.execute_cap_commit(parameters, randomness)
        material = producer.material_from_execution(parameters, execution, 0)
        local_values = tail.MemoryAssignment()
        global_values = tail.MemoryAssignment()
        global_values.values = [0] * 999
        for bit in range(193):
            global_values.values[99 + bit] = (material.point_values[0] >> bit) & 1
        generated = producer.build_tree_producer(
            parameters,
            randomness,
            None,
            0,
            producer_material=material,
            external_point_starts=(100,),
            local_wire_start=1000,
            assignment_writer=local_values,
        )
        composed = production.CompositeAssignment(
            global_values,
            production.OffsetAssignment(local_values, 1000, len(local_values)),
        )
        verified = producer.build_tree_producer(
            parameters,
            randomness,
            None,
            0,
            producer_material=material,
            external_point_starts=(100,),
            local_wire_start=1000,
            verification_assignment=composed,
        )
        self.assertEqual(verified.verification_failures, 0)
        self.assertEqual(generated.stream_sha256, verified.stream_sha256)
        self.assertEqual(generated.imported_point_wires, (100,))
        self.assertEqual(generated.wires, len(local_values))


if __name__ == "__main__":
    unittest.main()
