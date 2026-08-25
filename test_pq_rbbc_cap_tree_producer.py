#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.10 tree-producer segments."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_tree_producer as producer


class TreeProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = cap.REDUCED_TEST_PARAMETERS
        cls.randomness = cap.deterministic_randomness(cls.parameters)
        cls.execution = cap.execute_cap_commit(cls.parameters, cls.randomness)
        built = tuple(
            producer.build_in_memory_tree_producer(
                cls.parameters,
                cls.randomness,
                cls.execution,
                tree_index,
            )
            for tree_index in range(cls.parameters.tree_count)
        )
        cls.generated = tuple(item[0] for item in built)
        cls.verified = tuple(item[1] for item in built)
        cls.probes = tuple(item[2] for item in built)
        cls.tail_summary = tail.build_in_memory_global_tail(
            cls.parameters, cls.randomness, cls.execution
        )[0]
        cls.matches = producer.match_tail_ports(
            cls.generated, cls.tail_summary
        )

    def test_each_segment_replays_and_rejects_six_mutations(self) -> None:
        for generated, verified, probes in zip(
            self.generated, self.verified, self.probes
        ):
            self.assertEqual(generated.rows, verified.rows)
            self.assertEqual(generated.wires, verified.wires)
            self.assertEqual(
                generated.stream_sha256, verified.stream_sha256
            )
            self.assertEqual(generated.external_assertions, 0)
            self.assertEqual(verified.verification_failures, 0)
            self.assertEqual(len(probes), 6)
            self.assertTrue(all(probe.rejected for probe in probes))
        self.assertEqual(
            tuple(item.rows for item in self.generated),
            (producer.FROZEN_REDUCED_ROWS_PER_TREE,) * 2,
        )
        self.assertEqual(
            tuple(item.wires for item in self.generated),
            (producer.FROZEN_REDUCED_WIRES_PER_TREE,) * 2,
        )
        self.assertEqual(
            tuple(item.stream_sha256 for item in self.generated),
            producer.FROZEN_REDUCED_STREAM_SHA256,
        )

    def test_all_four_output_ports_match_tail_for_every_tree(self) -> None:
        self.assertEqual(len(self.matches), self.parameters.tree_count * 4)
        self.assertTrue(all(item.exact_value_match for item in self.matches))
        self.assertTrue(all(not item.exact_wire_identity for item in self.matches))
        self.assertEqual(
            {item.port_id for item in self.matches},
            {
                f"tree[{tree_index}].{suffix}"
                for tree_index in range(self.parameters.tree_count)
                for suffix in (
                    "leaf-commitments",
                    "p-plain",
                    "mhat-plain",
                    "xi-masks",
                )
            },
        )

    def test_points_are_explicit_inputs_not_locally_rederived(self) -> None:
        material = tail.derive_tail_material(
            self.parameters, self.execution, bytes(32)
        )
        expected_digest = producer._field_tuple_digest(material.points)
        for summary in self.generated:
            ports = {port.port_id: port for port in summary.ports}
            point_port = ports["global.consistency-points"]
            self.assertEqual(point_port.direction, "input")
            self.assertEqual(point_port.phase, "tree-post")
            self.assertEqual(
                point_port.bit_length,
                self.parameters.consistency_points * 193,
            )
            self.assertEqual(point_port.value_sha256, expected_digest)
            labels = tuple(group.name for group in summary.groups)
            self.assertNotIn("h1-and-points", labels)
            self.assertNotIn("h2-commitment-and-request", labels)
            self.assertEqual(
                summary.sponge_accounting.calls,
                len(producer._tree_calls(self.execution, summary.tree_index)),
            )

    def test_port_widths_are_exact(self) -> None:
        for summary, poly in zip(
            self.generated, self.execution.tree_polynomials
        ):
            ports = {port.port_id: port for port in summary.ports}
            index = summary.tree_index
            self.assertEqual(
                ports[f"tree[{index}].leaf-commitments"].bit_length,
                poly.leaves * 2 * 193,
            )
            self.assertEqual(
                ports[f"tree[{index}].p-plain"].bit_length,
                self.parameters.witness_bits,
            )
            self.assertEqual(
                ports[f"tree[{index}].mhat-plain"].bit_length,
                self.parameters.consistency_bits,
            )
            self.assertEqual(
                ports[f"tree[{index}].xi-masks"].bit_length,
                self.parameters.consistency_bits * poly.extension_degree,
            )

    def test_disk_archives_and_manifest_remain_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = tuple(
                producer.build_assignment_backed_tree_producer(
                    root / f"tree-{tree_index}.f193assign",
                    self.parameters,
                    self.randomness,
                    self.execution,
                    tree_index,
                )
                for tree_index in range(self.parameters.tree_count)
            )
            manifest = producer.build_manifest(
                results, self.tail_summary, self.matches
            )
        boundary = manifest["claim_boundary"]
        self.assertTrue(boundary["reduced_tree_producer_segments_native_closed"])
        self.assertTrue(boundary["producer_to_tail_port_values_match"])
        self.assertFalse(boundary["production_tree_producer_segments_materialized"])
        self.assertFalse(boundary["point_wire_identity_to_global_tail_closed"])
        self.assertFalse(boundary["cross_segment_wire_identity_closed"])
        self.assertFalse(boundary["complete_18_tree_assignment_replayed"])
        self.assertFalse(boundary["production_closed"])

    def test_binary_topology_is_witness_independent(self) -> None:
        changed_randomness = cap.CAPRandomness(
            (
                self.randomness.salt[0] ^ 1,
                self.randomness.salt[1],
            ),
            self.randomness.roots,
        )
        changed_execution = cap.execute_cap_commit(
            self.parameters, changed_randomness
        )
        changed = producer.build_in_memory_tree_producer(
            self.parameters,
            changed_randomness,
            changed_execution,
            0,
        )[0]
        self.assertEqual(
            self.generated[0].stream_sha256, changed.stream_sha256
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
