#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.16 production namespace plan."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_production_namespace as namespace


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifests" / namespace.MANIFEST_NAME


class ProductionNamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = namespace.build_plan()
        cls.generated = namespace.build_manifest()
        cls.frozen = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_frozen_plan_identity_and_totals(self) -> None:
        self.assertEqual(
            namespace.plan_sha256(self.plan), namespace.FROZEN_PLAN_SHA256
        )
        self.assertEqual(
            json.loads(json.dumps(self.generated)),
            self.frozen,
        )
        self.assertEqual(len(self.plan.trees), 18)
        self.assertEqual(self.plan.tree_order, tuple(range(18)))
        self.assertEqual(
            self.plan.total_producer_wires,
            namespace.FROZEN_TOTAL_PRODUCER_WIRES,
        )
        self.assertEqual(
            self.plan.total_producer_rows,
            namespace.FROZEN_TOTAL_PRODUCER_ROWS,
        )
        self.assertEqual(
            self.plan.total_output_relocation_rows,
            namespace.FROZEN_TOTAL_OUTPUT_RELOCATION_ROWS,
        )
        self.assertEqual(
            self.plan.planned_composition_rows,
            namespace.FROZEN_PLANNED_COMPOSITION_ROWS,
        )
        self.assertEqual(
            self.plan.max_wire_id,
            namespace.FROZEN_MAX_PLANNED_WIRE_ID,
        )

    def test_shapes_and_intervals_are_exact_and_nonoverlapping(self) -> None:
        for tree in self.plan.trees[:2]:
            self.assertEqual((tree.leaves, tree.extension_degree), (4096, 13))
            self.assertEqual(tree.local_wires, 38_953_830)
            self.assertEqual(tree.producer_rows, 51_325_080)
        for tree in self.plan.trees[2:]:
            self.assertEqual((tree.leaves, tree.extension_degree), (2048, 12))
            self.assertEqual(tree.local_wires, 19_478_436)
            self.assertEqual(tree.producer_rows, 25_666_386)
        intervals = [
            (self.plan.tail_interval.start, self.plan.tail_interval.end)
        ] + [
            (tree.planned_wire_start, tree.planned_wire_end)
            for tree in self.plan.trees
        ]
        self.assertTrue(
            all(left[1] + 1 == right[0] for left, right in zip(intervals, intervals[1:]))
        )
        self.assertEqual(namespace.validate_plan(self.plan, json.loads(
            namespace.DEFAULT_TAIL_MANIFEST.read_text(encoding="utf-8")
        )), ())

    def test_global_point_imports_keep_exact_wire_ids(self) -> None:
        self.assertEqual(
            tuple(item.wire_start for item in self.plan.point_imports),
            namespace.POINT_WIRE_STARTS,
        )
        self.assertTrue(
            all(item.bit_length == field.FIELD_DEGREE for item in self.plan.point_imports)
        )
        for tree in self.plan.trees:
            for point in self.plan.point_imports:
                for offset in (0, point.bit_length - 1):
                    wire = point.wire_start + offset
                    self.assertEqual(namespace.rebase_wire(tree, wire), wire)

    def test_all_72_output_ranges_are_planned(self) -> None:
        outputs = [port for tree in self.plan.trees for port in tree.outputs]
        self.assertEqual(len(outputs), 72)
        self.assertEqual(sum(port.bit_length for port in outputs), 15_938_520)
        self.assertTrue(
            all(
                tree.planned_wire_start <= port.planned_wire_start
                and port.planned_wire_end <= tree.planned_wire_end
                for tree in self.plan.trees
                for port in tree.outputs
            )
        )
        self.assertTrue(
            all(port.producer_value_digest_verified for port in self.plan.trees[0].outputs)
        )
        self.assertTrue(
            all(port.producer_value_digest_verified for port in self.plan.trees[2].outputs)
        )
        self.assertTrue(
            all(
                not port.producer_value_digest_verified
                for index, tree in enumerate(self.plan.trees)
                if index not in namespace.REPRESENTATIVE_TREE_INDICES
                for port in tree.outputs
            )
        )

    def test_representative_rebase_offsets_are_explicit(self) -> None:
        tree0 = self.plan.trees[0]
        tree2 = self.plan.trees[2]
        self.assertEqual(tree0.rebase_delta, 0)
        self.assertEqual(tree2.rebase_delta, 77_907_660)
        self.assertEqual(tree2.planned_wire_start, 118_102_257)
        self.assertEqual(
            tuple(port.planned_wire_start for port in tree2.outputs),
            (136_713_057, 137_503_585, 137_505_633, 137_576_061),
        )

    def test_row_rebase_changes_only_permitted_wire_ids(self) -> None:
        tree = self.plan.trees[2]
        local = tree.standalone_wire_start
        point = namespace.POINT_WIRE_STARTS[0]
        row = field.RankOneRow(
            "probe",
            field.LinearForm(((point, 3), (local, 5)), 7),
            field.LinearForm.wire(local + 1, 11),
            field.LinearForm.wire(local + 2, 13),
        )
        rebased = namespace.rebase_row(tree, row)
        self.assertEqual(row.label, rebased.label)
        self.assertEqual(row.left.constant, rebased.left.constant)
        self.assertEqual(
            tuple(coefficient for _, coefficient in row.left.terms),
            tuple(coefficient for _, coefficient in rebased.left.terms),
        )
        self.assertIn((point, 3), rebased.left.terms)
        self.assertIn((tree.planned_wire_start, 5), rebased.left.terms)
        with self.assertRaises(ValueError):
            namespace.rebase_wire(tree, 1)

    def test_configuration_mutations_fail_closed(self) -> None:
        probes = self.generated["configuration_mutation_probes"]
        self.assertEqual(len(probes), 8)
        self.assertTrue(all(item["rejected"] for item in probes))
        self.assertTrue(all(item["failures"] for item in probes))
        overlapping = replace(
            self.plan.trees[1],
            planned_wire_start=self.plan.trees[0].planned_wire_start,
        )
        mutated = replace(
            self.plan,
            trees=(self.plan.trees[0], overlapping, *self.plan.trees[2:]),
        )
        failures = namespace.validate_plan(
            mutated,
            json.loads(namespace.DEFAULT_TAIL_MANIFEST.read_text(encoding="utf-8")),
        )
        self.assertTrue(any("overlapping_intervals" in item for item in failures))

    def test_claim_boundary_does_not_confuse_plan_with_replay(self) -> None:
        claims = self.generated["claim_boundary"]
        for name in (
            "production_18_tree_namespace_plan_closed",
            "production_namespace_intervals_nonoverlapping",
            "production_global_point_imports_preserved",
            "representative_rebase_rule_fixture_verified",
        ):
            self.assertTrue(claims[name], name)
        for name in (
            "representative_producers_rebased_replayed",
            "tree_producer_segments_materialized",
            "all_72_output_relocations_closed",
            "complete_18_tree_assignment_replayed",
            "cross_segment_wire_identity_closed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(claims[name], name)


if __name__ == "__main__":
    unittest.main()
