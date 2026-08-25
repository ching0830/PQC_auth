#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.12 production split observer."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_global_tail as tail
import pq_rbbc_cap_production_split_tail as production_split
import pq_rbbc_cap_split_tail as reduced_split


ROOT = Path(__file__).resolve().parents[1]
SOURCE_MANIFEST = ROOT / "manifests" / "pq_rbbc_cap_global_tail_manifest_v2_9.json"
PRODUCTION_MANIFEST = (
    ROOT
    / "artifacts"
    / "metadata"
    / "production_split_v2_12"
    / "pq_rbbc_cap_production_split_tail_manifest_v2_12.json"
)


class ProductionSplitTailTests(unittest.TestCase):
    def test_exact_production_layout(self) -> None:
        layout = production_split.build_production_layout()
        self.assertEqual(
            (layout.phase_a_row_start, layout.phase_a_row_end),
            (15_939_162, 56_375_441),
        )
        self.assertEqual(
            (layout.phase_b_row_start, layout.phase_b_row_end),
            (56_375_441, 56_806_711),
        )
        self.assertEqual(
            (layout.phase_a_wire_start, layout.phase_a_wire_end),
            (15_939_163, 39_946_062),
        )
        self.assertEqual(
            (layout.phase_b_wire_start, layout.phase_b_wire_end),
            (39_946_062, 40_194_597),
        )
        self.assertEqual(layout.h1_wire_start, 39_943_623)
        self.assertEqual(layout.point_wire_starts, (39_945_673, 39_945_866))
        self.assertEqual(layout.commitment_wire_start, 40_084_506)
        self.assertEqual(layout.request_hash_wire_start, 40_194_018)

    def test_layout_partitions_frozen_v2_9_trace(self) -> None:
        source = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
        layout = production_split.build_production_layout()
        production_split._validate_layout_against_source(layout, source)
        self.assertEqual(layout.rows, tail.FROZEN_PRODUCTION_ROWS)
        self.assertEqual(layout.wires, tail.FROZEN_PRODUCTION_WIRES)

    def test_layout_validation_fails_closed(self) -> None:
        source = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
        changed = copy.deepcopy(source)
        changed["trace"]["groups"][1]["rows"] += 1
        with self.assertRaisesRegex(ValueError, "group schedule"):
            production_split._validate_layout_against_source(
                production_split.build_production_layout(), changed
            )
        with mock.patch.object(production_split, "FROZEN_H1_WIRE_START", 1):
            with self.assertRaisesRegex(ValueError, "frozen v2.12"):
                production_split._validate_layout_against_source(
                    production_split.build_production_layout(), source
                )

    def test_topology_fixture_is_witness_independent_on_reduced_shape(self) -> None:
        randomness, execution = production_split._topology_execution(
            cap.REDUCED_TEST_PARAMETERS
        )
        contracts = []
        observed = tail.build_global_tail(
            cap.REDUCED_TEST_PARAMETERS,
            randomness,
            execution,
            split_contract_output=contracts,
        )
        self.assertEqual(observed.rows, reduced_split.FROZEN_REDUCED_ROWS)
        self.assertEqual(observed.wires, reduced_split.FROZEN_REDUCED_WIRES)
        self.assertEqual(
            observed.stream_sha256,
            reduced_split.FROZEN_REDUCED_STREAM_SHA256,
        )
        self.assertEqual(len(contracts), 1)

    def test_sealed_production_manifest(self) -> None:
        self.assertTrue(PRODUCTION_MANIFEST.exists())
        manifest = json.loads(PRODUCTION_MANIFEST.read_text(encoding="utf-8"))
        boundary = manifest["claim_boundary"]
        self.assertTrue(boundary["production_split_tail_materialized"])
        self.assertTrue(
            boundary[
                "production_h1_and_two_consistency_point_ports_native_closed"
            ]
        )
        self.assertTrue(
            boundary[
                "production_tail_phase_a_to_phase_b_wire_identity_closed"
            ]
        )
        self.assertFalse(boundary["producer_point_wire_identity_closed"])
        self.assertFalse(boundary["complete_18_tree_assignment_replayed"])
        self.assertFalse(boundary["production_closed"])
        self.assertEqual(
            len(manifest["boundary_wire_probes"]),
            production_split.FROZEN_BOUNDARY_PROBES,
        )
        self.assertTrue(
            all(item["rejected"] for item in manifest["boundary_wire_probes"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
