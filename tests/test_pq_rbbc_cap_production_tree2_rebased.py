#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.17 tree-2 rebase gate."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pq_rbbc_cap_production_namespace as namespace
import pq_rbbc_cap_production_tree2_producer as standalone
import pq_rbbc_cap_production_tree2_rebased as rebased


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifests" / rebased.MANIFEST_NAME


class ProductionTree2RebasedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = rebased.load_contract()
        cls.generated = rebased.build_preflight_manifest()
        cls.fixture = rebased.ReducedOffsetFixtureEvidence(
            **cls.generated["reduced_offset_fixture"]
        )
        cls.frozen = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_frozen_contract_binds_v216_plan_and_v214_evidence(self) -> None:
        contract = self.contract
        self.assertEqual(
            rebased.contract_sha256(contract), rebased.FROZEN_CONTRACT_SHA256
        )
        self.assertEqual(contract.namespace_plan_sha256, namespace.FROZEN_PLAN_SHA256)
        self.assertEqual(contract.tree_index, 2)
        self.assertEqual(contract.planned_local_wire_start, 118_102_257)
        self.assertEqual(contract.planned_max_wire_id, 137_580_692)
        self.assertEqual(contract.planned_rebase_delta, 77_907_660)
        self.assertEqual(
            contract.planned_output_wire_starts,
            (136_713_057, 137_503_585, 137_505_633, 137_576_061),
        )
        self.assertEqual(contract.rows, standalone.FROZEN_ROWS)
        self.assertEqual(contract.local_wires, standalone.FROZEN_LOCAL_WIRES)
        self.assertEqual(
            contract.standalone_row_stream_sha256, standalone.FROZEN_STREAM_SHA256
        )
        self.assertEqual(
            contract.standalone_assignment_sha256,
            standalone.FROZEN_ASSIGNMENT_SHA256,
        )
        self.assertEqual(rebased.contract_failures(contract, contract), ())

    def test_configuration_mutations_fail_closed(self) -> None:
        probes = self.generated["configuration_mutation_probes"]
        self.assertEqual(len(probes), 8)
        self.assertTrue(all(item["rejected"] for item in probes))
        self.assertTrue(all(item["failures"] for item in probes))

    def test_real_reduced_generator_rebases_exactly(self) -> None:
        fixture = self.fixture
        self.assertEqual(fixture.rows, 33_954)
        self.assertEqual(fixture.wires, 23_135)
        self.assertEqual(fixture.nonlinear_rows, 22_727)
        self.assertEqual(fixture.linear_rows, 11_227)
        self.assertEqual(
            fixture.assignment_value_sha256,
            rebased.FROZEN_REDUCED_FIXTURE_ASSIGNMENT_SHA256,
        )
        self.assertTrue(fixture.assignment_values_identical)
        self.assertTrue(fixture.row_count_and_accounting_identical)
        self.assertTrue(fixture.port_values_identical)
        self.assertTrue(fixture.local_port_ids_shifted_exactly)
        self.assertTrue(fixture.point_wire_ids_preserved)
        self.assertTrue(fixture.captured_rows_rebase_exact)
        self.assertEqual(fixture.planned_replay_failures, 0)
        self.assertEqual(fixture.stale_witness_probes, 6)
        self.assertTrue(fixture.stale_witness_probes_rejected)
        self.assertTrue(fixture.fixture_is_not_production_replay_evidence)

    def test_preflight_manifest_is_frozen_and_claims_are_exact(self) -> None:
        self.assertEqual(json.loads(json.dumps(self.generated)), self.frozen)
        replay = self.generated["production_replay"]
        self.assertEqual(replay["status"], "not_materialized")
        self.assertEqual(replay["production_rows_replayed_at_planned_offset"], 0)
        claims = self.generated["claim_boundary"]
        self.assertTrue(claims["production_tree2_planned_offset_execution_gate_closed"])
        self.assertTrue(claims["planned_offset_reduced_fixture_replayed"])
        for name in (
            "production_tree2_rebased_assignment_materialized",
            "production_tree2_rebased_full_replay_closed",
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

    def test_production_wrapper_uses_only_the_planned_offset_and_tag(self) -> None:
        sentinel = object()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "source-cache.pkl"
            with mock.patch.object(
                rebased.standalone,
                "build_production_tree2",
                return_value=sentinel,
            ) as build:
                result = rebased.run_production_replay(
                    root,
                    root / "global.f193assign",
                    root / "global.json",
                    execution_cache_path=cache,
                    workers=3,
                    replace=True,
                )
        self.assertIs(result, sentinel)
        build.assert_called_once_with(
            root,
            root / "global.f193assign",
            root / "global.json",
            local_wire_start=rebased.PLANNED_LOCAL_WIRE_START,
            artifact_tag=rebased.ARTIFACT_TAG,
            execution_cache_path=cache,
            workers=3,
            replace=True,
            progress=None,
        )

    def test_generalized_v214_builder_rejects_unsafe_configuration_early(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "filesystem-safe"):
                standalone.build_production_tree2(
                    root,
                    root / "missing.f193assign",
                    root / "missing.json",
                    artifact_tag="../escape",
                )
            with self.assertRaisesRegex(ValueError, "point import contract"):
                standalone.build_production_tree2(
                    root,
                    root / "missing.f193assign",
                    root / "missing.json",
                    local_wire_start=(
                        namespace.POINT_WIRE_STARTS[-1]
                        + rebased.field.FIELD_DEGREE
                        - 1
                    ),
                )
            with self.assertRaisesRegex(ValueError, "wire_integer_overflow"):
                standalone.build_production_tree2(
                    root,
                    root / "missing.f193assign",
                    root / "missing.json",
                    local_wire_start=standalone.MAX_WIRE_ID,
                )


if __name__ == "__main__":
    unittest.main()
