#!/usr/bin/env python3
"""Regression tests for the v2.25 planned-offset tree runner."""

from __future__ import annotations

import json
import pickle
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_composer as composer
import pq_rbbc_cap_planned_tree_producer as planned
import pq_rbbc_cap_production_namespace as namespace
import pq_rbbc_cap_production_tree0_producer as tree0
import pq_rbbc_cap_production_tree2_producer as tree2


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifests" / planned.MANIFEST_NAME


class PlannedTreeProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = planned.load_contract(1)
        cls.tree3_contract = planned.load_contract(3)
        cls.tree4_contract = planned.load_contract(4)
        cls.batch_contracts = tuple(planned.load_contract(index) for index in (5, 6, 7))
        cls.generated = planned.build_preflight_manifest(7)
        cls.randomness = cap.deterministic_randomness(
            cap.PRODUCTION_PARAMETERS, composer.FROZEN_RANDOMNESS_LABEL
        )
        cls.points = (1, 2)

    def test_tree1_contract_is_exact_and_frozen(self) -> None:
        contract = self.contract
        self.assertEqual(
            planned.contract_sha256(contract),
            planned.FROZEN_TREE1_CONTRACT_SHA256,
        )
        self.assertEqual(contract.namespace_plan_sha256, namespace.FROZEN_PLAN_SHA256)
        self.assertEqual(contract.tree_index, 1)
        self.assertEqual((contract.leaves, contract.extension_degree), (4096, 13))
        self.assertEqual(contract.planned_local_wire_start, 79_148_427)
        self.assertEqual(contract.planned_max_wire_id, 118_102_256)
        self.assertEqual(contract.rebase_delta, 38_953_830)
        self.assertEqual(contract.local_wires, 38_953_830)
        self.assertEqual(contract.rows, 51_325_080)
        self.assertEqual(contract.nonlinear_rows, 38_212_470)
        self.assertEqual(contract.linear_rows, 13_112_610)
        self.assertEqual(contract.stream_bytes, 18_008_277_115)
        self.assertEqual(contract.assignment_bytes, 973_845_878)
        self.assertEqual(
            contract.planned_output_wire_starts,
            (116_373_499, 117_954_555, 117_956_603, 118_097_239),
        )
        self.assertEqual(planned.contract_failures(contract, contract), ())

    def test_legacy_tree_contracts_are_preserved(self) -> None:
        contract0 = planned.load_contract(0)
        contract2 = planned.load_contract(2)
        self.assertEqual(contract0.planned_local_wire_start, tree0.LOCAL_WIRE_START)
        self.assertEqual(contract0.local_wires, tree0.FROZEN_LOCAL_WIRES)
        self.assertEqual(contract0.rows, tree0.FROZEN_ROWS)
        self.assertEqual(
            contract0.planned_output_wire_starts, tree0.FROZEN_OUTPUT_WIRE_STARTS
        )
        self.assertEqual(contract2.planned_local_wire_start, 118_102_257)
        self.assertEqual(contract2.local_wires, tree2.FROZEN_LOCAL_WIRES)
        self.assertEqual(contract2.rows, tree2.FROZEN_ROWS)
        self.assertEqual(contract0.stream_bytes, tree0.FROZEN_STREAM_BYTES)
        self.assertEqual(contract2.stream_bytes, tree2.FROZEN_STREAM_BYTES)
        self.assertEqual(
            contract2.planned_output_wire_starts,
            tuple(
                value + contract2.rebase_delta
                for value in tree2.FROZEN_OUTPUT_WIRE_STARTS
            ),
        )
        self.assertEqual(planned.load_contract(3).stream_bytes, 8_961_160_824)
        self.assertEqual(planned.load_contract(4).stream_bytes, 8_961_160_824)

    def test_tree3_contract_is_exact_and_frozen_after_replay(self) -> None:
        contract = self.tree3_contract
        self.assertEqual(
            planned.contract_sha256(contract),
            planned.FROZEN_TREE3_CONTRACT_SHA256,
        )
        self.assertEqual(contract.tree_index, 3)
        self.assertEqual((contract.leaves, contract.extension_degree), (2048, 12))
        self.assertEqual(contract.planned_local_wire_start, 137_580_693)
        self.assertEqual(contract.planned_max_wire_id, 157_059_128)
        self.assertEqual(contract.rebase_delta, 97_386_096)
        self.assertEqual(contract.local_wires, 19_478_436)
        self.assertEqual(contract.rows, 25_666_386)
        self.assertEqual(contract.stream_bytes, 8_961_160_824)
        self.assertEqual(contract.assignment_bytes, 486_961_028)
        self.assertEqual(
            contract.planned_output_wire_starts,
            (156_191_493, 156_982_021, 156_984_069, 157_054_497),
        )

    def test_tree4_contract_is_exact_and_frozen_after_replay(self) -> None:
        contract = self.tree4_contract
        self.assertEqual(
            planned.contract_sha256(contract),
            planned.FROZEN_TREE4_CONTRACT_SHA256,
        )
        self.assertEqual(contract.tree_index, 4)
        self.assertEqual((contract.leaves, contract.extension_degree), (2048, 12))
        self.assertEqual(contract.planned_local_wire_start, 157_059_129)
        self.assertEqual(contract.planned_max_wire_id, 176_537_564)
        self.assertEqual(contract.rebase_delta, 116_864_532)
        self.assertEqual(contract.local_wires, 19_478_436)
        self.assertEqual(contract.rows, 25_666_386)
        self.assertEqual(contract.stream_bytes, 8_961_160_824)
        self.assertEqual(contract.assignment_bytes, 486_961_028)
        self.assertEqual(
            contract.planned_output_wire_starts,
            (175_669_929, 176_460_457, 176_462_505, 176_532_933),
        )

    def test_tree5_to_tree7_final_contracts_are_exact(self) -> None:
        expected = (
            (5, 176_537_565, 196_016_000, 136_342_968,
             (195_148_365, 195_938_893, 195_940_941, 196_011_369),
             planned.FROZEN_TREE5_CONTRACT_SHA256,
             planned.PREFREEZE_TREE5_CONTRACT_SHA256),
            (6, 196_016_001, 215_494_436, 155_821_404,
             (214_626_801, 215_417_329, 215_419_377, 215_489_805),
             planned.FROZEN_TREE6_CONTRACT_SHA256,
             planned.PREFREEZE_TREE6_CONTRACT_SHA256),
            (7, 215_494_437, 234_972_872, 175_299_840,
             (234_105_237, 234_895_765, 234_897_813, 234_968_241),
             planned.FROZEN_TREE7_CONTRACT_SHA256,
             planned.PREFREEZE_TREE7_CONTRACT_SHA256),
        )
        for contract, item in zip(self.batch_contracts, expected, strict=True):
            tree_index, start, end, delta, outputs, digest, prefreeze_digest = item
            with self.subTest(tree_index=tree_index):
                self.assertEqual(contract.tree_index, tree_index)
                self.assertEqual((contract.leaves, contract.extension_degree), (2048, 12))
                self.assertEqual(contract.planned_local_wire_start, start)
                self.assertEqual(contract.planned_max_wire_id, end)
                self.assertEqual(contract.rebase_delta, delta)
                self.assertEqual(contract.local_wires, 19_478_436)
                self.assertEqual(contract.rows, 25_666_386)
                self.assertEqual(contract.stream_bytes, 8_961_160_824)
                self.assertEqual(contract.assignment_bytes, 486_961_028)
                self.assertEqual(contract.planned_output_wire_starts, outputs)
                self.assertEqual(planned.contract_sha256(contract), digest)
                self.assertEqual(
                    planned.contract_sha256(replace(contract, stream_bytes=None)),
                    prefreeze_digest,
                )
                self.assertEqual(planned.contract_failures(contract, contract), ())

    def test_configuration_mutations_fail_closed(self) -> None:
        probes = self.generated["configuration_mutation_probes"]
        self.assertEqual(len(probes), 10)
        self.assertTrue(all(item["rejected"] for item in probes))
        self.assertTrue(all(item["failures"] for item in probes))

    def test_checkpoint_is_bound_to_every_execution_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v2-22-cache-") as directory:
            path = Path(directory) / "tree1.pkl"
            state, resumed = planned._load_execution_checkpoint(
                path, self.contract, self.randomness, self.points
            )
            self.assertFalse(resumed)
            for key in (
                "runner_relation_id",
                "producer_relation_id",
                "namespace_plan_sha256",
                "contract_sha256",
                "profile_fingerprint",
                "randomness_label",
                "randomness_sha256",
                "source_assignment_sha256",
                "point_value_sha256",
                "tree_index",
                "leaves",
                "extension_degree",
                "planned_local_wire_start",
                "planned_max_wire_id",
                "planned_output_wire_starts",
            ):
                self.assertIn(key, state)
            path.write_bytes(pickle.dumps(state, protocol=pickle.HIGHEST_PROTOCOL))
            _, resumed = planned._load_execution_checkpoint(
                path, self.contract, self.randomness, self.points
            )
            self.assertTrue(resumed)
            with self.assertRaisesRegex(ValueError, "point_value_sha256"):
                planned._load_execution_checkpoint(
                    path, self.contract, self.randomness, (1, 3)
                )
            moved = replace(
                self.contract,
                planned_local_wire_start=self.contract.planned_local_wire_start + 1,
            )
            with self.assertRaisesRegex(ValueError, "contract_sha256"):
                planned._load_execution_checkpoint(
                    path, moved, self.randomness, self.points
                )

    def test_prefix_writer_rejects_changed_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v2-22-prefix-") as directory:
            path = Path(directory) / "resume.f193assign"
            first = tree2.ResumableAssignmentArchiveWriter(path)
            first.append_values((0, 1, 2, 3))
            first.abort()
            resumed = tree2.ResumableAssignmentArchiveWriter(path)
            with self.assertRaisesRegex(ValueError, "prefix value mismatch"):
                resumed.append_values((0, 1, 9, 3))
            resumed.abort()

    def test_unsafe_configuration_rejects_before_input_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-rbbc-v2-22-config-") as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "outside the frozen namespace"):
                planned.build_production_tree(
                    18, root, root / "missing.f193assign", root / "missing.json"
                )
            with self.assertRaisesRegex(ValueError, "filesystem-safe"):
                planned.build_production_tree(
                    1,
                    root,
                    root / "missing.f193assign",
                    root / "missing.json",
                    artifact_tag="../escape",
                )

    def test_preflight_manifest_is_frozen_and_claims_are_exact(self) -> None:
        frozen = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(json.loads(json.dumps(self.generated)), frozen)
        self.assertTrue(
            self.generated["claim_boundary"]["planned_tree_runner_preflight_closed"]
        )
        self.assertTrue(
            self.generated["claim_boundary"][
                "planned_offset_reduced_fixture_replayed"
            ]
        )
        self.assertEqual(
            self.generated["production_replay"]["status"], "not_materialized"
        )
        self.assertEqual(self.generated["claim_boundary"]["target_tree_index"], 7)
        for name in (
            "production_tree1_planned_assignment_materialized",
            "production_tree1_planned_full_replay_closed",
            "production_tree3_planned_assignment_materialized",
            "production_tree3_planned_full_replay_closed",
            "production_tree4_planned_assignment_materialized",
            "production_tree4_planned_full_replay_closed",
            "production_tree5_planned_assignment_materialized",
            "production_tree5_planned_full_replay_closed",
            "production_tree6_planned_assignment_materialized",
            "production_tree6_planned_full_replay_closed",
            "production_tree7_planned_assignment_materialized",
            "production_tree7_planned_full_replay_closed",
            "remaining_planned_tree_producers_materialized",
            "all_72_output_relocations_closed",
            "complete_18_tree_assignment_replayed",
            "cross_segment_wire_identity_closed",
            "parent_cap_to_h_rbbc_join_closed",
            "fork_security_proof_revalidated",
            "production_closed",
        ):
            self.assertFalse(self.generated["claim_boundary"][name], name)


if __name__ == "__main__":
    unittest.main()
