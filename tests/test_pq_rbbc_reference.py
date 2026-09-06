#!/usr/bin/env python3
"""Regression tests for the executable PQ-RBBC/SGTD v2.4 relation."""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace

import pq_rbbc_reference as core


class PrimitiveTests(unittest.TestCase):
    def test_shake256_matches_hashlib(self) -> None:
        for message in (b"", b"abc", bytes(range(137))):
            with self.subTest(length=len(message)):
                self.assertEqual(
                    core.shake256(message, 64),
                    hashlib.shake_256(message).digest(64),
                )

    def test_symbolic_shake_matches_hashlib_and_costs_one_permutation(self) -> None:
        message = b"symbolic SHAKE check"
        sink = core.CountingSink()
        builder = core.Char2CircuitBuilder(sink)
        builder.set_block("test")
        output = core.shake256_wires(
            builder, core.constant_wires(builder, message), 32
        )
        self.assertEqual(
            core.wire_bytes(output), hashlib.shake_256(message).digest(32)
        )
        self.assertEqual(sink.blocks["test"].keccak_permutations, 1)
        self.assertEqual(sink.blocks["test"].nonlinear_constraints, 38_400)

    def test_kmac256_matches_openssl(self) -> None:
        key = bytes(range(32))
        message = b"PQ-RBBC v1.4 independent KMAC check"
        expected = core._openssl_kmac(key, message, core.CUSTOMIZATION)
        if expected is None:
            self.skipTest("OpenSSL KMAC-256 provider is unavailable")
        self.assertEqual(core.kmac256(key, message), expected)


class RelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix, cls.statement, cls.witness, cls.adapter = core.reference_fixture()

    def test_frozen_wire_sizes(self) -> None:
        self.assertEqual(len(self.statement.payload.encode()), 368)
        self.assertEqual(len(self.statement.payload.encode()) + core.SIGNATURE_BYTES, 12012)
        self.assertEqual(len(self.statement.blind_request.encode()), 72)
        self.assertEqual(len(self.statement.payload.syndrome), 208)

    def test_honest_witness_accepts(self) -> None:
        result = core.verify_relation(
            self.matrix, self.statement, self.witness, self.adapter
        )
        self.assertTrue(result.ok, result.failures)

    def test_manifest_is_fail_closed_at_native_boundary(self) -> None:
        manifest = core.build_manifest(full_negative_circuits=False)
        contract = manifest["native_import_contract"]
        self.assertTrue(contract["linear_mask_equation_internalized"])
        self.assertEqual(contract["native_cap_hash_external_assertions"], 1)
        self.assertEqual(contract["anemoi_component_nonlinear_rows"], 336)
        self.assertTrue(contract["request_binding_hash_primitive_implemented"])
        self.assertTrue(contract["production_cap_reference_algorithm_implemented"])
        self.assertEqual(contract["reduced_cap_native_rows"], 88_282)
        self.assertEqual(contract["reduced_cap_native_wires"], 59_602)
        self.assertEqual(contract["reduced_cap_native_external_assertions"], 0)
        self.assertTrue(contract["reduced_cap_to_h_rbbc_native_wire_join"])
        self.assertFalse(contract["reduced_cap_profile_is_secure"])
        self.assertTrue(contract["arbitrary_length_multi_squeeze_native"])
        self.assertTrue(contract["production_width_2450_bit_tape_native"])
        self.assertEqual(contract["extended_2450_cap_native_rows"], 113_802)
        self.assertEqual(contract["extended_2450_cap_native_wires"], 85_034)
        self.assertEqual(
            contract["extended_2450_cap_native_external_assertions"], 0
        )
        self.assertTrue(contract["generic_multi_coefficient_horner_native"])
        self.assertEqual(contract["production_2048_bit_horner_coefficients"], 11)
        self.assertEqual(
            contract["production_2048_bit_horner_multiplication_rows"], 20
        )
        self.assertTrue(contract["symbolic_extension_mask_horner_native"])
        self.assertEqual(contract["horner_2450_cap_native_rows"], 125_401)
        self.assertEqual(contract["horner_2450_cap_native_wires"], 92_816)
        self.assertEqual(contract["horner_2450_cap_native_external_assertions"], 0)
        self.assertTrue(contract["production_2048_leaf_shard_executed"])
        self.assertEqual(contract["production_2048_leaf_shard_rows"], 26_126_283)
        self.assertEqual(contract["production_2048_leaf_shard_wires"], 19_903_324)
        self.assertEqual(
            contract["production_2048_leaf_shard_external_assertions"], 0
        )
        self.assertTrue(
            contract["production_2048_leaf_shard_assignment_materialized"]
        )
        self.assertTrue(
            contract["production_2048_leaf_shard_whole_assignment_verified"]
        )
        self.assertTrue(
            contract["production_2048_leaf_shard_stale_witness_rejected"]
        )
        self.assertFalse(contract["production_2048_leaf_shard_profile_is_secure"])
        self.assertTrue(contract["production_4096_leaf_shard_executed"])
        self.assertEqual(contract["production_4096_leaf_shard_rows"], 52_224_501)
        self.assertEqual(contract["production_4096_leaf_shard_wires"], 39_789_564)
        self.assertEqual(
            contract["production_4096_leaf_shard_external_assertions"], 0
        )
        self.assertTrue(
            contract["production_4096_leaf_shard_assignment_materialized"]
        )
        self.assertTrue(
            contract["production_4096_leaf_shard_whole_assignment_verified"]
        )
        self.assertTrue(
            contract["production_4096_leaf_shard_stale_witness_rejected"]
        )
        self.assertFalse(contract["production_4096_leaf_shard_profile_is_secure"])
        self.assertTrue(
            contract["both_production_tree_shard_types_closed_separately"]
        )
        self.assertTrue(contract["production_cap_full_vector_executed"])
        self.assertTrue(contract["canonical_18_tree_link_schedule_closed"])
        self.assertTrue(contract["production_cap_native_global_tail_materialized"])
        self.assertTrue(contract["reduced_split_tail_phase_contract_closed"])
        self.assertTrue(
            contract["canonical_tail_stream_and_assignment_equivalent"]
        )
        self.assertTrue(
            contract["h1_and_consistency_point_ports_native_closed"]
        )
        self.assertTrue(
            contract["tail_phase_a_to_phase_b_wire_identity_closed"]
        )
        self.assertTrue(contract["production_split_tail_materialized"])
        self.assertTrue(
            contract[
                "production_h1_and_two_consistency_point_ports_native_closed"
            ]
        )
        self.assertTrue(
            contract[
                "production_tail_phase_a_to_phase_b_wire_identity_closed"
            ]
        )
        self.assertEqual(contract["production_tree0_producer_rows"], 51_325_080)
        self.assertEqual(
            contract["production_tree0_producer_local_wires"], 38_953_830
        )
        self.assertEqual(
            tuple(contract["production_tree0_point_wire_starts"]),
            (39_945_673, 39_945_866),
        )
        self.assertTrue(
            contract["production_index0_4096_degree13_producer_native_closed"]
        )
        self.assertTrue(contract["production_index0_point_wire_identity_closed"])
        self.assertTrue(contract["production_index0_output_values_match_tail"])
        self.assertEqual(contract["production_tree2_producer_rows"], 25_666_386)
        self.assertEqual(
            contract["production_tree2_producer_local_wires"], 19_478_436
        )
        self.assertEqual(contract["production_tree2_producer_max_wire_id"], 59_673_032)
        self.assertEqual(
            tuple(contract["production_tree2_point_wire_starts"]),
            (39_945_673, 39_945_866),
        )
        self.assertTrue(
            contract["production_index2_2048_degree12_producer_native_closed"]
        )
        self.assertTrue(contract["production_index2_point_wire_identity_closed"])
        self.assertTrue(contract["production_index2_output_values_match_tail"])
        self.assertEqual(contract["production_output_relocation_rows"], 2_386_102)
        self.assertEqual(contract["production_output_relocation_wires"], 4_772_204)
        self.assertEqual(
            tuple(contract["production_output_relocation_representative_tree_indices"]),
            (0, 2),
        )
        for name in (
            "production_representative_output_relocation_contract_closed",
            "production_index0_all_four_output_relocations_closed",
            "production_index2_all_four_output_relocations_closed",
            "all_four_output_relocations_closed",
            "representative_cross_segment_wire_relation_closed",
        ):
            self.assertTrue(contract[name], name)
        self.assertEqual(
            tuple(contract["production_namespace_tree_order"]), tuple(range(18))
        )
        self.assertEqual(contract["production_namespace_total_producer_wires"], 389_562_636)
        self.assertEqual(contract["production_namespace_total_producer_rows"], 513_312_336)
        self.assertEqual(contract["production_namespace_total_output_relocation_rows"], 15_938_520)
        self.assertEqual(contract["production_namespace_planned_composition_rows"], 586_057_567)
        self.assertEqual(contract["production_namespace_max_wire_id"], 429_757_232)
        self.assertTrue(contract["production_18_tree_namespace_plan_closed"])
        self.assertEqual(
            contract["production_tree2_planned_local_wire_start"], 118_102_257
        )
        self.assertEqual(contract["production_tree2_planned_max_wire_id"], 137_580_692)
        self.assertEqual(
            contract["production_tree2_rebased_production_rows_replayed"],
            25_666_386,
        )
        self.assertEqual(
            contract["production_tree2_rebased_recovery_evidence_sha256"],
            core.native_profile.tree2_rebased_recovery_evidence.FROZEN_EVIDENCE_SHA256,
        )
        self.assertTrue(contract["production_tree2_planned_offset_execution_gate_closed"])
        self.assertTrue(contract["planned_offset_reduced_fixture_replayed"])
        self.assertTrue(contract["production_tree2_rebased_assignment_materialized"])
        self.assertTrue(contract["production_tree2_rebased_full_replay_closed"])
        self.assertEqual(
            contract["planned_tree_runner_relation_id"],
            core.native_profile.planned_tree_producer.RELATION_ID,
        )
        self.assertEqual(
            contract["production_tree1_planned_local_wire_start"], 79_148_427
        )
        self.assertEqual(
            contract["production_tree1_planned_max_wire_id"], 118_102_256
        )
        self.assertEqual(
            tuple(contract["production_tree1_planned_output_wire_starts"]),
            (116_373_499, 117_954_555, 117_956_603, 118_097_239),
        )
        self.assertEqual(contract["production_tree1_planned_rows_replayed"], 51_325_080)
        self.assertEqual(contract["production_tree1_planned_local_wires"], 38_953_830)
        self.assertEqual(
            contract["production_tree1_planned_row_stream_bytes"], 18_008_277_115
        )
        self.assertEqual(
            contract["production_tree1_planned_recovery_evidence_sha256"],
            core.native_profile.tree1_planned_recovery_evidence.FROZEN_EVIDENCE_SHA256,
        )
        self.assertEqual(contract["production_tree3_planned_local_wire_start"], 137_580_693)
        self.assertEqual(contract["production_tree3_planned_max_wire_id"], 157_059_128)
        self.assertEqual(contract["production_tree3_planned_rows_replayed"], 25_666_386)
        self.assertEqual(contract["production_tree3_planned_local_wires"], 19_478_436)
        self.assertEqual(
            contract["production_tree3_planned_row_stream_bytes"], 8_961_160_824
        )
        self.assertEqual(
            contract["production_tree3_planned_recovery_evidence_sha256"],
            core.native_profile.tree3_planned_recovery_evidence.FROZEN_EVIDENCE_SHA256,
        )
        self.assertEqual(contract["production_tree4_planned_local_wire_start"], 157_059_129)
        self.assertEqual(contract["production_tree4_planned_max_wire_id"], 176_537_564)
        self.assertEqual(contract["production_tree4_planned_rows_replayed"], 25_666_386)
        self.assertEqual(contract["production_tree4_planned_local_wires"], 19_478_436)
        self.assertEqual(
            contract["production_tree4_planned_row_stream_bytes"], 8_961_160_824
        )
        self.assertEqual(
            contract["production_tree4_planned_recovery_evidence_sha256"],
            core.native_profile.tree4_planned_recovery_evidence.FROZEN_EVIDENCE_SHA256,
        )
        self.assertTrue(contract["production_tree1_planned_assignment_materialized"])
        self.assertTrue(contract["production_tree1_planned_full_replay_closed"])
        self.assertTrue(contract["production_tree3_planned_assignment_materialized"])
        self.assertTrue(contract["production_tree3_planned_full_replay_closed"])
        self.assertTrue(contract["production_tree4_planned_assignment_materialized"])
        self.assertTrue(contract["production_tree4_planned_full_replay_closed"])
        self.assertEqual(
            contract["production_tree5_7_batch_recovery_evidence_sha256"],
            core.native_profile.tree5_7_batch_recovery_evidence.FROZEN_EVIDENCE_SHA256,
        )
        self.assertEqual([item["tree_index"] for item in contract["production_tree5_7_batch_contracts"]], [5, 6, 7])
        for tree_index in (5, 6, 7):
            self.assertTrue(contract[f"production_tree{tree_index}_planned_assignment_materialized"])
            self.assertTrue(contract[f"production_tree{tree_index}_planned_full_replay_closed"])
        self.assertEqual(contract["materialized_planned_tree_indices"], list(range(8)))
        self.assertEqual(contract["materialized_planned_tree_count"], 8)
        self.assertFalse(contract["remaining_planned_tree_producers_materialized"])
        self.assertEqual(
            contract["production_composer_recovery_production_levels_checkpointed"],
            182,
        )
        self.assertEqual(
            contract[
                "production_composer_recovery_production_leaf_outputs_checkpointed"
            ],
            40_960,
        )
        self.assertTrue(
            contract["production_composer_checkpoint_recovery_gate_closed"]
        )
        self.assertTrue(contract["reduced_checkpoint_resume_bit_exact"])
        self.assertTrue(contract["production_execution_cache_regenerated"])
        self.assertTrue(contract["production_composition_document_revalidated"])
        self.assertTrue(contract["production_global_tail_archive_regenerated"])
        self.assertTrue(contract["representative_producers_rebased_replayed"])
        self.assertFalse(contract["all_72_output_relocations_closed"])
        self.assertTrue(contract["reduced_tree_producer_segments_native_closed"])
        self.assertTrue(contract["reduced_producer_to_tail_port_values_match"])
        self.assertFalse(contract["reduced_producer_point_wire_identity_closed"])
        self.assertFalse(contract["tree_producer_segments_materialized"])
        self.assertFalse(contract["cross_segment_wire_identity_closed"])
        self.assertFalse(contract["monolithic_18_tree_assignment_verified"])
        self.assertTrue(contract["canonical_cap_bytes_bound_to_h_rbbc"])
        self.assertFalse(contract["production_cap_native_rows_materialized"])
        self.assertEqual(
            contract["cap_production_accounting"]["commitment_bytes"], 5_391
        )
        self.assertFalse(contract["complete_cap_hash_implemented"])
        self.assertFalse(contract["blind_uov_bit_exact_compatible"])
        self.assertFalse(contract["paper_240_gap_blocks_fork_engineering"])
        self.assertFalse(contract["fork_security_proof_revalidated"])
        self.assertFalse(contract["signature_size_rebenchmarked"])
        self.assertFalse(contract["production_closed"])

    def test_every_negative_case_rejects(self) -> None:
        results = core.negative_case_results(
            self.matrix, self.statement, self.witness, self.adapter
        )
        expected_cases = {
            "wrong_weight",
            "syndrome_tamper",
            "masked_identity_tamper",
            "holder_hash_tamper",
            "tag_tamper",
            "serial_tamper",
            "blind_request_tamper",
            "blind_mask_tamper",
            "blind_hash_image_tamper",
            "blind_randomness_tamper",
            "context_tamper",
        }
        self.assertEqual(set(results), expected_cases)
        for name, failures in results.items():
            with self.subTest(name=name):
                self.assertTrue(failures, "tampered relation unexpectedly accepted")

    def test_full_incremental_circuit_accepts_and_matches_audit(self) -> None:
        report = core.generate_issue_circuit(
            self.matrix, self.statement, self.witness, self.adapter
        )
        self.assertTrue(report.satisfied)
        self.assertEqual(report.totals["failed_assertions"], 0)
        self.assertEqual(report.totals["keccak_permutations"], 17)
        self.assertEqual(report.totals["bitness_constraints"], 8224)
        self.assertEqual(report.totals["nonlinear_constraints"], 685_571)
        self.assertEqual(report.public_input_bits, 4032)
        self.assertEqual(report.secret_input_bits, 8224)
        self.assertEqual(report.totals["linear_assertions"], 3534)
        self.assertEqual(report.wire_count, 2_980_304)
        self.assertEqual(report.external_assertions, 1)
        self.assertEqual(report.blocks["shape"]["nonlinear_constraints"], 128)
        self.assertEqual(
            report.blocks["ticket_hash"]["nonlinear_constraints"], 115_200
        )
        self.assertEqual(
            report.blocks["blind_uov_mask_binding"]["nonlinear_constraints"],
            1152,
        )
        self.assertEqual(
            report.blocks["blind_uov_mask_binding"]["linear_assertions"],
            576,
        )
        self.assertEqual(report.blocks["holder"]["nonlinear_constraints"], 38_656)
        self.assertEqual(report.blocks["trace"]["nonlinear_constraints"], 530_435)

    def test_full_circuit_rejects_every_negative_case(self) -> None:
        cases = core.negative_cases(
            self.matrix, self.statement, self.witness, self.adapter
        )
        for name, (statement, witness) in cases.items():
            with self.subTest(name=name):
                report = core.generate_issue_circuit(
                    self.matrix, statement, witness, self.adapter
                )
                self.assertFalse(report.satisfied, "tampered circuit unexpectedly accepted")

    def test_mask_equation_rejects_even_if_native_boundary_lies(self) -> None:
        class AlwaysAcceptNativeBoundary(type(self.adapter)):
            def verify_cap_hash(
                self,
                message: bytes,
                mask: bytes,
                cap_randomness: bytes,
                hash_image: bytes,
            ) -> bool:
                return True

        changed = bytearray(self.statement.blind_request.masked_target)
        changed[0] ^= 1
        bad_statement = replace(
            self.statement,
            blind_request=replace(
                self.statement.blind_request,
                masked_target=bytes(changed),
            ),
        )
        report = core.generate_issue_circuit(
            self.matrix,
            bad_statement,
            self.witness,
            AlwaysAcceptNativeBoundary(),
        )
        self.assertFalse(report.satisfied)
        self.assertEqual(report.external_assertions, 1)
        self.assertGreater(
            report.blocks["blind_uov_mask_binding"]["failed_assertions"], 0
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
