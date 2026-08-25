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
        self.assertTrue(contract["canonical_cap_bytes_bound_to_h_rbbc"])
        self.assertFalse(contract["production_cap_native_rows_materialized"])
        self.assertEqual(
            contract["cap_production_accounting"]["commitment_bytes"], 5_378
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
