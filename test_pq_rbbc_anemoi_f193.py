#!/usr/bin/env python3
"""Regression and tamper tests for the PQ-RBBC v1.9 Anemoi probe."""

from __future__ import annotations

import hashlib
import unittest

import pq_rbbc_anemoi_f193 as anemoi


class AnemoiF193Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = anemoi.derive_parameters()
        cls.zero_trace = anemoi.build_native_trace(
            (0,) * anemoi.STATE_ELEMENTS, cls.parameters
        )

    def test_field_and_round_rules_are_frozen(self) -> None:
        self.assertEqual(
            anemoi.CONWAY_EXPONENTS, (193, 8, 7, 6, 5, 4, 2, 1, 0)
        )
        self.assertEqual(
            anemoi.upstream_round_count(192, 4, 3), anemoi.UPSTREAM_ROUNDS
        )
        self.assertEqual(anemoi.UPSTREAM_ROUNDS, 14)
        self.assertEqual(
            anemoi.paper_characteristic_two_round_count(192, 4), 15
        )

    def test_field_inverse_and_reduction(self) -> None:
        for value in (1, 2, 3, 0x123456789ABCDEF, anemoi.FIELD_MASK):
            self.assertEqual(anemoi.fmul(value, anemoi.finv(value)), 1)

    def test_fast_square_and_cube_root_match_generic_arithmetic(self) -> None:
        for value in (0, 1, 2, 3, (1 << 192) | 0xA5A5, anemoi.FIELD_MASK):
            with self.subTest(value=value):
                self.assertEqual(
                    anemoi.fsquare(value),
                    anemoi.fmul(value, value),
                )
                self.assertEqual(
                    anemoi.fcuberoot(value),
                    anemoi.fpow(value, pow(3, -1, anemoi.FIELD_ORDER - 1)),
                )
                self.assertEqual(
                    anemoi.fpow(anemoi.fcuberoot(value), 3),
                    value,
                )
        reduced_x_193 = anemoi.fmul(1 << 192, 2)
        self.assertEqual(reduced_x_193, anemoi.REDUCTION_POLYNOMIAL)

    def test_mds_and_parameter_fingerprint_are_frozen(self) -> None:
        self.assertEqual(self.parameters.mds_generator_exponent, 1)
        self.assertTrue(anemoi.is_mds(self.parameters.mds_matrix))
        self.assertEqual(
            self.parameters.fingerprint(),
            "5718d003de2fed43e675d36949320e7a140d0f278d7a44e825175f1ea0789b12",
        )

    def test_honest_trace_has_exact_rows(self) -> None:
        self.assertEqual(self.zero_trace.nonlinear_rows, 336)
        self.assertEqual(self.zero_trace.output_binding_rows, 8)
        self.assertEqual(len(self.zero_trace.rows), 344)
        self.assertEqual(len(self.zero_trace.assignment), 352)
        self.assertEqual(self.zero_trace.failed_rows(), [])

    def test_direct_and_constrained_outputs_match(self) -> None:
        for state in (
            (0,) * anemoi.STATE_ELEMENTS,
            tuple(range(1, anemoi.STATE_ELEMENTS + 1)),
            tuple(1 << index for index in range(anemoi.STATE_ELEMENTS)),
        ):
            trace = anemoi.build_native_trace(state, self.parameters)
            self.assertEqual(
                trace.output_state,
                anemoi.evaluate_permutation(state, self.parameters),
            )
            self.assertEqual(trace.failed_rows(), [])

    def test_stale_witness_rejects_input_tamper(self) -> None:
        assignment = dict(self.zero_trace.assignment)
        assignment[self.zero_trace.input_wires[0]] ^= 1
        self.assertTrue(self.zero_trace.failed_rows(assignment))

    def test_output_binding_rejects_output_tamper(self) -> None:
        assignment = dict(self.zero_trace.assignment)
        assignment[self.zero_trace.output_wires[-1]] ^= 1
        failures = self.zero_trace.failed_rows(assignment)
        self.assertIn("output[7]", failures)

    def test_row_topology_is_witness_independent(self) -> None:
        other = anemoi.build_native_trace(
            tuple(range(1, anemoi.STATE_ELEMENTS + 1)), self.parameters
        )
        zero_stream = anemoi.serialize_row_stream(self.zero_trace, self.parameters)
        other_stream = anemoi.serialize_row_stream(other, self.parameters)
        self.assertEqual(zero_stream, other_stream)
        self.assertEqual(
            hashlib.sha256(zero_stream).hexdigest(),
            "25deba5f7fa3f54f1ccc2fd165f2755f8d7137eaa924def12f0c28ba5cdbae4d",
        )

    def test_blind_uov_parameter_gap_is_fail_closed(self) -> None:
        manifest = anemoi.build_manifest(self.zero_trace, self.parameters)
        gap = manifest["public_artifact_gap"]
        self.assertEqual(gap["blind_uov_reported_constraints"], 240)
        self.assertEqual(gap["direct_closed_flystel_rows_for_upstream_main"], 336)
        self.assertEqual(gap["direct_closed_flystel_rows_for_paper_round_rule"], 360)
        self.assertFalse(gap["reported_count_reproduced"])
        self.assertFalse(gap["gap_resolved"])
        self.assertFalse(manifest["claim_boundary"]["production_closed"])


if __name__ == "__main__":
    unittest.main()
