#!/usr/bin/env python3
"""Regression tests for PQ-RBBC v2.4 native multiplication and Horner rows."""

from __future__ import annotations

import hashlib
import unittest

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_cap_commit as cap
import pq_rbbc_horner_native as native


class NativeMultiplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.left, cls.right = native.frozen_multiplication_fixture()
        cls.trace = native.build_multiplication_trace(cls.left, cls.right)
        cls.row_stream = native.serialize_multiplication_row_stream(cls.trace)

    def test_exact_multiplication_vector_and_rows(self) -> None:
        self.assertEqual(self.trace.output, field.fmul(self.left, self.right))
        self.assertEqual(
            field.fhex(self.trace.output),
            "011e6dabdb4a6f680c8f194ffd9d0dfc4a7a20a7a5599900c9",
        )
        self.assertEqual(len(self.trace.assignment), 580)
        self.assertEqual(len(self.trace.rows), 581)
        self.assertEqual(self.trace.multiplication_rows, 1)
        self.assertEqual(self.trace.input_bitness_rows, 386)
        self.assertEqual(self.trace.output_bitness_rows, 193)
        self.assertEqual(self.trace.output_pack_rows, 1)
        self.assertEqual(self.trace.failed_rows(), [])
        self.assertEqual(len(self.row_stream), 269_342)
        self.assertEqual(
            hashlib.sha256(self.row_stream).hexdigest(),
            "1c2c2bb9fa869fd43f1bc1f7089e5e05a6f9e5cba1d1c8d0a6a80039417681f7",
        )

    def test_operand_tamper_rejects_stale_product(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.left_bit_wires[0]] ^= 1
        self.assertIn("product.mul", self.trace.failed_rows(assignment))

    def test_output_bit_tamper_rejects_stale_product(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.output_bit_wires[-1]] ^= 1
        self.assertIn("output.pack", self.trace.failed_rows(assignment))


class NativeHornerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vector, cls.points = native.frozen_horner_fixture()
        cls.trace = native.build_horner_trace(
            cls.vector,
            native.PRODUCTION_WITNESS_BITS,
            cls.points,
        )
        cls.row_stream = native.serialize_horner_row_stream(cls.trace)

    def test_exact_production_width_horner_vector(self) -> None:
        self.assertEqual(self.trace.vector_bits, 2_048)
        self.assertEqual(self.trace.accounting.coefficients, 11)
        self.assertEqual(self.trace.accounting.points, 2)
        self.assertEqual(self.trace.accounting.multiplication_rows, 20)
        self.assertEqual(self.trace.accounting.point_validation_rows, 3)
        self.assertEqual(self.trace.accounting.output_bitness_rows, 386)
        self.assertEqual(self.trace.accounting.output_pack_rows, 2)
        self.assertEqual(len(self.trace.assignment), 2_843)
        self.assertEqual(len(self.trace.rows), 2_845)
        self.assertEqual(self.trace.nonlinear_rows, 2_843)
        self.assertEqual(self.trace.linear_rows, 2)
        self.assertEqual(self.trace.external_assertions, 0)
        self.assertEqual(self.trace.failed_rows(), [])
        self.assertEqual(
            self.trace.output_bytes.hex(),
            "8cdbedaf58ce66bc2ea57fcbfab70282a60781d5564dc0e6827a83d0e8c393e2"
            "5c6cc19bf2496ab0a3771a29780c4cc402",
        )
        self.assertEqual(
            hashlib.sha256(self.trace.output_bytes).hexdigest(),
            "3efd441d53d4ecc3874e0cf3ffb0884a58bccfcf534392b3046c604a41efbc22",
        )

    def test_horner_matches_cap_reference(self) -> None:
        packed_reference = cap._linear_hash_vector(
            self.vector,
            self.trace.vector_bits,
            self.points,
        )
        packed_native = sum(
            value << (index * field.FIELD_DEGREE)
            for index, value in enumerate(self.trace.output_fields)
        )
        self.assertEqual(packed_native, packed_reference)

    def test_horner_row_stream_is_frozen(self) -> None:
        self.assertEqual(len(self.row_stream), 1_714_967)
        self.assertEqual(
            hashlib.sha256(self.row_stream).hexdigest(),
            "0c9d742d44808a20a35838be84a638924dc5b2f9183bba731eefba1cb9069850",
        )

    def test_vector_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.vector_bit_wires[0]] ^= 1
        failures = self.trace.failed_rows(assignment)
        # Bit zero belongs to c_0, which is added after the final native
        # multiplication; stale output decompositions must therefore fail.
        self.assertIn("horner.point[0].output.pack", failures)
        self.assertIn("horner.point[1].output.pack", failures)

    def test_point_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.point_bit_wires[0][0]] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertTrue(any("horner.validate" in label for label in failures))
        self.assertTrue(any(label.startswith("horner.point[0].mul") for label in failures))

    def test_intermediate_product_tamper_rejects(self) -> None:
        target = next(
            wire_id
            for wire_id, label in self.trace.wire_labels.items()
            if label == "horner.point[0].mul[9]"
        )
        assignment = dict(self.trace.assignment)
        assignment[target] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertIn("horner.point[0].mul[9]", failures)

    def test_output_tamper_rejects(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.output_bit_wires[-1]] ^= 1
        self.assertIn("horner.point[1].output.pack", self.trace.failed_rows(assignment))

    def test_degenerate_points_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            native.build_horner_trace(self.vector, 2_048, (0, self.points[1]))
        with self.assertRaises(ValueError):
            native.build_horner_trace(self.vector, 2_048, (self.points[0], self.points[0]))

    def test_topology_is_witness_independent(self) -> None:
        changed_points = (self.points[0] ^ 1, self.points[1] ^ 1)
        self.assertTrue(all(changed_points))
        self.assertNotEqual(changed_points[0], changed_points[1])
        changed = native.build_horner_trace(
            self.vector ^ ((1 << 2_048) - 1),
            2_048,
            changed_points,
        )
        changed_stream = native.serialize_horner_row_stream(changed)
        self.assertEqual(changed.failed_rows(), [])
        self.assertEqual(changed_stream, self.row_stream)
        self.assertNotEqual(changed.output_bytes, self.trace.output_bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
