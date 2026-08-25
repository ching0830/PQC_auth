#!/usr/bin/env python3
"""Regression tests for the executable PQ-RBBC/SGTD v1.7 relation."""

from __future__ import annotations

import hashlib
import unittest

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
        self.assertEqual(report.totals["bitness_constraints"], 7072)
        self.assertEqual(report.totals["nonlinear_constraints"], 684_419)
        self.assertEqual(report.public_input_bits, 4032)
        self.assertEqual(report.totals["linear_assertions"], 2958)
        self.assertEqual(report.wire_count, 2_976_848)
        self.assertEqual(report.external_assertions, 1)
        self.assertEqual(report.blocks["shape"]["nonlinear_constraints"], 128)
        self.assertEqual(
            report.blocks["ticket_hash"]["nonlinear_constraints"], 115_200
        )
        self.assertEqual(
            report.blocks["blind_uov_mask_increment"]["nonlinear_constraints"],
            0,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
