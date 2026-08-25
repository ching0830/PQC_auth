#!/usr/bin/env python3
"""End-to-end tests for the PQ-RBBC binary F2-R1CS backend."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pq_rbbc_br1cs as backend


class BinaryR1CSBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="pq-rbbc-br1cs-test-")
        cls.archive = Path(cls.temporary.name) / "reference.br1cs"
        cls.manifest = backend.build_backend_manifest(cls.archive)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_exact_portable_row_counts(self) -> None:
        accounting = self.manifest["constraint_accounting"]
        self.assertEqual(accounting["nonlinear_rows"], 684_419)
        self.assertEqual(accounting["materialized_linear_rows"], 2_284_281)
        self.assertEqual(accounting["portable_total_r1cs_rows"], 2_968_700)

    def test_archive_is_complete_and_round_trips(self) -> None:
        archive = self.manifest["archive"]
        round_trip = self.manifest["round_trip"]
        self.assertEqual(archive["wire_count"], 2_976_784)
        self.assertEqual(archive["public_inputs"], 3968)
        self.assertEqual(archive["secret_inputs"], 7072)
        self.assertEqual(archive["keccak_permutations"], 17)
        self.assertTrue(round_trip["honest_assignment_accepts"])
        self.assertTrue(round_trip["body_sha256_verified"])
        self.assertEqual(round_trip["rows_checked"], 2_968_700)

    def test_assignment_and_archive_tampering_are_rejected(self) -> None:
        round_trip = self.manifest["round_trip"]
        self.assertTrue(round_trip["assignment_bit_tamper_rejected"])
        self.assertTrue(round_trip["archive_corruption_rejected"])

    def test_structure_is_witness_independent(self) -> None:
        independence = self.manifest["witness_independence"]
        self.assertTrue(independence["honest_and_wrong_weight_body_digest_equal"])
        self.assertTrue(independence["wrong_weight_assignment_rejected"])
        self.assertGreater(independence["wrong_weight_failed_constraints"], 0)

    def test_blind_uov_boundary_remains_explicit(self) -> None:
        boundary = self.manifest["claim_boundary"]
        self.assertEqual(boundary["external_assertions"], 2)
        self.assertEqual(
            boundary["external_component"],
            "two native Blind-UOV pi_1/CAP request relations",
        )
        self.assertEqual(
            self.manifest["round_trip"]["external_assertions_unchecked"], 2
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
