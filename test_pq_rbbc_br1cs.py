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
        self.assertEqual(accounting["nonlinear_rows"], 685_571)
        self.assertEqual(accounting["materialized_linear_rows"], 2_286_009)
        self.assertEqual(accounting["portable_total_r1cs_rows"], 2_971_580)

    def test_archive_is_complete_and_round_trips(self) -> None:
        archive = self.manifest["archive"]
        round_trip = self.manifest["round_trip"]
        self.assertEqual(archive["wire_count"], 2_980_304)
        self.assertEqual(archive["public_inputs"], 4032)
        self.assertEqual(archive["secret_inputs"], 8224)
        self.assertEqual(archive["keccak_permutations"], 17)
        self.assertTrue(round_trip["honest_assignment_accepts"])
        self.assertTrue(round_trip["body_sha256_verified"])
        self.assertEqual(round_trip["rows_checked"], 2_971_580)

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
        self.assertEqual(boundary["external_assertions"], 1)
        self.assertEqual(
            boundary["external_component"],
            "native PQ-RBBC-CAP-v1 full 18-tree row stream and exact H_RBBC wire join",
        )
        self.assertEqual(
            self.manifest["round_trip"]["external_assertions_unchecked"], 1
        )
        contract = self.manifest["native_import_contract"]
        self.assertTrue(contract["linear_mask_equation_internalized"])
        self.assertFalse(contract["current_archive_field_matches_target"])
        self.assertEqual(contract["anemoi_component_nonlinear_rows"], 336)
        self.assertTrue(contract["request_binding_hash_primitive_implemented"])
        self.assertTrue(contract["production_cap_reference_algorithm_implemented"])
        self.assertEqual(contract["reduced_cap_native_rows"], 88_282)
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
        self.assertTrue(contract["canonical_cap_bytes_bound_to_h_rbbc"])
        self.assertFalse(contract["production_cap_native_rows_materialized"])
        self.assertFalse(contract["complete_cap_hash_implemented"])
        self.assertFalse(contract["blind_uov_bit_exact_compatible"])
        self.assertFalse(contract["paper_240_gap_blocks_fork_engineering"])
        self.assertFalse(contract["fork_security_proof_revalidated"])
        self.assertFalse(contract["signature_size_rebenchmarked"])
        self.assertFalse(contract["production_closed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
