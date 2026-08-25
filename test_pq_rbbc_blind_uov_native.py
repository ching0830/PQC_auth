#!/usr/bin/env python3
"""Tests for the v1.8 native Blind-UOV-III import contract."""

from __future__ import annotations

import unittest

import pq_rbbc_blind_uov_native as native


class NativeImportContractTests(unittest.TestCase):
    def test_frozen_paper_profile(self) -> None:
        profile = native.PAPER_PROFILE
        self.assertEqual(profile.security_parameter_bits, 192)
        self.assertEqual(profile.n_r_bits, 576)
        self.assertEqual(profile.n_x_bits, 1472)
        self.assertEqual(profile.cap_witness_bits, 2048)
        self.assertEqual(profile.cap_parallel_repetitions, 18)
        self.assertEqual(profile.tree_groups, ((2, 4096), (16, 2048)))
        self.assertEqual(profile.opened_seeds_upper_bound, 174)
        self.assertEqual(profile.anemoi_field_degree, 193)
        self.assertEqual(profile.anemoi_constraints_per_permutation, 240)
        self.assertFalse(profile.level_iii_nizk_cost_reported_by_paper)

    def test_missing_import_can_never_be_closed(self) -> None:
        audit = native.audit_native_import(None)
        self.assertFalse(audit.closed)
        self.assertEqual(audit.failures, ("native_import_evidence_missing",))

    def test_external_assertion_prevents_closure(self) -> None:
        evidence = self._complete_synthetic_evidence(external_assertions=1)
        audit = native.audit_native_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("external_assertions_remain", audit.failures)

    def test_field_mismatch_prevents_closure(self) -> None:
        evidence = self._complete_synthetic_evidence(target_field="F2")
        audit = native.audit_native_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("backend_field_mismatch", audit.failures)

    def test_missing_binding_tamper_case_prevents_closure(self) -> None:
        evidence = self._complete_synthetic_evidence(
            tamper_rejections={"message": True, "mask": True, "hash_image": True}
        )
        audit = native.audit_native_import(evidence)
        self.assertFalse(audit.closed)
        self.assertTrue(
            any(item.startswith("missing_tamper_cases:") for item in audit.failures)
        )

    def test_structurally_complete_synthetic_evidence_passes_validator(self) -> None:
        evidence = self._complete_synthetic_evidence()
        audit = native.audit_native_import(evidence)
        self.assertTrue(audit.closed, audit.failures)

    @staticmethod
    def _complete_synthetic_evidence(**changes: object) -> native.NativeImportEvidence:
        values: dict[str, object] = {
            "relation_id": native.RELATION_ID,
            "profile_sha256": native.PAPER_PROFILE.fingerprint(),
            "target_field": native.TARGET_FIELD,
            "generator_source_sha256": "11" * 32,
            "parameter_file_sha256": "22" * 32,
            "row_stream_sha256": "33" * 32,
            "native_rows": 1,
            "external_assertions": 0,
            "witness_independent_topology": True,
            "honest_accepts": True,
            "tamper_rejections": {
                "message": True,
                "mask": True,
                "cap_randomness": True,
                "hash_image": True,
            },
            "circuit_ticket_digest_is_native_message": True,
            "circuit_mask_is_native_mask": True,
            "circuit_hash_image_is_native_output": True,
            "domain_separation_locked": True,
            "serialization_locked": True,
            "anemoi_test_vectors_verified": True,
            "cap_unique_witness_reviewed": True,
            "cap_straightline_extraction_reviewed": True,
        }
        values.update(changes)
        return native.NativeImportEvidence(**values)


if __name__ == "__main__":
    unittest.main(verbosity=2)
