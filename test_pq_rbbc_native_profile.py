#!/usr/bin/env python3
"""Tests for the fail-closed PQ-RBBC v2.4 fork import contract."""

from __future__ import annotations

import unittest

import pq_rbbc_native_profile as native


class ForkNativeProfileTests(unittest.TestCase):
    def test_selected_profile_is_not_blind_uov_bit_exact(self) -> None:
        manifest = native.build_native_profile_manifest()
        compatibility = manifest["compatibility"]
        self.assertFalse(compatibility["blind_uov_bit_exact_compatible"])
        self.assertFalse(
            compatibility["paper_security_reduction_automatically_inherited"]
        )
        self.assertFalse(
            compatibility["paper_signature_size_automatically_inherited"]
        )
        self.assertFalse(
            compatibility["reported_240_constraint_gap_blocks_fork_engineering"]
        )
        self.assertFalse(manifest["claim_boundary"]["production_closed"])
        self.assertTrue(
            manifest["implemented_primitives"]["production_cap_reference_algorithm"]
        )
        self.assertTrue(
            manifest["implemented_primitives"]["cap_to_h_rbbc_byte_join"]
        )
        self.assertFalse(
            manifest["implemented_primitives"][
                "production_cap_native_rows_materialized"
            ]
        )
        self.assertEqual(manifest["fork_profile"]["cap_commitment_bytes"], 5_378)
        reduced = manifest["fork_profile"]["reduced_native_component"]
        self.assertEqual(reduced["rows"], 88_282)
        self.assertEqual(reduced["wires"], 59_602)
        self.assertEqual(reduced["external_assertions"], 0)
        self.assertTrue(
            manifest["implemented_primitives"][
                "reduced_cap_to_h_rbbc_native_wire_join"
            ]
        )
        self.assertTrue(manifest["claim_boundary"]["reduced_fixture_native_closed"])
        self.assertFalse(manifest["claim_boundary"]["reduced_fixture_security_profile"])
        extended = manifest["fork_profile"]["extended_2450_native_component"]
        self.assertEqual(extended["production_width_tape_bits"], 2_450)
        self.assertEqual(extended["rows"], 113_802)
        self.assertEqual(extended["wires"], 85_034)
        self.assertEqual(extended["anemoi_permutations"], 81)
        self.assertEqual(extended["external_assertions"], 0)
        self.assertTrue(
            manifest["implemented_primitives"][
                "arbitrary_length_multi_squeeze_native"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "extended_2450_fixture_native_closed"
            ]
        )
        arithmetic = manifest["fork_profile"][
            "production_width_horner_component"
        ]
        self.assertEqual(arithmetic["vector_bits"], 2_048)
        self.assertEqual(arithmetic["coefficients"], 11)
        self.assertEqual(arithmetic["multiplication_rows"], 20)
        self.assertEqual(arithmetic["external_assertions"], 0)
        combined = manifest["fork_profile"]["horner_2450_native_component"]
        self.assertEqual(combined["witness_bits"], 386)
        self.assertEqual(combined["consistency_points"], 2)
        self.assertEqual(combined["rows"], 125_401)
        self.assertEqual(combined["wires"], 92_816)
        self.assertEqual(combined["multiplication_rows"], 14)
        self.assertEqual(combined["external_assertions"], 0)
        self.assertTrue(
            manifest["claim_boundary"]["arithmetic_primitive_native_closed"]
        )
        self.assertTrue(
            manifest["claim_boundary"]["horner_2450_fixture_native_closed"]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_polynomial_hash_blocker_closed"
            ]
        )
        self.assertFalse(
            manifest["claim_boundary"][
                "production_2048_bit_cap_integration_closed"
            ]
        )

    def test_missing_import_is_fail_closed(self) -> None:
        audit = native.audit_fork_import(None)
        self.assertFalse(audit.closed)
        self.assertEqual(
            audit.failures, ("fork_native_import_evidence_missing",)
        )

    def test_missing_component_rejects(self) -> None:
        component_rows = {name: 1 for name in native.REQUIRED_NATIVE_COMPONENTS}
        component_rows.pop("ggm_seed_expansion")
        evidence = self._complete_synthetic_evidence(component_rows=component_rows)
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertTrue(
            any(item.startswith("missing_native_components:") for item in audit.failures)
        )

    def test_unreviewed_fork_security_rejects(self) -> None:
        evidence = self._complete_synthetic_evidence(
            fork_security_proof_revalidated=False
        )
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("fork_security_proof_revalidated", audit.failures)

    def test_unbenchmarked_signature_size_rejects(self) -> None:
        evidence = self._complete_synthetic_evidence(
            signature_size_rebenchmarked=False
        )
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("signature_size_rebenchmarked", audit.failures)

    def test_false_bit_exact_claim_rejects(self) -> None:
        evidence = self._complete_synthetic_evidence(
            claims_blind_uov_bit_exact_compatibility=True
        )
        audit = native.audit_fork_import(evidence)
        self.assertFalse(audit.closed)
        self.assertIn("forbidden_blind_uov_bit_exact_claim", audit.failures)

    def test_structurally_complete_synthetic_evidence_passes(self) -> None:
        evidence = self._complete_synthetic_evidence()
        audit = native.audit_fork_import(evidence)
        self.assertTrue(audit.closed, audit.failures)

    @staticmethod
    def _complete_synthetic_evidence(
        **changes: object,
    ) -> native.ForkNativeImportEvidence:
        components = {name: 1 for name in native.REQUIRED_NATIVE_COMPONENTS}
        values: dict[str, object] = {
            "relation_id": native.RELATION_ID,
            "fork_profile_sha256": native.fork_profile_fingerprint(),
            "target_field": native.TARGET_FIELD,
            "generator_source_sha256": "11" * 32,
            "parameter_file_sha256": "22" * 32,
            "row_stream_sha256": "33" * 32,
            "native_rows": len(components),
            "external_assertions": 0,
            "witness_independent_topology": True,
            "honest_accepts": True,
            "tamper_rejections": {
                "message": True,
                "mask": True,
                "cap_randomness": True,
                "hash_image": True,
            },
            "component_rows": components,
            "circuit_ticket_digest_is_native_message": True,
            "circuit_mask_is_native_mask": True,
            "circuit_hash_image_is_native_output": True,
            "domain_separation_locked": True,
            "serialization_locked": True,
            "fork_vectors_verified_independently": True,
            "cap_unique_witness_reviewed": True,
            "cap_straightline_extraction_reviewed": True,
            "fork_security_proof_revalidated": True,
            "signature_size_rebenchmarked": True,
            "claims_blind_uov_bit_exact_compatibility": False,
        }
        values.update(changes)
        if "component_rows" in changes and "native_rows" not in changes:
            values["native_rows"] = sum(
                int(value) for value in values["component_rows"].values()
            )
        return native.ForkNativeImportEvidence(**values)


if __name__ == "__main__":
    unittest.main(verbosity=2)
