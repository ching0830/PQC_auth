#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC-BUOV-336 hidden-state ABI."""

from __future__ import annotations

import dataclasses
import hashlib
from types import SimpleNamespace
import unittest

import pq_rbbc_blind_uov_abi as abi
import pq_rbbc_cap_commit as cap
import pq_rbbc_reference as core


class BlindUOVVisibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = abi.TestPQRBBC336Adapter()
        self.message = hashlib.shake_256(b"abi-test-message-v2.0").digest(32)
        self.mask = hashlib.shake_256(b"abi-test-mask-v2.0").digest(72)
        self.randomness = hashlib.shake_256(b"abi-test-randomness-v2.0").digest(32)
        self.request = self.adapter.create(
            self.message, self.mask, self.randomness
        )

    def test_public_request_is_exactly_y(self) -> None:
        self.assertEqual(len(self.request.encode()), 72)
        self.assertEqual(self.request.encode(), self.request.masked_target)
        self.assertEqual(
            [field.name for field in dataclasses.fields(self.request)],
            ["masked_target"],
        )

    def test_commitment_and_message_are_not_public_request_fields(self) -> None:
        request_fields = {field.name for field in dataclasses.fields(self.request)}
        self.assertNotIn("cap_commitment", request_fields)
        self.assertNotIn("message_digest", request_fields)
        statement_fields = {
            field.name for field in dataclasses.fields(core.IssueStatement)
        }
        self.assertNotIn("ticket_digest", statement_fields)

    def test_hidden_relation_accepts_and_tampering_rejects(self) -> None:
        hidden = self.adapter.hidden_state(
            self.message, self.mask, self.randomness
        )
        self.assertTrue(
            self.adapter.verify_cap_hash(
                self.message,
                self.mask,
                self.randomness,
                hidden.hash_image,
            )
        )
        self.assertEqual(
            self.request.masked_target,
            abi.xor_bytes(self.mask, hidden.hash_image),
        )
        self.assertTrue(
            self.adapter.verify(
                self.request, self.message, self.mask, self.randomness
            )
        )
        changed_message = bytes((self.message[0] ^ 1,)) + self.message[1:]
        self.assertFalse(
            self.adapter.verify(
                self.request, changed_message, self.mask, self.randomness
            )
        )
        changed_hash_image = bytes((hidden.hash_image[0] ^ 1,)) + hidden.hash_image[1:]
        self.assertFalse(
            self.adapter.verify_cap_hash(
                self.message,
                self.mask,
                self.randomness,
                changed_hash_image,
            )
        )
        changed_y = bytes((self.request.masked_target[0] ^ 1,)) + self.request.masked_target[1:]
        self.assertFalse(
            self.adapter.verify(
                abi.BlindUOVRequest(changed_y),
                self.message,
                self.mask,
                self.randomness,
            )
        )

    def test_wrong_mask_length_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.adapter.create(self.message, self.mask[:-1], self.randomness)

    def test_production_cap_byte_join_is_strict(self) -> None:
        view = SimpleNamespace(
            parameters_fingerprint=cap.profile_fingerprint(
                cap.PRODUCTION_PARAMETERS
            ),
            derived_mask=int.from_bytes(self.mask, "little"),
            encoded=bytes(cap.commitment_bytes(cap.PRODUCTION_PARAMETERS)),
        )
        state = abi.request_from_production_cap(self.message, view)
        self.assertEqual(len(state.request.encode()), 72)
        self.assertEqual(state.mask, self.mask)
        self.assertEqual(
            state.request.masked_target,
            abi.xor_bytes(state.mask, state.hash_image),
        )
        bad_profile = SimpleNamespace(
            parameters_fingerprint="00" * 32,
            derived_mask=view.derived_mask,
            encoded=view.encoded,
        )
        with self.assertRaises(ValueError):
            abi.request_from_production_cap(self.message, bad_profile)
        bad_length = SimpleNamespace(
            parameters_fingerprint=view.parameters_fingerprint,
            derived_mask=view.derived_mask,
            encoded=view.encoded[:-1],
        )
        with self.assertRaises(ValueError):
            abi.request_from_production_cap(self.message, bad_length)

    def test_manifest_records_fork_boundary_and_qrom_assumption(self) -> None:
        manifest = abi.build_abi_manifest()
        checks = manifest["regression_checks"]
        self.assertTrue(checks["honest_request_accepts"])
        self.assertFalse(checks["request_has_cap_commitment_field"])
        self.assertFalse(checks["request_has_message_digest_field"])
        self.assertEqual(
            manifest["binding_reduction"]["name"],
            "single-lane QROM cross-message request collision resistance",
        )
        self.assertIn("2^192", manifest["binding_reduction"]["generic_quantum_collision_cost"])
        self.assertFalse(
            manifest["v1_6_correction"][
                "independent_parallel_lanes_amplify_security_bits"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"]["linear_y_equals_r_plus_h_internalized"]
        )
        self.assertTrue(
            manifest["claim_boundary"]["test_adapter_uses_forked_anemoi_request_hash"]
        )
        self.assertFalse(manifest["fork_profile"]["blind_uov_bit_exact_compatible"])
        self.assertFalse(manifest["fork_profile"]["paper_security_reduction_revalidated"])
        self.assertFalse(manifest["fork_profile"]["paper_signature_size_rebenchmarked"])
        self.assertFalse(
            manifest["claim_boundary"]["native_tcih_anemoi_constraint_import_complete"]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_cap_reference_algorithm_implemented"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_cap_canonical_serialization_bound_to_h_rbbc"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "reduced_cap_to_h_rbbc_native_wire_join_complete"
            ]
        )
        self.assertEqual(
            manifest["claim_boundary"]["reduced_cap_native_external_assertions"],
            0,
        )
        self.assertFalse(
            manifest["claim_boundary"]["reduced_cap_profile_is_secure"]
        )
        self.assertFalse(
            manifest["claim_boundary"][
                "full_production_cap_native_rows_materialized"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "arbitrary_length_multi_squeeze_native"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "production_width_2450_bit_tape_native"
            ]
        )
        self.assertEqual(
            manifest["claim_boundary"]["extended_2450_cap_native_rows"],
            113_802,
        )
        self.assertEqual(
            manifest["claim_boundary"][
                "extended_2450_cap_native_external_assertions"
            ],
            0,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
