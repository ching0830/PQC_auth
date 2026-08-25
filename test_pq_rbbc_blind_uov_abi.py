#!/usr/bin/env python3
"""Regression tests for the Blind-UOV-III hidden-state ABI."""

from __future__ import annotations

import dataclasses
import hashlib
import unittest

import pq_rbbc_blind_uov_abi as abi
import pq_rbbc_reference as core


class BlindUOVVisibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = abi.TestBlindUOVAdapter()
        self.message = hashlib.shake_256(b"abi-test-message-v1.8").digest(32)
        self.mask = hashlib.shake_256(b"abi-test-mask-v1.8").digest(72)
        self.randomness = hashlib.shake_256(b"abi-test-randomness-v1.8").digest(32)
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

    def test_manifest_records_qrom_reduction_and_v1_6_correction(self) -> None:
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
        self.assertFalse(
            manifest["claim_boundary"]["native_tcih_anemoi_constraint_import_complete"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
