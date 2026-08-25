#!/usr/bin/env python3
"""Regression tests for the corrected hidden-state Blind-UOV ABI."""

from __future__ import annotations

import dataclasses
import hashlib
import unittest

import pq_rbbc_blind_uov_abi as abi
import pq_rbbc_reference as core


class BlindUOVVisibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = abi.TestBlindUOVAdapter()
        self.message = hashlib.shake_256(b"abi-test-message").digest(32)
        self.masks = tuple(
            hashlib.shake_256(b"abi-test-mask" + bytes((lane,))).digest(32)
            for lane in range(2)
        )
        self.randomness = tuple(
            hashlib.shake_256(b"abi-test-randomness" + bytes((lane,))).digest(32)
            for lane in range(2)
        )
        self.request = self.adapter.create(
            self.message, self.masks, self.randomness
        )

    def test_public_request_is_exactly_two_y_values(self) -> None:
        self.assertEqual(len(self.request.encode()), 64)
        self.assertEqual(self.request.encode(), b"".join(self.request.masked_targets))
        self.assertEqual(
            [field.name for field in dataclasses.fields(self.request)],
            ["masked_targets"],
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
        self.assertTrue(
            self.adapter.verify(
                self.request, self.message, self.masks, self.randomness
            )
        )
        changed_message = bytes((self.message[0] ^ 1,)) + self.message[1:]
        self.assertFalse(
            self.adapter.verify(
                self.request, changed_message, self.masks, self.randomness
            )
        )
        changed_y0 = bytes((self.request.masked_targets[0][0] ^ 1,)) + self.request.masked_targets[0][1:]
        self.assertFalse(
            self.adapter.verify(
                abi.BlindUOVRequest((changed_y0, self.request.masked_targets[1])),
                self.message,
                self.masks,
                self.randomness,
            )
        )

    def test_lane_domain_separation_and_independence(self) -> None:
        self.assertNotEqual(self.request.masked_targets[0], self.request.masked_targets[1])
        self.assertNotEqual(self.masks[0], self.masks[1])
        self.assertNotEqual(self.randomness[0], self.randomness[1])

    def test_invalid_lane_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.adapter.verify_lane(
                self.request, 2, self.message, self.masks[0], self.randomness[0]
            )

    def test_manifest_marks_new_binding_obligation(self) -> None:
        manifest = abi.build_abi_manifest()
        checks = manifest["regression_checks"]
        self.assertTrue(checks["honest_request_accepts"])
        self.assertFalse(checks["request_has_cap_commitment_field"])
        self.assertFalse(checks["request_has_message_digest_field"])
        self.assertEqual(
            manifest["binding_proof_obligation"]["name"],
            "dual-lane cross-message request claw resistance",
        )
        self.assertIn("2^170", manifest["binding_proof_obligation"]["dual_lane_qrom_target"])
        self.assertEqual(len(manifest["final_signed_messages"]), 2)
        self.assertEqual(
            manifest["binding_proof_obligation"]["status"],
            "required assumption/reduction; not implied by CAP binding plus hash collision resistance",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
