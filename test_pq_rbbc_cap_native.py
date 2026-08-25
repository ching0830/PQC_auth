#!/usr/bin/env python3
"""Regression tests for the zero-callback reduced CAP native lowering."""

from __future__ import annotations

import dataclasses
import hashlib
import unittest

import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap
import pq_rbbc_cap_native as native


class ReducedNativeCAPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.randomness = cap.deterministic_randomness(
            cap.REDUCED_TEST_PARAMETERS
        )
        cls.message = bytes(32)
        cls.trace = native.build_reduced_native_trace(
            cls.randomness, cls.message
        )

    def test_frozen_native_profile_and_vector(self) -> None:
        manifest = native.build_manifest(self.trace)
        self.assertEqual(manifest["implementation_version"], "2.3")
        self.assertTrue(
            manifest["profile"]["explicitly_non_secure_reduced_profile"]
        )
        self.assertEqual(
            manifest["profile"]["cap_profile_fingerprint"],
            "5d067a55e2ea9104b2604dc7efa393f44d1ce1880c3974bdcaae32aeb825f2ea",
        )
        self.assertEqual(
            manifest["frozen_vector"]["commitment_sha256"],
            "07a09a4f623233586af7ebca90d0eeba7d6a5bb94ff86c7dff29ade7be79b800",
        )
        self.assertEqual(
            manifest["frozen_vector"]["request_hash_hex"],
            "3ff3bcd5d5097524beb5765f45ae0d2159de80d81773837c79a66de6337f5ab9"
            "2ab9b7e30f24397e630a894ae9406e4a561497e112f8b1adbe6ef5f207a3aff6"
            "6e8ce000ea404486",
        )

    def test_exact_native_rows_and_zero_external_assertions(self) -> None:
        accounting = self.trace.xof_accounting
        self.assertEqual(accounting.calls, native.FROZEN_REDUCED_XOF_CALLS)
        self.assertEqual(
            accounting.permutations, native.FROZEN_REDUCED_PERMUTATIONS
        )
        self.assertEqual(accounting.permutation_rows, 19_152)
        self.assertEqual(accounting.payload_bitness_rows, 26_848)
        self.assertEqual(accounting.output_bitness_rows, 9_264)
        self.assertEqual(accounting.source_link_rows, 26_848)
        self.assertEqual(len(self.trace.rows), native.FROZEN_REDUCED_ROWS)
        self.assertEqual(
            len(self.trace.assignment), native.FROZEN_REDUCED_WIRES
        )
        self.assertEqual(
            self.trace.nonlinear_rows, native.FROZEN_REDUCED_NONLINEAR_ROWS
        )
        self.assertEqual(
            self.trace.linear_rows, native.FROZEN_REDUCED_LINEAR_ROWS
        )
        self.assertEqual(self.trace.external_assertions, 0)
        self.assertEqual(self.trace.failed_rows(), [])

    def test_row_stream_digest_is_frozen(self) -> None:
        row_stream = native.serialize_row_stream(self.trace)
        self.assertEqual(len(row_stream), native.FROZEN_REDUCED_ROW_STREAM_BYTES)
        self.assertEqual(
            hashlib.sha256(row_stream).hexdigest(),
            native.FROZEN_REDUCED_ROW_STREAM_SHA256,
        )

    def test_canonical_commitment_and_hash_join_match_reference(self) -> None:
        execution = cap.execute_cap_commit(
            cap.REDUCED_TEST_PARAMETERS, self.randomness
        )
        self.assertEqual(self.trace.commitment_bytes, execution.commitment.encoded)
        self.assertEqual(len(self.trace.commitment_bit_wires), 215 * 8)
        self.assertEqual(len(self.trace.request_hash_bit_wires), 576)
        self.assertEqual(
            self.trace.request_hash_bytes,
            sponge.hash_request_binding(
                self.message, execution.commitment.encoded
            ),
        )

    def test_salt_input_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.randomness_bit_wires[0]] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertTrue(any("payload" in label for label in failures))

    def test_message_input_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.message_bit_wires[0]] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertTrue(any("request-binding.payload" in label for label in failures))

    def test_commitment_output_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.commitment_bit_wires[-1]] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertTrue(any("output.commitment" in label for label in failures))
        self.assertTrue(any("request-binding.payload" in label for label in failures))

    def test_request_hash_output_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.request_hash_bit_wires[-1]] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertTrue(any("digest.lane[2].pack" in label for label in failures))

    def test_topology_is_witness_independent(self) -> None:
        roots = list(self.randomness.roots)
        roots[0] = (roots[0][0] ^ 1, roots[0][1])
        changed_randomness = dataclasses.replace(
            self.randomness,
            salt=(self.randomness.salt[0] ^ 1, self.randomness.salt[1]),
            roots=tuple(roots),
        )
        changed = native.build_reduced_native_trace(
            changed_randomness, bytes([0xA5]) * 32
        )
        self.assertEqual(changed.failed_rows(), [])
        self.assertEqual(
            hashlib.sha256(native.serialize_row_stream(changed)).hexdigest(),
            hashlib.sha256(native.serialize_row_stream(self.trace)).hexdigest(),
        )
        self.assertNotEqual(changed.commitment_bytes, self.trace.commitment_bytes)
        self.assertNotEqual(changed.request_hash_bytes, self.trace.request_hash_bytes)

    def test_production_profile_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            native.build_reduced_native_trace(
                cap.deterministic_randomness(cap.PRODUCTION_PARAMETERS),
                self.message,
                cap.PRODUCTION_PARAMETERS,
            )
        manifest = native.build_manifest(self.trace)
        self.assertTrue(manifest["claim_boundary"]["reduced_fixture_native_closed"])
        self.assertFalse(manifest["claim_boundary"]["production_closed"])
        self.assertFalse(
            manifest["implemented"]["full_production_native_rows_materialized"]
        )


class ExtendedMultiSqueezeCAPTests(unittest.TestCase):
    """Exercise production-width tapes without claiming production security."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = native.EXTENDED_MULTISQUEEZE_TEST_PARAMETERS
        cls.randomness = cap.deterministic_randomness(cls.parameters)
        cls.message = bytes([0x3C]) * 32
        cls.trace = native.build_native_cap_trace(
            cls.randomness,
            cls.message,
            cls.parameters,
        )
        cls.row_stream = native.serialize_row_stream(cls.trace)
        cls.manifest = native.build_manifest(cls.trace)

    def test_extended_fixture_is_explicitly_non_secure(self) -> None:
        self.assertEqual(self.parameters.random_polynomial_bits, 2_450)
        self.assertEqual(self.parameters.witness_bits, 64)
        self.assertFalse(self.parameters.secure_profile)
        self.assertEqual(
            self.manifest["profile"]["cap_profile_fingerprint"],
            "efb2d1d30ea253c7b2fa44d7b5b8774ed2b0af483671cc62808c5d86af5839e4",
        )
        self.assertTrue(
            self.manifest["claim_boundary"][
                "extended_multisqueeze_fixture_native_closed"
            ]
        )
        self.assertFalse(self.manifest["claim_boundary"]["production_closed"])
        self.assertNotIn(
            "multi-block XOF squeeze rows for the 2450-bit tape",
            self.manifest["claim_boundary"]["production_blockers"],
        )

    def test_exact_extended_native_rows(self) -> None:
        accounting = self.trace.xof_accounting
        self.assertEqual(accounting.calls, native.FROZEN_EXTENDED_XOF_CALLS)
        self.assertEqual(
            accounting.permutations, native.FROZEN_EXTENDED_PERMUTATIONS
        )
        self.assertEqual(accounting.permutation_rows, 27_216)
        self.assertEqual(accounting.payload_bitness_rows, 26_848)
        self.assertEqual(accounting.output_bitness_rows, 26_248)
        self.assertEqual(accounting.source_link_rows, 26_848)
        self.assertEqual(len(self.trace.rows), native.FROZEN_EXTENDED_ROWS)
        self.assertEqual(
            len(self.trace.assignment), native.FROZEN_EXTENDED_WIRES
        )
        self.assertEqual(
            self.trace.nonlinear_rows,
            native.FROZEN_EXTENDED_NONLINEAR_ROWS,
        )
        self.assertEqual(
            self.trace.linear_rows,
            native.FROZEN_EXTENDED_LINEAR_ROWS,
        )
        self.assertEqual(self.trace.external_assertions, 0)
        self.assertEqual(self.trace.failed_rows(), [])

    def test_exact_extended_row_stream_and_vector(self) -> None:
        self.assertEqual(
            len(self.row_stream), native.FROZEN_EXTENDED_ROW_STREAM_BYTES
        )
        self.assertEqual(
            hashlib.sha256(self.row_stream).hexdigest(),
            native.FROZEN_EXTENDED_ROW_STREAM_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(self.trace.commitment_bytes).hexdigest(),
            "e6756238a3119c2b290e5181050cba6b77ecfb9f40dc8fefd33de33aa2722503",
        )
        execution = cap.execute_cap_commit(self.parameters, self.randomness)
        self.assertEqual(self.trace.commitment_bytes, execution.commitment.encoded)
        tape_calls = [
            call for call in execution.xof_calls if call.label.endswith(".tape")
        ]
        self.assertEqual(len(tape_calls), 8)
        self.assertTrue(all(call.output_bits == 2_450 for call in tape_calls))
        self.assertEqual(
            self.trace.request_hash_bytes,
            sponge.hash_request_binding(
                self.message,
                execution.commitment.encoded,
            ),
        )

    def test_later_tape_block_tamper_rejects_stale_witness(self) -> None:
        target_label = (
            "xof[3].tree[0].leaf[1].tape."
            "digest.block[1].lane[0].bit[0]"
        )
        target_wire = next(
            wire_id
            for wire_id, label in self.trace.wire_labels.items()
            if label == target_label
        )
        assignment = dict(self.trace.assignment)
        assignment[target_wire] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertTrue(
            any(
                "tree[0].leaf[1].tape.digest.block[1].lane[0].pack"
                in label
                for label in failures
            )
        )

    def test_extended_topology_is_witness_independent(self) -> None:
        roots = list(self.randomness.roots)
        roots[-1] = (roots[-1][0], roots[-1][1] ^ 1)
        changed_randomness = dataclasses.replace(
            self.randomness,
            salt=(self.randomness.salt[0] ^ 1, self.randomness.salt[1]),
            roots=tuple(roots),
        )
        changed = native.build_native_cap_trace(
            changed_randomness,
            bytes([0xC3]) * 32,
            self.parameters,
        )
        changed_stream = native.serialize_row_stream(changed)
        self.assertEqual(changed.failed_rows(), [])
        self.assertEqual(changed_stream, self.row_stream)
        self.assertNotEqual(changed.commitment_bytes, self.trace.commitment_bytes)
        self.assertNotEqual(
            changed.request_hash_bytes,
            self.trace.request_hash_bytes,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
