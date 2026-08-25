#!/usr/bin/env python3
"""Regression tests for the independent PQ-RBBC v2.0 sponge profile."""

from __future__ import annotations

import hashlib
import unittest

import pq_rbbc_anemoi_f193 as permutation
import pq_rbbc_anemoi_sponge as sponge


class AnemoiSpongeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = permutation.derive_parameters()
        cls.message = bytes(32)
        cls.commitment = bytes(range(48))
        cls.payload = sponge.encode_transcript((cls.message, cls.commitment))
        cls.trace = sponge.build_sponge_trace(
            sponge.REQUEST_BINDING_DOMAIN,
            cls.payload,
            cls.parameters,
        )

    def test_profile_is_independent_and_frozen(self) -> None:
        self.assertEqual(sponge.RATE_BITS, 772)
        self.assertEqual(sponge.CAPACITY_BITS, 772)
        self.assertEqual(sponge.REQUEST_HASH_BITS, 576)
        self.assertEqual(permutation.NONLINEAR_ROWS, 336)
        self.assertEqual(
            sponge.profile_fingerprint(self.parameters),
            "4fa0eb276ebba70a9f6c2f38f3f55d197c094121a2b614cc6ef9b7e8522cac87",
        )

    def test_transcript_encoding_is_tuple_injective(self) -> None:
        self.assertNotEqual(
            sponge.encode_transcript((b"a", b"bc")),
            sponge.encode_transcript((b"ab", b"c")),
        )
        self.assertNotEqual(
            sponge.encode_transcript((b"",)),
            sponge.encode_transcript(()),
        )

    def test_domain_and_length_separation_change_output(self) -> None:
        base = sponge.evaluate_sponge(b"domain-a", b"abc")
        self.assertNotEqual(base, sponge.evaluate_sponge(b"domain-b", b"abc"))
        self.assertNotEqual(base, sponge.evaluate_sponge(b"domain-a", b"abc\x00"))
        self.assertNotEqual(base, sponge.evaluate_sponge(b"domain-a", b"abd"))

    def test_frozen_request_binding_vector(self) -> None:
        expected = bytes.fromhex(
            "d7e05c906d029478056894a134577e10461af7da21bf1e91"
            "da1ff9a14c3674dedcd6ce709d63b37e2339d8f1cf9dd8e2"
            "0d2203e029b7fdc35c0b91b38203b9860c194841e51f2661"
        )
        self.assertEqual(
            sponge.hash_request_binding(self.message, self.commitment),
            expected,
        )
        self.assertEqual(self.trace.output_bytes, expected)

    def test_native_trace_has_exact_rows(self) -> None:
        self.assertEqual(len(self.payload), 118)
        self.assertEqual(self.trace.absorbed_blocks, 2)
        self.assertEqual(self.trace.permutation_nonlinear_rows, 672)
        self.assertEqual(self.trace.input_bitness_rows, 944)
        self.assertEqual(self.trace.output_bitness_rows, 579)
        self.assertEqual(self.trace.linear_rows, 43)
        self.assertEqual(len(self.trace.rows), 2238)
        self.assertEqual(len(self.trace.assignment), 2235)
        self.assertEqual(self.trace.failed_rows(), [])

    def test_direct_and_constrained_hashes_match(self) -> None:
        for payload in (
            b"",
            b"abc",
            bytes(range(64)),
            self.payload,
        ):
            with self.subTest(length=len(payload)):
                trace = sponge.build_sponge_trace(
                    sponge.REQUEST_BINDING_DOMAIN,
                    payload,
                    self.parameters,
                )
                self.assertEqual(
                    trace.output_bytes,
                    sponge.evaluate_sponge(
                        sponge.REQUEST_BINDING_DOMAIN,
                        payload,
                        sponge.REQUEST_HASH_BYTES,
                        self.parameters,
                    ),
                )
                self.assertEqual(trace.failed_rows(), [])

    def test_payload_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.payload_bit_wires[0]] ^= 1
        self.assertTrue(self.trace.failed_rows(assignment))

    def test_output_tamper_rejects_stale_witness(self) -> None:
        assignment = dict(self.trace.assignment)
        assignment[self.trace.output_bit_wires[-1]] ^= 1
        failures = self.trace.failed_rows(assignment)
        self.assertTrue(any(label.endswith("digest.lane[2].pack") for label in failures))

    def test_topology_is_witness_independent_for_fixed_lengths(self) -> None:
        changed_payload = bytes(byte ^ 0xA5 for byte in self.payload)
        changed = sponge.build_sponge_trace(
            sponge.REQUEST_BINDING_DOMAIN,
            changed_payload,
            self.parameters,
        )
        original_stream = sponge.serialize_sponge_row_stream(
            self.trace,
            sponge.REQUEST_BINDING_DOMAIN,
            len(self.payload),
            self.parameters,
        )
        changed_stream = sponge.serialize_sponge_row_stream(
            changed,
            sponge.REQUEST_BINDING_DOMAIN,
            len(changed_payload),
            self.parameters,
        )
        self.assertEqual(original_stream, changed_stream)
        self.assertEqual(
            hashlib.sha256(original_stream).hexdigest(),
            "3aa60bc6d8d507003fb541a6ac991e88da58aea05b7b278ab7e1859772aac9ed",
        )

    def test_manifest_never_claims_blind_uov_compatibility(self) -> None:
        manifest = sponge.build_manifest(
            self.trace,
            sponge.REQUEST_BINDING_DOMAIN,
            self.payload,
            self.parameters,
        )
        decision = manifest["fork_decision"]
        self.assertEqual(decision["selected_mode"], "independent-pq-rbbc-profile")
        self.assertFalse(decision["blind_uov_bit_exact_compatible"])
        self.assertFalse(decision["paper_security_reduction_revalidated_for_fork"])
        self.assertFalse(decision["paper_signature_size_inherited_as_theorem"])
        self.assertFalse(manifest["component_status"]["complete_cap_hash"])
        self.assertFalse(manifest["claim_boundary"]["production_closed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
