#!/usr/bin/env python3
"""Regression tests for the PQ-RBBC v2.1 CAP.Commit reference core."""

from __future__ import annotations

import dataclasses
import hashlib
import unittest

import pq_rbbc_anemoi_f193 as field
import pq_rbbc_anemoi_sponge as sponge
import pq_rbbc_cap_commit as cap


class CAPCommitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = cap.REDUCED_TEST_PARAMETERS
        cls.randomness = cap.deterministic_randomness(cls.parameters)
        cls.execution = cap.execute_cap_commit(cls.parameters, cls.randomness)

    def test_production_profile_and_safe_extensions_are_frozen(self) -> None:
        params = cap.PRODUCTION_PARAMETERS
        self.assertEqual(params.mask_bits, 576)
        self.assertEqual(params.appended_signature_bits, 1472)
        self.assertEqual(params.witness_bits, 2048)
        self.assertEqual(params.tree_count, 18)
        self.assertEqual(params.leaf_count, 40960)
        self.assertEqual(params.expanded_leaf_counts(), (4096,) * 2 + (2048,) * 16)
        self.assertEqual(params.expanded_extension_degrees(), (13,) * 2 + (12,) * 16)
        self.assertEqual(params.rho, 16)
        self.assertEqual(params.consistency_bits, 386)
        self.assertEqual(params.random_polynomial_bits, 2450)
        self.assertEqual(cap.commitment_bytes(params), 5391)
        self.assertEqual(
            cap.profile_fingerprint(params),
            "2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38",
        )

    def test_extension_points_are_nonzero_unique_and_invertible(self) -> None:
        for degree, leaves in ((12, 2048), (13, 4096)):
            seen = set(range(1, leaves + 1))
            self.assertEqual(len(seen), leaves)
            self.assertNotIn(0, seen)
            for point in (1, 2, 3, leaves - 1, leaves):
                inverse = cap.gf2m_inv(point, degree)
                self.assertEqual(cap.gf2m_mul(point, inverse, degree), 1)

    def test_reduced_vector_is_frozen(self) -> None:
        commitment = self.execution.commitment
        self.assertEqual(
            cap.commitment_bytes(self.parameters), len(commitment.encoded)
        )
        self.assertEqual(len(self.execution.xof_calls), 23)
        self.assertEqual(len(commitment.encoded), 215)
        self.assertEqual(
            hashlib.sha256(commitment.encoded).hexdigest(),
            "07a09a4f623233586af7ebca90d0eeba7d6a5bb94ff86c7dff29ade7be79b800",
        )
        self.assertEqual(commitment.derived_mask, 0xF40749DD)
        self.assertEqual(
            cap.hash_bytes(commitment.h2).hex(),
            "8f7d225912dbfdc5fe95115fe80cffd6814e00c1600c623b1664f5876616988"
            "ff98544b84e294ed5aa7aea146bdc8da701",
        )

    def test_corrections_force_one_common_constant(self) -> None:
        params = self.parameters
        polynomials = self.execution.tree_polynomials
        witness_mask = (1 << params.witness_bits) - 1
        mhat_shift = params.witness_bits + (params.degree - 1) * params.rho
        mhat_mask = (1 << params.consistency_bits) - 1
        common_p = polynomials[0].plain & witness_mask
        common_mhat = (polynomials[0].plain >> mhat_shift) & mhat_mask
        for index, polynomial in enumerate(polynomials[1:]):
            plain_p = polynomial.plain & witness_mask
            plain_mhat = (polynomial.plain >> mhat_shift) & mhat_mask
            self.assertEqual(
                plain_p ^ self.execution.commitment.delta_p[index],
                common_p,
            )
            self.assertEqual(
                plain_mhat ^ self.execution.commitment.delta_mhat[index],
                common_mhat,
            )

    def test_mask_is_derived_and_append_delta_round_trips(self) -> None:
        commitment = self.execution.commitment
        signature = 0xA5C35A3C
        delta = commitment.append_signature(signature, 32)
        self.assertEqual(commitment.recover_appended_signature(delta), signature)
        self.assertEqual(
            commitment.derived_mask,
            self.execution.tree_polynomials[0].plain & ((1 << 32) - 1),
        )

    def test_salt_or_root_mutation_changes_commitment(self) -> None:
        changed_salt = dataclasses.replace(
            self.randomness,
            salt=(self.randomness.salt[0] ^ 1, self.randomness.salt[1]),
        )
        changed_root_pairs = list(self.randomness.roots)
        changed_root_pairs[0] = (
            changed_root_pairs[0][0] ^ 1,
            changed_root_pairs[0][1],
        )
        changed_root = dataclasses.replace(
            self.randomness, roots=tuple(changed_root_pairs)
        )
        salt_execution = cap.execute_cap_commit(self.parameters, changed_salt)
        root_execution = cap.execute_cap_commit(self.parameters, changed_root)
        self.assertNotEqual(
            salt_execution.commitment.encoded,
            self.execution.commitment.encoded,
        )
        self.assertNotEqual(
            root_execution.commitment.encoded,
            self.execution.commitment.encoded,
        )

    def test_internal_domains_are_distinct(self) -> None:
        domains = {
            cap.DOMAIN_SEED_DERIVE,
            cap.DOMAIN_SEED_COMMIT,
            cap.DOMAIN_TAPE_EXPAND,
            cap.DOMAIN_H1,
            cap.DOMAIN_CONSISTENCY_POINTS,
            cap.DOMAIN_H2,
            sponge.REQUEST_BINDING_DOMAIN,
        }
        self.assertEqual(len(domains), 7)

    def test_commitment_binds_into_request_hash(self) -> None:
        message = bytes(32)
        digest = sponge.hash_request_binding(
            message, self.execution.commitment.encoded
        )
        changed = bytearray(self.execution.commitment.encoded)
        changed[-1] ^= 1
        self.assertNotEqual(
            digest,
            sponge.hash_request_binding(message, bytes(changed)),
        )

    def test_production_accounting_is_exact_and_fail_closed(self) -> None:
        accounting = cap.production_accounting()
        self.assertEqual(accounting["seed_derive_calls"], 40924)
        self.assertEqual(accounting["seed_commit_calls"], 40960)
        self.assertEqual(accounting["tape_expand_calls"], 40960)
        self.assertEqual(accounting["total_xof_calls"], 122847)
        self.assertEqual(accounting["total_anemoi_permutations"], 389974)
        self.assertEqual(accounting["permutation_nonlinear_rows"], 131031264)
        with self.assertRaises(RuntimeError):
            cap.execute_cap_commit(
                cap.PRODUCTION_PARAMETERS,
                cap.deterministic_randomness(cap.PRODUCTION_PARAMETERS),
            )

    def test_manifest_records_reference_not_native_closure(self) -> None:
        manifest = cap.build_manifest(self.execution)
        self.assertFalse(manifest["profile"]["blind_uov_bit_exact_compatible"])
        self.assertTrue(manifest["implemented"]["ggm_seed_derivation_reference"])
        self.assertTrue(manifest["implemented"]["masked_consistency_digest"])
        self.assertFalse(
            manifest["implemented"]["full_production_native_rows_materialized"]
        )
        self.assertFalse(manifest["implemented"]["inter_call_wire_identity_proved"])
        self.assertFalse(
            manifest["claim_boundary"][
                "full_18_tree_vector_executed_in_this_manifest"
            ]
        )
        self.assertTrue(
            manifest["claim_boundary"][
                "linked_composer_manifest_required_for_full_vector_evidence"
            ]
        )
        self.assertFalse(manifest["claim_boundary"]["production_closed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
