#!/usr/bin/env python3
"""Tests for the system-profile v0.1 initialization contracts."""

from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from pq_rbbc.contracts.system import (
    CONFIG_MAGIC,
    ContractError,
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)
from pq_rbbc.governance.system_init import (
    INITIALIZATION_AUTH_DOMAIN,
    AuthenticatedSystemInitialization,
    initialization_manifest,
    verify_initialization,
)


ROOT = Path(__file__).resolve().parents[3]
FROZEN_MANIFEST = (
    ROOT / "manifests" / "pq_rbbc_system_initialization_contracts_v0_1.json"
)


def fixed_bytes(label: bytes) -> bytes:
    return hashlib.sha256(b"PQ-RBBC/system-init-test/" + label).digest()


def reference_bundle() -> SystemInitializationBundle:
    references = tuple(
        KeyReference(
            role=role,
            key_id=fixed_bytes(b"key-id/" + role.name.encode("ascii")),
            public_key_digest=fixed_bytes(
                b"public-key/" + role.name.encode("ascii")
            ),
        )
        for role in KeyRole
    )
    issuer_key = next(
        reference
        for reference in references
        if reference.role is KeyRole.ISSUER_VERIFICATION
    )
    opening_key = next(
        reference
        for reference in references
        if reference.role is KeyRole.OPENING_ENCRYPTION
    )
    configuration = SystemConfiguration(
        protocol_version=1,
        epoch=42,
        domain=fixed_bytes(b"domain"),
        policy_digest=fixed_bytes(b"policy"),
        expiry_bucket=1_900_000_000,
        oa_key_id=opening_key.key_id,
        issuer_key_id=issuer_key.key_id,
    )
    return SystemInitializationBundle(
        configuration=configuration,
        common_parameters_digest=fixed_bytes(b"common-parameters"),
        federation_policy=ThresholdPolicy(member_count=5, threshold=3),
        opening_policy=ThresholdPolicy(member_count=7, threshold=5),
        keys=references,
    )


class DigestTestVerifier:
    """Deterministic unit-test adapter; not a cryptographic signature."""

    @staticmethod
    def sign(key: KeyReference, message: bytes) -> bytes:
        return hashlib.sha256(key.public_key_digest + message).digest()

    def verify(
        self,
        key: KeyReference,
        message: bytes,
        authentication: bytes,
    ) -> bool:
        return authentication == self.sign(key, message)


def reference_envelope() -> AuthenticatedSystemInitialization:
    bundle = reference_bundle()
    key = bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
    message = INITIALIZATION_AUTH_DOMAIN + bundle.encode()
    authentication = DigestTestVerifier.sign(key, message)
    return AuthenticatedSystemInitialization(bundle, authentication)


class ConfigurationContractTests(unittest.TestCase):
    def test_configuration_round_trip_and_context_are_deterministic(self) -> None:
        configuration = reference_bundle().configuration
        encoded = configuration.encode()
        self.assertTrue(encoded.startswith(CONFIG_MAGIC))
        self.assertEqual(SystemConfiguration.decode(encoded), configuration)
        self.assertEqual(len(configuration.ctx), 32)
        self.assertEqual(
            configuration.ctx.hex(),
            "b446e4856aecef5352380c5e79e84b947e52b1deadacc62aec055fbea46cb989",
        )

    def test_configuration_parser_rejects_mutations(self) -> None:
        encoded = reference_bundle().configuration.encode()
        cases = {
            "wrong_magic": bytes([encoded[0] ^ 1]) + encoded[1:],
            "truncated": encoded[:-1],
            "trailing": encoded + b"\x00",
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaises(ContractError):
                SystemConfiguration.decode(candidate)

    def test_configuration_rejects_zero_identifier(self) -> None:
        configuration = reference_bundle().configuration
        with self.assertRaises(ContractError):
            replace(configuration, domain=bytes(32)).encode()

    def test_configuration_rejects_unknown_protocol_version(self) -> None:
        configuration = reference_bundle().configuration
        with self.assertRaises(ContractError):
            replace(configuration, protocol_version=2).encode()


class InitializationBundleTests(unittest.TestCase):
    def test_bundle_round_trip_and_fixed_role_order(self) -> None:
        bundle = reference_bundle()
        encoded = bundle.encode()
        self.assertEqual(SystemInitializationBundle.decode(encoded), bundle)
        self.assertEqual(
            tuple(reference.role for reference in bundle.keys), tuple(KeyRole)
        )
        self.assertEqual(len(bundle.ctx), 32)
        self.assertEqual(len(bundle.sha256), 64)

    def test_bundle_rejects_key_role_reorder(self) -> None:
        bundle = reference_bundle()
        reordered = replace(bundle, keys=(bundle.keys[1], bundle.keys[0], *bundle.keys[2:]))
        with self.assertRaises(ContractError):
            reordered.encode()

    def test_bundle_rejects_cross_role_key_reuse(self) -> None:
        bundle = reference_bundle()
        reused = replace(
            bundle.keys[1],
            key_id=bundle.keys[0].key_id,
            public_key_digest=bundle.keys[0].public_key_digest,
        )
        with self.assertRaises(ContractError):
            replace(bundle, keys=(bundle.keys[0], reused, *bundle.keys[2:])).encode()

    def test_bundle_rejects_configuration_key_mismatch(self) -> None:
        bundle = reference_bundle()
        bad_configuration = replace(
            bundle.configuration,
            issuer_key_id=bundle.key_for(KeyRole.OPENING_ENCRYPTION).key_id,
        )
        with self.assertRaises(ContractError):
            replace(bundle, configuration=bad_configuration).encode()

    def test_bundle_rejects_invalid_thresholds(self) -> None:
        bundle = reference_bundle()
        with self.assertRaises(ContractError):
            replace(
                bundle,
                opening_policy=ThresholdPolicy(member_count=3, threshold=4),
            ).encode()

    def test_bundle_parser_rejects_ctx_mutation(self) -> None:
        bundle = reference_bundle()
        encoded = bytearray(bundle.encode())
        configuration_length_offset = len(b"PQRBBC-SYSTEM-INIT-BUNDLE-V1") + 2
        configuration_length = int.from_bytes(
            encoded[
                configuration_length_offset : configuration_length_offset + 4
            ],
            "little",
        )
        ctx_offset = configuration_length_offset + 4 + configuration_length
        encoded[ctx_offset] ^= 1
        with self.assertRaises(ContractError):
            SystemInitializationBundle.decode(bytes(encoded))


class AuthenticatedInitializationTests(unittest.TestCase):
    def test_authenticated_initialization_accepts(self) -> None:
        envelope = reference_envelope()
        encoded = envelope.encode()
        self.assertEqual(AuthenticatedSystemInitialization.decode(encoded), envelope)
        trusted_key = envelope.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
        result = verify_initialization(encoded, trusted_key, DigestTestVerifier())
        self.assertTrue(result.accepted, result.failures)
        self.assertEqual(result.bundle, envelope.bundle)

    def test_authentication_and_bundle_mutations_reject(self) -> None:
        envelope = reference_envelope()
        encoded = envelope.encode()
        cases = {
            "authentication": encoded[:-1] + bytes([encoded[-1] ^ 1]),
            "bundle": encoded[:80] + bytes([encoded[80] ^ 1]) + encoded[81:],
            "truncated": encoded[:-1],
            "trailing": encoded + b"\x00",
        }
        trusted_key = envelope.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
        for name, candidate in cases.items():
            with self.subTest(name=name):
                result = verify_initialization(
                    candidate, trusted_key, DigestTestVerifier()
                )
                self.assertFalse(result.accepted)
                self.assertIsNone(result.bundle)

    def test_self_advertised_configuration_key_is_not_a_trust_anchor(self) -> None:
        envelope = reference_envelope()
        advertised = envelope.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
        wrong_trust_anchor = replace(
            advertised,
            key_id=fixed_bytes(b"untrusted/configuration-key-id"),
            public_key_digest=fixed_bytes(b"untrusted/configuration-public-key"),
        )
        result = verify_initialization(
            envelope.encode(), wrong_trust_anchor, DigestTestVerifier()
        )
        self.assertFalse(result.accepted)
        self.assertEqual(
            result.failures, ("configuration_trust_anchor_mismatch",)
        )

    def test_backend_exception_fails_closed(self) -> None:
        class BrokenVerifier:
            def verify(self, *_args: object) -> bool:
                raise RuntimeError("test backend failure")

        envelope = reference_envelope()
        trusted_key = envelope.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
        result = verify_initialization(
            envelope.encode(), trusted_key, BrokenVerifier()
        )
        self.assertFalse(result.accepted)
        self.assertEqual(
            result.failures,
            ("configuration_authentication_backend:RuntimeError",),
        )

    def test_manifest_preserves_claim_boundary(self) -> None:
        manifest = initialization_manifest(reference_envelope())
        self.assertEqual(manifest, json.loads(FROZEN_MANIFEST.read_text()))
        self.assertEqual(manifest["bundle_bytes"], 609)
        self.assertEqual(
            manifest["bundle_sha256"],
            "5103e95793f747be2a4ffb325ebe47d6411dcbfe274e8294254f0a38b9be17e5",
        )
        claims = manifest["claim_boundary"]
        self.assertTrue(claims["canonical_configuration_codec_implemented"])
        self.assertTrue(claims["explicit_configuration_trust_anchor_required"])
        self.assertTrue(claims["configuration_authentication_backend_abstract"])
        self.assertFalse(claims["fac_threshold_signature_instantiated"])
        self.assertFalse(claims["fac_dkg_implemented"])
        self.assertFalse(claims["opening_dkg_implemented"])
        self.assertFalse(claims["threshold_decoder_implemented"])
        self.assertFalse(claims["production_system_initialized"])


if __name__ == "__main__":
    unittest.main()
