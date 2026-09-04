#!/usr/bin/env python3
"""Tests for the system-profile v0.1 issuer-authorization prototype."""

from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Thread

from pq_rbbc.contracts.system import (
    ContractError,
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)
from pq_rbbc.governance.issuer_authorization import (
    AUTHENTICATED_ISSUER_GRANT_MAGIC,
    ISSUER_AUTHORIZATION_DOMAIN,
    ISSUER_GRANT_MAGIC,
    AuthenticatedIssuerGrant,
    IssuerGrant,
    QuotaConsumeStatus,
    SingleProcessMemoryQuotaStore,
    authorize_issuance,
    issuer_authorization_manifest,
    issuer_grant_authentication_message,
)
from pq_rbbc.governance.system_init import (
    INITIALIZATION_AUTH_DOMAIN,
    AuthenticatedSystemInitialization,
)


ROOT = Path(__file__).resolve().parents[3]
FROZEN_MANIFEST = ROOT / "manifests" / "pq_rbbc_issuer_authorization_v0_1.json"
VALID_TIME = 1_750_000_000


def fixed_bytes(label: bytes) -> bytes:
    return hashlib.sha256(b"PQ-RBBC/issuer-authorization-test/" + label).digest()


class DeterministicTestVerifier:
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
    return SystemInitializationBundle(
        configuration=SystemConfiguration(
            protocol_version=1,
            epoch=42,
            domain=fixed_bytes(b"domain"),
            policy_digest=fixed_bytes(b"policy"),
            expiry_bucket=1_900_000_000,
            oa_key_id=opening_key.key_id,
            issuer_key_id=issuer_key.key_id,
        ),
        common_parameters_digest=fixed_bytes(b"common-parameters"),
        federation_policy=ThresholdPolicy(member_count=5, threshold=3),
        opening_policy=ThresholdPolicy(member_count=7, threshold=5),
        keys=references,
    )


def reference_initialization() -> AuthenticatedSystemInitialization:
    bundle = reference_bundle()
    key = bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
    message = INITIALIZATION_AUTH_DOMAIN + bundle.encode()
    return AuthenticatedSystemInitialization(
        bundle=bundle,
        authentication=DeterministicTestVerifier.sign(key, message),
    )


def reference_grant(quota: int = 3) -> IssuerGrant:
    bundle = reference_bundle()
    return IssuerGrant(
        ctx=bundle.ctx,
        protocol_version=bundle.configuration.protocol_version,
        epoch=bundle.configuration.epoch,
        policy_digest=bundle.configuration.policy_digest,
        issuer_key_id=bundle.configuration.issuer_key_id,
        issuer_authorization_key_id=bundle.key_for(
            KeyRole.ISSUER_AUTHORIZATION
        ).key_id,
        quota=quota,
        not_before=1_700_000_000,
        expiry=1_800_000_000,
        grant_identifier=fixed_bytes(b"grant/id-0001"),
    )


def authenticated_grant(
    grant: IssuerGrant | None = None,
    *,
    signing_role: KeyRole = KeyRole.ISSUER_AUTHORIZATION,
    signing_key: KeyReference | None = None,
) -> AuthenticatedIssuerGrant:
    grant = reference_grant() if grant is None else grant
    bundle = reference_bundle()
    key = (
        bundle.key_for(KeyRole.ISSUER_AUTHORIZATION)
        if signing_key is None
        else signing_key
    )
    message = issuer_grant_authentication_message(grant, signing_role)
    return AuthenticatedIssuerGrant(
        grant=grant,
        signing_role=signing_role,
        authentication=DeterministicTestVerifier.sign(key, message),
    )


def raw_grant_envelope(
    grant_bytes: bytes,
    *,
    role_value: int = int(KeyRole.ISSUER_AUTHORIZATION),
    authentication: bytes = b"invalid-for-parser-test",
) -> bytes:
    return b"".join(
        (
            AUTHENTICATED_ISSUER_GRANT_MAGIC,
            (1).to_bytes(2, "little"),
            role_value.to_bytes(2, "little"),
            len(grant_bytes).to_bytes(4, "little"),
            grant_bytes,
            len(authentication).to_bytes(4, "little"),
            authentication,
        )
    )


def authorize(
    encoded_grant: bytes,
    *,
    store: SingleProcessMemoryQuotaStore | None = None,
    sid: bytes = b"issuer-session-0001",
    now: int = VALID_TIME,
    trusted_key: KeyReference | None = None,
    initialization: bytes | None = None,
    grant_verifier: object | None = None,
):
    init = reference_initialization()
    return authorize_issuance(
        init.encode() if initialization is None else initialization,
        encoded_grant,
        trusted_configuration_key=(
            init.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
            if trusted_key is None
            else trusted_key
        ),
        initialization_verifier=DeterministicTestVerifier(),
        grant_verifier=(
            DeterministicTestVerifier()
            if grant_verifier is None
            else grant_verifier
        ),
        quota_store=SingleProcessMemoryQuotaStore() if store is None else store,
        issuer_sid=sid,
        now=now,
    )


class IssuerGrantCodecTests(unittest.TestCase):
    def test_canonical_round_trip(self) -> None:
        grant = reference_grant()
        encoded = grant.encode()
        self.assertTrue(encoded.startswith(ISSUER_GRANT_MAGIC))
        self.assertEqual(IssuerGrant.decode(encoded), grant)
        envelope = authenticated_grant(grant)
        self.assertEqual(
            AuthenticatedIssuerGrant.decode(envelope.encode()), envelope
        )
        self.assertTrue(envelope.authentication_message.startswith(
            ISSUER_AUTHORIZATION_DOMAIN
        ))

    def test_exact_frozen_vector(self) -> None:
        envelope = authenticated_grant()
        self.assertEqual(
            envelope.grant.encode().hex(),
            "5051524242432d4953535545522d4752414e542d56310100fdf626166c98213e"
            "387b74c3bab59e68c205651752827784aa6a4fe438a6c15901002a0000000000"
            "0000c55d671a7c5f2172e72e3d4c098f8a4929988c999510f1ad759afea343e1"
            "fe4bee9c3571e5ea2c641d52a4e4146ffc2b559f107dbc5d5d9cf111693050a8"
            "c93182dce0cad1094bca55135b7693437eefc0439805e4c95871b3601aafad10c"
            "042030000000000000000f153650000000000d2496b0000000045faef2e1d948"
            "c8df2dddfc0695bfbacbe3bb6b09f8048b4a85b4536e2fd1c57",
        )
        self.assertEqual(
            hashlib.sha256(envelope.encode()).hexdigest(),
            "d069b1fb8bccbf13b59acfed7ea637748ac3de852fb4c25a22af21b37b75ef77",
        )
        self.assertEqual(
            issuer_authorization_manifest(envelope),
            json.loads(FROZEN_MANIFEST.read_text()),
        )

    def test_unknown_versions_and_role_reject(self) -> None:
        envelope_bytes = bytearray(authenticated_grant().encode())
        envelope_version_offset = len(AUTHENTICATED_ISSUER_GRANT_MAGIC)
        envelope_bytes[envelope_version_offset] = 2
        decision = authorize(bytes(envelope_bytes))
        self.assertFalse(decision.accepted)
        self.assertIn("version", decision.failures[0])

        grant_bytes = bytearray(reference_grant().encode())
        grant_version_offset = len(ISSUER_GRANT_MAGIC)
        grant_bytes[grant_version_offset] = 2
        decision = authorize(raw_grant_envelope(bytes(grant_bytes)))
        self.assertFalse(decision.accepted)
        self.assertIn("version", decision.failures[0])

        unknown_role = bytearray(authenticated_grant().encode())
        role_offset = len(AUTHENTICATED_ISSUER_GRANT_MAGIC) + 2
        unknown_role[role_offset : role_offset + 2] = (65535).to_bytes(2, "little")
        decision = authorize(bytes(unknown_role))
        self.assertFalse(decision.accepted)
        self.assertIn("unknown", decision.failures[0])

    def test_malformed_truncated_and_trailing_bytes_reject(self) -> None:
        encoded = authenticated_grant().encode()
        wrong_magic = bytes([encoded[0] ^ 1]) + encoded[1:]
        self.assertFalse(authorize(wrong_magic).accepted)
        for cut in range(len(encoded)):
            with self.subTest(cut=cut):
                self.assertFalse(authorize(encoded[:cut]).accepted)
        self.assertFalse(authorize(encoded + b"\x00").accepted)

        grant_bytes = bytearray(reference_grant().encode())
        quota_offset = (
            len(ISSUER_GRANT_MAGIC) + 2 + 32 + 2 + 8 + 32 + 32 + 32
        )
        grant_bytes[quota_offset : quota_offset + 8] = bytes(8)
        self.assertFalse(authorize(raw_grant_envelope(bytes(grant_bytes))).accepted)

    def test_reordered_bound_fields_reject_even_when_reauthenticated(self) -> None:
        grant = reference_grant()
        reordered = replace(
            grant,
            policy_digest=grant.issuer_key_id,
            issuer_key_id=grant.policy_digest,
        )
        decision = authorize(authenticated_grant(reordered).encode())
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.failures, ("grant_policy_digest_mismatch",))


class IssuerAuthorizationTests(unittest.TestCase):
    def test_honest_authorization_accepts(self) -> None:
        grant = authenticated_grant()
        decision = authorize(grant.encode())
        self.assertTrue(decision.accepted, decision.failures)
        self.assertEqual(decision.remaining_quota, 2)
        self.assertEqual(decision.grant_digest, grant.grant.digest)

    def test_initialization_is_authenticated_before_grant_parsing(self) -> None:
        initialization = bytearray(reference_initialization().encode())
        initialization[-1] ^= 1
        decision = authorize(b"not-a-grant", initialization=bytes(initialization))
        self.assertFalse(decision.accepted)
        self.assertTrue(decision.failures[0].startswith("initialization:"))

    def test_bound_field_mutations_reject_even_when_reauthenticated(self) -> None:
        grant = reference_grant()
        mutations = {
            "ctx": replace(grant, ctx=bytes([grant.ctx[0] ^ 1]) + grant.ctx[1:]),
            "policy": replace(grant, policy_digest=fixed_bytes(b"other-policy")),
            "epoch": replace(grant, epoch=grant.epoch + 1),
            "issuer_key": replace(
                grant, issuer_key_id=fixed_bytes(b"other-issuer-key")
            ),
            "authorization_key": replace(
                grant,
                issuer_authorization_key_id=fixed_bytes(
                    b"other-authorization-key"
                ),
            ),
        }
        expected_failures = {
            "ctx": "grant_ctx_mismatch",
            "policy": "grant_policy_digest_mismatch",
            "epoch": "grant_epoch_mismatch",
            "issuer_key": "grant_issuer_key_id_mismatch",
            "authorization_key": "grant_authorization_key_id_mismatch",
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                decision = authorize(authenticated_grant(mutated).encode())
                self.assertFalse(decision.accepted)
                self.assertEqual(decision.failures, (expected_failures[name],))

    def test_not_before_and_expiry_are_fail_closed(self) -> None:
        envelope = authenticated_grant()
        not_yet = authorize(envelope.encode(), now=envelope.grant.not_before - 1)
        self.assertFalse(not_yet.accepted)
        self.assertEqual(not_yet.failures, ("grant_not_yet_valid",))
        expired = authorize(envelope.encode(), now=envelope.grant.expiry)
        self.assertFalse(expired.accepted)
        self.assertEqual(expired.failures, ("grant_expired",))

    def test_signature_mutation_rejects(self) -> None:
        encoded = authenticated_grant().encode()
        mutated = encoded[:-1] + bytes([encoded[-1] ^ 1])
        decision = authorize(mutated)
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.failures, ("grant_authentication_invalid",))

    def test_wrong_known_key_role_rejects(self) -> None:
        envelope = authenticated_grant(signing_role=KeyRole.OPENING_AUTHORIZATION)
        decision = authorize(envelope.encode())
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.failures, ("grant_wrong_key_role",))

    def test_non_authorization_bundle_key_cannot_authenticate_grant(self) -> None:
        opening_key = reference_bundle().key_for(KeyRole.OPENING_AUTHORIZATION)
        envelope = authenticated_grant(signing_key=opening_key)
        decision = authorize(envelope.encode())
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.failures, ("grant_authentication_invalid",))

    def test_authentication_backend_exception_fails_closed(self) -> None:
        class BrokenVerifier:
            def verify(self, *_args: object) -> bool:
                raise RuntimeError("test backend failure")

        decision = authorize(
            authenticated_grant().encode(), grant_verifier=BrokenVerifier()
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(
            decision.failures,
            ("grant_authentication_backend:RuntimeError",),
        )

    def test_wrong_initialization_trust_anchor_rejects(self) -> None:
        advertised = reference_bundle().key_for(KeyRole.FEDERATION_CONFIGURATION)
        wrong_anchor = replace(
            advertised,
            key_id=fixed_bytes(b"wrong-trust-anchor/key-id"),
            public_key_digest=fixed_bytes(b"wrong-trust-anchor/public-key"),
        )
        decision = authorize(
            authenticated_grant().encode(), trusted_key=wrong_anchor
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(
            decision.failures,
            ("initialization:configuration_trust_anchor_mismatch",),
        )


class QuotaReplayTests(unittest.TestCase):
    def test_quota_decrements_from_n_to_zero_for_different_sids(self) -> None:
        store = SingleProcessMemoryQuotaStore()
        encoded = authenticated_grant().encode()
        remaining = []
        for index in range(3):
            decision = authorize(
                encoded,
                store=store,
                sid=f"issuer-session-{index}".encode("ascii"),
            )
            self.assertTrue(decision.accepted, decision.failures)
            remaining.append(decision.remaining_quota)
        self.assertEqual(remaining, [2, 1, 0])

    def test_quota_exhausted_rejects(self) -> None:
        store = SingleProcessMemoryQuotaStore()
        encoded = authenticated_grant(reference_grant(quota=1)).encode()
        self.assertTrue(authorize(encoded, store=store, sid=b"sid-a").accepted)
        decision = authorize(encoded, store=store, sid=b"sid-b")
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.failures, ("quota_exhausted",))
        self.assertEqual(decision.remaining_quota, 0)

    def test_same_sid_replay_rejects_without_decrement(self) -> None:
        store = SingleProcessMemoryQuotaStore()
        envelope = authenticated_grant()
        first = authorize(envelope.encode(), store=store, sid=b"same-sid")
        replay = authorize(envelope.encode(), store=store, sid=b"same-sid")
        self.assertTrue(first.accepted)
        self.assertFalse(replay.accepted)
        self.assertEqual(replay.failures, ("quota_replay",))
        self.assertEqual(replay.remaining_quota, first.remaining_quota)

        different = authorize(envelope.encode(), store=store, sid=b"different-sid")
        self.assertTrue(different.accepted)
        self.assertEqual(different.remaining_quota, first.remaining_quota - 1)

    def test_memory_store_consume_is_atomic_within_one_process(self) -> None:
        quota = 5
        contenders = 12
        store = SingleProcessMemoryQuotaStore()
        grant = reference_grant(quota=quota)
        barrier = Barrier(contenders)
        results = []

        def consume(index: int) -> None:
            barrier.wait()
            results.append(
                store.consume(
                    grant.digest,
                    f"concurrent-sid-{index}".encode("ascii"),
                    quota,
                )
            )

        threads = [Thread(target=consume, args=(index,)) for index in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(
            sum(result.status is QuotaConsumeStatus.CONSUMED for result in results),
            quota,
        )
        self.assertEqual(
            sum(result.status is QuotaConsumeStatus.EXHAUSTED for result in results),
            contenders - quota,
        )


if __name__ == "__main__":
    unittest.main()
