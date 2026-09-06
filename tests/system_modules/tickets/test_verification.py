#!/usr/bin/env python3
"""Tests for the stateless VerifyTicket contract checkpoint."""

from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from pq_rbbc.contracts.system import (
    KeyReference,
    KeyRole,
    SystemConfiguration,
    SystemInitializationBundle,
    ThresholdPolicy,
)
from pq_rbbc.governance.system_init import (
    INITIALIZATION_AUTH_DOMAIN,
    AuthenticatedSystemInitialization,
)
from pq_rbbc.opening.request import canonical_ticket_digest
from pq_rbbc.tickets.verification import (
    TICKET_MAGIC,
    TICKET_PAYLOAD_BYTES,
    CanonicalTicket,
    SystemTicketVerifier,
    decode_ticket_payload,
    ticket_payload_digest,
    verify_ticket,
    verify_ticket_manifest,
)
from pq_rbbc_reference import LABEL_TICKET, TicketPayload


ROOT = Path(__file__).resolve().parents[3]
FROZEN_MANIFEST = ROOT / "manifests" / "pq_rbbc_verify_ticket_contract_v0_1.json"
VALID_TIME = 1_800_000_000


def fixed_bytes(label: bytes) -> bytes:
    return hashlib.sha256(b"PQ-RBBC/verify-ticket-test/" + label).digest()


class DeterministicConfigurationVerifier:
    """Deterministic test checksum; not a cryptographic signature."""

    def __init__(self, *, broken: bool = False) -> None:
        self.broken = broken
        self.calls = 0

    @staticmethod
    def sign(key: KeyReference, message: bytes) -> bytes:
        return hashlib.sha256(
            b"TEST-ONLY/CONFIG-AUTH/" + key.public_key_digest + message
        ).digest()

    def verify(
        self,
        key: KeyReference,
        message: bytes,
        authentication: bytes,
    ) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("test configuration backend failure")
        return authentication == self.sign(key, message)


class DeterministicTicketVerifier:
    """Deterministic test checksum; not Blind-UOV or a signature scheme."""

    def __init__(self, *, broken: bool = False, result: object = True) -> None:
        self.broken = broken
        self.result = result
        self.calls = 0
        self.keys: list[KeyReference] = []
        self.message_digests: list[bytes] = []

    @staticmethod
    def sign(key: KeyReference, message_digest: bytes) -> bytes:
        return hashlib.sha256(
            b"TEST-ONLY/TICKET-AUTH/"
            + key.public_key_digest
            + message_digest
        ).digest()

    def verify(
        self,
        key: KeyReference,
        message_digest: bytes,
        signature: bytes,
    ) -> bool:
        self.calls += 1
        self.keys.append(key)
        self.message_digests.append(message_digest)
        if self.broken:
            raise RuntimeError("test ticket backend failure")
        if self.result is not True:
            return self.result  # type: ignore[return-value]
        return signature == self.sign(key, message_digest)


class FixedClock:
    def __init__(self, timestamp: object = VALID_TIME, *, broken: bool = False) -> None:
        self.timestamp = timestamp
        self.broken = broken

    def now(self) -> int:
        if self.broken:
            raise OSError("test clock failure")
        return self.timestamp  # type: ignore[return-value]


def reference_bundle() -> SystemInitializationBundle:
    keys = tuple(
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
        key for key in keys if key.role is KeyRole.ISSUER_VERIFICATION
    )
    opening_key = next(
        key for key in keys if key.role is KeyRole.OPENING_ENCRYPTION
    )
    return SystemInitializationBundle(
        configuration=SystemConfiguration(
            protocol_version=1,
            epoch=91,
            domain=fixed_bytes(b"domain"),
            policy_digest=fixed_bytes(b"policy"),
            expiry_bucket=1_900_000_000,
            oa_key_id=opening_key.key_id,
            issuer_key_id=issuer_key.key_id,
        ),
        common_parameters_digest=fixed_bytes(b"common-parameters"),
        federation_policy=ThresholdPolicy(member_count=5, threshold=3),
        opening_policy=ThresholdPolicy(member_count=7, threshold=5),
        keys=keys,
    )


def authenticated_initialization(
    bundle: SystemInitializationBundle | None = None,
) -> AuthenticatedSystemInitialization:
    bundle = reference_bundle() if bundle is None else bundle
    key = bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
    message = INITIALIZATION_AUTH_DOMAIN + bundle.encode()
    return AuthenticatedSystemInitialization(
        bundle=bundle,
        authentication=DeterministicConfigurationVerifier.sign(key, message),
    )


def reference_payload(
    bundle: SystemInitializationBundle | None = None,
) -> TicketPayload:
    bundle = reference_bundle() if bundle is None else bundle
    return TicketPayload(
        ctx=bundle.ctx,
        sn=fixed_bytes(b"visible-serial")[:16],
        holder_hash=fixed_bytes(b"holder-hash"),
        syndrome=hashlib.shake_256(b"PQ-RBBC/verify-ticket-test/syndrome").digest(
            208
        ),
        masked_identity=hashlib.shake_256(
            b"PQ-RBBC/verify-ticket-test/masked-identity"
        ).digest(48),
        tag=fixed_bytes(b"trace-tag"),
    )


def authenticated_ticket(
    *,
    payload: TicketPayload | None = None,
    issuer_key_id: bytes | None = None,
    signing_role: KeyRole = KeyRole.ISSUER_VERIFICATION,
    protocol_version: int = 1,
    signing_key: KeyReference | None = None,
) -> CanonicalTicket:
    bundle = reference_bundle()
    payload = reference_payload(bundle) if payload is None else payload
    key = (
        bundle.key_for(KeyRole.ISSUER_VERIFICATION)
        if signing_key is None
        else signing_key
    )
    draft = CanonicalTicket(
        protocol_version=protocol_version,
        signing_role=signing_role,
        issuer_key_id=key.key_id if issuer_key_id is None else issuer_key_id,
        payload=payload,
        signature=b"unsigned-test-placeholder",
    )
    return replace(
        draft,
        signature=DeterministicTicketVerifier.sign(key, draft.payload_digest),
    )


def verify(
    encoded_ticket: bytes,
    *,
    initialization: bytes | None = None,
    trusted_key: KeyReference | None = None,
    initialization_verifier: object | None = None,
    ticket_verifier: object | None = None,
    clock: object | None = None,
):
    envelope = authenticated_initialization()
    return verify_ticket(
        envelope.encode() if initialization is None else initialization,
        encoded_ticket,
        trusted_configuration_key=(
            envelope.bundle.key_for(KeyRole.FEDERATION_CONFIGURATION)
            if trusted_key is None
            else trusted_key
        ),
        initialization_verifier=(
            DeterministicConfigurationVerifier()
            if initialization_verifier is None
            else initialization_verifier
        ),
        ticket_verifier=(
            DeterministicTicketVerifier()
            if ticket_verifier is None
            else ticket_verifier
        ),
        clock=FixedClock() if clock is None else clock,
    )


class CanonicalTicketCodecTests(unittest.TestCase):
    def test_canonical_round_trip_and_reference_payload_identity(self) -> None:
        ticket = authenticated_ticket()
        encoded = ticket.encode()
        self.assertTrue(encoded.startswith(TICKET_MAGIC))
        self.assertEqual(CanonicalTicket.decode(encoded), ticket)
        self.assertEqual(decode_ticket_payload(ticket.payload.encode()), ticket.payload)
        self.assertEqual(len(ticket.payload.encode()), TICKET_PAYLOAD_BYTES)
        self.assertEqual(ticket_payload_digest(ticket.payload), ticket.payload_digest)
        self.assertEqual(
            ticket.payload_digest,
            hashlib.shake_256(LABEL_TICKET + ticket.payload.encode()).digest(32),
        )

    def test_exact_frozen_vector(self) -> None:
        ticket = authenticated_ticket()
        self.assertEqual(
            ticket.encode().hex(),
            "5051524242432d5449434b45542d5631010001000400e76089b0af1304417905"
            "a6bc968d02d272f00b4235ed70065d235679ba29f24870010000e72b44581e99"
            "45ed8f1c5ed522cddb6e87d8d2ef15f5cc7b293df9b855e2506a0610e4bfd63"
            "f35f49bb94fbdffc2bb48ad1faa7b22015db883cec42d3cccef7cbb45e58e104"
            "7853334a269b1f08bd53ca3886d5bf19b23593fb5be271512daad80361b95c833"
            "55b95da7fd7bdb5b917a53d639408aed1f58ec01b42b54afff955b99890c2c227"
            "fbf0f7aca39b0de744103298e0988dcd7db52cc24cc7120c53a29d2e229b4604"
            "70b33606184a716de4fc978c790114ea4188b576d888a2127d594f848c5539a663"
            "97be01c9ac89c775c5a880722c61bdd67ec13fcc754659cf076c4843d6c3d9f845"
            "a67f93ee289a82197154496ec237d8df85dc15071e133388a6e37f390e6fe34e4e"
            "addffbe091bfa46b180c3083e67a8602617c144023d2d25d1425890c89d7a5547d"
            "538e090ca5ccbb51ee75d906008f9c99cb0d24323083e74e4c91b61a6e24dd9f5"
            "59b31caea5bd2dad6800fa3f592cf45123e1601343d7590fe22b16ea0404a6965d"
            "335cf5bf20000000eb3a19e6867093666570300430a912227fdb7118fb3deb3005"
            "2803590d276f17",
        )
        self.assertEqual(
            ticket.payload_digest.hex(),
            "41284b146af4f04412e8e39d4a82d2a76a855014951f05223aa1f000ac0364d5",
        )
        self.assertEqual(
            ticket.canonical_digest.hex(),
            "25800ecc6190e8474b8848866b47d11f31d2819c4abcdefecacb14ae41cb7cc6",
        )
        manifest = verify_ticket_manifest(ticket)
        self.assertEqual(manifest, json.loads(FROZEN_MANIFEST.read_text()))
        claims = manifest["claim_boundary"]
        self.assertFalse(claims["test_signature_is_cryptographic"])
        self.assertFalse(claims["production_signature_encoding_frozen"])
        self.assertFalse(claims["production_verify_ticket_complete"])

    def test_unknown_schema_protocol_and_role_reject(self) -> None:
        encoded = bytearray(authenticated_ticket().encode())
        schema_offset = len(TICKET_MAGIC)
        encoded[schema_offset : schema_offset + 2] = (2).to_bytes(2, "little")
        self.assertFalse(verify(bytes(encoded)).accepted)

        encoded = bytearray(authenticated_ticket().encode())
        protocol_offset = len(TICKET_MAGIC) + 2
        encoded[protocol_offset : protocol_offset + 2] = (2).to_bytes(
            2, "little"
        )
        self.assertFalse(verify(bytes(encoded)).accepted)

        encoded = bytearray(authenticated_ticket().encode())
        role_offset = len(TICKET_MAGIC) + 4
        encoded[role_offset : role_offset + 2] = (65535).to_bytes(2, "little")
        self.assertFalse(verify(bytes(encoded)).accepted)

    def test_malformed_truncated_and_trailing_bytes_reject(self) -> None:
        encoded = authenticated_ticket().encode()
        self.assertFalse(verify(bytes([encoded[0] ^ 1]) + encoded[1:]).accepted)
        for cut in range(len(encoded)):
            with self.subTest(cut=cut):
                self.assertFalse(verify(encoded[:cut]).accepted)
        self.assertFalse(verify(encoded + b"\x00").accepted)

        payload_length_offset = len(TICKET_MAGIC) + 2 + 2 + 2 + 32
        malformed = bytearray(encoded)
        malformed[payload_length_offset : payload_length_offset + 4] = (
            TICKET_PAYLOAD_BYTES - 1
        ).to_bytes(4, "little")
        self.assertFalse(verify(bytes(malformed)).accepted)

        signature_length_offset = payload_length_offset + 4 + TICKET_PAYLOAD_BYTES
        malformed = bytearray(encoded)
        malformed[signature_length_offset : signature_length_offset + 4] = bytes(4)
        self.assertFalse(verify(bytes(malformed)).accepted)

    def test_fixed_field_reordering_rejects(self) -> None:
        encoded = bytearray(authenticated_ticket().encode())
        protocol_offset = len(TICKET_MAGIC) + 2
        role_offset = protocol_offset + 2
        protocol = bytes(encoded[protocol_offset : protocol_offset + 2])
        role = bytes(encoded[role_offset : role_offset + 2])
        encoded[protocol_offset : protocol_offset + 2] = role
        encoded[role_offset : role_offset + 2] = protocol
        self.assertFalse(verify(bytes(encoded)).accepted)

    def test_payload_identity_is_independent_of_signature_representation(self) -> None:
        ticket = authenticated_ticket()
        alternate = replace(ticket, signature=b"alternate-test-signature")
        self.assertEqual(alternate.payload_digest, ticket.payload_digest)
        self.assertNotEqual(alternate.canonical_digest, ticket.canonical_digest)


class VerifyTicketTests(unittest.TestCase):
    def test_honest_authorization_accepts_and_builds_ticket_view(self) -> None:
        backend = DeterministicTicketVerifier()
        ticket = authenticated_ticket()
        outcome = verify(ticket.encode(), ticket_verifier=backend)
        self.assertTrue(outcome.accepted, outcome.failures)
        self.assertEqual(outcome.failures, ())
        self.assertEqual(outcome.payload_digest, ticket.payload_digest)
        self.assertIsNotNone(outcome.ticket)
        assert outcome.ticket is not None
        self.assertEqual(outcome.ticket.ticket_digest, ticket.canonical_digest)
        self.assertEqual(
            outcome.ticket.ticket_digest,
            canonical_ticket_digest(ticket.encode()),
        )
        self.assertEqual(outcome.ticket.ctx, ticket.payload.ctx)
        self.assertEqual(outcome.ticket.visible_serial, ticket.payload.sn)
        self.assertEqual(outcome.ticket.trace_ciphertext, ticket.trace_ciphertext)
        self.assertEqual(len(outcome.ticket.trace_ciphertext), 288)
        self.assertEqual(backend.calls, 1)
        self.assertIs(backend.keys[0].role, KeyRole.ISSUER_VERIFICATION)
        self.assertEqual(backend.message_digests, [ticket.payload_digest])

    def test_initialization_is_checked_before_ticket_parsing(self) -> None:
        envelope = bytearray(authenticated_initialization().encode())
        envelope[-1] ^= 1
        backend = DeterministicTicketVerifier()
        outcome = verify(
            b"not-a-ticket",
            initialization=bytes(envelope),
            ticket_verifier=backend,
        )
        self.assertFalse(outcome.accepted)
        self.assertTrue(outcome.failures[0].startswith("initialization:"))
        self.assertEqual(backend.calls, 0)

    def test_ctx_mutation_rejects_even_when_reauthenticated(self) -> None:
        payload = reference_payload()
        mutated = replace(
            payload,
            ctx=bytes([payload.ctx[0] ^ 1]) + payload.ctx[1:],
        )
        backend = DeterministicTicketVerifier()
        outcome = verify(
            authenticated_ticket(payload=mutated).encode(),
            ticket_verifier=backend,
        )
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("ticket_ctx_mismatch",))
        self.assertEqual(backend.calls, 0)

    def test_policy_and_epoch_changes_reject_through_authenticated_ctx(self) -> None:
        base = reference_bundle()
        changed_configurations = {
            "policy": replace(
                base.configuration,
                policy_digest=fixed_bytes(b"changed-policy"),
            ),
            "epoch": replace(base.configuration, epoch=base.configuration.epoch + 1),
        }
        ticket = authenticated_ticket().encode()
        for name, configuration in changed_configurations.items():
            with self.subTest(name=name):
                changed_bundle = replace(base, configuration=configuration)
                initialization = authenticated_initialization(changed_bundle)
                outcome = verify(ticket, initialization=initialization.encode())
                self.assertFalse(outcome.accepted)
                self.assertEqual(outcome.failures, ("ticket_ctx_mismatch",))

    def test_issuer_key_id_mutation_rejects_before_backend(self) -> None:
        backend = DeterministicTicketVerifier()
        ticket = authenticated_ticket(issuer_key_id=fixed_bytes(b"wrong-issuer"))
        outcome = verify(ticket.encode(), ticket_verifier=backend)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("ticket_issuer_key_id_mismatch",))
        self.assertEqual(backend.calls, 0)

    def test_signature_and_payload_mutations_reject(self) -> None:
        ticket = authenticated_ticket()
        encoded = ticket.encode()
        signature_mutation = encoded[:-1] + bytes([encoded[-1] ^ 1])
        outcome = verify(signature_mutation)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("ticket_authentication_invalid",))

        payload = replace(
            ticket.payload,
            holder_hash=bytes([ticket.payload.holder_hash[0] ^ 1])
            + ticket.payload.holder_hash[1:],
        )
        unsigned_mutation = replace(ticket, payload=payload)
        outcome = verify(unsigned_mutation.encode())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("ticket_authentication_invalid",))

    def test_wrong_known_key_role_rejects(self) -> None:
        ticket = authenticated_ticket(signing_role=KeyRole.OPENING_AUTHORIZATION)
        outcome = verify(ticket.encode())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("ticket_wrong_key_role",))

    def test_configuration_expiry_is_half_open(self) -> None:
        expiry = reference_bundle().configuration.expiry_bucket
        before = verify(
            authenticated_ticket().encode(),
            clock=FixedClock(expiry - 1),
        )
        self.assertTrue(before.accepted, before.failures)
        expired = verify(
            authenticated_ticket().encode(),
            clock=FixedClock(expiry),
        )
        self.assertFalse(expired.accepted)
        self.assertEqual(expired.failures, ("ticket_expired",))

    def test_backend_exceptions_and_non_boolean_success_fail_closed(self) -> None:
        ticket = authenticated_ticket().encode()
        outcome = verify(
            ticket,
            ticket_verifier=DeterministicTicketVerifier(broken=True),
        )
        self.assertFalse(outcome.accepted)
        self.assertEqual(
            outcome.failures,
            ("ticket_authentication_backend:RuntimeError",),
        )
        outcome = verify(
            ticket,
            ticket_verifier=DeterministicTicketVerifier(result=1),
        )
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("ticket_authentication_invalid",))

        outcome = verify(ticket, clock=FixedClock(broken=True))
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("clock_backend:OSError",))
        outcome = verify(ticket, clock=FixedClock(True))
        self.assertFalse(outcome.accepted)
        self.assertIn("clock_backend:", outcome.failures[0])

        outcome = verify(
            ticket,
            initialization_verifier=DeterministicConfigurationVerifier(
                broken=True
            ),
        )
        self.assertFalse(outcome.accepted)
        self.assertEqual(
            outcome.failures,
            ("initialization:configuration_authentication_backend:RuntimeError",),
        )

    def test_non_issuer_bundle_key_cannot_authenticate_ticket(self) -> None:
        bundle = reference_bundle()
        issuer_key = bundle.key_for(KeyRole.ISSUER_VERIFICATION)
        opening_key = bundle.key_for(KeyRole.OPENING_AUTHORIZATION)
        ticket = authenticated_ticket(
            issuer_key_id=issuer_key.key_id,
            signing_key=opening_key,
        )
        outcome = verify(ticket.encode())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, ("ticket_authentication_invalid",))

    def test_wrong_initialization_trust_anchor_rejects(self) -> None:
        advertised = reference_bundle().key_for(KeyRole.FEDERATION_CONFIGURATION)
        wrong_anchor = replace(
            advertised,
            key_id=fixed_bytes(b"wrong-anchor/key-id"),
            public_key_digest=fixed_bytes(b"wrong-anchor/public-key"),
        )
        outcome = verify(
            authenticated_ticket().encode(),
            trusted_key=wrong_anchor,
        )
        self.assertFalse(outcome.accepted)
        self.assertEqual(
            outcome.failures,
            ("initialization:configuration_trust_anchor_mismatch",),
        )

    def test_adapter_is_stateless_and_compatible_with_opening_interface(self) -> None:
        initialization = authenticated_initialization()
        bundle = initialization.bundle
        adapter = SystemTicketVerifier(
            authenticated_initialization=initialization.encode(),
            trusted_configuration_key=bundle.key_for(
                KeyRole.FEDERATION_CONFIGURATION
            ),
            initialization_verifier=DeterministicConfigurationVerifier(),
            ticket_verifier=DeterministicTicketVerifier(),
            clock=FixedClock(),
        )
        ticket = authenticated_ticket().encode()
        first = adapter.verify(ticket)
        second = adapter.verify(ticket)
        self.assertIsNotNone(first)
        self.assertEqual(first, second)
        self.assertIsNone(adapter.verify(ticket + b"\x00"))


if __name__ == "__main__":
    unittest.main()
