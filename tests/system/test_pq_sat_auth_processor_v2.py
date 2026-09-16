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
from pq_rbbc.tickets.verification import CanonicalTicket
from pq_rbbc_reference import TicketPayload
from pq_sat_auth.v2.access import (
    REFERENCE_PROOF_SUITE_ID,
    REFERENCE_SUITE_ID,
    AccessRequestV2,
    ChannelBindingMode,
    derive_request_core_digest,
    encode_access_request,
)
from pq_sat_auth.v2.processor import (
    PRODUCTION_READY,
    AccessConfigurationSnapshotV2,
    AccessRevocationSnapshotV2,
    ChannelBindingPolicyV2,
    FGSPureCheckProcessorV2,
    SystemAccessTicketVerifierV2,
    fgs_pure_check_manifest,
)
from pq_sat_auth.v2.proof import (
    AccessProofStatementV2,
    derive_holder_binding_tag,
    derive_holder_hash,
)
from pq_sat_auth.v2.replay import (
    InMemoryLinearizableReplayStoreV2,
    ReserveDispositionV2,
)


NOW = 1_800_000_000
ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_fgs_pure_check_v0_2.json"


def fixed(label: bytes, size: int = 32) -> bytes:
    return hashlib.shake_256(b"PQ-SAT/FGS-PURE-CHECK/TEST/" + label).digest(size)


class ConfigurationAuthenticationTestBackend:
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
        return authentication == self.sign(key, message)


class TicketAuthenticationTestBackend:
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
        return signature == self.sign(key, message_digest)


class FixedClock:
    def __init__(self, value: object = NOW, *, broken: bool = False) -> None:
        self.value = value
        self.broken = broken
        self.calls = 0

    def now(self) -> int:
        self.calls += 1
        if self.broken:
            raise OSError("clock unavailable")
        return self.value  # type: ignore[return-value]


class ConfigurationProvider:
    def __init__(
        self,
        configuration: object,
        *,
        return_for_any_digest: bool = False,
        broken: bool = False,
    ) -> None:
        self.configuration = configuration
        self.return_for_any_digest = return_for_any_digest
        self.broken = broken
        self.calls = 0

    def resolve(self, system_config_digest: bytes):
        self.calls += 1
        if self.broken:
            raise OSError("configuration service unavailable")
        if self.return_for_any_digest:
            return self.configuration
        if (
            isinstance(self.configuration, AccessConfigurationSnapshotV2)
            and self.configuration.system_config_digest == system_config_digest
        ):
            return self.configuration
        return None


class RevocationProvider:
    def __init__(self, **changes: object) -> None:
        self.changes = changes
        self.calls = 0
        self.broken = False
        self.last_query = None

    def snapshot(self, query):
        self.calls += 1
        self.last_query = query
        if self.broken:
            raise OSError("revocation service unavailable")
        snapshot = AccessRevocationSnapshotV2(
            query_digest=query.digest,
            generation=12,
            effective_at=NOW - 60,
            valid_until=NOW + 60,
        )
        return replace(snapshot, **self.changes)


class AccessNIZKTestBackend:
    proof_suite_id = REFERENCE_PROOF_SUITE_ID
    production_ready = False

    def __init__(self, result: object = True, *, broken: bool = False) -> None:
        self.result = result
        self.broken = broken
        self.calls = 0

    @staticmethod
    def proof(statement: AccessProofStatementV2) -> bytes:
        return hashlib.sha256(
            b"TEST-ONLY/ACCESS-NIZK/" + statement.encode()
        ).digest()

    def prove(self, statement, witness):
        raise NotImplementedError

    def verify(self, statement: AccessProofStatementV2, proof: bytes) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("proof backend failed")
        if self.result is not True:
            return self.result  # type: ignore[return-value]
        return proof == self.proof(statement)


class KEMTestBackend:
    suite_id = REFERENCE_SUITE_ID
    production_ready = False

    def __init__(self, result: object = True, *, broken: bool = False) -> None:
        self.result = result
        self.broken = broken
        self.calls = 0

    def validate_public_key(self, public_key: bytes) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("KEM backend failed")
        if self.result is not True:
            return self.result  # type: ignore[return-value]
        return public_key == b"test-only-ephemeral-kem-public-key"

    def encapsulate(self, public_key: bytes):
        raise NotImplementedError

    def decapsulate(self, secret_key: bytes, ciphertext: bytes):
        raise NotImplementedError


class ChannelBindingVerifier:
    def __init__(self, expected: bytes, result: object = True) -> None:
        self.expected = expected
        self.result = result
        self.calls = 0
        self.broken = False

    def verify_authenticated_exporter(self, claimed_digest: bytes) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("exporter unavailable")
        return self.result is True and claimed_digest == self.expected


class AdmissionPolicy:
    def __init__(self, result: object = True, *, broken: bool = False) -> None:
        self.result = result
        self.broken = broken
        self.calls = 0

    def admit(self, request, ticket, *, checked_at: int) -> bool:
        self.calls += 1
        if self.broken:
            raise RuntimeError("admission backend failed")
        return self.result  # type: ignore[return-value]


def reference_bundle() -> SystemInitializationBundle:
    keys = tuple(
        KeyReference(
            role=role,
            key_id=fixed(b"key-id/" + role.name.encode("ascii")),
            public_key_digest=fixed(
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
            domain=fixed(b"domain"),
            policy_digest=fixed(b"policy"),
            expiry_bucket=NOW + 10_000,
            oa_key_id=opening_key.key_id,
            issuer_key_id=issuer_key.key_id,
        ),
        common_parameters_digest=fixed(b"common-parameters"),
        federation_policy=ThresholdPolicy(member_count=5, threshold=3),
        opening_policy=ThresholdPolicy(member_count=7, threshold=5),
        keys=keys,
    )


class FGSPureCheckFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = reference_bundle()
        configuration_key = self.bundle.key_for(
            KeyRole.FEDERATION_CONFIGURATION
        )
        initialization_message = INITIALIZATION_AUTH_DOMAIN + self.bundle.encode()
        self.initialization = AuthenticatedSystemInitialization(
            bundle=self.bundle,
            authentication=ConfigurationAuthenticationTestBackend.sign(
                configuration_key,
                initialization_message,
            ),
        )
        self.holder_secret = fixed(b"holder-secret")
        payload = TicketPayload(
            ctx=self.bundle.ctx,
            sn=fixed(b"serial", 16),
            holder_hash=derive_holder_hash(self.holder_secret),
            syndrome=fixed(b"syndrome", 208),
            masked_identity=fixed(b"masked-identity", 48),
            tag=fixed(b"trace-tag"),
        )
        issuer_key = self.bundle.key_for(KeyRole.ISSUER_VERIFICATION)
        draft_ticket = CanonicalTicket(
            protocol_version=1,
            signing_role=KeyRole.ISSUER_VERIFICATION,
            issuer_key_id=issuer_key.key_id,
            payload=payload,
            signature=b"unsigned-test-placeholder",
        )
        self.ticket = replace(
            draft_ticket,
            signature=TicketAuthenticationTestBackend.sign(
                issuer_key,
                draft_ticket.payload_digest,
            ),
        )
        self.access_configuration = AccessConfigurationSnapshotV2(
            system_config_digest=fixed(b"access-system-configuration"),
            initialization_configuration_digest=hashlib.sha256(
                self.bundle.configuration.encode()
            ).digest(),
            access_protocol_version=2,
            ctx=self.bundle.ctx,
            epoch=91,
            valid_from=NOW - 1_000,
            valid_until=NOW + 1_000,
            freshness_window_seconds=120,
            maximum_clock_skew_seconds=10,
            pure_check_max_age_seconds=5,
            reservation_lease_seconds=30,
            activation_window_seconds=60,
            session_lifetime_seconds=600,
            replay_retention_grace_seconds=300,
            access_profile_digest=fixed(b"access-profile"),
            access_pp_digest=fixed(b"access-pp"),
            fgs_id=fixed(b"fgs-id"),
            fgs_auth_key_id=fixed(b"fgs-auth-key-id"),
            issuer_verification_key_id=issuer_key.key_id,
            serving_context_digest=fixed(b"serving-context"),
            authorization_digest=fixed(b"authorization"),
            acceptance_domain_digest=fixed(b"acceptance-domain"),
            allowed_suite_ids=(REFERENCE_SUITE_ID,),
            allowed_proof_suite_ids=(REFERENCE_PROOF_SUITE_ID,),
            channel_binding_policy=(
                ChannelBindingPolicyV2.REQUIRE_AUTHENTICATED_EXPORTER
            ),
            minimum_revocation_generation=10,
        )
        self.ticket_verifier = SystemAccessTicketVerifierV2(
            authenticated_initialization=self.initialization.encode(),
            trusted_configuration_key=configuration_key,
            initialization_verifier=ConfigurationAuthenticationTestBackend(),
            ticket_verifier=TicketAuthenticationTestBackend(),
        )
        self.clock = FixedClock()
        self.configuration_provider = ConfigurationProvider(
            self.access_configuration
        )
        self.revocation_provider = RevocationProvider()
        self.proof_backend = AccessNIZKTestBackend()
        self.kem_backend = KEMTestBackend()
        self.channel_binding = ChannelBindingVerifier(fixed(b"exporter"))
        self.admission = AdmissionPolicy()

        draft_request = AccessRequestV2(
            suite_id=REFERENCE_SUITE_ID,
            proof_suite_id=REFERENCE_PROOF_SUITE_ID,
            system_config_digest=(
                self.access_configuration.system_config_digest
            ),
            ctx=self.access_configuration.ctx,
            epoch=self.access_configuration.epoch,
            target_fgs_id=self.access_configuration.fgs_id,
            fgs_auth_key_id=self.access_configuration.fgs_auth_key_id,
            serving_context_digest=(
                self.access_configuration.serving_context_digest
            ),
            authorization_digest=(
                self.access_configuration.authorization_digest
            ),
            client_time=NOW,
            ue_nonce=fixed(b"ue-nonce"),
            attempt_nonce=fixed(b"attempt-nonce", 16),
            channel_binding_mode=ChannelBindingMode.AUTHENTICATED_EXPORTER,
            channel_binding_digest=fixed(b"exporter"),
            ticket=self.ticket.encode(),
            ue_kem_epk=b"test-only-ephemeral-kem-public-key",
            holder_binding_tag=bytes(32),
            access_nizk=b"test-only-proof-placeholder",
        )
        self.request = self._complete_request(draft_request)

    def _complete_request(self, request: AccessRequestV2) -> AccessRequestV2:
        draft = replace(
            request,
            holder_binding_tag=bytes(32),
            access_nizk=b"test-only-proof-placeholder",
        )
        tagged = replace(
            draft,
            holder_binding_tag=derive_holder_binding_tag(
                self.holder_secret,
                derive_request_core_digest(draft),
            ),
        )
        statement = AccessProofStatementV2(
            access_profile_digest=self.access_configuration.access_profile_digest,
            access_pp_digest=self.access_configuration.access_pp_digest,
            holder_hash=self.ticket.payload.holder_hash,
            request_core_digest=derive_request_core_digest(tagged),
            holder_binding_tag=tagged.holder_binding_tag,
        )
        return replace(
            tagged,
            access_nizk=AccessNIZKTestBackend.proof(statement),
        )

    def processor(self, **overrides: object) -> FGSPureCheckProcessorV2:
        arguments = {
            "configuration_provider": self.configuration_provider,
            "clock": self.clock,
            "ticket_verifier": self.ticket_verifier,
            "revocation_provider": self.revocation_provider,
            "access_nizk_backend": self.proof_backend,
            "kem_backend": self.kem_backend,
            "admission_policy": self.admission,
            "channel_binding_verifier": self.channel_binding,
        }
        arguments.update(overrides)
        return FGSPureCheckProcessorV2(**arguments)  # type: ignore[arg-type]

    def process(self, request: AccessRequestV2 | None = None, **overrides: object):
        target = self.request if request is None else request
        return self.processor(**overrides).process(encode_access_request(target))


class FGSPureCheckPositiveTests(FGSPureCheckFixture):
    def test_machine_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            fgs_pure_check_manifest(),
        )

    def test_honest_request_returns_reservation_ready_identity(self) -> None:
        outcome = self.process()
        self.assertTrue(outcome.accepted, outcome.failures)
        self.assertEqual(outcome.failures, ())
        self.assertIsNotNone(outcome.validated)
        assert outcome.validated is not None
        validated = outcome.validated
        self.assertEqual(validated.request_bytes, encode_access_request(self.request))
        self.assertEqual(validated.checked_at, NOW)
        self.assertEqual(validated.revocation_generation, 12)
        self.assertEqual(
            validated.revocation_query.digest,
            self.revocation_provider.last_query.digest,
        )
        self.assertEqual(
            validated.identity.ticket_digest,
            self.ticket.payload_digest,
        )
        self.assertEqual(
            validated.ticket.system_config_digest,
            self.access_configuration.initialization_configuration_digest,
        )
        self.assertEqual(
            validated.ticket.expires_at,
            self.bundle.configuration.expiry_bucket,
        )
        self.assertNotEqual(
            validated.identity.ticket_digest,
            self.ticket.canonical_digest,
        )
        self.assertEqual(validated.ticket.holder_hash, self.ticket.payload.holder_hash)
        self.assertFalse(PRODUCTION_READY)
        self.assertFalse(self.processor().production_ready)

    def test_processor_stops_before_reserve_but_output_connects_to_store(self) -> None:
        store = InMemoryLinearizableReplayStoreV2()
        outcome = self.process()
        self.assertEqual(len(store), 0)
        assert outcome.validated is not None
        validated = outcome.validated
        reservation = store.reserve(
            validated.identity,
            attempt_id=validated.attempt_id,
            request_digest=validated.request_digest,
            serving_context_digest=validated.request.serving_context_digest,
            reserved_at=validated.checked_at,
            lease_deadline=validated.checked_at + 30,
            revocation_generation=validated.revocation_generation,
        )
        self.assertIs(reservation.disposition, ReserveDispositionV2.NEW)

    def test_none_channel_mode_is_accepted_only_by_explicit_policy(self) -> None:
        configuration = replace(
            self.access_configuration,
            channel_binding_policy=ChannelBindingPolicyV2.NONE_ONLY,
        )
        request = self._complete_request(
            replace(
                self.request,
                channel_binding_mode=ChannelBindingMode.NONE,
                channel_binding_digest=bytes(32),
            )
        )
        outcome = self.process(
            request,
            configuration_provider=ConfigurationProvider(configuration),
            channel_binding_verifier=None,
        )
        self.assertTrue(outcome.accepted, outcome.failures)


class FGSPureCheckBoundaryTests(FGSPureCheckFixture):
    def assert_rejected(self, outcome, failure: str) -> None:
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.failures, (failure,))
        self.assertIsNone(outcome.validated)

    def test_malformed_and_trailing_requests_reject_before_configuration(self) -> None:
        encoded = encode_access_request(self.request)
        for candidate in (encoded[:-1], encoded + b"\x00"):
            with self.subTest(length=len(candidate)):
                provider = ConfigurationProvider(self.access_configuration)
                outcome = self.processor(
                    configuration_provider=provider
                ).process(candidate)
                self.assertFalse(outcome.accepted)
                self.assertTrue(outcome.failures[0].startswith("request_encoding:"))
                self.assertEqual(provider.calls, 0)

    def test_configuration_backend_and_invalid_snapshot_fail_closed(self) -> None:
        broken = ConfigurationProvider(self.access_configuration, broken=True)
        outcome = self.process(configuration_provider=broken)
        self.assert_rejected(outcome, "configuration_backend:OSError")

        invalid = replace(self.access_configuration, valid_until=NOW - 2_000)
        outcome = self.process(
            configuration_provider=ConfigurationProvider(invalid)
        )
        self.assert_rejected(outcome, "configuration_invalid:ValueError")

        invalid = replace(
            self.access_configuration,
            acceptance_domain_digest=bytes(32),
        )
        outcome = self.process(
            configuration_provider=ConfigurationProvider(invalid)
        )
        self.assert_rejected(outcome, "configuration_invalid:ValueError")

        invalid = replace(
            self.access_configuration,
            reservation_lease_seconds=0,
        )
        outcome = self.process(
            configuration_provider=ConfigurationProvider(invalid)
        )
        self.assert_rejected(outcome, "configuration_invalid:ValueError")

    def test_every_request_configuration_binding_is_checked(self) -> None:
        cases = (
            ("system_config_digest", fixed(b"wrong-config"), "configuration_digest_mismatch"),
            ("ctx", fixed(b"wrong-ctx"), "configuration_ctx_mismatch"),
            ("epoch", 92, "configuration_epoch_mismatch"),
            ("target_fgs_id", fixed(b"wrong-fgs"), "target_fgs_mismatch"),
            ("fgs_auth_key_id", fixed(b"wrong-fgs-key"), "fgs_auth_key_mismatch"),
            ("serving_context_digest", fixed(b"wrong-serving"), "serving_context_mismatch"),
            ("authorization_digest", fixed(b"wrong-authz"), "authorization_mismatch"),
        )
        for field, value, failure in cases:
            with self.subTest(field=field):
                request = replace(self.request, **{field: value})
                provider = ConfigurationProvider(
                    self.access_configuration,
                    return_for_any_digest=True,
                )
                self.assert_rejected(
                    self.process(request, configuration_provider=provider),
                    failure,
                )

    def test_suite_and_proof_suite_must_be_configuration_authorized(self) -> None:
        configuration = replace(
            self.access_configuration,
            allowed_suite_ids=(1,),
        )
        self.assert_rejected(
            self.process(
                configuration_provider=ConfigurationProvider(configuration)
            ),
            "access_suite_not_authorized",
        )
        configuration = replace(
            self.access_configuration,
            allowed_proof_suite_ids=(1,),
        )
        self.assert_rejected(
            self.process(
                configuration_provider=ConfigurationProvider(configuration)
            ),
            "proof_suite_not_authorized",
        )

    def test_clock_configuration_and_client_freshness_boundaries(self) -> None:
        outcome = self.process(clock=FixedClock(broken=True))
        self.assert_rejected(outcome, "clock_backend:OSError")
        outcome = self.process(clock=FixedClock(True))
        self.assert_rejected(outcome, "clock_backend:TypeError")

        inactive = replace(self.access_configuration, valid_until=NOW)
        self.assert_rejected(
            self.process(
                configuration_provider=ConfigurationProvider(inactive)
            ),
            "configuration_inactive",
        )
        stale = replace(
            self.request,
            client_time=NOW
            - self.access_configuration.freshness_window_seconds
            - 1,
        )
        self.assert_rejected(self.process(stale), "client_time_stale")
        future = replace(
            self.request,
            client_time=NOW
            + self.access_configuration.maximum_clock_skew_seconds
            + 1,
        )
        self.assert_rejected(self.process(future), "client_time_in_future")

    def test_zero_nonces_reject(self) -> None:
        # This is deliberately only a structural/sentinel check.  A receiver
        # cannot prove the sender's RNG entropy from one encoded request.
        self.assert_rejected(
            self.process(replace(self.request, ue_nonce=bytes(32))),
            "ue_nonce_zero",
        )
        self.assert_rejected(
            self.process(replace(self.request, attempt_nonce=bytes(16))),
            "attempt_nonce_zero",
        )

    def test_channel_policy_and_exporter_backend_fail_closed(self) -> None:
        none_request = replace(
            self.request,
            channel_binding_mode=ChannelBindingMode.NONE,
            channel_binding_digest=bytes(32),
        )
        self.assert_rejected(
            self.process(none_request),
            "channel_binding_required",
        )

        none_only = replace(
            self.access_configuration,
            channel_binding_policy=ChannelBindingPolicyV2.NONE_ONLY,
        )
        self.assert_rejected(
            self.process(
                configuration_provider=ConfigurationProvider(none_only)
            ),
            "channel_binding_mode_not_authorized",
        )
        self.assert_rejected(
            self.process(channel_binding_verifier=None),
            "channel_binding_backend_unavailable",
        )
        invalid = ChannelBindingVerifier(fixed(b"other-exporter"))
        self.assert_rejected(
            self.process(channel_binding_verifier=invalid),
            "channel_binding_invalid",
        )
        broken = ChannelBindingVerifier(fixed(b"exporter"))
        broken.broken = True
        self.assert_rejected(
            self.process(channel_binding_verifier=broken),
            "channel_binding_backend:RuntimeError",
        )

    def test_stable_verify_ticket_rejects_signature_and_key_binding(self) -> None:
        corrupted = bytearray(self.ticket.encode())
        corrupted[-1] ^= 1
        request = replace(self.request, ticket=bytes(corrupted))
        self.assert_rejected(self.process(request), "verify_ticket_rejected")

        wrong_issuer_configuration = replace(
            self.access_configuration,
            issuer_verification_key_id=fixed(b"different-issuer-key"),
        )
        self.assert_rejected(
            self.process(
                configuration_provider=ConfigurationProvider(
                    wrong_issuer_configuration
                )
            ),
            "ticket_issuer_key_mismatch",
        )

    def test_verify_ticket_boundary_exceptions_and_invalid_output_fail_closed(self) -> None:
        class BrokenTicketVerifier:
            def verify(self, canonical_ticket: bytes, *, now: int):
                raise RuntimeError("ticket backend failed")

        self.assert_rejected(
            self.process(ticket_verifier=BrokenTicketVerifier()),
            "verify_ticket_backend:RuntimeError",
        )

        class RejectingTicketVerifier:
            def verify(self, canonical_ticket: bytes, *, now: int):
                return None

        self.assert_rejected(
            self.process(ticket_verifier=RejectingTicketVerifier()),
            "verify_ticket_rejected",
        )

        class MismatchedConfigurationTicketVerifier:
            def verify(self, canonical_ticket: bytes, *, now: int):
                verified = self_delegate.verify(canonical_ticket, now=now)
                assert verified is not None
                return replace(
                    verified,
                    system_config_digest=fixed(b"other-system-configuration"),
                )

        self_delegate = self.ticket_verifier
        self.assert_rejected(
            self.process(ticket_verifier=MismatchedConfigurationTicketVerifier()),
            "ticket_configuration_mismatch",
        )

    def test_revocation_query_generation_validity_and_flags_fail_closed(self) -> None:
        cases = (
            ({"query_digest": fixed(b"wrong-query")}, "revocation_query_mismatch"),
            ({"generation": 9}, "revocation_generation_stale"),
            ({"valid_until": NOW}, "revocation_snapshot_inactive"),
            ({"configuration_revoked": True}, "revoked"),
            ({"fgs_key_revoked": True}, "revoked"),
            ({"issuer_key_revoked": True}, "revoked"),
            ({"ticket_revoked": True}, "revoked"),
            ({"serial_revoked": True}, "revoked"),
            ({"holder_revoked": True}, "revoked"),
        )
        for changes, failure in cases:
            with self.subTest(changes=changes):
                self.assert_rejected(
                    self.process(
                        revocation_provider=RevocationProvider(**changes)
                    ),
                    failure,
                )
        broken = RevocationProvider()
        broken.broken = True
        self.assert_rejected(
            self.process(revocation_provider=broken),
            "revocation_backend:OSError",
        )

    def test_nizk_kem_and_admission_boundaries_require_explicit_true(self) -> None:
        proof = AccessNIZKTestBackend(result=1)
        self.assert_rejected(
            self.process(access_nizk_backend=proof),
            "access_nizk_invalid",
        )
        proof = AccessNIZKTestBackend(broken=True)
        self.assert_rejected(
            self.process(access_nizk_backend=proof),
            "access_nizk_backend:RuntimeError",
        )
        proof = AccessNIZKTestBackend()
        proof.proof_suite_id = 1
        self.assert_rejected(
            self.process(access_nizk_backend=proof),
            "access_nizk_backend_suite_mismatch",
        )

        kem = KEMTestBackend(result=1)
        self.assert_rejected(
            self.process(kem_backend=kem),
            "ue_kem_public_key_invalid",
        )
        kem = KEMTestBackend(broken=True)
        self.assert_rejected(
            self.process(kem_backend=kem),
            "kem_backend:RuntimeError",
        )
        kem = KEMTestBackend()
        kem.suite_id = 1
        self.assert_rejected(
            self.process(kem_backend=kem),
            "kem_backend_suite_mismatch",
        )

        self.assert_rejected(
            self.process(admission_policy=AdmissionPolicy(result=1)),
            "admission_rejected",
        )
        self.assert_rejected(
            self.process(admission_policy=AdmissionPolicy(broken=True)),
            "admission_backend:RuntimeError",
        )

    def test_fail_fast_order_skips_later_expensive_backends(self) -> None:
        revocation = RevocationProvider(ticket_revoked=True)
        proof = AccessNIZKTestBackend()
        kem = KEMTestBackend()
        admission = AdmissionPolicy()
        outcome = self.process(
            revocation_provider=revocation,
            access_nizk_backend=proof,
            kem_backend=kem,
            admission_policy=admission,
        )
        self.assert_rejected(outcome, "revoked")
        self.assertEqual(revocation.calls, 1)
        self.assertEqual(proof.calls, 0)
        self.assertEqual(kem.calls, 0)
        self.assertEqual(admission.calls, 0)


if __name__ == "__main__":
    unittest.main()
