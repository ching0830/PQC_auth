from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.access import (
    REFERENCE_SUITE_ID,
    decode_access_accept,
    derive_response_digest,
    encode_access_accept,
)
from pq_sat_auth.v2.activation import FGSActivationProcessorV2
from pq_sat_auth.v2.replay import GrantStateV2
from pq_sat_auth.v2.ue import (
    FGSVerificationKeyQueryV2,
    FGSVerificationKeySnapshotV2,
    PRODUCTION_READY,
    UEAccessAcceptProcessorV2,
    UEAccessAttemptStateV2,
    UEResponseDispositionV2,
    ue_access_accept_processor_manifest,
)
from tests.system.test_pq_sat_auth_activation_v2 import (
    ActivationKeySchedule,
    ActivationRevocationProvider,
)
from tests.system.test_pq_sat_auth_grant_v2 import (
    FGSAuthenticationTestBackend,
    FGSGrantFixture,
    GrantClock,
    KeyScheduleTestBackend,
)
from tests.system.test_pq_sat_auth_processor_v2 import (
    ConfigurationProvider,
    NOW,
    fixed,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_ue_accept_v0_2.json"
FGS_TEST_KEY = b"test-only-fgs-private-key-handle"
UE_TEST_KEM_SECRET = b"test-only-ephemeral-kem-secret-key"


class UEKEMTestBackend:
    suite_id = REFERENCE_SUITE_ID
    production_ready = False

    def __init__(self) -> None:
        self.decapsulation_output: object | None = None
        self.broken = False
        self.decapsulation_calls = 0
        self._lock = threading.Lock()

    def validate_public_key(self, public_key: bytes) -> bool:
        raise NotImplementedError

    def encapsulate(self, public_key: bytes):
        raise NotImplementedError

    def decapsulate(self, secret_key: bytes, ciphertext: bytes):
        with self._lock:
            self.decapsulation_calls += 1
        if self.broken:
            raise RuntimeError("UE KEM decapsulation failed")
        if self.decapsulation_output is not None:
            return self.decapsulation_output
        if secret_key != UE_TEST_KEM_SECRET:
            raise ValueError("unexpected UE KEM secret key")
        if ciphertext != b"test-only-kem-ciphertext":
            raise ValueError("unexpected KEM ciphertext")
        return fixed(b"shared-secret")


class UEAuthenticationTestBackend(FGSAuthenticationTestBackend):
    def __init__(self) -> None:
        super().__init__()
        self.verification_result: object | None = None
        self.broken_verify = False
        self.verification_calls = 0

    def verify(
        self,
        verification_key: object,
        message: bytes,
        authenticator: bytes,
    ):
        self.verification_calls += 1
        if self.broken_verify:
            raise RuntimeError("FGS authentication verification failed")
        if self.verification_result is not None:
            return self.verification_result
        return super().verify(verification_key, message, authenticator)


class UEKeyScheduleTestBackend(KeyScheduleTestBackend):
    def __init__(self) -> None:
        super().__init__()
        self.server_verification_result: object | None = None
        self.broken_server_verify = False
        self.broken_client_finished = False
        self.client_finished_output: object | None = None
        self.server_verification_calls = 0

    def verify_server_finished(
        self,
        key: bytes,
        transcript_digest: bytes,
        fgs_authenticator_digest: bytes,
        confirmation: bytes,
    ):
        self.server_verification_calls += 1
        if self.broken_server_verify:
            raise RuntimeError("server Finished verification failed")
        if self.server_verification_result is not None:
            return self.server_verification_result
        return super().verify_server_finished(
            key,
            transcript_digest,
            fgs_authenticator_digest,
            confirmation,
        )

    def client_finished(self, key: bytes, response_digest: bytes):
        if self.broken_client_finished:
            raise RuntimeError("client Finished generation failed")
        if self.client_finished_output is not None:
            return self.client_finished_output
        return super().client_finished(key, response_digest)


class FGSKeyProvider:
    def __init__(self) -> None:
        self.query_digest: bytes | None = None
        self.valid_from = NOW - 1_000
        self.valid_until = NOW + 1_000
        self.revoked: object = False
        self.verification_key: object = FGS_TEST_KEY
        self.wrong_type = False
        self.broken = False
        self.calls = 0
        self.last_query: FGSVerificationKeyQueryV2 | None = None

    def resolve(self, query: FGSVerificationKeyQueryV2):
        self.calls += 1
        self.last_query = query
        if self.broken:
            raise OSError("FGS key service unavailable")
        if self.wrong_type:
            return object()
        return FGSVerificationKeySnapshotV2(
            query_digest=(
                query.digest if self.query_digest is None else self.query_digest
            ),
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            revoked=self.revoked,  # type: ignore[arg-type]
            verification_key=self.verification_key,
        )


class UEAccessAcceptFixture(FGSGrantFixture):
    def setUp(self) -> None:
        super().setUp()
        grant = self.grant_processor().process(self.validated)
        self.assertTrue(grant.accepted, grant.failures)
        assert grant.response_bytes is not None
        assert grant.record is not None
        self.response_bytes = grant.response_bytes
        self.response = decode_access_accept(self.response_bytes)
        self.grant_record = grant.record
        self.attempt_state = UEAccessAttemptStateV2(
            request_bytes=self.validated.request_bytes,
            configuration=self.validated.configuration,
            request_digest=self.validated.request_digest,
            attempt_id=self.validated.attempt_id,
            ticket_expires_at=self.validated.ticket.expires_at,
            created_at=self.validated.request.client_time,
            ue_kem_secret_key=UE_TEST_KEM_SECRET,
        )
        self.ue_clock = GrantClock()
        self.ue_configuration = ConfigurationProvider(
            self.validated.configuration
        )
        self.fgs_keys = FGSKeyProvider()
        self.ue_kem = UEKEMTestBackend()
        self.ue_auth = UEAuthenticationTestBackend()
        self.ue_kdf = UEKeyScheduleTestBackend()

    def ue_processor(self, **overrides: object) -> UEAccessAcceptProcessorV2:
        arguments = {
            "configuration_provider": self.ue_configuration,
            "fgs_key_provider": self.fgs_keys,
            "clock": self.ue_clock,
            "kem_backend": self.ue_kem,
            "authentication_backend": self.ue_auth,
            "key_schedule_backend": self.ue_kdf,
        }
        arguments.update(overrides)
        return UEAccessAcceptProcessorV2(**arguments)  # type: ignore[arg-type]

    def assert_rejected(self, result, prefix: str) -> None:
        self.assertFalse(result.accepted)
        self.assertIs(result.disposition, UEResponseDispositionV2.REJECTED)
        self.assertIsNone(result.response)
        self.assertIsNone(result.session)
        self.assertTrue(result.failures[0].startswith(prefix), result.failures)


class UEAccessAcceptPositiveTests(UEAccessAcceptFixture):
    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            ue_access_accept_processor_manifest(),
        )

    def test_honest_m2_produces_exact_activation_and_matching_keys(self) -> None:
        result = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assertTrue(result.accepted, result.failures)
        self.assertIs(result.disposition, UEResponseDispositionV2.ACCEPTED)
        self.assertEqual(result.response, self.response)
        self.assertIsNotNone(result.session)
        assert result.session is not None
        assert self.recovery.last_state is not None
        self.assertEqual(
            result.session.application_key,
            self.recovery.last_state.application_key,
        )
        self.assertEqual(
            result.session.exporter_key,
            self.recovery.last_state.exporter_key,
        )
        self.assertEqual(
            result.session.response_digest,
            derive_response_digest(self.response),
        )
        self.assertEqual(
            result.session.activation.response_digest,
            result.session.response_digest,
        )
        self.assertEqual(self.ue_auth.verification_calls, 1)
        self.assertEqual(self.ue_kem.decapsulation_calls, 1)
        self.assertEqual(self.ue_kdf.derive_calls, 1)
        self.assertEqual(self.ue_kdf.server_verification_calls, 1)
        self.assertFalse(PRODUCTION_READY)
        self.assertFalse(self.ue_processor().production_ready)

        activation = FGSActivationProcessorV2(
            replay_store=self.store,
            clock=GrantClock(),
            revocation_provider=ActivationRevocationProvider(
                self.grant_record.revocation_generation
            ),
            key_schedule_backend=ActivationKeySchedule(),
            recovery_backend=self.recovery,
        ).process(result.session.activation_bytes)
        self.assertTrue(activation.accepted, activation.failures)
        assert activation.record is not None
        self.assertIs(activation.record.state, GrantStateV2.CONSUMED_ACTIVE)

    def test_exact_response_retry_is_deterministic_and_stateless(self) -> None:
        processor = self.ue_processor()
        first = processor.process(self.response_bytes, self.attempt_state)
        second = processor.process(self.response_bytes, self.attempt_state)
        self.assertTrue(first.accepted, first.failures)
        self.assertTrue(second.accepted, second.failures)
        self.assertEqual(second.response, first.response)
        self.assertEqual(second.session, first.session)
        self.assertEqual(self.ue_kem.decapsulation_calls, 2)

    def test_accepted_session_rejects_mismatched_activation_identity(self) -> None:
        result = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assertTrue(result.accepted, result.failures)
        assert result.session is not None
        for activation in (
            replace(result.session.activation, suite_id=7),
            replace(
                result.session.activation,
                response_digest=fixed(b"wrong-response-digest"),
            ),
        ):
            with self.subTest(activation=activation):
                changed = replace(result.session, activation=activation)
                with self.assertRaisesRegex(
                    ValueError,
                    "activation and accepted session differ",
                ):
                    changed.validate()

    def test_parallel_processing_has_identical_session_outputs(self) -> None:
        processor = self.ue_processor()
        workers = 12
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return processor.process(self.response_bytes, self.attempt_state)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(invoke, range(workers)))
        self.assertTrue(all(result.accepted for result in outcomes))
        sessions = [result.session for result in outcomes]
        self.assertTrue(all(session == sessions[0] for session in sessions))

    def test_fgs_key_query_has_frozen_encoding_and_identity(self) -> None:
        result = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assertTrue(result.accepted, result.failures)
        query = self.fgs_keys.last_query
        self.assertIsNotNone(query)
        assert query is not None
        self.assertEqual(len(query.encode()), 138)
        self.assertEqual(
            query.digest.hex(),
            "e7b65e22e13048cf69c0adc80e911e35"
            "0ebf3a20968461713cf655036754edce",
        )
        self.assertEqual(query.fgs_id, self.validated.request.target_fgs_id)
        self.assertEqual(
            query.fgs_auth_key_id,
            self.validated.request.fgs_auth_key_id,
        )


class UEAccessAcceptBoundaryTests(UEAccessAcceptFixture):
    def test_malformed_response_rejects_before_any_backend(self) -> None:
        for encoded in (self.response_bytes[:-1], self.response_bytes + b"\x00"):
            with self.subTest(length=len(encoded)):
                result = self.ue_processor().process(
                    encoded,
                    self.attempt_state,
                )
                self.assert_rejected(result, "response_encoding:")
        self.assertEqual(self.ue_configuration.calls, 0)
        self.assertEqual(self.fgs_keys.calls, 0)
        self.assertEqual(self.ue_auth.verification_calls, 0)
        self.assertEqual(self.ue_kem.decapsulation_calls, 0)

    def test_wallet_request_ticket_configuration_and_secret_are_bound(self) -> None:
        cases = (
            replace(
                self.attempt_state,
                request_bytes=self.attempt_state.request_bytes + b"\x00",
            ),
            replace(
                self.attempt_state,
                configuration=replace(
                    self.attempt_state.configuration,
                    acceptance_domain_digest=fixed(b"wrong-domain"),
                ),
            ),
            replace(
                self.attempt_state,
                ticket_expires_at=self.attempt_state.created_at,
            ),
            replace(
                self.attempt_state,
                request_digest=fixed(b"wrong-wallet-request"),
            ),
            replace(
                self.attempt_state,
                attempt_id=fixed(b"wrong-wallet-attempt"),
            ),
        )
        for state in cases:
            with self.subTest(state=state):
                result = self.ue_processor().process(
                    self.response_bytes,
                    state,
                )
                self.assertFalse(result.accepted)
                self.assertIsNone(result.session)

        wrong_secret = replace(
            self.attempt_state,
            ue_kem_secret_key=b"wrong-secret",
        )
        result = self.ue_processor().process(
            self.response_bytes,
            wrong_secret,
        )
        self.assert_rejected(result, "session_keys:")

    def test_response_context_and_attempt_mutations_reject_before_crypto(
        self,
    ) -> None:
        for changed in (
            replace(self.response, fgs_id=fixed(b"wrong-fgs")),
            replace(self.response, request_digest=fixed(b"wrong-request")),
            replace(self.response, attempt_id=fixed(b"wrong-attempt")),
        ):
            with self.subTest(changed=changed):
                result = self.ue_processor().process(
                    encode_access_accept(changed),
                    self.attempt_state,
                )
                self.assert_rejected(result, "response_binding:")
        self.assertEqual(self.fgs_keys.calls, 0)
        self.assertEqual(self.ue_auth.verification_calls, 0)
        self.assertEqual(self.ue_kem.decapsulation_calls, 0)

    def test_current_configuration_is_exact_and_fail_closed(self) -> None:
        missing = self.ue_processor(
            configuration_provider=ConfigurationProvider(None)
        ).process(self.response_bytes, self.attempt_state)
        self.assert_rejected(missing, "configuration_unavailable")

        broken = self.ue_processor(
            configuration_provider=ConfigurationProvider(None, broken=True)
        ).process(self.response_bytes, self.attempt_state)
        self.assert_rejected(broken, "configuration_backend:")

        changed_configuration = replace(
            self.validated.configuration,
            acceptance_domain_digest=fixed(b"changed-domain"),
        )
        changed = self.ue_processor(
            configuration_provider=ConfigurationProvider(
                changed_configuration,
                return_for_any_digest=True,
            )
        ).process(self.response_bytes, self.attempt_state)
        self.assert_rejected(changed, "response_binding:")

    def test_acceptance_time_and_response_lifetimes_are_enforced(self) -> None:
        for value in (
            self.validated.configuration.valid_until,
            self.validated.ticket.expires_at,
            self.response.activation_deadline + 1,
            True,
        ):
            with self.subTest(now=value):
                result = self.ue_processor(clock=GrantClock(value)).process(
                    self.response_bytes,
                    self.attempt_state,
                )
                self.assert_rejected(result, "acceptance_time:")

        broken = self.ue_processor(
            clock=GrantClock(broken=True)
        ).process(self.response_bytes, self.attempt_state)
        self.assert_rejected(broken, "acceptance_time:")

        long_activation = replace(
            self.response,
            activation_deadline=NOW + 100,
        )
        rejected = self.ue_processor().process(
            encode_access_accept(long_activation),
            self.attempt_state,
        )
        self.assert_rejected(rejected, "acceptance_time:")

        long_session = replace(
            self.response,
            session_expiry=NOW + 700,
        )
        rejected = self.ue_processor().process(
            encode_access_accept(long_session),
            self.attempt_state,
        )
        self.assert_rejected(rejected, "acceptance_time:")

    def test_fgs_key_snapshot_is_exact_current_and_nonrevoked(self) -> None:
        variants = (
            ("query_digest", fixed(b"wrong-key-query"), "fgs_key_query_mismatch"),
            ("valid_until", NOW, "fgs_key_inactive"),
            ("revoked", True, "fgs_key_revoked"),
            ("revoked", 1, "fgs_key_snapshot:"),
            ("verification_key", None, "fgs_key_snapshot:"),
        )
        for name, value, prefix in variants:
            provider = FGSKeyProvider()
            setattr(provider, name, value)
            with self.subTest(field=name, value=value):
                result = self.ue_processor(
                    fgs_key_provider=provider
                ).process(self.response_bytes, self.attempt_state)
                self.assert_rejected(result, prefix)

        unavailable = FGSKeyProvider()
        unavailable.wrong_type = True
        result = self.ue_processor(fgs_key_provider=unavailable).process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(result, "fgs_key_unavailable")

        broken = FGSKeyProvider()
        broken.broken = True
        result = self.ue_processor(fgs_key_provider=broken).process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(result, "fgs_key_backend:")

    def test_backend_suite_mismatch_rejects_before_authentication(self) -> None:
        for name, backend in (
            ("kem_backend", UEKEMTestBackend()),
            ("authentication_backend", UEAuthenticationTestBackend()),
            ("key_schedule_backend", UEKeyScheduleTestBackend()),
        ):
            backend.suite_id = 7
            with self.subTest(backend=name):
                result = self.ue_processor(**{name: backend}).process(
                    self.response_bytes,
                    self.attempt_state,
                )
                self.assertFalse(result.accepted)
                self.assertIsNone(result.session)
        self.assertEqual(self.ue_auth.verification_calls, 0)
        self.assertEqual(self.ue_kem.decapsulation_calls, 0)

    def test_fgs_authentication_fails_before_kem_decapsulation(self) -> None:
        tampered = replace(
            self.response,
            fgs_authenticator=b"wrong-authenticator",
        )
        result = self.ue_processor().process(
            encode_access_accept(tampered),
            self.attempt_state,
        )
        self.assert_rejected(result, "fgs_authentication_invalid")
        self.assertEqual(self.ue_kem.decapsulation_calls, 0)

        self.ue_auth.verification_result = 1
        truthy = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(truthy, "fgs_authentication_invalid")
        self.assertEqual(self.ue_kem.decapsulation_calls, 0)

        self.ue_auth.verification_result = None
        self.ue_auth.broken_verify = True
        broken = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(broken, "fgs_authentication:")
        self.assertEqual(self.ue_kem.decapsulation_calls, 0)

    def test_ciphertext_and_session_key_failures_release_no_session(self) -> None:
        tampered = replace(
            self.response,
            kem_ciphertext_to_ue=b"wrong-ciphertext",
        )
        result = self.ue_processor().process(
            encode_access_accept(tampered),
            self.attempt_state,
        )
        self.assert_rejected(result, "fgs_authentication_invalid")
        self.assertEqual(self.ue_kem.decapsulation_calls, 0)

        self.ue_kem.broken = True
        broken = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(broken, "session_keys:")

        self.ue_kem.broken = False
        self.ue_kem.decapsulation_output = object()
        invalid_secret = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(invalid_secret, "session_keys:")

        self.ue_kem.decapsulation_output = None
        self.ue_kdf.wrong_type = True
        wrong_kdf = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(wrong_kdf, "session_keys:")

        self.ue_kdf.wrong_type = False
        self.ue_kdf.broken = True
        broken_kdf = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(broken_kdf, "session_keys:")

    def test_server_and_client_finished_fail_closed(self) -> None:
        wrong_server = replace(
            self.response,
            server_key_confirmation=b"wrong-server-finished",
        )
        result = self.ue_processor().process(
            encode_access_accept(wrong_server),
            self.attempt_state,
        )
        self.assert_rejected(result, "server_finished_invalid")

        self.ue_kdf.server_verification_result = 1
        truthy = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(truthy, "server_finished_invalid")

        self.ue_kdf.server_verification_result = None
        self.ue_kdf.broken_server_verify = True
        broken = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(broken, "server_finished:")

        self.ue_kdf.broken_server_verify = False
        self.ue_kdf.client_finished_output = object()
        invalid_client = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(invalid_client, "activation_output:")

        self.ue_kdf.client_finished_output = None
        self.ue_kdf.broken_client_finished = True
        broken_client = self.ue_processor().process(
            self.response_bytes,
            self.attempt_state,
        )
        self.assert_rejected(broken_client, "activation_output:")


if __name__ == "__main__":
    unittest.main()
