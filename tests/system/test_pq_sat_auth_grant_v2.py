from __future__ import annotations

import hashlib
import hmac
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
    derive_transcript_digest,
    validate_response_binding,
)
from pq_sat_auth.v2.backends import SessionKeysV2
from pq_sat_auth.v2.grant import (
    PRODUCTION_READY,
    FGSAuthenticationKeyHandleV2,
    FGSGrantProcessorV2,
    GrantDispositionV2,
    PendingSessionStateV2,
    encode_key_schedule_context,
    fgs_grant_processor_manifest,
)
from pq_sat_auth.v2.replay import (
    GrantStateV2,
    InMemoryLinearizableReplayStoreV2,
    ReservationV2,
    ReserveResultV2,
)
from tests.system.test_pq_sat_auth_processor_v2 import (
    FGSPureCheckFixture,
    NOW,
    RevocationProvider,
    fixed,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_fgs_grant_v0_2.json"


class GrantClock:
    def __init__(self, value: object = NOW, *, broken: bool = False) -> None:
        self.value = value
        self.broken = broken
        self.calls = 0
        self._lock = threading.Lock()

    def now(self):
        with self._lock:
            self.calls += 1
        if self.broken:
            raise OSError("grant clock unavailable")
        return self.value


class SequenceGrantClock:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls = 0
        self._lock = threading.Lock()

    def now(self):
        with self._lock:
            self.calls += 1
            if not self.values:
                raise RuntimeError("unexpected extra clock sample")
            return self.values.pop(0)


class GrantKEMTestBackend:
    suite_id = REFERENCE_SUITE_ID
    production_ready = False

    def __init__(self, output: object = None, *, broken: bool = False) -> None:
        self.output = output
        self.broken = broken
        self.calls = 0
        self._lock = threading.Lock()

    def validate_public_key(self, public_key: bytes) -> bool:
        return True

    def encapsulate(self, public_key: bytes):
        with self._lock:
            self.calls += 1
        if self.broken:
            raise RuntimeError("KEM failure")
        if self.output is not None:
            return self.output
        if public_key != b"test-only-ephemeral-kem-public-key":
            raise ValueError("unexpected test public key")
        return b"test-only-kem-ciphertext", fixed(b"shared-secret")

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        if secret_key != b"test-only-ephemeral-kem-secret-key":
            raise ValueError("unexpected test secret key")
        if ciphertext != b"test-only-kem-ciphertext":
            raise ValueError("unexpected test ciphertext")
        return fixed(b"shared-secret")


class FGSAuthenticationTestBackend:
    suite_id = REFERENCE_SUITE_ID
    production_ready = False

    def __init__(self, output: object = None, *, broken: bool = False) -> None:
        self.output = output
        self.broken = broken
        self.calls = 0

    def authenticate(self, signing_key: object, message: bytes):
        self.calls += 1
        if self.broken:
            raise RuntimeError("authentication failure")
        if self.output is not None:
            return self.output
        if not isinstance(signing_key, bytes):
            raise TypeError("test signing key must be bytes")
        return hashlib.sha256(
            b"TEST-ONLY/FGS-AUTH/" + signing_key + message
        ).digest()

    def verify(
        self,
        verification_key: object,
        message: bytes,
        authenticator: bytes,
    ) -> bool:
        if not isinstance(verification_key, bytes):
            return False
        expected = hashlib.sha256(
            b"TEST-ONLY/FGS-AUTH/" + verification_key + message
        ).digest()
        return hmac.compare_digest(expected, authenticator)


class KeyScheduleTestBackend:
    suite_id = REFERENCE_SUITE_ID
    production_ready = False

    def __init__(self, *, wrong_type: bool = False, broken: bool = False) -> None:
        self.wrong_type = wrong_type
        self.broken = broken
        self.derive_calls = 0
        self.finished_calls = 0
        self.last_context = None

    @staticmethod
    def _key(label: bytes, material: bytes) -> bytes:
        return hashlib.sha256(b"TEST-ONLY/KDF/" + label + material).digest()

    def derive_session_keys(
        self,
        shared_secret: bytes,
        transcript_digest: bytes,
        schedule_context: bytes,
    ):
        self.derive_calls += 1
        self.last_context = schedule_context
        if self.broken:
            raise RuntimeError("KDF failure")
        if self.wrong_type:
            return object()
        material = shared_secret + transcript_digest + schedule_context
        return SessionKeysV2(
            server_finished_key=self._key(b"server", material),
            client_finished_key=self._key(b"client", material),
            application_key=self._key(b"application", material),
            exporter_key=self._key(b"exporter", material),
        )

    def server_finished(
        self,
        key: bytes,
        transcript_digest: bytes,
        fgs_authenticator_digest: bytes,
    ) -> bytes:
        self.finished_calls += 1
        return hashlib.sha256(
            b"TEST-ONLY/SERVER-FINISHED/"
            + key
            + transcript_digest
            + fgs_authenticator_digest
        ).digest()

    def client_finished(
        self,
        key: bytes,
        response_digest: bytes,
    ) -> bytes:
        return hashlib.sha256(
            b"TEST-ONLY/CLIENT-FINISHED/" + key + response_digest
        ).digest()

    def verify_server_finished(
        self,
        key: bytes,
        transcript_digest: bytes,
        fgs_authenticator_digest: bytes,
        confirmation: bytes,
    ) -> bool:
        expected = self.server_finished(
            key,
            transcript_digest,
            fgs_authenticator_digest,
        )
        return hmac.compare_digest(expected, confirmation)

    def verify_finished(
        self,
        key: bytes,
        input_digest: bytes,
        confirmation: bytes,
    ) -> bool:
        return confirmation == self.client_finished(key, input_digest)


class SessionIdentifierTestSource:
    def __init__(self, output: object = None) -> None:
        self.output = fixed(b"session-id") if output is None else output
        self.calls = 0
        self._lock = threading.Lock()

    def new_session_id(self):
        with self._lock:
            self.calls += 1
        return self.output


class GrantRecoveryTestBackend:
    production_ready = False

    def __init__(self) -> None:
        self.seal_response_calls = 0
        self.recover_response_calls = 0
        self.seal_session_calls = 0
        self.last_state: PendingSessionStateV2 | None = None
        self._session_states: dict[bytes, PendingSessionStateV2] = {}
        self.tamper_recovery = False
        self.tamper_session_state = False
        self.broken = False

    def seal_response(
        self,
        response: bytes,
        *,
        response_digest: bytes,
    ) -> bytes:
        self.seal_response_calls += 1
        if self.broken:
            raise RuntimeError("response sealing failed")
        return b"TEST-SEALED-RESPONSE/" + response_digest + response

    def recover_response(
        self,
        sealed_response: bytes,
        *,
        response_digest: bytes,
    ) -> bytes:
        self.recover_response_calls += 1
        prefix = b"TEST-SEALED-RESPONSE/" + response_digest
        if not sealed_response.startswith(prefix):
            raise ValueError("sealed response binding mismatch")
        response = sealed_response[len(prefix) :]
        if self.tamper_recovery:
            return response + b"\x00"
        return response

    def seal_session_state(self, state: PendingSessionStateV2) -> bytes:
        self.seal_session_calls += 1
        if self.broken:
            raise RuntimeError("session sealing failed")
        state.validate()
        self.last_state = state
        sealed = b"TEST-SEALED-SESSION/" + hashlib.sha256(
            state.response_digest
            + state.client_finished_key
            + state.application_key
            + state.exporter_key
        ).digest()
        self._session_states[sealed] = state
        return sealed

    def recover_session_state(
        self,
        sealed_session_state: bytes,
        *,
        session_id: bytes,
        response_digest: bytes,
    ) -> PendingSessionStateV2:
        state = self._session_states[sealed_session_state]
        if (
            state.session_id != session_id
            or state.response_digest != response_digest
        ):
            raise ValueError("sealed session state binding mismatch")
        if self.tamper_session_state:
            return replace(
                state,
                system_config_digest=fixed(b"wrong-recovered-config"),
            )
        return state


class CommitFailureStore(InMemoryLinearizableReplayStoreV2):
    def commit_grant(self, *args, **kwargs):
        raise OSError("simulated durable commit failure")


class MutatingReserveOutputStore(InMemoryLinearizableReplayStoreV2):
    def reserve(self, *args, **kwargs):
        result = super().reserve(*args, **kwargs)
        assert isinstance(result.record, ReservationV2)
        return ReserveResultV2(
            result.disposition,
            replace(
                result.record,
                lease_deadline=result.record.lease_deadline + 1,
            ),
        )


class MutatingCommitOutputStore(InMemoryLinearizableReplayStoreV2):
    def commit_grant(self, *args, **kwargs):
        record = super().commit_grant(*args, **kwargs)
        return replace(record, fgs_id=fixed(b"wrong-commit-fgs"))


class FGSGrantFixture(FGSPureCheckFixture):
    def setUp(self) -> None:
        super().setUp()
        pure_result = self.process()
        self.assertTrue(pure_result.accepted, pure_result.failures)
        assert pure_result.validated is not None
        self.validated = pure_result.validated
        self.store = InMemoryLinearizableReplayStoreV2()
        self.grant_clock = GrantClock()
        self.grant_revocation = RevocationProvider()
        self.grant_kem = GrantKEMTestBackend()
        self.grant_auth = FGSAuthenticationTestBackend()
        self.grant_kdf = KeyScheduleTestBackend()
        self.session_ids = SessionIdentifierTestSource()
        self.recovery = GrantRecoveryTestBackend()
        self.authentication_key = FGSAuthenticationKeyHandleV2(
            key_id=self.access_configuration.fgs_auth_key_id,
            private_handle=b"test-only-fgs-private-key-handle",
        )

    def grant_processor(self, **overrides: object) -> FGSGrantProcessorV2:
        arguments = {
            "replay_store": self.store,
            "clock": self.grant_clock,
            "revocation_provider": self.grant_revocation,
            "kem_backend": self.grant_kem,
            "authentication_backend": self.grant_auth,
            "authentication_key": self.authentication_key,
            "key_schedule_backend": self.grant_kdf,
            "session_identifier_source": self.session_ids,
            "recovery_backend": self.recovery,
        }
        arguments.update(overrides)
        return FGSGrantProcessorV2(**arguments)  # type: ignore[arg-type]

    def assert_recovery_required(self, result, prefix: str) -> None:
        self.assertFalse(result.accepted)
        self.assertIs(result.disposition, GrantDispositionV2.RECOVERY_REQUIRED)
        self.assertTrue(result.reservation_held)
        self.assertIsNone(result.response_bytes)
        self.assertTrue(result.failures[0].startswith(prefix), result.failures)


class FGSGrantPositiveTests(FGSGrantFixture):
    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            fgs_grant_processor_manifest(),
        )

    def test_new_grant_is_committed_before_response_is_returned(self) -> None:
        result = self.grant_processor().process(self.validated)
        self.assertTrue(result.accepted, result.failures)
        self.assertIs(result.disposition, GrantDispositionV2.NEW_GRANT)
        self.assertFalse(result.reservation_held)
        self.assertIsNotNone(result.response_bytes)
        self.assertIsNotNone(result.record)
        assert result.response_bytes is not None
        assert result.record is not None
        response = decode_access_accept(result.response_bytes)
        validate_response_binding(
            self.validated.request,
            response,
            use_key=self.validated.identity.use_key,
        )
        self.assertEqual(
            derive_response_digest(response),
            result.record.response_digest,
        )
        self.assertEqual(
            derive_transcript_digest(response),
            result.record.transcript_digest,
        )
        self.assertEqual(
            result.record.state,
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        self.assertEqual(result.record.activation_deadline, NOW + 60)
        self.assertEqual(result.record.session_expiry, NOW + 600)
        self.assertEqual(
            result.record.retention_deadline,
            self.bundle.configuration.expiry_bucket + 310,
        )
        self.assertNotEqual(result.record.sealed_response, result.response_bytes)
        self.assertEqual(self.grant_kem.calls, 1)
        self.assertEqual(self.grant_auth.calls, 1)
        self.assertEqual(self.grant_kdf.derive_calls, 1)
        self.assertEqual(self.grant_kdf.finished_calls, 1)
        self.assertEqual(self.session_ids.calls, 1)
        self.assertEqual(self.grant_revocation.calls, 1)
        self.assertFalse(PRODUCTION_READY)
        self.assertFalse(self.grant_processor().production_ready)
        assert self.recovery.last_state is not None
        self.assertEqual(
            self.grant_kdf.last_context,
            encode_key_schedule_context(
                self.validated,
                session_id=response.session_id,
            ),
        )

    def test_exact_retry_recovers_identical_response_without_second_kem(self) -> None:
        processor = self.grant_processor()
        first = processor.process(self.validated)
        second = processor.process(self.validated)
        self.assertTrue(first.accepted)
        self.assertTrue(second.accepted)
        self.assertIs(second.disposition, GrantDispositionV2.EXISTING_GRANT)
        self.assertEqual(second.response_bytes, first.response_bytes)
        self.assertEqual(second.record, first.record)
        self.assertEqual(self.grant_kem.calls, 1)
        self.assertEqual(self.grant_auth.calls, 1)
        self.assertEqual(self.session_ids.calls, 1)
        self.assertEqual(self.recovery.recover_response_calls, 1)

    def test_newer_nonrevoked_generation_is_recorded_at_commit(self) -> None:
        revocation = RevocationProvider(generation=13)
        result = self.grant_processor(
            revocation_provider=revocation
        ).process(self.validated)
        self.assertTrue(result.accepted, result.failures)
        assert result.record is not None
        self.assertEqual(result.record.revocation_generation, 13)


class FGSGrantBoundaryTests(FGSGrantFixture):
    def test_handoff_mutation_and_staleness_reject_before_reserve(self) -> None:
        changes = (
            replace(
                self.validated,
                request_digest=fixed(b"wrong-request-digest"),
            ),
            replace(
                self.validated,
                revocation_query=replace(
                    self.validated.revocation_query,
                    acceptance_domain_digest=fixed(b"wrong-domain"),
                ),
            ),
            replace(
                self.validated,
                configuration=replace(
                    self.validated.configuration,
                    fgs_id=fixed(b"wrong-fgs"),
                ),
            ),
        )
        for changed in changes:
            with self.subTest(changed=changed):
                store = InMemoryLinearizableReplayStoreV2()
                result = self.grant_processor(
                    replay_store=store
                ).process(changed)
                self.assertFalse(result.accepted)
                self.assertIs(result.disposition, GrantDispositionV2.REJECTED)
                self.assertEqual(len(store), 0)
                self.assertEqual(self.grant_kem.calls, 0)

        stale_clock = GrantClock(
            NOW + self.access_configuration.pure_check_max_age_seconds + 1
        )
        result = self.grant_processor(clock=stale_clock).process(self.validated)
        self.assertFalse(result.accepted)
        self.assertEqual(len(self.store), 0)

    def test_existing_reservation_never_starts_second_grant_worker(self) -> None:
        self.store.reserve(
            self.validated.identity,
            attempt_id=self.validated.attempt_id,
            request_digest=self.validated.request_digest,
            serving_context_digest=(
                self.validated.request.serving_context_digest
            ),
            reserved_at=NOW,
            lease_deadline=NOW + 30,
            revocation_generation=self.validated.revocation_generation,
        )
        result = self.grant_processor().process(self.validated)
        self.assertFalse(result.accepted)
        self.assertIs(
            result.disposition,
            GrantDispositionV2.EXISTING_RESERVATION,
        )
        self.assertTrue(result.reservation_held)
        self.assertEqual(self.grant_kem.calls, 0)

    def test_crypto_or_sealing_failure_leaves_fail_closed_reservation(self) -> None:
        wrong_suite_kem = GrantKEMTestBackend()
        wrong_suite_kem.suite_id = 1
        cases = (
            {"kem_backend": GrantKEMTestBackend(broken=True)},
            {"kem_backend": wrong_suite_kem},
            {
                "authentication_backend": FGSAuthenticationTestBackend(
                    output=b""
                )
            },
            {"key_schedule_backend": KeyScheduleTestBackend(wrong_type=True)},
            {"session_identifier_source": SessionIdentifierTestSource(bytes(32))},
            {
                "authentication_key": FGSAuthenticationKeyHandleV2(
                    key_id=fixed(b"wrong-fgs-auth-key"),
                    private_handle=b"test-only-wrong-key",
                )
            },
        )
        for overrides in cases:
            with self.subTest(overrides=tuple(overrides)):
                store = InMemoryLinearizableReplayStoreV2()
                result = self.grant_processor(
                    replay_store=store,
                    **overrides,
                ).process(self.validated)
                self.assert_recovery_required(result, "grant_build:")
                self.assertIsInstance(
                    store.lookup(self.validated.identity),
                    ReservationV2,
                )

        store = InMemoryLinearizableReplayStoreV2()
        recovery = GrantRecoveryTestBackend()
        recovery.broken = True
        result = self.grant_processor(
            replay_store=store,
            recovery_backend=recovery,
        ).process(self.validated)
        self.assert_recovery_required(result, "grant_build:")

    def test_precommit_revocation_failure_never_returns_m2(self) -> None:
        cases = (
            RevocationProvider(ticket_revoked=True),
            RevocationProvider(generation=11),
            RevocationProvider(query_digest=fixed(b"wrong-query")),
            RevocationProvider(valid_until=NOW),
        )
        for provider in cases:
            with self.subTest(changes=provider.changes):
                store = InMemoryLinearizableReplayStoreV2()
                result = self.grant_processor(
                    replay_store=store,
                    revocation_provider=provider,
                ).process(self.validated)
                self.assert_recovery_required(result, "grant_build:")
                self.assertIsNone(result.response_bytes)
                self.assertIsInstance(
                    store.lookup(self.validated.identity),
                    ReservationV2,
                )

    def test_expired_lease_before_commit_never_returns_m2(self) -> None:
        clock = SequenceGrantClock(NOW, NOW, NOW + 31)
        result = self.grant_processor(clock=clock).process(self.validated)
        self.assert_recovery_required(result, "grant_build:ValueError")
        self.assertEqual(clock.calls, 3)
        self.assertEqual(self.grant_revocation.calls, 0)
        self.assertIsInstance(
            self.store.lookup(self.validated.identity),
            ReservationV2,
        )

    def test_commit_failure_never_returns_uncommitted_response(self) -> None:
        store = CommitFailureStore()
        result = self.grant_processor(replay_store=store).process(self.validated)
        self.assert_recovery_required(result, "commit_backend:OSError")
        self.assertIsInstance(
            store.lookup(self.validated.identity),
            ReservationV2,
        )

    def test_store_output_mutation_is_fail_closed(self) -> None:
        reserve_store = MutatingReserveOutputStore()
        reserve_result = self.grant_processor(
            replay_store=reserve_store
        ).process(self.validated)
        self.assert_recovery_required(
            reserve_result,
            "new_reservation_binding_mismatch",
        )
        self.assertEqual(self.grant_kem.calls, 0)

        commit_store = MutatingCommitOutputStore()
        commit_result = self.grant_processor(
            replay_store=commit_store
        ).process(self.validated)
        self.assert_recovery_required(
            commit_result,
            "commit_backend:ValueError",
        )
        committed = commit_store.lookup(self.validated.identity)
        self.assertIsNotNone(committed)
        self.assertEqual(
            committed.state,  # type: ignore[union-attr]
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        recovered = self.grant_processor(
            replay_store=commit_store
        ).process(self.validated)
        self.assertTrue(recovered.accepted, recovered.failures)
        self.assertIs(
            recovered.disposition,
            GrantDispositionV2.EXISTING_GRANT,
        )

    def test_recovered_response_is_revalidated_and_expired_state_not_reissued(self) -> None:
        processor = self.grant_processor()
        first = processor.process(self.validated)
        self.assertTrue(first.accepted)
        self.recovery.tamper_recovery = True
        rejected = processor.process(self.validated)
        self.assertFalse(rejected.accepted)
        self.assertTrue(rejected.failures[0].startswith("response_recovery:"))

        self.recovery.tamper_recovery = False
        assert first.record is not None
        self.store.expire(
            self.validated.identity,
            expired_at=first.record.activation_deadline + 1,
            reason="activation-timeout",
        )
        expired = processor.process(self.validated)
        self.assertFalse(expired.accepted)
        self.assertIs(
            expired.disposition,
            GrantDispositionV2.EXISTING_EXPIRED,
        )
        self.assertIsNone(expired.response_bytes)

    def test_parallel_same_request_builds_at_most_one_kem_response(self) -> None:
        processor = self.grant_processor()
        workers = 16
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return processor.process(self.validated)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(invoke, range(workers)))
        self.assertEqual(
            sum(
                result.disposition is GrantDispositionV2.NEW_GRANT
                for result in outcomes
            ),
            1,
        )
        self.assertEqual(self.grant_kem.calls, 1)
        responses = [
            result.response_bytes
            for result in outcomes
            if result.response_bytes is not None
        ]
        self.assertTrue(responses)
        self.assertTrue(all(response == responses[0] for response in responses))


if __name__ == "__main__":
    unittest.main()
