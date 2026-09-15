from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.access import (
    SessionActivateV2,
    derive_activation_digest,
    encode_session_activate,
)
from pq_sat_auth.v2.activation import (
    ActivationDispositionV2,
    ActivationRevocationQueryV2,
    ActivationRevocationSnapshotV2,
    FGSActivationProcessorV2,
    fgs_activation_processor_manifest,
)
from pq_sat_auth.v2.replay import (
    ActivateResultV2,
    GrantRecordV2,
    GrantStateV2,
    InMemoryLinearizableReplayStoreV2,
)
from tests.system.test_pq_sat_auth_grant_v2 import (
    FGSGrantFixture,
    GrantClock,
    KeyScheduleTestBackend,
)
from tests.system.test_pq_sat_auth_processor_v2 import NOW, fixed


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_fgs_activation_v0_2.json"


class ActivationRevocationProvider:
    def __init__(self, generation: int) -> None:
        self.generation = generation
        self.effective_at = NOW - 1
        self.valid_until = NOW + 1_000
        self.query_digest: bytes | None = None
        self.configuration_revoked = False
        self.fgs_key_revoked = False
        self.ticket_revoked = False
        self.session_revoked = False
        self.wrong_type = False
        self.broken = False
        self.calls = 0
        self.last_query: ActivationRevocationQueryV2 | None = None
        self._lock = threading.Lock()

    def snapshot(self, query: ActivationRevocationQueryV2):
        with self._lock:
            self.calls += 1
            self.last_query = query
        if self.broken:
            raise OSError("activation revocation unavailable")
        if self.wrong_type:
            return object()
        return ActivationRevocationSnapshotV2(
            query_digest=(
                query.digest if self.query_digest is None else self.query_digest
            ),
            generation=self.generation,
            effective_at=self.effective_at,
            valid_until=self.valid_until,
            configuration_revoked=self.configuration_revoked,
            fgs_key_revoked=self.fgs_key_revoked,
            ticket_revoked=self.ticket_revoked,
            session_revoked=self.session_revoked,
        )


class ActivationKeySchedule(KeyScheduleTestBackend):
    def __init__(self) -> None:
        super().__init__()
        self.verification_result: object | None = None
        self.broken_verify = False
        self.verification_calls = 0
        self._verify_lock = threading.Lock()

    def verify_finished(
        self,
        key: bytes,
        input_digest: bytes,
        confirmation: bytes,
    ):
        with self._verify_lock:
            self.verification_calls += 1
        if self.broken_verify:
            raise RuntimeError("client Finished verification failed")
        if self.verification_result is not None:
            return self.verification_result
        return super().verify_finished(key, input_digest, confirmation)


class ActivationFaultStore(InMemoryLinearizableReplayStoreV2):
    def __init__(self) -> None:
        super().__init__()
        self.mode: str | None = None

    def activate_session(self, *args, **kwargs):
        result = super().activate_session(*args, **kwargs)
        if self.mode == "raise_after_commit":
            raise OSError("simulated lost activation acknowledgement")
        if self.mode == "mutate_output":
            return ActivateResultV2(
                result.disposition,
                replace(result.record, fgs_id=fixed(b"wrong-active-fgs")),
            )
        if self.mode == "wrong_type":
            return object()
        if self.mode == "wrong_disposition":
            return ActivateResultV2(
                disposition=type(result.disposition).NEW,
                record=result.record,
            )
        return result


class FGSActivationFixture(FGSGrantFixture):
    def setUp(self) -> None:
        super().setUp()
        self.store = ActivationFaultStore()
        grant = self.grant_processor().process(self.validated)
        self.assertTrue(grant.accepted, grant.failures)
        assert grant.record is not None
        assert grant.response_bytes is not None
        assert self.recovery.last_state is not None
        self.pending = grant.record
        self.session_state = self.recovery.last_state
        self.activation_clock = GrantClock()
        self.activation_revocation = ActivationRevocationProvider(
            self.pending.revocation_generation
        )
        self.activation_kdf = ActivationKeySchedule()
        self.activation = SessionActivateV2(
            suite_id=self.session_state.suite_id,
            request_digest=self.pending.request_digest,
            attempt_id=self.pending.attempt_id,
            session_id=self.pending.session_id,
            response_digest=self.pending.response_digest,
            client_key_confirmation=self.activation_kdf.client_finished(
                self.session_state.client_finished_key,
                self.pending.response_digest,
            ),
        )
        self.encoded_activation = encode_session_activate(self.activation)

    def activation_processor(
        self,
        **overrides: object,
    ) -> FGSActivationProcessorV2:
        arguments = {
            "replay_store": self.store,
            "clock": self.activation_clock,
            "revocation_provider": self.activation_revocation,
            "key_schedule_backend": self.activation_kdf,
            "recovery_backend": self.recovery,
        }
        arguments.update(overrides)
        return FGSActivationProcessorV2(**arguments)  # type: ignore[arg-type]

    def assert_pending(self) -> None:
        record = self.store.lookup_session(self.pending.session_id)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertIs(record.state, GrantStateV2.CONSUMED_PENDING_CONFIRM)


class FGSActivationPositiveTests(FGSActivationFixture):
    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            fgs_activation_processor_manifest(),
        )

    def test_valid_client_finished_activates_before_releasing_capability(
        self,
    ) -> None:
        result = self.activation_processor().process(self.encoded_activation)
        self.assertTrue(result.accepted, result.failures)
        self.assertIs(result.disposition, ActivationDispositionV2.ACTIVATED)
        self.assertIsNotNone(result.record)
        self.assertIsNotNone(result.capability)
        assert result.record is not None
        assert result.capability is not None
        self.assertIs(result.record.state, GrantStateV2.CONSUMED_ACTIVE)
        self.assertEqual(
            result.record.client_confirmation_digest,
            derive_activation_digest(self.activation),
        )
        self.assertEqual(result.record.activated_at, NOW)
        self.assertEqual(
            self.store.lookup_session(self.pending.session_id),
            result.record,
        )
        self.assertEqual(
            result.capability.application_key,
            self.session_state.application_key,
        )
        self.assertEqual(
            result.capability.exporter_key,
            self.session_state.exporter_key,
        )
        query = self.activation_revocation.last_query
        self.assertIsNotNone(query)
        assert query is not None
        self.assertEqual(query.session_id, self.pending.session_id)
        self.assertEqual(
            query.original_revocation_query_digest,
            self.session_state.revocation_query.digest,
        )

    def test_exact_retry_recovers_the_same_active_capability(self) -> None:
        processor = self.activation_processor()
        first = processor.process(self.encoded_activation)
        retry = processor.process(self.encoded_activation)
        self.assertTrue(first.accepted, first.failures)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(first.disposition, ActivationDispositionV2.ACTIVATED)
        self.assertIs(
            retry.disposition,
            ActivationDispositionV2.ALREADY_ACTIVE,
        )
        self.assertEqual(retry.record, first.record)
        self.assertEqual(retry.capability, first.capability)

    def test_parallel_exact_activation_has_one_transition_winner(self) -> None:
        processor = self.activation_processor()
        workers = 16
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return processor.process(self.encoded_activation)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(invoke, range(workers)))
        self.assertTrue(all(result.accepted for result in outcomes))
        self.assertEqual(
            sum(
                result.disposition is ActivationDispositionV2.ACTIVATED
                for result in outcomes
            ),
            1,
        )
        self.assertEqual(
            sum(
                result.disposition is ActivationDispositionV2.ALREADY_ACTIVE
                for result in outcomes
            ),
            workers - 1,
        )
        capabilities = [result.capability for result in outcomes]
        self.assertTrue(all(item == capabilities[0] for item in capabilities))


class FGSActivationBoundaryTests(FGSActivationFixture):
    def test_noncanonical_unknown_and_cross_bound_activation_reject(self) -> None:
        processor = self.activation_processor()
        cases = (
            self.encoded_activation + b"\x00",
            encode_session_activate(
                replace(self.activation, session_id=fixed(b"unknown-session"))
            ),
            encode_session_activate(
                replace(self.activation, request_digest=fixed(b"wrong-request"))
            ),
        )
        for encoded in cases:
            with self.subTest(encoded=encoded[:12]):
                result = processor.process(encoded)
                self.assertFalse(result.accepted)
                self.assertIsNone(result.capability)
        self.assert_pending()

    def test_invalid_or_non_boolean_client_finished_rejects(self) -> None:
        wrong = encode_session_activate(
            replace(self.activation, client_key_confirmation=b"wrong-finished")
        )
        rejected = self.activation_processor().process(wrong)
        self.assertFalse(rejected.accepted)
        self.assertEqual(rejected.failures, ("client_finished_invalid",))
        self.assert_pending()

        self.activation_kdf.verification_result = 1
        truthy = self.activation_processor().process(self.encoded_activation)
        self.assertFalse(truthy.accepted)
        self.assertEqual(truthy.failures, ("client_finished_invalid",))
        self.assert_pending()

        self.activation_kdf.verification_result = None
        self.activation_kdf.broken_verify = True
        broken = self.activation_processor().process(self.encoded_activation)
        self.assertFalse(broken.accepted)
        self.assertTrue(broken.failures[0].startswith("client_finished_backend:"))
        self.assert_pending()

    def test_deadline_and_active_session_expiry_are_enforced(self) -> None:
        late_clock = GrantClock(self.pending.activation_deadline + 1)
        late = self.activation_processor(clock=late_clock).process(
            self.encoded_activation
        )
        self.assertFalse(late.accepted)
        self.assertEqual(late.failures, ("activation_deadline_expired",))
        self.assertEqual(self.activation_revocation.calls, 0)
        self.assert_pending()

        activated = self.activation_processor().process(self.encoded_activation)
        self.assertTrue(activated.accepted, activated.failures)
        expired_clock = GrantClock(self.pending.session_expiry + 1)
        expired = self.activation_processor(clock=expired_clock).process(
            self.encoded_activation
        )
        self.assertFalse(expired.accepted)
        self.assertEqual(expired.failures, ("active_session_expired",))
        self.assertIsNone(expired.capability)

    def test_revocation_snapshot_is_query_bound_fresh_and_nonrevoked(self) -> None:
        processor = self.activation_processor()
        self.activation_revocation.query_digest = fixed(b"wrong-query")
        mismatch = processor.process(self.encoded_activation)
        self.assertEqual(
            mismatch.failures,
            ("activation_revocation_query_mismatch",),
        )
        self.activation_revocation.query_digest = None
        self.activation_revocation.generation = self.pending.revocation_generation - 1
        stale = processor.process(self.encoded_activation)
        self.assertEqual(
            stale.failures,
            ("activation_revocation_generation_stale",),
        )
        self.activation_revocation.generation = self.pending.revocation_generation
        self.activation_revocation.valid_until = NOW
        inactive = processor.process(self.encoded_activation)
        self.assertEqual(
            inactive.failures,
            ("activation_revocation_snapshot_inactive",),
        )
        self.assert_pending()

    def test_each_activation_revocation_flag_rejects(self) -> None:
        processor = self.activation_processor()
        for name in (
            "configuration_revoked",
            "fgs_key_revoked",
            "ticket_revoked",
            "session_revoked",
        ):
            setattr(self.activation_revocation, name, True)
            with self.subTest(flag=name):
                result = processor.process(self.encoded_activation)
                self.assertFalse(result.accepted)
                self.assertEqual(result.failures, ("activation_revoked",))
                self.assertIsNone(result.capability)
            setattr(self.activation_revocation, name, False)
        self.assert_pending()

    def test_revocation_backend_and_invalid_snapshot_fail_closed(self) -> None:
        self.activation_revocation.broken = True
        broken = self.activation_processor().process(self.encoded_activation)
        self.assertTrue(
            broken.failures[0].startswith("activation_revocation_backend:")
        )
        self.activation_revocation.broken = False
        self.activation_revocation.wrong_type = True
        unavailable = self.activation_processor().process(
            self.encoded_activation
        )
        self.assertEqual(
            unavailable.failures,
            ("activation_revocation_snapshot_unavailable",),
        )
        self.activation_revocation.wrong_type = False
        self.activation_revocation.configuration_revoked = 1
        malformed = self.activation_processor().process(
            self.encoded_activation
        )
        self.assertTrue(
            malformed.failures[0].startswith(
                "activation_revocation_snapshot:"
            )
        )
        self.assert_pending()

    def test_recovered_response_and_secret_state_are_revalidated(self) -> None:
        self.recovery.tamper_recovery = True
        response_tamper = self.activation_processor().process(
            self.encoded_activation
        )
        self.assertTrue(response_tamper.failures[0].startswith("session_recovery:"))
        self.recovery.tamper_recovery = False
        self.recovery.tamper_session_state = True
        state_tamper = self.activation_processor().process(
            self.encoded_activation
        )
        self.assertTrue(state_tamper.failures[0].startswith("session_recovery:"))
        self.assert_pending()

    def test_post_commit_failure_releases_no_capability_and_retry_recovers(
        self,
    ) -> None:
        self.store.mode = "raise_after_commit"
        uncertain = self.activation_processor().process(self.encoded_activation)
        self.assertFalse(uncertain.accepted)
        self.assertIs(
            uncertain.disposition,
            ActivationDispositionV2.COMMIT_UNCERTAIN,
        )
        self.assertIsNone(uncertain.capability)
        active = self.store.lookup_session(self.pending.session_id)
        self.assertIsNotNone(active)
        assert active is not None
        self.assertIs(active.state, GrantStateV2.CONSUMED_ACTIVE)

        self.store.mode = None
        recovered = self.activation_processor().process(self.encoded_activation)
        self.assertTrue(recovered.accepted, recovered.failures)
        self.assertIs(
            recovered.disposition,
            ActivationDispositionV2.ALREADY_ACTIVE,
        )
        self.assertIsNotNone(recovered.capability)

    def test_mutating_or_wrong_type_store_output_is_commit_uncertain(self) -> None:
        for mode in ("mutate_output", "wrong_type", "wrong_disposition"):
            with self.subTest(mode=mode):
                self.store.mode = mode
                result = self.activation_processor().process(
                    self.encoded_activation
                )
                self.assertFalse(result.accepted)
                self.assertIs(
                    result.disposition,
                    ActivationDispositionV2.COMMIT_UNCERTAIN,
                )
                self.assertIsNone(result.capability)
                self.store.mode = None
                recovered = self.activation_processor().process(
                    self.encoded_activation
                )
                self.assertTrue(recovered.accepted, recovered.failures)


if __name__ == "__main__":
    unittest.main()
