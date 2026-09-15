from __future__ import annotations

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from pq_sat_auth.identities import USE_KEY_LABEL, TicketUseIdentity
from pq_sat_auth.replay import (
    IdentityConflict,
    InvalidTransition,
    ReservationNotFound,
    TicketUnavailable,
)
from pq_sat_auth.v2.replay import (
    GrantRecordV2,
    GrantStateV2,
    InMemoryLinearizableReplayStoreV2,
    ReservationAbortEvidenceV2,
    ReservationV2,
    ReserveDispositionV2,
)


def fixed(value: int, size: int = 32) -> bytes:
    return bytes((value,)) * size


def identity(
    *,
    ctx: int = 1,
    serial: int = 2,
    digest: int = 3,
) -> TicketUseIdentity:
    return TicketUseIdentity(
        ctx=fixed(ctx),
        serial=fixed(serial, 16),
        ticket_digest=fixed(digest),
    )


class ReplayStoreV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryLinearizableReplayStoreV2()
        self.identity = identity()
        self.attempt = fixed(4)
        self.request = fixed(5)

    def reserve(self):
        return self.store.reserve(
            self.identity,
            attempt_id=self.attempt,
            request_digest=self.request,
            serving_context_digest=fixed(6),
            reserved_at=100,
            lease_deadline=200,
            revocation_generation=7,
        )

    def commit(self) -> GrantRecordV2:
        return self.store.commit_grant(
            self.identity,
            attempt_id=self.attempt,
            request_digest=self.request,
            transcript_digest=fixed(8),
            session_id=fixed(9),
            response_digest=fixed(10),
            sealed_response=b"exact-access-accept-v2",
            sealed_session_state=b"sealed-kem-and-session-state",
            serving_context_digest=fixed(6),
            fgs_id=fixed(11),
            revocation_generation=7,
            consumed_at=150,
            activation_deadline=250,
            session_expiry=500,
            retention_deadline=900,
        )

    @staticmethod
    def abort_evidence() -> ReservationAbortEvidenceV2:
        return ReservationAbortEvidenceV2(
            no_grant_digest=fixed(80),
            no_publication_digest=fixed(81),
            fencing_digest=fixed(82),
        )

    def test_reserve_commit_and_exact_retry_are_idempotent(self) -> None:
        first = self.reserve()
        self.assertEqual(first.disposition, ReserveDispositionV2.NEW)
        duplicate = self.reserve()
        self.assertEqual(
            duplicate.disposition,
            ReserveDispositionV2.EXISTING_RESERVATION,
        )
        self.assertEqual(duplicate.record, first.record)

        grant = self.commit()
        self.assertEqual(
            grant.state,
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        self.assertEqual(self.commit(), grant)
        retry = self.reserve()
        self.assertEqual(retry.disposition, ReserveDispositionV2.EXISTING_GRANT)
        self.assertEqual(retry.record.sealed_response, grant.sealed_response)
        self.assertEqual(len(self.store), 1)

    def test_different_attempt_and_cross_version_retry_are_rejected(self) -> None:
        self.reserve()
        with self.assertRaises(TicketUnavailable):
            self.store.reserve(
                self.identity,
                attempt_id=fixed(20),
                request_digest=fixed(21),
                serving_context_digest=fixed(6),
                reserved_at=101,
                lease_deadline=201,
                revocation_generation=7,
            )
        self.commit()
        self.assertEqual(USE_KEY_LABEL, b"PQ-SAT/USE-KEY/v1")
        with self.assertRaises(TicketUnavailable):
            self.store.reserve(
                self.identity,
                attempt_id=fixed(30),  # Model of a distinct V1 wire attempt.
                request_digest=fixed(31),
                serving_context_digest=fixed(6),
                reserved_at=102,
                lease_deadline=202,
                revocation_generation=7,
            )

    def test_commit_requires_exact_live_reservation(self) -> None:
        with self.assertRaises(ReservationNotFound):
            self.commit()
        self.reserve()
        with self.assertRaises(ReservationNotFound):
            self.store.commit_grant(
                self.identity,
                attempt_id=fixed(40),
                request_digest=self.request,
                transcript_digest=fixed(8),
                session_id=fixed(9),
                response_digest=fixed(10),
                sealed_response=b"exact-access-accept-v2",
                sealed_session_state=b"sealed-kem-and-session-state",
                serving_context_digest=fixed(6),
                fgs_id=fixed(11),
                revocation_generation=7,
                consumed_at=150,
                activation_deadline=250,
                session_expiry=500,
                retention_deadline=900,
            )
        with self.assertRaises(InvalidTransition):
            self.store.commit_grant(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                transcript_digest=fixed(8),
                session_id=fixed(9),
                response_digest=fixed(10),
                sealed_response=b"exact-access-accept-v2",
                sealed_session_state=b"sealed-kem-and-session-state",
                serving_context_digest=fixed(6),
                fgs_id=fixed(11),
                revocation_generation=7,
                consumed_at=201,
                activation_deadline=250,
                session_expiry=500,
                retention_deadline=900,
            )
        self.assertIsInstance(self.store.lookup(self.identity), ReservationV2)

    def test_commit_may_advance_but_not_rollback_revocation_generation(self) -> None:
        self.reserve()
        advanced = self.store.commit_grant(
            self.identity,
            attempt_id=self.attempt,
            request_digest=self.request,
            transcript_digest=fixed(8),
            session_id=fixed(9),
            response_digest=fixed(10),
            sealed_response=b"exact-access-accept-v2",
            sealed_session_state=b"sealed-kem-and-session-state",
            serving_context_digest=fixed(6),
            fgs_id=fixed(11),
            revocation_generation=8,
            consumed_at=150,
            activation_deadline=250,
            session_expiry=500,
            retention_deadline=900,
        )
        self.assertEqual(advanced.revocation_generation, 8)

        other_store = InMemoryLinearizableReplayStoreV2()
        other_store.reserve(
            self.identity,
            attempt_id=self.attempt,
            request_digest=self.request,
            serving_context_digest=fixed(6),
            reserved_at=100,
            lease_deadline=200,
            revocation_generation=7,
        )
        with self.assertRaises(ReservationNotFound):
            other_store.commit_grant(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                transcript_digest=fixed(8),
                session_id=fixed(9),
                response_digest=fixed(10),
                sealed_response=b"exact-access-accept-v2",
                sealed_session_state=b"sealed-kem-and-session-state",
                serving_context_digest=fixed(6),
                fgs_id=fixed(11),
                revocation_generation=6,
                consumed_at=150,
                activation_deadline=250,
                session_expiry=500,
                retention_deadline=900,
            )

    def test_activation_is_exact_and_idempotent(self) -> None:
        self.reserve()
        pending = self.commit()
        active = self.store.activate(
            self.identity,
            attempt_id=self.attempt,
            request_digest=self.request,
            session_id=pending.session_id,
            response_digest=pending.response_digest,
            client_confirmation_digest=fixed(12),
            activated_at=200,
        )
        self.assertEqual(active.state, GrantStateV2.CONSUMED_ACTIVE)
        retried = self.store.activate(
            self.identity,
            attempt_id=self.attempt,
            request_digest=self.request,
            session_id=pending.session_id,
            response_digest=pending.response_digest,
            client_confirmation_digest=fixed(12),
            activated_at=210,
        )
        self.assertEqual(retried, active)
        self.assertEqual(self.commit(), active)
        with self.assertRaises(InvalidTransition):
            self.store.activate(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                session_id=pending.session_id,
                response_digest=pending.response_digest,
                client_confirmation_digest=fixed(13),
                activated_at=210,
            )

    def test_wrong_session_and_late_confirmation_do_not_activate(self) -> None:
        self.reserve()
        pending = self.commit()
        with self.assertRaises(InvalidTransition):
            self.store.activate(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                session_id=fixed(50),
                response_digest=pending.response_digest,
                client_confirmation_digest=fixed(12),
                activated_at=200,
            )
        with self.assertRaises(InvalidTransition):
            self.store.activate(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                session_id=pending.session_id,
                response_digest=pending.response_digest,
                client_confirmation_digest=fixed(12),
                activated_at=251,
            )
        self.assertEqual(
            self.store.lookup(self.identity).state,  # type: ignore[union-attr]
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )

    def test_pending_and_active_grants_expire_without_becoming_reusable(self) -> None:
        self.reserve()
        self.commit()
        with self.assertRaises(InvalidTransition):
            self.store.expire(
                self.identity,
                expired_at=250,
                reason="activation-timeout",
            )
        expired = self.store.expire(
            self.identity,
            expired_at=251,
            reason="activation-timeout",
        )
        self.assertEqual(expired.state, GrantStateV2.CONSUMED_EXPIRED)
        self.assertEqual(
            self.store.expire(
                self.identity,
                expired_at=300,
                reason="different-retry-reason",
            ),
            expired,
        )
        with self.assertRaises(TicketUnavailable):
            self.store.reserve(
                self.identity,
                attempt_id=fixed(51),
                request_digest=fixed(52),
                serving_context_digest=fixed(6),
                reserved_at=300,
                lease_deadline=400,
                revocation_generation=7,
            )
        with self.assertRaises(InvalidTransition):
            self.store.abort_reservation(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                evidence=self.abort_evidence(),
            )

    def test_early_termination_keeps_ticket_consumed(self) -> None:
        self.reserve()
        pending = self.commit()
        terminated = self.store.terminate(
            self.identity,
            terminated_at=pending.consumed_at,
            reason="operator-termination",
        )
        self.assertEqual(terminated.state, GrantStateV2.CONSUMED_EXPIRED)
        with self.assertRaises(InvalidTransition):
            self.store.activate(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                session_id=pending.session_id,
                response_digest=pending.response_digest,
                client_confirmation_digest=fixed(12),
                activated_at=200,
            )

    def test_abort_requires_exact_uncommitted_reservation_and_evidence(self) -> None:
        self.reserve()
        with self.assertRaises(TypeError):
            self.store.abort_reservation(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                evidence=object(),  # type: ignore[arg-type]
            )
        with self.assertRaises(ReservationNotFound):
            self.store.abort_reservation(
                self.identity,
                attempt_id=fixed(60),
                request_digest=self.request,
                evidence=self.abort_evidence(),
            )
        self.store.abort_reservation(
            self.identity,
            attempt_id=self.attempt,
            request_digest=self.request,
            evidence=self.abort_evidence(),
        )
        self.assertIsNone(self.store.lookup(self.identity))
        self.assertEqual(self.reserve().disposition, ReserveDispositionV2.NEW)

    def test_serial_and_digest_cross_bindings_fail_closed(self) -> None:
        self.reserve()
        for conflicting in (identity(digest=9), identity(serial=9)):
            with self.subTest(identity=conflicting):
                with self.assertRaises(IdentityConflict):
                    self.store.reserve(
                        conflicting,
                        attempt_id=fixed(61),
                        request_digest=fixed(62),
                        serving_context_digest=fixed(6),
                        reserved_at=100,
                        lease_deadline=200,
                        revocation_generation=7,
                    )

    def test_session_identifier_is_unique_across_committed_tickets(self) -> None:
        self.reserve()
        first = self.commit()
        other_identity = identity(ctx=10, serial=11, digest=12)
        self.store.reserve(
            other_identity,
            attempt_id=fixed(13),
            request_digest=fixed(14),
            serving_context_digest=fixed(15),
            reserved_at=100,
            lease_deadline=200,
            revocation_generation=7,
        )
        with self.assertRaises(IdentityConflict):
            self.store.commit_grant(
                other_identity,
                attempt_id=fixed(13),
                request_digest=fixed(14),
                transcript_digest=fixed(16),
                session_id=first.session_id,
                response_digest=fixed(17),
                sealed_response=b"second-access-accept-v2",
                sealed_session_state=b"second-sealed-session-state",
                serving_context_digest=fixed(15),
                fgs_id=fixed(18),
                revocation_generation=7,
                consumed_at=150,
                activation_deadline=250,
                session_expiry=500,
                retention_deadline=900,
            )
        self.assertEqual(self.store.lookup_session(first.session_id), first)
        self.assertIsInstance(self.store.lookup(other_identity), ReservationV2)

    def test_parallel_distinct_attempts_have_one_winner(self) -> None:
        workers = 24
        barrier = threading.Barrier(workers)

        def compete(worker: int) -> ReserveDispositionV2 | None:
            barrier.wait()
            try:
                return self.store.reserve(
                    self.identity,
                    attempt_id=fixed(worker + 20),
                    request_digest=fixed(worker + 80),
                    serving_context_digest=fixed(6),
                    reserved_at=100,
                    lease_deadline=200,
                    revocation_generation=7,
                ).disposition
            except TicketUnavailable:
                return None

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(compete, range(workers)))
        self.assertEqual(outcomes.count(ReserveDispositionV2.NEW), 1)
        self.assertEqual(outcomes.count(None), workers - 1)
        self.assertEqual(len(self.store), 1)

    def test_parallel_same_attempt_is_idempotent(self) -> None:
        workers = 24
        barrier = threading.Barrier(workers)

        def retry(_: int) -> ReserveDispositionV2:
            barrier.wait()
            return self.reserve().disposition

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(retry, range(workers)))
        self.assertEqual(outcomes.count(ReserveDispositionV2.NEW), 1)
        self.assertEqual(
            outcomes.count(ReserveDispositionV2.EXISTING_RESERVATION),
            workers - 1,
        )

    def test_parallel_activation_has_one_state_and_same_retry_result(self) -> None:
        self.reserve()
        pending = self.commit()
        workers = 24
        barrier = threading.Barrier(workers)

        def activate(_: int) -> GrantRecordV2:
            barrier.wait()
            return self.store.activate(
                self.identity,
                attempt_id=self.attempt,
                request_digest=self.request,
                session_id=pending.session_id,
                response_digest=pending.response_digest,
                client_confirmation_digest=fixed(12),
                activated_at=200,
            )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(activate, range(workers)))
        self.assertTrue(all(record == outcomes[0] for record in outcomes))
        self.assertEqual(outcomes[0].state, GrantStateV2.CONSUMED_ACTIVE)

    def test_parallel_different_grants_commit_only_one_response(self) -> None:
        self.reserve()
        workers = 24
        barrier = threading.Barrier(workers)

        def commit(worker: int) -> GrantRecordV2 | None:
            barrier.wait()
            try:
                return self.store.commit_grant(
                    self.identity,
                    attempt_id=self.attempt,
                    request_digest=self.request,
                    transcript_digest=fixed(worker + 20),
                    session_id=fixed(worker + 50),
                    response_digest=fixed(worker + 80),
                    sealed_response=b"response-" + bytes((worker,)),
                    sealed_session_state=b"state-" + bytes((worker,)),
                    serving_context_digest=fixed(6),
                    fgs_id=fixed(11),
                    revocation_generation=7,
                    consumed_at=150,
                    activation_deadline=250,
                    session_expiry=500,
                    retention_deadline=900,
                )
            except InvalidTransition:
                return None

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(commit, range(workers)))
        winners = [record for record in outcomes if record is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(self.store.lookup(self.identity), winners[0])


if __name__ == "__main__":
    unittest.main()
