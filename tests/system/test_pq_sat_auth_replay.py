from __future__ import annotations

import hashlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from pq_sat_auth.identities import TicketUseIdentity, derive_use_key
from pq_sat_auth.replay import (
    Consumption,
    IdentityConflict,
    InMemoryLinearizableReplayStore,
    InvalidTransition,
    ReservationNotFound,
    ReserveDisposition,
    TicketUnavailable,
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


class TicketUseIdentityTests(unittest.TestCase):
    def test_use_key_matches_direct_domain_separated_hash(self) -> None:
        item = identity()
        expected = hashlib.shake_256(
            b"PQ-SAT/USE-KEY/v1"
            + item.ctx
            + item.serial
            + item.ticket_digest
        ).digest(32)
        self.assertEqual(item.use_key, expected)
        self.assertEqual(
            derive_use_key(item.ctx, item.serial, item.ticket_digest),
            expected,
        )
        self.assertEqual(
            expected.hex(),
            "ec3f58d96cf215e04a0a4fe14a1d4de93174e8613fc904e632d6e28c0e266841",
        )

    def test_identity_widths_are_strict(self) -> None:
        with self.assertRaises(ValueError):
            TicketUseIdentity(fixed(1, 31), fixed(2, 16), fixed(3))
        with self.assertRaises(ValueError):
            TicketUseIdentity(fixed(1), fixed(2, 15), fixed(3))
        with self.assertRaises(ValueError):
            TicketUseIdentity(fixed(1), fixed(2, 16), fixed(3, 31))


class ReplayStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryLinearizableReplayStore()
        self.identity = identity()
        self.attempt = fixed(4)
        self.transcript = fixed(5)

    def reserve(self):
        return self.store.reserve(
            self.identity,
            attempt_id=self.attempt,
            transcript_digest=self.transcript,
            reserved_at=100,
            lease_deadline=200,
        )

    def commit(self) -> Consumption:
        return self.store.commit(
            self.identity,
            attempt_id=self.attempt,
            transcript_digest=self.transcript,
            session_id=fixed(6),
            response_digest=fixed(7),
            sealed_response=b"sealed-access-accept",
            consumed_at=150,
            retention_deadline=500,
        )

    def test_reserve_commit_and_same_attempt_retry_are_idempotent(self) -> None:
        first = self.reserve()
        self.assertEqual(first.disposition, ReserveDisposition.NEW)

        duplicate = self.reserve()
        self.assertEqual(
            duplicate.disposition,
            ReserveDisposition.EXISTING_RESERVATION,
        )
        self.assertEqual(duplicate.record, first.record)

        consumed = self.commit()
        self.assertEqual(self.commit(), consumed)

        retry = self.reserve()
        self.assertEqual(
            retry.disposition,
            ReserveDisposition.EXISTING_CONSUMPTION,
        )
        self.assertEqual(retry.record, consumed)
        self.assertEqual(len(self.store), 1)

    def test_different_attempt_cannot_reserve_or_change_consumed_ticket(self) -> None:
        self.reserve()
        with self.assertRaises(TicketUnavailable):
            self.store.reserve(
                self.identity,
                attempt_id=fixed(8),
                transcript_digest=fixed(9),
                reserved_at=101,
                lease_deadline=201,
            )
        self.commit()
        with self.assertRaises(TicketUnavailable):
            self.store.reserve(
                self.identity,
                attempt_id=fixed(8),
                transcript_digest=fixed(9),
                reserved_at=102,
                lease_deadline=202,
            )

    def test_commit_requires_exact_reservation(self) -> None:
        with self.assertRaises(ReservationNotFound):
            self.commit()
        self.reserve()
        with self.assertRaises(ReservationNotFound):
            self.store.commit(
                self.identity,
                attempt_id=fixed(8),
                transcript_digest=self.transcript,
                session_id=fixed(6),
                response_digest=fixed(7),
                sealed_response=b"sealed-access-accept",
                consumed_at=150,
                retention_deadline=500,
            )
        self.assertNotIsInstance(self.store.lookup(self.identity), Consumption)

    def test_abort_releases_only_the_exact_uncommitted_attempt(self) -> None:
        self.reserve()
        with self.assertRaises(ReservationNotFound):
            self.store.abort(
                self.identity,
                attempt_id=fixed(8),
                transcript_digest=self.transcript,
            )
        self.store.abort(
            self.identity,
            attempt_id=self.attempt,
            transcript_digest=self.transcript,
        )
        self.assertIsNone(self.store.lookup(self.identity))
        self.assertEqual(len(self.store), 0)
        self.assertEqual(self.reserve().disposition, ReserveDisposition.NEW)

    def test_consumed_ticket_can_never_be_released(self) -> None:
        self.reserve()
        self.commit()
        with self.assertRaises(InvalidTransition):
            self.store.abort(
                self.identity,
                attempt_id=self.attempt,
                transcript_digest=self.transcript,
            )
        self.assertIsInstance(self.store.lookup(self.identity), Consumption)

    def test_serial_and_digest_cross_bindings_fail_closed(self) -> None:
        self.reserve()
        same_serial_different_digest = identity(digest=9)
        same_digest_different_serial = identity(serial=9)
        with self.assertRaises(IdentityConflict):
            self.store.reserve(
                same_serial_different_digest,
                attempt_id=fixed(10),
                transcript_digest=fixed(11),
                reserved_at=100,
                lease_deadline=200,
            )
        with self.assertRaises(IdentityConflict):
            self.store.reserve(
                same_digest_different_serial,
                attempt_id=fixed(10),
                transcript_digest=fixed(11),
                reserved_at=100,
                lease_deadline=200,
            )

    def test_parallel_distinct_attempts_have_one_winner(self) -> None:
        workers = 24
        barrier = threading.Barrier(workers)

        def compete(worker: int) -> ReserveDisposition | None:
            barrier.wait()
            try:
                result = self.store.reserve(
                    self.identity,
                    attempt_id=fixed(worker + 20),
                    transcript_digest=fixed(worker + 80),
                    reserved_at=100,
                    lease_deadline=200,
                )
                return result.disposition
            except TicketUnavailable:
                return None

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(compete, range(workers)))
        self.assertEqual(outcomes.count(ReserveDisposition.NEW), 1)
        self.assertEqual(outcomes.count(None), workers - 1)
        self.assertEqual(len(self.store), 1)

    def test_parallel_same_attempt_is_idempotent(self) -> None:
        workers = 24
        barrier = threading.Barrier(workers)

        def retry(_: int) -> ReserveDisposition:
            barrier.wait()
            return self.reserve().disposition

        with ThreadPoolExecutor(max_workers=workers) as executor:
            outcomes = list(executor.map(retry, range(workers)))
        self.assertEqual(outcomes.count(ReserveDisposition.NEW), 1)
        self.assertEqual(
            outcomes.count(ReserveDisposition.EXISTING_RESERVATION),
            workers - 1,
        )


if __name__ == "__main__":
    unittest.main()
