from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pq_sat_auth.replay import (
    IdentityConflict,
    InvalidTransition,
    ReservationNotFound,
    TicketUnavailable,
)
from pq_sat_auth.v2.access import SessionActivateV2, encode_session_activate
from pq_sat_auth.v2.activation import FGSActivationProcessorV2
from pq_sat_auth.v2.grant import GrantDispositionV2
from pq_sat_auth.v2.replay import (
    ActivateDispositionV2,
    FencedReservationV2,
    GrantRecordV2,
    GrantStateV2,
    ReservationAbortEvidenceV2,
    ReservationV2,
    ReserveDispositionV2,
    derive_reservation_abort_evidence_v2,
    reservation_abort_evidence_digest_v2,
)
from pq_sat_auth.v2.storage.sqlite_replay import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    FGSReplayIntegrityError,
    SQLiteFGSReplayStoreV2,
    decode_replay_record,
    encode_replay_record,
    sqlite_fgs_replay_manifest,
)
from tests.system.test_pq_sat_auth_activation_v2 import (
    ActivationKeySchedule,
    ActivationRevocationProvider,
)
from tests.system.test_pq_sat_auth_grant_v2 import FGSGrantFixture, GrantClock
from tests.system import test_pq_sat_auth_replay_v2 as replay_reference_tests
from tests.system.test_pq_sat_auth_replay_v2 import fixed, identity


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_fgs_replay_sqlite_v0_2.json"
TEST_KEY = hashlib.sha256(b"test-only-fgs-replay-protection-key").digest()


class ReplayProtectionTestBackend:
    production_ready = False

    def __init__(
        self,
        key: bytes = TEST_KEY,
        *,
        protection_id: str = "TEST-ONLY-XOR-HMAC-SHA256/v1",
    ) -> None:
        self.key = key
        self.protection_id = protection_id
        self.broken_seal = False
        self.broken_open = False
        self.invalid_seal = False
        self.invalid_open = False

    def _stream(self, aad: bytes, length: int) -> bytes:
        return hashlib.shake_256(
            b"TEST-ONLY/FGS-REPLAY-STREAM/" + self.key + aad
        ).digest(length)

    def seal(self, plaintext: bytes, *, aad: bytes) -> bytes:
        if self.broken_seal:
            raise RuntimeError("test replay seal failed")
        if self.invalid_seal:
            return b""  # type: ignore[return-value]
        stream = self._stream(aad, len(plaintext))
        body = bytes(left ^ right for left, right in zip(plaintext, stream))
        tag = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        return tag + body

    def open(self, protected_record: bytes, *, aad: bytes) -> bytes:
        if self.broken_open:
            raise RuntimeError("test replay open failed")
        if self.invalid_open:
            return b""  # type: ignore[return-value]
        if len(protected_record) <= hashlib.sha256().digest_size:
            raise ValueError("test replay record is truncated")
        tag = protected_record[: hashlib.sha256().digest_size]
        body = protected_record[hashlib.sha256().digest_size :]
        expected = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("test replay record authentication failed")
        stream = self._stream(aad, len(body))
        return bytes(left ^ right for left, right in zip(body, stream))


def _reserve_arguments(worker: int = 0) -> dict[str, object]:
    return {
        "attempt_id": fixed(4 + worker),
        "request_digest": fixed(5 + worker),
        "serving_context_digest": fixed(6),
        "reserved_at": 100,
        "lease_deadline": 200,
        "revocation_generation": 7,
    }


def _commit_arguments(worker: int = 0) -> dict[str, object]:
    return {
        "fencing_generation": 1,
        "attempt_id": fixed(4),
        "request_digest": fixed(5),
        "transcript_digest": fixed(20 + worker),
        "session_id": fixed(50 + worker),
        "response_digest": fixed(80 + worker),
        "sealed_response": b"response-" + bytes((worker,)),
        "sealed_session_state": b"state-" + bytes((worker,)),
        "serving_context_digest": fixed(6),
        "fgs_id": fixed(11),
        "revocation_generation": 7,
        "consumed_at": 150,
        "activation_deadline": 250,
        "session_expiry": 500,
        "retention_deadline": 900,
    }


def _sqlite_store(path: str | Path) -> SQLiteFGSReplayStoreV2:
    return SQLiteFGSReplayStoreV2(
        Path(path),
        ReplayProtectionTestBackend(),
        busy_timeout_ms=20_000,
    )


def _reserve_process_worker(
    path: str,
    worker: int,
    same_attempt: bool,
    start,
    output,
) -> None:
    try:
        store = _sqlite_store(path)
        start.wait(10)
        result = store.reserve(
            identity(),
            **_reserve_arguments(0 if same_attempt else worker),
        )
        output.put(("ok", result.disposition.value))
    except Exception as error:
        output.put(("error", type(error).__name__))


def _commit_process_worker(path: str, worker: int, start, output) -> None:
    try:
        store = _sqlite_store(path)
        start.wait(10)
        record = store.commit_grant(identity(), **_commit_arguments(worker))
        output.put(("ok", record.session_id))
    except Exception as error:
        output.put(("error", type(error).__name__))


def _commit_then_exit_worker(path: str) -> None:
    store = _sqlite_store(path)
    store.commit_grant(identity(), **_commit_arguments())
    os._exit(17)


def _activate_process_worker(path: str, start, output) -> None:
    try:
        store = _sqlite_store(path)
        start.wait(10)
        result = store.activate_session(
            identity(),
            attempt_id=fixed(4),
            request_digest=fixed(5),
            session_id=fixed(50),
            response_digest=fixed(80),
            client_confirmation_digest=fixed(12),
            activated_at=200,
        )
        output.put(("ok", result.disposition.value, result.record))
    except Exception as error:
        output.put(("error", type(error).__name__))


class SQLiteReplayFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "fgs-replay.sqlite3"
        self.protection = ReplayProtectionTestBackend()
        self.store = SQLiteFGSReplayStoreV2(self.path, self.protection)
        self.identity = identity()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reserve(self):
        return self.store.reserve(self.identity, **_reserve_arguments())

    def commit(self):
        return self.store.commit_grant(self.identity, **_commit_arguments())

    @staticmethod
    def abort_evidence(
        reservation: ReservationV2,
        observed_at: int = 201,
    ) -> ReservationAbortEvidenceV2:
        return derive_reservation_abort_evidence_v2(
            reservation,
            observed_at,
        )


class SQLiteReplayCodecTests(SQLiteReplayFixture):
    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            sqlite_fgs_replay_manifest(),
        )

    def test_reservation_and_each_grant_state_round_trip_canonically(self) -> None:
        reservation = ReservationV2(
            self.identity,
            **_reserve_arguments(),
            fencing_generation=1,
        )
        abort_evidence = derive_reservation_abort_evidence_v2(reservation, 201)
        fenced = FencedReservationV2(
            **{
                **reservation.__dict__,
                "fencing_generation": 2,
            },
            fenced_at=201,
            abort_evidence_digest=reservation_abort_evidence_digest_v2(
                abort_evidence
            ),
        )
        grant_fields = _commit_arguments()
        grant_fields.pop("fencing_generation")
        pending = GrantRecordV2(
            state=GrantStateV2.CONSUMED_PENDING_CONFIRM,
            identity=self.identity,
            **grant_fields,
        )
        active = GrantRecordV2(
            **{
                **pending.__dict__,
                "state": GrantStateV2.CONSUMED_ACTIVE,
                "client_confirmation_digest": fixed(12),
                "activated_at": 200,
            }
        )
        expired = GrantRecordV2(
            **{
                **active.__dict__,
                "state": GrantStateV2.CONSUMED_EXPIRED,
                "expired_at": 600,
                "expiry_reason": "測試終止",
            }
        )
        for record in (reservation, fenced, pending, active, expired):
            with self.subTest(record=type(record).__name__, state=getattr(record, "state", None)):
                encoded = encode_replay_record(record)
                self.assertEqual(decode_replay_record(encoded), record)
                self.assertEqual(encode_replay_record(decode_replay_record(encoded)), encoded)
        self.assertEqual(
            hashlib.sha256(encode_replay_record(pending)).hexdigest(),
            "1a934050420d1c6014f29e29eacee4a7bc8b0a3e789cc545136222aa4701094a",
        )

    def test_decoder_rejects_unknown_noncanonical_and_trailing_data(self) -> None:
        encoded = encode_replay_record(
            ReservationV2(
                self.identity,
                **_reserve_arguments(),
                fencing_generation=1,
            )
        )
        parsed = json.loads(encoded)
        cases = []
        changed = dict(parsed)
        changed["unknown"] = 1
        cases.append(json.dumps(changed, sort_keys=True, separators=(",", ":")).encode())
        cases.append(encoded + b" ")
        changed = dict(parsed)
        changed["format"] = "PQ-SAT-FGS-REPLAY-RECORD-v9"
        cases.append(json.dumps(changed, sort_keys=True, separators=(",", ":")).encode())
        for candidate in cases:
            with self.subTest(candidate=candidate[-16:]):
                with self.assertRaises((TypeError, ValueError, FGSReplayIntegrityError)):
                    decode_replay_record(candidate)


class SQLiteReplayLifecycleTests(SQLiteReplayFixture):
    def test_full_lifecycle_is_idempotent_and_restart_recoverable(self) -> None:
        reserved = self.reserve()
        self.assertIs(reserved.disposition, ReserveDispositionV2.NEW)
        restarted = _sqlite_store(self.path)
        retry = restarted.reserve(self.identity, **_reserve_arguments())
        self.assertIs(
            retry.disposition,
            ReserveDispositionV2.EXISTING_RESERVATION,
        )
        pending = restarted.commit_grant(self.identity, **_commit_arguments())
        restarted = _sqlite_store(self.path)
        self.assertEqual(restarted.lookup(self.identity), pending)
        self.assertEqual(restarted.lookup_session(pending.session_id), pending)
        activation = restarted.activate_session(
            self.identity,
            attempt_id=pending.attempt_id,
            request_digest=pending.request_digest,
            session_id=pending.session_id,
            response_digest=pending.response_digest,
            client_confirmation_digest=fixed(12),
            activated_at=200,
        )
        self.assertIs(activation.disposition, ActivateDispositionV2.NEW)
        restarted = _sqlite_store(self.path)
        exact = restarted.activate_session(
            self.identity,
            attempt_id=pending.attempt_id,
            request_digest=pending.request_digest,
            session_id=pending.session_id,
            response_digest=pending.response_digest,
            client_confirmation_digest=fixed(12),
            activated_at=210,
        )
        self.assertIs(
            exact.disposition,
            ActivateDispositionV2.EXISTING_ACTIVE,
        )
        self.assertEqual(exact.record, activation.record)
        expired = restarted.expire(
            self.identity,
            expired_at=501,
            reason="session-expired",
        )
        self.assertIs(expired.state, GrantStateV2.CONSUMED_EXPIRED)
        final = _sqlite_store(self.path).lookup(self.identity)
        self.assertEqual(final, expired)
        self.assertEqual(len(restarted), 1)

    def test_abort_only_releases_exact_reservation(self) -> None:
        result = self.reserve()
        self.assertIsInstance(result.record, ReservationV2)
        reservation = result.record
        self.assertEqual(
            self.store.expired_reservations(observed_at=200),
            (),
        )
        self.assertEqual(
            _sqlite_store(self.path).expired_reservations(observed_at=201),
            (reservation,),
        )
        with self.assertRaises(ReservationNotFound):
            self.store.abort_reservation(
                self.identity,
                fencing_generation=reservation.fencing_generation,
                attempt_id=fixed(40),
                request_digest=fixed(5),
                observed_at=201,
                evidence=self.abort_evidence(reservation),
            )
        fenced = self.store.abort_reservation(
            self.identity,
            fencing_generation=reservation.fencing_generation,
            attempt_id=fixed(4),
            request_digest=fixed(5),
            observed_at=201,
            evidence=self.abort_evidence(reservation),
        )
        self.assertIsInstance(fenced, FencedReservationV2)
        self.assertEqual(
            fenced.fencing_generation,
            reservation.fencing_generation + 1,
        )
        self.assertIsNone(_sqlite_store(self.path).lookup(self.identity))
        self.assertEqual(
            self.store.expired_reservations(observed_at=201),
            (),
        )
        restarted = _sqlite_store(self.path)
        self.assertEqual(restarted.lookup_reservation_fence(self.identity), fenced)
        replacement = self.reserve()
        self.assertIs(replacement.disposition, ReserveDispositionV2.NEW)
        self.assertIsInstance(replacement.record, ReservationV2)
        self.assertEqual(
            replacement.record.fencing_generation,
            fenced.fencing_generation + 1,
        )
        arguments = _commit_arguments()
        arguments["fencing_generation"] = replacement.record.fencing_generation
        self.store.commit_grant(self.identity, **arguments)
        with self.assertRaises(InvalidTransition):
            self.store.abort_reservation(
                self.identity,
                fencing_generation=replacement.record.fencing_generation,
                attempt_id=fixed(4),
                request_digest=fixed(5),
                observed_at=201,
                evidence=self.abort_evidence(replacement.record),
            )

    def test_identity_session_and_transition_conflicts_fail_closed(self) -> None:
        self.reserve()
        with self.assertRaises(TicketUnavailable):
            self.store.reserve(self.identity, **_reserve_arguments(20))
        for conflicting in (identity(digest=9), identity(serial=9)):
            with self.subTest(conflicting=conflicting):
                with self.assertRaises(IdentityConflict):
                    self.store.reserve(conflicting, **_reserve_arguments(30))
        pending = self.commit()
        other = identity(ctx=10, serial=11, digest=12)
        self.store.reserve(other, **_reserve_arguments(40))
        arguments = _commit_arguments(41)
        arguments["attempt_id"] = fixed(44)
        arguments["request_digest"] = fixed(45)
        arguments["session_id"] = pending.session_id
        with self.assertRaises(IdentityConflict):
            self.store.commit_grant(other, **arguments)
        with self.assertRaises(InvalidTransition):
            self.store.activate_session(
                self.identity,
                attempt_id=pending.attempt_id,
                request_digest=pending.request_digest,
                session_id=pending.session_id,
                response_digest=pending.response_digest,
                client_confirmation_digest=fixed(12),
                activated_at=pending.activation_deadline + 1,
            )

    def test_committed_grant_survives_abrupt_process_exit(self) -> None:
        self.reserve()
        context = multiprocessing.get_context("spawn")
        process = context.Process(
            target=_commit_then_exit_worker,
            args=(str(self.path),),
        )
        process.start()
        process.join(timeout=30)
        self.assertEqual(process.exitcode, 17)
        recovered = _sqlite_store(self.path).lookup(self.identity)
        self.assertIsInstance(recovered, GrantRecordV2)
        assert isinstance(recovered, GrantRecordV2)
        self.assertEqual(recovered.sealed_response, b"response-\x00")

    def test_database_identity_protection_and_row_mutations_are_checked(self) -> None:
        self.reserve()
        self.assertEqual(APPLICATION_ID, 0x50515352)
        self.assertEqual(SCHEMA_VERSION, 2)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        mutations = (
            ("state", 2),
            ("lease_deadline", 199),
            ("ctx", fixed(33)),
            ("protected_record", b"corrupt"),
            ("protection_id", "OTHER/v1"),
        )
        for column, value in mutations:
            with self.subTest(column=column):
                path = Path(self.temporary.name) / f"mutation-{column}.sqlite3"
                store = SQLiteFGSReplayStoreV2(path, ReplayProtectionTestBackend())
                store.reserve(self.identity, **_reserve_arguments())
                connection = sqlite3.connect(path)
                try:
                    connection.execute("PRAGMA ignore_check_constraints = ON")
                    connection.execute(
                        f"UPDATE fgs_replay_records SET {column} = ?",
                        (value,),
                    )
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(FGSReplayIntegrityError):
                    store.lookup(self.identity)

        wrong_schema = Path(self.temporary.name) / "wrong-schema.sqlite3"
        SQLiteFGSReplayStoreV2(
            wrong_schema,
            ReplayProtectionTestBackend(),
        )
        connection = sqlite3.connect(wrong_schema)
        try:
            connection.execute("PRAGMA user_version = 1")
        finally:
            connection.close()
        with self.assertRaises(FGSReplayIntegrityError):
            SQLiteFGSReplayStoreV2(
                wrong_schema,
                ReplayProtectionTestBackend(),
            )

        wrong_key = SQLiteFGSReplayStoreV2(
            self.path,
            ReplayProtectionTestBackend(key=fixed(77)),
        )
        with self.assertRaises(FGSReplayIntegrityError):
            wrong_key.lookup(self.identity)

    def test_protection_backend_failures_release_no_transition(self) -> None:
        self.protection.broken_seal = True
        with self.assertRaises(FGSReplayIntegrityError):
            self.reserve()
        self.assertEqual(len(self.store), 0)
        self.protection.broken_seal = False
        self.reserve()
        self.protection.broken_open = True
        with self.assertRaises(FGSReplayIntegrityError):
            self.store.lookup(self.identity)


class SQLiteReplaySemanticParityTests(
    replay_reference_tests.ReplayStoreV2Tests
):
    """Run the complete process-local state contract against SQLite."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = _sqlite_store(
            Path(self.temporary.name) / "semantic-parity.sqlite3"
        )
        self.identity = identity()
        self.attempt = fixed(4)
        self.request = fixed(5)

    def tearDown(self) -> None:
        self.temporary.cleanup()


class SQLiteReplayConcurrencyTests(SQLiteReplayFixture):
    def test_expired_reconciliation_and_stale_commit_have_one_order(self) -> None:
        reserved = self.reserve()
        self.assertIsInstance(reserved.record, ReservationV2)
        reservation = reserved.record
        evidence = derive_reservation_abort_evidence_v2(reservation, 201)
        barrier = threading.Barrier(2)

        def commit():
            barrier.wait()
            try:
                return ("commit", self.commit())
            except Exception as error:
                return ("commit_error", type(error).__name__)

        def reconcile():
            barrier.wait()
            try:
                return (
                    "fence",
                    self.store.abort_reservation(
                        self.identity,
                        fencing_generation=reservation.fencing_generation,
                        attempt_id=reservation.attempt_id,
                        request_digest=reservation.request_digest,
                        observed_at=201,
                        evidence=evidence,
                    ),
                )
            except Exception as error:
                return ("fence_error", type(error).__name__)

        with ThreadPoolExecutor(max_workers=2) as executor:
            commit_future = executor.submit(commit)
            reconcile_future = executor.submit(reconcile)
            results = (
                commit_future.result(timeout=10),
                reconcile_future.result(timeout=10),
            )
        kinds = {result[0] for result in results}
        self.assertIn(
            kinds,
            (
                {"commit", "fence_error"},
                {"commit_error", "fence"},
            ),
        )
        if "commit" in kinds:
            self.assertIsInstance(self.store.lookup(self.identity), GrantRecordV2)
            self.assertIsNone(self.store.lookup_reservation_fence(self.identity))
        else:
            self.assertIsNone(self.store.lookup(self.identity))
            self.assertIsInstance(
                self.store.lookup_reservation_fence(self.identity),
                FencedReservationV2,
            )

    def _run_reserve_processes(self, same_attempt: bool):
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_reserve_process_worker,
                args=(str(self.path), worker, same_attempt, start, output),
            )
            for worker in range(8)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        return results

    def test_parallel_process_same_and_distinct_reservations_linearize(self) -> None:
        same = self._run_reserve_processes(True)
        self.assertEqual(
            sum(item == ("ok", ReserveDispositionV2.NEW.value) for item in same),
            1,
        )
        self.assertEqual(
            sum(
                item
                == ("ok", ReserveDispositionV2.EXISTING_RESERVATION.value)
                for item in same
            ),
            7,
        )

        other_path = Path(self.temporary.name) / "distinct.sqlite3"
        self.path = other_path
        self.store = SQLiteFGSReplayStoreV2(other_path, self.protection)
        distinct = self._run_reserve_processes(False)
        self.assertEqual(
            sum(item == ("ok", ReserveDispositionV2.NEW.value) for item in distinct),
            1,
        )
        self.assertEqual(
            sum(item == ("error", "TicketUnavailable") for item in distinct),
            7,
        )

    def test_parallel_process_competing_grants_have_one_exact_winner(self) -> None:
        self.reserve()
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_commit_process_worker,
                args=(str(self.path), worker, start, output),
            )
            for worker in range(8)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        winners = [item for item in results if item[0] == "ok"]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(
            sum(item == ("error", "InvalidTransition") for item in results),
            7,
        )
        recovered = _sqlite_store(self.path).lookup(self.identity)
        assert isinstance(recovered, GrantRecordV2)
        self.assertEqual(recovered.session_id, winners[0][1])

    def test_parallel_threads_activation_has_one_transition_winner(self) -> None:
        self.reserve()
        pending = self.commit()
        workers = 16
        barrier = threading.Barrier(workers)

        def activate(_: int):
            barrier.wait()
            return self.store.activate_session(
                self.identity,
                attempt_id=pending.attempt_id,
                request_digest=pending.request_digest,
                session_id=pending.session_id,
                response_digest=pending.response_digest,
                client_confirmation_digest=fixed(12),
                activated_at=200,
            )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(activate, range(workers)))
        self.assertEqual(
            sum(
                item.disposition is ActivateDispositionV2.NEW
                for item in results
            ),
            1,
        )
        self.assertTrue(all(item.record == results[0].record for item in results))

    def test_parallel_process_activation_has_one_transition_winner(self) -> None:
        self.reserve()
        self.commit()
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_activate_process_worker,
                args=(str(self.path), start, output),
            )
            for _ in range(8)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(
            sum(
                item[:2] == ("ok", ActivateDispositionV2.NEW.value)
                for item in results
            ),
            1,
        )
        self.assertEqual(
            sum(
                item[:2]
                == ("ok", ActivateDispositionV2.EXISTING_ACTIVE.value)
                for item in results
            ),
            7,
        )
        records = [item[2] for item in results]
        self.assertTrue(all(record == records[0] for record in records))


class SQLiteFGSGrantActivationTests(FGSGrantFixture):
    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "fgs-pipeline.sqlite3"
        self.store = SQLiteFGSReplayStoreV2(
            self.path,
            ReplayProtectionTestBackend(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_grant_retry_and_activation_survive_store_restart(self) -> None:
        grant = self.grant_processor().process(self.validated)
        self.assertTrue(grant.accepted, grant.failures)
        self.assertIs(grant.disposition, GrantDispositionV2.NEW_GRANT)
        assert grant.record is not None
        assert grant.response_bytes is not None
        assert self.recovery.last_state is not None

        restarted = SQLiteFGSReplayStoreV2(
            self.path,
            ReplayProtectionTestBackend(),
        )
        self.store = restarted
        retry = self.grant_processor().process(self.validated)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(retry.disposition, GrantDispositionV2.EXISTING_GRANT)
        self.assertEqual(retry.response_bytes, grant.response_bytes)

        key_schedule = ActivationKeySchedule()
        activation = SessionActivateV2(
            suite_id=self.recovery.last_state.suite_id,
            request_digest=grant.record.request_digest,
            attempt_id=grant.record.attempt_id,
            session_id=grant.record.session_id,
            response_digest=grant.record.response_digest,
            client_key_confirmation=key_schedule.client_finished(
                self.recovery.last_state.client_finished_key,
                grant.record.response_digest,
            ),
        )
        activated = FGSActivationProcessorV2(
            replay_store=restarted,
            clock=GrantClock(),
            revocation_provider=ActivationRevocationProvider(
                grant.record.revocation_generation
            ),
            key_schedule_backend=key_schedule,
            recovery_backend=self.recovery,
        ).process(encode_session_activate(activation))
        self.assertTrue(activated.accepted, activated.failures)
        recovered = SQLiteFGSReplayStoreV2(
            self.path,
            ReplayProtectionTestBackend(),
        ).lookup_session(grant.record.session_id)
        assert recovered is not None
        self.assertIs(recovered.state, GrantStateV2.CONSUMED_ACTIVE)


if __name__ == "__main__":
    unittest.main()
