from __future__ import annotations

import json
import multiprocessing
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.reconciliation import (
    ReconciliationItemDispositionV2,
    ReservationReconciliationCoordinatorV2,
    ReservationReconciliationInvocationV2,
    ReservationReconciliationPlanV2,
    ReservationReconciliationPolicyV2,
)
from pq_sat_auth.v2.reconciliation_audit import (
    ReconciliationAuditIntentV2,
    encode_reconciliation_audit_intent,
)
from pq_sat_auth.v2.reconciliation_lease import (
    LEASE_FORMAT,
    MAX_LEASE_SECONDS,
    LeaseFencedResumableReconciliationRunnerV2,
    ReconciliationExecutionLeasePolicyV2,
    ReconciliationExecutionLeaseV2,
    ReconciliationLeaseAcquireDispositionV2,
    ReconciliationLeaseAcquireResultV2,
    decode_reconciliation_execution_lease,
    encode_reconciliation_execution_lease,
    reconciliation_execution_lease_manifest,
)
from pq_sat_auth.v2.reconciliation_resume import (
    ReconciliationProgressV2,
    ResumableReconciliationDispositionV2,
)
from pq_sat_auth.v2.replay import InMemoryLinearizableReplayStoreV2
from pq_sat_auth.v2.storage.sqlite_reconciliation_audit import (
    ReconciliationAuditJournalConflict,
    ReconciliationAuditJournalIntegrityError,
)
from pq_sat_auth.v2.storage.sqlite_reconciliation_resume import (
    APPLICATION_ID,
    INTENT_AAD,
    SCHEMA_VERSION,
    SQLiteResumableReconciliationJournalV2,
    _INTENT_SCHEMA_SQL,
    _PLAN_SCHEMA_SQL,
    _PROGRESS_SCHEMA_SQL,
    _RECEIPT_SCHEMA_SQL,
)
from tests.system.test_pq_sat_auth_reconciliation_audit_v2 import (
    AuditProtectionTestBackend,
)
from tests.system.test_pq_sat_auth_reconciliation_v2 import (
    DelegatingStore,
    FixedClock,
)
from tests.system.test_pq_sat_auth_replay_v2 import fixed, identity


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    ROOT
    / "manifests"
    / "pq_sat_auth_fgs_reconciliation_execution_lease_v0_2.json"
)


def reserve(store, value: int = 1):
    return store.reserve(
        identity(ctx=value, serial=value + 20, digest=value + 40),
        attempt_id=fixed(value + 60),
        request_digest=fixed(value + 80),
        serving_context_digest=fixed(6),
        reserved_at=100,
        lease_deadline=200,
        revocation_generation=7,
    ).record


def _acquire_process(path: str, owner_value: int, start, output) -> None:
    try:
        journal = SQLiteResumableReconciliationJournalV2(
            path,
            AuditProtectionTestBackend(),
        )
        start.wait(10)
        result = journal.acquire_execution_lease(
            invocation_id=fixed(90),
            owner_id=fixed(owner_value),
            observed_at=100,
            policy=ReconciliationExecutionLeasePolicyV2(10, 2),
        )
        output.put(("ok", result.disposition.value))
    except Exception as error:
        output.put(("error", type(error).__name__))


class LeaseFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "resume.sqlite3"
        self.protection = AuditProtectionTestBackend()
        self.journal = SQLiteResumableReconciliationJournalV2(
            self.path,
            self.protection,
        )
        self.replay = InMemoryLinearizableReplayStoreV2()
        self.reconciliation_clock = FixedClock(250)
        self.lease_clock = FixedClock(100)
        self.policy = ReservationReconciliationPolicyV2(10, 20)
        self.lease_policy = ReconciliationExecutionLeasePolicyV2(10, 2)
        self.invocation = ReservationReconciliationInvocationV2(fixed(90))
        self.intent = ReconciliationAuditIntentV2.create(
            self.invocation,
            self.policy,
        )
        self.coordinator = ReservationReconciliationCoordinatorV2(
            store=self.replay,
            clock=self.reconciliation_clock,
            policy=self.policy,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def begin(self) -> None:
        self.journal.begin_intent(self.intent)

    def acquire(
        self,
        owner: int = 1,
        observed_at: int = 100,
    ):
        return self.journal.acquire_execution_lease(
            invocation_id=self.invocation.invocation_id,
            owner_id=fixed(owner),
            observed_at=observed_at,
            policy=self.lease_policy,
        )

    def prepare_plan(self, count: int = 1) -> ReservationReconciliationPlanV2:
        for value in range(1, count + 1):
            reserve(self.replay, value)
        prepared = self.coordinator.prepare_run(self.invocation)
        assert isinstance(prepared, ReservationReconciliationPlanV2)
        self.begin()
        self.journal.append_plan(prepared)
        return prepared

    def runner(self, owner: int = 1, *, journal=None, lease_clock=None):
        return LeaseFencedResumableReconciliationRunnerV2(
            coordinator=self.coordinator,
            journal=self.journal if journal is None else journal,
            lease_clock=self.lease_clock if lease_clock is None else lease_clock,
            owner_id=fixed(owner),
            lease_policy=self.lease_policy,
        )


class LeaseCodecTests(unittest.TestCase):
    def test_policy_and_lease_are_strict(self) -> None:
        for seconds in (0, MAX_LEASE_SECONDS + 1):
            with self.assertRaises(ValueError):
                ReconciliationExecutionLeasePolicyV2(seconds, 0)
        with self.assertRaises(ValueError):
            ReconciliationExecutionLeasePolicyV2(10, 10)
        with self.assertRaises(TypeError):
            ReconciliationExecutionLeasePolicyV2(True, 0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ReconciliationExecutionLeaseV2(
                fixed(1),
                fixed(2),
                0,
                100,
                110,
                10,
                2,
            )

    def test_canonical_round_trip_and_mutation_rejection(self) -> None:
        lease = ReconciliationExecutionLeaseV2(
            fixed(10),
            fixed(2),
            3,
            100,
            110,
            10,
            2,
        )
        encoded = encode_reconciliation_execution_lease(lease)
        self.assertEqual(decode_reconciliation_execution_lease(encoded), lease)
        self.assertIn(LEASE_FORMAT.encode("ascii"), encoded)
        with self.assertRaises(ValueError):
            decode_reconciliation_execution_lease(encoded + b" ")
        value = json.loads(encoded.decode("ascii"))
        value["invocation_id"] = value["invocation_id"].upper()
        with self.assertRaises(ValueError):
            decode_reconciliation_execution_lease(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )

    def test_manifest_matches_and_keeps_production_claims_false(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            reconciliation_execution_lease_manifest(),
        )
        claims = reconciliation_execution_lease_manifest()["claim_boundary"]
        self.assertTrue(claims["stale_executor_journal_writes_rejected"])
        self.assertFalse(claims["distributed_consensus_lease"])
        self.assertFalse(claims["unique_owner_id_enforced"])
        self.assertFalse(claims["production_clock_instantiated"])
        self.assertFalse(claims["production_ready"])


class SQLiteLeaseTests(LeaseFixture):
    def test_acquire_existing_peer_and_expired_takeover(self) -> None:
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.acquire()
        self.begin()
        first = self.acquire()
        self.assertIs(
            first.disposition,
            ReconciliationLeaseAcquireDispositionV2.NEW,
        )
        exact = self.acquire(observed_at=101)
        self.assertIs(
            exact.disposition,
            ReconciliationLeaseAcquireDispositionV2.EXISTING,
        )
        self.assertEqual(exact.lease, first.lease)
        peer = self.acquire(owner=2, observed_at=109)
        self.assertIs(
            peer.disposition,
            ReconciliationLeaseAcquireDispositionV2.HELD_BY_PEER,
        )
        self.assertIsNone(peer.lease)
        takeover = self.acquire(owner=2, observed_at=110)
        self.assertIs(
            takeover.disposition,
            ReconciliationLeaseAcquireDispositionV2.TAKEOVER,
        )
        assert first.lease is not None and takeover.lease is not None
        self.assertEqual(takeover.lease.lease_generation, 2)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.assert_execution_lease(
                first.lease,
                observed_at=109,
            )
        self.assertEqual(self.journal.lease_count(), 2)

    def test_renewal_rotates_generation_and_rejects_old_token(self) -> None:
        self.begin()
        acquired = self.acquire()
        assert acquired.lease is not None
        renewed = self.journal.renew_execution_lease(
            acquired.lease,
            observed_at=108,
        )
        self.assertEqual(renewed.lease_generation, 2)
        self.assertEqual(renewed.lease_deadline, 118)
        self.journal.assert_execution_lease(renewed, observed_at=109)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.renew_execution_lease(
                acquired.lease,
                observed_at=109,
            )
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.assert_execution_lease(
                renewed,
                observed_at=118,
            )

    def test_policy_conflict_and_clock_rollback_fail_closed(self) -> None:
        self.begin()
        self.acquire(observed_at=100)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.acquire_execution_lease(
                invocation_id=self.invocation.invocation_id,
                owner_id=fixed(1),
                observed_at=101,
                policy=ReconciliationExecutionLeasePolicyV2(11, 2),
            )
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.acquire(observed_at=99)

    def test_progress_and_receipt_writes_require_current_unexpired_token(self) -> None:
        plan = self.prepare_plan()
        first = self.acquire()
        assert first.lease is not None
        item = self.coordinator.reconcile_plan_item(plan, 0)
        progress = ReconciliationProgressV2(plan.invocation_id, 0, item)
        self.journal.append_progress_under_lease(
            progress,
            lease=first.lease,
            observed_at=101,
        )
        takeover = self.acquire(owner=2, observed_at=110)
        assert takeover.lease is not None
        receipt = self.coordinator.finalize_plan(plan, (item,))
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_receipt_under_lease(
                receipt,
                lease=first.lease,
                observed_at=109,
            )
        self.journal.append_receipt_under_lease(
            receipt,
            lease=takeover.lease,
            observed_at=111,
        )
        terminal = self.acquire(owner=3, observed_at=120)
        self.assertIs(
            terminal.disposition,
            ReconciliationLeaseAcquireDispositionV2.TERMINAL,
        )

    def test_cross_process_acquisition_has_one_winner(self) -> None:
        self.begin()
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_acquire_process,
                args=(str(self.path), owner, start, output),
            )
            for owner in (1, 2)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(
            sorted(results),
            [("ok", "held_by_peer"), ("ok", "new")],
        )
        self.assertEqual(self.journal.lease_count(), 1)

    def test_protected_lease_mutation_fails_closed(self) -> None:
        self.begin()
        self.acquire()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE reconciliation_resume_leases "
                "SET protected_lease=zeroblob(length(protected_lease))"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ReconciliationAuditJournalIntegrityError):
            self.journal.load_execution_lease(self.invocation.invocation_id)

    def test_lease_seal_failure_and_extra_schema_fail_closed(self) -> None:
        self.begin()
        self.protection.broken_seal = True
        with self.assertRaises(ReconciliationAuditJournalIntegrityError):
            self.acquire()
        self.protection.broken_seal = False
        self.assertEqual(self.journal.lease_count(), 0)

        extra_path = Path(self.temporary.name) / "extra.sqlite3"
        SQLiteResumableReconciliationJournalV2(
            extra_path,
            AuditProtectionTestBackend(),
        )
        connection = sqlite3.connect(extra_path)
        try:
            connection.execute("CREATE TABLE unexpected(value INTEGER)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ReconciliationAuditJournalIntegrityError):
            SQLiteResumableReconciliationJournalV2(
                extra_path,
                AuditProtectionTestBackend(),
            )

    def test_schema_v1_migration_preserves_existing_intent(self) -> None:
        migration_path = Path(self.temporary.name) / "legacy.sqlite3"
        protection = AuditProtectionTestBackend()
        connection = sqlite3.connect(migration_path, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute("PRAGMA user_version=1")
            for schema in (
                _INTENT_SCHEMA_SQL,
                _PLAN_SCHEMA_SQL,
                _PROGRESS_SCHEMA_SQL,
                _RECEIPT_SCHEMA_SQL,
            ):
                connection.execute(schema)
            plaintext = encode_reconciliation_audit_intent(self.intent)
            protected = protection.seal(
                plaintext,
                aad=INTENT_AAD + self.intent.invocation_id,
            )
            connection.execute(
                "INSERT INTO reconciliation_resume_intents VALUES (?, ?, ?)",
                (
                    self.intent.invocation_id,
                    protection.protection_id,
                    protected,
                ),
            )
        finally:
            connection.close()
        migrated = SQLiteResumableReconciliationJournalV2(
            migration_path,
            AuditProtectionTestBackend(),
        )
        self.assertEqual(
            migrated.load_intent(self.intent.invocation_id),
            self.intent,
        )
        connection = sqlite3.connect(migration_path)
        try:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
        finally:
            connection.close()


class JournalProxy:
    def __init__(self, inner) -> None:
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)


class DropLeasedProgress(JournalProxy):
    def append_progress_under_lease(
        self,
        progress,
        *,
        lease,
        observed_at,
    ):
        del progress, lease, observed_at
        raise OSError("simulated progress commit loss")


class MutatedAcquireJournal(JournalProxy):
    def acquire_execution_lease(self, **arguments):
        result = self.inner.acquire_execution_lease(**arguments)
        assert result.lease is not None
        return ReconciliationLeaseAcquireResultV2(
            result.disposition,
            replace(result.lease, owner_id=fixed(99)),
        )


class LostAcquireAcknowledgement(JournalProxy):
    def acquire_execution_lease(self, **arguments):
        self.inner.acquire_execution_lease(**arguments)
        raise OSError("simulated lease acknowledgement loss")


class LeaseRunnerTests(LeaseFixture):
    def test_happy_path_uses_lease_and_recorded_retry_does_not_reacquire(self) -> None:
        reserve(self.replay)
        result = self.runner().run_once(self.invocation)
        self.assertTrue(result.recorded)
        self.assertEqual(self.journal.lease_count(), 1)
        retry = self.runner(owner=2).run_once(self.invocation)
        self.assertIs(
            retry.disposition,
            ResumableReconciliationDispositionV2.RECORDED_REPLAY,
        )
        self.assertEqual(self.journal.lease_count(), 1)

    def test_live_peer_is_rejected_before_replay_mutation(self) -> None:
        wrapped = DelegatingStore(self.replay)
        coordinator = ReservationReconciliationCoordinatorV2(
            store=wrapped,
            clock=self.reconciliation_clock,
            policy=self.policy,
        )
        self.begin()
        self.acquire(owner=1, observed_at=100)
        runner = LeaseFencedResumableReconciliationRunnerV2(
            coordinator=coordinator,
            journal=self.journal,
            lease_clock=FixedClock(101),
            owner_id=fixed(2),
            lease_policy=self.lease_policy,
        )
        reservation = reserve(self.replay)
        result = runner.run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assertEqual(wrapped.abort_calls, 0)
        self.assertIsNotNone(self.replay.lookup(reservation.identity))

    def test_mutated_acquisition_output_rejects_before_replay_mutation(self) -> None:
        wrapped = DelegatingStore(self.replay)
        coordinator = ReservationReconciliationCoordinatorV2(
            store=wrapped,
            clock=self.reconciliation_clock,
            policy=self.policy,
        )
        reservation = reserve(self.replay)
        runner = LeaseFencedResumableReconciliationRunnerV2(
            coordinator=coordinator,
            journal=MutatedAcquireJournal(self.journal),
            lease_clock=self.lease_clock,
            owner_id=fixed(1),
            lease_policy=self.lease_policy,
        )
        result = runner.run_once(self.invocation)
        self.assertFalse(result.recorded)
        self.assertEqual(wrapped.abort_calls, 0)
        self.assertIsNotNone(self.replay.lookup(reservation.identity))

    def test_lost_acquire_ack_retries_same_owner_without_mutation_loss(self) -> None:
        reservation = reserve(self.replay)
        first = self.runner(
            journal=LostAcquireAcknowledgement(self.journal)
        ).run_once(self.invocation)
        self.assertFalse(first.recorded)
        self.assertIsNotNone(self.replay.lookup(reservation.identity))
        self.assertEqual(self.journal.lease_count(), 1)
        recovered = self.runner(
            lease_clock=FixedClock(101),
        ).run_once(self.invocation)
        self.assertTrue(recovered.recorded)
        self.assertIsNone(self.replay.lookup(reservation.identity))
        self.assertEqual(self.journal.lease_count(), 1)

    def test_expired_takeover_recovers_mutation_without_progress(self) -> None:
        reservation = reserve(self.replay)
        first = self.runner(
            owner=1,
            journal=DropLeasedProgress(self.journal),
        ).run_once(self.invocation)
        self.assertFalse(first.recorded)
        self.assertIsNone(self.replay.lookup(reservation.identity))
        self.assertEqual(self.journal.counts(), (1, 1, 0, 0))
        self.assertEqual(self.journal.lease_count(), 1)

        resumed = self.runner(
            owner=2,
            lease_clock=FixedClock(110),
        ).run_once(self.invocation)
        self.assertTrue(resumed.recorded)
        assert resumed.result is not None
        self.assertIs(
            resumed.result.items[0].disposition,
            ReconciliationItemDispositionV2.FENCED_RECOVERED,
        )
        self.assertEqual(self.journal.lease_count(), 2)

    def test_runner_renews_near_deadline_before_progress(self) -> None:
        class SequenceClock:
            def __init__(self) -> None:
                self.values = iter((100, 108, 108, 108))

            def now(self) -> int:
                return next(self.values)

        reserve(self.replay)
        runner = LeaseFencedResumableReconciliationRunnerV2(
            coordinator=self.coordinator,
            journal=self.journal,
            lease_clock=SequenceClock(),
            owner_id=fixed(1),
            lease_policy=ReconciliationExecutionLeasePolicyV2(10, 3),
        )
        result = runner.run_once(self.invocation)
        self.assertTrue(result.recorded)
        self.assertEqual(self.journal.lease_count(), 2)
        current = self.journal.load_execution_lease(
            self.invocation.invocation_id
        )
        assert current is not None
        self.assertEqual(current.lease_deadline, 118)


if __name__ == "__main__":
    unittest.main()
