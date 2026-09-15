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
    ReconciliationRunDispositionV2,
    ReservationReconciliationCoordinatorV2,
    ReservationReconciliationInvocationV2,
    ReservationReconciliationPlanV2,
    ReservationReconciliationPolicyV2,
)
from pq_sat_auth.v2.reconciliation_audit import ReconciliationAuditIntentV2
from pq_sat_auth.v2.reconciliation_resume import (
    ReconciliationProgressV2,
    ResumableJournaledReservationReconciliationRunnerV2,
    ResumableReconciliationDispositionV2,
    decode_reconciliation_plan,
    decode_reconciliation_progress,
    encode_reconciliation_plan,
    encode_reconciliation_progress,
    reconciliation_resume_manifest,
)
from pq_sat_auth.v2.replay import InMemoryLinearizableReplayStoreV2
from pq_sat_auth.v2.storage.sqlite_reconciliation_audit import (
    ReconciliationAuditJournalConflict,
    ReconciliationAuditJournalIntegrityError,
)
from pq_sat_auth.v2.storage.sqlite_reconciliation_resume import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    SQLiteResumableReconciliationJournalV2,
    sqlite_reconciliation_resume_manifest,
)
from tests.system.test_pq_sat_auth_reconciliation_v2 import (
    AbortFailureStore,
    FixedClock,
)
from tests.system.test_pq_sat_auth_replay_v2 import fixed, identity
from tests.system.test_pq_sat_auth_reconciliation_audit_v2 import (
    AuditProtectionTestBackend,
)


ROOT = Path(__file__).resolve().parents[2]
RESUME_MANIFEST = ROOT / "manifests" / "pq_sat_auth_fgs_reconciliation_resume_v0_2.json"
SQLITE_MANIFEST = ROOT / "manifests" / "pq_sat_auth_fgs_reconciliation_resume_sqlite_v0_2.json"


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


def _begin_resume_intent_process(path: str, start, output) -> None:
    try:
        journal = SQLiteResumableReconciliationJournalV2(
            path,
            AuditProtectionTestBackend(),
        )
        start.wait(10)
        result = journal.begin_intent(
            ReconciliationAuditIntentV2(fixed(90), 10, 20)
        )
        output.put(("ok", result.disposition.value))
    except Exception as error:
        output.put(("error", type(error).__name__))


class ResumeFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "resume.sqlite3"
        self.protection = AuditProtectionTestBackend()
        self.journal = SQLiteResumableReconciliationJournalV2(
            self.path,
            self.protection,
        )
        self.store = InMemoryLinearizableReplayStoreV2()
        self.clock = FixedClock(250)
        self.policy = ReservationReconciliationPolicyV2(10, 20)
        self.invocation = ReservationReconciliationInvocationV2(fixed(90))
        self.coordinator = ReservationReconciliationCoordinatorV2(
            store=self.store,
            clock=self.clock,
            policy=self.policy,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_plan(self, count: int = 1) -> ReservationReconciliationPlanV2:
        for value in range(1, count + 1):
            reserve(self.store, value)
        prepared = self.coordinator.prepare_run(self.invocation)
        assert isinstance(prepared, ReservationReconciliationPlanV2)
        return prepared

    def begin_plan(self, count: int = 1) -> ReservationReconciliationPlanV2:
        plan = self.make_plan(count)
        self.journal.begin_intent(
            ReconciliationAuditIntentV2.create(self.invocation, self.policy)
        )
        self.journal.append_plan(plan)
        return plan

    def runner(self, *, coordinator=None, journal=None):
        return ResumableJournaledReservationReconciliationRunnerV2(
            coordinator=self.coordinator if coordinator is None else coordinator,
            journal=self.journal if journal is None else journal,
        )


class ResumeCodecTests(ResumeFixture):
    def test_plan_and_progress_canonical_round_trip(self) -> None:
        plan = self.make_plan(2)
        encoded_plan = encode_reconciliation_plan(plan)
        self.assertEqual(decode_reconciliation_plan(encoded_plan), plan)
        item = self.coordinator.reconcile_plan_item(plan, 0)
        progress = ReconciliationProgressV2(plan.invocation_id, 0, item)
        encoded_progress = encode_reconciliation_progress(progress)
        self.assertEqual(
            decode_reconciliation_progress(encoded_progress),
            progress,
        )

    def test_codecs_reject_unknown_trailing_uppercase_and_bad_plan_binding(self) -> None:
        plan = self.make_plan()
        encoded = encode_reconciliation_plan(plan)
        with self.assertRaises(ValueError):
            decode_reconciliation_plan(encoded + b" ")
        value = json.loads(encoded.decode("ascii"))
        value["unknown"] = 1
        with self.assertRaises(ValueError):
            decode_reconciliation_plan(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            )
        value.pop("unknown")
        value["invocation_id"] = value["invocation_id"].upper()
        with self.assertRaises(ValueError):
            decode_reconciliation_plan(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            )
        with self.assertRaises(ValueError):
            replace(plan, scan_cutoff=plan.scan_cutoff - 1)
        with self.assertRaises(ValueError):
            replace(plan, candidates=plan.candidates + plan.candidates)

    def test_progress_rejects_wrong_candidate_and_noncanonical_encoding(self) -> None:
        plan = self.make_plan()
        item = self.coordinator.reconcile_plan_item(plan, 0)
        progress = ReconciliationProgressV2(plan.invocation_id, 0, item)
        encoded = encode_reconciliation_progress(progress)
        value = json.loads(encoded.decode("ascii"))
        value["item"]["disposition"] = "unknown"
        with self.assertRaises(ValueError):
            decode_reconciliation_progress(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            )
        with self.assertRaises(ValueError):
            ReconciliationProgressV2(plan.invocation_id, -1, item)

    def test_manifest_files_exactly_match_implementation(self) -> None:
        self.assertEqual(
            json.loads(RESUME_MANIFEST.read_text(encoding="utf-8")),
            reconciliation_resume_manifest(),
        )
        self.assertEqual(
            json.loads(SQLITE_MANIFEST.read_text(encoding="utf-8")),
            sqlite_reconciliation_resume_manifest(),
        )
        claims = reconciliation_resume_manifest()["claim_boundary"]
        self.assertFalse(claims["journal_and_replay_atomic_transaction"])
        self.assertFalse(claims["single_active_executor_enforced"])
        self.assertFalse(claims["production_ready"])


class ResumeCoordinatorPhaseTests(ResumeFixture):
    def test_prepare_is_read_only_and_finalize_exact_prefix(self) -> None:
        plan = self.make_plan(2)
        self.assertEqual(len(self.store), 2)
        self.assertEqual(self.clock.calls, 1)
        first = self.coordinator.reconcile_plan_item(plan, 0)
        self.assertEqual(len(self.store), 1)
        with self.assertRaises(ValueError):
            self.coordinator.finalize_plan(plan, (first,))
        second = self.coordinator.reconcile_plan_item(plan, 1)
        result = self.coordinator.finalize_plan(plan, (first, second))
        self.assertTrue(result.accepted)
        self.assertEqual(result.scanned_count, 2)

    def test_plan_item_policy_index_and_binding_are_strict(self) -> None:
        plan = self.make_plan()
        with self.assertRaises(ValueError):
            self.coordinator.reconcile_plan_item(plan, 1)
        other = ReservationReconciliationCoordinatorV2(
            store=self.store,
            clock=self.clock,
            policy=ReservationReconciliationPolicyV2(9, 20),
        )
        with self.assertRaises(ValueError):
            other.reconcile_plan_item(plan, 0)
        item = self.coordinator.reconcile_plan_item(plan, 0)
        with self.assertRaises(ValueError):
            self.coordinator.finalize_plan(
                plan,
                (replace(item, attempt_id=fixed(99)),),
            )


class ResumeSQLiteTests(ResumeFixture):
    def test_schema_identity_permissions_and_empty_counts(self) -> None:
        self.assertEqual(self.journal.counts(), (0, 0, 0, 0))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(
                connection.execute("PRAGMA application_id").fetchone()[0],
                APPLICATION_ID,
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(
                tables,
                {
                    "reconciliation_resume_intents",
                    "reconciliation_resume_plans",
                    "reconciliation_resume_progress",
                    "reconciliation_resume_receipts",
                    "reconciliation_resume_leases",
                },
            )
        finally:
            connection.close()

    def test_append_order_exact_retry_and_restart(self) -> None:
        plan = self.make_plan()
        expected_intent = ReconciliationAuditIntentV2.create(
            self.invocation,
            self.policy,
        )
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_plan(plan)
        self.journal.begin_intent(expected_intent)
        self.journal.begin_intent(expected_intent)
        self.journal.append_plan(plan)
        self.journal.append_plan(plan)
        item = self.coordinator.reconcile_plan_item(plan, 0)
        progress = ReconciliationProgressV2(plan.invocation_id, 0, item)
        self.journal.append_progress(progress)
        self.journal.append_progress(progress)
        receipt = self.coordinator.finalize_plan(plan, (item,))
        self.journal.append_receipt(receipt)
        self.journal.append_receipt(receipt)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_plan(plan)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_progress(progress)
        self.assertEqual(self.journal.counts(), (1, 1, 1, 1))
        restarted = SQLiteResumableReconciliationJournalV2(
            self.path,
            AuditProtectionTestBackend(),
        )
        self.assertEqual(restarted.load_plan(plan.invocation_id), plan)
        self.assertEqual(restarted.load_progress(plan.invocation_id), (progress,))
        self.assertEqual(restarted.load_receipt(plan.invocation_id), receipt)

    def test_progress_must_be_contiguous_bound_and_terminal(self) -> None:
        plan = self.begin_plan(2)
        first = self.coordinator.reconcile_plan_item(plan, 0)
        second = self.coordinator.reconcile_plan_item(plan, 1)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_progress(
                ReconciliationProgressV2(plan.invocation_id, 1, second)
            )
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_progress(
                ReconciliationProgressV2(
                    plan.invocation_id,
                    0,
                    replace(first, attempt_id=fixed(99)),
                )
            )
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_progress(
                ReconciliationProgressV2(
                    plan.invocation_id,
                    0,
                    replace(first, fence_generation=None),
                )
            )
        self.journal.append_progress(
            ReconciliationProgressV2(plan.invocation_id, 0, first)
        )
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_receipt(
                self.coordinator.finalize_plan(plan, (first, second))
            )

    def test_protected_progress_mutation_fails_closed(self) -> None:
        plan = self.begin_plan()
        item = self.coordinator.reconcile_plan_item(plan, 0)
        self.journal.append_progress(
            ReconciliationProgressV2(plan.invocation_id, 0, item)
        )
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE reconciliation_resume_progress SET protected_progress=zeroblob(length(protected_progress))"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ReconciliationAuditJournalIntegrityError):
            self.journal.load_progress(plan.invocation_id)

    def test_two_processes_serialize_one_intent_identity(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_begin_resume_intent_process,
                args=(str(self.path), start, output),
            )
            for _ in range(2)
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
            [("ok", "existing"), ("ok", "new")],
        )
        self.assertEqual(self.journal.counts(), (1, 0, 0, 0))


class JournalProxy:
    def __init__(self, inner) -> None:
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)


class LostIntentAck(JournalProxy):
    def begin_intent(self, expected):
        self.inner.begin_intent(expected)
        raise OSError("lost intent acknowledgement")


class LostPlanAck(JournalProxy):
    def append_plan(self, plan):
        self.inner.append_plan(plan)
        raise OSError("lost plan acknowledgement")


class LostProgressAck(JournalProxy):
    def append_progress(self, progress):
        self.inner.append_progress(progress)
        raise OSError("lost progress acknowledgement")


class DropProgressAck(JournalProxy):
    def append_progress(self, progress):
        del progress
        raise OSError("progress not committed")


class InterruptingCoordinator:
    def __init__(self, inner) -> None:
        self.inner = inner
        self.item_calls = 0

    @property
    def policy(self):
        return self.inner.policy

    def prepare_run(self, invocation):
        return self.inner.prepare_run(invocation)

    def reconcile_plan_item(self, plan, index):
        self.item_calls += 1
        if self.item_calls == 2:
            raise OSError("simulated process interruption")
        return self.inner.reconcile_plan_item(plan, index)

    def finalize_plan(self, plan, items):
        return self.inner.finalize_plan(plan, items)


class ResumeRunnerTests(ResumeFixture):
    def test_happy_path_persists_each_layer_and_recorded_retry_does_no_work(self) -> None:
        reserve(self.store, 1)
        reserve(self.store, 2)
        first = self.runner().run_once(self.invocation)
        self.assertTrue(first.recorded)
        self.assertIs(
            first.disposition,
            ResumableReconciliationDispositionV2.EXECUTED_AND_RECORDED,
        )
        self.assertEqual(self.journal.counts(), (1, 1, 2, 1))
        self.assertEqual(self.clock.calls, 1)
        retry = self.runner().run_once(self.invocation)
        self.assertIs(
            retry.disposition,
            ResumableReconciliationDispositionV2.RECORDED_REPLAY,
        )
        self.assertEqual(retry.result, first.result)
        self.assertEqual(self.clock.calls, 1)

    def test_lost_intent_plan_and_progress_acknowledgements_are_read_back(self) -> None:
        for wrapper in (LostIntentAck, LostPlanAck, LostProgressAck):
            with self.subTest(wrapper=wrapper.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    journal = SQLiteResumableReconciliationJournalV2(
                        Path(temporary) / "resume.sqlite3",
                        AuditProtectionTestBackend(),
                    )
                    store = InMemoryLinearizableReplayStoreV2()
                    reserve(store)
                    coordinator = ReservationReconciliationCoordinatorV2(
                        store=store,
                        clock=FixedClock(250),
                        policy=self.policy,
                    )
                    outcome = self.runner(
                        coordinator=coordinator,
                        journal=wrapper(journal),
                    ).run_once(self.invocation)
                    self.assertTrue(outcome.recorded)
                    self.assertEqual(journal.counts(), (1, 1, 1, 1))

    def test_restart_resumes_saved_prefix_without_clock_or_rescan(self) -> None:
        reserve(self.store, 1)
        reserve(self.store, 2)
        interrupting = InterruptingCoordinator(self.coordinator)
        first = self.runner(coordinator=interrupting).run_once(self.invocation)
        self.assertFalse(first.recorded)
        self.assertIs(
            first.disposition,
            ResumableReconciliationDispositionV2.AUDIT_UNCERTAIN,
        )
        self.assertEqual(self.journal.counts(), (1, 1, 1, 0))
        self.assertEqual(self.clock.calls, 1)

        self.clock.value = 999
        restarted = SQLiteResumableReconciliationJournalV2(
            self.path,
            AuditProtectionTestBackend(),
        )
        resumed = self.runner(journal=restarted).run_once(self.invocation)
        self.assertTrue(resumed.recorded)
        self.assertIs(
            resumed.disposition,
            ResumableReconciliationDispositionV2.RESUMED_AND_RECORDED,
        )
        self.assertEqual(self.clock.calls, 1)
        assert resumed.result is not None
        self.assertEqual(resumed.result.observed_at, 250)
        self.assertEqual(restarted.counts(), (1, 1, 2, 1))

    def test_mutation_before_missing_progress_commit_is_recovered_on_restart(self) -> None:
        reservation = reserve(self.store)
        first = self.runner(journal=DropProgressAck(self.journal)).run_once(
            self.invocation
        )
        self.assertFalse(first.recorded)
        self.assertEqual(self.journal.counts(), (1, 1, 0, 0))
        self.assertIsNone(self.store.lookup(reservation.identity))
        self.assertIsNotNone(
            self.store.lookup_reservation_fence(reservation.identity)
        )
        resumed = self.runner().run_once(self.invocation)
        self.assertTrue(resumed.recorded)
        assert resumed.result is not None
        self.assertIs(
            resumed.result.items[0].disposition,
            ReconciliationItemDispositionV2.FENCED_RECOVERED,
        )
        self.assertEqual(self.clock.calls, 1)

    def test_unresolved_item_is_terminally_recorded_not_retried(self) -> None:
        reserve(self.store)
        broken = ReservationReconciliationCoordinatorV2(
            store=AbortFailureStore(self.store),
            clock=self.clock,
            policy=self.policy,
        )
        outcome = self.runner(coordinator=broken).run_once(self.invocation)
        self.assertTrue(outcome.recorded)
        assert outcome.result is not None
        self.assertIs(
            outcome.result.disposition,
            ReconciliationRunDispositionV2.HALTED,
        )
        retry = self.runner(coordinator=broken).run_once(self.invocation)
        self.assertIs(
            retry.disposition,
            ResumableReconciliationDispositionV2.RECORDED_REPLAY,
        )

    def test_clock_rejection_records_receipt_without_plan(self) -> None:
        coordinator = ReservationReconciliationCoordinatorV2(
            store=self.store,
            clock=FixedClock(broken=True),
            policy=self.policy,
        )
        outcome = self.runner(coordinator=coordinator).run_once(self.invocation)
        self.assertTrue(outcome.recorded)
        assert outcome.result is not None
        self.assertIs(
            outcome.result.disposition,
            ReconciliationRunDispositionV2.REJECTED,
        )
        self.assertEqual(self.journal.counts(), (1, 0, 0, 1))


if __name__ == "__main__":
    unittest.main()
