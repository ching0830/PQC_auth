from __future__ import annotations

import hashlib
import hmac
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
    ReservationReconciliationItemResultV2,
    ReservationReconciliationPolicyV2,
    ReservationReconciliationRunResultV2,
)
from pq_sat_auth.v2.reconciliation_audit import (
    AUDIT_INTENT_FORMAT,
    AUDIT_RECEIPT_FORMAT,
    JournaledReconciliationDispositionV2,
    JournaledReservationReconciliationRunnerV2,
    ReconciliationAuditAppendDispositionV2,
    ReconciliationAuditIntentV2,
    ReconciliationAuditIntentWriteResultV2,
    decode_reconciliation_audit_intent,
    decode_reconciliation_audit_receipt,
    encode_reconciliation_audit_intent,
    encode_reconciliation_audit_receipt,
    reconciliation_audit_manifest,
    validate_reconciliation_audit_binding,
)
from pq_sat_auth.v2.replay import InMemoryLinearizableReplayStoreV2
from pq_sat_auth.v2.storage.sqlite_reconciliation_audit import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    ReconciliationAuditJournalConflict,
    ReconciliationAuditJournalIntegrityError,
    SQLiteReconciliationAuditJournalV2,
    sqlite_reconciliation_audit_manifest,
)
from tests.system.test_pq_sat_auth_replay_v2 import fixed, identity


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    ROOT
    / "manifests"
    / "pq_sat_auth_fgs_reconciliation_audit_sqlite_v0_2.json"
)
TEST_KEY = hashlib.sha256(b"test-only-reconciliation-audit-key").digest()


class AuditProtectionTestBackend:
    production_ready = False

    def __init__(
        self,
        key: bytes = TEST_KEY,
        *,
        protection_id: str = "TEST-ONLY-AUDIT-XOR-HMAC-SHA256/v1",
    ) -> None:
        self.key = key
        self.protection_id = protection_id
        self.broken_seal = False
        self.broken_open = False
        self.invalid_seal = False
        self.invalid_open = False

    def _stream(self, aad: bytes, length: int) -> bytes:
        return hashlib.shake_256(
            b"TEST-ONLY/RECONCILIATION-AUDIT/STREAM/" + self.key + aad
        ).digest(length)

    def seal(self, plaintext: bytes, *, aad: bytes) -> bytes:
        if self.broken_seal:
            raise RuntimeError("test audit seal failed")
        if self.invalid_seal:
            return b""
        stream = self._stream(aad, len(plaintext))
        body = bytes(left ^ right for left, right in zip(plaintext, stream))
        tag = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        return tag + body

    def open(self, protected_record: bytes, *, aad: bytes) -> bytes:
        if self.broken_open:
            raise RuntimeError("test audit open failed")
        if self.invalid_open:
            return b""  # type: ignore[return-value]
        if len(protected_record) <= hashlib.sha256().digest_size:
            raise ValueError("test audit record is truncated")
        tag = protected_record[: hashlib.sha256().digest_size]
        body = protected_record[hashlib.sha256().digest_size :]
        expected = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("test audit record authentication failed")
        stream = self._stream(aad, len(body))
        return bytes(left ^ right for left, right in zip(body, stream))


class FixedClock:
    def __init__(self, value: int = 250) -> None:
        self.value = value
        self.calls = 0

    def now(self) -> int:
        self.calls += 1
        return self.value


def intent(value: int = 90, *, batch_limit: int = 10):
    return ReconciliationAuditIntentV2(
        fixed(value),
        batch_limit,
        20,
    )


def completed_receipt(
    value: int = 90,
    *,
    observed_at: int = 250,
) -> ReservationReconciliationRunResultV2:
    return ReservationReconciliationRunResultV2(
        accepted=True,
        disposition=ReconciliationRunDispositionV2.COMPLETED,
        invocation_id=fixed(value),
        observed_at=observed_at,
        scan_cutoff=observed_at - 20,
        scanned_count=0,
        items=(),
        failures=(),
    )


def item_receipt(value: int = 90) -> ReservationReconciliationRunResultV2:
    item = ReservationReconciliationItemResultV2(
        use_key=fixed(1),
        attempt_id=fixed(2),
        prior_fencing_generation=1,
        fence_generation=2,
        disposition=ReconciliationItemDispositionV2.FENCED,
        detail=None,
    )
    return ReservationReconciliationRunResultV2(
        accepted=True,
        disposition=ReconciliationRunDispositionV2.COMPLETED,
        invocation_id=fixed(value),
        observed_at=250,
        scan_cutoff=230,
        scanned_count=1,
        items=(item,),
        failures=(),
    )


def _begin_intent_process(path: str, start, output) -> None:
    try:
        journal = SQLiteReconciliationAuditJournalV2(
            path,
            AuditProtectionTestBackend(),
        )
        start.wait(10)
        result = journal.begin_intent(intent())
        output.put(("ok", result.disposition.value))
    except Exception as error:
        output.put(("error", type(error).__name__))


class AuditCodecTests(unittest.TestCase):
    def test_manifest_matches_implementation_and_keeps_claims_bounded(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            {
                "runner": reconciliation_audit_manifest(),
                "sqlite_journal": sqlite_reconciliation_audit_manifest(),
            },
        )
        runner_claims = reconciliation_audit_manifest()["claim_boundary"]
        store_claims = sqlite_reconciliation_audit_manifest()["claims"]
        for claims in (runner_claims, store_claims):
            self.assertFalse(claims["production_ready"])
        self.assertFalse(runner_claims["journal_and_replay_atomic_transaction"])
        self.assertFalse(runner_claims["incomplete_run_automatic_reconstruction"])
        self.assertFalse(runner_claims["operator_authentication_instantiated"])
        self.assertFalse(store_claims["atomic_with_replay_state"])

    def test_intent_and_receipt_round_trip_canonically(self) -> None:
        expected_intent = intent()
        encoded_intent = encode_reconciliation_audit_intent(expected_intent)
        self.assertEqual(
            decode_reconciliation_audit_intent(encoded_intent),
            expected_intent,
        )
        self.assertIn(AUDIT_INTENT_FORMAT.encode("ascii"), encoded_intent)

        expected_receipt = item_receipt()
        encoded_receipt = encode_reconciliation_audit_receipt(expected_receipt)
        self.assertEqual(
            decode_reconciliation_audit_receipt(encoded_receipt),
            expected_receipt,
        )
        self.assertIn(AUDIT_RECEIPT_FORMAT.encode("ascii"), encoded_receipt)

    def test_decoders_reject_unknown_noncanonical_and_trailing_data(self) -> None:
        encoded_intent = encode_reconciliation_audit_intent(intent())
        encoded_receipt = encode_reconciliation_audit_receipt(item_receipt())
        for encoded, decoder in (
            (encoded_intent, decode_reconciliation_audit_intent),
            (encoded_receipt, decode_reconciliation_audit_receipt),
        ):
            with self.subTest(decoder=decoder.__name__, mutation="trailing"):
                with self.assertRaises(ValueError):
                    decoder(encoded + b" ")
            value = json.loads(encoded.decode("ascii"))
            value["unknown"] = 1
            mutated = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            with self.subTest(decoder=decoder.__name__, mutation="unknown"):
                with self.assertRaises(ValueError):
                    decoder(mutated)

        value = json.loads(encoded_intent.decode("ascii"))
        value["invocation_id"] = value["invocation_id"].upper()
        with self.assertRaises(ValueError):
            decode_reconciliation_audit_intent(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )

        receipt_value = json.loads(encoded_receipt.decode("ascii"))
        receipt_value["disposition"] = "unknown"
        with self.assertRaises(ValueError):
            decode_reconciliation_audit_receipt(
                json.dumps(
                    receipt_value,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )

    def test_receipt_encoder_rejects_unbounded_detail(self) -> None:
        original = item_receipt()
        mutated_item = replace(
            original.items[0],
            detail="x" * 257,
        )
        mutated = replace(original, items=(mutated_item,))
        with self.assertRaises(ValueError):
            encode_reconciliation_audit_receipt(mutated)

    def test_receipt_binding_enforces_invocation_batch_and_cutoff_policy(self) -> None:
        expected_intent = intent()
        expected_receipt = completed_receipt()
        validate_reconciliation_audit_binding(
            expected_intent,
            expected_receipt,
        )
        mutations = (
            replace(expected_receipt, invocation_id=fixed(91)),
            replace(expected_receipt, scanned_count=11),
            replace(expected_receipt, scan_cutoff=229),
            ReservationReconciliationRunResultV2(
                accepted=False,
                disposition=ReconciliationRunDispositionV2.REJECTED,
                invocation_id=fixed(90),
                observed_at=None,
                scan_cutoff=None,
                scanned_count=1,
                items=(item_receipt().items[0],),
                failures=("clock_backend:OSError",),
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    validate_reconciliation_audit_binding(
                        expected_intent,
                        mutation,
                    )


class SQLiteAuditFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "audit.sqlite3"
        self.protection = AuditProtectionTestBackend()
        self.journal = SQLiteReconciliationAuditJournalV2(
            self.path,
            self.protection,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()


class SQLiteAuditJournalTests(SQLiteAuditFixture):
    def test_schema_identity_permissions_and_empty_counts(self) -> None:
        self.assertEqual(self.journal.counts(), (0, 0))
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
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(
                tables,
                {
                    "reconciliation_audit_intents",
                    "reconciliation_audit_receipts",
                },
            )
        finally:
            connection.close()

    def test_append_exact_retry_and_restart_are_idempotent(self) -> None:
        expected_intent = intent()
        expected_receipt = item_receipt()
        first_intent = self.journal.begin_intent(expected_intent)
        self.assertIs(
            first_intent.disposition,
            ReconciliationAuditAppendDispositionV2.NEW,
        )
        retry_intent = self.journal.begin_intent(expected_intent)
        self.assertIs(
            retry_intent.disposition,
            ReconciliationAuditAppendDispositionV2.EXISTING,
        )
        first_receipt = self.journal.append_receipt(expected_receipt)
        self.assertIs(
            first_receipt.disposition,
            ReconciliationAuditAppendDispositionV2.NEW,
        )
        retry_receipt = self.journal.append_receipt(expected_receipt)
        self.assertIs(
            retry_receipt.disposition,
            ReconciliationAuditAppendDispositionV2.EXISTING,
        )
        self.assertEqual(self.journal.counts(), (1, 1))

        restarted = SQLiteReconciliationAuditJournalV2(
            self.path,
            AuditProtectionTestBackend(),
        )
        self.assertEqual(
            restarted.load_intent(expected_intent.invocation_id),
            expected_intent,
        )
        self.assertEqual(
            restarted.load_receipt(expected_intent.invocation_id),
            expected_receipt,
        )

    def test_conflicting_intent_receipt_and_orphan_receipt_are_rejected(self) -> None:
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_receipt(completed_receipt())
        self.journal.begin_intent(intent())
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.begin_intent(intent(batch_limit=9))
        self.journal.append_receipt(completed_receipt())
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_receipt(
                completed_receipt(observed_at=251)
            )
        self.assertEqual(self.journal.counts(), (1, 1))

    def test_receipt_must_match_committed_intent_policy(self) -> None:
        self.journal.begin_intent(intent(batch_limit=1))
        wrong_cutoff = replace(completed_receipt(), scan_cutoff=229)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_receipt(wrong_cutoff)
        too_many = replace(completed_receipt(), scanned_count=2)
        with self.assertRaises(ReconciliationAuditJournalConflict):
            self.journal.append_receipt(too_many)
        self.assertEqual(self.journal.counts(), (1, 0))

    def test_protected_record_metadata_and_database_mutations_fail_closed(self) -> None:
        self.journal.begin_intent(intent())
        self.journal.append_receipt(completed_receipt())
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE reconciliation_audit_receipts "
                "SET protected_receipt = zeroblob(length(protected_receipt))"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ReconciliationAuditJournalIntegrityError):
            self.journal.load_receipt(fixed(90))

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "wrong.sqlite3"
            SQLiteReconciliationAuditJournalV2(
                path,
                AuditProtectionTestBackend(),
            )
            connection = sqlite3.connect(path)
            try:
                connection.execute("PRAGMA user_version = 2")
            finally:
                connection.close()
            with self.assertRaises(ReconciliationAuditJournalIntegrityError):
                SQLiteReconciliationAuditJournalV2(
                    path,
                    AuditProtectionTestBackend(),
                )

    def test_protection_failures_never_append_partial_records(self) -> None:
        self.protection.broken_seal = True
        with self.assertRaises(ReconciliationAuditJournalIntegrityError):
            self.journal.begin_intent(intent())
        self.protection.broken_seal = False
        self.assertEqual(self.journal.counts(), (0, 0))
        self.journal.begin_intent(intent())
        self.protection.invalid_seal = True
        with self.assertRaises(ReconciliationAuditJournalIntegrityError):
            self.journal.append_receipt(completed_receipt())
        self.protection.invalid_seal = False
        self.assertEqual(self.journal.counts(), (1, 0))

    def test_two_processes_append_one_intent_identity(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_begin_intent_process,
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
        self.assertEqual(self.journal.counts(), (1, 0))


class CoordinatorSpy:
    def __init__(self, coordinator, journal, *, broken: bool = False) -> None:
        self.inner = coordinator
        self.journal = journal
        self.broken = broken
        self.calls = 0

    @property
    def policy(self):
        return self.inner.policy

    def run_once(self, invocation):
        self.calls += 1
        stored = self.journal.load_intent(invocation.invocation_id)
        if stored is None:
            raise AssertionError("coordinator ran before durable intent")
        if self.broken:
            raise OSError("test coordinator failed")
        return self.inner.run_once(invocation)


class JournalProxy:
    def __init__(self, inner) -> None:
        self.inner = inner

    def load_intent(self, invocation_id):
        return self.inner.load_intent(invocation_id)

    def load_receipt(self, invocation_id):
        return self.inner.load_receipt(invocation_id)

    def begin_intent(self, expected):
        return self.inner.begin_intent(expected)

    def append_receipt(self, receipt):
        return self.inner.append_receipt(receipt)


class LostIntentAcknowledgementJournal(JournalProxy):
    def begin_intent(self, expected):
        self.inner.begin_intent(expected)
        raise OSError("test intent acknowledgement lost")


class LostReceiptAcknowledgementJournal(JournalProxy):
    def append_receipt(self, receipt):
        self.inner.append_receipt(receipt)
        raise OSError("test receipt acknowledgement lost")


class ReceiptFailureJournal(JournalProxy):
    def append_receipt(self, receipt):
        del receipt
        raise OSError("test receipt commit failed")


class MutatedIntentOutputJournal(JournalProxy):
    def begin_intent(self, expected):
        result = self.inner.begin_intent(expected)
        return ReconciliationAuditIntentWriteResultV2(
            result.disposition,
            intent(91),
        )


class AuditLoadFailureJournal(JournalProxy):
    def load_intent(self, invocation_id):
        del invocation_id
        raise OSError("test journal unavailable")


class JournaledRunnerFixture(SQLiteAuditFixture):
    def setUp(self) -> None:
        super().setUp()
        self.clock = FixedClock()
        self.policy = ReservationReconciliationPolicyV2(10, 20)
        self.replay_store = InMemoryLinearizableReplayStoreV2()
        self.coordinator = ReservationReconciliationCoordinatorV2(
            store=self.replay_store,
            clock=self.clock,
            policy=self.policy,
        )
        self.spy = CoordinatorSpy(self.coordinator, self.journal)
        self.invocation = ReservationReconciliationInvocationV2(fixed(90))

    def runner(self, *, journal=None, spy=None):
        return JournaledReservationReconciliationRunnerV2(
            coordinator=self.spy if spy is None else spy,
            journal=self.journal if journal is None else journal,
        )


class JournaledRunnerTests(JournaledRunnerFixture):
    def test_intent_precedes_run_receipt_precedes_return_and_retry_is_replayed(self) -> None:
        first = self.runner().run_once(self.invocation)
        self.assertTrue(first.completed)
        self.assertIs(
            first.disposition,
            JournaledReconciliationDispositionV2.EXECUTED_AND_RECORDED,
        )
        self.assertEqual(self.spy.calls, 1)
        self.assertEqual(self.clock.calls, 1)
        self.assertEqual(self.journal.counts(), (1, 1))
        self.assertEqual(
            self.journal.load_receipt(self.invocation.invocation_id),
            first.result,
        )

        retry = self.runner().run_once(self.invocation)
        self.assertTrue(retry.completed)
        self.assertIs(
            retry.disposition,
            JournaledReconciliationDispositionV2.RECORDED_REPLAY,
        )
        self.assertEqual(retry.result, first.result)
        self.assertEqual(self.spy.calls, 1)
        self.assertEqual(self.clock.calls, 1)

    def test_incomplete_or_conflicting_intent_never_runs_coordinator(self) -> None:
        self.journal.begin_intent(intent())
        incomplete = self.runner().run_once(self.invocation)
        self.assertFalse(incomplete.completed)
        self.assertIs(
            incomplete.disposition,
            JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
        )
        self.assertEqual(
            incomplete.failures,
            ("audit_intent_without_receipt",),
        )
        self.assertEqual(self.spy.calls, 0)

        restarted = SQLiteReconciliationAuditJournalV2(
            self.path,
            AuditProtectionTestBackend(),
        )
        restarted_spy = CoordinatorSpy(self.coordinator, restarted)
        after_restart = self.runner(
            journal=restarted,
            spy=restarted_spy,
        ).run_once(self.invocation)
        self.assertIs(
            after_restart.disposition,
            JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
        )
        self.assertEqual(restarted_spy.calls, 0)

        conflicting_invocation = ReservationReconciliationInvocationV2(fixed(91))
        self.journal.begin_intent(intent(91, batch_limit=9))
        conflict = self.runner().run_once(conflicting_invocation)
        self.assertFalse(conflict.completed)
        self.assertIs(
            conflict.disposition,
            JournaledReconciliationDispositionV2.REJECTED,
        )
        self.assertEqual(conflict.failures, ("audit_intent_conflict",))
        self.assertEqual(self.spy.calls, 0)

    def test_lost_intent_ack_marks_uncertainty_and_retry_requires_recovery(self) -> None:
        wrapped = LostIntentAcknowledgementJournal(self.journal)
        first = self.runner(journal=wrapped).run_once(self.invocation)
        self.assertFalse(first.completed)
        self.assertIs(
            first.disposition,
            JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
        )
        self.assertEqual(self.spy.calls, 0)
        retry = self.runner().run_once(self.invocation)
        self.assertIs(
            retry.disposition,
            JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
        )
        self.assertEqual(self.spy.calls, 0)

    def test_lost_receipt_ack_is_recovered_by_exact_readback(self) -> None:
        wrapped = LostReceiptAcknowledgementJournal(self.journal)
        result = self.runner(journal=wrapped).run_once(self.invocation)
        self.assertTrue(result.completed)
        self.assertIs(
            result.disposition,
            JournaledReconciliationDispositionV2.EXECUTED_RECEIPT_RECOVERED,
        )
        self.assertEqual(self.spy.calls, 1)
        self.assertEqual(self.journal.counts(), (1, 1))

    def test_receipt_failure_returns_uncertain_and_retry_does_not_rerun(self) -> None:
        ticket_identity = identity()
        reservation = self.replay_store.reserve(
            ticket_identity,
            attempt_id=fixed(4),
            request_digest=fixed(5),
            serving_context_digest=fixed(6),
            reserved_at=100,
            lease_deadline=200,
            revocation_generation=7,
        ).record
        result = self.runner(
            journal=ReceiptFailureJournal(self.journal)
        ).run_once(self.invocation)
        self.assertFalse(result.completed)
        self.assertIs(
            result.disposition,
            JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
        )
        self.assertIsNotNone(result.result)
        self.assertEqual(self.spy.calls, 1)
        self.assertEqual(self.journal.counts(), (1, 0))
        self.assertIsNone(self.replay_store.lookup(ticket_identity))
        fence = self.replay_store.lookup_reservation_fence(ticket_identity)
        self.assertIsNotNone(fence)
        self.assertEqual(fence.fencing_generation, reservation.fencing_generation + 1)
        retry = self.runner().run_once(self.invocation)
        self.assertIs(
            retry.disposition,
            JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
        )
        self.assertEqual(self.spy.calls, 1)
        self.assertEqual(
            self.replay_store.lookup_reservation_fence(ticket_identity),
            fence,
        )

    def test_journal_or_coordinator_failures_never_become_completed(self) -> None:
        unavailable = self.runner(
            journal=AuditLoadFailureJournal(self.journal)
        ).run_once(self.invocation)
        self.assertFalse(unavailable.completed)
        self.assertIs(
            unavailable.disposition,
            JournaledReconciliationDispositionV2.REJECTED,
        )
        self.assertEqual(self.spy.calls, 0)

        mutated = self.runner(
            journal=MutatedIntentOutputJournal(self.journal)
        ).run_once(self.invocation)
        self.assertFalse(mutated.completed)
        self.assertIs(
            mutated.disposition,
            JournaledReconciliationDispositionV2.AUDIT_UNCERTAIN,
        )
        self.assertEqual(self.spy.calls, 0)

        second_path = Path(self.temporary.name) / "coordinator.sqlite3"
        second_journal = SQLiteReconciliationAuditJournalV2(
            second_path,
            AuditProtectionTestBackend(),
        )
        broken_spy = CoordinatorSpy(
            self.coordinator,
            second_journal,
            broken=True,
        )
        failed = self.runner(journal=second_journal, spy=broken_spy).run_once(
            self.invocation
        )
        self.assertFalse(failed.completed)
        self.assertIs(
            failed.disposition,
            JournaledReconciliationDispositionV2.RECOVERY_REQUIRED,
        )
        self.assertEqual(second_journal.counts(), (1, 0))
        self.assertEqual(broken_spy.calls, 1)


if __name__ == "__main__":
    unittest.main()
