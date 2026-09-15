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
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.v2.application import (
    FGSFirstApplicationRecordProcessorV2,
    FGSFirstRecordDispositionV2,
    FirstApplicationInboxEntryV2,
    FirstApplicationInboxStateV2,
    FirstRecordOutboxConflictError,
    InMemoryFirstApplicationDeliveryStoreV2,
    InboxEnqueueDispositionV2,
    derive_first_application_plaintext_digest,
)
from pq_sat_auth.v2.dispatch import (
    ApplicationApplyDispositionV2,
    ApplicationApplyResultV2,
    ApplicationDispatchDispositionV2,
    FGSApplicationInboxDispatcherV2,
    application_dispatch_manifest,
)
from pq_sat_auth.v2.storage.sqlite_inbox import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    ApplicationInboxIntegrityError,
    SQLiteFirstApplicationInboxV2,
    decode_application_inbox_entry,
    encode_application_inbox_entry,
    sqlite_first_application_inbox_manifest,
)
from tests.system.test_pq_sat_auth_first_application_v2 import (
    PLAINTEXT,
    FirstApplicationFixture,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_first_application_v0_2.json"
TEST_KEY = hashlib.sha256(b"test-only-application-inbox-key").digest()
SESSION_ID = hashlib.sha256(b"application-inbox-session").digest()
RECORD_DIGEST = hashlib.sha256(b"application-inbox-record").digest()


class InboxProtectionTestBackend:
    production_ready = False

    def __init__(
        self,
        key: bytes = TEST_KEY,
        *,
        protection_id: str = "TEST-ONLY-INBOX-XOR-HMAC-SHA256/v1",
    ) -> None:
        self.key = key
        self.protection_id = protection_id
        self.broken_seal = False
        self.broken_open = False
        self.invalid_seal = False
        self.invalid_open = False

    def _stream(self, aad: bytes, length: int) -> bytes:
        return hashlib.shake_256(
            b"TEST-ONLY/APPLICATION-INBOX-STREAM/" + self.key + aad
        ).digest(length)

    def seal(self, plaintext: bytes, *, aad: bytes) -> bytes:
        if self.broken_seal:
            raise RuntimeError("test inbox seal failed")
        if self.invalid_seal:
            return b""  # type: ignore[return-value]
        stream = self._stream(aad, len(plaintext))
        body = bytes(left ^ right for left, right in zip(plaintext, stream))
        tag = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        return tag + body

    def open(self, protected_record: bytes, *, aad: bytes) -> bytes:
        if self.broken_open:
            raise RuntimeError("test inbox open failed")
        if self.invalid_open:
            return b""  # type: ignore[return-value]
        if len(protected_record) <= hashlib.sha256().digest_size:
            raise ValueError("test inbox record is truncated")
        tag = protected_record[: hashlib.sha256().digest_size]
        body = protected_record[hashlib.sha256().digest_size :]
        expected = hmac.new(self.key, aad + body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("test inbox record authentication failed")
        stream = self._stream(aad, len(body))
        return bytes(left ^ right for left, right in zip(body, stream))


def _inbox(path: str | Path) -> SQLiteFirstApplicationInboxV2:
    return SQLiteFirstApplicationInboxV2(
        Path(path),
        InboxProtectionTestBackend(),
        busy_timeout_ms=20_000,
    )


def _enqueue_worker(path: str, start, output) -> None:
    try:
        inbox = _inbox(path)
        start.wait(10)
        result = inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        output.put(("ok", result.disposition.value))
    except Exception as error:
        output.put(("error", type(error).__name__, str(error)))


def _enqueue_then_exit_worker(path: str) -> None:
    _inbox(path).enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
    os._exit(29)


class SQLiteIdempotentApplicationTestBackend:
    production_ready = False
    durable = True

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS applied_operations ("
                "idempotency_key BLOB PRIMARY KEY, "
                "plaintext_digest BLOB NOT NULL, receipt BLOB NOT NULL)"
            )
            connection.commit()
        finally:
            connection.close()

    def apply_once(
        self,
        idempotency_key: bytes,
        plaintext: bytes,
    ) -> ApplicationApplyResultV2:
        digest = derive_first_application_plaintext_digest(plaintext)
        receipt = hashlib.sha256(
            b"TEST-ONLY/APPLICATION-RECEIPT/" + idempotency_key + digest
        ).digest()
        connection = sqlite3.connect(
            self.path,
            timeout=20,
            isolation_level=None,
        )
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT plaintext_digest, receipt FROM applied_operations "
                "WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is not None:
                if row != (digest, receipt):
                    raise FirstRecordOutboxConflictError(
                        "application idempotency key changed operation"
                    )
                connection.execute("COMMIT")
                return ApplicationApplyResultV2(
                    ApplicationApplyDispositionV2.EXISTING,
                    idempotency_key,
                    digest,
                    receipt,
                )
            connection.execute(
                "INSERT INTO applied_operations "
                "(idempotency_key, plaintext_digest, receipt) VALUES (?, ?, ?)",
                (idempotency_key, digest, receipt),
            )
            connection.execute("COMMIT")
            return ApplicationApplyResultV2(
                ApplicationApplyDispositionV2.APPLIED,
                idempotency_key,
                digest,
                receipt,
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def effect_count(self) -> int:
        connection = sqlite3.connect(self.path)
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM applied_operations"
            ).fetchone()
            assert row is not None
            return int(row[0])
        finally:
            connection.close()


class RaiseAfterApplyBackend:
    production_ready = False
    durable = True

    def __init__(self, delegate: SQLiteIdempotentApplicationTestBackend) -> None:
        self.delegate = delegate

    def apply_once(self, idempotency_key: bytes, plaintext: bytes):
        self.delegate.apply_once(idempotency_key, plaintext)
        raise OSError("simulated lost application acknowledgement")


class BrokenApplicationBackend:
    production_ready = False
    durable = False

    def __init__(self, mode: str) -> None:
        self.mode = mode

    def apply_once(self, idempotency_key: bytes, plaintext: bytes):
        if self.mode == "raise":
            raise OSError("application backend unavailable")
        if self.mode == "conflict":
            raise FirstRecordOutboxConflictError("application conflict")
        if self.mode == "wrong_type":
            return object()
        if self.mode == "mutate":
            return ApplicationApplyResultV2(
                ApplicationApplyDispositionV2.APPLIED,
                hashlib.sha256(b"wrong-key").digest(),
                derive_first_application_plaintext_digest(plaintext),
                b"wrong-result",
            )
        raise AssertionError("unknown broken application mode")


class RaiseAfterCompleteInbox:
    durable = True
    distributed = False
    production_ready = False

    def __init__(self, delegate: SQLiteFirstApplicationInboxV2) -> None:
        self.delegate = delegate

    def enqueue(self, session_id, record_digest, plaintext):
        return self.delegate.enqueue(session_id, record_digest, plaintext)

    def load(self, session_id):
        return self.delegate.load(session_id)

    def complete(self, session_id, record_digest, receipt):
        self.delegate.complete(session_id, record_digest, receipt)
        raise OSError("simulated lost inbox-completion acknowledgement")

    def pending(self, *, limit=100):
        return self.delegate.pending(limit=limit)


class SQLiteApplicationInboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(self.temporary) / "application-inbox.sqlite3"
        self.inbox = _inbox(self.path)

    @staticmethod
    def pending_entry() -> FirstApplicationInboxEntryV2:
        return FirstApplicationInboxEntryV2(
            FirstApplicationInboxStateV2.PENDING,
            1,
            SESSION_ID,
            RECORD_DIGEST,
            PLAINTEXT,
        )

    def test_manifest_and_canonical_frozen_records(self) -> None:
        expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            expected["sqlite_inbox"],
            sqlite_first_application_inbox_manifest(),
        )
        self.assertEqual(expected["dispatch"], application_dispatch_manifest())
        pending = self.pending_entry()
        completed = replace(pending, state=FirstApplicationInboxStateV2.COMPLETED, revision=2, receipt=b"receipt")
        for entry in (pending, completed):
            encoded = encode_application_inbox_entry(entry)
            self.assertEqual(decode_application_inbox_entry(encoded), entry)
            self.assertEqual(encode_application_inbox_entry(decode_application_inbox_entry(encoded)), encoded)
        self.assertEqual(
            hashlib.sha256(encode_application_inbox_entry(pending)).hexdigest(),
            "549fead456c459189ea2874717f01db6af6e1f6a92e8b30290843a3467245718",
        )

    def test_decoder_rejects_unknown_noncanonical_and_trailing_data(self) -> None:
        encoded = encode_application_inbox_entry(self.pending_entry())
        parsed = json.loads(encoded)
        changed = dict(parsed)
        changed["unknown"] = 1
        candidates = (
            encoded + b" ",
            json.dumps(changed, sort_keys=True, separators=(",", ":")).encode(),
            encoded.replace(b'"PENDING"', b'"UNKNOWN"'),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate[-16:]):
                with self.assertRaises((TypeError, ValueError, ApplicationInboxIntegrityError)):
                    decode_application_inbox_entry(candidate)

    def test_enqueue_complete_restart_and_exact_retries(self) -> None:
        first = self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        self.assertIs(first.disposition, InboxEnqueueDispositionV2.NEW)
        retry = self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        self.assertIs(retry.disposition, InboxEnqueueDispositionV2.EXISTING_PENDING)
        self.assertEqual(self.inbox.pending(), (SESSION_ID,))
        completed = self.inbox.complete(SESSION_ID, RECORD_DIGEST, b"receipt")
        self.assertIs(completed.state, FirstApplicationInboxStateV2.COMPLETED)
        exact = _inbox(self.path).complete(SESSION_ID, RECORD_DIGEST, b"receipt")
        self.assertEqual(exact, completed)
        final = _inbox(self.path).enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        self.assertIs(final.disposition, InboxEnqueueDispositionV2.EXISTING_COMPLETED)
        self.assertEqual(self.inbox.pending(), ())
        self.assertEqual(len(self.inbox), 1)
        with self.assertRaises(FirstRecordOutboxConflictError):
            self.inbox.complete(SESSION_ID, RECORD_DIGEST, b"different-receipt")

    def test_competing_record_or_plaintext_is_rejected(self) -> None:
        self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        with self.assertRaises(FirstRecordOutboxConflictError):
            self.inbox.enqueue(
                SESSION_ID,
                hashlib.sha256(b"different-record").digest(),
                PLAINTEXT,
            )
        with self.assertRaises(FirstRecordOutboxConflictError):
            self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, b"different plaintext")

    def test_thread_and_process_races_have_one_enqueue_winner(self) -> None:
        workers = 12
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(invoke, range(workers)))
        self.assertEqual(
            sum(result.disposition is InboxEnqueueDispositionV2.NEW for result in results),
            1,
        )

        process_path = Path(self.temporary) / "process-inbox.sqlite3"
        _inbox(process_path)
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_enqueue_worker,
                args=(str(process_path), start, output),
            )
            for _ in range(6)
        ]
        for process in processes:
            process.start()
        start.set()
        outcomes = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        self.assertTrue(all(item[0] == "ok" for item in outcomes), outcomes)
        self.assertEqual(
            sum(item[1] == InboxEnqueueDispositionV2.NEW.value for item in outcomes),
            1,
        )

    def test_enqueue_survives_abrupt_process_exit(self) -> None:
        context = multiprocessing.get_context("spawn")
        process = context.Process(
            target=_enqueue_then_exit_worker,
            args=(str(self.path),),
        )
        process.start()
        process.join(timeout=30)
        self.assertEqual(process.exitcode, 29)
        recovered = _inbox(self.path).load(SESSION_ID)
        self.assertIsNotNone(recovered)
        assert recovered is not None
        self.assertEqual(recovered.plaintext, PLAINTEXT)

    def test_schema_protection_identity_and_row_mutation_fail_closed(self) -> None:
        self.assertEqual(APPLICATION_ID, 0x50515349)
        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        mutations = (
            ("record_digest", hashlib.sha256(b"mutated-record").digest()),
            ("state", 2),
            ("protection_id", "OTHER/v1"),
            ("protected_record", b"corrupt"),
        )
        for column, value in mutations:
            with self.subTest(column=column):
                path = Path(self.temporary) / f"mutated-{column}.sqlite3"
                inbox = _inbox(path)
                inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
                connection = sqlite3.connect(path)
                try:
                    connection.execute("PRAGMA ignore_check_constraints = ON")
                    connection.execute(
                        f"UPDATE first_application_inbox SET {column} = ?",
                        (value,),
                    )
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(ApplicationInboxIntegrityError):
                    inbox.load(SESSION_ID)

        self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        with self.assertRaises(ApplicationInboxIntegrityError):
            SQLiteFirstApplicationInboxV2(
                self.path,
                InboxProtectionTestBackend(key=bytes(32)),
            ).load(SESSION_ID)

    def test_pending_bounds_and_invalid_inputs_fail_before_mutation(self) -> None:
        for limit in (0, 1001, True, "10"):
            with self.subTest(limit=limit):
                with self.assertRaises((TypeError, ValueError)):
                    self.inbox.pending(limit=limit)  # type: ignore[arg-type]
        with self.assertRaises((TypeError, ValueError)):
            self.inbox.enqueue(SESSION_ID[:-1], RECORD_DIGEST, PLAINTEXT)
        with self.assertRaises((TypeError, ValueError)):
            self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, b"")
        self.assertEqual(len(self.inbox), 0)

    def test_protection_failures_do_not_release_or_open_plaintext(self) -> None:
        seal_backend = InboxProtectionTestBackend()
        seal_backend.broken_seal = True
        seal_path = Path(self.temporary) / "broken-seal.sqlite3"
        sealed = SQLiteFirstApplicationInboxV2(seal_path, seal_backend)
        with self.assertRaises(ApplicationInboxIntegrityError):
            sealed.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        self.assertIsNone(_inbox(seal_path).load(SESSION_ID))

        self.inbox.enqueue(SESSION_ID, RECORD_DIGEST, PLAINTEXT)
        open_backend = InboxProtectionTestBackend()
        open_backend.broken_open = True
        with self.assertRaises(ApplicationInboxIntegrityError):
            SQLiteFirstApplicationInboxV2(
                self.path,
                open_backend,
            ).load(SESSION_ID)


class ApplicationInboxPipelineTests(FirstApplicationFixture):
    def setUp(self) -> None:
        super().setUp()
        self.inbox_path = Path(self.temporary.name) / "application-inbox.sqlite3"
        self.application_path = Path(self.temporary.name) / "application-ledger.sqlite3"

    def inbox(self):
        return _inbox(self.inbox_path)

    def first_processor(self, inbox=None):
        return FGSFirstApplicationRecordProcessorV2(
            activation_processor=self.activation_processor(),
            protection_backend=self.application_protection,
            inbox_store=self.inbox() if inbox is None else inbox,
        )

    def test_first_record_is_queued_without_plaintext_delivery_then_dispatched(self) -> None:
        prepared = self.prepare()
        queued = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(queued.accepted, queued.failures)
        self.assertIs(queued.disposition, FGSFirstRecordDispositionV2.QUEUED)
        self.assertIsNone(queued.delivery)
        self.assertIsNotNone(queued.inbox)

        retry = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_QUEUED,
        )
        backend = SQLiteIdempotentApplicationTestBackend(self.application_path)
        dispatcher = FGSApplicationInboxDispatcherV2(
            inbox_store=self.inbox(),
            application_backend=backend,
        )
        completed = dispatcher.process(self.session.session_id)
        self.assertTrue(completed.accepted, completed.failures)
        self.assertIs(
            completed.disposition,
            ApplicationDispatchDispositionV2.COMPLETED,
        )
        self.assertEqual(backend.effect_count(), 1)
        final_retry = self.first_processor().process(prepared.record_bytes)
        self.assertIs(
            final_retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_COMPLETED,
        )
        dispatch_retry = dispatcher.process(self.session.session_id)
        self.assertIs(
            dispatch_retry.disposition,
            ApplicationDispatchDispositionV2.ALREADY_COMPLETED,
        )
        self.assertEqual(backend.effect_count(), 1)

    def test_lost_application_ack_is_recovered_without_duplicate_effect(self) -> None:
        prepared = self.prepare()
        self.assertTrue(self.first_processor().process(prepared.record_bytes).accepted)
        backend = SQLiteIdempotentApplicationTestBackend(self.application_path)
        uncertain = FGSApplicationInboxDispatcherV2(
            inbox_store=self.inbox(),
            application_backend=RaiseAfterApplyBackend(backend),
        ).process(self.session.session_id)
        self.assertFalse(uncertain.accepted)
        self.assertIs(
            uncertain.disposition,
            ApplicationDispatchDispositionV2.COMMIT_UNCERTAIN,
        )
        pending = self.inbox().load(self.session.session_id)
        assert pending is not None
        self.assertIs(pending.state, FirstApplicationInboxStateV2.PENDING)
        recovered = FGSApplicationInboxDispatcherV2(
            inbox_store=self.inbox(),
            application_backend=backend,
        ).process(self.session.session_id)
        self.assertTrue(recovered.accepted, recovered.failures)
        self.assertIs(
            recovered.disposition,
            ApplicationDispatchDispositionV2.RECOVERED_COMPLETION,
        )
        self.assertEqual(backend.effect_count(), 1)

    def test_lost_completion_ack_is_recovered_without_reapply(self) -> None:
        prepared = self.prepare()
        self.assertTrue(self.first_processor().process(prepared.record_bytes).accepted)
        backend = SQLiteIdempotentApplicationTestBackend(self.application_path)
        inbox = self.inbox()
        uncertain = FGSApplicationInboxDispatcherV2(
            inbox_store=RaiseAfterCompleteInbox(inbox),
            application_backend=backend,
        ).process(self.session.session_id)
        self.assertFalse(uncertain.accepted)
        retry = FGSApplicationInboxDispatcherV2(
            inbox_store=self.inbox(),
            application_backend=backend,
        ).process(self.session.session_id)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            ApplicationDispatchDispositionV2.ALREADY_COMPLETED,
        )
        self.assertEqual(backend.effect_count(), 1)

    def test_parallel_dispatchers_share_one_idempotent_effect(self) -> None:
        prepared = self.prepare()
        self.assertTrue(self.first_processor().process(prepared.record_bytes).accepted)
        backend = SQLiteIdempotentApplicationTestBackend(self.application_path)
        workers = 12
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return FGSApplicationInboxDispatcherV2(
                inbox_store=self.inbox(),
                application_backend=backend,
            ).process(self.session.session_id)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(invoke, range(workers)))
        self.assertTrue(all(result.accepted for result in results), results)
        self.assertEqual(backend.effect_count(), 1)
        self.assertTrue(
            all(result.receipt == results[0].receipt for result in results)
        )

    def test_processor_requires_exactly_one_post_activation_sink(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            FGSFirstApplicationRecordProcessorV2(
                activation_processor=self.activation_processor(),
                protection_backend=self.application_protection,
            )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            FGSFirstApplicationRecordProcessorV2(
                activation_processor=self.activation_processor(),
                protection_backend=self.application_protection,
                delivery_store=InMemoryFirstApplicationDeliveryStoreV2(),
                inbox_store=self.inbox(),
            )

    def test_dispatcher_fails_closed_on_missing_or_invalid_application(self) -> None:
        missing = FGSApplicationInboxDispatcherV2(
            inbox_store=self.inbox(),
            application_backend=BrokenApplicationBackend("raise"),
        ).process(self.session.session_id)
        self.assertFalse(missing.accepted)
        self.assertEqual(missing.failures, ("inbox_missing",))

        prepared = self.prepare()
        self.assertTrue(self.first_processor().process(prepared.record_bytes).accepted)
        for mode in ("raise", "wrong_type", "mutate", "conflict"):
            with self.subTest(mode=mode):
                result = FGSApplicationInboxDispatcherV2(
                    inbox_store=self.inbox(),
                    application_backend=BrokenApplicationBackend(mode),
                ).process(self.session.session_id)
                self.assertFalse(result.accepted)
                expected = (
                    ApplicationDispatchDispositionV2.REJECTED
                    if mode == "conflict"
                    else ApplicationDispatchDispositionV2.COMMIT_UNCERTAIN
                )
                self.assertIs(result.disposition, expected)
                self.assertIsNone(result.receipt)


if __name__ == "__main__":
    unittest.main()
