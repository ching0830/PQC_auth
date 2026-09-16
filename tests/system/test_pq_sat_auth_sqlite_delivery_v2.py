from __future__ import annotations

import hashlib
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
    DeliveryClaimDispositionV2,
    FGSFirstRecordDispositionV2,
    FirstRecordOutboxConflictError,
    derive_first_application_aad,
    derive_first_application_nonce_context,
    encode_first_application_record,
)
from pq_sat_auth.v2.storage.sqlite_delivery import (
    APPLICATION_ID,
    CLAIM_REVISION,
    SCHEMA_VERSION,
    FirstApplicationDeliveryIntegrityError,
    SQLiteFirstApplicationDeliveryStoreV2,
    derive_delivery_claim_checksum,
    sqlite_first_application_delivery_manifest,
)
from tests.system.test_pq_sat_auth_first_application_v2 import (
    PLAINTEXT,
    FirstApplicationFixture,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "manifests" / "pq_sat_auth_first_application_v0_2.json"
SESSION_ID = hashlib.sha256(b"delivery-test-session").digest()
RECORD_DIGEST = hashlib.sha256(b"delivery-test-record").digest()


def _store(path: str | Path) -> SQLiteFirstApplicationDeliveryStoreV2:
    return SQLiteFirstApplicationDeliveryStoreV2(
        Path(path),
        busy_timeout_ms=20_000,
    )


def _claim_worker(
    path: str,
    record_digest: bytes,
    start,
    output,
) -> None:
    try:
        store = _store(path)
        start.wait(10)
        result = store.claim(SESSION_ID, record_digest)
        output.put(("ok", result.disposition.value, result.record_digest))
    except Exception as error:
        output.put(("error", type(error).__name__, str(error)))


def _claim_then_exit_worker(path: str) -> None:
    _store(path).claim(SESSION_ID, RECORD_DIGEST)
    os._exit(23)


class RaiseAfterClaimStore:
    durable = True
    distributed = False
    production_ready = False

    def __init__(self, delegate: SQLiteFirstApplicationDeliveryStoreV2) -> None:
        self.delegate = delegate

    def claim(self, session_id: bytes, record_digest: bytes):
        self.delegate.claim(session_id, record_digest)
        raise OSError("simulated lost delivery-claim acknowledgement")


class SQLiteFirstApplicationDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(self.temporary) / "fgs-delivery.sqlite3"
        self.store = SQLiteFirstApplicationDeliveryStoreV2(self.path)

    def test_manifest_and_frozen_claim_checksum(self) -> None:
        expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            expected["sqlite_delivery"],
            sqlite_first_application_delivery_manifest(),
        )
        self.assertEqual(
            derive_delivery_claim_checksum(SESSION_ID, RECORD_DIGEST).hex(),
            "35ee75a9810bc12e1e249d6909386f7efc4a7d41fe79c27cee577855a93bb273",
        )

    def test_new_exact_retry_and_restart_are_idempotent(self) -> None:
        first = self.store.claim(SESSION_ID, RECORD_DIGEST)
        self.assertIs(first.disposition, DeliveryClaimDispositionV2.NEW)
        retry = self.store.claim(SESSION_ID, RECORD_DIGEST)
        self.assertIs(retry.disposition, DeliveryClaimDispositionV2.EXISTING)
        restarted = _store(self.path)
        recovered = restarted.load(SESSION_ID)
        self.assertEqual(recovered, retry)
        self.assertEqual(len(restarted), 1)
        with self.assertRaises(FirstRecordOutboxConflictError):
            restarted.claim(SESSION_ID, hashlib.sha256(b"competing").digest())

    def test_thread_race_has_one_new_exact_claim(self) -> None:
        workers = 16
        barrier = threading.Barrier(workers)

        def invoke(_: int):
            barrier.wait()
            return self.store.claim(SESSION_ID, RECORD_DIGEST)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(invoke, range(workers)))
        self.assertEqual(
            sum(
                result.disposition is DeliveryClaimDispositionV2.NEW
                for result in results
            ),
            1,
        )
        self.assertTrue(
            all(result.record_digest == RECORD_DIGEST for result in results)
        )

    def test_process_race_has_one_new_exact_claim(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_claim_worker,
                args=(str(self.path), RECORD_DIGEST, start, output),
            )
            for _ in range(6)
        ]
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        self.assertTrue(all(result[0] == "ok" for result in results), results)
        self.assertEqual(
            sum(result[1] == DeliveryClaimDispositionV2.NEW.value for result in results),
            1,
        )
        self.assertEqual(
            sum(
                result[1] == DeliveryClaimDispositionV2.EXISTING.value
                for result in results
            ),
            len(processes) - 1,
        )

    def test_competing_process_records_have_one_winner(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        digests = [hashlib.sha256(bytes((worker,))).digest() for worker in range(6)]
        processes = [
            context.Process(
                target=_claim_worker,
                args=(str(self.path), digest, start, output),
            )
            for digest in digests
        ]
        for process in processes:
            process.start()
        start.set()
        results = [output.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(timeout=30)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sum(result[0] == "ok" for result in results), 1)
        self.assertEqual(
            sum(
                result[:2] == ("error", "FirstRecordOutboxConflictError")
                for result in results
            ),
            len(processes) - 1,
        )

    def test_committed_claim_survives_abrupt_process_exit(self) -> None:
        context = multiprocessing.get_context("spawn")
        process = context.Process(
            target=_claim_then_exit_worker,
            args=(str(self.path),),
        )
        process.start()
        process.join(timeout=30)
        self.assertEqual(process.exitcode, 23)
        recovered = _store(self.path).load(SESSION_ID)
        self.assertIsNotNone(recovered)
        assert recovered is not None
        self.assertEqual(recovered.record_digest, RECORD_DIGEST)

    def test_path_database_identity_and_permissions_are_checked(self) -> None:
        self.assertEqual(APPLICATION_ID, 0x50515344)
        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(CLAIM_REVISION, 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "absolute"):
            SQLiteFirstApplicationDeliveryStoreV2(Path("relative.sqlite3"))

        wrong_path = Path(self.temporary) / "wrong-identity.sqlite3"
        wrong = sqlite3.connect(wrong_path)
        try:
            wrong.execute("PRAGMA application_id = 123")
            wrong.commit()
        finally:
            wrong.close()
        with self.assertRaises(FirstApplicationDeliveryIntegrityError):
            SQLiteFirstApplicationDeliveryStoreV2(wrong_path)

    def test_schema_and_row_corruption_fail_closed(self) -> None:
        mutations = (
            ("revision", 2),
            ("session_id", hashlib.sha256(b"changed-session").digest()),
            ("record_digest", hashlib.sha256(b"changed-record").digest()),
            ("claim_checksum", bytes(32)),
        )
        for column, value in mutations:
            with self.subTest(column=column):
                path = Path(self.temporary) / f"mutated-{column}.sqlite3"
                store = _store(path)
                store.claim(SESSION_ID, RECORD_DIGEST)
                connection = sqlite3.connect(path)
                try:
                    connection.execute("PRAGMA ignore_check_constraints = ON")
                    connection.execute(
                        f"UPDATE first_application_delivery_claims "
                        f"SET {column} = ?",
                        (value,),
                    )
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(FirstApplicationDeliveryIntegrityError):
                    store.load(value if column == "session_id" else SESSION_ID)

        schema_path = Path(self.temporary) / "wrong-schema.sqlite3"
        schema = sqlite3.connect(schema_path)
        try:
            schema.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            schema.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            schema.execute("CREATE TABLE wrong_table (value INTEGER)")
            schema.commit()
        finally:
            schema.close()
        with self.assertRaises(FirstApplicationDeliveryIntegrityError):
            SQLiteFirstApplicationDeliveryStoreV2(schema_path)

    def test_input_lengths_and_types_fail_before_mutation(self) -> None:
        invalid = (
            (SESSION_ID[:-1], RECORD_DIGEST),
            (SESSION_ID, RECORD_DIGEST + b"\x00"),
            ("not-bytes", RECORD_DIGEST),
        )
        for session, digest in invalid:
            with self.subTest(session=session, digest=digest):
                with self.assertRaises((TypeError, ValueError)):
                    self.store.claim(session, digest)  # type: ignore[arg-type]
        self.assertEqual(len(self.store), 0)


class SQLiteDeliveryProcessorIntegrationTests(FirstApplicationFixture):
    def setUp(self) -> None:
        super().setUp()
        self.delivery_path = Path(self.temporary.name) / "fgs-delivery.sqlite3"

    def test_processor_restart_does_not_release_plaintext_twice(self) -> None:
        prepared = self.prepare()
        first = self.fgs_first_processor(
            delivery_store=_store(self.delivery_path)
        ).process(prepared.record_bytes)
        self.assertTrue(first.accepted, first.failures)
        self.assertIs(first.disposition, FGSFirstRecordDispositionV2.DELIVERED)
        self.assertIsNotNone(first.delivery)

        retry = self.fgs_first_processor(
            delivery_store=_store(self.delivery_path)
        ).process(prepared.record_bytes)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_DELIVERED,
        )
        self.assertIsNone(retry.delivery)

    def test_lost_claim_ack_can_drop_work_but_retry_cannot_duplicate(self) -> None:
        prepared = self.prepare()
        store = _store(self.delivery_path)
        uncertain = self.fgs_first_processor(
            delivery_store=RaiseAfterClaimStore(store)
        ).process(prepared.record_bytes)
        self.assertFalse(uncertain.accepted)
        self.assertIs(
            uncertain.disposition,
            FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
        )
        self.assertIsNone(uncertain.delivery)

        retry = self.fgs_first_processor(
            delivery_store=_store(self.delivery_path)
        ).process(prepared.record_bytes)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_DELIVERED,
        )
        self.assertIsNone(retry.delivery)

    def test_sqlite_claim_rejects_second_authenticated_sequence_zero_record(self) -> None:
        prepared = self.prepare()
        assert prepared.record is not None
        processor = self.fgs_first_processor(
            delivery_store=_store(self.delivery_path)
        )
        first = processor.process(prepared.record_bytes)
        self.assertTrue(first.accepted, first.failures)
        prototype = replace(prepared.record, ciphertext=b"placeholder")
        ciphertext = self.application_protection.seal(
            self.session.application_key,
            nonce_context=derive_first_application_nonce_context(
                self.session.suite_id,
                self.session.session_id,
            ),
            aad=derive_first_application_aad(prototype),
            plaintext=b"competing authenticated operation",
        )
        competing = replace(prepared.record, ciphertext=ciphertext)
        conflict = processor.process(encode_first_application_record(competing))
        self.assertFalse(conflict.accepted)
        self.assertEqual(conflict.failures, ("delivery_conflict",))
        self.assertIsNone(conflict.delivery)


if __name__ == "__main__":
    unittest.main()
