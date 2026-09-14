#!/usr/bin/env python3
"""Real SQLite transaction, process-concurrency, and restart tests."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import queue
import sqlite3
import tempfile
import unittest
from pathlib import Path

from pq_rbbc.contracts.system import ContractError
from pq_rbbc.governance.issuer_authorization import QuotaConsumeStatus
from pq_rbbc.governance.storage import (
    SQLITE_APPLICATION_ID,
    SQLiteIssuerQuotaStore,
    SQLiteQuotaStoreBusyError,
    SQLiteQuotaStoreCorruptError,
    SQLiteQuotaStoreSchemaError,
    sqlite_quota_store_manifest,
)


def _digest(label: bytes) -> bytes:
    return hashlib.sha256(b"PQRBBC/sqlite-quota-test/" + label).digest()


def _consume_worker(
    database_path: str,
    grant_digest: bytes,
    issuer_sid: bytes,
    quota_value: int,
    start_barrier: object,
    output_queue: object,
) -> None:
    try:
        store = SQLiteIssuerQuotaStore(database_path, busy_timeout_ms=10_000)
        start_barrier.wait(timeout=20)
        result = store.consume(grant_digest, issuer_sid, quota_value)
        output_queue.put(("result", result.status.value, result.remaining))
    except BaseException as error:
        output_queue.put(("error", type(error).__name__, str(error)))


class _CommitGateStore(SQLiteIssuerQuotaStore):
    def __init__(
        self,
        database_path: str,
        reached: object,
        release: object,
        *,
        gate_after_commit: bool,
    ) -> None:
        self._gate_armed = False
        self._reached = reached
        self._release = release
        self._gate_after_commit = gate_after_commit
        super().__init__(database_path, busy_timeout_ms=10_000)
        self._gate_armed = True

    def _commit_transaction(self, connection: sqlite3.Connection) -> None:
        if not self._gate_armed:
            super()._commit_transaction(connection)
            return
        if self._gate_after_commit:
            super()._commit_transaction(connection)
            self._reached.set()
            self._release.wait(timeout=20)
        else:
            self._reached.set()
            self._release.wait(timeout=20)
            super()._commit_transaction(connection)


def _commit_gate_worker(
    database_path: str,
    grant_digest: bytes,
    issuer_sid: bytes,
    quota_value: int,
    reached: object,
    release: object,
    gate_after_commit: bool,
) -> None:
    store = _CommitGateStore(
        database_path,
        reached,
        release,
        gate_after_commit=gate_after_commit,
    )
    store.consume(grant_digest, issuer_sid, quota_value)


class _InjectedTransactionFailure(RuntimeError):
    pass


class _RollbackProbeStore(SQLiteIssuerQuotaStore):
    def __init__(self, database_path: str) -> None:
        self._probe_armed = False
        super().__init__(database_path)
        self._probe_armed = True

    def _commit_transaction(self, connection: sqlite3.Connection) -> None:
        if self._probe_armed:
            raise _InjectedTransactionFailure("before commit")
        super()._commit_transaction(connection)


class SQLiteQuotaSemanticsTests(unittest.TestCase):
    def test_path_free_manifest_matches_implementation(self) -> None:
        root = Path(__file__).resolve().parents[4]
        manifest_path = (
            root
            / "manifests"
            / "system_governance"
            / "issuer_quota_sqlite_v1.json"
        )
        self.assertEqual(
            sqlite_quota_store_manifest(),
            json.loads(manifest_path.read_text(encoding="utf-8")),
        )

    def test_restart_preserves_remaining_quota_and_sid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            grant_digest = _digest(b"restart")
            first_store = SQLiteIssuerQuotaStore(database_path)
            first = first_store.consume(grant_digest, b"sid-a", 3)
            self.assertEqual(first.status, QuotaConsumeStatus.CONSUMED)
            self.assertEqual(first.remaining, 2)

            reopened = SQLiteIssuerQuotaStore(database_path)
            replay = reopened.consume(grant_digest, b"sid-a", 3)
            second = reopened.consume(grant_digest, b"sid-b", 3)
            self.assertEqual(replay.status, QuotaConsumeStatus.REPLAY)
            self.assertEqual(replay.remaining, 2)
            self.assertEqual(second.status, QuotaConsumeStatus.CONSUMED)
            self.assertEqual(second.remaining, 1)

    def test_same_sid_under_different_grant_digest_is_not_global_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = SQLiteIssuerQuotaStore(
                str(Path(temporary_directory) / "quota.sqlite3")
            )
            first = store.consume(_digest(b"grant-a"), b"shared-sid", 1)
            second = store.consume(_digest(b"grant-b"), b"shared-sid", 1)
            self.assertEqual(first.status, QuotaConsumeStatus.CONSUMED)
            self.assertEqual(second.status, QuotaConsumeStatus.CONSUMED)

    def test_existing_grant_cannot_be_reinitialized_with_another_quota(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            grant_digest = _digest(b"quota-change")
            SQLiteIssuerQuotaStore(database_path).consume(
                grant_digest, b"first-sid", 4
            )
            reopened = SQLiteIssuerQuotaStore(database_path)
            with self.assertRaises(ContractError):
                reopened.consume(grant_digest, b"second-sid", 5)
            replay = reopened.consume(grant_digest, b"first-sid", 4)
            self.assertEqual(replay.status, QuotaConsumeStatus.REPLAY)
            self.assertEqual(replay.remaining, 3)

    def test_u64_quota_is_not_truncated_to_sqlite_signed_integer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = SQLiteIssuerQuotaStore(
                str(Path(temporary_directory) / "quota.sqlite3")
            )
            maximum = (1 << 64) - 1
            result = store.consume(_digest(b"u64"), b"sid", maximum)
            self.assertEqual(result.status, QuotaConsumeStatus.CONSUMED)
            self.assertEqual(result.remaining, maximum - 1)

    def test_exception_before_commit_rolls_back_entire_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            grant_digest = _digest(b"rollback")
            with self.assertRaises(_InjectedTransactionFailure):
                _RollbackProbeStore(database_path).consume(
                    grant_digest, b"rollback-sid", 2
                )

            result = SQLiteIssuerQuotaStore(database_path).consume(
                grant_digest, b"rollback-sid", 2
            )
            self.assertEqual(result.status, QuotaConsumeStatus.CONSUMED)
            self.assertEqual(result.remaining, 1)

    def test_connection_is_closed_and_writer_lock_is_released(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            store = SQLiteIssuerQuotaStore(database_path)
            store.consume(_digest(b"lifecycle"), b"sid", 1)
            connection = sqlite3.connect(database_path, isolation_level=None)
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            finally:
                connection.close()


class SQLiteQuotaConcurrencyTests(unittest.TestCase):
    def _run_contenders(
        self,
        database_path: str,
        grant_digest: bytes,
        issuer_sids: list[bytes],
        quota_value: int,
    ) -> list[tuple[str, str, int | str]]:
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(len(issuer_sids))
        output_queue = context.Queue()
        processes = [
            context.Process(
                target=_consume_worker,
                args=(
                    database_path,
                    grant_digest,
                    issuer_sid,
                    quota_value,
                    barrier,
                    output_queue,
                ),
            )
            for issuer_sid in issuer_sids
        ]
        for process in processes:
            process.start()
        results = []
        for _ in processes:
            try:
                results.append(output_queue.get(timeout=30))
            except queue.Empty as error:
                self.fail(f"worker result timed out: {error}")
        for process in processes:
            process.join(timeout=10)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
            self.assertEqual(process.exitcode, 0)
        errors = [result for result in results if result[0] == "error"]
        self.assertEqual(errors, [])
        return results

    def test_multiple_processes_contend_for_last_quota(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            SQLiteIssuerQuotaStore(database_path)
            results = self._run_contenders(
                database_path,
                _digest(b"last-quota"),
                [f"sid-{index}".encode("ascii") for index in range(8)],
                1,
            )
            statuses = [result[1] for result in results]
            self.assertEqual(statuses.count("consumed"), 1)
            self.assertEqual(statuses.count("exhausted"), 7)

    def test_multiple_processes_contend_for_same_sid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            SQLiteIssuerQuotaStore(database_path)
            results = self._run_contenders(
                database_path,
                _digest(b"same-sid"),
                [b"same-sid"] * 8,
                8,
            )
            statuses = [result[1] for result in results]
            self.assertEqual(statuses.count("consumed"), 1)
            self.assertEqual(statuses.count("replay"), 7)
            self.assertTrue(all(result[2] == 7 for result in results))

    def test_simultaneous_first_grant_creation_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            SQLiteIssuerQuotaStore(database_path)
            results = self._run_contenders(
                database_path,
                _digest(b"first-create"),
                [f"first-{index}".encode("ascii") for index in range(6)],
                6,
            )
            self.assertTrue(all(result[1] == "consumed" for result in results))
            self.assertEqual(sorted(int(result[2]) for result in results), list(range(6)))


class SQLiteQuotaProcessTerminationTests(unittest.TestCase):
    def _kill_at_commit_boundary(self, gate_after_commit: bool):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        database_path = str(Path(temporary_directory.name) / "quota.sqlite3")
        SQLiteIssuerQuotaStore(database_path)
        context = multiprocessing.get_context("spawn")
        reached = context.Event()
        release = context.Event()
        process = context.Process(
            target=_commit_gate_worker,
            args=(
                database_path,
                _digest(b"process-termination"),
                b"termination-sid",
                2,
                reached,
                release,
                gate_after_commit,
            ),
        )
        process.start()
        self.assertTrue(reached.wait(timeout=20), "child did not reach commit gate")
        process.kill()
        process.join(timeout=10)
        self.assertIsNotNone(process.exitcode)
        self.assertNotEqual(process.exitcode, 0)
        return database_path

    def test_process_killed_before_commit_does_not_consume(self) -> None:
        database_path = self._kill_at_commit_boundary(False)
        result = SQLiteIssuerQuotaStore(database_path).consume(
            _digest(b"process-termination"), b"termination-sid", 2
        )
        self.assertEqual(result.status, QuotaConsumeStatus.CONSUMED)
        self.assertEqual(result.remaining, 1)

    def test_process_killed_after_commit_before_reply_replays(self) -> None:
        database_path = self._kill_at_commit_boundary(True)
        result = SQLiteIssuerQuotaStore(database_path).consume(
            _digest(b"process-termination"), b"termination-sid", 2
        )
        self.assertEqual(result.status, QuotaConsumeStatus.REPLAY)
        self.assertEqual(result.remaining, 1)


class SQLiteQuotaFailureTests(unittest.TestCase):
    def test_busy_writer_fails_closed_without_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            store = SQLiteIssuerQuotaStore(database_path, busy_timeout_ms=25)
            locker = sqlite3.connect(database_path, isolation_level=None)
            try:
                locker.execute("BEGIN IMMEDIATE")
                with self.assertRaises(SQLiteQuotaStoreBusyError):
                    store.consume(_digest(b"busy"), b"sid", 1)
                locker.rollback()
            finally:
                locker.close()
            result = store.consume(_digest(b"busy"), b"sid", 1)
            self.assertEqual(result.status, QuotaConsumeStatus.CONSUMED)

    def test_corrupt_database_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "quota.sqlite3"
            database_path.write_bytes(b"not a sqlite database")
            with self.assertRaises(SQLiteQuotaStoreCorruptError):
                SQLiteIssuerQuotaStore(str(database_path))

    def test_unknown_schema_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            SQLiteIssuerQuotaStore(database_path)
            connection = sqlite3.connect(database_path, isolation_level=None)
            try:
                connection.execute("PRAGMA user_version = 2")
            finally:
                connection.close()
            with self.assertRaises(SQLiteQuotaStoreSchemaError):
                SQLiteIssuerQuotaStore(database_path)

    def test_same_version_schema_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            SQLiteIssuerQuotaStore(database_path)
            connection = sqlite3.connect(database_path, isolation_level=None)
            try:
                connection.execute("CREATE TABLE unexpected(value INTEGER)")
            finally:
                connection.close()
            with self.assertRaises(SQLiteQuotaStoreSchemaError):
                SQLiteIssuerQuotaStore(database_path)

    def test_wrong_application_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = str(Path(temporary_directory) / "quota.sqlite3")
            SQLiteIssuerQuotaStore(database_path)
            connection = sqlite3.connect(database_path, isolation_level=None)
            try:
                connection.execute(
                    f"PRAGMA application_id = {SQLITE_APPLICATION_ID + 1}"
                )
            finally:
                connection.close()
            with self.assertRaises(SQLiteQuotaStoreSchemaError):
                SQLiteIssuerQuotaStore(database_path)

    def test_non_persistent_paths_and_invalid_inputs_reject(self) -> None:
        with self.assertRaises(ValueError):
            SQLiteIssuerQuotaStore(":memory:")
        with self.assertRaises(ValueError):
            SQLiteIssuerQuotaStore("relative.sqlite3")
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = SQLiteIssuerQuotaStore(
                str(Path(temporary_directory) / "quota.sqlite3")
            )
            with self.assertRaises(ContractError):
                store.consume(bytes(31), b"sid", 1)
            with self.assertRaises(ContractError):
                store.consume(_digest(b"input"), b"", 1)
            with self.assertRaises(ContractError):
                store.consume(_digest(b"input"), b"sid", 0)


if __name__ == "__main__":
    unittest.main()
