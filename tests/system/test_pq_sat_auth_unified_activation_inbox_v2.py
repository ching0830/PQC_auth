from __future__ import annotations

import json
import multiprocessing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from pq_sat_auth.replay import InvalidTransition
from pq_sat_auth.v2.access import (
    decode_session_activate,
    derive_activation_digest,
)
from pq_sat_auth.v2.activation import (
    ActivationCommitRequestV2,
    FGSActivationProcessorV2,
)
from pq_sat_auth.v2.application import (
    FGSFirstApplicationRecordProcessorV2,
    FGSFirstRecordDispositionV2,
    FirstApplicationInboxStateV2,
    derive_first_application_record_digest,
)
from pq_sat_auth.v2.dispatch import (
    ApplicationDispatchDispositionV2,
    FGSApplicationInboxDispatcherV2,
)
from pq_sat_auth.v2.replay import GrantStateV2
from pq_sat_auth.v2.storage.sqlite_first_record import SQLiteFirstRecordOutboxV2
from pq_sat_auth.v2.storage.sqlite_unified import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    SQLiteFGSUnifiedActivationInboxStoreV2,
    UnifiedActivationInboxIntegrityError,
    sqlite_unified_activation_inbox_manifest,
)
from tests.system.test_pq_sat_auth_activation_v2 import (
    ActivationKeySchedule,
    ActivationRevocationProvider,
)
from tests.system.test_pq_sat_auth_application_inbox_v2 import (
    InboxProtectionTestBackend,
    SQLiteIdempotentApplicationTestBackend,
)
from tests.system.test_pq_sat_auth_first_application_v2 import (
    PLAINTEXT,
    FirstApplicationFixture,
)
from tests.system.test_pq_sat_auth_grant_v2 import GrantClock
from tests.system.test_pq_sat_auth_sqlite_replay_v2 import (
    ReplayProtectionTestBackend,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    ROOT
    / "manifests"
    / "pq_sat_auth_fgs_unified_activation_inbox_sqlite_v0_2.json"
)


def _atomic_process_worker(
    path: str,
    request: ActivationCommitRequestV2,
    record_digest: bytes,
    plaintext: bytes,
    start,
    output,
) -> None:
    try:
        store = SQLiteFGSUnifiedActivationInboxStoreV2(
            Path(path),
            ReplayProtectionTestBackend(),
            InboxProtectionTestBackend(),
            busy_timeout_ms=20_000,
        )
        start.wait(10)
        result = store.activate_and_enqueue(
            request,
            record_digest,
            plaintext,
        )
        output.put(
            (
                "ok",
                result.activation.disposition.value,
                result.inbox.disposition.value,
            )
        )
    except Exception as error:
        output.put(("error", type(error).__name__, str(error)))


class UnifiedActivationInboxTests(FirstApplicationFixture):
    def setUp(self) -> None:
        super().setUp()
        self.unified_path = (
            Path(self.temporary.name) / "fgs-unified-activation-inbox.sqlite3"
        )
        self.replay_protection = ReplayProtectionTestBackend()
        self.inbox_protection = InboxProtectionTestBackend()
        self.unified = self.open_unified()
        self.install_pending_grant()

    def open_unified(self) -> SQLiteFGSUnifiedActivationInboxStoreV2:
        return SQLiteFGSUnifiedActivationInboxStoreV2(
            self.unified_path,
            self.replay_protection,
            self.inbox_protection,
            busy_timeout_ms=20_000,
        )

    def install_pending_grant(self) -> None:
        grant = self.grant_record
        self.unified.reserve(
            grant.identity,
            attempt_id=grant.attempt_id,
            request_digest=grant.request_digest,
            serving_context_digest=grant.serving_context_digest,
            reserved_at=max(0, grant.consumed_at - 1),
            lease_deadline=grant.consumed_at,
            revocation_generation=grant.revocation_generation,
        )
        self.unified.commit_grant(
            grant.identity,
            fencing_generation=1,
            attempt_id=grant.attempt_id,
            request_digest=grant.request_digest,
            transcript_digest=grant.transcript_digest,
            session_id=grant.session_id,
            response_digest=grant.response_digest,
            sealed_response=grant.sealed_response,
            sealed_session_state=grant.sealed_session_state,
            serving_context_digest=grant.serving_context_digest,
            fgs_id=grant.fgs_id,
            revocation_generation=grant.revocation_generation,
            consumed_at=grant.consumed_at,
            activation_deadline=grant.activation_deadline,
            session_expiry=grant.session_expiry,
            retention_deadline=grant.retention_deadline,
        )

    def activation_processor(
        self,
        store: SQLiteFGSUnifiedActivationInboxStoreV2 | None = None,
    ) -> FGSActivationProcessorV2:
        return FGSActivationProcessorV2(
            replay_store=self.unified if store is None else store,
            clock=GrantClock(),
            revocation_provider=ActivationRevocationProvider(
                self.grant_record.revocation_generation
            ),
            key_schedule_backend=ActivationKeySchedule(),
            recovery_backend=self.recovery,
        )

    def first_processor(
        self,
        store: SQLiteFGSUnifiedActivationInboxStoreV2 | None = None,
    ) -> FGSFirstApplicationRecordProcessorV2:
        selected = self.unified if store is None else store
        return FGSFirstApplicationRecordProcessorV2(
            activation_processor=self.activation_processor(selected),
            protection_backend=self.application_protection,
            atomic_inbox_store=selected,
        )

    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            sqlite_unified_activation_inbox_manifest(),
        )

    def test_schema_is_one_database_with_exactly_two_tables(self) -> None:
        connection = sqlite3.connect(self.unified_path)
        try:
            application_id = connection.execute(
                "PRAGMA application_id"
            ).fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            }
            databases = connection.execute("PRAGMA database_list").fetchall()
        finally:
            connection.close()
        self.assertEqual(application_id, (APPLICATION_ID,))
        self.assertEqual(user_version, (SCHEMA_VERSION,))
        self.assertEqual(
            tables,
            {"fgs_replay_records", "first_application_inbox"},
        )
        self.assertEqual([row[1] for row in databases], ["main"])

    def test_database_identity_extra_table_and_inbox_mutation_fail_closed(self) -> None:
        identity_path = Path(self.temporary.name) / "wrong-identity.sqlite3"
        SQLiteFGSUnifiedActivationInboxStoreV2(
            identity_path,
            ReplayProtectionTestBackend(),
            InboxProtectionTestBackend(),
        )
        connection = sqlite3.connect(identity_path)
        try:
            connection.execute("PRAGMA application_id = 0")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(UnifiedActivationInboxIntegrityError):
            SQLiteFGSUnifiedActivationInboxStoreV2(
                identity_path,
                ReplayProtectionTestBackend(),
                InboxProtectionTestBackend(),
            )

        schema_path = Path(self.temporary.name) / "extra-table.sqlite3"
        SQLiteFGSUnifiedActivationInboxStoreV2(
            schema_path,
            ReplayProtectionTestBackend(),
            InboxProtectionTestBackend(),
        )
        connection = sqlite3.connect(schema_path)
        try:
            connection.execute("CREATE TABLE unexpected(value INTEGER)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(UnifiedActivationInboxIntegrityError):
            SQLiteFGSUnifiedActivationInboxStoreV2(
                schema_path,
                ReplayProtectionTestBackend(),
                InboxProtectionTestBackend(),
            )

        prepared = self.prepare()
        result = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(result.accepted, result.failures)
        connection = sqlite3.connect(self.unified_path)
        try:
            connection.execute(
                "UPDATE first_application_inbox SET protected_record = ?",
                (b"tampered",),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(UnifiedActivationInboxIntegrityError):
            self.unified.load(self.grant_record.session_id)

    def test_new_record_activates_and_enqueues_before_success(self) -> None:
        prepared = self.prepare()
        result = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(result.accepted, result.failures)
        self.assertIs(result.disposition, FGSFirstRecordDispositionV2.QUEUED)
        self.assertIsNone(result.delivery)
        self.assertIsNotNone(result.inbox)

        replay = self.unified.lookup(self.grant_record.identity)
        self.assertIsNotNone(replay)
        self.assertIs(replay.state, GrantStateV2.CONSUMED_ACTIVE)  # type: ignore[union-attr]
        inbox = self.unified.load(self.grant_record.session_id)
        self.assertIsNotNone(inbox)
        self.assertIs(inbox.state, FirstApplicationInboxStateV2.PENDING)  # type: ignore[union-attr]
        self.assertEqual(inbox.plaintext, PLAINTEXT)  # type: ignore[union-attr]

    def test_inbox_seal_failure_rolls_activation_back(self) -> None:
        prepared = self.prepare()
        self.inbox_protection.broken_seal = True
        failed = self.first_processor().process(prepared.record_bytes)
        self.assertFalse(failed.accepted)
        self.assertIs(
            failed.disposition,
            FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
        )
        replay = self.unified.lookup(self.grant_record.identity)
        self.assertIs(replay.state, GrantStateV2.CONSUMED_PENDING_CONFIRM)  # type: ignore[union-attr]
        self.assertIsNone(self.unified.load(self.grant_record.session_id))

        self.inbox_protection.broken_seal = False
        recovered = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(recovered.accepted, recovered.failures)
        self.assertIs(recovered.disposition, FGSFirstRecordDispositionV2.QUEUED)

    def test_exact_retry_survives_store_restart(self) -> None:
        prepared = self.prepare()
        first = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(first.accepted, first.failures)

        restarted = self.open_unified()
        retry = self.first_processor(restarted).process(prepared.record_bytes)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_QUEUED,
        )
        self.assertEqual(restarted.inbox_count(), 1)

    def test_competing_processes_commit_one_atomic_pair(self) -> None:
        prepared = self.prepare()
        assert prepared.record is not None
        activation = decode_session_activate(prepared.record.activation_bytes)
        request = ActivationCommitRequestV2(
            identity=self.grant_record.identity,
            attempt_id=self.grant_record.attempt_id,
            request_digest=self.grant_record.request_digest,
            session_id=self.grant_record.session_id,
            response_digest=self.grant_record.response_digest,
            client_confirmation_digest=derive_activation_digest(activation),
            activated_at=GrantClock().now(),
        )
        digest = derive_first_application_record_digest(prepared.record)
        context = multiprocessing.get_context("fork")
        start = context.Event()
        output = context.Queue()
        workers = [
            context.Process(
                target=_atomic_process_worker,
                args=(
                    str(self.unified_path),
                    request,
                    digest,
                    PLAINTEXT,
                    start,
                    output,
                ),
            )
            for _ in range(4)
        ]
        for worker in workers:
            worker.start()
        start.set()
        results = [output.get(timeout=20) for _ in workers]
        for worker in workers:
            worker.join(20)
            self.assertEqual(worker.exitcode, 0)
        self.assertTrue(all(result[0] == "ok" for result in results), results)
        self.assertEqual(
            sum(result[1:] == ("new", "new") for result in results),
            1,
        )
        self.assertEqual(
            sum(
                result[1:] == ("existing_active", "existing_pending")
                for result in results
            ),
            3,
        )
        self.assertEqual(self.unified.inbox_count(), 1)

    def test_competing_authenticated_first_record_cannot_replace_inbox(self) -> None:
        first = self.prepare()
        accepted = self.first_processor().process(first.record_bytes)
        self.assertTrue(accepted.accepted, accepted.failures)

        competing_outbox = SQLiteFirstRecordOutboxV2(
            Path(self.temporary.name) / "competing-first-record.sqlite3"
        )
        competing = self.ue_first_processor(outbox=competing_outbox).process(
            self.session,
            b"competing authenticated plaintext",
        )
        self.assertTrue(competing.accepted, competing.failures)
        rejected = self.first_processor().process(competing.record_bytes)
        self.assertFalse(rejected.accepted)
        self.assertIs(
            rejected.disposition,
            FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
        )
        inbox = self.unified.load(self.grant_record.session_id)
        self.assertEqual(inbox.plaintext, PLAINTEXT)  # type: ignore[union-attr]
        self.assertEqual(self.unified.inbox_count(), 1)

    def test_dispatch_completion_and_record_retry_remain_idempotent(self) -> None:
        prepared = self.prepare()
        queued = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(queued.accepted, queued.failures)
        application = SQLiteIdempotentApplicationTestBackend(
            Path(self.temporary.name) / "application-ledger.sqlite3"
        )
        dispatched = FGSApplicationInboxDispatcherV2(
            inbox_store=self.unified,
            application_backend=application,
        ).process(self.grant_record.session_id)
        self.assertTrue(dispatched.accepted, dispatched.failures)
        self.assertIs(
            dispatched.disposition,
            ApplicationDispatchDispositionV2.COMPLETED,
        )
        retry = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(
            retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_COMPLETED,
        )
        self.assertEqual(application.effect_count(), 1)

    def test_queued_work_can_complete_after_active_session_expires(self) -> None:
        prepared = self.prepare()
        queued = self.first_processor().process(prepared.record_bytes)
        self.assertTrue(queued.accepted, queued.failures)
        self.unified.expire(
            self.grant_record.identity,
            expired_at=self.grant_record.session_expiry + 1,
            reason="session lifetime elapsed after accepted record",
        )
        self.assertEqual(self.unified.pending(), (self.grant_record.session_id,))
        application = SQLiteIdempotentApplicationTestBackend(
            Path(self.temporary.name) / "expired-application-ledger.sqlite3"
        )
        dispatched = FGSApplicationInboxDispatcherV2(
            inbox_store=self.unified,
            application_backend=application,
        ).process(self.grant_record.session_id)
        self.assertTrue(dispatched.accepted, dispatched.failures)
        self.assertIs(
            dispatched.disposition,
            ApplicationDispatchDispositionV2.COMPLETED,
        )

    def test_direct_activation_is_disabled_for_unified_store(self) -> None:
        with self.assertRaisesRegex(InvalidTransition, "activate_and_enqueue"):
            self.unified.activate_session(
                self.grant_record.identity,
                attempt_id=self.grant_record.attempt_id,
                request_digest=self.grant_record.request_digest,
                session_id=self.grant_record.session_id,
                response_digest=self.grant_record.response_digest,
                client_confirmation_digest=b"c" * 32,
                activated_at=self.grant_record.consumed_at,
            )

    def test_processor_rejects_distinct_atomic_and_replay_store_objects(self) -> None:
        other_path = Path(self.temporary.name) / "other-unified.sqlite3"
        other = SQLiteFGSUnifiedActivationInboxStoreV2(
            other_path,
            ReplayProtectionTestBackend(),
            InboxProtectionTestBackend(),
        )
        with self.assertRaisesRegex(ValueError, "must be the activation"):
            FGSFirstApplicationRecordProcessorV2(
                activation_processor=self.activation_processor(),
                protection_backend=self.application_protection,
                atomic_inbox_store=other,
            )


if __name__ == "__main__":
    unittest.main()
