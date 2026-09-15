from __future__ import annotations

import json
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.replay import InvalidTransition
from pq_sat_auth.v2.access import (
    decode_session_activate,
    derive_activation_digest,
)
from pq_sat_auth.v2.activation import (
    ActivationCommitRequestV2,
    ActivationRevocationSnapshotV2,
    FGSActivationProcessorV2,
)
from pq_sat_auth.v2.application import (
    FGSFirstApplicationRecordProcessorV2,
    FGSFirstRecordDispositionV2,
)
from pq_sat_auth.v2.dispatch import (
    ApplicationDispatchDispositionV2,
    FGSApplicationInboxDispatcherV2,
)
from pq_sat_auth.v2.replay import GrantStateV2
from pq_sat_auth.v2.storage.sqlite_authoritative import (
    APPLICATION_ID,
    FENCE_RECORD_BYTES,
    SCHEMA_VERSION,
    ActivationRevocationFenceChanged,
    ActivationRevocationFenceRecordV2,
    ActivationRevocationFenceUnavailable,
    SQLiteFGSAuthoritativeActivationInboxStoreV2,
    decode_activation_revocation_fence,
    derive_activation_revocation_fence_checksum,
    encode_activation_revocation_fence,
    sqlite_authoritative_activation_inbox_manifest,
)
from pq_sat_auth.v2.storage.sqlite_unified import (
    UnifiedActivationInboxIntegrityError,
)
from tests.system.test_pq_sat_auth_activation_v2 import ActivationKeySchedule
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
    / "pq_sat_auth_fgs_authoritative_activation_inbox_sqlite_v0_2.json"
)


class PublishAfterSnapshot:
    def __init__(
        self,
        store: SQLiteFGSAuthoritativeActivationInboxStoreV2,
        *,
        revoke: bool,
    ) -> None:
        self.store = store
        self.revoke = revoke

    def snapshot(self, query):
        checked = self.store.snapshot(query)
        self.store.publish_activation_revocation(
            replace(
                checked,
                generation=checked.generation + 1,
                ticket_revoked=self.revoke,
            )
        )
        return checked


class AuthoritativeActivationFixture(FirstApplicationFixture):
    def setUp(self) -> None:
        super().setUp()
        self.authoritative_path = (
            Path(self.temporary.name) / "fgs-authoritative.sqlite3"
        )
        self.replay_protection = ReplayProtectionTestBackend()
        self.inbox_protection = InboxProtectionTestBackend()
        self.authoritative = self.open_authoritative()
        self.install_pending_grant()
        assert self.recovery.last_state is not None
        self.query = FGSActivationProcessorV2._activation_revocation_query(
            self.response,
            self.grant_record,
            self.recovery.last_state,
        )
        self.snapshot = ActivationRevocationSnapshotV2(
            query_digest=self.query.digest,
            generation=self.grant_record.revocation_generation,
            effective_at=0,
            valid_until=(1 << 63) - 1,
        )
        self.authoritative.publish_activation_revocation(self.snapshot)

    def open_authoritative(
        self,
    ) -> SQLiteFGSAuthoritativeActivationInboxStoreV2:
        return SQLiteFGSAuthoritativeActivationInboxStoreV2(
            self.authoritative_path,
            self.replay_protection,
            self.inbox_protection,
            busy_timeout_ms=20_000,
        )

    def install_pending_grant(self) -> None:
        grant = self.grant_record
        self.authoritative.reserve(
            grant.identity,
            attempt_id=grant.attempt_id,
            request_digest=grant.request_digest,
            serving_context_digest=grant.serving_context_digest,
            reserved_at=max(0, grant.consumed_at - 1),
            lease_deadline=grant.consumed_at,
            revocation_generation=grant.revocation_generation,
        )
        self.authoritative.commit_grant(
            grant.identity,
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

    def authoritative_activation_processor(
        self,
        provider=None,
    ) -> FGSActivationProcessorV2:
        return FGSActivationProcessorV2(
            replay_store=self.authoritative,
            clock=GrantClock(),
            revocation_provider=(
                self.authoritative if provider is None else provider
            ),
            key_schedule_backend=ActivationKeySchedule(),
            recovery_backend=self.recovery,
        )

    def authoritative_first_processor(
        self,
        provider=None,
    ) -> FGSFirstApplicationRecordProcessorV2:
        return FGSFirstApplicationRecordProcessorV2(
            activation_processor=self.authoritative_activation_processor(
                provider
            ),
            protection_backend=self.application_protection,
            atomic_inbox_store=self.authoritative,
        )

    def commit_request(self, prepared) -> ActivationCommitRequestV2:
        activation = decode_session_activate(prepared.record.activation_bytes)
        return ActivationCommitRequestV2(
            identity=self.grant_record.identity,
            attempt_id=self.grant_record.attempt_id,
            request_digest=self.grant_record.request_digest,
            session_id=self.grant_record.session_id,
            response_digest=self.grant_record.response_digest,
            client_confirmation_digest=derive_activation_digest(activation),
            activated_at=GrantClock().now(),
            revocation_query=self.query,
            revocation_snapshot=self.snapshot,
        )


class AuthoritativeActivationTests(AuthoritativeActivationFixture):
    def test_manifest_matches_implementation(self) -> None:
        self.assertEqual(
            json.loads(MANIFEST.read_text(encoding="utf-8")),
            sqlite_authoritative_activation_inbox_manifest(),
        )

    def test_fence_codec_is_exact_and_canonical(self) -> None:
        record = ActivationRevocationFenceRecordV2(self.snapshot, 1)
        encoded = encode_activation_revocation_fence(record)
        self.assertEqual(len(encoded), FENCE_RECORD_BYTES)
        self.assertEqual(decode_activation_revocation_fence(encoded), record)
        self.assertEqual(
            len(derive_activation_revocation_fence_checksum(encoded)),
            32,
        )
        for changed in (encoded[:-1], encoded + b"\x00"):
            with self.subTest(length=len(changed)):
                with self.assertRaises(UnifiedActivationInboxIntegrityError):
                    decode_activation_revocation_fence(changed)
        invalid_flag = encoded[:-1] + b"\x02"
        with self.assertRaises(UnifiedActivationInboxIntegrityError):
            decode_activation_revocation_fence(invalid_flag)

    def test_new_record_and_exact_retry_use_same_atomic_pair(self) -> None:
        prepared = self.prepare()
        processor = self.authoritative_first_processor()
        first = processor.process(prepared.record_bytes)
        retry = processor.process(prepared.record_bytes)
        self.assertTrue(first.accepted, first.failures)
        self.assertTrue(retry.accepted, retry.failures)
        self.assertIs(first.disposition, FGSFirstRecordDispositionV2.QUEUED)
        self.assertIs(
            retry.disposition,
            FGSFirstRecordDispositionV2.ALREADY_QUEUED,
        )
        replay = self.authoritative.lookup(self.grant_record.identity)
        self.assertIs(replay.state, GrantStateV2.CONSUMED_ACTIVE)  # type: ignore[union-attr]
        self.assertEqual(self.authoritative.inbox_count(), 1)
        restarted = self.open_authoritative()
        self.assertEqual(restarted.snapshot(self.query), self.snapshot)
        self.assertEqual(restarted.inbox_count(), 1)

    def test_revocation_committing_before_activation_rolls_back_pair(self) -> None:
        prepared = self.prepare()
        result = self.authoritative_first_processor(
            PublishAfterSnapshot(self.authoritative, revoke=True)
        ).process(prepared.record_bytes)
        self.assertFalse(result.accepted)
        self.assertIs(
            result.disposition,
            FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
        )
        self.assertIn("ActivationRevocationFenceChanged", result.failures[0])
        replay = self.authoritative.lookup(self.grant_record.identity)
        self.assertIs(  # type: ignore[union-attr]
            replay.state,
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        self.assertEqual(self.authoritative.inbox_count(), 0)

    def test_nonrevoked_generation_race_requires_fresh_retry(self) -> None:
        prepared = self.prepare()
        stale = self.authoritative_first_processor(
            PublishAfterSnapshot(self.authoritative, revoke=False)
        ).process(prepared.record_bytes)
        self.assertFalse(stale.accepted)
        self.assertIs(
            stale.disposition,
            FGSFirstRecordDispositionV2.COMMIT_UNCERTAIN,
        )
        fresh = self.authoritative_first_processor().process(
            prepared.record_bytes
        )
        self.assertTrue(fresh.accepted, fresh.failures)
        self.assertIs(fresh.disposition, FGSFirstRecordDispositionV2.QUEUED)

    def test_published_revocation_rejects_before_commit(self) -> None:
        self.authoritative.publish_activation_revocation(
            replace(
                self.snapshot,
                generation=self.snapshot.generation + 1,
                ticket_revoked=True,
            )
        )
        prepared = self.prepare()
        result = self.authoritative_first_processor().process(
            prepared.record_bytes
        )
        self.assertFalse(result.accepted)
        self.assertIs(result.disposition, FGSFirstRecordDispositionV2.REJECTED)
        self.assertEqual(result.failures, ("activation:activation_revoked",))
        replay = self.authoritative.lookup(self.grant_record.identity)
        self.assertIs(  # type: ignore[union-attr]
            replay.state,
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        self.assertEqual(self.authoritative.inbox_count(), 0)

    def test_activation_winning_before_revocation_preserves_queued_work(
        self,
    ) -> None:
        prepared = self.prepare()
        accepted = self.authoritative_first_processor().process(
            prepared.record_bytes
        )
        self.assertTrue(accepted.accepted, accepted.failures)
        self.authoritative.publish_activation_revocation(
            replace(
                self.snapshot,
                generation=self.snapshot.generation + 1,
                session_revoked=True,
            )
        )
        application = SQLiteIdempotentApplicationTestBackend(
            Path(self.temporary.name) / "authoritative-application.sqlite3"
        )
        dispatched = FGSApplicationInboxDispatcherV2(
            inbox_store=self.authoritative,
            application_backend=application,
        ).process(self.grant_record.session_id)
        self.assertTrue(dispatched.accepted, dispatched.failures)
        self.assertIs(
            dispatched.disposition,
            ApplicationDispatchDispositionV2.COMPLETED,
        )
        self.assertEqual(application.effect_count(), 1)

    def test_concurrent_publish_and_activation_have_one_valid_order(
        self,
    ) -> None:
        prepared = self.prepare()
        request = self.commit_request(prepared)
        revoked = replace(
            self.snapshot,
            generation=self.snapshot.generation + 1,
            ticket_revoked=True,
        )
        start = threading.Barrier(2)

        def activate():
            start.wait()
            try:
                return self.authoritative.activate_and_enqueue(
                    request,
                    b"r" * 32,
                    PLAINTEXT,
                )
            except ActivationRevocationFenceChanged as error:
                return error

        def publish():
            start.wait()
            return self.authoritative.publish_activation_revocation(revoked)

        with ThreadPoolExecutor(max_workers=2) as executor:
            activation_future = executor.submit(activate)
            publication_future = executor.submit(publish)
            activation_outcome = activation_future.result(timeout=10)
            publication_outcome = publication_future.result(timeout=10)

        self.assertEqual(publication_outcome.snapshot, revoked)
        replay = self.authoritative.lookup(self.grant_record.identity)
        if isinstance(activation_outcome, ActivationRevocationFenceChanged):
            self.assertIs(  # type: ignore[union-attr]
                replay.state,
                GrantStateV2.CONSUMED_PENDING_CONFIRM,
            )
            self.assertEqual(self.authoritative.inbox_count(), 0)
        else:
            self.assertIs(  # type: ignore[union-attr]
                replay.state,
                GrantStateV2.CONSUMED_ACTIVE,
            )
            self.assertEqual(self.authoritative.inbox_count(), 1)

    def test_publication_is_idempotent_monotonic_and_sticky(self) -> None:
        first = self.authoritative.publish_activation_revocation(self.snapshot)
        exact = self.authoritative.publish_activation_revocation(self.snapshot)
        self.assertEqual(exact, first)
        with self.assertRaises(InvalidTransition):
            self.authoritative.publish_activation_revocation(
                replace(self.snapshot, valid_until=self.snapshot.valid_until - 1)
            )
        revoked = replace(
            self.snapshot,
            generation=self.snapshot.generation + 1,
            ticket_revoked=True,
        )
        second = self.authoritative.publish_activation_revocation(revoked)
        self.assertEqual(second.revision, first.revision + 1)
        with self.assertRaises(InvalidTransition):
            self.authoritative.publish_activation_revocation(
                replace(
                    revoked,
                    generation=revoked.generation + 1,
                    ticket_revoked=False,
                )
            )

    def test_missing_or_unbound_fence_fails_without_consumption(self) -> None:
        prepared = self.prepare()
        connection = sqlite3.connect(self.authoritative_path)
        try:
            connection.execute("DELETE FROM activation_revocation_fences")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(ActivationRevocationFenceUnavailable):
            self.authoritative.activate_and_enqueue(
                self.commit_request(prepared),
                b"r" * 32,
                PLAINTEXT,
            )
        replay = self.authoritative.lookup(self.grant_record.identity)
        self.assertIs(  # type: ignore[union-attr]
            replay.state,
            GrantStateV2.CONSUMED_PENDING_CONFIRM,
        )
        self.assertEqual(self.authoritative.inbox_count(), 0)

    def test_store_requires_checked_query_and_snapshot_at_commit(self) -> None:
        prepared = self.prepare()
        request = replace(
            self.commit_request(prepared),
            revocation_query=None,
            revocation_snapshot=None,
        )
        with self.assertRaises(ActivationRevocationFenceUnavailable):
            self.authoritative.activate_and_enqueue(
                request,
                b"r" * 32,
                PLAINTEXT,
            )
        self.assertEqual(self.authoritative.inbox_count(), 0)

        with self.assertRaisesRegex(ValueError, "provided together"):
            replace(
                self.commit_request(prepared),
                revocation_snapshot=None,
            ).validate()

    def test_query_must_remain_bound_to_the_committed_grant(self) -> None:
        prepared = self.prepare()
        wrong_fgs_id = bytes((self.query.fgs_id[0] ^ 1,)) + self.query.fgs_id[1:]
        wrong_query = replace(self.query, fgs_id=wrong_fgs_id)
        wrong_snapshot = replace(
            self.snapshot,
            query_digest=wrong_query.digest,
        )
        request = replace(
            self.commit_request(prepared),
            revocation_query=wrong_query,
            revocation_snapshot=wrong_snapshot,
        )
        with self.assertRaisesRegex(
            InvalidTransition,
            "context and grant differ",
        ):
            self.authoritative.activate_and_enqueue(
                request,
                b"r" * 32,
                PLAINTEXT,
            )
        self.assertEqual(self.authoritative.inbox_count(), 0)

    def test_changed_snapshot_is_rejected_inside_transaction(self) -> None:
        prepared = self.prepare()
        changed = replace(
            self.snapshot,
            generation=self.snapshot.generation + 1,
        )
        self.authoritative.publish_activation_revocation(changed)
        with self.assertRaises(ActivationRevocationFenceChanged):
            self.authoritative.activate_and_enqueue(
                self.commit_request(prepared),
                b"r" * 32,
                PLAINTEXT,
            )
        self.assertEqual(self.authoritative.inbox_count(), 0)

    def test_schema_identity_extra_table_and_row_mutation_fail_closed(
        self,
    ) -> None:
        connection = sqlite3.connect(self.authoritative_path)
        try:
            self.assertEqual(
                connection.execute("PRAGMA application_id").fetchone(),
                (APPLICATION_ID,),
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone(),
                (SCHEMA_VERSION,),
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(
                tables,
                {
                    "fgs_replay_records",
                    "first_application_inbox",
                    "activation_revocation_fences",
                },
            )
            connection.execute(
                "UPDATE activation_revocation_fences "
                "SET canonical_record = ?",
                (b"tampered",),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(UnifiedActivationInboxIntegrityError):
            self.authoritative.snapshot(self.query)

        extra_path = Path(self.temporary.name) / "extra.sqlite3"
        extra = SQLiteFGSAuthoritativeActivationInboxStoreV2(
            extra_path,
            ReplayProtectionTestBackend(),
            InboxProtectionTestBackend(),
        )
        del extra
        connection = sqlite3.connect(extra_path)
        try:
            connection.execute("CREATE TABLE unexpected(value INTEGER)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(UnifiedActivationInboxIntegrityError):
            SQLiteFGSAuthoritativeActivationInboxStoreV2(
                extra_path,
                ReplayProtectionTestBackend(),
                InboxProtectionTestBackend(),
            )


if __name__ == "__main__":
    unittest.main()
