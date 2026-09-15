"""Single-host SQLite transaction for session activation and inbox enqueue.

This profile stores replay state and protected first-application work in one
database.  The transition to ``CONSUMED_ACTIVE`` and creation of the matching
``PENDING`` inbox row share one connection and one ``BEGIN IMMEDIATE``
transaction.  It deliberately does not use SQLite ``ATTACH`` or claim a
distributed/external-application transaction.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import replace
from pathlib import Path

from pq_sat_auth.replay import InvalidTransition, ReservationNotFound

from ..activation import ActivationCommitRequestV2
from ..application import (
    AtomicActivationInboxResultV2,
    FirstApplicationInboxEntryV2,
    FirstApplicationInboxStateV2,
    FirstRecordOutboxConflictError,
    InboxEnqueueDispositionV2,
    InboxEnqueueResultV2,
    MAX_APPLICATION_RECEIPT_BYTES,
)
from ..replay import (
    ActivateDispositionV2,
    ActivateResultV2,
    GrantRecordV2,
    GrantStateV2,
    ReservationV2,
)
from .sqlite_inbox import (
    MAX_PROTECTED_RECORD_BYTES as MAX_PROTECTED_INBOX_RECORD_BYTES,
    FGSApplicationInboxProtectionV2,
    _SCHEMA_SQL as INBOX_SCHEMA_SQL,
    _bounded_bytes as _inbox_bounded_bytes,
    _fixed as _inbox_fixed,
    _normalized_sql,
    _protection_id as _inbox_protection_id,
    _record_aad as _inbox_record_aad,
    decode_application_inbox_entry,
    encode_application_inbox_entry,
)
from .sqlite_replay import (
    FGSReplayIntegrityError,
    FGSReplayRecordProtectionV2,
    FGSReplayStorageError,
    SQLiteFGSReplayStoreV2,
    _SCHEMA_SQL as REPLAY_SCHEMA_SQL,
)


APPLICATION_ID = 0x50515355
SCHEMA_VERSION = 1
PRODUCTION_READY = False


class UnifiedActivationInboxStorageError(FGSReplayStorageError):
    pass


class UnifiedActivationInboxIntegrityError(FGSReplayIntegrityError):
    pass


class SQLiteFGSUnifiedActivationInboxStoreV2(SQLiteFGSReplayStoreV2):
    """Replay store plus protected inbox with a single activation commit."""

    production_ready = False
    durable = True
    distributed = False

    def __init__(
        self,
        path: str | os.PathLike[str],
        replay_protection_backend: FGSReplayRecordProtectionV2,
        inbox_protection_backend: FGSApplicationInboxProtectionV2,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self._inbox_protection_backend = inbox_protection_backend
        self._inbox_protection_id = _inbox_protection_id(
            getattr(inbox_protection_backend, "protection_id", None)
        )
        super().__init__(
            path,
            replay_protection_backend,
            busy_timeout_ms=busy_timeout_ms,
        )

    def _verify_database(self, connection: sqlite3.Connection) -> None:
        if self._pragma(connection, "application_id") != APPLICATION_ID:
            raise UnifiedActivationInboxIntegrityError(
                "unified database application_id mismatch"
            )
        if self._pragma(connection, "user_version") != SCHEMA_VERSION:
            raise UnifiedActivationInboxIntegrityError(
                "unified database schema version mismatch"
            )
        tables = self._tables(connection)
        if set(tables) != {
            "fgs_replay_records",
            "first_application_inbox",
        }:
            raise UnifiedActivationInboxIntegrityError(
                "unified database table set mismatch"
            )
        if _normalized_sql(tables["fgs_replay_records"]) != _normalized_sql(
            REPLAY_SCHEMA_SQL
        ):
            raise UnifiedActivationInboxIntegrityError(
                "unified replay schema mismatch"
            )
        if _normalized_sql(
            tables["first_application_inbox"]
        ) != _normalized_sql(INBOX_SCHEMA_SQL):
            raise UnifiedActivationInboxIntegrityError(
                "unified inbox schema mismatch"
            )
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise UnifiedActivationInboxIntegrityError(
                "unified database is not in WAL mode"
            )
        if self._pragma(connection, "synchronous") != 2:
            raise UnifiedActivationInboxIntegrityError(
                "unified database is not FULL synchronous"
            )

    def _initialize(self) -> None:
        existed = self._path.exists()
        connection = self._raw_connection()
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise UnifiedActivationInboxStorageError(
                    "SQLite WAL mode is unavailable"
                )
            connection.execute("BEGIN IMMEDIATE")
            if not self._tables(connection):
                if self._pragma(connection, "application_id") != 0:
                    raise UnifiedActivationInboxIntegrityError(
                        "empty unified database has unexpected application_id"
                    )
                if self._pragma(connection, "user_version") != 0:
                    raise UnifiedActivationInboxIntegrityError(
                        "empty unified database has unexpected schema version"
                    )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute(REPLAY_SCHEMA_SQL)
                connection.execute(INBOX_SCHEMA_SQL)
            self._verify_database(connection)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        if not existed:
            os.chmod(self._path, 0o600)
            directory = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def _protect_inbox(self, entry: FirstApplicationInboxEntryV2) -> bytes:
        plaintext = encode_application_inbox_entry(entry)
        try:
            protected = self._inbox_protection_backend.seal(
                plaintext,
                aad=_inbox_record_aad(
                    entry.session_id,
                    entry.record_digest,
                    entry.state,
                ),
            )
        except Exception as error:
            raise UnifiedActivationInboxIntegrityError(
                "application inbox record sealing failed"
            ) from error
        if not isinstance(protected, bytes) or not protected:
            raise UnifiedActivationInboxIntegrityError(
                "application inbox protector returned an invalid record"
            )
        if len(protected) > MAX_PROTECTED_INBOX_RECORD_BYTES:
            raise UnifiedActivationInboxIntegrityError(
                "protected application inbox record exceeds bounds"
            )
        return protected

    def _decode_inbox_row(
        self,
        row: tuple[object, ...],
    ) -> FirstApplicationInboxEntryV2:
        if len(row) != 6:
            raise UnifiedActivationInboxIntegrityError(
                "unified inbox row has wrong width"
            )
        session_value, digest_value, state_value, revision_value = row[:4]
        protection_id, protected = row[4:]
        try:
            session_id = _inbox_fixed(session_value, 32, "stored session_id")  # type: ignore[arg-type]
            record_digest = _inbox_fixed(  # type: ignore[arg-type]
                digest_value,
                32,
                "stored record_digest",
            )
            if isinstance(state_value, bool) or not isinstance(state_value, int):
                raise TypeError("stored inbox state must be an integer")
            state = FirstApplicationInboxStateV2(state_value)
            if (
                isinstance(revision_value, bool)
                or not isinstance(revision_value, int)
                or revision_value != int(state)
            ):
                raise ValueError("stored inbox state and revision differ")
            if protection_id != self._inbox_protection_id:
                raise ValueError("application inbox protection identity mismatch")
            if not isinstance(protected, bytes) or not protected:
                raise TypeError("protected application inbox record is invalid")
            if len(protected) > MAX_PROTECTED_INBOX_RECORD_BYTES:
                raise ValueError("protected application inbox record exceeds bounds")
            opened = self._inbox_protection_backend.open(
                protected,
                aad=_inbox_record_aad(session_id, record_digest, state),
            )
            if not isinstance(opened, bytes) or not opened:
                raise TypeError(
                    "application inbox protector returned invalid plaintext"
                )
            entry = decode_application_inbox_entry(opened)
            if (
                entry.session_id,
                entry.record_digest,
                entry.state,
                entry.revision,
            ) != (session_id, record_digest, state, revision_value):
                raise ValueError("inbox row and protected record differ")
            return entry
        except Exception as error:
            raise UnifiedActivationInboxIntegrityError(
                "stored unified inbox entry is invalid"
            ) from error

    def _select_inbox(
        self,
        connection: sqlite3.Connection,
        session_id: bytes,
    ) -> FirstApplicationInboxEntryV2 | None:
        row = connection.execute(
            "SELECT session_id, record_digest, state, revision, "
            "protection_id, protected_record FROM first_application_inbox "
            "WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return None if row is None else self._decode_inbox_row(row)

    @staticmethod
    def _enqueue_result(
        entry: FirstApplicationInboxEntryV2,
    ) -> InboxEnqueueResultV2:
        disposition = (
            InboxEnqueueDispositionV2.EXISTING_PENDING
            if entry.state is FirstApplicationInboxStateV2.PENDING
            else InboxEnqueueDispositionV2.EXISTING_COMPLETED
        )
        result = InboxEnqueueResultV2(
            disposition,
            entry.session_id,
            entry.record_digest,
        )
        result.validate()
        return result

    @staticmethod
    def _has_completed_activation(record: object) -> bool:
        return (
            isinstance(record, GrantRecordV2)
            and record.state
            in (GrantStateV2.CONSUMED_ACTIVE, GrantStateV2.CONSUMED_EXPIRED)
            and record.client_confirmation_digest is not None
            and record.activated_at is not None
        )

    def activate_session(self, *args: object, **kwargs: object) -> ActivateResultV2:
        raise InvalidTransition(
            "unified store requires activate_and_enqueue for activation"
        )

    def activate_and_enqueue(
        self,
        request: ActivationCommitRequestV2,
        record_digest: bytes,
        plaintext: bytes,
    ) -> AtomicActivationInboxResultV2:
        if not isinstance(request, ActivationCommitRequestV2):
            raise TypeError("request must be an ActivationCommitRequestV2")
        request.validate()
        candidate = FirstApplicationInboxEntryV2(
            state=FirstApplicationInboxStateV2.PENDING,
            revision=1,
            session_id=request.session_id,
            record_digest=record_digest,
            plaintext=plaintext,
        )
        candidate.validate()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _, existing = self._check_identity_bindings(
                connection,
                request.identity,
            )
            if existing is None or isinstance(existing, ReservationV2):
                raise ReservationNotFound("no committed grant exists")
            if (
                existing.attempt_id,
                existing.request_digest,
                existing.session_id,
                existing.response_digest,
            ) != (
                request.attempt_id,
                request.request_digest,
                request.session_id,
                request.response_digest,
            ):
                raise InvalidTransition("activation belongs to another grant")
            if existing.state is GrantStateV2.CONSUMED_EXPIRED:
                raise InvalidTransition("expired grant cannot activate")

            inbox = self._select_inbox(connection, request.session_id)
            if existing.state is GrantStateV2.CONSUMED_ACTIVE:
                if (
                    existing.client_confirmation_digest
                    != request.client_confirmation_digest
                ):
                    raise InvalidTransition(
                        "active grant confirmation cannot change"
                    )
                if inbox is None:
                    raise UnifiedActivationInboxIntegrityError(
                        "active grant lacks its atomic inbox item"
                    )
                if (
                    inbox.record_digest != candidate.record_digest
                    or inbox.plaintext != candidate.plaintext
                ):
                    raise FirstRecordOutboxConflictError(
                        "session inbox already contains another first record"
                    )
                activation_result = ActivateResultV2(
                    ActivateDispositionV2.EXISTING_ACTIVE,
                    existing,
                )
                inbox_result = self._enqueue_result(inbox)
            else:
                if inbox is not None:
                    raise UnifiedActivationInboxIntegrityError(
                        "pending grant already has an inbox item"
                    )
                if request.activated_at > existing.activation_deadline:
                    raise InvalidTransition("activation deadline has passed")
                active = replace(
                    existing,
                    state=GrantStateV2.CONSUMED_ACTIVE,
                    client_confirmation_digest=(
                        request.client_confirmation_digest
                    ),
                    activated_at=request.activated_at,
                )
                self._replace(connection, active)
                protected = self._protect_inbox(candidate)
                cursor = connection.execute(
                    "INSERT INTO first_application_inbox "
                    "(session_id, record_digest, state, revision, "
                    "protection_id, protected_record) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        candidate.session_id,
                        candidate.record_digest,
                        int(candidate.state),
                        candidate.revision,
                        self._inbox_protection_id,
                        protected,
                    ),
                )
                if cursor.rowcount != 1:
                    raise UnifiedActivationInboxStorageError(
                        "atomic inbox enqueue changed an unexpected row count"
                    )
                activation_result = ActivateResultV2(
                    ActivateDispositionV2.NEW,
                    active,
                )
                inbox_result = InboxEnqueueResultV2(
                    InboxEnqueueDispositionV2.NEW,
                    candidate.session_id,
                    candidate.record_digest,
                )

            result = AtomicActivationInboxResultV2(
                activation_result,
                inbox_result,
            )
            result.validate()
            connection.execute("COMMIT")
            return result
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def load(self, session_id: bytes) -> FirstApplicationInboxEntryV2 | None:
        session = _inbox_fixed(session_id, 32, "session_id")
        connection = self._connect()
        try:
            return self._select_inbox(connection, session)
        finally:
            connection.close()

    def complete(
        self,
        session_id: bytes,
        record_digest: bytes,
        receipt: bytes,
    ) -> FirstApplicationInboxEntryV2:
        session = _inbox_fixed(session_id, 32, "session_id")
        digest = _inbox_fixed(record_digest, 32, "record_digest")
        completed_receipt = _inbox_bounded_bytes(
            receipt,
            MAX_APPLICATION_RECEIPT_BYTES,
            "receipt",
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._select_inbox(connection, session)
            if existing is None:
                raise FirstRecordOutboxConflictError(
                    "cannot complete a missing application inbox item"
                )
            replay = self._select_where(connection, "session_id", session)
            if replay is None or isinstance(replay, ReservationV2):
                raise UnifiedActivationInboxIntegrityError(
                    "inbox item lacks a committed replay record"
                )
            if not self._has_completed_activation(replay):
                raise UnifiedActivationInboxIntegrityError(
                    "inbox item is not bound to a completed activation"
                )
            if existing.record_digest != digest:
                raise FirstRecordOutboxConflictError(
                    "application receipt belongs to another first record"
                )
            if existing.state is FirstApplicationInboxStateV2.COMPLETED:
                if existing.receipt != completed_receipt:
                    raise FirstRecordOutboxConflictError(
                        "completed application receipt cannot change"
                    )
                connection.execute("COMMIT")
                return existing
            completed = replace(
                existing,
                state=FirstApplicationInboxStateV2.COMPLETED,
                revision=2,
                receipt=completed_receipt,
            )
            completed.validate()
            protected = self._protect_inbox(completed)
            cursor = connection.execute(
                "UPDATE first_application_inbox SET state = ?, revision = ?, "
                "protected_record = ? WHERE session_id = ? AND state = 1 "
                "AND revision = 1",
                (
                    int(completed.state),
                    completed.revision,
                    protected,
                    completed.session_id,
                ),
            )
            if cursor.rowcount != 1:
                raise UnifiedActivationInboxStorageError(
                    "inbox completion changed an unexpected row count"
                )
            connection.execute("COMMIT")
            return completed
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def pending(self, *, limit: int = 100) -> tuple[bytes, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("pending limit must be an integer")
        if not 1 <= limit <= 1_000:
            raise ValueError("pending limit is outside bounds")
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT session_id, record_digest, state, revision, "
                "protection_id, protected_record FROM first_application_inbox "
                "WHERE state = 1 ORDER BY session_id LIMIT ?",
                (limit,),
            ).fetchall()
            entries = tuple(self._decode_inbox_row(row) for row in rows)
            for entry in entries:
                replay = self._select_where(
                    connection,
                    "session_id",
                    entry.session_id,
                )
                if (
                    replay is None
                    or isinstance(replay, ReservationV2)
                    or not self._has_completed_activation(replay)
                ):
                    raise UnifiedActivationInboxIntegrityError(
                        "pending inbox item is not bound to a completed activation"
                    )
            return tuple(entry.session_id for entry in entries)
        finally:
            connection.close()

    def inbox_count(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM first_application_inbox"
            ).fetchone()
            if row is None:
                raise UnifiedActivationInboxStorageError(
                    "unified inbox count is unavailable"
                )
            return int(row[0])
        finally:
            connection.close()


def sqlite_unified_activation_inbox_manifest() -> dict[str, object]:
    return {
        "format": "PQ-SAT-FGS-UNIFIED-ACTIVATION-INBOX-SQLITE-v0.2",
        "application_id": f"0x{APPLICATION_ID:08x}",
        "schema_version": SCHEMA_VERSION,
        "journal_mode": "WAL",
        "synchronous": "FULL",
        "tables": ["fgs_replay_records", "first_application_inbox"],
        "transaction_order": [
            "begin_immediate_on_one_database",
            "validate_exact_pending_grant",
            "transition_grant_to_consumed_active",
            "insert_protected_pending_inbox_item",
            "validate_composed_result",
            "commit_once",
        ],
        "claims": {
            "single_database_connection": True,
            "sqlite_attach_used": False,
            "single_host_atomic_activation_and_inbox": True,
            "exact_retry_idempotent": True,
            "competing_first_record_rejected": True,
            "direct_activation_disabled": True,
            "pending_scan_for_restart_recovery": True,
            "application_apply_once_required": True,
            "production_record_protection_instantiated": False,
            "production_plaintext_protection_instantiated": False,
            "external_application_exactly_once_proven": False,
            "atomic_revocation_and_activation": False,
            "hostile_filesystem_protection": False,
            "rollback_resistance": False,
            "physical_power_loss_tested": False,
            "distributed": False,
            "production_ready": False,
        },
    }
